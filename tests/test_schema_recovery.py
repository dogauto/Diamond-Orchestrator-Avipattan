"""Comprehensive regression test suite for Diamond schema recovery (versions 2-11)."""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from support import TASK_ID, ProjectCase

from diamond.domain import Provider, Role, TaskSpec, TaskStatus
from diamond.errors import StorageError
from diamond.evidence import AttemptStatus, ExecutionAttempt, digest_text
from diamond.schema import (
    HISTORICAL_SCHEMA_CONTRACTS,
    LEGACY_ATTEMPTS_CREATE,
    LEGACY_EVENT_CREATE,
    SCHEMA_STATEMENTS,
    SCHEMA_VERSION,
    _normalize_sql,
    check_schema,
    migrate_schema,
)
from diamond.store import EventStore
from diamond.validation import canonical_json, utc_now


class SchemaRecoveryRegressionTests(ProjectCase):
    def setUp(self) -> None:
        super().setUp()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.timestamp = "2026-10-16T12:00:00.000000Z"
        self.attempt_id = "b" * 32

    def tearDown(self) -> None:
        self.temp_dir.cleanup()
        super().tearDown()

    def create_historical_database(self, version: int, name: str = "historical.sqlite3") -> Path:
        """Construct an authentic historical database using frozen historical contracts."""
        db_path = self.root / name
        statements = HISTORICAL_SCHEMA_CONTRACTS[version]
        spec = TaskSpec(TASK_ID, "Historical test spec", Role.BUILDER, Provider.CLAUDE)
        snapshot = {
            "spec": spec.to_dict(), "status": "CREATED", "revision": 1,
            "created_at": self.timestamp, "updated_at": self.timestamp,
            "blocking_reason": None, "resume_status": None, "plan_revision": None,
            "plan_digest": None, "current_attempt": None, "correction_rounds_used": 0,
        }
        with closing(sqlite3.connect(db_path)) as conn, conn:
            conn.execute("PRAGMA foreign_keys=OFF")
            for statement in statements:
                conn.execute(statement)
            conn.execute(f"PRAGMA user_version={version}")
            # Insert historical data
            conn.execute("INSERT INTO tasks VALUES (?, 1, 'CREATED', ?)",
                         (TASK_ID, canonical_json(snapshot)))
            conn.execute("INSERT INTO events VALUES (?, 1, ?, 1, 'TASK_CREATED', ?, 'controller', 'cmd-1', ?)",
                         ("e" * 32, TASK_ID, self.timestamp, canonical_json({"schema_version": 1, "spec": spec.to_dict()})))
            conn.execute("INSERT INTO commands VALUES ('cmd-1', ?, ?)",
                         (canonical_json({"op": "create"}), canonical_json(snapshot)))

            if version >= 3:
                attempt = ExecutionAttempt(self.attempt_id, TASK_ID, 1, Role.BUILDER, Provider.CLAUDE,
                                           "/bin/test", "/workspace", AttemptStatus.INTENDED, self.timestamp)
                # Column counts by version:
                #   v3-v10: 29 (accepted_packet_id, provider_binding_digest present)
                #   v11-v13: 27 (provider_id/adapter_id not yet added)
                #   v14+: 29 (provider_id/adapter_id added)
                if version in (11, 12, 13):
                    values = EventStore._attempt_values(attempt)
                    ncols = 27
                else:
                    values = EventStore._attempt_values_full(attempt)
                    ncols = 29
                placeholders = ",".join(["?"] * ncols)
                conn.execute(f"INSERT INTO attempts VALUES ({placeholders})", values[:ncols])
                conn.execute("INSERT INTO attempt_commands VALUES ('att-cmd-1', ?, '{\"req\":1}', '{\"res\":1}')",
                             (self.attempt_id,))
                evidence_payload = '{"detail":"historical evidence"}'
                conn.execute("INSERT INTO attempt_evidence VALUES (?, 1, ?, 'fixture', ?, ?, ?, 'cmd-ev-1', '{}')",
                             ("c" * 32, self.attempt_id, self.timestamp, evidence_payload,
                              digest_text(evidence_payload)))

            if version >= 4:
                packet = '{"pkg":1}'
                conn.execute(
                    "INSERT INTO dispatch_claims VALUES (?, 1, ?, 1, ?, ?, ?, 'test-owner', ?, 'cmd-claim-1', '{}')",
                    ("d" * 32, TASK_ID, self.attempt_id, digest_text(packet), packet, self.timestamp),
                )
        return db_path

    def test_all_historical_versions_migrate_step_by_step_and_preserve_records(self) -> None:
        """Every historical version 2-10 must migrate cleanly to SCHEMA_VERSION 11 and preserve rows."""
        for v in range(2, SCHEMA_VERSION):
            with self.subTest(version=v):
                db_path = self.create_historical_database(v, f"db_v{v}.sqlite3")
                store = EventStore(db_path)

                # Prior to explicit migration, unmigrated store rejects normal access
                with self.assertRaises(StorageError):
                    store.get(TASK_ID)

                # Migrate to current schema
                res = store.migrate()
                self.assertEqual(res, SCHEMA_VERSION)

                # Verify user_version and data preservation
                with closing(sqlite3.connect(db_path)) as conn:
                    current_v = conn.execute("PRAGMA user_version").fetchone()[0]
                    self.assertEqual(current_v, SCHEMA_VERSION)
                    self.assertEqual(conn.execute("PRAGMA foreign_key_check").fetchall(), [])
                    self.assertEqual(conn.execute("PRAGMA integrity_check").fetchall(), [("ok",)])

                # Reopening store succeeds
                reopened = EventStore(db_path)
                t = reopened.get(TASK_ID)
                self.assertEqual(t.spec.task_id, TASK_ID)
                self.assertEqual(t.status, TaskStatus.CREATED)

                # Calling migrate again on already-migrated database is idempotent
                self.assertEqual(reopened.migrate(), SCHEMA_VERSION)

    def test_forged_user_version_rejected(self) -> None:
        """Forged user_version=11 on a legacy layout must be rejected upon opening and migration."""
        db_path = self.create_historical_database(2, "forged_v2.sqlite3")
        with closing(sqlite3.connect(db_path)) as conn, conn:
            conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

        store = EventStore(db_path)
        with self.assertRaises(StorageError):
            store.list()
        with self.assertRaises(StorageError):
            store.migrate()

    def test_rogue_application_owned_objects_rejected(self) -> None:
        """Rogue tables, triggers, and indexes are rejected during migration."""
        for rogue_stmt in (
            "CREATE TABLE rogue_table (id TEXT PRIMARY KEY)",
            "CREATE TRIGGER rogue_trigger AFTER INSERT ON events BEGIN SELECT 1; END",
            "CREATE INDEX rogue_index ON events(timestamp)",
        ):
            with self.subTest(rogue=rogue_stmt):
                db_path = self.create_historical_database(8, f"rogue_{abs(hash(rogue_stmt))}.sqlite3")
                with closing(sqlite3.connect(db_path)) as conn, conn:
                    conn.execute(rogue_stmt)

                store = EventStore(db_path)
                with self.assertRaises(StorageError):
                    store.migrate()

    def test_sql_normalization_adversarial(self) -> None:
        """Normalization must differentiate string literal content while allowing whitespace/casing variations."""
        stmt = SCHEMA_STATEMENTS[1]
        norm = _normalize_sql(stmt)

        # Keyword capitalization matches
        kw_variation = stmt.replace("WITHOUT ROWID", "without rowid").replace("CREATE TABLE", "create table")
        self.assertEqual(_normalize_sql(kw_variation), norm)

        # Double-quoted identifier matches
        dquote_variation = stmt.replace("CREATE TABLE events", 'CREATE TABLE "events"')
        self.assertEqual(_normalize_sql(dquote_variation), norm)

        # Spacing around delimiters matches
        spacing_variation = stmt.replace("CHECK(schema_version = 1)", "CHECK( schema_version=1 )")
        self.assertEqual(_normalize_sql(spacing_variation), norm)

        # CHECK string literal casing MUST NOT match
        case_mutation = stmt.replace("'controller'", "'CONTROLLER'")
        self.assertNotEqual(_normalize_sql(case_mutation), norm)

        # Adjacent quotes token buffer inversion check
        self.assertEqual(_normalize_sql("actor='controller'"), "actor = 'controller'")

    def test_failed_migration_rolls_back_atomically(self) -> None:
        """Failure mid-migration must restore original database bytes and foreign key enforcement."""
        db_path = self.create_historical_database(9, "rollback_test.sqlite3")
        before_bytes = db_path.read_bytes()

        with patch("diamond.schema.MIGRATION_9_TO_10", ("INVALID SQL STATEMENT",)):
            store = EventStore(db_path)
            with self.assertRaises(StorageError):
                store.migrate()

        # Database bytes completely restored
        self.assertEqual(db_path.read_bytes(), before_bytes)

        # user_version remains 9 and events table is unchanged from pre-migration state
        with closing(sqlite3.connect(db_path)) as conn:
            self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 9)
            events_sql = conn.execute("SELECT sql FROM sqlite_master WHERE name='events'").fetchone()[0]
            self.assertIn("events", events_sql)

        # Subsequent valid migration succeeds
        store2 = EventStore(db_path)
        self.assertEqual(store2.migrate(), SCHEMA_VERSION)

    def test_foreign_key_violation_triggers_rollback(self) -> None:
        """Foreign key violation present before migration causes rollback."""
        db_path = self.create_historical_database(9, "fk_violation.sqlite3")
        with closing(sqlite3.connect(db_path)) as conn, conn:
            conn.execute("PRAGMA foreign_keys=OFF")
            conn.execute("INSERT INTO commands VALUES ('missing-cmd', '{}', '{}')")
        before_bytes = db_path.read_bytes()

        store = EventStore(db_path)
        with self.assertRaises(StorageError):
            store.migrate()

        self.assertEqual(db_path.read_bytes(), before_bytes)


if __name__ == "__main__":
    unittest.main()
