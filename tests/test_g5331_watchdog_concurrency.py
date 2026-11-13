"""G5.3.3.1 — watchdog concurrency and EventStore reliability repair.

Reproduces the agent_runtime_events collision and verifies durable event
writes coexist under concurrent access once the composite unique constraint
is removed by schema migration.
"""
from __future__ import annotations

import shutil
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from uuid import uuid4

from diamond.policy_ipc import AttemptRevocationResult
from diamond.runtime_store import AgentRuntimeStoreMixin
from diamond.store import EventStore
from diamond.validation import canonical_json, utc_now


class CollisionReproduction(unittest.TestCase):
    """Deterministic reproduction of the pre-migration collision."""

    def setUp(self) -> None:
        self.tmpdir = Path(tempfile.mkdtemp(prefix="diamond-g5331-"))
        self.db = self.tmpdir / "collision.sqlite3"

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_composite_unique_rejects_concurrent_writes(self) -> None:
        """Simulate a live v12 database with the extra composite unique."""
        conn = sqlite3.connect(str(self.db))
        conn.execute("""CREATE TABLE agent_runtime_events (
            event_id TEXT PRIMARY KEY, entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision >= 1),
            event_type TEXT NOT NULL, timestamp TEXT NOT NULL,
            command_id TEXT NOT NULL UNIQUE, payload_json TEXT NOT NULL,
            UNIQUE(entity_type, entity_id, revision)) WITHOUT ROWID""")
        conn.execute("CREATE TRIGGER agent_runtime_events_no_update BEFORE UPDATE ON agent_runtime_events BEGIN SELECT RAISE(ABORT,'immutable'); END")
        conn.execute("CREATE TRIGGER agent_runtime_events_no_delete BEFORE DELETE ON agent_runtime_events BEGIN SELECT RAISE(ABORT,'immutable'); END")
        conn.execute("""CREATE TRIGGER agent_runtime_events_no_replace BEFORE INSERT ON agent_runtime_events WHEN EXISTS (
            SELECT 1 FROM agent_runtime_events WHERE event_id=NEW.event_id OR command_id=NEW.command_id)
            BEGIN SELECT RAISE(ABORT, 'agent runtime events cannot be replaced'); END""")
        conn.commit(); conn.close()

        errors: list[tuple[int, str]] = []
        lock = threading.Lock()

        def writer(i: int) -> None:
            try:
                conn = sqlite3.connect(str(self.db), timeout=30)
                conn.execute(
                    "INSERT INTO agent_runtime_events VALUES (?,?,?,?,?,?,?,?)",
                    (uuid4().hex, "policy_watchdog", "a1", 1, "SNAPSHOT",
                     utc_now(), f"watchdog:{i}", canonical_json({"i": i})),
                )
                conn.commit(); conn.close()
            except sqlite3.IntegrityError as exc:
                with lock:
                    errors.append((i, str(exc)))

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(50)]
        for t in threads: t.start()
        for t in threads: t.join()

        collision_errors = [msg for _, msg in errors if "UNIQUE constraint failed" in msg]
        self.assertTrue(len(collision_errors) > 0,
                        "expected at least one composite-unique collision under concurrent write pressure")
        rows = sqlite3.connect(str(self.db)).execute("SELECT COUNT(*) FROM agent_runtime_events").fetchone()[0]
        self.assertLess(rows, 50, "concurrent insert should not produce full row count under composite unique")


class FreshSchemaConcurrency(unittest.TestCase):
    """Verify concurrent writes succeed on the current schema."""

    def setUp(self) -> None:
        self.tmpdir = Path(tempfile.mkdtemp(prefix="diamond-g5331-new-"))
        self.db = self.tmpdir / "fresh.sqlite3"

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_concurrent_event_writes_succeed(self) -> None:
        """Watchdog SNAPSHOT and PolicyIPC policy_decision events coexist."""
        store = EventStore(self.db)
        # Initialize the v15 schema.
        with store._connection(write=True):
            pass

        errors: list[Exception] = []
        lock = threading.Lock()
        attempts = 50

        def insert_watchdog_snapshot(i: int) -> None:
            try:
                with store._connection(write=True) as conn:
                    AgentRuntimeStoreMixin._runtime_event(
                        conn,
                        entity_type="policy_watchdog",
                        entity_id="agent-1",
                        revision=1,
                        event_type="SNAPSHOT",
                        command=f"watchdog:{i}",
                        payload=canonical_json({"seq": i, "state": "HEALTHY"}),
                    )
            except Exception as exc:
                with lock:
                    errors.append(exc)

        def insert_policy_decision(i: int) -> None:
            try:
                with store._connection(write=True) as conn:
                    AgentRuntimeStoreMixin._runtime_event(
                        conn,
                        entity_type="policy_decision",
                        entity_id="agent-1",
                        revision=1,
                        event_type="ALLOW",
                        command=f"policy:{i}",
                        payload=canonical_json({"tool": "Read", "decision": "allow", "seq": i}),
                    )
            except Exception as exc:
                with lock:
                    errors.append(exc)

        threads = []
        for i in range(attempts):
            t1 = threading.Thread(target=insert_watchdog_snapshot, args=(i,))
            t2 = threading.Thread(target=insert_policy_decision, args=(i,))
            threads.extend([t1, t2])
            t1.start()
            t2.start()

        for t in threads:
            t.join()

        self.assertEqual(errors, [], f"Concurrent inserts raised {len(errors)} errors: {errors[:3]}")

        with store._connection(write=False) as conn:
            rows = conn.execute(
                "SELECT COUNT(*) FROM agent_runtime_events WHERE entity_id='agent-1' AND revision=1"
            ).fetchone()
            total = rows[0] if rows else 0
            self.assertEqual(total, 2 * attempts, f"Expected {2 * attempts} events, got {total}")

    def test_schema_lacks_composite_unique(self) -> None:
        """Current source schema does not carry the composite constraint."""
        store = EventStore(self.db)
        with store._connection(write=True):
            pass
        ddl = sqlite3.connect(str(self.db)).execute(
            "SELECT sql FROM sqlite_master WHERE name='agent_runtime_events'"
        ).fetchone()[0]
        self.assertNotIn("UNIQUE(entity_type, entity_id, revision)", ddl,
                          "current schema must not re-introduce the composite unique")


class RevocationReporting(unittest.TestCase):
    """Durable revocation evidence reflects actual persistence state."""

    def test_auth_revoked_with_binding_failure_reports_incomplete(self) -> None:
        from diamond.orchestration import OrchestrationLifecycle
        from diamond.policy_ipc import PolicyIPCServerContext
        import tempfile
        db = Path(tempfile.mktemp(suffix=".sqlite3"))
        store = EventStore(db)
        lc = OrchestrationLifecycle()

        class FailingStore:
            revoke_count = 0
            def revoke_policy_ipc_binding(self, attempt_id, command_id):
                self.revoke_count += 1
                raise RuntimeError("db lock")
            def __getattr__(self, name):
                raise AttributeError(name)

        ctx = PolicyIPCServerContext(
            socket_path=Path("/tmp/g5331-fake.sock"), store=FailingStore(),
            agent_id="a", task_id="t", attempt_id="att-fail", command_prefix="g5331",
        )
        lc.register_attempt("att-fail", ctx)
        result = lc.revoke_attempt("att-fail")
        self.assertEqual(result, AttemptRevocationResult.AUTHORITY_REVOKED_RESOURCE_CLEANUP_INCOMPLETE)
        self.assertFalse(bool(lc.active_attempt_ids()), "no active attempts after auth revoked")
        db.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
