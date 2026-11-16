"""Least-privilege capability binding and migration regression tests."""

from __future__ import annotations

import hashlib
import sqlite3
import sys
import unittest
from contextlib import closing
from dataclasses import replace
from pathlib import Path

from support import ProjectCase

from diamond.capability_binding import CapabilityBinding
from diamond.domain import Provider, Role, TaskSpec
from diamond.evidence import AttemptStatus, ExecutionAttempt
from diamond.errors import ExecutionGuardError, ValidationError
from diamond.packets import OutputContract, PacketContext, TaskPacket
from diamond.provider_metadata import ProviderMetadataRecord
from diamond.schema import CAPABILITY_SCHEMA_STATEMENTS, SCHEMA_STATEMENTS, SCHEMA_VERSION
from diamond.skills import SkillRecord, SkillRegistry
from diamond.store import EventStore
from diamond.validation import canonical_json, utc_now


class CapabilityBindingTests(ProjectCase):
    def setUp(self) -> None:
        super().setUp()
        self.database = self.project / ".diamond" / "diamond.sqlite3"
        self.store = EventStore(self.database)
        self.task_id = "a" * 32
        self.attempt_id = "b" * 32
        self.skill_path = self.project / "bounded-skill.md"
        self.skill_path.write_text("Use only the assigned workspace.\n", encoding="utf-8")
        self.skill = SkillRecord.from_file(
            "bounded-skill", self.skill_path, "1.0", "least privilege",
            (Role.BUILDER,), required_capabilities=("python",),
        )
        self.registry = SkillRegistry((self.skill,))
        self.spec = TaskSpec(
            self.task_id, "bind one assignment", Role.BUILDER, Provider.CLAUDE,
            owned_paths=("result.txt",), allowed_tools=(sys.executable,),
            allowed_skills=("bounded-skill",), timeout_seconds=30,
        )
        self.store.create(self.spec, "task:create")
        self.context = PacketContext(1, "1" * 64, "2" * 64, "3" * 64)
        self.packet = TaskPacket.from_task_spec(
            self.spec, self.attempt_id, self.project, 1,
            self.context.plan_digest, self.context.base_digest, self.context.config_digest,
            self.registry, ("python",), OutputContract("text", (), 4096),
        )
        self.attempt = ExecutionAttempt(
            self.attempt_id, self.task_id, 1, Role.BUILDER, Provider.CLAUDE,
            sys.executable, str(self.project.resolve()), AttemptStatus.INTENDED, utc_now(),
        )
        self.metadata = ProviderMetadataRecord.legacy(Provider.CLAUDE, sys.executable, sys.executable, utc_now())

    def test_binding_persists_digest_and_unknown_usage_across_restart(self) -> None:
        _, bound_attempt = self.store.reserve_dispatch(
            self.packet, self.attempt, "capability-test", "dispatch:one",
            provider_metadata=self.metadata, available_capabilities=("python",),
            available_tools=(sys.executable,), permission_mode="plan",
        )
        binding = self.store.capability_binding(bound_attempt.attempt_id)
        self.assertEqual(binding.packet_digest, self.packet.packet_digest())
        self.assertEqual(binding.execution_mode, "one_shot")
        self.assertEqual(binding.network_access, "denied")
        self.assertEqual(binding.assigned_skills[0]["content_digest"], self.skill.digest_sha256)
        # Ensure no usage rows exist initially (we no longer create UNKNOWN rows)
        self.assertEqual(self.store.capability_usage(self.attempt_id), ())

        reopened = EventStore(self.database)
        self.assertEqual(reopened.capability_binding(self.attempt_id), binding)
        self.assertEqual(reopened.capability_binding(self.attempt_id).capability_digest, binding.capability_digest)
        self.assertEqual(reopened.capability_usage(self.attempt_id), self.store.capability_usage(self.attempt_id))

    def test_stale_skill_digest_fails_before_attempt_or_binding_commit(self) -> None:
        self.skill_path.write_text("tampered instructions\n", encoding="utf-8")
        with self.assertRaisesRegex(ValidationError, "digest changed"):
            self.store.reserve_dispatch(
                self.packet, self.attempt, "capability-test", "dispatch:stale",
                provider_metadata=self.metadata, available_capabilities=("python",),
                available_tools=(sys.executable,), permission_mode="plan",
            )
        self.assertEqual(self.store.attempts(self.task_id), ())
        with self.assertRaises(Exception):
            self.store.capability_binding(self.attempt_id)

    def test_missing_provider_capability_and_unsupported_integrations_fail_closed(self) -> None:
        snapshot = self.metadata.to_dict()
        snapshot["verified_capabilities"] = ["timeout_enforcement"]
        metadata_json = canonical_json(snapshot)
        incompatible = replace(
            self.metadata, verified_capabilities=("timeout_enforcement",),
            metadata_json=metadata_json, metadata_digest=hashlib.sha256(metadata_json.encode()).hexdigest(),
        )
        with self.assertRaisesRegex(ExecutionGuardError, "missing"):
            CapabilityBinding.from_packet(self.packet, incompatible, "c" * 32,
                                          available_capabilities=("python",))

        with self.assertRaisesRegex(ExecutionGuardError, "MCP"):
            CapabilityBinding.from_packet(self.packet, self.metadata, "c" * 32,
                                          available_capabilities=("python",), mcp_integrations=("filesystem",))
        with self.assertRaisesRegex(ExecutionGuardError, "plugin"):
            CapabilityBinding.from_packet(self.packet, self.metadata, "d" * 32,
                                          available_capabilities=("python",), plugin_integrations=("arbitrary",))

    def test_packet_digest_and_provider_binding_are_prelaunch_guards(self) -> None:
        _, bound_attempt = self.store.reserve_dispatch(
            self.packet, self.attempt, "capability-test", "dispatch:guards",
            provider_metadata=self.metadata, available_capabilities=("python",),
            available_tools=(sys.executable,), permission_mode="plan",
        )
        changed = replace(self.packet, allowed_tools=("/bin/sh",))
        with self.assertRaises(ExecutionGuardError):
            self.store.verify_capability_binding(changed, bound_attempt.attempt_id)

    def test_schema_11_migrates_to_capability_schema_in_isolated_database(self) -> None:
        database = self.base / "schema-11.sqlite3"
        previous_statements = SCHEMA_STATEMENTS[:-len(CAPABILITY_SCHEMA_STATEMENTS)]
        with closing(sqlite3.connect(database)) as connection, connection:
            for statement in previous_statements:
                connection.execute(statement)
            connection.execute("PRAGMA user_version=11")
        migrated = EventStore(database)
        self.assertEqual(migrated.migrate(), SCHEMA_VERSION)
        self.assertEqual(SCHEMA_VERSION, 15)
        with closing(sqlite3.connect(database)) as connection:
            names = {row[0] for row in connection.execute("SELECT name FROM sqlite_master")}
            self.assertIn("capability_bindings", names)
            self.assertIn("capability_usage", names)
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 15)


if __name__ == "__main__":
    unittest.main()
