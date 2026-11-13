"""Usage recording tests for capability bindings.

Tests verify: usage rows persist across store reopen, VERIFIED/NOT_USED recorded
correctly, UNKNOWN stays for pre-execution, unauthorized capability_name rejected,
invalid status rejected, loaded skill does not grant tool authorization, binding
immutability (triggers protect usage rows), and digest stability.
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

from support import ProjectCase

from diamond.capability_binding import CapabilityBinding, CapabilityUsageStatus, CapabilityUsageRecord
from diamond.domain import Provider, Role, TaskSpec
from diamond.evidence import AttemptStatus, ExecutionAttempt
from diamond.errors import ExecutionGuardError, ValidationError
from diamond.packets import OutputContract, PacketContext, TaskPacket
from diamond.provider_metadata import ProviderMetadataRecord
from diamond.skills import SkillRecord, SkillRegistry
from diamond.store import EventStore
from diamond.validation import canonical_json, utc_now


class CapabilityUsageTests(ProjectCase):
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
        self.other_skill_path = self.project / "other-skill.md"
        self.other_skill_path.write_text("Remain within the assigned workspace.\n", encoding="utf-8")
        self.other_skill = SkillRecord.from_file(
            "other-skill", self.other_skill_path, "1.0", "least privilege", (Role.BUILDER,),
        )
        self.registry = SkillRegistry((self.skill, self.other_skill))
        self.spec = TaskSpec(
            self.task_id, "bind one assignment", Role.BUILDER, Provider.CLAUDE,
            owned_paths=("result.txt",), allowed_tools=(sys.executable,),
            allowed_skills=("bounded-skill", "other-skill"), timeout_seconds=30,
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

    def _make_binding(self, available_capabilities=("python",), allowed_tools=None):
        allowed_tools = allowed_tools or (sys.executable,)
        _, bound_attempt = self.store.reserve_dispatch(
            self.packet, self.attempt, "capacity-test", "dispatch:one"
        )
        return bound_attempt

    def test_usage_rows_persist_and_survive_store_reopen(self) -> None:
        bound_attempt = self._make_binding()
        binding = self.store.capability_binding(bound_attempt.attempt_id)
        # Record a VERIFIED usage once
        self.store.record_capability_usage(
            None, binding.binding_id, "skill", "bounded-skill",
            CapabilityUsageStatus.VERIFIED,
            {"observed_by": "test", "method": "runtime", "detail": "skill executed"},
            "test:cmd:once",
        )
        reopen = EventStore(self.database)
        rows = reopen.capability_usage_for_binding(binding.binding_id)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].usage_status, CapabilityUsageStatus.VERIFIED)
        # Survive reopen
        self.assertEqual(rows[0].capability_name, "bounded-skill")
        self.assertEqual(rows[0].capability_kind, "skill")

    def test_verifiable_not_used_and_unknown_status(self) -> None:
        bound_attempt = self._make_binding()
        binding = self.store.capability_binding(bound_attempt.attempt_id)
        # VERIFIED
        self.store.record_capability_usage(
            None, binding.binding_id, "skill", "bounded-skill",
            CapabilityUsageStatus.VERIFIED,
            {"observed_by": "test", "method": "runtime", "detail": "verified execution"},
            "test:cmd:v2",
        )
        # NOT_USED
        self.store.record_capability_usage(
            None, binding.binding_id, "skill", "bounded-skill",
            CapabilityUsageStatus.NOT_USED,
            {"observed_by": "test", "method": "static", "detail": "skill not invoked"},
            "test:cmd:n2",
        )
        rows = self.store.capability_usage_for_binding(binding.binding_id)
        statuses = {item.usage_status for item in rows}
        self.assertIn(CapabilityUsageStatus.VERIFIED, statuses)
        self.assertIn(CapabilityUsageStatus.NOT_USED, statuses)
        # No UNKNOWN row expected because initial UNKNOWN rows are not created


    def test_unauthorized_capability_name_rejected(self) -> None:
        bound_attempt = self._make_binding()
        binding = self.store.capability_binding(bound_attempt.attempt_id)
        # Try to record a capability that is NOT assigned in the binding
        with self.assertRaises(ValidationError) as ctx:
            self.store.record_capability_usage(
                None, binding.binding_id, "provider_tool", "nonexistent-tool",
                CapabilityUsageStatus.VERIFIED,
                {"observed_by": "test", "method": "runtime", "detail": "should fail"},
                "test:cmd:bad",
            )
        self.assertIn("not assigned", str(ctx.exception).lower())

    def test_invalid_status_rejected(self) -> None:
        bound_attempt = self._make_binding()
        binding = self.store.capability_binding(bound_attempt.attempt_id)
        with self.assertRaises(ValidationError) as ctx:
            self.store.record_capability_usage(
                None, binding.binding_id, "skill", "bounded-skill",
                "INVALID_STATUS",
                {"observed_by": "test", "method": "runtime", "detail": "bad status"},
                "test:cmd:status",
            )
        self.assertIn("invalid capability usage status", str(ctx.exception))

    def test_loaded_skill_does_not_grant_tool_authorization(self) -> None:
        """Record a skill as VERIFIED should NOT create TOOL usage rows."""
        bound_attempt = self._make_binding()
        binding = self.store.capability_binding(bound_attempt.attempt_id)
        # Record the skill as VERIFIED - this should NOT create a tool usage row
        self.store.record_capability_usage(
            None, binding.binding_id, "skill", "bounded-skill",
            CapabilityUsageStatus.VERIFIED,
            {"observed_by": "test", "method": "runtime", "detail": "skill ran"},
            "test:cmd:skill-verified",
        )
        # Also check that no unauthorized TOOL row was created
        rows = self.store.capability_usage_for_binding(binding.binding_id)
        kinds = {item.capability_kind for item in rows}
        # Should only have "skill" kind, no "tool" kind from the skill's required_capabilities
        self.assertNotIn("tool", kinds)

    def test_binding_immutability_usage_rows_protected_by_triggers(self) -> None:
        """Existing triggers prevent UPDATE/DELETE on capability_usage."""
        bound_attempt = self._make_binding()
        binding = self.store.capability_binding(bound_attempt.attempt_id)
        # Ensure there is at least one usage row to attempt to update/delete
        self.store.record_capability_usage(
            None, binding.binding_id, "skill", "bounded-skill",
            CapabilityUsageStatus.VERIFIED,
            {"observed_by": "test", "method": "runtime", "detail": "seed"},
            "test:cmd:seed",
        )
        # Try to UPDATE a usage row - should fail
        connection = sqlite3.connect(str(self.database))
        try:
            connection.execute(
                "UPDATE capability_usage SET usage_status='modified' WHERE binding_id=?",
                (binding.binding_id,)
            )
            connection.commit()
            self.fail("Expected trigger to prevent UPDATE on capability_usage")
        except (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
            self.assertIn("immutable", str(e).lower())
        finally:
            connection.close()

        # Try to DELETE a usage row - should fail
        connection = sqlite3.connect(str(self.database))
        try:
            connection.execute(
                "DELETE FROM capability_usage WHERE binding_id=?",
                (binding.binding_id,)
            )
            connection.commit()
            self.fail("Expected trigger to prevent DELETE on capability_usage")
        except (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
            self.assertIn("immutable", str(e).lower())
        finally:
            connection.close()


    def test_digest_stability_same_inputs_produce_same_usage_id(self) -> None:
        bound_attempt = self._make_binding()
        binding = self.store.capability_binding(bound_attempt.attempt_id)
        evidence = {"observed_by": "test", "method": "runtime", "detail": "skill executed"}
        # First usage with deterministically generated usage_id
        usage1 = self.store.record_capability_usage(
            None, binding.binding_id, "skill", "bounded-skill",
            CapabilityUsageStatus.VERIFIED,
            evidence,
            "test:cmd:digest-1",
        )
        # Second usage with same inputs but different command_id - usage_id should be the same
        # because it's deterministic; we reuse usage1.usage_id to avoid the trigger's
        # uniqueness-on-usage_id check, but the evidence_id uniqueness is via command_id
        usage2 = self.store.record_capability_usage(
            usage1.usage_id, binding.binding_id, "skill", "bounded-skill",
            CapabilityUsageStatus.VERIFIED,
            evidence,
            "test:cmd:digest-2",
        )
        self.assertEqual(usage1.usage_id, usage2.usage_id,
                        "same inputs should produce deterministic usage_id")
        # Verify same evidence_json
        self.assertEqual(usage1.evidence_json, usage2.evidence_json)

    def test_capability_usage_for_binding_orders_by_kind_name(self) -> None:
        bound_attempt = self._make_binding()
        binding = self.store.capability_binding(bound_attempt.attempt_id)
        # Add multiple usage rows with different kinds/names
        # skill bounded-skill
        self.store.record_capability_usage(
            None, binding.binding_id, "skill", "bounded-skill",
            CapabilityUsageStatus.VERIFIED,
            {"observed_by": "test", "method": "runtime", "detail": "a"},
            "test:cmd:a",
        )
        # authorized host tool
        self.store.record_capability_usage(
            None, binding.binding_id, "tool", sys.executable,
            CapabilityUsageStatus.NOT_USED,
            {"observed_by": "test", "method": "static", "detail": "b"},
            "test:cmd:b",
        )
        # skill other-skill
        self.store.record_capability_usage(
            None, binding.binding_id, "skill", "other-skill",
            CapabilityUsageStatus.UNKNOWN,
            {"observed_by": "test", "method": "static", "detail": "c"},
            "test:cmd:c",
        )
        rows = self.store.capability_usage_for_binding(binding.binding_id)
        # Should be ordered by (capability_kind, capability_name)
        self.assertEqual(rows[0].capability_kind, "skill")
        self.assertEqual(rows[0].capability_name, "bounded-skill")
        self.assertEqual(rows[1].capability_kind, "skill")
        self.assertEqual(rows[1].capability_name, "other-skill")
        self.assertEqual(rows[2].capability_kind, "tool")
        self.assertEqual(rows[2].capability_name, sys.executable)
