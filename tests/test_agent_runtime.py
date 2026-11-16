"""Isolated regression tests for the controller-owned agent runtime spine."""

from __future__ import annotations

import subprocess
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from support import ProjectCase

from diamond.agent_runtime import ChildOutcome, DeliveryStatus
from diamond.domain import Provider, Role, TaskSpec
from diamond.evidence import AttemptStatus, ExecutionAttempt, EvidenceRecord, digest_text
from diamond.errors import ConflictError, ExecutionGuardError, NotFoundError, ValidationError
from diamond.fake_child_adapter import DeterministicChildAdapter
from diamond.paths import resolve_paths
from diamond.store import EventStore
from diamond.validation import canonical_json, utc_now


class AgentRuntimeTests(ProjectCase):
    def setUp(self) -> None:
        super().setUp()
        self.database = self.project / ".diamond" / "diamond.sqlite3"
        self.store = EventStore(self.database)
        self.parent_task = "a" * 32
        self.child_task = "b" * 32
        self.parent_attempt = "c" * 32
        self.child_attempt = "d" * 32
        self.parent_agent = "1" * 32
        self.child_agent = "2" * 32
        self.parent_session = "3" * 32
        self.delegation = "4" * 32

        self.store.create(TaskSpec(self.parent_task, "parent objective", Role.BUILDER, Provider.CLAUDE), "task:parent")
        self.store.create(TaskSpec(self.child_task, "child objective", Role.RESEARCHER, Provider.CODEX), "task:child")
        self.store.begin_attempt(ExecutionAttempt(
            self.parent_attempt, self.parent_task, 1, Role.BUILDER, Provider.CLAUDE,
            "claude", str(self.project), AttemptStatus.INTENDED, utc_now()), "attempt:parent")
        self.store.begin_attempt(ExecutionAttempt(
            self.child_attempt, self.child_task, 1, Role.RESEARCHER, Provider.CODEX,
            "codex", str(self.project), AttemptStatus.INTENDED, utc_now()), "attempt:child")
        self.store.register_agent(self.parent_agent, "parent-agent", Role.BUILDER, Provider.CLAUDE,
                                 "fake:parent", self.parent_task, "agent:parent", attempt_id=self.parent_attempt)
        self.store.register_agent(self.child_agent, "child-agent", Role.RESEARCHER, Provider.CODEX,
                                 DeterministicChildAdapter.adapter_id, self.child_task, "agent:child",
                                 attempt_id=self.child_attempt, parent_agent_id=self.parent_agent)
        self.store.create_agent_session(self.parent_session, self.parent_agent, Provider.CLAUDE,
                                       "fake:parent", "session:parent")
        self.store.authorize_delegation(
            self.delegation, self.parent_task, self.parent_attempt, self.parent_agent,
            self.child_task, Role.RESEARCHER, Provider.CODEX, DeterministicChildAdapter.adapter_id,
            "delegation:authorize", child_attempt_id=self.child_attempt,
        )

    def run_fake(self, *, outcome: ChildOutcome = ChildOutcome.SUCCEEDED):
        return DeterministicChildAdapter().run(
            self.store, self.delegation, self.parent_session, self.child_agent,
            "fake:child", {"type": "request", "objective": "inspect"}, outcome=outcome,
        )

    def test_full_vertical_slice_reopens_with_ordered_messages_and_receipt(self) -> None:
        result = self.run_fake()
        self.assertTrue(result.receipt.accepted)
        self.assertEqual([message.sequence_no for message, _ in self.store.conversation_messages(result.conversation_id)], [1, 2])
        self.assertEqual({delivery.status for _, delivery in self.store.conversation_messages(result.conversation_id)}, {DeliveryStatus.ACKNOWLEDGED})

        reopened = EventStore(self.database)
        receipt = reopened.completion_receipt(self.delegation)
        messages = reopened.conversation_messages(result.conversation_id)
        self.assertEqual(receipt, result.receipt)
        self.assertEqual([item[0].message_id for item in messages], [result.request.message_id, result.response.message_id])
        self.assertEqual(reopened.agent_identity(self.child_agent).parent_agent_id, self.parent_agent)
        self.assertEqual(reopened.agent_session(result.session_id).status.value, "SUCCEEDED")

    def test_invalid_parent_and_unverified_child_are_rejected(self) -> None:
        with self.assertRaises(ConflictError):
            self.store.authorize_delegation(
                "5" * 32, self.child_task, self.parent_attempt, self.parent_agent,
                self.parent_task, Role.BUILDER, Provider.CLAUDE, "fake:parent", "delegation:bad-parent",
            )
        session = self.store.child_session(self.delegation, "5" * 32, self.child_agent, "session:child")
        self.store.create_conversation("6" * 32, self.delegation, self.parent_session, session.session_id, "conversation:test")
        payload = canonical_json({"result": "ok"})
        evidence = EvidenceRecord("7" * 32, self.child_attempt, "child_completion", utc_now(), payload, digest_text(payload))
        self.store.record_evidence(evidence, "evidence:test")
        with self.assertRaises(ExecutionGuardError):
            self.store.complete_child(self.delegation, session.session_id, ChildOutcome.SUCCEEDED,
                                      evidence.digest_sha256, "complete:unverified")

    def test_completion_rejects_evidence_for_the_wrong_child_or_outcome(self) -> None:
        session = self.store.child_session(self.delegation, "5" * 32, self.child_agent, "session:child")
        self.store.verify_session_identity(session.session_id, {"fake": True}, "identity:child")
        self.store.create_conversation("6" * 32, self.delegation, self.parent_session, session.session_id, "conversation:test")
        payload = canonical_json({"session_id": "f" * 32, "outcome": "FAILED", "identity_verified": True})
        evidence = EvidenceRecord("7" * 32, self.child_attempt, "child_completion", utc_now(), payload, digest_text(payload))
        self.store.record_evidence(evidence, "evidence:test")
        with self.assertRaises(ExecutionGuardError):
            self.store.complete_child(self.delegation, session.session_id, ChildOutcome.SUCCEEDED,
                                      evidence.digest_sha256, "complete:mismatched-evidence")

    def test_message_idempotency_delivery_and_bounds(self) -> None:
        child_session = self.store.child_session(self.delegation, "5" * 32, self.child_agent, "session:child")
        self.store.verify_session_identity(child_session.session_id, {"fake": True}, "identity:child")
        self.store.create_conversation("6" * 32, self.delegation, self.parent_session, child_session.session_id, "conversation:test")
        first = self.store.send_agent_message("6" * 32, self.parent_session, child_session.session_id,
                                              {"n": 1}, "corr:1", "idem:1", "message:one")
        duplicate = self.store.send_agent_message("6" * 32, self.parent_session, child_session.session_id,
                                                  {"n": 1}, "corr:1", "idem:1", "message:one-retry")
        self.assertEqual(first, duplicate)
        delivered = self.store.mark_message_delivered(first.message_id, "delivery:one")
        self.assertEqual(delivered.status, DeliveryStatus.DELIVERED)
        self.assertEqual(self.store.acknowledge_message(first.message_id, "ack:one").status, DeliveryStatus.ACKNOWLEDGED)
        failed = self.store.send_agent_message("6" * 32, self.parent_session, child_session.session_id,
                                              {"n": 2}, "corr:2", "idem:2", "message:two")
        self.assertEqual(self.store.fail_message(failed.message_id, "child session unavailable", "failure:two").status,
                         DeliveryStatus.FAILED)
        with self.assertRaises(ValidationError):
            self.store.send_agent_message("6" * 32, self.parent_session, child_session.session_id,
                                          {"body": "x" * 70_000}, "corr:large", "idem:large", "message:large")

    def test_uncertain_completion_is_terminal_and_not_relaunched(self) -> None:
        result = self.run_fake(outcome=ChildOutcome.UNCERTAIN)
        self.assertFalse(result.receipt.accepted)
        self.assertEqual(self.store.delegation(self.delegation).status.value, "UNCERTAIN")
        with self.assertRaises(ConflictError):
            self.store.child_session(self.delegation, "5" * 32, self.child_agent, "session:relaunch")

    def test_cancelled_child_and_failed_delivery_are_explicit_terminal_states(self) -> None:
        result = self.run_fake(outcome=ChildOutcome.CANCELLED)
        self.assertFalse(result.receipt.accepted)
        self.assertEqual(self.store.agent_session(result.session_id).status.value, "CANCELLED")
        child_session = self.store.agent_sessions(self.child_task)[0]
        self.assertEqual(child_session.session_id, result.session_id)
        with self.assertRaises(ConflictError):
            self.store.child_session(self.delegation, "5" * 32, self.child_agent, "session:after-cancel")


    def test_fake_adapter_never_invokes_a_provider(self) -> None:
        with patch.object(subprocess, "run", side_effect=AssertionError("provider invocation")):
            result = self.run_fake()
        self.assertTrue(result.receipt.accepted)

    def test_duplicate_session_creation_and_receipt_commands_are_idempotent(self) -> None:
        child_session = self.store.child_session(self.delegation, "5" * 32, self.child_agent, "session:child")
        self.assertEqual(self.store.child_session(self.delegation, child_session.session_id, self.child_agent, "session:child"), child_session)
        self.store.verify_session_identity(child_session.session_id, {"fake": True}, "identity:child")
        self.store.create_conversation("6" * 32, self.delegation, self.parent_session, child_session.session_id, "conversation:test")
        request = self.store.send_agent_message("6" * 32, self.parent_session, child_session.session_id,
                                               {"n": 1}, "corr:1", "idem:1", "message:one")
        self.store.mark_message_delivered(request.message_id, "delivery:one")
        self.store.acknowledge_message(request.message_id, "ack:one")
        payload = canonical_json({"ok": True, "session_id": child_session.session_id,
                                 "outcome": ChildOutcome.SUCCEEDED.value, "identity_verified": True})
        evidence = EvidenceRecord("7" * 32, self.child_attempt, "child_completion", utc_now(), payload, digest_text(payload))
        self.store.record_evidence(evidence, "evidence:test")
        # A response is required before controller acceptance.
        response = self.store.send_agent_message("6" * 32, child_session.session_id, self.parent_session,
                                                 {"ok": True}, "corr:2", "idem:2", "message:two")
        self.store.mark_message_delivered(response.message_id, "delivery:two")
        self.store.acknowledge_message(response.message_id, "ack:two")
        receipt = self.store.complete_child(self.delegation, child_session.session_id, ChildOutcome.SUCCEEDED,
                                            evidence.digest_sha256, "complete:child")
        self.assertEqual(self.store.complete_child(self.delegation, child_session.session_id, ChildOutcome.SUCCEEDED,
                                                   evidence.digest_sha256, "complete:child"), receipt)


if __name__ == "__main__":
    unittest.main()