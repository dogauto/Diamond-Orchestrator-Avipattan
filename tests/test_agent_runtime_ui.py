"""Read-only UI projection tests for the controller-owned agent runtime spine.

These tests exercise the UI adapter's read-only projections over the agent runtime
ledger. They require the ui_adapter, runtime_ui, and ui_streaming modules.
"""

from __future__ import annotations

import unittest

from support import ProjectCase

from diamond.agent_runtime import ChildOutcome, DeliveryStatus
from diamond.domain import Provider, Role, TaskSpec
from diamond.evidence import AttemptStatus, ExecutionAttempt, EvidenceRecord, digest_text
from diamond.errors import ConflictError, ExecutionGuardError, NotFoundError, ValidationError
from diamond.fake_child_adapter import DeterministicChildAdapter
from diamond.paths import resolve_paths
from diamond.store import EventStore
from diamond.ui_adapter import UiAdapter, UiAgent, UiMessage, UiReceipt, UiSession
from diamond.validation import canonical_json, utc_now


class AgentRuntimeUITests(ProjectCase):
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

    def test_read_only_ui_exposes_runtime_records(self) -> None:
        result = self.run_fake()
        adapter = UiAdapter(str(self.project), str(self.project / "config" / "diamond.toml"))
        try:
            status = adapter.project_status()
            self.assertEqual(len(status["agents"]), 2)
            self.assertEqual(len(status["sessions"]), 2)
            self.assertIsInstance(adapter.agents()[0], UiAgent)
            self.assertIsInstance(adapter.sessions()[0], UiSession)
            messages = adapter.conversation_messages(result.conversation_id)
            self.assertEqual([item.sequence_no for item in messages], [1, 2])
            self.assertTrue(all(isinstance(item, UiMessage) for item in messages))
            receipt = adapter.completion_receipt(self.delegation)
            self.assertIsInstance(receipt, UiReceipt)
            self.assertTrue(receipt.accepted)
        finally:
            adapter.close()


if __name__ == "__main__":
    unittest.main()