"""Scheduler integration with the controller-owned generic execution path."""

from __future__ import annotations

import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest.mock import MagicMock, patch

from diamond.controller_dispatcher import PersistedControllerDispatcher, PersistedLaunch
from diamond.domain import Provider, Role, TaskSpec, TaskStatus
from diamond.evidence import AttemptStatus, ExecutionAttempt, EvidenceRecord
from diamond.errors import ConflictError, ExecutionGuardError
from diamond.orchestration import OrchestrationLifecycle
from diamond.policy_ipc import AttemptRevocationResult
from diamond.policy_ipc import AttemptRevocationResult
from diamond.packets import OutputContract, PacketContext, TaskPacket
from diamond.provider_discovery import DiscoveryRecord, DiscoveryState
from diamond.provider_execution import ExecutionOutcome
from diamond.provider_gateway import ProviderExecutionGateway
from diamond.provider_metadata import ProviderMetadataRecord
from diamond.provider_registry import ProviderRegistry
from diamond.orchestration import run_persisted_graph
from diamond.scheduler import SchedulerOutcome
from diamond.skills import SkillRegistry
from diamond.store import EventStore
from diamond.validation import utc_now
from tests.support import ProjectCase
from tests.test_generic_execution import CountingAdapter


class PersistedSchedulerTests(ProjectCase):
    def setUp(self) -> None:
        super().setUp()
        self.store = EventStore(self.project / ".diamond" / "diamond.sqlite3")
        self.context = PacketContext(1, "1" * 64, "2" * 64, "3" * 64)
        self.adapter = CountingAdapter()
        self.registry = ProviderRegistry()
        self.registry.register(
            self.adapter.manifest,
            sys.executable,
            self.adapter.adapter_id,
            self.adapter,
        )
        self.registry.record_discovery(
            DiscoveryRecord(
                "synthetic-cli",
                self.adapter.adapter_id,
                sys.executable,
                sys.executable,
                DiscoveryState.DISCOVERED,
                version="1.0.0",
                returncode=0,
            )
        )
        from diamond.provider_contracts import (
            Capability,
            ManifestValidationResult,
            ManifestValidationStatus,
        )

        self.registry.record_validation(
            "synthetic-cli",
            ManifestValidationResult(True, ManifestValidationStatus.VALIDATED, "validated"),
            (Capability.ONE_SHOT_EXECUTION, Capability.TIMEOUT_ENFORCEMENT),
        )
        self.registry.mark_available("synthetic-cli")
        self.registry.record_authorization("synthetic-cli", True, ("scheduler test",))
        self.gateway = ProviderExecutionGateway(self.registry)
        self.metadata = ProviderMetadataRecord.from_descriptor(
            self.registry.get("synthetic-cli"), utc_now()
        )

    def launch(self, spec: TaskSpec, attempt_id: str) -> PersistedLaunch:
        self.store.create(spec, f"scheduler-create-{spec.task_id}")
        if not self.store.provider_metadata_list():
            self.store.register_provider_metadata(self.metadata, "scheduler-metadata")
        packet = TaskPacket.from_task_spec(
            spec,
            attempt_id,
            self.project,
            1,
            self.context.plan_digest,
            self.context.base_digest,
            self.context.config_digest,
            SkillRegistry(()),
            (),
            OutputContract("text", (), 4096),
        )
        # Check if TaskPacket has provider_id/adapter_id fields (new format)
        if hasattr(packet, 'provider_id'):
            # New format with provider_id and adapter_id
            packet = replace(
                packet,
                provider_id="synthetic-cli",
                adapter_id=self.adapter.adapter_id,
            )
        else:
            # Legacy format - use provider instead
            packet = replace(
                packet,
                provider="Provider.synthetic_cli" if "synthetic_cli" in Provider.__members__ else Provider.CLAUDE,
                provider_tools=("synthetic-cli",) if "synthetic-cli" in Provider.__members__ else (),
            )
        attempt = ExecutionAttempt(
            packet.attempt_id,
            spec.task_id,
            1,
            spec.role,
            spec.provider,
            sys.executable,
            packet.workspace_root,
            AttemptStatus.INTENDED,
            utc_now(),
        )
        return PersistedLaunch(
            self.store,
            packet,
            attempt,
            None,
            self.project,
            "scheduler-test-owner",
            SkillRegistry(()),
            self.context,
            provider_gateway=self.gateway,
        )

    def dispatcher_for(self, *launches: PersistedLaunch) -> PersistedControllerDispatcher:
        return PersistedControllerDispatcher(
            {launch.packet.task_id: launch for launch in launches}
        )

    def test_scheduler_reaches_generic_gateway_and_persists_result(self) -> None:
        task_id = "a" * 32
        spec = TaskSpec(task_id, "run one generic task", Role.QA, Provider.CLAUDE)
        launch = self.launch(spec, "b" * 32)

        result = run_persisted_graph({task_id: spec}, {task_id: launch})

        self.assertEqual(result.outcome, SchedulerOutcome.SUCCESS)
        self.assertEqual(result.results[task_id].status, TaskStatus.SUCCEEDED)
        self.assertEqual(self.adapter.execute_calls, 1)
        self.assertEqual(self.store.get_attempt(launch.attempt.attempt_id).status, AttemptStatus.SUCCEEDED)
        self.assertEqual(len(self.store.evidence(task_id)), 3)
        self.assertEqual(result.results[task_id].metadata["dispatch_path"], "persisted_controller")

    def test_dependent_dispatch_requires_scheduler_proof_and_runs_after_success(self) -> None:
        first_id = "a" * 32
        second_id = "b" * 32
        first = TaskSpec(first_id, "first", Role.QA, Provider.CLAUDE)
        second = TaskSpec(
            second_id,
            "second",
            Role.QA,
            Provider.CLAUDE,
            dependencies=(first_id,),
        )
        first_launch = self.launch(first, "c" * 32)
        second_launch = self.launch(second, "d" * 32)
        dispatcher = self.dispatcher_for(first_launch, second_launch)

        with self.assertRaises(ExecutionGuardError):
            dispatcher.dispatch(second)
        self.assertEqual(self.adapter.execute_calls, 0)

        result = run_persisted_graph(
            {first_id: first, second_id: second},
            {first_id: first_launch, second_id: second_launch},
        )

        self.assertEqual(result.outcome, SchedulerOutcome.SUCCESS)
        self.assertEqual(result.ordered, [first_id, second_id])
        self.assertEqual(self.adapter.execute_calls, 2)
        self.assertEqual(
            self.store.get_attempt(second_launch.attempt.attempt_id).status,
            AttemptStatus.SUCCEEDED,
        )

    def test_failed_prerequisite_blocks_dependent_at_production_boundary(self) -> None:
        first_id = "a" * 32
        second_id = "b" * 32
        first = TaskSpec(first_id, "first", Role.QA, Provider.CLAUDE)
        second = TaskSpec(second_id, "second", Role.QA, Provider.CLAUDE, dependencies=(first_id,))
        first_launch = self.launch(first, "c" * 32)
        second_launch = self.launch(second, "d" * 32)
        self.adapter.outcome = ExecutionOutcome.FAILED

        result = run_persisted_graph(
            {first_id: first, second_id: second},
            {first_id: first_launch, second_id: second_launch},
        )

        self.assertEqual(result.outcome, SchedulerOutcome.PARTIAL)
        self.assertEqual(result.results[first_id].status, TaskStatus.FAILED)
        self.assertNotIn(second_id, result.results)
        self.assertEqual(self.adapter.execute_calls, 1)
        self.assertEqual(self.store.attempts(second_id), ())

    def test_ambiguous_provider_result_blocks_dependents(self) -> None:
        first_id = "a" * 32
        second_id = "b" * 32
        first = TaskSpec(first_id, "first", Role.QA, Provider.CLAUDE)
        second = TaskSpec(
            second_id,
            "second",
            Role.QA,
            Provider.CLAUDE,
            dependencies=(first_id,),
        )
        first_launch = self.launch(first, "c" * 32)
        second_launch = self.launch(second, "d" * 32)
        self.adapter.outcome = ExecutionOutcome.UNKNOWN

        result = run_persisted_graph(
            {first_id: first, second_id: second},
            {first_id: first_launch, second_id: second_launch},
        )

        self.assertEqual(result.outcome, SchedulerOutcome.PARTIAL)
        self.assertEqual(result.results[first_id].status, TaskStatus.FAILED)
        self.assertNotIn(second_id, result.results)
        self.assertEqual(self.store.get_attempt(first_launch.attempt.attempt_id).status, AttemptStatus.AMBIGUOUS)
        self.assertEqual(self.store.attempts(second_id), ())

    def test_restart_resumes_successful_prerequisite_without_rerunning_it(self) -> None:
        first_id = "a" * 32
        second_id = "b" * 32
        first = TaskSpec(first_id, "first", Role.QA, Provider.CLAUDE)
        second = TaskSpec(second_id, "second", Role.QA, Provider.CLAUDE, dependencies=(first_id,))
        first_launch = self.launch(first, "c" * 32)
        second_launch = self.launch(second, "d" * 32)

        initial = run_persisted_graph({first_id: first}, {first_id: first_launch})
        self.assertEqual(initial.results[first_id].status, TaskStatus.SUCCEEDED)

        reopened = EventStore(self.store.database)
        first_launch = replace(first_launch, store=reopened)
        second_launch = replace(second_launch, store=reopened)
        result = run_persisted_graph(
            {first_id: first, second_id: second},
            {first_id: first_launch, second_id: second_launch},
        )

        self.assertEqual(result.outcome, SchedulerOutcome.SUCCESS)
        self.assertEqual(result.ordered, [first_id, second_id])
        self.assertEqual(result.results[first_id].metadata["resumed_from_ledger"], True)
        self.assertEqual(self.adapter.execute_calls, 2)

    def test_restart_with_ambiguous_attempt_does_not_rerun_or_unlock(self) -> None:
        first_id = "a" * 32
        second_id = "b" * 32
        first = TaskSpec(first_id, "first", Role.QA, Provider.CLAUDE)
        second = TaskSpec(second_id, "second", Role.QA, Provider.CLAUDE, dependencies=(first_id,))
        first_launch = self.launch(first, "c" * 32)
        second_launch = self.launch(second, "d" * 32)
        self.adapter.outcome = ExecutionOutcome.UNKNOWN

        initial = run_persisted_graph({first_id: first}, {first_id: first_launch})
        self.assertEqual(initial.results[first_id].status, TaskStatus.FAILED)
        self.assertEqual(self.store.get_attempt(first_launch.attempt.attempt_id).status, AttemptStatus.AMBIGUOUS)

        self.adapter.outcome = ExecutionOutcome.SUCCEEDED
        reopened = EventStore(self.store.database)
        result = run_persisted_graph(
            {first_id: first, second_id: second},
            {
                first_id: replace(first_launch, store=reopened),
                second_id: replace(second_launch, store=reopened),
            },
        )

        self.assertEqual(result.outcome, SchedulerOutcome.PARTIAL)
        self.assertEqual(result.results[first_id].metadata["attempt_status"], AttemptStatus.AMBIGUOUS.value)
        self.assertNotIn(second_id, result.results)
        self.assertEqual(self.adapter.execute_calls, 1)

    def test_replaying_same_launch_does_not_execute_adapter_twice(self) -> None:
        task_id = "a" * 32
        spec = TaskSpec(task_id, "run once", Role.QA, Provider.CLAUDE)
        launch = self.launch(spec, "b" * 32)
        dispatcher = self.dispatcher_for(launch)

        first = dispatcher.dispatch(spec)
        self.assertEqual(first.status, TaskStatus.SUCCEEDED)
        with self.assertRaises(ConflictError):
            dispatcher.dispatch(spec)
        self.assertEqual(self.adapter.execute_calls, 1)

    def test_revoked_registered_binding_blocks_before_adapter_execution(self) -> None:
        task_id = "a" * 32
        spec = TaskSpec(task_id, "revoked provider", Role.QA, Provider.CLAUDE)
        launch = self.launch(spec, "b" * 32)
        self.registry.invalidate("synthetic-cli", "test revocation")

        result = run_persisted_graph({task_id: spec}, {task_id: launch})

        self.assertEqual(result.outcome, SchedulerOutcome.PARTIAL)
        self.assertEqual(result.results[task_id].status, TaskStatus.FAILED)
        self.assertEqual(self.adapter.execute_calls, 0)
        self.assertEqual(self.store.attempts(task_id), ())

    def test_exception_during_run_persisted_still_revokes_attempt(self) -> None:
        task_id = "a" * 32
        spec = TaskSpec(task_id, "exception path", Role.QA, Provider.CLAUDE)
        launch = self.launch(spec, "b" * 32)
        launch = replace(launch, lifecycle=None)
        dispatcher = self.dispatcher_for(launch)

        with patch("diamond.controller_dispatcher.run_persisted", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                dispatcher.dispatch(spec)
        # No lifecycle means nothing to revoke; verify no crash and no
        # adapter call.
        self.assertEqual(self.adapter.execute_calls, 0)

    def test_exception_during_run_persisted_revokes_when_lifecycle_attached(self) -> None:
        from diamond.orchestration import OrchestrationLifecycle

        task_id = "a" * 32
        spec = TaskSpec(task_id, "exception path with lifecycle", Role.QA, Provider.CLAUDE)
        launch = self.launch(spec, "b" * 32)
        lifecycle = OrchestrationLifecycle()
        # Register a fake IPC context so revoke_attempt has something to pop.
        fake_ctx = MagicMock()
        fake_ctx.revoke.return_value = AttemptRevocationResult.REVOKED
        lifecycle.register_attempt(launch.attempt.attempt_id, fake_ctx)
        launch = replace(launch, lifecycle=lifecycle)
        dispatcher = self.dispatcher_for(launch)

        with patch("diamond.controller_dispatcher.run_persisted", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                dispatcher.dispatch(spec)

        # run_persisted raised, but the dispatcher's exception path must
        # have revoked the attempt so no stale capability remains.
        # Authority is invalidated (revoke() called); the context is
        # retained in _cleanup_pending for retryability.
        self.assertEqual(lifecycle.active_attempt_ids(), ())
        self.assertEqual(lifecycle.cleanup_failed_ids(), ())
        self.assertIn(launch.attempt.attempt_id, lifecycle._permanently_revoked)
        fake_ctx.revoke.assert_called_once()

    def test_concurrent_dispatch_has_one_durable_winner(self) -> None:
        task_id = "a" * 32
        spec = TaskSpec(task_id, "one winner", Role.QA, Provider.CLAUDE)
        launch = self.launch(spec, "b" * 32)
        started = threading.Event()
        release = threading.Event()
        original_execute = self.adapter.execute

        def gated_execute(request):
            started.set()
            if not release.wait(timeout=5):
                raise AssertionError("controlled adapter release was not signalled")
            return original_execute(request)

        self.adapter.execute = gated_execute
        first = PersistedControllerDispatcher({task_id: launch})
        second = PersistedControllerDispatcher({task_id: launch})
        with ThreadPoolExecutor(max_workers=2) as pool:
            first_future = pool.submit(first.dispatch, spec)
            self.assertTrue(started.wait(timeout=5))
            second_future = pool.submit(second.dispatch, spec)
            with self.assertRaises(ConflictError):
                second_future.result(timeout=5)
            release.set()
            winner = first_future.result(timeout=5)

        self.assertEqual(winner.status, TaskStatus.SUCCEEDED)
        self.assertEqual(self.adapter.execute_calls, 1)
        self.assertEqual(len(self.store.dispatch_claims(task_id)), 1)


class PersistenceRetryTests(ProjectCase):
    """G5.2.2.4.1 — lifecycle observability and cleanup retry (tests 17-32)."""

    def setUp(self) -> None:
        super().setUp()
        self.store = EventStore(self.project / ".diamond" / "diamond.sqlite3")
        self.context = PacketContext(1, "1" * 64, "2" * 64, "3" * 64)
        self.adapter = CountingAdapter()
        self.registry = ProviderRegistry()
        self.registry.register(
            self.adapter.manifest,
            sys.executable,
            self.adapter.adapter_id,
            self.adapter,
        )
        self.registry.record_discovery(
            DiscoveryRecord(
                "synthetic-cli",
                self.adapter.adapter_id,
                sys.executable,
                sys.executable,
                DiscoveryState.DISCOVERED,
                version="1.0.0",
                returncode=0,
            )
        )
        from diamond.provider_contracts import (
            Capability,
            ManifestValidationResult,
            ManifestValidationStatus,
        )
        self.registry.record_validation(
            "synthetic-cli",
            ManifestValidationResult(True, ManifestValidationStatus.VALIDATED, "validated"),
            (Capability.ONE_SHOT_EXECUTION, Capability.TIMEOUT_ENFORCEMENT),
        )
        self.registry.mark_available("synthetic-cli")
        self.registry.record_authorization("synthetic-cli", True, ("persistence retry test",))
        self.gateway = ProviderExecutionGateway(self.registry)
        from diamond.provider_metadata import ProviderMetadataRecord
        from diamond.validation import utc_now
        self.metadata = ProviderMetadataRecord.from_descriptor(
            self.registry.get("synthetic-cli"), utc_now()
        )

    def launch(self, spec: TaskSpec, attempt_id: str) -> PersistedLaunch:
        self.store.create(spec, f"persist-retry-create-{spec.task_id}")
        if not self.store.provider_metadata_list():
            self.store.register_provider_metadata(self.metadata, "persist-metadata")
        packet = TaskPacket.from_task_spec(
            spec,
            attempt_id,
            self.project,
            1,
            self.context.plan_digest,
            self.context.base_digest,
            self.context.config_digest,
            SkillRegistry(()),
            (),
            OutputContract("text", (), 4096),
        )
        if hasattr(packet, 'provider_id'):
            packet = replace(packet, provider_id="synthetic-cli", adapter_id=self.adapter.adapter_id)
        else:
            packet = replace(packet, provider=Provider.CLAUDE, provider_tools=())
        attempt = ExecutionAttempt(
            packet.attempt_id, spec.task_id, 1, spec.role, spec.provider,
            sys.executable, packet.workspace_root, AttemptStatus.INTENDED, utc_now(),
        )
        return PersistedLaunch(
            self.store, packet, attempt, None, self.project,
            "persist-retry-owner", SkillRegistry(()), self.context,
            provider_gateway=self.gateway,
        )

    def dispatcher_for(self, *launches: PersistedLaunch) -> PersistedControllerDispatcher:
        return PersistedControllerDispatcher({launch.packet.task_id: launch for launch in launches})

    # 17. CancelledError triggers per-attempt revocation
    def test_cancelled_error_triggers_per_attempt_revocation(self) -> None:
        from diamond.orchestration import OrchestrationLifecycle

        task_id = "a" * 32
        spec = TaskSpec(task_id, "cancel path", Role.QA, Provider.CLAUDE)
        launch = self.launch(spec, "b" * 32)
        lifecycle = OrchestrationLifecycle()
        fake_ctx = MagicMock()
        fake_ctx.revoke.return_value = AttemptRevocationResult.REVOKED
        lifecycle.register_attempt(launch.attempt.attempt_id, fake_ctx)
        launch = replace(launch, lifecycle=lifecycle)
        dispatcher = self.dispatcher_for(launch)

        with patch("diamond.controller_dispatcher.run_persisted", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                dispatcher.dispatch(spec)

        # Authority invalidated; context retained in _cleanup_pending for retry
        self.assertEqual(lifecycle.active_attempt_ids(), ())
        self.assertIn(launch.attempt.attempt_id, lifecycle._permanently_revoked)
        fake_ctx.revoke.assert_called_once()

    # 18. Provider process termination precedes revocation
    def test_provider_termination_precedes_revocation(self) -> None:
        """Verify revocation is called AFTER run_persisted returns."""
        from diamond.evidence import AttemptStatus
        from diamond.validation import utc_now

        task_id = "a" * 32
        spec = TaskSpec(task_id, "order check", Role.QA, Provider.CLAUDE)
        launch = self.launch(spec, "b" * 32)
        lifecycle = OrchestrationLifecycle()
        order_log: list[str] = []
        real_ctx = MagicMock()
        real_ctx.revoke.side_effect = lambda: (order_log.append("revoked"), AttemptRevocationResult.REVOKED)[1]
        lifecycle.register_attempt(launch.attempt.attempt_id, real_ctx)
        launch = replace(launch, lifecycle=lifecycle)
        dispatcher = self.dispatcher_for(launch)

        # Create a mock completed attempt with SUCCEEDED status
        completed_attempt = replace(
            launch.attempt,
            status=AttemptStatus.SUCCEEDED,
            completed_at=utc_now(),
        )

        async def ordered_run_persisted(**kwargs):
            order_log.append("run_persisted_completed")
            return (completed_attempt, MagicMock(), MagicMock(), MagicMock())

        with patch("diamond.controller_dispatcher.run_persisted", ordered_run_persisted):
            result = dispatcher.dispatch(spec)

        self.assertEqual(order_log, ["run_persisted_completed", "revoked"])
        self.assertEqual(result.status, TaskStatus.SUCCEEDED)

    # 19. Revocation cannot be interrupted by task cancellation
    def test_revocation_not_interrupted_by_cancellation(self) -> None:
        from diamond.evidence import AttemptStatus
        from diamond.validation import utc_now

        task_id = "a" * 32
        spec = TaskSpec(task_id, "interrupt check", Role.QA, Provider.CLAUDE)
        launch = self.launch(spec, "b" * 32)
        lifecycle = OrchestrationLifecycle()
        fake_ctx = MagicMock()
        fake_ctx.revoke.return_value = AttemptRevocationResult.REVOKED
        lifecycle.register_attempt(launch.attempt.attempt_id, fake_ctx)
        launch = replace(launch, lifecycle=lifecycle)
        dispatcher = self.dispatcher_for(launch)

        completed_attempt = replace(
            launch.attempt,
            status=AttemptStatus.SUCCEEDED,
            completed_at=utc_now(),
        )
        with patch("diamond.controller_dispatcher.run_persisted", return_value=(
            completed_attempt, MagicMock(), MagicMock(), MagicMock()
        )):
            result = dispatcher.dispatch(spec)

        self.assertTrue(fake_ctx.revoke.called)
        self.assertEqual(result.status, TaskStatus.SUCCEEDED)
        self.assertEqual(lifecycle.active_attempt_ids(), ())

    # 20. Original execution exception is preserved
    def test_original_exception_preserved_after_exception_path_revocation(self) -> None:
        task_id = "a" * 32
        spec = TaskSpec(task_id, "exception preservation", Role.QA, Provider.CLAUDE)
        launch = self.launch(spec, "b" * 32)
        lifecycle = OrchestrationLifecycle()
        fake_ctx = MagicMock()
        fake_ctx.revoke.return_value = AttemptRevocationResult.REVOKED
        lifecycle.register_attempt(launch.attempt.attempt_id, fake_ctx)
        launch = replace(launch, lifecycle=lifecycle)
        dispatcher = self.dispatcher_for(launch)

        try:
            with patch("diamond.controller_dispatcher.run_persisted", side_effect=RuntimeError("original error")):
                dispatcher.dispatch(spec)
            self.fail("Expected RuntimeError to propagate")
        except RuntimeError as exc:
            self.assertEqual(str(exc), "original error")
            fake_ctx.revoke.assert_called_once()

    # 21. Revocation failure is observable via cleanup_failed_ids()
    def test_revocation_failure_is_obserable_via_cleanup_failed(self) -> None:
        from diamond.orchestration import OrchestrationLifecycle

        task_id = "a" * 32
        spec = TaskSpec(task_id, "failure observable", Role.QA, Provider.CLAUDE)
        launch = self.launch(spec, "b" * 32)
        lifecycle = OrchestrationLifecycle()
        fake_ctx = MagicMock()
        fake_ctx.revoke.side_effect = RuntimeError("server already dead")
        lifecycle.register_attempt(launch.attempt.attempt_id, fake_ctx)
        launch = replace(launch, lifecycle=lifecycle)
        dispatcher = self.dispatcher_for(launch)

        with patch("diamond.controller_dispatcher.run_persisted", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                dispatcher.dispatch(spec)

        failed = lifecycle.cleanup_failed_ids()
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0][0], launch.attempt.attempt_id)
        self.assertEqual(failed[0][1], AttemptRevocationResult.CLEANUP_FAILED)
        self.assertIn(launch.attempt.attempt_id, lifecycle._cleanup_pending)
        self.assertIn(launch.attempt.attempt_id, lifecycle._permanently_revoked)
        self.assertEqual(lifecycle.active_attempt_ids(), ())

    # 22. Failed resource cleanup retains retryable context
    def test_failed_cleanup_retains_retryable_context(self) -> None:
        task_id = "a" * 32
        spec = TaskSpec(task_id, "retryable context", Role.QA, Provider.CLAUDE)
        launch = self.launch(spec, "b" * 32)
        lifecycle = OrchestrationLifecycle()
        fake_ctx = MagicMock()
        fake_ctx.revoke.side_effect = RuntimeError("bad socket")
        lifecycle.register_attempt(launch.attempt.attempt_id, fake_ctx)
        launch = replace(launch, lifecycle=lifecycle)
        dispatcher = self.dispatcher_for(launch)

        with patch("diamond.controller_dispatcher.run_persisted", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                dispatcher.dispatch(spec)

        self.assertIn(launch.attempt.attempt_id, lifecycle._cleanup_pending)
        ctx_stored, result_stored = lifecycle._cleanup_pending[launch.attempt.attempt_id]
        self.assertIs(ctx_stored, fake_ctx)
        self.assertEqual(result_stored, AttemptRevocationResult.CLEANUP_FAILED)

    # 23. Cleanup retry succeeds without restoring authority
    def test_cleanup_retry_succeeds_without_restoring_authority(self) -> None:
        task_id = "a" * 32
        spec = TaskSpec(task_id, "retry success", Role.QA, Provider.CLAUDE)
        launch = self.launch(spec, "b" * 32)
        lifecycle = OrchestrationLifecycle()
        call_count = [0]
        def conditional_revoke():
            call_count[0] += 1
            if call_count[0] == 1:
                raise RuntimeError("transient")
            return AttemptRevocationResult.REVOKED
        fake_ctx = MagicMock()
        fake_ctx.revoke.side_effect = conditional_revoke
        lifecycle.register_attempt(launch.attempt.attempt_id, fake_ctx)
        launch = replace(launch, lifecycle=lifecycle)
        dispatcher = self.dispatcher_for(launch)

        with patch("diamond.controller_dispatcher.run_persisted", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                dispatcher.dispatch(spec)

        outcomes = lifecycle.retry_cleanup_failed()
        self.assertEqual(outcomes, {launch.attempt.attempt_id: AttemptRevocationResult.REVOKED})
        self.assertEqual(lifecycle.active_attempt_ids(), ())
        self.assertEqual(lifecycle.cleanup_failed_ids(), ())
        self.assertNotIn(launch.attempt.attempt_id, lifecycle._cleanup_pending)

    # 24. Successful retry clears cleanup-pending state
    def test_successful_retry_clears_cleanup_pending_state(self) -> None:
        task_id = "a" * 32
        spec = TaskSpec(task_id, "clear pending", Role.QA, Provider.CLAUDE)
        launch = self.launch(spec, "b" * 32)
        lifecycle = OrchestrationLifecycle()
        fake_ctx = MagicMock()
        fake_ctx.revoke.side_effect = RuntimeError("first fail")
        lifecycle.register_attempt(launch.attempt.attempt_id, fake_ctx)
        launch = replace(launch, lifecycle=lifecycle)
        dispatcher = self.dispatcher_for(launch)

        with patch("diamond.controller_dispatcher.run_persisted", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                dispatcher.dispatch(spec)

        # Force success on retry
        fake_ctx.revoke.side_effect = None
        fake_ctx.revoke.return_value = AttemptRevocationResult.REVOKED
        outcomes = lifecycle.retry_cleanup_failed()
        self.assertEqual(outcomes, {launch.attempt.attempt_id: AttemptRevocationResult.REVOKED})
        self.assertNotIn(launch.attempt.attempt_id, lifecycle._cleanup_pending)
        self.assertEqual(lifecycle.cleanup_failed_ids(), ())

    # 25. Full runtime shutdown retries pending cleanup
    def test_full_runtime_shutdown_retries_pending_cleanup(self) -> None:
        from diamond.orchestration import OrchestrationLifecycle

        lifecycle = OrchestrationLifecycle()
        fake_ctx_a = MagicMock()
        fake_ctx_a.revoke.side_effect = RuntimeError("fail a")
        fake_ctx_b = MagicMock()
        fake_ctx_b.revoke.return_value = AttemptRevocationResult.REVOKED

        lifecycle.register_attempt("att-a", fake_ctx_a)
        lifecycle.register_attempt("att-b", fake_ctx_b)

        # Simulate partial failure state
        lifecycle._cleanup_pending["att-a"] = (fake_ctx_a, AttemptRevocationResult.CLEANUP_FAILED)
        lifecycle._cleanup_pending["att-b"] = (fake_ctx_b, AttemptRevocationResult.REVOKED)

        outcomes = lifecycle.retry_cleanup_failed()
        self.assertIn("att-a", outcomes)
        self.assertIn("att-b", outcomes)
        self.assertEqual(outcomes["att-b"], AttemptRevocationResult.REVOKED)

    # 26. Revocation events are persisted to store
    def test_revocation_events_persisted_to_store(self) -> None:
        from diamond.evidence import AttemptStatus
        from diamond.validation import utc_now

        task_id = "a" * 32
        spec = TaskSpec(task_id, "event persistence", Role.QA, Provider.CLAUDE)
        launch = self.launch(spec, "b" * 32)
        lifecycle = OrchestrationLifecycle()
        fake_ctx = MagicMock()
        fake_ctx.revoke.return_value = AttemptRevocationResult.REVOKED
        lifecycle.register_attempt(launch.attempt.attempt_id, fake_ctx)
        launch = replace(launch, lifecycle=lifecycle)
        dispatcher = self.dispatcher_for(launch)

        completed_attempt = replace(
            launch.attempt,
            status=AttemptStatus.SUCCEEDED,
            completed_at=utc_now(),
        )
        recorded: list = []
        with patch("diamond.controller_dispatcher.run_persisted", return_value=(
            completed_attempt, MagicMock(), MagicMock(), MagicMock()
        )), patch.object(launch.store, "record_evidence", side_effect=lambda rec, cmd: recorded.append(rec)):
            dispatcher.dispatch(spec)

        revocation_records = [r for r in recorded if r.kind == "revocation_result"]
        self.assertTrue(revocation_records, "no revocation_result evidence recorded")
        self.assertEqual(revocation_records[0].attempt_id, completed_attempt.attempt_id)

    # 27. Duplicate revocation events prevented by idempotency
    def test_duplicate_revocation_events_prevented(self) -> None:
        task_id = "a" * 32
        spec = TaskSpec(task_id, "duplicate prevention", Role.QA, Provider.CLAUDE)
        launch = self.launch(spec, "b" * 32)
        lifecycle = OrchestrationLifecycle()
        fake_ctx = MagicMock()
        fake_ctx.revoke.return_value = AttemptRevocationResult.REVOKED
        lifecycle.register_attempt(launch.attempt.attempt_id, fake_ctx)
        launch = replace(launch, lifecycle=lifecycle)
        dispatcher = self.dispatcher_for(launch)

        completed_attempt = replace(
            launch.attempt,
            status=AttemptStatus.SUCCEEDED,
            completed_at=utc_now(),
        )
        with patch("diamond.controller_dispatcher.run_persisted", return_value=(
            completed_attempt, MagicMock(), MagicMock(), MagicMock()
        )):
            dispatcher.dispatch(spec)

        # Second revocation must be idempotent: ALREADY_REVOKED, not a fresh revoke
        result = lifecycle.revoke_attempt(launch.attempt.attempt_id)
        self.assertEqual(result, AttemptRevocationResult.ALREADY_REVOKED)
        fake_ctx.revoke.assert_called_once()

    # 28. Event persistence failure does not conceal resource cleanup outcome
    def test_evidence_failure_does_not_mask_cleanup(self) -> None:
        from diamond.evidence import AttemptStatus
        from diamond.validation import utc_now

        task_id = "a" * 32
        spec = TaskSpec(task_id, "evidence failure", Role.QA, Provider.CLAUDE)
        launch = self.launch(spec, "b" * 32)
        lifecycle = OrchestrationLifecycle()
        fake_ctx = MagicMock()
        fake_ctx.revoke.return_value = AttemptRevocationResult.REVOKED
        lifecycle.register_attempt(launch.attempt.attempt_id, fake_ctx)
        launch = replace(launch, lifecycle=lifecycle)
        dispatcher = self.dispatcher_for(launch)

        completed_attempt = replace(
            launch.attempt,
            status=AttemptStatus.SUCCEEDED,
            completed_at=utc_now(),
        )
        with patch("diamond.controller_dispatcher.run_persisted", return_value=(
            completed_attempt, MagicMock(), MagicMock(), MagicMock()
        )), patch.object(launch.store, 'record_evidence', side_effect=RuntimeError("store broken")):
            result = dispatcher.dispatch(spec)

        # Dispatch still succeeds despite evidence failure
        self.assertEqual(result.status, TaskStatus.SUCCEEDED)
        # But revocation did happen
        self.assertEqual(lifecycle.active_attempt_ids(), ())
        fake_ctx.revoke.assert_called_once()

    # 29. Multiple cleanup errors captured separately
    def test_multiple_cleanup_errors_captured_separately(self) -> None:
        task_id = "a" * 32
        spec = TaskSpec(task_id, "multiple errors", Role.QA, Provider.CLAUDE)
        launch = self.launch(spec, "b" * 32)
        lifecycle = OrchestrationLifecycle()
        fake_ctx_a = MagicMock()
        fake_ctx_a.revoke.side_effect = RuntimeError("fail a")
        fake_ctx_b = MagicMock()
        fake_ctx_b.revoke.side_effect = RuntimeError("fail b")
        lifecycle.register_attempt(launch.attempt.attempt_id + "a", fake_ctx_a)
        lifecycle.register_attempt(launch.attempt.attempt_id + "b", fake_ctx_b)

        r1 = lifecycle.revoke_attempt(launch.attempt.attempt_id + "a")
        r2 = lifecycle.revoke_attempt(launch.attempt.attempt_id + "b")
        self.assertEqual(r1, AttemptRevocationResult.CLEANUP_FAILED)
        self.assertEqual(r2, AttemptRevocationResult.CLEANUP_FAILED)
        self.assertIn(launch.attempt.attempt_id + "a", lifecycle._cleanup_pending)
        self.assertIn(launch.attempt.attempt_id + "b", lifecycle._cleanup_pending)
        self.assertEqual(len(lifecycle.cleanup_failed_ids()), 2)

    # 30. Other attempts remain active during one cleanup failure
    def test_other_attempts_remain_active_during_cleanup_failure(self) -> None:
        lifecycle = OrchestrationLifecycle()
        bad_ctx = MagicMock()
        bad_ctx.revoke.side_effect = RuntimeError("bad")
        good_ctx = MagicMock()
        good_ctx.revoke.return_value = AttemptRevocationResult.REVOKED

        lifecycle.register_attempt("bad-att", bad_ctx)
        lifecycle.register_attempt("good-att", good_ctx)

        r1 = lifecycle.revoke_attempt("bad-att")
        r2 = lifecycle.revoke_attempt("good-att")

        self.assertEqual(r1, AttemptRevocationResult.CLEANUP_FAILED)
        self.assertEqual(r2, AttemptRevocationResult.REVOKED)
        self.assertEqual(lifecycle.active_attempt_ids(), ())
        self.assertIn("bad-att", lifecycle._cleanup_pending)
        self.assertNotIn("good-att", lifecycle._cleanup_pending)

    # 31. Bootstrap IPC remains active after attempt revocation failure
    def test_bootstrap_ipc_remains_active_after_attempt_failure(self) -> None:
        from diamond.policy_ipc import PolicyIPCServerContext

        lifecycle = OrchestrationLifecycle()
        socket_dir = Path("/var/tmp/diamond-rev-tests")
        socket_dir.mkdir(parents=True, exist_ok=True)

        bootstrap_ctx = PolicyIPCServerContext(
            socket_path=socket_dir / "bootstrap.sock", store=self.store,
            agent_id="controller", task_id="controller-task", attempt_id=None,
            command_prefix="bootstrap",
        )
        bootstrap_ctx.start()
        lifecycle.ipc_context = bootstrap_ctx

        bad_ctx = MagicMock()
        bad_ctx.revoke.side_effect = RuntimeError("fail")
        lifecycle.register_attempt("bad-att", bad_ctx)

        r = lifecycle.revoke_attempt("bad-att")
        self.assertEqual(r, AttemptRevocationResult.CLEANUP_FAILED)
        self.assertIsNotNone(lifecycle.ipc_context)
        self.assertEqual(lifecycle.active_attempt_ids(), ())

    # 32. Repeated cleanup is idempotent
    def test_repeated_cleanup_is_idempotent(self) -> None:
        lifecycle = OrchestrationLifecycle()
        ctx = MagicMock()
        ctx.revoke.side_effect = RuntimeError("always fails")
        lifecycle.register_attempt("att-x", ctx)

        lifecycle.revoke_attempt("att-x")
        self.assertIn("att-x", lifecycle._cleanup_pending)

        # Retry — same failure, no crash
        outcomes = lifecycle.retry_cleanup_failed()
        self.assertEqual(outcomes["att-x"], AttemptRevocationResult.CLEANUP_FAILED)
        self.assertIn("att-x", lifecycle._cleanup_pending)

        # Third attempt — still in pending
        outcomes2 = lifecycle.retry_cleanup_failed()
        self.assertEqual(outcomes2["att-x"], AttemptRevocationResult.CLEANUP_FAILED)


if __name__ == "__main__":
    unittest.main(verbosity=2)
