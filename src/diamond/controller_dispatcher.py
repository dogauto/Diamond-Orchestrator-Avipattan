"""Scheduler bridge for the controller-owned persisted execution path."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .adapters import Invocation
from .controller import run_persisted
from .domain import TaskSpec, TaskStatus
from .errors import NotFoundError, ValidationError
from .evidence import AttemptStatus, EvidenceRecord, ExecutionAttempt, digest_text
from .packets import ArtifactRef, PacketContext, TaskPacket
from .policy_ipc import AttemptRevocationResult
from .provider_gateway import ProviderExecutionGateway
from .results import NormalizedResult
from .scheduler import Dispatcher, SchedulerException, TaskResult
from .skills import SkillRegistry
from .store import EventStore
from .supervisor import ExecutionResult
from .validation import command_id, text, canonical_json, utc_now, parse_canonical_json
import uuid as _uuid_module

if TYPE_CHECKING:
    from .orchestration import OrchestrationLifecycle


def _merge_revocation_payload(evidence: EvidenceRecord, extra: dict[str, Any]) -> EvidenceRecord:
    """Merge revocation metadata into an evidence payload without raising.

    ``EvidenceRecord`` validates its payload on construction, so a redacted
    or empty payload must not abort revocation. Failures fall back to the
    original evidence unchanged.
    """
    try:
        payload = canonical_json({**parse_canonical_json(evidence.payload_json), **extra})
        return replace(evidence, payload_json=payload)
    except Exception:
        return evidence


@dataclass(frozen=True)
class PersistedLaunch:
    """Immutable inputs prepared before a task enters the scheduler.

    ``lifecycle`` is the runtime-wide OrchestrationLifecycle that owns this
    attempt's IPC context. When set, the dispatcher revokes the attempt's
    capability immediately after the execution boundary (success or failure),
    ensuring no post-completion request can use the authority again.
    """

    store: EventStore
    packet: TaskPacket
    attempt: ExecutionAttempt
    invocation: Invocation | None
    cwd: Path
    owner: str
    registry: SkillRegistry
    context: PacketContext
    available_capabilities: tuple[str, ...] = ()
    timeout_seconds: float = 900
    output_limit: int = 1_048_576
    environment: dict[str, str] | None = None
    output_artifacts: tuple[ArtifactRef, ...] = ()
    max_workers: int = 2
    provider_gateway: ProviderExecutionGateway | None = None
    command_prefix: str | None = None
    lifecycle: "OrchestrationLifecycle" | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.store, EventStore):
            raise ValidationError("persisted launch requires an EventStore")
        if not isinstance(self.packet, TaskPacket) or not isinstance(self.attempt, ExecutionAttempt):
            raise ValidationError("persisted launch requires a packet and execution attempt")
        if not isinstance(self.cwd, Path):
            raise ValidationError("persisted launch cwd must be a pathlib.Path")
        if not isinstance(self.registry, SkillRegistry):
            raise ValidationError("persisted launch requires a skill registry")
        if not isinstance(self.context, PacketContext):
            raise ValidationError("persisted launch requires packet context")
        if type(self.available_capabilities) is not tuple:
            raise ValidationError("persisted launch capabilities must be an immutable tuple")
        if type(self.output_artifacts) is not tuple or any(
            not isinstance(artifact, ArtifactRef) for artifact in self.output_artifacts
        ):
            raise ValidationError("persisted launch artifacts must be ArtifactRef values")
        text(self.owner, "persisted launch owner", 256)
        if self.command_prefix is not None:
            text(self.command_prefix, "persisted launch command prefix", 80)
            command_id(self.command_prefix)
        if self.lifecycle is not None:
            from .orchestration import OrchestrationLifecycle
            if not isinstance(self.lifecycle, OrchestrationLifecycle):
                raise ValidationError("lifecycle must be an OrchestrationLifecycle instance")
        if self.packet.task_id != self.attempt.task_id:
            raise ValidationError("persisted launch packet and attempt task IDs differ")
        if self.packet.attempt_id != self.attempt.attempt_id:
            raise ValidationError("persisted launch packet and attempt IDs differ")
        if self.packet.task_revision != self.attempt.task_revision:
            raise ValidationError("persisted launch packet and attempt revisions differ")
        # Use getattr with defaults for older TaskPacket versions that lack provider_id/adapter_id
        packet_provider_id = getattr(self.packet, 'provider_id', None)
        packet_adapter_id = getattr(self.packet, 'adapter_id', None)
        generic = packet_provider_id is not None or packet_adapter_id is not None
        if generic:
            if self.invocation is not None:
                raise ValidationError("generic persisted launches cannot carry a CLI invocation")
            if not isinstance(self.provider_gateway, ProviderExecutionGateway):
                raise ValidationError("generic persisted launches require ProviderExecutionGateway")
        elif not isinstance(self.invocation, Invocation):
            raise ValidationError("legacy persisted launches require an Invocation")

    @property
    def effective_command_prefix(self) -> str:
        """Return a stable prefix derived from the task and attempt identity."""
        return self.command_prefix or f"scheduler:{self.packet.task_id}:{self.packet.attempt_id}"


class PersistedControllerDispatcher(Dispatcher):
    """Dispatch scheduled tasks through ``controller.run_persisted``.

    Launch records are prepared by the caller, while the controller remains
    responsible for packet validation, provider authorization, reservation,
    execution, evidence, and completion.  Direct dispatch of a dependent task
    fails closed; only the scheduler's optional dependency-aware call supplies
    the dependency proof.
    """

    def __init__(self, launches: Mapping[str, PersistedLaunch], *, resume_completed: bool = False) -> None:
        if not isinstance(launches, Mapping):
            raise ValidationError("persisted controller launches must be a mapping")
        if type(resume_completed) is not bool:
            raise ValidationError("resume_completed must be boolean")
        self._resume_completed = resume_completed
        self._launches = dict(launches)
        for task_id, launch in self._launches.items():
            if not isinstance(task_id, str) or not task_id:
                raise ValidationError("persisted controller launch keys must be nonblank strings")
            if not isinstance(launch, PersistedLaunch):
                raise ValidationError("persisted controller launches must contain PersistedLaunch values")
            if launch.packet.task_id != task_id:
                raise ValidationError("persisted controller launch key does not match its packet")

    def dispatch(self, task: TaskSpec) -> TaskResult:
        """Dispatch an independent task; dependent tasks require scheduler proof."""
        return self._dispatch(task, dependencies_satisfied=False)

    def dispatch_with_dependencies(
        self, task: TaskSpec, *, dependencies_satisfied: bool
    ) -> TaskResult:
        if type(dependencies_satisfied) is not bool:
            raise ValidationError("dependencies_satisfied must be boolean")
        return self._dispatch(task, dependencies_satisfied=dependencies_satisfied)

    def _dispatch(self, task: TaskSpec, *, dependencies_satisfied: bool) -> TaskResult:
        if not isinstance(task, TaskSpec):
            raise ValidationError("persisted controller dispatcher requires a TaskSpec")
        launch = self._launches.get(task.task_id)
        if launch is None:
            raise ValidationError(f"no persisted launch prepared for task {task.task_id}")
        self._validate_task_binding(task, launch)
        if self._resume_completed:
            resumed = self._resume_terminal(launch, task)
            if resumed is not None:
                return resumed
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise SchedulerException(
                "PersistedControllerDispatcher cannot run inside an active event loop"
            )

        try:
            completed, result, execution, evidence = asyncio.run(
                self._run_launch(launch, dependencies_satisfied)
            )
        except asyncio.CancelledError:
            return TaskResult(
                task.task_id,
                TaskStatus.CANCELLED,
                "execution cancelled",
                {"dispatch_path": "persisted_controller"},
            )

        if completed.task_id != task.task_id:
            raise ValidationError("persisted controller returned a mismatched task ID")
        status = self._task_status(completed.status)
        metadata: dict[str, object] = {
            "dispatch_path": "persisted_controller",
            "attempt_id": completed.attempt_id,
            "attempt_status": completed.status.value,
            "result_status": completed.result_status,
            "evidence_id": evidence.evidence_id,
        }
        if completed.provider_id is not None:
            metadata["provider_id"] = completed.provider_id
        if completed.adapter_id is not None:
            metadata["adapter_id"] = completed.adapter_id
        error = None
        if status is not TaskStatus.SUCCEEDED:
            error = completed.detail or result.detail or execution.detail or completed.status.value
        return TaskResult(task.task_id, status, error, metadata)

    async def _run_launch(
        self, launch: PersistedLaunch, dependencies_satisfied: bool
    ) -> tuple[ExecutionAttempt, NormalizedResult, ExecutionResult, EvidenceRecord]:
        try:
            completed, result, execution, evidence = await run_persisted(
                store=launch.store,
                packet=launch.packet,
                attempt=launch.attempt,
                invocation=launch.invocation,
                cwd=launch.cwd,
                owner=launch.owner,
                command_prefix=launch.effective_command_prefix,
                registry=launch.registry,
                context=launch.context,
                available_capabilities=launch.available_capabilities,
                timeout_seconds=launch.timeout_seconds,
                output_limit=launch.output_limit,
                environment=launch.environment,
                output_artifacts=launch.output_artifacts,
                max_workers=launch.max_workers,
                provider_gateway=launch.provider_gateway,
                lifecycle=launch.lifecycle,
                dependencies_satisfied=dependencies_satisfied,
            )
        except BaseException:
            # Revoke IPC authority before propagating so a raised
            # run_persisted (exception, timeout, cancellation) never leaves
            # the attempt's capability registered. Revocation failure must
            # not mask the original error; cleanup failures are recorded
            # in the lifecycle's cleanup-pending set for later retry.
            if launch.lifecycle is not None:
                try:
                    launch.lifecycle.revoke_attempt(launch.attempt.attempt_id)
                except Exception:
                    pass  # Best-effort; original exception will propagate
            raise
        # After the attempt execution boundary, revoke the attempt's
        # IPC capability so no post-completion request can use the old
        # authority. This runs on every path: success, failure, timeout,
        # cancellation. Revocation failure must not swallow the original
        # result; instead it is recorded as separate evidence.
        revocation_result: AttemptRevocationResult | None = None
        if launch.lifecycle is not None and completed.attempt_id is not None:
            try:
                revocation_result = launch.lifecycle.revoke_attempt(completed.attempt_id)
            except Exception as exc:
                # Capture cleanup failure without masking the original error.
                revocation_result = AttemptRevocationResult.CLEANUP_FAILED
                evidence = _merge_revocation_payload(
                    evidence, {"revocation_error": str(exc), "revocation_result": revocation_result.value}
                )
            else:
                # Record revocation outcome as structured evidence.
                if revocation_result is not AttemptRevocationResult.REVOKED:
                    evidence = _merge_revocation_payload(
                        evidence,
                        {
                            "revocation_result": revocation_result.value,
                            "reason": f"attempt {completed.attempt_id} revoked with outcome: {revocation_result.value}",
                        },
                    )
                try:
                    payload = canonical_json({
                        "attempt_id": completed.attempt_id,
                        "task_id": completed.task_id,
                        "revocation_result": revocation_result.value,
                        "agent_id": launch.packet.adapter_id or launch.packet.provider,
                    })
                    launch.store.record_evidence(
                        EvidenceRecord(
                            evidence_id=_uuid_module.uuid4().hex,
                            attempt_id=completed.attempt_id,
                            kind="revocation_result",
                            created_at=utc_now(),
                            payload_json=payload,
                            digest_sha256=digest_text(payload),
                        ),
                        f"{launch.effective_command_prefix}:revocation-evidence",
                    )
                except Exception:
                    pass  # Evidence persistence failure must not mask execution result
        return completed, result, execution, evidence

    @staticmethod
    def _task_status(status: AttemptStatus) -> TaskStatus:
        if status is AttemptStatus.SUCCEEDED:
            return TaskStatus.SUCCEEDED
        if status is AttemptStatus.CANCELLED:
            return TaskStatus.CANCELLED
        # AMBIGUOUS is deliberately a scheduler failure so it cannot unlock
        # descendants or make SchedulerOutcome.SUCCESS appear safe.
        return TaskStatus.FAILED

    def _resume_terminal(self, launch: PersistedLaunch, task: TaskSpec) -> TaskResult | None:
        try:
            completed = launch.store.get_attempt(launch.attempt.attempt_id)
        except NotFoundError:
            return None
        if completed.status not in {
            AttemptStatus.SUCCEEDED,
            AttemptStatus.FAILED,
            AttemptStatus.AMBIGUOUS,
            AttemptStatus.CANCELLED,
        }:
            return None
        evidence_id = None
        for evidence in launch.store.evidence(task.task_id):
            if evidence.attempt_id == completed.attempt_id and evidence.kind == "provider_result":
                evidence_id = evidence.evidence_id
        status = self._task_status(completed.status)
        metadata: dict[str, object] = {
            "dispatch_path": "persisted_controller",
            "resumed_from_ledger": True,
            "attempt_id": completed.attempt_id,
            "attempt_status": completed.status.value,
            "result_status": completed.result_status,
            "evidence_id": evidence_id,
        }
        if completed.provider_id is not None:
            metadata["provider_id"] = completed.provider_id
        if completed.adapter_id is not None:
            metadata["adapter_id"] = completed.adapter_id
        error = None if status is TaskStatus.SUCCEEDED else completed.detail or completed.status.value
        return TaskResult(task.task_id, status, error, metadata)

    @staticmethod
    def _validate_task_binding(task: TaskSpec, launch: PersistedLaunch) -> None:
        packet = launch.packet
        if (packet.task_id, packet.objective, packet.role, packet.provider) != (
            task.task_id,
            task.objective,
            task.role,
            task.provider,
        ):
            raise ValidationError("scheduler task does not match its persisted packet")
        for name in (
            "owned_paths",
            "allowed_tools",
            "required_tests",
            "acceptance_conditions",
        ):
            expected = getattr(task, name) or ()
            actual = getattr(packet, name)
            if actual != expected:
                raise ValidationError(f"scheduler task changed packet {name}")
        if packet.timeout_seconds != (task.timeout_seconds or 900):
            raise ValidationError("scheduler task changed packet timeout")
        if packet.correction_round_limit != (task.correction_round_limit or 0):
            raise ValidationError("scheduler task changed packet correction limit")
