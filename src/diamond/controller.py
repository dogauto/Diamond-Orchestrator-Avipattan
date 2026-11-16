from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

from .adapters import Invocation
from .domain import TaskStatus
from .evidence import (AttemptStatus, EvidenceRecord, ExecutionAttempt, digest_text,
                       environment_secrets, output_evidence, safe_excerpt)
from .errors import ConflictError, ExecutionGuardError, NotFoundError, ValidationError
from .packets import ArtifactRef, PacketContext, TaskPacket
from .processes import ProcessIdentity
from .results import NormalizedResult, ParseStatus, parse_result
from .provider_contracts import Capability, ExecutionMode, NormalizedExecutionResult, TaskExecutionRequest, TaskRequirements
from .provider_execution import CancellationRequest, ExecutionOutcome, ExecutionPolicy
from .provider_gateway import ProviderExecutionGateway
from .skills import SkillRegistry
from .store import EventStore
from .supervisor import CancelledExecution, ExecutionResult, ExecutionStatus, run
from .validation import bounded_int, canonical_json, command_id as validate_command_id, text, utc_now


def recover_on_startup(store: EventStore, reason: str) -> tuple:
    """Recover interrupted executions on startup.

    Finds tasks with RUNNING execution status and marks them UNCERTAIN.
    Returns a tuple of recovered TaskSnapshot objects.

    Args:
        store: EventStore instance
        reason: Human-readable recovery reason

    Returns:
        Tuple of TaskSnapshot objects that were recovered (marked UNCERTAIN)
    """
    from .store import EventStore
    if not isinstance(store, EventStore):
        raise ValidationError("recover_on_startup requires an EventStore")
    # Sanitize reason for command ID - replace spaces and special chars
    safe_reason = "".join(c if c.isalnum() or c in "-_" else "-" for c in reason)
    recovered = store.recover_interrupted_tasks(f"startup-recover-{safe_reason}", reason)

    # D2.2: inspect CONSUMED approvals that survived a crash and persist findings.
    # Never auto-resets CONSUMED → APPROVED; never auto-redispatches uncertain tasks.
    from .watchdog import CrashRecoveryInspector
    findings = _controller_recovery_inspection(store, reason)
    return recovered + tuple(findings)


def _controller_recovery_inspection(store: EventStore, reason: str) -> tuple:
    """Inspect CONSUMED approvals after a crash and persist recovery findings.

    Idempotent: duplicate findings are rejected by the runtime_events
    command_id UNIQUE constraint, so repeated startup never creates noise.
    """
    from uuid import uuid4
    from .watchdog import CrashRecoveryInspector
    findings = []
    if not store._database_present():
        return ()
    with store._connection(write=False) as conn:
        rows = conn.execute(
            "SELECT DISTINCT agent_id, task_id FROM agent_approval_state WHERE approval_status='CONSUMED'"
        ).fetchall()
        for row in rows:
            agent_id = row["agent_id"]
            task_id = row["task_id"]
            inspector = CrashRecoveryInspector(store, agent_id, task_id)
            consumed = inspector.inspect_consumed_approvals()
            for c in consumed:
                rec = inspector.recommend_recovery(c["approval_id"])
                findings.append({
                    "approval_id": c["approval_id"],
                    "agent_id": agent_id,
                    "task_id": task_id,
                    "recommendation": rec,
                    "execution_events": c.get("execution_events", []),
                })
    if findings:
        with store._connection(write=True) as conn:
            for f in findings:
                cmd_id = f"controller:recovery:{f['approval_id']}"
                try:
                    conn.execute(
                        """INSERT INTO agent_runtime_events
                           (event_id, entity_type, entity_id, revision, event_type,
                            timestamp, command_id, payload_json)
                           VALUES (?,?,?,?,?,?,?,?)""",
                        (uuid4().hex, "crash_recovery", f["agent_id"], 1,
                         "FINDING", utc_now(), cmd_id, canonical_json(f)),
                    )
                except Exception:
                    pass  # Idempotent: UNIQUE(command_id) rejects duplicates
    return tuple(findings)


def evaluate_watchdog_restart(
    watchdog: "PolicyWatchdog",
    store: EventStore,
    ipc_context: Optional["PolicyIPCServerContext"] = None,
) -> dict:
    """Controller-mediated watchdog restart handler (D2.2).

    The watchdog reports restart intent. The Controller owns the decision
    and execution. This function:

    1. Evaluates the watchdog's restart intent.
    2. Distinguishes process-unavailable vs IPC-unreachable vs IPC-crashed vs
       EventStore-unavailable vs Controller-shutting-down.
    3. Executes a bounded restart with backoff.
    4. Verifies the restart independently.
    5. Records evidence in the EventStore.

    Never authorizes tools, never changes policy decisions, never
    redispatches uncertain tasks.
    """
    from .watchdog import ServiceState

    intent = watchdog.get_restart_intent()
    if intent is None:
        return {"action": "none", "reason": "no restart intent pending"}

    # Distinguish failure modes
    if not store._database_present():
        watchdog.clear_restart_intent()
        return {"action": "none", "reason": "EventStore unavailable; cannot restart"}

    if intent["attempt"] > intent["max_attempts"]:
        watchdog.clear_restart_intent()
        return {"action": "none", "reason": f"max restart attempts exceeded ({intent['attempt']}/{intent['max_attempts']})"}

    # Execute the restart
    try:
        if ipc_context is not None:
            try:
                ipc_context.stop()
            except Exception:
                pass
            try:
                ipc_context.start()
            except Exception as exc:
                return {
                    "action": "restart_failed",
                    "reason": f"restart attempt {intent['attempt']} failed: {exc}",
                    "attempt": intent["attempt"],
                }
            # Verify the restart independently
            from .watchdog import PolicyWatchdog, WatchdogConfig
            probe = PolicyWatchdog(
                store=store,
                socket_path=ipc_context.ipc_socket_path,
                capability=ipc_context.ipc_capability,
                agent_id=ipc_context.agent_id,
                task_id=ipc_context.task_id,
                attempt_id=ipc_context.attempt_id,
                command_prefix=ipc_context.command_prefix,
                config=WatchdogConfig(ipc_total_timeout=1.0),
            )
            state, detail, kind = probe._probe_ipc_sync()
            watchdog.clear_restart_intent()
            return {
                "action": "restart_succeeded" if state == ServiceState.HEALTHY else "restart_degraded",
                "reason": detail,
                "attempt": intent["attempt"],
                "probe_state": state.value,
                "probe_detail": detail,
            }
        else:
            # No IPC context to restart — record intent and clear
            watchdog.clear_restart_intent()
            return {
                "action": "restart_skipped",
                "reason": "no IPC context available for restart",
                "attempt": intent["attempt"],
            }
    except Exception as exc:
        watchdog.clear_restart_intent()
        return {"action": "restart_error", "reason": str(exc), "attempt": intent["attempt"]}


def _gateway_result(normalized: NormalizedExecutionResult, output_limit: int) -> tuple[NormalizedResult, ExecutionResult]:
    content = normalized.content
    if content is None and normalized.structured_output_json is not None:
        content = normalized.structured_output_json
    content = content or ""
    detail = normalized.diagnostics[-1] if normalized.diagnostics else ""
    if normalized.outcome is ExecutionOutcome.SUCCEEDED:
        parse_status = ParseStatus.VALID if content else ParseStatus.EMPTY
        execution_status = ExecutionStatus.SUCCEEDED
        returncode = 0
    else:
        parse_status = ParseStatus.PROVIDER_ERROR
        execution_status = {
            ExecutionOutcome.TIMEOUT: ExecutionStatus.TIMEOUT,
            ExecutionOutcome.CANCELLED: ExecutionStatus.CANCELLED,
            ExecutionOutcome.OUTPUT_LIMIT: ExecutionStatus.OUTPUT_LIMIT,
            ExecutionOutcome.START_FAILED: ExecutionStatus.START_FAILED,
        }.get(normalized.outcome, ExecutionStatus.NONZERO)
        returncode = None if normalized.outcome is ExecutionOutcome.UNKNOWN else 1
        if not detail:
            detail = normalized.outcome.value
    result = NormalizedResult(
        parse_status, normalized.content, normalized.reported_model, normalized.session_id,
        (normalized.structured_output_json,) if normalized.structured_output_json is not None else ((canonical_json({"text": content}),) if content else ()),
        detail, normalized.structured_output_json,
    )
    execution = ExecutionResult(
        execution_status, returncode, content, "\n".join(normalized.diagnostics), detail,
        stdout_bytes=len(content.encode("utf-8")), stderr_bytes=len("\n".join(normalized.diagnostics).encode("utf-8")),
        stdout_sha256=digest_text(content), stderr_sha256=digest_text("\n".join(normalized.diagnostics)),
        cleanup_complete=True,
    )
    if len(content.encode("utf-8")) > output_limit:
        execution = replace(execution, status=ExecutionStatus.OUTPUT_LIMIT, detail="provider output exceeded the controller limit")
    return result, execution


def _gateway_evidence(attempt: ExecutionAttempt, normalized: NormalizedExecutionResult,
                      execution: ExecutionResult, created_at: str, binding_digest: str,
                      artifact_refs: tuple[ArtifactRef, ...], artifact_error: str | None,
                      secrets: tuple[str, ...] = ()) -> EvidenceRecord:
    provenance = normalized.provenance
    payload = {
        "schema_version": 1,
        "execution_path": "provider_gateway",
        "task_id": normalized.task_id,
        "correlation_id": normalized.correlation_id,
        "provider_id": normalized.provider_id,
        "adapter_id": provenance.adapter_id,
        "adapter_contract_version": provenance.adapter_contract_version,
        "provider_binding_digest": binding_digest,
        "process_identity": {
            "pid": normalized.process_id,
            "launcher_pid": normalized.launcher_process_id,
            "child_pid": normalized.child_process_id,
        } if normalized.process_id is not None else None,
        "execution_identity": {"attempt_id": attempt.attempt_id, "correlation_id": normalized.correlation_id},
        "outcome": normalized.outcome.value,
        "reported_model": safe_excerpt(normalized.reported_model, 256, secrets) if normalized.reported_model is not None else None,
        "session_id": safe_excerpt(normalized.session_id, 4096, secrets) if normalized.session_id is not None else None,
        "content": safe_excerpt(normalized.content, 32_768, secrets) if normalized.content is not None else None,
        "structured_output": safe_excerpt(normalized.structured_output_json, 32_768, secrets) if normalized.structured_output_json is not None else None,
        "diagnostics": [safe_excerpt(item, 4_096, secrets) for item in normalized.diagnostics],
        "provenance": {
            "provider_id": provenance.provider_id,
            "provider_version": provenance.provider_version,
            "adapter_id": provenance.adapter_id,
            "adapter_contract_version": provenance.adapter_contract_version,
            "manifest_digest": provenance.manifest_digest,
            "source": provenance.source,
        },
        "normalized_result": {
            "provider_id": normalized.provider_id,
            "task_id": normalized.task_id,
            "correlation_id": normalized.correlation_id,
            "outcome": normalized.outcome.value,
            "content": safe_excerpt(normalized.content, 32_768, secrets) if normalized.content is not None else None,
            "reported_model": safe_excerpt(normalized.reported_model, 256, secrets) if normalized.reported_model is not None else None,
            "session_id": safe_excerpt(normalized.session_id, 4096, secrets) if normalized.session_id is not None else None,
            "structured_output_json": safe_excerpt(normalized.structured_output_json, 32_768, secrets)
            if normalized.structured_output_json is not None else None,
            "diagnostics": [safe_excerpt(item, 4_096, secrets) for item in normalized.diagnostics],
            "model_selection": safe_excerpt(normalized.model_selection, 256, secrets) if normalized.model_selection is not None else None,
            "verified_model": safe_excerpt(normalized.verified_model, 256, secrets) if normalized.verified_model is not None else None,
            "process_id": normalized.process_id,
            "launcher_process_id": normalized.launcher_process_id,
            "child_process_id": normalized.child_process_id,
            "provenance": {
                "provider_id": provenance.provider_id,
                "provider_version": provenance.provider_version,
                "adapter_id": provenance.adapter_id,
                "adapter_contract_version": provenance.adapter_contract_version,
                "manifest_digest": provenance.manifest_digest,
                "source": provenance.source,
            },
        },
        "returncode": execution.returncode,
        "execution_status": execution.status.value,
        "stdout_sha256": execution.stdout_sha256,
        "stderr_sha256": execution.stderr_sha256,
        "artifact_refs": [artifact.to_dict() for artifact in artifact_refs],
        "artifacts_verified": artifact_error is None,
        "artifact_error": safe_excerpt(artifact_error, 4096, secrets) if artifact_error else None,
        "cleanup_complete": execution.cleanup_complete,
    }
    payload_json = canonical_json(payload)
    return EvidenceRecord(uuid4().hex, attempt.attempt_id, "provider_result", created_at,
                          payload_json, digest_text(payload_json))


async def run_persisted(store: EventStore, packet: TaskPacket, attempt: ExecutionAttempt,
                        invocation: Invocation | None, cwd: Path, owner: str, command_prefix: str,
                        registry: SkillRegistry, context: PacketContext,
                        available_capabilities: tuple[str, ...] = (),
                        timeout_seconds: float = 900,
                         output_limit: int = 1_048_576,
                         environment: dict[str, str] | None = None,
                         output_artifacts: tuple[ArtifactRef, ...] = (), max_workers: int = 2,
                         provider_gateway: ProviderExecutionGateway | None = None,
                         lifecycle: OrchestrationLifecycle | None = None,
                         dependencies_satisfied: bool = False) -> tuple[ExecutionAttempt, NormalizedResult,
                                                                                   ExecutionResult, EvidenceRecord]:
    """Run one explicit invocation with launch intent and completion evidence in the ledger."""
    if not isinstance(store, EventStore) or not isinstance(packet, TaskPacket) or not isinstance(attempt, ExecutionAttempt):
        raise ValidationError("run_persisted requires a store, packet, and validated attempt")
    generic = packet.provider_id is not None or packet.adapter_id is not None
    if generic:
        if invocation is not None or not isinstance(provider_gateway, ProviderExecutionGateway):
            raise ValidationError("generic persisted execution requires ProviderExecutionGateway and no invocation")
    elif not isinstance(invocation, Invocation):
        raise ValidationError("run_persisted requires a validated invocation")
    if packet.schema_version == 2:
        raise ExecutionGuardError("profile pilot is preview-only until persisted trial assignment and aggregate budgets are implemented")
    if not isinstance(cwd, Path):
        raise ValidationError("run_persisted cwd must be a pathlib.Path")
    if not isinstance(registry, SkillRegistry) or type(available_capabilities) is not tuple:
        raise ValidationError("run_persisted requires a skill registry and immutable capabilities")
    if not isinstance(context, PacketContext):
        raise ValidationError("run_persisted requires current accepted context")
    packet.verify_current(context.plan_revision, context.plan_digest, context.base_digest, context.config_digest)
    bounded_int(output_limit, "output_limit", 1, 16_777_216)
    bounded_int(max_workers, "max_workers", 1, 64)
    if type(dependencies_satisfied) is not bool:
        raise ValidationError("dependencies_satisfied must be boolean")
    if type(output_artifacts) is not tuple or any(not isinstance(artifact, ArtifactRef) for artifact in output_artifacts):
        raise ValidationError("output artifacts must be an immutable tuple of ArtifactRef values")
    if environment is not None and (type(environment) is not dict or any(type(key) is not str or type(value) is not str
            for key, value in environment.items())):
        raise ValidationError("execution environment overrides must be a string mapping")
    if environment and any(key in environment for key in ("PATH", "HOME", "CODEX_HOME", "CLAUDE_CONFIG_DIR")):
        raise ValidationError("execution overrides must not change executable resolution or provider state roots")
    packet.verify(registry, available_capabilities)
    if not generic:
        assert invocation is not None
        packet.authorize_invocation(invocation, cwd)
        expected_executable = invocation.argv[0]
    else:
        expected_executable = attempt.executable
    if (attempt.task_id, attempt.task_revision, attempt.attempt_id, attempt.role, attempt.provider,
            attempt.requested_model, attempt.workspace_root, attempt.executable) != \
            (packet.task_id, packet.task_revision, packet.attempt_id, packet.role, packet.provider,
             packet.requested_model, packet.workspace_root, expected_executable):
        raise ValidationError("packet, attempt, and launch identities do not match")
    runtime_secrets = provider_gateway.redaction_secrets if generic and provider_gateway is not None else ()
    secrets = tuple(dict.fromkeys((*environment_secrets(environment), *runtime_secrets)))
    text(command_prefix, "attempt command prefix", 80)
    validate_command_id(f"{command_prefix}:intent")
    validate_command_id(f"{command_prefix}:claim")
    validate_command_id(f"{command_prefix}:start")
    validate_command_id(f"{command_prefix}:complete")
    validate_command_id(f"{command_prefix}:evidence")
    if generic:
        validate_command_id(f"{command_prefix}:accept")

    accepted = None
    metadata = None
    if generic:
        assert provider_gateway is not None
        metadata = store.provider_metadata(packet.stable_provider_id)
        accepted = store.accept_packet(packet, metadata, f"{command_prefix}:accept")
        provider_gateway.validate_execution_binding(accepted.binding, metadata)

    claim, intent = store.reserve_dispatch(packet, attempt, owner, f"{command_prefix}:claim", max_workers,
                                           dependencies_satisfied=dependencies_satisfied)
    if intent.status is not AttemptStatus.INTENDED:
        raise ConflictError("execution attempt already advanced; refusing blind relaunch")
    if generic:
        assert provider_gateway is not None
        assert accepted is not None and metadata is not None
        accepted = store.verify_accepted_packet(packet, intent.attempt_id)
        provider_gateway.validate_execution_binding(accepted.binding, metadata)
        launch_payload = canonical_json({
            "execution_path": "provider_gateway",
            "provider_id": packet.stable_provider_id,
            "adapter_id": packet.stable_adapter_id,
            "correlation_id": intent.attempt_id,
            "packet_digest": packet.packet_digest(),
            "process_identity": None,
        })
    else:
        assert invocation is not None
        launch_payload = canonical_json({"argv": [safe_excerpt(arg, 4096, secrets) for arg in invocation.argv],
            "argv_digest": digest_text(canonical_json(list(invocation.argv))), "cwd": str(cwd.resolve()),
            "packet_digest": packet.packet_digest(), "host_write_enforced": True,
            "provider_tools": list(packet.provider_tools) if packet.provider_tools is not None else None})
    store.record_evidence(EvidenceRecord(uuid4().hex, intent.attempt_id, "launch_intent", utc_now(),
                                         launch_payload, digest_text(launch_payload)), f"{command_prefix}:launch")
    packet.verify(registry, available_capabilities)
    started = store.acquire_start(claim, f"{command_prefix}:start")
    # Wire execution-state projection: begin execution tracking after launch authority
    try:
        store.begin_execution(packet.task_id, attempt.attempt_id, packet.task_revision,
                              f"{command_prefix}:exec-begin")
    except (ConflictError, ExecutionGuardError, NotFoundError):
        pass  # Already started or task not found

    # Register per-attempt IPC capability binding for durable evidence
    # Must be done after attempt is in the database (post-acquire_start)
    if lifecycle is not None:
        from .orchestration import OrchestrationLifecycle
        # Get the attempt IPC context from lifecycle
        attempt_ctx = lifecycle.attempt_ipc_contexts.get(attempt.attempt_id)
        if attempt_ctx is not None:
            cmd_prefix = f"{command_prefix}:ipc-bind"
            try:
                store.register_policy_ipc_binding(
                    attempt_id=attempt.attempt_id,
                    capability=attempt_ctx.ipc_capability,
                    command_id=cmd_prefix
                )
            except Exception:
                pass  # Binding already exists or other issue; don't block execution

    def process_started(pid: int, identity: ProcessIdentity | None) -> None:
        payload = canonical_json({"pid": pid, "identity": identity.to_dict() if identity is not None else None})
        store.record_evidence(EvidenceRecord(uuid4().hex, started.attempt_id, "process_started", utc_now(),
                                             payload, digest_text(payload)), f"{command_prefix}:process")

    # Track process for cancellation evidence
    _processes: dict[str, object] = {}

    cancelled = False
    normalized: NormalizedExecutionResult | None = None
    try:
        if generic:
            assert provider_gateway is not None
            request = TaskExecutionRequest(
                packet.task_id, started.attempt_id, packet.objective,
                TaskRequirements(
                    frozenset({Capability.ONE_SHOT_EXECUTION, Capability.TIMEOUT_ENFORCEMENT}),
                    frozenset({ExecutionMode.ONE_SHOT}),
                ),
                ExecutionMode.ONE_SHOT, max(1, min(int(timeout_seconds), packet.timeout_seconds)),
                # Packets created before the provider-gateway policy field was
                # introduced remain runnable as explicitly bounded writable
                # executions.  New read-only work, including UAT-001, must
                # carry ``execution_policy="read_only"`` in the accepted
                # packet; this fallback never upgrades a task to read-only.
                execution_policy=ExecutionPolicy.from_packet(
                    packet.execution_policy or "writable", packet.workspace_root, packet.owned_paths
                ),
            )
            normalized = await asyncio.to_thread(provider_gateway.execute, packet.stable_provider_id, request)
            result, execution = _gateway_result(normalized, output_limit)
        else:
            assert invocation is not None
            execution = await run(invocation, cwd, min(timeout_seconds, packet.timeout_seconds), output_limit, environment,
                                  on_started=lambda pid, identity: (_processes.__setitem__(started.attempt_id, _processes) or process_started(pid, identity)),
                                  enforce_paths=True,
                                  owned_paths=packet.owned_paths if invocation.permission_mode.value != "plan" else ())
            if execution.status is ExecutionStatus.CANCELLED:
                cancelled = True
            try:
                result = parse_result(invocation, execution)
            except (ValidationError, ValueError, RecursionError):
                result = NormalizedResult(ParseStatus.MALFORMED, None, None, None, (), "provider result failed strict normalization")
    except CancelledExecution as exc:
        # Supervisor explicitly cancelled - use its result
        execution = exc.result
        cancelled = True
        now = utc_now()
        # Record individual evidence records that reconcile_attempt expects
        for kind, payload_dict in (
            ('process_terminated', {'signal': execution.returncode, 'terminated_at': now}),
            ('process_group_terminated', {'group_terminated': True, 'terminated_at': now}),
            ('cleanup_complete', {'cleanup_complete': execution.cleanup_complete, 'completed_at': now}),
        ):
            payload = canonical_json(payload_dict)
            evidence = EvidenceRecord(uuid4().hex, started.attempt_id, kind, now, payload, digest_text(payload))
            store.record_evidence(evidence, f"{command_prefix}:termination:{kind}")
        # Record provider_result evidence so tests can verify cancellation trail
        if invocation is not None:
            result = NormalizedResult(ParseStatus.PROVIDER_ERROR, "cancelled", None, None, (), "execution cancelled")
            prov_evidence = output_evidence(started, invocation, execution, result, now)
            store.record_evidence(prov_evidence, f"{command_prefix}:result")
        store.reconcile_attempt(started.attempt_id, f"{command_prefix}:cancel",
                                "execution cancelled by supervisor")
        raise
    except asyncio.CancelledError:
        # Record structured termination evidence before reconciliation
        termination_evidence = {}
        try:
            # Check if process was terminated with signal
            process = _processes.get(started.attempt_id)
            if process is not None:
                if hasattr(process, 'poll') and process.poll() is not None:
                    termination_evidence['process_terminated'] = {
                        'signal': process.returncode,
                        'terminated_at': utc_now().isoformat()
                    }
                elif hasattr(process, 'returncode'):
                    termination_evidence['process_terminated'] = {
                        'signal': process.returncode,
                        'terminated_at': utc_now().isoformat()
                    }
        except Exception:
            pass

        # Check if process group was terminated (via killpg)
        try:
            group_evidence = _processes.get(started.attempt_id + '_group')
            if group_evidence and group_evidence.get('group_terminated'):
                termination_evidence['process_group_terminated'] = {
                    'group_terminated': True,
                    'terminated_at': utc_now().isoformat()
                }
        except Exception:
            pass

        # Check if cleanup was completed
        try:
            cleanup_evidence = _processes.get(started.attempt_id + '_cleanup')
            if cleanup_evidence and cleanup_evidence.get('cleanup_complete'):
                termination_evidence['cleanup_complete'] = {
                    'cleanup_complete': True,
                    'completed_at': utc_now().isoformat()
                }
        except Exception:
            pass

        if generic and provider_gateway is not None:
            try:
                await asyncio.to_thread(provider_gateway.cancel, packet.stable_provider_id,
                                        CancellationRequest(packet.stable_provider_id, packet.task_id,
                                                             started.attempt_id))
            except Exception:
                pass

        # Record termination evidence BEFORE reconciliation so store can read it
        if termination_evidence:
            timestamp = utc_now()
            payload = canonical_json(termination_evidence)
            evidence = EvidenceRecord(uuid4().hex, started.attempt_id, "termination_observation", timestamp,
                                     payload, digest_text(payload))
            store.record_evidence(evidence, f"{command_prefix}:termination")

        store.reconcile_attempt(started.attempt_id, f"{command_prefix}:cancel",
                                cancellation_reason if 'cancellation_reason' in dir() else "launch interrupted")

        raise
    except Exception as exc:
        store.reconcile_attempt(started.attempt_id, f"{command_prefix}:exception",
                                safe_excerpt(f"controller exception; reconciliation required: {exc}", 4096, secrets))
        raise
    artifact_error = None
    try:
        packet.verify_output_artifacts(output_artifacts)
        if result.status is ParseStatus.VALID:
            packet.output_contract.verify(result.structured_output or result.content)
    except ValidationError as exc:
        artifact_error = str(exc)
    if generic and normalized is not None and normalized.outcome in {ExecutionOutcome.UNKNOWN, ExecutionOutcome.CANCELLED}:
        status, detail = AttemptStatus.AMBIGUOUS, f"provider outcome is {normalized.outcome.value}; reconciliation required"
    elif execution.status is ExecutionStatus.CLEANUP_FAILED:
        status = AttemptStatus.AMBIGUOUS
        detail = "process cleanup could not be proven; reconciliation required"
    elif cancelled:
        status, detail = AttemptStatus.CANCELLED, "execution cancelled; supervised process group cleaned"
    elif artifact_error is not None:
        status = AttemptStatus.FAILED
        detail = f"output artifact validation failed: {artifact_error}"
    elif execution.status is ExecutionStatus.SUCCEEDED and result.status is ParseStatus.VALID:
        status = AttemptStatus.SUCCEEDED
        detail = result.detail
    else:
        status = AttemptStatus.FAILED
        detail = result.detail or execution.detail or execution.status.value
    completed = replace(
        started,
        status=status,
        completed_at=utc_now(),
        provider_session_id=safe_excerpt(result.session_id, 4096, secrets) if result.session_id else None,
        reported_model=safe_excerpt(result.reported_model, 256, secrets) if result.reported_model else None,
        returncode=execution.returncode,
        signal=-execution.returncode if execution.returncode is not None and execution.returncode < 0 else None,
        stdout_bytes=execution.stdout_bytes if execution.stdout_bytes is not None else len(execution.stdout.encode("utf-8")),
        stderr_bytes=execution.stderr_bytes if execution.stderr_bytes is not None else len(execution.stderr.encode("utf-8")),
        stdout_sha256=execution.stdout_sha256 or digest_text(execution.stdout),
        stderr_sha256=execution.stderr_sha256 or digest_text(execution.stderr),
        result_status=result.status.value,
        detail=safe_excerpt(detail, 4096, secrets),
        revision=started.revision + 1,
    )
    if generic:
        assert normalized is not None
        evidence = _gateway_evidence(completed, normalized, execution, utc_now(),
                                     intent.provider_binding_digest or "", output_artifacts, artifact_error, secrets)
    else:
        assert invocation is not None
        evidence = output_evidence(completed, invocation, execution, result, utc_now(), output_artifacts, secrets, artifact_error)
    try:
        completed = store.complete_attempt(completed, started.revision, evidence, f"{command_prefix}:complete")
    except ConflictError:
        store.record_evidence(replace(evidence, kind="late_result"), f"{command_prefix}:late")
        raise
    if cancelled:
        raise asyncio.CancelledError
    # Wire execution-state projection: complete the task
    # Use current task revision as the expected revision for complete_execution,
    # accounting for any begin_execution updates that may have occurred.
    try:
        current_revision = store.get(packet.task_id).revision
        exec_detail = completed.detail if completed.detail.strip() else None
        if completed.status in {AttemptStatus.SUCCEEDED, AttemptStatus.FAILED}:
            store.complete_execution(packet.task_id,
                                     TaskStatus.SUCCEEDED if completed.status is AttemptStatus.SUCCEEDED else TaskStatus.FAILED,
                                     current_revision, f"{command_prefix}:exec-complete",
                                     exec_detail)
    except (ConflictError, ExecutionGuardError):
        pass  # Best-effort; execution already recorded elsewhere

    # Record revocation evidence after attempt completion
    # This captures the authority revocation outcome for audit trail
    # Derives the outcome from the actual OrchestrationLifecycle.revoke_attempt()
    # result; never hardcodes success.
    from .policy_ipc import AttemptRevocationResult

    revocation_result: AttemptRevocationResult | None = None
    if lifecycle is not None and completed.attempt_id is not None:
        try:
            revocation_result = lifecycle.revoke_attempt(completed.attempt_id)
        except Exception as exc:
            revocation_result = AttemptRevocationResult.CLEANUP_FAILED
            revocation_reason = f"revocation exception: {exc}"
        else:
            revocation_reason = (
                f"Attempt {completed.status.value} - authority revoked with outcome: "
                f"{revocation_result.value}"
            )
    else:
        revocation_result = AttemptRevocationResult.UNKNOWN_ATTEMPT
        revocation_reason = f"Attempt {completed.status.value} - no lifecycle available"

    revocation_payload = canonical_json({
        "attempt_id": completed.attempt_id,
        "task_id": completed.task_id,
        "outcome": revocation_result.value,
        "reasoning": revocation_reason,
        "timestamp": utc_now(),
    })
    revocation_evidence = EvidenceRecord(
        evidence_id=uuid4().hex,
        attempt_id=completed.attempt_id,
        kind="revocation_result",
        created_at=utc_now(),
        payload_json=revocation_payload,
        digest_sha256=digest_text(revocation_payload),
    )
    store.record_evidence(revocation_evidence, f"{command_prefix}:revoke")

    return completed, result, execution, evidence
