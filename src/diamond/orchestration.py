"""Controller-owned orchestration over the persisted task execution path."""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

from .config import DiamondConfig, load_config
from .controller import recover_on_startup
from .controller_dispatcher import PersistedControllerDispatcher, PersistedLaunch
from .domain import Provider, TaskSpec
from .errors import ExecutionGuardError, ValidationError
from .evidence import AttemptStatus, ExecutionAttempt
from .owner import project_owner
from .packets import PacketContext, TaskPacket
from .paths import resolve_paths
from .policy_ipc import AttemptRevocationResult
from .provider_discovery import DiscoveryState
from .provider_discovery import DiscoveryEngine, ExecutableCandidate
from .provider_gateway import ProviderExecutionGateway
from .provider_registry import ProviderRegistry
from .scheduler import Scheduler, SchedulerResult
from .skills import SkillRegistry
from .store import EventStore
from .validation import bounded_int, command_id, exact_keys, task_id as validate_task_id, text


_POLICY_MARKERS: dict[str, tuple[str, ...]] = {
    "CONSTRAINTS.md": (
        "# Diamond constraints",
        "## Non-negotiable invariants",
        "## Enforcement placement",
        "## Conflict rule",
        "## Change gate",
    ),
    "CLAUDE.md": (
        "Flawless Diamond Piece",
        "CONSTRAINTS.md",
        "src/diamond/controller.py",
        "max_workers",
    ),
}
_POLICY_CONFLICTS = (
    "provider output is authoritative",
    "external skills grant capability",
    "workers may rewrite evaluator",
    "unrestricted shell execution is permitted",
    "automatic provider fallback is allowed",
)


def _policy_report(issues: list[str], checks: dict[str, object]) -> dict[str, object]:
    return {"ok": not issues, "issues": issues, "checks": checks}


def verify_policy(config_path: Path, project_root: Path) -> dict[str, object]:
    """Validate the repository policy and schema-1 configuration contract.

    This check is offline: it reads policy/configuration only and never probes
    providers, opens the ledger, or grants execution authority.
    """
    issues: list[str] = []
    checks: dict[str, object] = {}
    if not isinstance(config_path, Path):
        issues.append("config path must be a pathlib.Path")
        return _policy_report(issues, checks)
    if not isinstance(project_root, Path):
        issues.append("project root must be a pathlib.Path")
        return _policy_report(issues, checks)

    try:
        root = project_root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        return _policy_report([f"project root cannot be resolved: {exc}"], checks)

    for relative, markers in _POLICY_MARKERS.items():
        path = root / relative
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            issues.append(f"{relative} cannot be read: {exc}")
            continue
        missing = [marker for marker in markers if marker not in content]
        checks[relative] = {"path": str(path), "markers": len(markers) - len(missing)}
        issues.extend(f"{relative} is missing required policy marker: {marker}" for marker in missing)
        lowered = content.lower()
        issues.extend(f"{relative} contains conflicting policy text: {phrase}" for phrase in _POLICY_CONFLICTS if phrase in lowered)

    try:
        loaded = load_config(config_path)
        checks["config"] = {
            "path": str(config_path),
            "schema_version": loaded.schema_version,
            "providers": len(loaded.providers),
            "roles": len(loaded.roles),
        }
    except Exception as exc:
        issues.append(f"configuration is invalid: {exc}")

    return _policy_report(issues, checks)


def verify_invariants(config_path: Path, project_root: Path) -> dict[str, object]:
    """Validate policy plus controller-boundary source invariants offline."""
    report = verify_policy(config_path, project_root)
    issues = list(cast(list[str], report["issues"]))
    checks = dict(cast(dict[str, object], report["checks"]))
    if not isinstance(project_root, Path):
        return _policy_report(issues, checks)
    root = project_root.resolve()
    source_checks = {
        "src/diamond/controller.py": ("async def run_persisted", "ProviderExecutionGateway"),
        "src/diamond/routing.py": ("def select_provider", "def explain_provider_route"),
        "src/diamond/orchestration.py": ("def run_persisted_graph", "def verify_policy", "def verify_invariants"),
    }
    for relative, markers in source_checks.items():
        path = root / relative
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            issues.append(f"{relative} cannot be read for invariant verification: {exc}")
            continue
        missing = [marker for marker in markers if marker not in content]
        checks[relative] = {"markers": len(markers) - len(missing)}
        issues.extend(f"{relative} is missing invariant marker: {marker}" for marker in missing)

    scheduler_path = root / "src/diamond/scheduler.py"
    try:
        scheduler = scheduler_path.read_text(encoding="utf-8")
        forbidden = ("Provider.", "build_invocation(")
        issues.extend(f"scheduler contains provider-specific construction: {marker}" for marker in forbidden if marker in scheduler)
        checks["scheduler_provider_neutral"] = not any(marker in scheduler for marker in forbidden)
    except (OSError, UnicodeError) as exc:
        issues.append(f"src/diamond/scheduler.py cannot be read for provider-neutrality verification: {exc}")

    return _policy_report(issues, checks)


@dataclass(frozen=True)
class DeclarativeLaunch:
    """Stable launch references supplied by the orchestration input file."""

    task_id: str
    provider_id: str
    adapter_id: str
    accepted_packet_id: str

    @classmethod
    def from_dict(cls, value: object) -> "DeclarativeLaunch":
        if not isinstance(value, dict):
            raise ValidationError("launch entries must be objects")
        expected = {"task_id", "provider_id", "adapter_id", "accepted_packet_id"}
        data = dict(exact_keys(value, expected, "launch entry"))
        return cls(
            text(data["task_id"], "launch task_id", 64),
            text(data["provider_id"], "launch provider_id", 64),
            text(data["adapter_id"], "launch adapter_id", 256),
            command_id(data["accepted_packet_id"]),
        )


@dataclass(frozen=True)
class OrchestrationRuntime:
    """Capabilities supplied by trusted bootstrap code, never by JSON."""

    registry: ProviderRegistry
    available_capabilities: tuple[str, ...] = ()
    skill_registry: SkillRegistry = SkillRegistry(())
    provider_gateway: ProviderExecutionGateway | None = None
    lifecycle: "OrchestrationLifecycle" | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.registry, ProviderRegistry):
            raise ValidationError("orchestration runtime requires a ProviderRegistry")
        if type(self.available_capabilities) is not tuple:
            raise ValidationError("runtime capabilities must be an immutable tuple")
        if any(not isinstance(value, str) for value in self.available_capabilities):
            raise ValidationError("runtime capabilities must contain text")
        if not isinstance(self.skill_registry, SkillRegistry):
            raise ValidationError("runtime requires a SkillRegistry")
        if self.provider_gateway is not None and not isinstance(
            self.provider_gateway, ProviderExecutionGateway
        ):
            raise ValidationError("runtime gateway must be a ProviderExecutionGateway")
        if self.provider_gateway is not None and self.provider_gateway.registry is not self.registry:
            raise ValidationError("runtime gateway must use the runtime provider registry")
        if self.lifecycle is not None and not isinstance(self.lifecycle, OrchestrationLifecycle):
            raise ValidationError("lifecycle must be an OrchestrationLifecycle instance")

    @property
    def gateway(self) -> ProviderExecutionGateway:
        return self.provider_gateway or ProviderExecutionGateway(self.registry)


class OrchestrationLifecycle:
    """Mutable lifecycle state for runtime-owned resources (IPC, watchdog, sweeper).

    Keeps OrchestrationRuntime frozen while allowing mutable lifecycle management.
    """

    __slots__ = ("ipc_context", "watchdog", "expiry_sweeper", "eval_thread",
                 "shutdown_event", "loop_interval", "attempt_ipc_contexts",
                 "_cleanup_failed", "_cleanup_pending", "_registry_lock",
                 "_permanently_revoked")

    def __init__(self) -> None:
        self.ipc_context: Any = None  # PolicyIPCServerContext
        self.watchdog: Any = None  # PolicyWatchdog
        self.expiry_sweeper: Any = None  # ApprovalExpirationSweeper
        self.eval_thread: threading.Thread | None = None
        self.shutdown_event: threading.Event | None = None
        self.loop_interval: float = 60.0
        # Keyed by attempt_id, not task_id. Two attempts of the same task
        # must never share or overwrite each other's context.
        self.attempt_ipc_contexts: dict[str, Any] = {}
        # Contexts whose cleanup failed. Kept so a later retry can observe
        # and retry the failure; never silently dropped.
        self._cleanup_failed: dict[str, AttemptRevocationResult] = {}
        # IPC contexts that had a non-REVOKED cleanup but still need to be
        # cleaned up again on the next retry call. The context is retained
        # (not popped from attempt_ipc_contexts is not possible here since
        # pop already happened) — actually we store a reference separately so
        # retry_cleanup_failed() can re-invoke revoke() on it without having
        # access to the original context object.
        self._cleanup_pending: dict[str, tuple[Any, AttemptRevocationResult]] = (
            {}
        )
        # All attempt_ids that have been permanently resolved (revoked
        # successfully or left with a persistent cleanup failure). Used
        # to make repeated revoke_attempt() calls return ALREADY_REVOKED.
        self._permanently_revoked: set[str] = set()
        self._registry_lock = threading.Lock()

    def register_attempt(self, attempt_id: str, context: Any) -> None:
        """Register a per-attempt IPC context.

        Raises ValidationError on duplicate attempt_id so two attempts
        of the same task cannot silently overwrite each other.
        """
        if not isinstance(attempt_id, str) or not attempt_id:
            raise ValidationError("attempt_id must be a non-empty string")
        with self._registry_lock:
            if attempt_id in self.attempt_ipc_contexts:
                raise ValidationError(
                    f"attempt IPC context already registered for attempt_id: {attempt_id}"
                )
            self.attempt_ipc_contexts[attempt_id] = context

    def revoke_attempt(self, attempt_id: str) -> AttemptRevocationResult:
        """Revoke an attempt's IPC authority and tear down its resources.

        Returns an explicit AttemptRevocationResult. Never reports success
        when authority or resources may still be active. Idempotent:
        repeated calls return ALREADY_REVOKED.
        The bootstrap IPC context is never affected.
        If cleanup fails the context is retained in ``_cleanup_pending``
        so a subsequent ``retry_cleanup_failed()`` call can replay it.
        """
        with self._registry_lock:
            ctx = self.attempt_ipc_contexts.pop(attempt_id, None)
            if ctx is None:
                if attempt_id in self._permanently_revoked:
                    # Idempotent: once permanently resolved, report ALREADY_REVOKED
                    # regardless of whether the initial cleanup had a binding error.
                    return AttemptRevocationResult.ALREADY_REVOKED
                return AttemptRevocationResult.UNKNOWN_ATTEMPT
        try:
            result = ctx.revoke()
        except Exception:
            # Authority revocation failed — store context + error for retry.
            # Do NOT re-raise: the caller (dispatcher) already handles the
            # original exception separately, and re-raising here would
            # mask the caller's own exception handling.
            with self._registry_lock:
                self._cleanup_failed[attempt_id] = AttemptRevocationResult.CLEANUP_FAILED
                self._cleanup_pending[attempt_id] = (ctx, AttemptRevocationResult.CLEANUP_FAILED)
            self._permanently_revoked.add(attempt_id)
            return AttemptRevocationResult.CLEANUP_FAILED
        with self._registry_lock:
            self._permanently_revoked.add(attempt_id)
            if result is AttemptRevocationResult.REVOKED:
                self._cleanup_failed.pop(attempt_id, None)
                self._cleanup_pending.pop(attempt_id, None)
            else:
                self._cleanup_failed[attempt_id] = result
                # Retain the context for retry; do NOT discard here
        # Record binding revocation in persistent store for any outcome
        # where the binding should be marked revoked. REVOKED and
        # ALREADY_REVOKED both mean the binding must not authorize new
        # requests. CLEANUP_FAILED leaves the binding active so a retry
        # can still revoke it.
        if result in (AttemptRevocationResult.REVOKED, AttemptRevocationResult.ALREADY_REVOKED):
            try:
                if hasattr(ctx, 'store') and ctx.store is not None:
                    ctx.store.revoke_policy_ipc_binding(attempt_id, f"orchestrate:{ctx.task_id}:ipc-revoke")
            except Exception as exc:
                # Distinguish "no binding exists to revoke" from a genuine
                # persistence failure. A missing binding is not a failure: the
                # attempt had no durable authority to record, so the runtime
                # revocation outcome is accurate. A real storage error means
                # the durable record did not advance even though runtime
                # authority was invalidated — surface that explicitly.
                if "no active binding found" in str(exc):
                    return result
                self._cleanup_failed[attempt_id] = (
                    AttemptRevocationResult.AUTHORITY_REVOKED_RESOURCE_CLEANUP_INCOMPLETE
                )
                # Retain the context so retry_cleanup_failed() can replay the
                # cleanup attempt after the transient binding failure clears.
                self._cleanup_pending[attempt_id] = (
                    ctx, AttemptRevocationResult.AUTHORITY_REVOKED_RESOURCE_CLEANUP_INCOMPLETE
                )
                return AttemptRevocationResult.AUTHORITY_REVOKED_RESOURCE_CLEANUP_INCOMPLETE
        return result

    def retry_cleanup_failed(self) -> dict[str, AttemptRevocationResult]:
        """Attempt resource cleanup for previously-failed revocations.

        Returns a map of attempt_id → result. Idempotent: once cleanup
        succeeds the entry is removed from the pending set. Other attempts'
        live authority is untouched.
        """
        with self._registry_lock:
            items = list(self._cleanup_pending.items())
            self._cleanup_pending.clear()
        outcomes: dict[str, AttemptRevocationResult] = {}
        for attempt_id, (ctx, _prior_result) in items:
            try:
                result = ctx.revoke()
            except Exception:
                result = AttemptRevocationResult.CLEANUP_FAILED
            with self._registry_lock:
                self._permanently_revoked.add(attempt_id)
                if result is AttemptRevocationResult.REVOKED:
                    self._cleanup_failed.pop(attempt_id, None)
                else:
                    self._cleanup_failed[attempt_id] = result
                    self._cleanup_pending[attempt_id] = (ctx, result)
            outcomes[attempt_id] = result
        return outcomes

    def release_attempt(self, attempt_id: str) -> AttemptRevocationResult:
        """Alias for revoke_attempt; releases attempt IPC resources."""
        return self.revoke_attempt(attempt_id)

    def active_attempt_ids(self) -> tuple[str, ...]:
        """Return sorted tuple of currently registered attempt IDs.

        Represents actual active authority: completed attempts that were
        revoked are absent, and cleanup-failed attempts are reported
        separately via cleanup_failed_ids().
        """
        with self._registry_lock:
            return tuple(sorted(self.attempt_ipc_contexts.keys()))

    def cleanup_failed_ids(self) -> tuple[tuple[str, AttemptRevocationResult], ...]:
        """Return sorted (attempt_id, result) pairs whose cleanup failed."""
        with self._registry_lock:
            return tuple(sorted(self._cleanup_failed.items()))

    def revoke_all(self) -> dict[str, AttemptRevocationResult]:
        """Revoke every registered attempt. Returns per-attempt outcomes.

        Used by full-runtime shutdown. Independent attempts are revoked
        concurrently-safe; a failure in one does not prevent others.
        Bootstrap IPC is never touched here.
        """
        with self._registry_lock:
            pending = dict(self.attempt_ipc_contexts)
            self.attempt_ipc_contexts.clear()
        outcomes: dict[str, AttemptRevocationResult] = {}
        for attempt_id, ctx in pending.items():
            try:
                result = ctx.revoke()
            except Exception:
                result = AttemptRevocationResult.CLEANUP_FAILED
            with self._registry_lock:
                self._permanently_revoked.add(attempt_id)
                if result is AttemptRevocationResult.REVOKED:
                    self._cleanup_failed.pop(attempt_id, None)
                    self._cleanup_pending.pop(attempt_id, None)
                else:
                    self._cleanup_failed[attempt_id] = result
                    self._cleanup_pending[attempt_id] = (ctx, result)
            outcomes[attempt_id] = result
        return outcomes

    def start_watchdog_evaluation_loop(self) -> None:
        """Start the background thread that evaluates watchdog restart intent."""
        self.shutdown_event = threading.Event()
        self.eval_thread = threading.Thread(target=self._watchdog_eval_loop, daemon=True)
        self.eval_thread.start()

    def stop_watchdog_evaluation_loop(self) -> None:
        """Signal shutdown and join the evaluation thread."""
        if self.shutdown_event is not None:
            self.shutdown_event.set()
        if self.eval_thread is not None:
            self.eval_thread.join(timeout=5)
            self.eval_thread = None

    def _watchdog_eval_loop(self) -> None:
        """Background thread: periodically evaluate watchdog restart intent."""
        while not (self.shutdown_event and self.shutdown_event.is_set()):
            try:
                if self.shutdown_event:
                    self.shutdown_event.wait(self.loop_interval)
                if self.shutdown_event and self.shutdown_event.is_set():
                    break
            except Exception:
                pass  # Non-fatal; continue loop


def resolve_gateway_runtime_config(environment: Mapping[str, str] | None = None):
    """Resolve loopback-compatible gateway settings without persisting secrets."""
    from .claude_code_adapter import ClaudeCodeRuntimeConfig
    from .freellmapi import normalize_base_url

    values = os.environ if environment is None else environment
    if not isinstance(values, Mapping):
        raise ValidationError("gateway environment must be a mapping")
    raw_urls = tuple(value for value in (
        values.get("FREELLMAPI_URL"), values.get("ANTHROPIC_BASE_URL")) if value)
    try:
        normalized_urls = tuple(normalize_base_url(value) for value in raw_urls)
    except ValidationError:
        raise ExecutionGuardError("FreeLLMAPI gateway URL is invalid") from None
    if any((urlsplit(value).hostname or "").lower() == "api.anthropic.com" for value in normalized_urls):
        raise ExecutionGuardError("Anthropic first-party endpoint is not an approved gateway")
    if len(set(normalized_urls)) > 1:
        raise ExecutionGuardError("conflicting FreeLLMAPI gateway URLs are configured")
    url = normalized_urls[0] if normalized_urls else "http://127.0.0.1:31415"
    credential = values.get("FREELLMAPI_API_KEY") or values.get("ANTHROPIC_AUTH_TOKEN")
    if not credential:
        raise ExecutionGuardError("FreeLLMAPI credential is unavailable")
    try:
        return ClaudeCodeRuntimeConfig(url, credential)
    except ValidationError:
        raise ExecutionGuardError("FreeLLMAPI credential is invalid") from None


def build_trusted_runtime(
    store: EventStore, project: Path, config: DiamondConfig
) -> OrchestrationRuntime:
    """Build the trusted runtime with the FreeLLMAPI gateway via Claude Code adapter.

    The bootstrap registers the FreeLLMAPI provider backed by the Claude Code adapter.
    Provider identity is 'freellmapi' (API gateway), adapter is 'claude-code' (CLI runtime).
    """
    if not isinstance(store, EventStore) or not isinstance(project, Path):
        raise ValidationError("trusted runtime requires the project store and path")
    if not isinstance(config, DiamondConfig):
        raise ValidationError("trusted runtime requires DiamondConfig")

    from .claude_code_adapter import get_adapter
    from .freellmapi import FreeLLMAPIClient, FreeLLMAPIConfig
    from .policy_ipc import PolicyIPCServerContext
    import tempfile

    runtime_config = resolve_gateway_runtime_config()
    try:
        # Authenticated GET /v1/models is bounded and non-inference.  Its result
        # is used only as a readiness gate; catalog data is never persisted.
        FreeLLMAPIClient(
            FreeLLMAPIConfig(runtime_config.base_url),
            environment={"FREELLMAPI_API_KEY": runtime_config.auth_token},
            timeout_seconds=5,
        ).readiness()
    except Exception as exc:
        from .errors import DiamondError
        if isinstance(exc, DiamondError):
            raise ExecutionGuardError("FreeLLMAPI readiness check failed") from None
        raise

    # Create the IPC socket in a temp directory under project state.
    # The socket lives for the entire runtime lifetime.
    ipc_dir = project / ".diamond" / "ipc"
    ipc_dir.mkdir(parents=True, exist_ok=True)
    socket_path = ipc_dir / f"policy-{os.getpid()}.sock"

    # Register the actual provider manifest and record real CLI discovery and
    # contract validation.  No lifecycle state is synthesized by bootstrap.
    registry = ProviderRegistry()
    adapter = get_adapter(runtime_config)
    manifest = adapter.get_capabilities()
    executable = config.providers[Provider.FREELLMAPI].executable
    descriptor = registry.register(
        manifest=manifest,
        executable=executable,
        adapter_id=adapter.adapter_id,
        adapter=adapter,
    )
    discovery = DiscoveryEngine().discover(
        (ExecutableCandidate(descriptor.provider_id, descriptor.executable, descriptor.adapter_id),),
        {descriptor.adapter_id: adapter},
    )[0]
    if discovery.state is not DiscoveryState.DISCOVERED:
        raise ExecutionGuardError("Claude Code executable discovery failed")
    descriptor = registry.record_discovery(discovery)
    validation = adapter.validate(manifest)
    if not validation.valid:
        raise ExecutionGuardError("Claude Code adapter validation failed")
    descriptor = registry.record_validation(
        descriptor.provider_id,
        validation,
        verified_capabilities=manifest.capabilities,
        evidence=validation.evidence,
    )
    descriptor = registry.mark_available(descriptor.provider_id)
    # The authenticated readiness request is the authorization observation for
    # this in-memory runtime; the credential itself is never persisted.
    descriptor = registry.record_authorization(
        descriptor.provider_id,
        authorized=True,
        evidence=("authenticated FreeLLMAPI /v1/models readiness check",),
    )

    # Create and start the IPC server for policy decisions.
    # We use the controller process identity as the authoritative agent.
    controller_agent_id = "controller"
    controller_task_id = "controller-task"
    # No attempt_id at bootstrap; per-attempt binding happens in _trusted_launches.
    ipc_context = PolicyIPCServerContext(
        socket_path=socket_path,
        store=store,
        agent_id=controller_agent_id,
        task_id=controller_task_id,
        attempt_id=None,
        command_prefix="orchestrate:bootstrap",
    )
    ipc_context.start()

    # Wire the IPC config into the adapter's runtime_config so hooks get it.
    runtime_config = runtime_config.__class__(
        base_url=runtime_config.base_url,
        auth_token=runtime_config.auth_token,
        agent_config_dir=runtime_config.agent_config_dir,
        session_id=runtime_config.session_id,
        ipc_socket_path=ipc_context.ipc_socket_path,
        ipc_capability=ipc_context.ipc_capability,
    )

    # Initialize mutable lifecycle state for IPC, watchdog, sweeper.
    from .watchdog import PolicyWatchdog, WatchdogConfig, ApprovalExpirationSweeper
    lifecycle = OrchestrationLifecycle()

    # Track resources for deterministic rollback on partial failure.
    started_resources: list[tuple[str, object, str]] = []  # (name, object, stop_method)

    try:
        # Attach IPC context to lifecycle for lifecycle management.
        lifecycle.ipc_context = ipc_context

        # Start PolicyWatchdog
        lifecycle.watchdog = PolicyWatchdog(
            store=store,
            socket_path=ipc_context.ipc_socket_path,
            capability=ipc_context.ipc_capability,
            agent_id=controller_agent_id,
            task_id=controller_task_id,
            attempt_id=None,
            command_prefix="orchestrate:bootstrap",
            config=WatchdogConfig(check_interval_seconds=30),
        )
        lifecycle.watchdog.start()
        started_resources.append(("watchdog", lifecycle.watchdog, "stop"))

        # Start ApprovalExpirationSweeper
        lifecycle.expiry_sweeper = ApprovalExpirationSweeper(
            store=store,
            command_prefix="orchestrate:bootstrap",
            interval_seconds=config.controller.approval_expiry_sweep_interval_seconds,
        )
        lifecycle.expiry_sweeper.start()
        started_resources.append(("expiry_sweeper", lifecycle.expiry_sweeper, "stop"))

        # Start autonomous watchdog evaluation loop (D2.3)
        from .controller import evaluate_watchdog_restart
        lifecycle.loop_interval = float(config.controller.watchdog_evaluation_interval_seconds)
        lifecycle.shutdown_event = threading.Event()
        lifecycle.eval_thread = threading.Thread(
            target=_watchdog_eval_loop, args=(lifecycle, store, evaluate_watchdog_restart), daemon=True
        )
        lifecycle.eval_thread.start()
        # Note: eval_thread cleanup via shutdown_event in lifecycle cleanup

        # IPC server already started by caller (ipc_context.start() before this function)

    except Exception:
        # Rollback in reverse order
        for name, obj, method_name in reversed(started_resources):
            try:
                getattr(obj, method_name)()
            except Exception:
                pass  # Best-effort cleanup; don't mask original exception
        # Clean up IPC context if it was started
        if lifecycle.ipc_context is not None:
            try:
                lifecycle.ipc_context.stop()
            except Exception:
                pass
        raise

    return OrchestrationRuntime(
        registry=registry,
        available_capabilities=("freellmapi",),
        skill_registry=SkillRegistry(()),
        provider_gateway=ProviderExecutionGateway(registry, (runtime_config.auth_token,)),
        lifecycle=lifecycle,
    )


def _watchdog_eval_loop(lifecycle: OrchestrationLifecycle, store: EventStore,
                        evaluate_fn) -> None:
    """Background thread: periodically evaluate watchdog restart intent."""
    while not lifecycle.shutdown_event.is_set():
        try:
            lifecycle.shutdown_event.wait(lifecycle.loop_interval)
            if lifecycle.shutdown_event.is_set():
                break
            if lifecycle.watchdog is not None:
                result = evaluate_fn(
                    lifecycle.watchdog,
                    store,
                    lifecycle.ipc_context,
                )
                # Record evaluation outcome
                if store._database_present():
                    from uuid import uuid4
                    from .validation import canonical_json, utc_now
                    cmd_id = f"orchestrate:watchdog_eval:{int(time.time() * 1000)}"
                    try:
                        with store._connection(write=True) as conn:
                            from .runtime_store import AgentRuntimeStoreMixin
                            AgentRuntimeStoreMixin._runtime_event(
                                conn,
                                entity_type="watchdog_evaluation",
                                entity_id="controller",
                                revision=1,
                                event_type="EVALUATION",
                                command=cmd_id,
                                payload=canonical_json({
                                    "timestamp": utc_now(),
                                    "result": result,
                                }),
                            )
                    except Exception:
                        pass  # Non-fatal
        except Exception:
            pass  # Non-fatal; continue loop


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _read_json_file(value: object, name: str, project: Path) -> object:
    path = Path(text(value, name, 4096)).expanduser()
    if ".." in path.parts:
        raise ValidationError(f"{name} must not contain traversal components")
    if not path.is_absolute():
        path = project / path
    try:
        path = path.resolve(strict=True)
        if not path.is_file() or path.stat().st_size > 1_048_576:
            raise ValidationError(f"{name} must be a regular JSON file of at most 1 MiB")
        raw = path.read_bytes()
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_json_object)
    except ValidationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValidationError(f"{name} must contain valid UTF-8 JSON: {path}") from exc


def _document_items(value: object, name: str, item_name: str) -> list[object]:
    if not isinstance(value, dict):
        raise ValidationError(f"{name} document must be an object")
    data = dict(exact_keys(value, {"schema_version", item_name}, name))
    if data["schema_version"] != 1:
        raise ValidationError(f"{name} document version must be 1")
    if type(data[item_name]) is not list:
        raise ValidationError(f"{name} must be an array")
    return cast(list[object], data[item_name])


def load_task_document(value: object) -> dict[str, TaskSpec]:
    """Decode the strict task graph document without creating runtime state."""
    tasks: dict[str, TaskSpec] = {}
    for raw in _document_items(value, "tasks", "tasks"):
        spec = TaskSpec.from_dict(raw)
        if spec.task_id in tasks:
            raise ValidationError(f"duplicate task ID: {spec.task_id}")
        tasks[spec.task_id] = spec
    return tasks


def load_launch_document(value: object) -> dict[str, DeclarativeLaunch]:
    """Decode stable launch references without importing executable code."""
    launches: dict[str, DeclarativeLaunch] = {}
    for raw in _document_items(value, "launches", "launches"):
        launch = DeclarativeLaunch.from_dict(raw)
        if launch.task_id in launches:
            raise ValidationError(f"duplicate launch task ID: {launch.task_id}")
        launches[launch.task_id] = launch
    return launches


def _runtime_context(packet: TaskPacket) -> PacketContext:
    return PacketContext(
        packet.plan_revision,
        packet.plan_digest,
        packet.base_digest,
        packet.config_digest,
    )


def _trusted_launches(
    tasks: Mapping[str, TaskSpec],
    descriptors: Mapping[str, DeclarativeLaunch],
    store: EventStore,
    runtime: OrchestrationRuntime,
    owner: str,
    max_workers: int,
) -> dict[str, PersistedLaunch]:
    if runtime.lifecycle is None or runtime.lifecycle.ipc_context is None:
        raise ValidationError("trusted launch requires initialized lifecycle with IPC context")
    launches: dict[str, PersistedLaunch] = {}
    for task_id, descriptor in descriptors.items():
        validate_task_id(task_id)
        if task_id not in tasks:
            raise ValidationError(f"launch references unknown task: {task_id}")
        accepted = store.accepted_packet_by_id(descriptor.accepted_packet_id)
        packet = TaskPacket.from_dict(accepted.to_dict()["packet"])
        if packet.task_id != task_id:
            raise ValidationError("launch accepted packet does not match task_id")
        if packet.provider_id != descriptor.provider_id or packet.adapter_id != descriptor.adapter_id:
            raise ValidationError("launch provider binding does not match accepted packet")
        spec = tasks[task_id]
        metadata = store.provider_metadata(descriptor.provider_id)
        if metadata.adapter_id != descriptor.adapter_id:
            raise ValidationError("launch adapter does not match persisted provider metadata")
        runtime.gateway.validate_execution_binding(accepted.binding, metadata)
        attempt = ExecutionAttempt(
            packet.attempt_id,
            packet.task_id,
            packet.task_revision,
            packet.role,
            packet.provider,
            metadata.executable,
            packet.workspace_root,
            AttemptStatus.INTENDED,
            accepted.accepted_at,
            requested_model=packet.requested_model,
        )
        if (packet.objective, packet.role, packet.provider) != (
            spec.objective,
            spec.role,
            spec.provider,
        ):
            raise ValidationError("launch accepted packet does not match task specification")

        # Create per-attempt IPC context for policy decisions.
        # The controller owns the server; the adapter gets the capability.
        # Each attempt gets its own socket path to avoid binding conflicts.
        from .policy_ipc import PolicyIPCServerContext
        if runtime.lifecycle is None or runtime.lifecycle.ipc_context is None:
            raise ValidationError("trusted launch requires initialized lifecycle with IPC context")
        # Derive per-attempt socket path from bootstrap path to keep them together
        # but distinct: policy-{pid}-{attempt_id}.sock
        bootstrap_socket = runtime.lifecycle.ipc_context.ipc_socket_path
        attempt_socket_path = bootstrap_socket.with_name(
            f"{bootstrap_socket.stem}-{packet.attempt_id[:16]}{bootstrap_socket.suffix}"
        )
        attempt_ipc = PolicyIPCServerContext(
            socket_path=attempt_socket_path,
            store=store,
            agent_id=packet.adapter_id,
            task_id=packet.task_id,
            attempt_id=packet.attempt_id,
            command_prefix=f"orchestrate:{task_id}",
        )
        attempt_ipc.start()

        # Update the adapter's runtime_config with the per-attempt capability
        new_runtime_config = runtime.gateway.registry.get(descriptor.provider_id).adapter._runtime_config
        if new_runtime_config is not None:
            from .claude_code_adapter import ClaudeCodeRuntimeConfig
            new_runtime_config = ClaudeCodeRuntimeConfig(
                base_url=new_runtime_config.base_url,
                auth_token=new_runtime_config.auth_token,
                agent_config_dir=new_runtime_config.agent_config_dir,
                session_id=new_runtime_config.session_id,
                ipc_socket_path=attempt_ipc.ipc_socket_path,
                ipc_capability=attempt_ipc.ipc_capability,
            )
            # Update the adapter's runtime config in-place
            runtime.gateway.registry.get(descriptor.provider_id).adapter._runtime_config = new_runtime_config

        # Store the attempt IPC context for cleanup, keyed by attempt_id
        # so two attempts of the same task never overwrite each other.
        if runtime.lifecycle is not None:
            runtime.lifecycle.register_attempt(packet.attempt_id, attempt_ipc)

        launches[task_id] = PersistedLaunch(
            store=store,
            packet=packet,
            attempt=attempt,
            invocation=None,
            cwd=Path(packet.workspace_root),
            owner=owner,
            registry=runtime.skill_registry,
            context=_runtime_context(packet),
            available_capabilities=runtime.available_capabilities,
            timeout_seconds=packet.timeout_seconds,
            output_limit=packet.output_contract.max_bytes,
            output_artifacts=(),
            max_workers=max_workers,
            provider_gateway=runtime.gateway,
        )
    return launches


def run_declarative_graph(
    tasks: Mapping[str, TaskSpec],
    descriptors: Mapping[str, DeclarativeLaunch],
    *,
    store: EventStore,
    runtime: OrchestrationRuntime,
    owner: str,
    max_workers: int,
    concurrency_limit: int = 1,
    resume_completed: bool = True,
) -> SchedulerResult:
    """Compose trusted runtime dependencies and execute declarative launches."""
    text(owner, "orchestration owner", 256)
    if not isinstance(store, EventStore):
        raise ValidationError("declarative graph requires an EventStore")
    if not isinstance(runtime, OrchestrationRuntime):
        raise ValidationError("declarative graph requires an OrchestrationRuntime")
    task_map = dict(tasks)
    descriptor_map = dict(descriptors)
    if set(task_map) != set(descriptor_map):
        raise ValidationError("task and launch IDs must match")
    bounded_int(max_workers, "max_workers", 1, 64)
    launches = _trusted_launches(task_map, descriptor_map, store, runtime, owner, max_workers)
    try:
        result = run_persisted_graph(
            task_map,
            launches,
            concurrency_limit=concurrency_limit,
            resume_completed=resume_completed,
        )
    finally:
        # Revoke every registered attempt authority and then tear down
        # lifecycle resources. revocation happens before shutdown so no
        # in-flight request can be authorized after the attempt completes.
        if runtime.lifecycle is not None:
            attempts_revoked = runtime.lifecycle.revoke_all()
            # Stop watchdog evaluation thread
            if runtime.lifecycle.shutdown_event is not None:
                try:
                    runtime.lifecycle.shutdown_event.set()
                except Exception:
                    pass
            if runtime.lifecycle.eval_thread is not None:
                try:
                    runtime.lifecycle.eval_thread.join(timeout=5)
                except Exception:
                    pass
            # Stop PolicyWatchdog
            if runtime.lifecycle.watchdog is not None:
                try:
                    runtime.lifecycle.watchdog.stop()
                except Exception:
                    pass
            # Stop ApprovalExpirationSweeper
            if runtime.lifecycle.expiry_sweeper is not None:
                try:
                    runtime.lifecycle.expiry_sweeper.stop()
                except Exception:
                    pass
            # Clean up bootstrap IPC context (stop, not revoke — bootstrap lives until graph shutdown)
            if runtime.lifecycle.ipc_context is not None:
                try:
                    runtime.lifecycle.ipc_context.stop()
                except Exception:
                    pass
    return result


def orchestrate_command(args: Any, config_path: Path, config: DiamondConfig) -> tuple[dict[str, Any], int]:
    """Handle the narrow declarative orchestration CLI surface."""
    paths = resolve_paths(args.project, str(config_path), getattr(args, "state_dir", None))
    if args.orchestration_command == "verify-policy":
        report = verify_policy(paths.config, paths.project)
        return report, 0 if report["ok"] else 1
    if args.orchestration_command == "verify-invariants":
        report = verify_invariants(paths.config, paths.project)
        return report, 0 if report["ok"] else 1
    if args.orchestration_command != "run":
        raise ValidationError("unsupported orchestration command")
    store = EventStore(paths.database)
    tasks = load_task_document(_read_json_file(args.tasks, "tasks file", paths.project))
    descriptors = load_launch_document(_read_json_file(args.launches, "launches file", paths.project))
    limit = args.concurrency_limit if args.concurrency_limit is not None else config.controller.max_workers
    bounded_int(limit, "concurrency_limit", 1, 64)
    owner = args.owner or f"cli:orchestrate:{paths.project.name}"
    with project_owner(paths.project, paths.state):
        recover_on_startup(store, "orchestrate startup")
        runtime = build_trusted_runtime(store, paths.project, config)
        result = run_declarative_graph(
            tasks,
            descriptors,
            store=store,
            runtime=runtime,
            owner=owner,
            max_workers=limit,
            concurrency_limit=limit,
            resume_completed=args.resume_completed,
        )
    return scheduler_result_to_dict(result), 0 if result.all_succeeded else 1


def _mapping_copy(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{name} must be a mapping")
    return dict(value)


def _validate_launch_graph(
    tasks: Mapping[str, TaskSpec], launches: Mapping[str, PersistedLaunch]
) -> tuple[dict[str, TaskSpec], dict[str, PersistedLaunch]]:
    task_map = _mapping_copy(tasks, "tasks")
    launch_map = _mapping_copy(launches, "launches")

    if any(not isinstance(task_id, str) or not task_id for task_id in task_map):
        raise ValidationError("task mapping keys must be nonblank strings")
    if any(not isinstance(task_id, str) or not task_id for task_id in launch_map):
        raise ValidationError("launch mapping keys must be nonblank strings")
    if any(not isinstance(spec, TaskSpec) for spec in task_map.values()):
        raise ValidationError("tasks must contain TaskSpec values")
    if any(not isinstance(launch, PersistedLaunch) for launch in launch_map.values()):
        raise ValidationError("launches must contain PersistedLaunch values")

    typed_tasks: dict[str, TaskSpec] = {
        task_id: cast(TaskSpec, spec) for task_id, spec in task_map.items()
    }
    typed_launches: dict[str, PersistedLaunch] = {
        task_id: cast(PersistedLaunch, launch) for task_id, launch in launch_map.items()
    }
    task_ids = set(typed_tasks)
    launch_ids = set(typed_launches)
    if task_ids != launch_ids:
        missing = sorted(task_ids - launch_ids)
        extra = sorted(launch_ids - task_ids)
        detail = []
        if missing:
            detail.append(f"missing launches: {', '.join(missing)}")
        if extra:
            detail.append(f"unknown launches: {', '.join(extra)}")
        raise ValidationError("task and launch IDs must match; " + "; ".join(detail))

    databases = {launch.store.database.resolve() for launch in typed_launches.values()}
    if len(databases) > 1:
        raise ValidationError("all persisted launches must use the same ledger database")
    owners = {launch.owner for launch in typed_launches.values()}
    if len(owners) > 1:
        raise ValidationError("all persisted launches must use the same execution owner")
    return typed_tasks, typed_launches


def run_persisted_graph(
    tasks: Mapping[str, TaskSpec],
    launches: Mapping[str, PersistedLaunch],
    *,
    concurrency_limit: int = 1,
    resume_completed: bool = True,
) -> SchedulerResult:
    """Run a validated task graph through the persisted controller boundary.

    The function validates graph-to-launch correspondence, then delegates DAG
    ordering to :class:`Scheduler` and execution to
    :class:`PersistedControllerDispatcher`. It does not acquire project
    ownership or perform startup recovery; those operations belong to the
    command boundary that owns the project lifecycle.
    """
    bounded_int(concurrency_limit, "concurrency_limit", 1, 64)
    if type(resume_completed) is not bool:
        raise ValidationError("resume_completed must be boolean")
    task_map, launch_map = _validate_launch_graph(tasks, launches)
    dispatcher = PersistedControllerDispatcher(
        launch_map,
        resume_completed=resume_completed,
    )
    return Scheduler(
        task_map,
        concurrency_limit=concurrency_limit,
    ).run(dispatcher)


def scheduler_result_to_dict(result: SchedulerResult) -> dict[str, Any]:
    """Serialize a scheduler result for the standard machine-readable CLI envelope."""
    if not isinstance(result, SchedulerResult):
        raise ValidationError("scheduler result must be a SchedulerResult")
    return {
        "outcome": result.outcome.value,
        "ordered": list(result.ordered),
        "results": {
            task_id: {
                "task_id": item.task_id,
                "status": item.status.value,
                "error": item.error,
                "metadata": dict(item.metadata),
            }
            for task_id, item in result.results.items()
        },
        "errors": list(result.errors),
    }
