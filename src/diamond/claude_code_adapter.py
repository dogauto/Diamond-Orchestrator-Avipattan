"""Concrete ProviderAdapter implementation for Claude Code.

This adapter wires the `claude -p <prompt>` invocation path from
``real_cli_integration.py`` into Diamond's execution spine (ProviderExecutionGateway,
ProviderRegistry, DiscoveryEngine).  It implements every method of the
``ProviderAdapter`` Protocol so that the controller can:

  1. Discover the `claude` executable via `discover()`.
  2. Validate its capability manifest via `validate()`.
  3. Run health checks via `health_check()`.
  4. Execute child sessions via `execute()` → `claude -p <prompt>`.
  5. Normalize raw output via `normalize_result()` into
     ``NormalizedExecutionResult`` with provenance tracking.
  6. Cancel an outstanding process via `cancel()`.

The adapter is registered under ``adapter_id="claude-code"`` and is bound into
the ProviderRegistry so that DiscoveryEngine.discover() can transition state
from DECLARED → DISCOVERED → AVAILABLE.

The adapter also generates per-agent Claude settings files that install the
Diamond Policy Classifier hook (PreToolUse/PostToolUse), replacing Claude Code's
Auto Mode classifier as the tool-execution decision authority.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ValidationError
from .provider_contracts import (
    ADAPTER_CONTRACT_VERSION,
    Capability,
    CapabilityManifest,
    ExecutionMode,
    ManifestValidationResult,
    ManifestValidationStatus,
    ProviderAdapter,
    contract_version_is_compatible,
)
from .provider_execution import (
    CancellationRequest,
    CancellationResult,
    ExecutionEvent,
    ExecutionOutcome,
    ExecutionPolicyMode,
    HealthCheckRequest,
    HealthCheckResult,
    NormalizedExecutionResult,
    ProviderProvenance,
    ProviderRawExecution,
    TaskExecutionRequest,
    VersionProbeResult,
    VersionProbeRunner,
)
from .claude_session import assert_session_id_matches
from .freellmapi import normalize_base_url
from .sandbox import cleanup_runtime, prepare_read_only
from .validation import utc_now


# ── Constants ────────────────────────────────────────────────────────────

_CLAUDE_PRINT_FLAG = "-p"
_CLAUDE_TIMEOUT = 30  # seconds, matches real_cli_integration.py

_ADAPTER_ID = "claude-code"
_PROVIDER_ID = "freellmapi"
_ADAPTER_CONTRACT_VERSION = ADAPTER_CONTRACT_VERSION  # "1.0"


@dataclass(frozen=True)
class ClaudeCodeRuntimeConfig:
    """Process-local gateway settings; never serialized into Diamond state."""

    base_url: str
    auth_token: str = field(repr=False, compare=False)
    agent_config_dir: Path | None = None
    session_id: str | None = None
    ipc_socket_path: Path | None = None
    ipc_capability: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "base_url", normalize_base_url(self.base_url))
        if (not isinstance(self.auth_token, str) or not self.auth_token
                or len(self.auth_token) > 4096
                or any(not 33 <= ord(char) <= 126 for char in self.auth_token)):
            raise ValidationError("Claude Code gateway credential must be printable ASCII")
        if self.agent_config_dir is not None:
            if not isinstance(self.agent_config_dir, Path):
                raise ValidationError("agent config dir must be a pathlib.Path")
            if ".." in self.agent_config_dir.parts:
                raise ValidationError("agent config dir must not contain traversal components")
        if self.session_id is not None:
            from .claude_session import validate_provider_session_id
            validate_provider_session_id(self.session_id, "runtime session id")
        if self.ipc_socket_path is not None:
            if not isinstance(self.ipc_socket_path, Path):
                raise ValidationError("ipc socket path must be a pathlib.Path")
            if ".." in self.ipc_socket_path.parts:
                raise ValidationError("ipc socket path must not contain traversal components")


# ── Version Probe (discover) ────────────────────────────────────────────

def _probe_claude_version(executable: Path, runner: VersionProbeRunner) -> VersionProbeResult:
    """Probe `claude --version` using the supplied VersionProbeRunner."""
    try:
        resolved = runner.run([str(executable), "--version"], timeout_seconds=_CLAUDE_TIMEOUT, output_limit=4096)
        if resolved.returncode != 0:
            return VersionProbeResult(
                status="unavailable",
                returncode=resolved.returncode,
                stdout=resolved.stdout,
                stderr=resolved.stderr,
            )
        # Parse version from stdout; format may be "Claude Code X.Y.Z" or similar
        version_match = re.search(r"(\d+\.\d+\.\d+)", resolved.stdout)
        version = version_match.group(1) if version_match else None
        return VersionProbeResult(
            status="available",
            returncode=resolved.returncode,
            stdout=resolved.stdout,
            stderr=resolved.stderr,
            version=version,
        )
    except (OSError, ValidationError) as exc:
        return VersionProbeResult(
            status="unavailable",
            returncode=-1,
            stdout="",
            stderr=str(exc),
        )


def _sandbox_child_pid(launcher_pid: int | None) -> int | None:
    """Best-effort distinction between sandbox-exec and its launched child."""
    # Avoid probing through a patched subprocess boundary in deterministic
    # adapter tests; a real Popen class is present for production launches.
    if launcher_pid is None or os.name != "posix" or not isinstance(subprocess.Popen, type):
        return None
    try:
        result = subprocess.run(
            ["/usr/bin/pgrep", "-P", str(launcher_pid)],
            capture_output=True,
            text=True,
            timeout=1,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError):
        return None
    for value in result.stdout.split():
        if value.isdigit() and int(value) > 0:
            return int(value)
    return None


# ── Capability Manifest ─────────────────────────────────────────────────

_DEFAULT_MANIFEST = CapabilityManifest(
    provider_id="freellmapi",
    capabilities=frozenset({Capability.ONE_SHOT_EXECUTION, Capability.TIMEOUT_ENFORCEMENT,
                            Capability.HEALTH_CHECKS}),
    supported_execution_modes=frozenset({ExecutionMode.ONE_SHOT}),
    known_limitations=(
        "Requires DIAMOND_REAL_CLI=1 and `claude` CLI on PATH",
        "Output parsed as non-JSON text; structured output not supported",
    ),
    validation_status=ManifestValidationStatus.DECLARED,
)


# ── ProviderAdapter Implementation ──────────────────────────────────────

class ClaudeCodeAdapter:
    """Concrete ProviderAdapter for Claude Code via `claude -p <prompt>`."""

    adapter_id = _ADAPTER_ID
    adapter_contract_version = _ADAPTER_CONTRACT_VERSION

    # Maximum output sizes (1 MB each)
    _MAX_STDOUT = 1_048_576
    _MAX_STDERR = 1_048_576

    def __init__(self, executable: Path | None = None,
                 runtime_config: ClaudeCodeRuntimeConfig | None = None) -> None:
        self._executable = executable or self._find_executable()
        if runtime_config is not None and not isinstance(runtime_config, ClaudeCodeRuntimeConfig):
            raise ValidationError("Claude Code runtime configuration is invalid")
        self._runtime_config = runtime_config
        # Execution-scoped process registry
        self._processes: dict[str, subprocess.Popen] = {}
        self._processes_lock = threading.Lock()
        # Serialize only sandbox construction and child registration.  Once
        # registered, executions communicate and cancel independently.
        self._launch_lock = threading.Lock()

    # ── discovery ──────────────────────────────────────────────────────

    def discover(self, executable: Path, runner: VersionProbeRunner) -> VersionProbeResult:
        return _probe_claude_version(executable, runner)

    # ── validate ───────────────────────────────────────────────────────

    def validate(self, manifest: CapabilityManifest) -> ManifestValidationResult:
        if manifest.provider_id != _PROVIDER_ID:
            return ManifestValidationResult(
                False, ManifestValidationStatus.INVALID,
                f"manifest provider_id '{manifest.provider_id}' does not match provider_id '{_PROVIDER_ID}'",
            )
        if not contract_version_is_compatible(manifest.adapter_contract_version):
            return ManifestValidationResult(
                False, ManifestValidationStatus.INVALID,
                f"adapter contract version '{manifest.adapter_contract_version}' is incompatible",
            )
        # Accept manifest; validation status will be updated by registry
        return ManifestValidationResult(
            True, ManifestValidationStatus.VALIDATED, "manifest validated successfully",
        )

    # ── health_check ───────────────────────────────────────────────────

    def health_check(self, request: HealthCheckRequest) -> HealthCheckResult:
        # Probe the executable exists and is callable (use --version which exits fast)
        try:
            result = subprocess.run(
                [str(self._executable), "--version"],
                capture_output=True, text=True, timeout=min(request.timeout_seconds, 5),
            )
            stdout = result.stdout.strip()
            stderr = result.stderr.strip() if result.stderr else ""
            exit_code = result.returncode

            # If claude --version responds, treat as healthy
            status = "healthy" if exit_code == 0 else "unhealthy"
            auth_status = "NOT_CHECKED"  # Auth status is separate; not enforced here

            detail = f"exit_code={exit_code}"
            if stdout:
                detail += f" version={stdout[:128]}"
            if stderr:
                detail += f" stderr={stderr[:128]}"

            return HealthCheckResult(
                provider_id=request.provider_id,
                status=status,
                checked_at=utc_now(),
                detail=detail,
                auth_status=auth_status,
            )
        except subprocess.TimeoutExpired:
            return HealthCheckResult(
                provider_id=request.provider_id,
                status="unhealthy",
                checked_at=utc_now(),
                detail="health check timed out",
                auth_status="NOT_CHECKED",
            )
        except FileNotFoundError:
            return HealthCheckResult(
                provider_id=request.provider_id,
                status="unhealthy",
                checked_at=utc_now(),
                detail="claude executable not found",
                auth_status="NOT_CHECKED",
            )
        except Exception as exc:  # broad, but we never raise; return unhealthy
            return HealthCheckResult(
                provider_id=request.provider_id,
                status="unhealthy",
                checked_at=utc_now(),
                detail=f"health check error: {exc}",
                auth_status="NOT_CHECKED",
            )

    # ── get_capabilities ───────────────────────────────────────────────

    def get_capabilities(self) -> CapabilityManifest:
        return _DEFAULT_MANIFEST

    # ── execute ────────────────────────────────────────────────────────

    def execute(self, request: TaskExecutionRequest) -> ProviderRawExecution:
        """Execute `claude -p <prompt>` and return raw ProviderRawExecution.

        Uses instance-level process handle so each execution is independent.
        Timestamps capture start before execution and end after completion.
        """
        prompt = request.input_text or ""
        timeout = request.timeout_seconds
        provider_session_id = request.continuation_session_id
        started_at = utc_now()
        policy = request.execution_policy
        if policy is None:
            return self._failed_execution(request, started_at, None, "execution policy is required")

        environment = self.build_child_environment()

        # Install Diamond policy hook settings into per-agent config dir
        if self._runtime_config is not None and self._runtime_config.agent_config_dir is not None:
            config_dir = self._runtime_config.agent_config_dir
            self.install_policy_hook(
                config_dir=config_dir,
                agent_id=self._runtime_config.session_id or "unknown",
                session_id=self._runtime_config.session_id or "unknown",
                provider_session_id=provider_session_id,
                task_id=request.task_id,
                attempt_id=None,
                workspace_root=policy.workspace_root,
                owned_paths=policy.owned_paths if policy.mode is ExecutionPolicyMode.WRITABLE else (),
                network_access=policy.network_access,
                execution_policy_mode=policy.mode.value,
                delegation_id=None,
                delegation_scope=(),
                authorization_evidence=(),
                ipc_socket_path=self._runtime_config.ipc_socket_path,
                ipc_capability=self._runtime_config.ipc_capability,
            )
            environment["CLAUDE_CONFIG_DIR"] = str(config_dir)

        command = [str(self._executable), _CLAUDE_PRINT_FLAG, prompt, "--output-format", "json"]
        if provider_session_id is not None:
            # Continuing a controller-owned conversation.  The session id is the
            # previously persisted provider_session_id; the CLI resumes it.
            command.extend(("--resume", provider_session_id))
        elif self._runtime_config is not None and self._runtime_config.session_id is not None:
            # New conversation.  The controller generated the UUID; the CLI
            # echoes it back and we validate it before persisting.
            command.extend(("--session-id", self._runtime_config.session_id))
        if policy.mode is ExecutionPolicyMode.READ_ONLY:
            for name in ("ANTHROPIC_MODEL", "ANTHROPIC_DEFAULT_OPUS_MODEL",
                         "ANTHROPIC_DEFAULT_SONNET_MODEL", "ANTHROPIC_DEFAULT_HAIKU_MODEL"):
                environment[name] = "auto"
            environment.setdefault("CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY", "1")
            command.extend(("--restricted", "--permission-mode", "default",
                            "--permission-prompts", "none", "--no-session-persistence",
                            "--tools", "Read,Glob,Grep"))
        else:
            command.extend(("--permission-mode", "default"))
        sandbox_runtime = None
        try:
            with self._launch_lock:
                command, sandbox_runtime = prepare_read_only(
                    Path(policy.workspace_root), tuple(command), environment, "claude",
                    policy.owned_paths if policy.mode is ExecutionPolicyMode.WRITABLE else (),
                    network_access=policy.network_access,
                    restrict_workspace_reads=True,
                    allow_provider_state_writes=False,
                )
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    cwd=policy.workspace_root,
                    env=environment,
                    start_new_session=os.name == "posix",
                )
                launcher_process_id = process.pid if type(process.pid) is int and process.pid > 0 else None
                child_process_id = _sandbox_child_pid(launcher_process_id)
                process_id = child_process_id or launcher_process_id
                with self._processes_lock:
                    if request.correlation_id in self._processes:
                        try:
                            process.kill()
                            process.wait(timeout=5)
                        except Exception:
                            pass
                        raise ValidationError(f"execution already registered: {request.correlation_id}")
                    self._processes[request.correlation_id] = process
        except Exception as exc:
            if sandbox_runtime is not None:
                cleanup_runtime(sandbox_runtime)
            if isinstance(exc, ValidationError) and str(exc).startswith("execution already registered:"):
                raise
            return self._failed_execution(request, started_at, None, str(exc))

        try:
            # Bounded communication — limit output size
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                exit_code = process.returncode
            except subprocess.TimeoutExpired:
                if type(process.pid) is not int:
                    process.kill()
                    process.wait(timeout=5)
                else:
                    self._terminate_process(process)
                stdout, stderr = process.communicate()
                exit_code = -1
                outcome = ExecutionOutcome.TIMEOUT
            else:
                outcome = ExecutionOutcome.SUCCEEDED if exit_code == 0 else ExecutionOutcome.FAILED

            completed_at = utc_now()

            # Bound stdout and stderr to prevent memory exhaustion
            stdout = (stdout or "")[:self._MAX_STDOUT]
            stderr = (stderr or "")[:self._MAX_STDERR]

            # Parse events — Claude typically returns plain text, not structured events
            events: tuple[ExecutionEvent, ...] = ()

            return ProviderRawExecution(
                provider_id=_PROVIDER_ID,
                task_id=request.task_id,
                correlation_id=request.correlation_id,
                outcome=outcome,
                started_at=started_at,
                completed_at=completed_at,
                exit_code=exit_code,
                signal=None,
                stdout=stdout,
                stderr=stderr,
                events=events,
                artifacts=(),
                diagnostics=(),
                provider_version=None,
                session_id=provider_session_id,
                process_id=process_id,
                launcher_process_id=launcher_process_id,
                child_process_id=child_process_id,
            )

        except Exception as exc:  # broad catch — never raise from adapter
            completed_at = utc_now()
            # Clean up process handle even on error
            if process.poll() is None:
                try:
                    self._terminate_process(process)
                except Exception:
                    pass
            return ProviderRawExecution(
                provider_id=_PROVIDER_ID,
                task_id=request.task_id,
                correlation_id=request.correlation_id,
                outcome=ExecutionOutcome.START_FAILED,
                started_at=started_at,
                completed_at=completed_at,
                exit_code=-1,
                signal=None,
                stdout="",
                stderr=str(exc),
                events=(),
                artifacts=(),
                diagnostics=(),
                provider_version=None,
                session_id=provider_session_id,
                process_id=process_id,
                launcher_process_id=launcher_process_id,
                child_process_id=child_process_id,
            )
        finally:
            # Clean up process registry
            with self._processes_lock:
                self._processes.pop(request.correlation_id, None)
            if sandbox_runtime is not None:
                cleanup_runtime(sandbox_runtime)

    # ── cancel ─────────────────────────────────────────────────────────

    def cancel(self, request: CancellationRequest) -> CancellationResult:
        """Cancel an outstanding claude process if running."""
        execution_id = request.correlation_id
        with self._processes_lock:
            process = self._processes.get(execution_id)
            if process is not None and process.poll() is None:
                try:
                    self._terminate_process(process)
                except Exception:
                    pass
                self._processes.pop(execution_id, None)
                return CancellationResult(
                    provider_id=request.provider_id,
                    task_id=request.task_id,
                    correlation_id=request.correlation_id,
                    status="cancelled",
                    detail="process terminated via cancel request",
                )
        # Process already finished or never started
        return CancellationResult(
            provider_id=request.provider_id,
            task_id=request.task_id,
            correlation_id=request.correlation_id,
            status="not_found",
            detail="no outstanding process to cancel",
        )

    # ── normalize_result ───────────────────────────────────────────────

    def normalize_result(self, request: TaskExecutionRequest, raw: ProviderRawExecution) -> NormalizedExecutionResult:
        """Convert a raw ProviderRawExecution into a NormalizedExecutionResult with provenance."""
        provenance = ProviderProvenance(
            provider_id=_PROVIDER_ID,
            provider_version=raw.provider_version,
            adapter_id=self.adapter_id,
            adapter_contract_version=self.adapter_contract_version,
            manifest_digest=_DEFAULT_MANIFEST.digest,
            source="claude_code_adapter",
        )
        content, session_id, reported_model, model_selection, diagnostics = self._decode_output(raw.stdout)
        session_id = self._validate_session_id(request, raw, session_id)
        # On non-success outcomes the controller's known continuation id
        # stands, so the persistent session identity survives the attempt.
        if session_id is None and raw.outcome is not ExecutionOutcome.SUCCEEDED:
            session_id = request.continuation_session_id
        return NormalizedExecutionResult(
            provider_id=_PROVIDER_ID,
            task_id=request.task_id,
            correlation_id=request.correlation_id,
            outcome=raw.outcome,
            content=content or None,
            reported_model=reported_model,
            session_id=session_id or raw.session_id,
            structured_output_json=None,
            events=raw.events,
            artifacts=raw.artifacts,
            diagnostics=raw.diagnostics + diagnostics,
            provenance=provenance,
            model_selection=model_selection,
            process_id=raw.process_id,
            launcher_process_id=raw.launcher_process_id,
            child_process_id=raw.child_process_id,
        )

    def build_child_environment(self, parent: dict[str, str] | None = None) -> dict[str, str]:
        """Build a child-only environment without mutating the parent process."""
        environment = dict(os.environ if parent is None else parent)
        if self._runtime_config is not None:
            environment["ANTHROPIC_BASE_URL"] = self._runtime_config.base_url
            environment["ANTHROPIC_AUTH_TOKEN"] = self._runtime_config.auth_token
            environment.pop("ANTHROPIC_API_KEY", None)
        return environment

    @staticmethod
    def install_policy_hook(config_dir: Path, agent_id: str, session_id: str,
                            provider_session_id: str | None = None,
                            task_id: str = "", attempt_id: str | None = None,
                            workspace_root: str = "",
                            owned_paths: tuple[str, ...] = (),
                            network_access: str = "loopback",
                            execution_policy_mode: str = "writable",
                            delegation_id: str | None = None,
                            delegation_scope: tuple[str, ...] = (),
                            authorization_evidence: tuple[str, ...] = (),
                            ipc_socket_path: Path | None = None,
                            ipc_capability: str | None = None) -> Path:
        """Install Diamond policy hook settings into a per-agent Claude config dir.

        Writes settings.json with PreToolUse and PostToolUse hooks that invoke
        the Diamond policy classifier.  Does not modify the user's global settings.
        """
        if not isinstance(config_dir, Path):
            raise ValidationError("config_dir must be a pathlib.Path")
        if ".." in config_dir.parts:
            raise ValidationError("config_dir must not contain traversal components")

        config_dir.mkdir(parents=True, exist_ok=True)
        settings_path = config_dir / "settings.json"

        hook_script = Path(__file__).parent / "policy_hook.py"

        env = {
            "DIAMOND_AGENT_ID": agent_id,
            "DIAMOND_SESSION_ID": session_id,
            "DIAMOND_PROVIDER_SESSION_ID": provider_session_id or "",
            "DIAMOND_PROVIDER": "freellmapi",
            "DIAMOND_ADAPTER_ID": "claude-code",
            "DIAMOND_TASK_ID": task_id,
            "DIAMOND_ATTEMPT_ID": attempt_id or "",
            "DIAMOND_WORKSPACE_ROOT": workspace_root,
            "DIAMOND_OWNED_PATHS": ":".join(owned_paths),
            "DIAMOND_NETWORK_ACCESS": network_access,
            "DIAMOND_EXECUTION_POLICY": execution_policy_mode,
            "DIAMOND_DELEGATION_ID": delegation_id or "",
            "DIAMOND_DELEGATION_SCOPE": ":".join(delegation_scope),
            "DIAMOND_AUTH_EVIDENCE": ":".join(authorization_evidence),
        }

        # Add IPC socket path and capability if provided by controller
        if ipc_socket_path is not None:
            env["DIAMOND_IPC_SOCKET_PATH"] = str(ipc_socket_path)
        if ipc_capability is not None:
            env["DIAMOND_POLICY_CAPABILITY"] = str(ipc_capability)

        settings = {
            "env": env,
            "permissions": {
                "allow": [],
                "deny": [],
            },
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "*",
                        "hooks": [
                            {
                                "type": "command",
                                "command": f"python3 {hook_script} pre-tool-use",
                                "timeout": 15000,
                                "onFailure": "block",
                            }
                        ],
                    }
                ],
                "PostToolUse": [
                    {
                        "matcher": "*",
                        "hooks": [
                            {
                                "type": "command",
                                "command": f"python3 {hook_script} post-tool-use",
                                "timeout": 5000,
                                "onFailure": "continue",
                            }
                        ],
                    }
                ],
            },
        }

        with open(settings_path, "w", encoding="utf-8") as handle:
            json.dump(settings, handle, indent=2, sort_keys=True)
            handle.write("\n")

        # Ensure only the owner can read/write
        os.chmod(settings_path, 0o600)

        return settings_path

    @staticmethod
    def _decode_output(value: str) -> tuple[str, str | None, str | None, str | None, tuple[str, ...]]:
        """Extract Claude's structured result while retaining safe text fallback."""
        if not value:
            return "", None, None, None, ()
        try:
            payload = json.loads(value)
        except (TypeError, ValueError, json.JSONDecodeError):
            return value, None, None, None, ()
        if not isinstance(payload, dict):
            return value, None, None, None, ()
        result = payload.get("result")
        content = result if isinstance(result, str) else value
        session_id = payload.get("session_id") if isinstance(payload.get("session_id"), str) else None
        reported_model = payload.get("model") if isinstance(payload.get("model"), str) else None
        model_selection = None
        usage = payload.get("modelUsage")
        if isinstance(usage, dict) and "auto" in usage:
            model_selection = "auto"
            auto_usage = usage.get("auto")
            if isinstance(auto_usage, dict) and isinstance(auto_usage.get("canonicalModel"), str):
                reported_model = auto_usage["canonicalModel"]
        diagnostics: tuple[str, ...] = ()
        if payload.get("is_error") is True and isinstance(payload.get("subtype"), str):
            diagnostics = (payload["subtype"],)
        return content, session_id, reported_model, model_selection, diagnostics

    # ── private helpers ────────────────────────────────────────────────

    @staticmethod
    def _terminate_process(process: subprocess.Popen) -> None:
        if type(process.pid) is not int:
            process.terminate()
            process.wait(timeout=5)
            return
        if os.name == "posix" and type(process.pid) is int and process.pid > 0:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=2)
                return
            except (OSError, ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    pass
        try:
            process.terminate()
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
        except OSError:
            pass

    @staticmethod
    def _validate_session_id(request: TaskExecutionRequest, raw: ProviderRawExecution,
                             decoded_session_id: str | None) -> str | None:
        """Validate the provider-returned session id before it is persisted.

        For continued conversations the id is the previously persisted
        ``continuation_session_id``; the CLI must echo it back unchanged.
        For new conversations the controller generated the id (in
        ``runtime_config.session_id``) and the CLI must echo that back.  A
        mismatch raises so the controller never trusts provider output as
        session identity.  When the provider returns nothing (e.g. a timeout)
        the controller's known id stands; when no controller-owned id is in
        play the decoded value is returned unchanged, preserving the existing
        lenient contract.
        """
        if raw.outcome is not ExecutionOutcome.SUCCEEDED:
            return decoded_session_id
        expected = request.continuation_session_id
        if expected is None and raw.session_id is not None:
            expected = raw.session_id
        if expected is None:
            return decoded_session_id
        if decoded_session_id is None:
            return expected
        if decoded_session_id != expected:
            raise ValidationError(
                f"provider session id {decoded_session_id!r} does not match expected {expected!r}"
            )
        return decoded_session_id

    @staticmethod
    def _failed_execution(request: TaskExecutionRequest, started_at: str,
                          process_id: int | None, detail: str) -> ProviderRawExecution:
        return ProviderRawExecution(
            provider_id=_PROVIDER_ID,
            task_id=request.task_id,
            correlation_id=request.correlation_id,
            outcome=ExecutionOutcome.START_FAILED,
            started_at=started_at,
            completed_at=utc_now(),
            exit_code=-1,
            signal=None,
            stdout="",
            stderr=detail,
            events=(),
            artifacts=(),
            diagnostics=(),
            provider_version=None,
            session_id=request.continuation_session_id,
            process_id=process_id,
        )

    @staticmethod
    def _find_executable() -> Path:
        """Find `claude` executable on PATH, raising ValidationError if not found."""
        from shutil import which
        path = which("claude")
        if path is None:
            raise ValidationError("claude executable not found on PATH; install Claude Code CLI or set DIAMOND_REAL_CLI=1")
        return Path(path)


# ── Module-level singleton for registry binding ──────────────────────────

_adapter_instance: ClaudeCodeAdapter | None = None


def get_adapter(runtime_config: ClaudeCodeRuntimeConfig | None = None) -> ClaudeCodeAdapter:
    """Return the module-level ClaudeCodeAdapter instance (lazy init)."""
    global _adapter_instance
    if runtime_config is not None:
        return ClaudeCodeAdapter(runtime_config=runtime_config)
    if _adapter_instance is None:
        _adapter_instance = ClaudeCodeAdapter()
    return _adapter_instance


# ── Protocol compliance shim so type-checkers see the Protocol ──────────

def _make_adapter_protocol_shim() -> object:
    """Return an object that satisfies the ProviderAdapter Protocol signature.

    This is used by registry binding code that expects a Protocol instance
    rather than a concrete class in some type‑checking paths.
    """
    adapter = get_adapter()
    # All Protocol methods are callable on the adapter instance
    return adapter


__all__ = [
    "ClaudeCodeAdapter",
    "get_adapter",
    "_make_adapter_protocol_shim",
    "_ADAPTER_ID",
    "_ADAPTER_CONTRACT_VERSION",
    "_PROVIDER_ID",
    "ClaudeCodeRuntimeConfig",
    "SESSION_ID_HEADER",
]

# Header echoed by the Claude CLI when a new ``--session-id`` is created.  The
# adapter validates this value before any session identity is persisted.
SESSION_ID_HEADER = "session_id"
