"""Provider-neutral execution, health, cancellation, and adapter contracts."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol, Sequence

from .errors import ValidationError
from .provider_contracts import (
    CapabilityManifest,
    ManifestValidationResult,
    TaskExecutionRequest,
    contract_version_is_compatible,
    provider_identifier,
)
from .validation import bounded_int, canonical_json, command_id, text, utc_timestamp


@dataclass(frozen=True)
class ArtifactReference:
    uri: str
    sha256: str | None = None
    media_type: str | None = None

    def __post_init__(self) -> None:
        text(self.uri, "artifact URI", 4096)
        if self.sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", self.sha256):
            raise ValidationError("artifact SHA-256 must be lowercase hexadecimal")
        if self.media_type is not None:
            text(self.media_type, "artifact media type", 256)


class ExecutionEventKind(str, Enum):
    STARTED = "started"
    PROGRESS = "progress"
    MESSAGE = "message"
    ARTIFACT = "artifact"
    DIAGNOSTIC = "diagnostic"
    COMPLETED = "completed"


@dataclass(frozen=True)
class ExecutionEvent:
    sequence: int
    kind: ExecutionEventKind
    timestamp: str
    message: str | None = None
    data_json: str | None = None
    artifact: ArtifactReference | None = None

    def __post_init__(self) -> None:
        bounded_int(self.sequence, "event sequence", 0, 2**31 - 1)
        if not isinstance(self.kind, ExecutionEventKind):
            raise ValidationError("execution event kind is invalid")
        utc_timestamp(self.timestamp)
        if self.message is not None:
            text(self.message, "execution event message", 16_384)
        if self.data_json is not None:
            try:
                if canonical_json(json.loads(self.data_json)) != self.data_json:
                    raise ValidationError("execution event data is not canonical JSON")
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ValidationError("execution event data is invalid JSON") from exc
        if self.artifact is not None and not isinstance(self.artifact, ArtifactReference):
            raise ValidationError("execution event artifact is invalid")


class ExecutionOutcome(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    START_FAILED = "start_failed"
    OUTPUT_LIMIT = "output_limit"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


class ExecutionPolicyMode(str, Enum):
    READ_ONLY = "read_only"
    WRITABLE = "writable"


@dataclass(frozen=True)
class ExecutionPolicy:
    """Controller-authorized process policy for one provider attempt."""

    mode: ExecutionPolicyMode
    workspace_root: str
    owned_paths: tuple[str, ...] = ()
    network_access: str = "loopback"

    def __post_init__(self) -> None:
        if not isinstance(self.mode, ExecutionPolicyMode):
            raise ValidationError("execution policy mode is invalid")
        if not isinstance(self.workspace_root, str) or not self.workspace_root:
            raise ValidationError("execution policy workspace root is required")
        root = Path(self.workspace_root).resolve(strict=True)
        if not root.is_dir():
            raise ValidationError("execution policy workspace root must be a directory")
        object.__setattr__(self, "workspace_root", str(root))
        if type(self.owned_paths) is not tuple:
            raise ValidationError("execution policy owned paths must be a tuple")
        for relative in self.owned_paths:
            if not isinstance(relative, str) or not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
                raise ValidationError("execution policy owned paths must be relative and contained")
            target = (root / relative).resolve()
            if not target.is_relative_to(root) or target == root:
                raise ValidationError("execution policy owned path escapes the workspace")
        if self.network_access not in {"denied", "loopback", "full"}:
            raise ValidationError("execution policy network access is invalid")
        if self.mode is ExecutionPolicyMode.READ_ONLY and self.network_access == "full":
            raise ValidationError("read-only execution cannot request full network access")

    @classmethod
    def from_packet(cls, mode: str, workspace_root: str, owned_paths: tuple[str, ...]) -> "ExecutionPolicy":
        try:
            policy_mode = ExecutionPolicyMode(mode)
        except ValueError as exc:
            raise ValidationError("packet execution policy is invalid") from exc
        return cls(policy_mode, workspace_root, owned_paths,
                   "loopback" if policy_mode is ExecutionPolicyMode.READ_ONLY else "full")


@dataclass(frozen=True)
class ProviderRawExecution:
    provider_id: str
    task_id: str
    correlation_id: str
    outcome: ExecutionOutcome
    started_at: str
    completed_at: str
    exit_code: int | None = None
    signal: str | None = None
    stdout: str = ""
    stderr: str = ""
    stdout_bytes: int | None = None
    stderr_bytes: int | None = None
    stdout_sha256: str | None = None
    stderr_sha256: str | None = None
    events: tuple[ExecutionEvent, ...] = ()
    artifacts: tuple[ArtifactReference, ...] = ()
    diagnostics: tuple[str, ...] = ()
    provider_version: str | None = None
    session_id: str | None = None
    process_id: int | None = None
    launcher_process_id: int | None = None
    child_process_id: int | None = None

    @property
    def returncode(self) -> int | None:
        return self.exit_code

    def __post_init__(self) -> None:
        provider_identifier(self.provider_id)
        command_id(self.task_id)
        command_id(self.correlation_id)
        if not isinstance(self.outcome, ExecutionOutcome):
            raise ValidationError("raw execution outcome is invalid")
        utc_timestamp(self.started_at)
        utc_timestamp(self.completed_at)
        if self.exit_code is not None and type(self.exit_code) is not int:
            raise ValidationError("raw execution exit code must be an integer or None")
        if self.signal is not None:
            text(self.signal, "process signal", 128)
        if self.stdout:
            text(self.stdout, "provider stdout", 1_048_576)
        if self.stderr:
            text(self.stderr, "provider stderr", 1_048_576)
        if type(self.events) is not tuple or not all(isinstance(item, ExecutionEvent) for item in self.events):
            raise ValidationError("raw execution events are invalid")
        if type(self.artifacts) is not tuple or not all(isinstance(item, ArtifactReference) for item in self.artifacts):
            raise ValidationError("raw execution artifacts are invalid")
        for item in self.diagnostics:
            text(item, "execution diagnostic", 16_384)
        if self.provider_version is not None:
            text(self.provider_version, "provider version", 256)
        if self.session_id is not None:
            command_id(self.session_id)
        if self.process_id is not None and (type(self.process_id) is not int or self.process_id < 1):
            raise ValidationError("raw execution process ID must be a positive integer or None")
        for value, name in ((self.launcher_process_id, "launcher process ID"),
                            (self.child_process_id, "child process ID")):
            if value is not None and (type(value) is not int or value < 1):
                raise ValidationError(f"raw execution {name} must be a positive integer or None")


@dataclass(frozen=True)
class ProviderProvenance:
    provider_id: str
    provider_version: str | None
    adapter_id: str
    adapter_contract_version: str
    manifest_digest: str
    source: str

    def __post_init__(self) -> None:
        provider_identifier(self.provider_id)
        text(self.adapter_id, "adapter ID", 256)
        if not contract_version_is_compatible(self.adapter_contract_version):
            raise ValidationError("provenance has an incompatible adapter contract version")
        if not re.fullmatch(r"[0-9a-f]{64}", self.manifest_digest):
            raise ValidationError("provenance manifest digest is invalid")
        text(self.source, "provenance source", 4096)


@dataclass(frozen=True)
class NormalizedExecutionResult:
    """Adapter result with separate selection, report, and identity fields.

    Adapters may preserve a provider selection token in ``model_selection``;
    ``reported_model`` remains provider-reported metadata.  A concrete
    ``verified_model`` requires evidence beyond an unverified provider value.
    """
    provider_id: str
    task_id: str
    correlation_id: str
    outcome: ExecutionOutcome
    content: str | None
    reported_model: str | None
    session_id: str | None
    structured_output_json: str | None
    events: tuple[ExecutionEvent, ...]
    artifacts: tuple[ArtifactReference, ...]
    diagnostics: tuple[str, ...]
    provenance: ProviderProvenance
    unknown_fields: tuple[str, ...] = ()
    unsupported_fields: tuple[str, ...] = ()
    model_selection: str | None = None
    verified_model: str | None = None
    process_id: int | None = None
    launcher_process_id: int | None = None
    child_process_id: int | None = None

    def __post_init__(self) -> None:
        provider_identifier(self.provider_id)
        command_id(self.task_id)
        command_id(self.correlation_id)
        if not isinstance(self.outcome, ExecutionOutcome):
            raise ValidationError("normalized execution outcome is invalid")
        for value, name, maximum in ((self.content, "normalized content", 1_000_000),
                                     (self.reported_model, "reported model", 256),
                                     (self.session_id, "session ID", 256),
                                     (self.model_selection, "model selection", 256),
                                     (self.verified_model, "verified model", 256)):
            if value is not None:
                text(value, name, maximum)
        if self.structured_output_json is not None:
            try:
                if canonical_json(json.loads(self.structured_output_json)) != self.structured_output_json:
                    raise ValidationError("structured output is not canonical JSON")
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ValidationError("structured output is invalid JSON") from exc
        if type(self.events) is not tuple or not all(isinstance(item, ExecutionEvent) for item in self.events):
            raise ValidationError("normalized execution events are invalid")
        if type(self.artifacts) is not tuple or not all(isinstance(item, ArtifactReference) for item in self.artifacts):
            raise ValidationError("normalized execution artifacts are invalid")
        if type(self.diagnostics) is not tuple or not type(self.unknown_fields) is tuple or not type(self.unsupported_fields) is tuple:
            raise ValidationError("normalized diagnostic fields must be tuples")
        for item in (*self.diagnostics, *self.unknown_fields, *self.unsupported_fields):
            text(item, "normalized diagnostic field", 16_384)
        if not isinstance(self.provenance, ProviderProvenance):
            raise ValidationError("normalized provenance is invalid")
        if self.process_id is not None and (type(self.process_id) is not int or self.process_id < 1):
            raise ValidationError("normalized execution process ID must be a positive integer or None")
        for value, name in ((self.launcher_process_id, "launcher process ID"),
                            (self.child_process_id, "child process ID")):
            if value is not None and (type(value) is not int or value < 1):
                raise ValidationError(f"normalized execution {name} must be a positive integer or None")


@dataclass(frozen=True)
class VersionProbeResult:
    status: str
    returncode: int | None
    stdout: str
    stderr: str
    version: str | None = None
    timed_out: bool = False
    output_limited: bool = False
    permission_denied: bool = False
    detail: str = ""

    def __post_init__(self) -> None:
        if self.status not in {"available", "missing", "timeout", "nonzero", "invalid_output", "permission_denied", "incompatible", "untrusted"}:
            raise ValidationError("invalid version probe status")
        for value, name in ((self.stdout, "probe stdout"), (self.stderr, "probe stderr"), (self.detail, "probe detail")):
            if not isinstance(value, str):
                raise ValidationError(f"{name} must be text")
            if value:
                text(value, name, 65_536)
        if self.version is not None:
            text(self.version, "probed version", 256)
        if self.status == "available" and not self.version:
            raise ValidationError("available version probes require a version")
        if self.returncode is not None and type(self.returncode) is not int:
            raise ValidationError("probe returncode must be an integer or None")
        if not all(type(value) is bool for value in (self.timed_out, self.output_limited, self.permission_denied)):
            raise ValidationError("probe outcome flags must be boolean")


class VersionProbeRunner(Protocol):
    def run(self, argv: Sequence[str], *, timeout_seconds: float, output_limit: int) -> VersionProbeResult:
        ...


@dataclass(frozen=True)
class HealthCheckRequest:
    provider_id: str
    timeout_seconds: int

    def __post_init__(self) -> None:
        provider_identifier(self.provider_id)
        bounded_int(self.timeout_seconds, "health-check timeout", 1, 300)


@dataclass(frozen=True)
class HealthCheckResult:
    provider_id: str
    status: str
    checked_at: str
    detail: str = ""
    auth_status: str = "NOT_CHECKED"

    def __post_init__(self) -> None:
        provider_identifier(self.provider_id)
        if self.status not in {"healthy", "unhealthy", "unknown", "unsupported"}:
            raise ValidationError("invalid health-check status")
        utc_timestamp(self.checked_at)
        if self.auth_status not in {"NOT_CHECKED", "READY", "NOT_READY", "UNKNOWN"}:
            raise ValidationError("invalid authentication readiness status")
        if self.detail:
            text(self.detail, "health-check detail", 4096)


@dataclass(frozen=True)
class CancellationRequest:
    provider_id: str
    task_id: str
    correlation_id: str
    session_id: str | None = None
    reason: str = "controller cancellation"

    def __post_init__(self) -> None:
        provider_identifier(self.provider_id)
        command_id(self.task_id)
        command_id(self.correlation_id)
        if self.session_id is not None:
            command_id(self.session_id)
        text(self.reason, "cancellation reason", 4096)


@dataclass(frozen=True)
class CancellationResult:
    provider_id: str
    task_id: str
    correlation_id: str
    status: str
    detail: str = ""

    def __post_init__(self) -> None:
        provider_identifier(self.provider_id)
        command_id(self.task_id)
        command_id(self.correlation_id)
        if self.status not in {"cancelled", "not_found", "unsupported", "unknown"}:
            raise ValidationError("invalid cancellation status")
        if self.detail:
            text(self.detail, "cancellation detail", 4096)


@dataclass(frozen=True)
class AdapterContractValidation:
    valid: bool
    detail: str
    missing_methods: tuple[str, ...] = ()


class ProviderAdapter(Protocol):
    """The complete lifecycle an adapter supplies to Diamond."""

    adapter_id: str
    adapter_contract_version: str

    def discover(self, executable: Path, runner: VersionProbeRunner) -> VersionProbeResult:
        ...

    def validate(self, manifest: CapabilityManifest) -> ManifestValidationResult:
        ...

    def health_check(self, request: HealthCheckRequest) -> HealthCheckResult:
        ...

    def get_capabilities(self) -> CapabilityManifest:
        ...

    def execute(self, request: TaskExecutionRequest) -> ProviderRawExecution:
        ...

    def normalize_result(self, request: TaskExecutionRequest, raw: ProviderRawExecution) -> NormalizedExecutionResult:
        ...

    def cancel(self, request: CancellationRequest) -> CancellationResult:
        ...


_ADAPTER_METHODS = ("discover", "validate", "health_check", "get_capabilities", "execute", "normalize_result", "cancel")


def validate_adapter_contract(adapter: object) -> AdapterContractValidation:
    missing = tuple(name for name in _ADAPTER_METHODS if not callable(getattr(adapter, name, None)))
    if missing:
        return AdapterContractValidation(False, "adapter is missing required lifecycle methods", missing)
    try:
        text(getattr(adapter, "adapter_id", None), "adapter ID", 256)
    except ValidationError:
        return AdapterContractValidation(False, "adapter ID is invalid")
    if not contract_version_is_compatible(getattr(adapter, "adapter_contract_version", None)):
        return AdapterContractValidation(False, "adapter contract version is incompatible")
    return AdapterContractValidation(True, "adapter implements the supported lifecycle contract")
