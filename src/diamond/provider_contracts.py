"""Provider-neutral contracts for CLI adapters.

This module is deliberately independent of the current closed ``Provider``
enum and the task ledger.  It gives future adapters a typed boundary without
silently widening schema-1 task records or granting execution authority.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .errors import ValidationError
from .validation import bounded_int, canonical_json, command_id, text


MANIFEST_SCHEMA_VERSION = 1
ADAPTER_CONTRACT_VERSION = "1.0"
_PROVIDER_ID = re.compile(r"[a-z][a-z0-9._-]{0,63}\Z")


def provider_identifier(value: object) -> str:
    if not isinstance(value, str) or _PROVIDER_ID.fullmatch(value) is None:
        raise ValidationError("provider identifier must be lowercase stable CLI-safe text")
    return value


def contract_version_is_compatible(value: object) -> bool:
    if not isinstance(value, str) or not re.fullmatch(r"\d+\.\d+", value):
        return False
    return value.split(".", 1)[0] == ADAPTER_CONTRACT_VERSION.split(".", 1)[0]


class Capability(str, Enum):
    ONE_SHOT_EXECUTION = "one_shot_execution"
    INTERACTIVE_SESSIONS = "interactive_sessions"
    STRUCTURED_INPUT = "structured_input"
    STRUCTURED_OUTPUT = "structured_output"
    STRUCTURED_EVENTS = "structured_events"
    SESSION_CONTINUATION = "session_continuation"
    CANCELLATION = "cancellation"
    TIMEOUT_ENFORCEMENT = "timeout_enforcement"
    ARTIFACT_REPORTING = "artifact_reporting"
    HEALTH_CHECKS = "health_checks"
    AUTHENTICATION_READINESS = "authentication_readiness"


class ExecutionMode(str, Enum):
    ONE_SHOT = "one_shot"
    INTERACTIVE = "interactive"
    PERSISTENT = "persistent"


class ManifestValidationStatus(str, Enum):
    DECLARED = "declared"
    VALIDATED = "validated"
    INVALID = "invalid"
    INCOMPATIBLE = "incompatible"


@dataclass(frozen=True)
class CapabilityManifest:
    """Versioned, self-declared provider capabilities.

    ``validation_status`` describes manifest validation only.  It does not
    claim that a CLI is installed, authenticated, or authorized to execute.
    Independent capability observations are stored by the registry separately.
    """

    provider_id: str
    manifest_schema_version: int = MANIFEST_SCHEMA_VERSION
    adapter_contract_version: str = ADAPTER_CONTRACT_VERSION
    provider_version_constraints: tuple[str, ...] = ()
    capabilities: frozenset[Capability] = frozenset()
    unsupported_capabilities: frozenset[Capability] = frozenset()
    supported_task_types: tuple[str, ...] = ()
    supported_execution_modes: frozenset[ExecutionMode] = frozenset()
    known_limitations: tuple[str, ...] = ()
    validation_status: ManifestValidationStatus = ManifestValidationStatus.DECLARED
    validation_evidence: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        provider_identifier(self.provider_id)
        bounded_int(self.manifest_schema_version, "manifest schema version", 1, 1)
        if not contract_version_is_compatible(self.adapter_contract_version):
            raise ValidationError(
                f"incompatible adapter contract version: {self.adapter_contract_version}"
            )
        if not isinstance(self.validation_status, ManifestValidationStatus):
            raise ValidationError("manifest validation status is invalid")
        if type(self.capabilities) is not frozenset or not all(
            isinstance(item, Capability) for item in self.capabilities
        ):
            raise ValidationError("manifest capabilities must be a frozenset of Capability values")
        if type(self.unsupported_capabilities) is not frozenset or not all(
            isinstance(item, Capability) for item in self.unsupported_capabilities
        ):
            raise ValidationError("manifest unsupported capabilities are invalid")
        if self.capabilities & self.unsupported_capabilities:
            raise ValidationError("a capability cannot be both supported and unsupported")
        for name, values, maximum in (
            ("provider version constraints", self.provider_version_constraints, 64),
            ("supported task types", self.supported_task_types, 128),
            ("known limitations", self.known_limitations, 256),
            ("manifest validation evidence", self.validation_evidence, 256),
        ):
            if type(values) is not tuple or len(values) > maximum:
                raise ValidationError(f"{name} must be a bounded tuple")
            for value in values:
                text(value, name, 4096)
        if type(self.supported_execution_modes) is not frozenset or not all(
            isinstance(item, ExecutionMode) for item in self.supported_execution_modes
        ):
            raise ValidationError("manifest execution modes are invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "manifest_schema_version": self.manifest_schema_version,
            "adapter_contract_version": self.adapter_contract_version,
            "provider_version_constraints": list(self.provider_version_constraints),
            "capabilities": sorted(item.value for item in self.capabilities),
            "unsupported_capabilities": sorted(item.value for item in self.unsupported_capabilities),
            "supported_task_types": list(self.supported_task_types),
            "supported_execution_modes": sorted(item.value for item in self.supported_execution_modes),
            "known_limitations": list(self.known_limitations),
            "validation_status": self.validation_status.value,
            "validation_evidence": list(self.validation_evidence),
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json(self.to_dict()).encode("utf-8")).hexdigest()

    @classmethod
    def from_dict(cls, value: object) -> "CapabilityManifest":
        if not isinstance(value, dict):
            raise ValidationError("manifest must be an object")
        expected = {
            "provider_id", "manifest_schema_version", "adapter_contract_version",
            "provider_version_constraints", "capabilities", "unsupported_capabilities",
            "supported_task_types", "supported_execution_modes", "known_limitations",
            "validation_status", "validation_evidence",
        }
        if set(value) != expected:
            raise ValidationError("manifest contains unknown or missing fields")
        try:
            arrays = (
                "provider_version_constraints", "capabilities", "unsupported_capabilities",
                "supported_task_types", "supported_execution_modes", "known_limitations",
                "validation_evidence",
            )
            for name in arrays:
                if type(value[name]) is not list:
                    raise ValidationError(f"manifest {name} must be an array")
            data = dict(value)
            data["provider_version_constraints"] = tuple(data["provider_version_constraints"])
            data["capabilities"] = frozenset(Capability(item) for item in data["capabilities"])
            data["unsupported_capabilities"] = frozenset(
                Capability(item) for item in data["unsupported_capabilities"]
            )
            data["supported_task_types"] = tuple(data["supported_task_types"])
            data["supported_execution_modes"] = frozenset(
                ExecutionMode(item) for item in data["supported_execution_modes"]
            )
            data["known_limitations"] = tuple(data["known_limitations"])
            data["validation_evidence"] = tuple(data["validation_evidence"])
            data["validation_status"] = ManifestValidationStatus(data["validation_status"])
            return cls(**data)
        except (TypeError, ValueError) as exc:
            raise ValidationError("manifest contains an invalid enum or field type") from exc


@dataclass(frozen=True)
class ManifestValidationResult:
    valid: bool
    status: ManifestValidationStatus
    detail: str
    evidence: tuple[str, ...] = ()


def validate_manifest(value: object) -> tuple[CapabilityManifest | None, ManifestValidationResult]:
    try:
        manifest = value if isinstance(value, CapabilityManifest) else CapabilityManifest.from_dict(value)
    except ValidationError as exc:
        detail = str(exc)
        status = ManifestValidationStatus.INCOMPATIBLE if "contract version" in detail else ManifestValidationStatus.INVALID
        return None, ManifestValidationResult(False, status, detail)
    if manifest.validation_status in {ManifestValidationStatus.INVALID, ManifestValidationStatus.INCOMPATIBLE}:
        return manifest, ManifestValidationResult(False, manifest.validation_status, "manifest is not valid")
    return manifest, ManifestValidationResult(True, ManifestValidationStatus.VALIDATED, "manifest shape and contract are valid")


@dataclass(frozen=True)
class TaskRequirements:
    required_capabilities: frozenset[Capability] = frozenset()
    required_execution_modes: frozenset[ExecutionMode] = frozenset()
    task_type: str | None = None

    def __post_init__(self) -> None:
        if type(self.required_capabilities) is not frozenset or not all(
            isinstance(item, Capability) for item in self.required_capabilities
        ):
            raise ValidationError("required capabilities must be a frozenset of Capability values")
        if type(self.required_execution_modes) is not frozenset or not all(
            isinstance(item, ExecutionMode) for item in self.required_execution_modes
        ):
            raise ValidationError("required execution modes are invalid")
        if self.task_type is not None:
            text(self.task_type, "task type", 128)


@dataclass(frozen=True)
class TaskExecutionRequest:
    task_id: str
    correlation_id: str
    input_text: str
    requirements: TaskRequirements
    execution_mode: ExecutionMode
    timeout_seconds: int
    continuation_session_id: str | None = None
    execution_policy: "ExecutionPolicy" | None = None

    def __post_init__(self) -> None:
        command_id(self.task_id)
        command_id(self.correlation_id)
        text(self.input_text, "task input", 1_000_000)
        if not isinstance(self.requirements, TaskRequirements):
            raise ValidationError("task requirements are invalid")
        if not isinstance(self.execution_mode, ExecutionMode):
            raise ValidationError("task execution mode is invalid")
        bounded_int(self.timeout_seconds, "task timeout", 1, 86_400)
        if self.continuation_session_id is not None:
            command_id(self.continuation_session_id)
        if self.execution_policy is not None and not isinstance(self.execution_policy, ExecutionPolicy):
            raise ValidationError("task execution policy is invalid")


from .provider_execution import (
    AdapterContractValidation,
    ArtifactReference,
    CancellationRequest,
    CancellationResult,
    ExecutionEvent,
    ExecutionEventKind,
    ExecutionOutcome,
    ExecutionPolicy,
    ExecutionPolicyMode,
    HealthCheckRequest,
    HealthCheckResult,
    NormalizedExecutionResult,
    ProviderAdapter,
    ProviderProvenance,
    ProviderRawExecution,
    VersionProbeResult,
    VersionProbeRunner,
    validate_adapter_contract,
)
