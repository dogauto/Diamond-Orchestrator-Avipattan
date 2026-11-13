"""Canonical in-memory registry for provider discovery and validation.

The registry is intentionally not a task-state store.  It holds a deterministic
projection of provider metadata and can be replaced by a controller-owned
persistent implementation in a later milestone without changing the adapter
contract or router.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Iterable

from .errors import ValidationError
from .provider_contracts import (
    ADAPTER_CONTRACT_VERSION,
    Capability,
    CapabilityManifest,
    ManifestValidationResult,
    ManifestValidationStatus,
    ProviderAdapter,
    contract_version_is_compatible,
    provider_identifier,
    validate_adapter_contract,
    validate_manifest,
)
from .provider_discovery import DiscoveryRecord, DiscoveryState
from .validation import text


class ProviderState(str, Enum):
    DECLARED = "declared"
    DISCOVERED = "discovered"
    VALIDATED = "validated"
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    INCOMPATIBLE = "incompatible"
    UNTRUSTED = "untrusted"
    EXECUTION_AUTHORIZED = "execution_authorized"
    STALE = "stale"


class AuthorizationState(str, Enum):
    NOT_AUTHORIZED = "not_authorized"
    AUTHORIZED = "authorized"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ProviderDescriptor:
    provider_id: str
    manifest: CapabilityManifest
    executable: str
    adapter_id: str
    state: ProviderState = ProviderState.DECLARED
    resolved_executable: str | None = None
    version: str | None = None
    verified_capabilities: frozenset[Capability] = frozenset()
    validation_evidence: tuple[str, ...] = ()
    discovery_detail: str = ""
    authorization: AuthorizationState = AuthorizationState.NOT_AUTHORIZED
    authorization_evidence: tuple[str, ...] = ()
    stale_reason: str | None = None
    adapter: ProviderAdapter | None = None

    def __post_init__(self) -> None:
        provider_identifier(self.provider_id)
        if self.manifest.provider_id != self.provider_id:
            raise ValidationError("descriptor provider ID must match its manifest")
        text(self.executable, "provider executable", 4096)
        text(self.adapter_id, "adapter ID", 256)
        if self.resolved_executable is not None:
            text(self.resolved_executable, "resolved executable", 4096)
        if self.version is not None:
            text(self.version, "provider version", 256)
        if type(self.verified_capabilities) is not frozenset or not all(
            isinstance(item, Capability) for item in self.verified_capabilities
        ):
            raise ValidationError("verified capabilities are invalid")
        if not self.verified_capabilities <= self.manifest.capabilities:
            raise ValidationError("verified capabilities must be declared by the manifest")
        for name, values in (("validation evidence", self.validation_evidence), ("authorization evidence", self.authorization_evidence)):
            if type(values) is not tuple:
                raise ValidationError(f"{name} must be a tuple")
            for value in values:
                text(value, name, 4096)
        if self.discovery_detail:
            text(self.discovery_detail, "discovery detail", 4096)
        if self.stale_reason is not None:
            text(self.stale_reason, "stale reason", 4096)
        if not isinstance(self.state, ProviderState) or not isinstance(self.authorization, AuthorizationState):
            raise ValidationError("provider descriptor state is invalid")
        if self.state is ProviderState.EXECUTION_AUTHORIZED and self.authorization is not AuthorizationState.AUTHORIZED:
            raise ValidationError("execution-authorized providers require authorized state")
        if self.authorization is AuthorizationState.AUTHORIZED and self.state not in {
            ProviderState.AVAILABLE, ProviderState.EXECUTION_AUTHORIZED,
        }:
            raise ValidationError("authorization requires an available provider")

    @property
    def manifest_digest(self) -> str:
        return self.manifest.digest

    def to_dict(self) -> dict[str, object]:
        return {
            "provider_id": self.provider_id,
            "adapter_id": self.adapter_id,
            "manifest_digest": self.manifest_digest,
            "manifest": self.manifest.to_dict(),
            "executable": self.executable,
            "resolved_executable": self.resolved_executable,
            "state": self.state.value,
            "version": self.version,
            "declared_capabilities": sorted(item.value for item in self.manifest.capabilities),
            "verified_capabilities": sorted(item.value for item in self.verified_capabilities),
            "validation_evidence": list(self.validation_evidence),
            "discovery_detail": self.discovery_detail,
            "authorization": self.authorization.value,
            "authorization_evidence": list(self.authorization_evidence),
            "stale_reason": self.stale_reason,
        }


class ProviderRegistry:
    """Deterministic provider metadata registry.

    Registration is explicit and duplicate-safe.  Discovery only updates
    metadata; it never calls ``execute`` and never changes authorization.
    """

    def __init__(self, descriptors: Iterable[ProviderDescriptor] = ()) -> None:
        self._providers: dict[str, ProviderDescriptor] = {}
        for descriptor in descriptors:
            self.register_descriptor(descriptor)

    def register_descriptor(self, descriptor: ProviderDescriptor) -> ProviderDescriptor:
        if not isinstance(descriptor, ProviderDescriptor):
            raise ValidationError("registry requires ProviderDescriptor values")
        if descriptor.provider_id in self._providers:
            raise ValidationError(f"provider already registered: {descriptor.provider_id}")
        self._providers[descriptor.provider_id] = descriptor
        return descriptor

    def register(
        self,
        manifest: CapabilityManifest,
        executable: str,
        adapter_id: str,
        adapter: ProviderAdapter | None = None,
    ) -> ProviderDescriptor:
        manifest, result = validate_manifest(manifest)
        if manifest is None or not result.valid:
            raise ValidationError(f"cannot register invalid manifest: {result.detail}")
        if not contract_version_is_compatible(ADAPTER_CONTRACT_VERSION):
            raise ValidationError("registry adapter contract is not supported")
        if adapter is not None:
            validation = validate_adapter_contract(adapter)
            if not validation.valid:
                raise ValidationError(validation.detail)
            if adapter.adapter_id != adapter_id:
                raise ValidationError("adapter ID does not match descriptor")
            if adapter.get_capabilities().provider_id != manifest.provider_id:
                raise ValidationError("adapter capability manifest does not match provider")
        descriptor = ProviderDescriptor(manifest.provider_id, manifest, executable, adapter_id, adapter=adapter)
        return self.register_descriptor(descriptor)

    def get(self, provider_id: str) -> ProviderDescriptor:
        provider_identifier(provider_id)
        try:
            return self._providers[provider_id]
        except KeyError as exc:
            raise ValidationError(f"provider is not registered: {provider_id}") from exc

    def list(self) -> tuple[ProviderDescriptor, ...]:
        return tuple(self._providers[key] for key in sorted(self._providers))

    def list_discovered(self) -> tuple[ProviderDescriptor, ...]:
        return tuple(item for item in self.list() if item.state is not ProviderState.DECLARED)

    def list_validated(self) -> tuple[ProviderDescriptor, ...]:
        return tuple(item for item in self.list() if item.state in {
            ProviderState.VALIDATED, ProviderState.AVAILABLE, ProviderState.EXECUTION_AUTHORIZED,
        })

    def record_discovery(self, record: DiscoveryRecord) -> ProviderDescriptor:
        current = self.get(record.provider_id)
        if record.adapter_id != current.adapter_id:
            raise ValidationError("discovery adapter ID does not match the registered adapter")
        state = {
            DiscoveryState.DISCOVERED: ProviderState.DISCOVERED,
            DiscoveryState.UNAVAILABLE: ProviderState.UNAVAILABLE,
            DiscoveryState.INCOMPATIBLE: ProviderState.INCOMPATIBLE,
            DiscoveryState.UNTRUSTED: ProviderState.UNTRUSTED,
        }[record.state]
        updated = replace(
            current,
            state=state,
            resolved_executable=record.resolved_executable,
            version=record.version,
            discovery_detail=record.detail,
            authorization=AuthorizationState.NOT_AUTHORIZED,
            authorization_evidence=(),
            verified_capabilities=frozenset(),
        )
        self._providers[record.provider_id] = updated
        return updated

    def record_validation(
        self,
        provider_id: str,
        result: ManifestValidationResult,
        verified_capabilities: Iterable[Capability] = (),
        evidence: Iterable[str] = (),
    ) -> ProviderDescriptor:
        current = self.get(provider_id)
        if not isinstance(result, ManifestValidationResult):
            raise ValidationError("manifest validation result is invalid")
        verified = frozenset(verified_capabilities)
        if not verified <= current.manifest.capabilities:
            raise ValidationError("verified capabilities must be declared by the manifest")
        evidence_tuple = tuple(evidence) + tuple(result.evidence)
        for item in evidence_tuple:
            text(item, "validation evidence", 4096)
        if result.status is ManifestValidationStatus.INCOMPATIBLE:
            state = ProviderState.INCOMPATIBLE
        elif not result.valid or result.status is ManifestValidationStatus.INVALID:
            state = ProviderState.UNTRUSTED
        else:
            state = ProviderState.VALIDATED
        updated = replace(current, state=state, verified_capabilities=verified, validation_evidence=evidence_tuple)
        self._providers[provider_id] = updated
        return updated

    def mark_available(self, provider_id: str) -> ProviderDescriptor:
        current = self.get(provider_id)
        if current.state is not ProviderState.VALIDATED:
            raise ValidationError("provider must be validated before it becomes available")
        if current.resolved_executable is None or current.version is None:
            raise ValidationError("provider availability requires a successful discovery")
        updated = replace(current, state=ProviderState.AVAILABLE)
        self._providers[provider_id] = updated
        return updated

    def record_authorization(self, provider_id: str, authorized: bool, evidence: Iterable[str] = ()) -> ProviderDescriptor:
        current = self.get(provider_id)
        if type(authorized) is not bool:
            raise ValidationError("authorization status must be boolean")
        if authorized and current.state is not ProviderState.AVAILABLE:
            raise ValidationError("execution authorization requires an available provider")
        evidence_tuple = tuple(evidence)
        for item in evidence_tuple:
            text(item, "authorization evidence", 4096)
        state = ProviderState.EXECUTION_AUTHORIZED if authorized else ProviderState.AVAILABLE
        updated = replace(
            current, state=state,
            authorization=AuthorizationState.AUTHORIZED if authorized else AuthorizationState.NOT_AUTHORIZED,
            authorization_evidence=evidence_tuple,
        )
        self._providers[provider_id] = updated
        return updated

    def invalidate(self, provider_id: str, reason: str) -> ProviderDescriptor:
        current = self.get(provider_id)
        text(reason, "stale provider reason", 4096)
        updated = replace(current, state=ProviderState.STALE, stale_reason=reason, authorization=AuthorizationState.UNKNOWN)
        self._providers[provider_id] = updated
        return updated

    def update(self, descriptor: ProviderDescriptor) -> ProviderDescriptor:
        current = self.get(descriptor.provider_id)
        if current.state is not ProviderState.STALE:
            raise ValidationError("provider updates require explicit stale invalidation")
        self._providers[descriptor.provider_id] = descriptor
        return descriptor
