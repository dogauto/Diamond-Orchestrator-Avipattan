"""Durable provider metadata and accepted-packet binding value objects."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .domain import Provider
from .errors import ValidationError
from .provider_contracts import (
    ADAPTER_CONTRACT_VERSION,
    Capability,
    CapabilityManifest,
    ExecutionMode,
    ManifestValidationStatus,
    provider_identifier,
    contract_version_is_compatible,
)
from .provider_registry import ProviderDescriptor, ProviderState
from .validation import bounded_int, canonical_json, command_id, text, utc_timestamp


def _digest(value: str, name: str) -> str:
    result = hashlib.sha256(value.encode("utf-8")).hexdigest()
    if not result:
        raise ValidationError(f"{name} digest could not be computed")
    return result


def executable_identity(configured: str, resolved: str | None) -> str:
    """Return deterministic resolution metadata without exposing environment values."""
    text(configured, "configured executable", 4096)
    if resolved is not None:
        text(resolved, "resolved executable", 4096)
    observation: dict[str, Any] = {
        "configured": configured,
        "resolved": resolved,
        "resolution": "absolute" if Path(configured).is_absolute() else "path_search",
        "file": None,
    }
    if resolved is not None:
        try:
            stat = os.stat(resolved)
            observation["file"] = {
                "device": stat.st_dev,
                "inode": stat.st_ino,
                "mode": stat.st_mode,
                "size": stat.st_size,
                "mtime_ns": stat.st_mtime_ns,
            }
        except OSError:
            observation["file"] = {"status": "unobserved"}
    return canonical_json(observation)


@dataclass(frozen=True)
class ProviderBinding:
    provider_id: str
    adapter_id: str
    adapter_contract_version: str
    manifest_digest: str
    executable_identity_json: str
    verified_capabilities: tuple[str, ...]
    metadata_revision: int
    metadata_digest: str

    def __post_init__(self) -> None:
        provider_identifier(self.provider_id)
        text(self.adapter_id, "binding adapter ID", 256)
        text(self.adapter_contract_version, "binding adapter contract version", 32)
        if len(self.manifest_digest) != 64 or any(char not in "0123456789abcdef" for char in self.manifest_digest):
            raise ValidationError("binding manifest digest is invalid")
        canonical_json(json.loads(self.executable_identity_json))
        if type(self.verified_capabilities) is not tuple:
            raise ValidationError("binding verified capabilities must be a tuple")
        if tuple(sorted(set(self.verified_capabilities))) != self.verified_capabilities:
            raise ValidationError("binding capabilities must be sorted and distinct")
        for capability in self.verified_capabilities:
            text(capability, "binding capability", 128)
        bounded_int(self.metadata_revision, "binding metadata revision", 1, 2**63 - 1)
        if len(self.metadata_digest) != 64 or any(char not in "0123456789abcdef" for char in self.metadata_digest):
            raise ValidationError("binding metadata digest is invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "provider_id": self.provider_id,
            "adapter_id": self.adapter_id,
            "adapter_contract_version": self.adapter_contract_version,
            "manifest_digest": self.manifest_digest,
            "executable_identity_json": self.executable_identity_json,
            "verified_capabilities": list(self.verified_capabilities),
            "metadata_revision": self.metadata_revision,
            "metadata_digest": self.metadata_digest,
        }

    @property
    def digest(self) -> str:
        return _digest(canonical_json(self.to_dict()), "provider binding")


@dataclass(frozen=True)
class AcceptedPacketRecord:
    accepted_packet_id: str
    task_id: str
    task_revision: int
    attempt_id: str
    packet_digest: str
    packet_json: str
    binding: ProviderBinding
    accepted_at: str
    command_id: str

    def __post_init__(self) -> None:
        command_id(self.accepted_packet_id)
        command_id(self.task_id)
        bounded_int(self.task_revision, "accepted packet task revision", 1, 2**63 - 1)
        command_id(self.attempt_id)
        if len(self.packet_digest) != 64 or any(char not in "0123456789abcdef" for char in self.packet_digest):
            raise ValidationError("accepted packet digest is invalid")
        if canonical_json(json.loads(self.packet_json)) != self.packet_json:
            raise ValidationError("accepted packet JSON is not canonical")
        if _digest(self.packet_json, "accepted packet") != self.packet_digest:
            raise ValidationError("accepted packet digest does not match packet JSON")
        if not isinstance(self.binding, ProviderBinding):
            raise ValidationError("accepted packet binding is invalid")
        packet = json.loads(self.packet_json)
        if packet.get("task_id") != self.task_id or packet.get("attempt_id") != self.attempt_id:
            raise ValidationError("accepted packet identity does not match its binding record")
        packet_provider = packet.get("provider_id") or packet.get("provider")
        if packet_provider != self.binding.provider_id:
            raise ValidationError("accepted packet provider does not match its binding")
        utc_timestamp(self.accepted_at)
        command_id(self.command_id)

    def to_dict(self) -> dict[str, object]:
        return {
            "accepted_packet_id": self.accepted_packet_id,
            "task_id": self.task_id,
            "task_revision": self.task_revision,
            "attempt_id": self.attempt_id,
            "packet_digest": self.packet_digest,
            "packet": json.loads(self.packet_json),
            "binding": self.binding.to_dict(),
            "accepted_at": self.accepted_at,
            "command_id": self.command_id,
        }


@dataclass(frozen=True)
class ProviderMetadataRecord:
    provider_id: str
    adapter_id: str
    adapter_contract_version: str
    provider_version: str | None
    manifest_schema_version: int
    manifest_digest: str
    executable: str
    resolved_executable: str | None
    executable_identity_json: str
    declared_capabilities: tuple[str, ...]
    verified_capabilities: tuple[str, ...]
    validation_status: str
    trust_status: str
    authorization_status: str
    state: str
    observed_at: str
    validated_at: str | None
    updated_at: str
    metadata_revision: int
    provenance_json: str
    metadata_json: str
    metadata_digest: str

    def __post_init__(self) -> None:
        provider_identifier(self.provider_id)
        text(self.adapter_id, "metadata adapter ID", 256)
        text(self.adapter_contract_version, "metadata adapter contract version", 32)
        if not contract_version_is_compatible(self.adapter_contract_version):
            raise ValidationError("metadata adapter contract version is incompatible")
        if self.provider_version is not None:
            text(self.provider_version, "metadata provider version", 256)
        bounded_int(self.manifest_schema_version, "metadata manifest schema version", 1, 1)
        for digest, name in ((self.manifest_digest, "manifest"), (self.metadata_digest, "metadata")):
            if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                raise ValidationError(f"{name} digest is invalid")
        text(self.executable, "metadata executable", 4096)
        if self.resolved_executable is not None:
            text(self.resolved_executable, "metadata resolved executable", 4096)
        for value, name in ((self.executable_identity_json, "executable identity"),
                            (self.provenance_json, "metadata provenance"),
                            (self.metadata_json, "metadata snapshot")):
            canonical_json(json.loads(value))
        for name, values in (("declared capabilities", self.declared_capabilities), ("verified capabilities", self.verified_capabilities)):
            if type(values) is not tuple:
                raise ValidationError(f"{name} must be a tuple")
            for value in values:
                text(value, name, 128)
        if not set(self.verified_capabilities) <= set(self.declared_capabilities):
            raise ValidationError("verified capabilities must be declared capabilities")
        if tuple(sorted(set(self.declared_capabilities))) != self.declared_capabilities:
            raise ValidationError("declared capabilities must be sorted and distinct")
        if tuple(sorted(set(self.verified_capabilities))) != self.verified_capabilities:
            raise ValidationError("verified capabilities must be sorted and distinct")
        for value, name in ((self.validation_status, "validation status"), (self.trust_status, "trust status"),
                            (self.authorization_status, "authorization status"), (self.state, "provider state")):
            text(value, name, 128)
        utc_timestamp(self.observed_at)
        if self.validated_at is not None:
            utc_timestamp(self.validated_at)
        utc_timestamp(self.updated_at)
        bounded_int(self.metadata_revision, "metadata revision", 1, 2**63 - 1)
        if _digest(self.snapshot_without_digest(), "metadata") != self.metadata_digest:
            raise ValidationError("metadata digest does not match its canonical snapshot")

    def snapshot_without_digest(self) -> str:
        return _metadata_snapshot({
            "provider_id": self.provider_id,
            "adapter_id": self.adapter_id,
            "adapter_contract_version": self.adapter_contract_version,
            "provider_version": self.provider_version,
            "manifest_schema_version": self.manifest_schema_version,
            "manifest_digest": self.manifest_digest,
            "executable": self.executable,
            "resolved_executable": self.resolved_executable,
            "executable_identity_json": self.executable_identity_json,
            "declared_capabilities": list(self.declared_capabilities),
            "verified_capabilities": list(self.verified_capabilities),
            "validation_status": self.validation_status,
            "trust_status": self.trust_status,
            "authorization_status": self.authorization_status,
            "state": self.state,
            "observed_at": self.observed_at,
            "validated_at": self.validated_at,
            "updated_at": self.updated_at,
            "metadata_revision": self.metadata_revision,
            "provenance_json": self.provenance_json,
        })

    def binding(self) -> ProviderBinding:
        return ProviderBinding(
            self.provider_id, self.adapter_id, self.adapter_contract_version,
            self.manifest_digest, self.executable_identity_json,
            tuple(sorted(self.verified_capabilities)), self.metadata_revision,
            self.metadata_digest,
        )

    def to_dict(self) -> dict[str, object]:
        return json.loads(self.snapshot_without_digest())

    @classmethod
    def from_descriptor(cls, descriptor: ProviderDescriptor, observed_at: str, *, metadata_revision: int = 1,
                        provenance: dict[str, object] | None = None) -> "ProviderMetadataRecord":
        if not isinstance(descriptor, ProviderDescriptor):
            raise ValidationError("provider metadata requires a ProviderDescriptor")
        now = observed_at
        provenance_json = canonical_json(provenance or {"source": "provider_registry", "evidence": []})
        snapshot = _metadata_snapshot({
            "provider_id": descriptor.provider_id, "adapter_id": descriptor.adapter_id,
            "adapter_contract_version": descriptor.manifest.adapter_contract_version,
            "provider_version": descriptor.version, "manifest_schema_version": descriptor.manifest.manifest_schema_version,
            "manifest_digest": descriptor.manifest_digest, "executable": descriptor.executable,
            "resolved_executable": descriptor.resolved_executable,
            "executable_identity_json": executable_identity(descriptor.executable, descriptor.resolved_executable),
            "declared_capabilities": tuple(sorted(item.value for item in descriptor.manifest.capabilities)),
            "verified_capabilities": tuple(sorted(item.value for item in descriptor.verified_capabilities)),
            "validation_status": descriptor.manifest.validation_status.value,
            "trust_status": "trusted_adapter" if descriptor.adapter is not None else "untrusted",
            "authorization_status": descriptor.authorization.value, "state": descriptor.state.value,
            "observed_at": now,
            "validated_at": now if descriptor.state in {ProviderState.VALIDATED, ProviderState.AVAILABLE, ProviderState.EXECUTION_AUTHORIZED} else None,
            "updated_at": now, "metadata_revision": metadata_revision, "provenance_json": provenance_json,
        })
        return cls(
            descriptor.provider_id, descriptor.adapter_id, descriptor.manifest.adapter_contract_version,
            descriptor.version, descriptor.manifest.manifest_schema_version, descriptor.manifest_digest,
            descriptor.executable, descriptor.resolved_executable,
            executable_identity(descriptor.executable, descriptor.resolved_executable),
            tuple(sorted(item.value for item in descriptor.manifest.capabilities)),
            tuple(sorted(item.value for item in descriptor.verified_capabilities)),
            descriptor.manifest.validation_status.value, "trusted_adapter" if descriptor.adapter is not None else "untrusted",
            descriptor.authorization.value, descriptor.state.value, now,
            now if descriptor.state in {ProviderState.VALIDATED, ProviderState.AVAILABLE, ProviderState.EXECUTION_AUTHORIZED} else None,
            now, metadata_revision, provenance_json, snapshot, _digest(snapshot, "metadata"),
        )

    @classmethod
    def legacy(cls, provider: Provider, executable: str, resolved_executable: str | None, observed_at: str) -> "ProviderMetadataRecord":
        provider_identifier(provider.value)
        manifest = CapabilityManifest(
            provider.value, adapter_contract_version=ADAPTER_CONTRACT_VERSION,
            capabilities=frozenset({Capability.ONE_SHOT_EXECUTION, Capability.TIMEOUT_ENFORCEMENT}),
            supported_execution_modes=frozenset({ExecutionMode.ONE_SHOT}),
            validation_status=ManifestValidationStatus.VALIDATED,
            validation_evidence=("legacy controller packet validation",),
        )
        provenance = canonical_json({"source": "legacy_controller_packet", "provider": provider.value})
        snapshot = _metadata_snapshot({
            "provider_id": provider.value, "adapter_id": f"legacy:{provider.value}",
            "adapter_contract_version": ADAPTER_CONTRACT_VERSION, "provider_version": None,
            "manifest_schema_version": manifest.manifest_schema_version, "manifest_digest": manifest.digest,
            "executable": executable, "resolved_executable": resolved_executable,
            "executable_identity_json": executable_identity(executable, resolved_executable),
            "declared_capabilities": tuple(sorted(item.value for item in manifest.capabilities)),
            "verified_capabilities": tuple(sorted(item.value for item in manifest.capabilities)),
            "validation_status": "validated", "trust_status": "controller_legacy",
            "authorization_status": "authorized", "state": "execution_authorized",
            "observed_at": observed_at, "validated_at": observed_at, "updated_at": observed_at,
            "metadata_revision": 1, "provenance_json": provenance,
        })
        return cls(
            provider.value, f"legacy:{provider.value}", ADAPTER_CONTRACT_VERSION, None,
            manifest.manifest_schema_version, manifest.digest, executable, resolved_executable,
            executable_identity(executable, resolved_executable),
            tuple(sorted(item.value for item in manifest.capabilities)),
            tuple(sorted(item.value for item in manifest.capabilities)), "validated",
            "controller_legacy", "authorized", "execution_authorized", observed_at, observed_at,
            observed_at, 1, provenance, snapshot, _digest(snapshot, "metadata"),
        )


def _metadata_snapshot(values: dict[str, object]) -> str:
    return canonical_json({
        "provider_id": values["provider_id"], "adapter_id": values["adapter_id"],
        "adapter_contract_version": values["adapter_contract_version"], "provider_version": values["provider_version"],
        "manifest_schema_version": values["manifest_schema_version"], "manifest_digest": values["manifest_digest"],
        "executable": values["executable"], "resolved_executable": values["resolved_executable"],
        "executable_identity_json": values["executable_identity_json"],
        "declared_capabilities": list(values["declared_capabilities"]),
        "verified_capabilities": list(values["verified_capabilities"]),
        "validation_status": values["validation_status"], "trust_status": values["trust_status"],
        "authorization_status": values["authorization_status"], "state": values["state"],
        "observed_at": values["observed_at"], "validated_at": values["validated_at"],
        "updated_at": values["updated_at"], "metadata_revision": values["metadata_revision"],
        "provenance_json": values["provenance_json"],
    })
