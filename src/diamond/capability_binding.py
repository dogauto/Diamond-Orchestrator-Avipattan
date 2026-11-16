"""Immutable least-privilege capability assignments for one dispatch."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .domain import Provider
from .agent_runtime import runtime_id
from .errors import ExecutionGuardError, ValidationError
from .packets import TaskPacket
from .provider_metadata import ProviderMetadataRecord
from .skills import SkillRecord
from .capability_policy import skill_assignment, tool_identity
from .validation import bounded_int, canonical_json, command_id, task_id, text, utc_now, utc_timestamp


_DIGEST_LENGTH = 64
_MAX_CAPABILITY_JSON = 1_048_576


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) != _DIGEST_LENGTH or any(char not in "0123456789abcdef" for char in value):
        raise ValidationError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _json(value: object, name: str) -> str:
    result = canonical_json(value)
    if len(result.encode("utf-8")) > _MAX_CAPABILITY_JSON:
        raise ValidationError(f"{name} exceeds the capability binding budget")
    return result


def _decode(value: str, name: str) -> object:
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValidationError(f"{name} must be canonical JSON") from exc
    if canonical_json(parsed) != value:
        raise ValidationError(f"{name} must be canonical JSON")
    return parsed


def _json_array(value: str, name: str) -> list[object]:
    parsed = _decode(value, name)
    if not isinstance(parsed, list):
        raise ValidationError(f"{name} must be a JSON array")
    return parsed


def _json_object(value: str, name: str) -> dict[str, object]:
    parsed = _decode(value, name)
    if not isinstance(parsed, dict):
        raise ValidationError(f"{name} must be a JSON object")
    return parsed


def _ordered_text(values: Iterable[str], name: str, maximum: int = 256) -> tuple[str, ...]:
    result = tuple(values)
    if any(not isinstance(value, str) for value in result):
        raise ValidationError(f"{name} must contain text values")
    for value in result:
        text(value, name, maximum)
    return tuple(sorted(set(result)))


def _tool_identity(value: str) -> str:
    return tool_identity(value)


def _file_digest(path: Path) -> str:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(65_536), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as exc:
        raise ExecutionGuardError(f"capability skill source cannot be read: {path}") from exc


@dataclass(frozen=True)
class CapabilityBinding:
    """Controller-authorized capability snapshot for exactly one attempt."""

    binding_id: str
    task_id: str
    task_revision: int
    attempt_id: str
    accepted_packet_id: str
    packet_digest: str
    provider_id: str
    adapter_id: str
    adapter_contract_version: str
    manifest_digest: str
    execution_mode: str
    requested_skills_json: str
    assigned_skills_json: str
    available_capabilities_json: str
    requested_tools_json: str
    authorized_tools_json: str
    available_tools_json: str
    provider_tools_json: str
    mcp_integrations_json: str
    plugin_integrations_json: str
    workspace_root: str
    owned_paths_json: str
    permission_mode: str
    sandbox_profile: str
    network_access: str
    resource_limits_json: str
    delegation_constraints_json: str
    created_at: str
    capability_digest: str
    usage_budget_json: str | None = None
    usage_budget_digest: str | None = None

    def __post_init__(self) -> None:
        command_id(self.binding_id)
        task_id(self.task_id)
        bounded_int(self.task_revision, "capability task revision", 1, 2**63 - 1)
        task_id(self.attempt_id)
        command_id(self.accepted_packet_id)
        _digest(self.packet_digest, "capability packet digest")
        text(self.provider_id, "capability provider", 128)
        text(self.adapter_id, "capability adapter", 256)
        text(self.adapter_contract_version, "capability adapter contract", 32)
        _digest(self.manifest_digest, "capability manifest digest")
        if self.execution_mode != "one_shot":
            raise ValidationError("only the verified one_shot execution mode is supported")
        for value, name in (
            (self.requested_skills_json, "requested skills"),
            (self.assigned_skills_json, "assigned skills"),
            (self.available_capabilities_json, "available capabilities"),
            (self.requested_tools_json, "requested tools"),
            (self.authorized_tools_json, "authorized tools"),
            (self.available_tools_json, "available tools"),
            (self.provider_tools_json, "provider tools"),
            (self.mcp_integrations_json, "MCP integrations"),
            (self.plugin_integrations_json, "plugin integrations"),
            (self.owned_paths_json, "owned paths"),
        ):
            _json_array(value, name)
        _json_object(self.resource_limits_json, "resource limits")
        _json_object(self.delegation_constraints_json, "delegation constraints")
        if self.usage_budget_json is not None:
            _json_object(self.usage_budget_json, "usage budget")
        root = Path(self.workspace_root)
        if not root.is_absolute() or "\x00" in self.workspace_root:
            raise ValidationError("capability workspace root must be absolute and NUL-free")
        text(self.permission_mode, "capability permission mode", 64)
        text(self.sandbox_profile, "capability sandbox profile", 128)
        if self.network_access not in {"denied", "loopback"}:
            raise ValidationError("capability network access must be denied or loopback")
        utc_timestamp(self.created_at)
        _digest(self.capability_digest, "capability digest")
        if self.usage_budget_json is not None:
            if self.usage_budget_digest is None:
                raise ValidationError("usage budget digest is required")
            _digest(self.usage_budget_digest, "usage budget digest")
            if self.usage_budget_digest != _sha256(self.usage_budget_json):
                raise ValidationError("usage budget digest does not match the usage budget")
        if self.capability_digest != _sha256(canonical_json(self._snapshot())):
            raise ValidationError("capability digest does not match the immutable assignment")

    def _snapshot(self) -> dict[str, object]:
        return {
            "task_id": self.task_id,
            "task_revision": self.task_revision,
            "attempt_id": self.attempt_id,
            "accepted_packet_id": self.accepted_packet_id,
            "packet_digest": self.packet_digest,
            "provider_id": self.provider_id,
            "adapter_id": self.adapter_id,
            "adapter_contract_version": self.adapter_contract_version,
            "manifest_digest": self.manifest_digest,
            "execution_mode": self.execution_mode,
            "requested_skills": _decode(self.requested_skills_json, "requested skills"),
            "assigned_skills": _decode(self.assigned_skills_json, "assigned skills"),
            "available_capabilities": _decode(self.available_capabilities_json, "available capabilities"),
            "requested_tools": _decode(self.requested_tools_json, "requested tools"),
            "authorized_tools": _decode(self.authorized_tools_json, "authorized tools"),
            "available_tools": _decode(self.available_tools_json, "available tools"),
            "provider_tools": _decode(self.provider_tools_json, "provider tools"),
            "mcp_integrations": _decode(self.mcp_integrations_json, "MCP integrations"),
            "plugin_integrations": _decode(self.plugin_integrations_json, "plugin integrations"),
            "workspace_root": self.workspace_root,
            "owned_paths": _decode(self.owned_paths_json, "owned paths"),
            "permission_mode": self.permission_mode,
            "sandbox_profile": self.sandbox_profile,
            "network_access": self.network_access,
            "resource_limits": _decode(self.resource_limits_json, "resource limits"),
            "delegation_constraints": _decode(self.delegation_constraints_json, "delegation constraints"),
            "usage_budget": _decode(self.usage_budget_json, "usage budget") if self.usage_budget_json is not None else None,
        }

    def to_dict(self) -> dict[str, object]:
        return {"binding_id": self.binding_id, **self._snapshot(), "created_at": self.created_at,
                "capability_digest": self.capability_digest}

    @property
    def usage_budget(self) -> dict[str, object] | None:
        if self.usage_budget_json is None:
            return None
        return _json_object(self.usage_budget_json, "usage budget")

    @property
    def assigned_skills(self) -> tuple[dict[str, object], ...]:
        values = _json_array(self.assigned_skills_json, "assigned skills")
        if any(not isinstance(item, dict) for item in values):
            raise ValidationError("assigned skills must contain JSON objects")
        return tuple(values)  # type: ignore[return-value]

    @property
    def assigned_capability_keys(self) -> tuple[tuple[str, str], ...]:
        keys: list[tuple[str, str]] = []
        for skill in self.assigned_skills:
            if isinstance(skill.get("name"), str):
                keys.append(("skill", skill["name"]))
        for tool in _json_array(self.authorized_tools_json, "authorized tools"):
            if isinstance(tool, str):
                keys.append(("tool", tool))
        for tool in _json_array(self.provider_tools_json, "provider tools"):
            if isinstance(tool, str):
                keys.append(("provider_tool", tool))
        return tuple(keys)

    @classmethod
    def from_packet(
        cls,
        packet: TaskPacket,
        metadata: ProviderMetadataRecord,
        accepted_packet_id: str,
        *,
        available_capabilities: Iterable[str] = (),
        available_tools: Iterable[str] | None = None,
        requested_skill_names: Iterable[str] | None = None,
        permission_mode: str = "controller-default",
        output_limit: int = 1_048_576,
        max_workers: int = 2,
        mcp_integrations: Iterable[str] = (),
        plugin_integrations: Iterable[str] = (),
        delegation_constraints: dict[str, object] | None = None,
    ) -> "CapabilityBinding":
        if not isinstance(packet, TaskPacket) or not isinstance(metadata, ProviderMetadataRecord):
            raise ValidationError("capability binding requires a packet and provider metadata")
        command_id(accepted_packet_id)
        packet.verify_workspace()
        if packet.stable_provider_id != metadata.provider_id or packet.stable_adapter_id != metadata.adapter_id:
            raise ExecutionGuardError("capability binding provider identity does not match the accepted packet")
        if metadata.authorization_status != "authorized" or metadata.state != "execution_authorized":
            raise ExecutionGuardError("capability binding requires an execution-authorized provider")
        required = {"one_shot_execution", "timeout_enforcement"}
        missing_provider = sorted(required - set(metadata.verified_capabilities))
        if missing_provider:
            raise ExecutionGuardError(f"provider capability binding is missing: {', '.join(missing_provider)}")
        available = _ordered_text(available_capabilities, "available capabilities", 256)
        requested_skills = _ordered_text(requested_skill_names if requested_skill_names is not None else
                                         (skill.name for skill in packet.skills), "requested skills")
        assigned = skill_assignment(packet, requested_skills, available)
        requested_tools = _ordered_text(packet.allowed_tools, "requested tools", 4096)
        authorized_tools = requested_tools
        available_tool_values = _ordered_text(
            available_tools if available_tools is not None else requested_tools,
            "available tools", 4096,
        )
        requested_tool_ids = {_tool_identity(tool) for tool in requested_tools}
        available_tool_ids = {_tool_identity(tool) for tool in available_tool_values}
        if not requested_tool_ids <= available_tool_ids:
            missing_tools = sorted(requested_tool_ids - available_tool_ids)
            raise ExecutionGuardError(f"requested tools are unavailable: {', '.join(missing_tools)}")
        provider_tools = _ordered_text(packet.provider_tools or (), "provider tools", 128)
        if provider_tools:
            raise ExecutionGuardError("provider tools require an explicit audited execution adapter; unsupported")
        mcp = _ordered_text(mcp_integrations, "MCP integrations", 256)
        plugins = _ordered_text(plugin_integrations, "plugin integrations", 256)
        if mcp:
            raise ExecutionGuardError("MCP capability assignment is unsupported by the current adapters")
        if plugins:
            raise ExecutionGuardError("plugin capability assignment is unsupported and cannot be authorized")
        bounded_int(output_limit, "capability output limit", 1, 16_777_216)
        bounded_int(max_workers, "capability worker limit", 1, 64)
        constraints = delegation_constraints if delegation_constraints is not None else {
            "delegation_id": None, "max_children": 0, "max_depth": 0,
        }
        if not isinstance(constraints, dict) or set(constraints) != {"delegation_id", "max_children", "max_depth"}:
            raise ValidationError("delegation constraints must be a JSON object")
        if constraints["delegation_id"] is not None:
            runtime_id(constraints["delegation_id"], "delegation_id")
        bounded_int(constraints["max_children"], "delegation max_children", 0, 64)
        bounded_int(constraints["max_depth"], "delegation max_depth", 0, 64)
        if constraints["max_children"] or constraints["max_depth"]:
            raise ExecutionGuardError("assignments cannot grant autonomous child delegation")
        if permission_mode not in {"controller-default", "plan", "default", "provider-gateway"}:
            raise ExecutionGuardError("unsupported permission mode cannot be bound")
        assigned_json = _json(assigned, "assigned skills")
        assigned_names = {item["name"] for item in assigned if isinstance(item.get("name"), str)}
        if not set(requested_skills) <= assigned_names:
            raise ExecutionGuardError("requested skill is missing from the assigned skill set")
        values = dict(
            binding_id=accepted_packet_id,
            task_id=packet.task_id,
            task_revision=packet.task_revision,
            attempt_id=packet.attempt_id,
            accepted_packet_id=accepted_packet_id,
            packet_digest=packet.packet_digest(),
            provider_id=metadata.provider_id,
            adapter_id=metadata.adapter_id,
            adapter_contract_version=metadata.adapter_contract_version,
            manifest_digest=metadata.manifest_digest,
            execution_mode="one_shot",
            requested_skills_json=_json([item for item in assigned if item["name"] in requested_skills], "requested skills"),
            assigned_skills_json=assigned_json,
            available_capabilities_json=_json(sorted(set(available) | set(metadata.verified_capabilities)), "available capabilities"),
            requested_tools_json=_json(list(requested_tools), "requested tools"),
            authorized_tools_json=_json(list(authorized_tools), "authorized tools"),
            available_tools_json=_json(sorted(available_tool_ids), "available tools"),
            provider_tools_json=_json(list(provider_tools), "provider tools"),
            mcp_integrations_json=_json(list(mcp), "MCP integrations"),
            plugin_integrations_json=_json(list(plugins), "plugin integrations"),
            workspace_root=packet.workspace_root,
            owned_paths_json=_json(list(packet.owned_paths), "owned paths"),
            permission_mode=permission_mode,
            sandbox_profile="adapter-enforced" if permission_mode == "provider-gateway" else "host-owned-workspace-network-denied",
            network_access="denied",
            resource_limits_json=_json({"timeout_seconds": packet.timeout_seconds, "output_limit": output_limit,
                                        "max_workers": max_workers, "message_bytes": 65_536}, "resource limits"),
            delegation_constraints_json=_json(constraints, "delegation constraints"),
            usage_budget_json=None,
            usage_budget_digest=None,
            created_at=utc_now(),
            capability_digest="0" * 64,
        )
        binding = object.__new__(cls)
        for name, value in values.items():
            object.__setattr__(binding, name, value)
        object.__setattr__(binding, "capability_digest", _sha256(canonical_json(binding._snapshot())))
        object.__setattr__(binding, "capability_digest", _sha256(canonical_json(binding._snapshot())))
        binding.__post_init__()
        return binding

    def verify_packet_identity(self, packet: TaskPacket, accepted_packet_id: str) -> None:
        if packet.task_id != self.task_id or packet.task_revision != self.task_revision or packet.attempt_id != self.attempt_id:
            raise ExecutionGuardError("capability binding task identity is stale")
        if accepted_packet_id != self.accepted_packet_id or packet.stable_provider_id != self.provider_id:
            raise ExecutionGuardError("capability binding accepted packet identity is stale")
        if packet.packet_digest() != self.packet_digest:
            raise ExecutionGuardError("capability binding packet digest is stale")

    def verify_skill_sources(self) -> None:
        for skill in self.assigned_skills:
            source_path = skill.get("source_path")
            content_digest = skill.get("content_digest")
            provenance = skill.get("provenance")
            if not isinstance(source_path, str) or not isinstance(content_digest, str):
                raise ExecutionGuardError("capability binding skill provenance is malformed")
            if not isinstance(provenance, dict) or provenance.get("source_sha256") != content_digest:
                raise ExecutionGuardError("capability binding skill provenance digest is inconsistent")
            path = Path(source_path)
            if not path.is_file() or _file_digest(path) != content_digest:
                raise ExecutionGuardError(f"capability skill digest is stale: {source_path}")


class CapabilityUsageStatus(str):
    UNKNOWN = "UNKNOWN"
    VERIFIED = "VERIFIED"
    NOT_USED = "NOT_USED"


@dataclass(frozen=True)
class CapabilityUsageRecord:
    usage_id: str
    binding_id: str
    capability_kind: str
    capability_name: str
    usage_status: str
    evidence_json: str
    observed_at: str

    def __post_init__(self) -> None:
        command_id(self.usage_id)
        command_id(self.binding_id)
        text(self.capability_kind, "capability usage kind", 64)
        text(self.capability_name, "capability usage name", 4096)
        if self.usage_status not in {CapabilityUsageStatus.UNKNOWN, CapabilityUsageStatus.VERIFIED, CapabilityUsageStatus.NOT_USED}:
            raise ValidationError("unsupported capability usage status")
        _json_object(self.evidence_json, "capability usage evidence")
        utc_timestamp(self.observed_at)

    def to_dict(self) -> dict[str, object]:
        return {"usage_id": self.usage_id, "binding_id": self.binding_id,
                "capability_kind": self.capability_kind, "capability_name": self.capability_name,
                "usage_status": self.usage_status, "evidence": _decode(self.evidence_json, "capability usage evidence"),
                "observed_at": self.observed_at}

# Builder for usage records with deterministic IDs and evidence shape validation
class CapabilityUsageBuilder:
    @staticmethod
    def build(binding: "CapabilityBinding", capability_kind: str, capability_name: str,
              status: str, evidence: dict[str, object]) -> CapabilityUsageRecord:
        # Validate capability belongs to binding
        if (capability_kind, capability_name) not in binding.assigned_capability_keys:
            raise ValidationError("capability not assigned in binding")
        # Validate status
        if status not in {CapabilityUsageStatus.VERIFIED, CapabilityUsageStatus.NOT_USED, CapabilityUsageStatus.UNKNOWN}:
            raise ValidationError("invalid capability usage status")
        # Validate evidence shape
        required_keys = {"observed_by", "method", "detail"}
        if not isinstance(evidence, dict) or not required_keys.issubset(evidence.keys()):
            raise ValidationError("evidence must contain observed_by, method, detail")
        evidence_json = canonical_json(evidence)
        observed_at = utc_now()
        # Deterministic usage_id based on binding and inputs
        import uuid, hashlib
        base = f"{binding.binding_id}:{capability_kind}:{capability_name}:{status}:{evidence_json}"
        usage_id = uuid.uuid5(uuid.NAMESPACE_URL, base).hex
        return CapabilityUsageRecord(usage_id, binding.binding_id, capability_kind, capability_name,
                                    status, evidence_json, observed_at)
