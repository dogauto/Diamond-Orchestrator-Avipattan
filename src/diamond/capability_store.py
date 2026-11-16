"""Authoritative persistence and pre-dispatch verification for capability bindings."""

from __future__ import annotations

import sqlite3
from uuid import NAMESPACE_URL, uuid4, uuid5

from .capability_binding import (
    CapabilityBinding, CapabilityUsageRecord, CapabilityUsageStatus,
)
from .errors import CommandConflictError, ConflictError, ExecutionGuardError, NotFoundError, ValidationError
from .packets import TaskPacket
from .provider_metadata import AcceptedPacketRecord, ProviderMetadataRecord
from .validation import canonical_json, command_id as validate_command_id, task_id, text, utc_now


class CapabilityBindingStoreMixin:
    @staticmethod
    def _decode_capability_binding(row: sqlite3.Row) -> CapabilityBinding:
        try:
            return CapabilityBinding(
                row["binding_id"], row["task_id"], row["task_revision"], row["attempt_id"],
                row["accepted_packet_id"], row["packet_digest"], row["provider_id"], row["adapter_id"],
                row["adapter_contract_version"], row["manifest_digest"], row["execution_mode"],
                row["requested_skills_json"], row["assigned_skills_json"], row["available_capabilities_json"],
                row["requested_tools_json"], row["authorized_tools_json"], row["available_tools_json"],
                row["provider_tools_json"], row["mcp_integrations_json"], row["plugin_integrations_json"],
                row["workspace_root"], row["owned_paths_json"], row["permission_mode"], row["sandbox_profile"],
                row["network_access"], row["resource_limits_json"], row["delegation_constraints_json"],
                row["created_at"], row["capability_digest"],
            )
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            raise ValidationError(f"invalid persisted capability binding: {exc}") from exc

    @staticmethod
    def _decode_capability_usage(row: sqlite3.Row) -> CapabilityUsageRecord:
        return CapabilityUsageRecord(row["usage_id"], row["binding_id"], row["capability_kind"],
                                     row["capability_name"], row["usage_status"], row["evidence_json"], row["observed_at"])

    @staticmethod
    def _binding_values(binding: CapabilityBinding, command_id: str, request: str) -> tuple[object, ...]:
        return (
            binding.binding_id, 1, binding.task_id, binding.task_revision, binding.attempt_id,
            binding.accepted_packet_id, binding.packet_digest, binding.provider_id, binding.adapter_id,
            binding.adapter_contract_version, binding.manifest_digest, binding.execution_mode,
            binding.requested_skills_json, binding.assigned_skills_json, binding.available_capabilities_json,
            binding.requested_tools_json, binding.authorized_tools_json, binding.available_tools_json,
            binding.provider_tools_json, binding.mcp_integrations_json, binding.plugin_integrations_json,
            binding.workspace_root, binding.owned_paths_json, binding.permission_mode, binding.sandbox_profile,
            binding.network_access, binding.resource_limits_json, binding.delegation_constraints_json,
            binding.created_at, binding.capability_digest, command_id, request,
        )

    def record_capability_usage(self, usage_id: str | None, binding_id: str, capability_kind: str, capability_name: str, status: str, evidence: dict[str, object], command_id: str, usage_budget: dict[str, Any] | None = None) -> CapabilityUsageRecord:
        validate_command_id(binding_id)
        validate_command_id(command_id)
        if usage_id is not None:
            validate_command_id(usage_id)
        if status not in {CapabilityUsageStatus.VERIFIED, CapabilityUsageStatus.NOT_USED, CapabilityUsageStatus.UNKNOWN}:
            raise ValidationError("invalid capability usage status")
        required_keys = {"observed_by", "method", "detail"}
        if not isinstance(evidence, dict) or not required_keys.issubset(evidence.keys()):
            raise ValidationError("evidence must contain observed_by, method, detail")
        text(capability_kind, "capability usage kind", 64)
        text(capability_name, "capability usage name", 4096)
        evidence_json = canonical_json(evidence)
        request = canonical_json({"operation": "capability_usage_record", "binding_id": binding_id,
                                  "capability_kind": capability_kind, "capability_name": capability_name,
                                  "status": status, "evidence": evidence, "usage_id": usage_id})
        with self._connection(write=True) as connection:
            previous = connection.execute("SELECT * FROM capability_usage WHERE command_id=?", (command_id,)).fetchone()
            if previous is not None:
                if previous["request_json"] != request:
                    raise CommandConflictError("capability usage command was reused with different input")
                return self._decode_capability_usage(previous)
            if usage_id is None:
                usage_id = uuid5(
                    NAMESPACE_URL,
                    f"{binding_id}:{capability_kind}:{capability_name}:{status}:{evidence_json}",
                ).hex
            previous_usage = connection.execute("SELECT * FROM capability_usage WHERE usage_id=?", (usage_id,)).fetchone()
            if previous_usage is not None:
                if (previous_usage["binding_id"], previous_usage["capability_kind"], previous_usage["capability_name"],
                        previous_usage["usage_status"], previous_usage["evidence_json"]) != (
                            binding_id, capability_kind, capability_name, status, evidence_json):
                    raise ConflictError("capability usage ID is bound to different evidence")
                return self._decode_capability_usage(previous_usage)
            binding_row = connection.execute("SELECT * FROM capability_bindings WHERE binding_id=?", (binding_id,)).fetchone()
            if binding_row is None:
                raise NotFoundError(f"capability binding {binding_id} not found")
            if not self._is_capability_assigned(binding_row, capability_kind, capability_name):
                raise ValidationError("capability not assigned in binding")
            usage = CapabilityUsageRecord(usage_id, binding_id, capability_kind, capability_name,
                                          status, evidence_json, utc_now())
            connection.execute("""INSERT INTO capability_usage
                (usage_id,schema_version,binding_id,capability_kind,capability_name,usage_status,evidence_json,observed_at,command_id,request_json)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                              (usage.usage_id, 1, usage.binding_id, usage.capability_kind, usage.capability_name,
                               usage.usage_status, usage.evidence_json, usage.observed_at, command_id, request))
            return usage

    def _is_capability_assigned(self, binding_row: sqlite3.Row, capability_kind: str,
                                capability_name: str) -> bool:
        # Decode the binding to get assigned_capability_keys
        from .capability_binding import CapabilityBinding
        binding = CapabilityBinding(
            binding_row["binding_id"], binding_row["task_id"], binding_row["task_revision"],
            binding_row["attempt_id"], binding_row["accepted_packet_id"], binding_row["packet_digest"],
            binding_row["provider_id"], binding_row["adapter_id"], binding_row["adapter_contract_version"],
            binding_row["manifest_digest"], binding_row["execution_mode"],
            binding_row["requested_skills_json"], binding_row["assigned_skills_json"],
            binding_row["available_capabilities_json"], binding_row["requested_tools_json"],
            binding_row["authorized_tools_json"], binding_row["available_tools_json"],
            binding_row["provider_tools_json"], binding_row["mcp_integrations_json"],
            binding_row["plugin_integrations_json"], binding_row["workspace_root"],
            binding_row["owned_paths_json"], binding_row["permission_mode"], binding_row["sandbox_profile"],
            binding_row["network_access"], binding_row["resource_limits_json"],
            binding_row["delegation_constraints_json"], binding_row["created_at"],
            binding_row["capability_digest"],
        )
        assigned_keys = binding.assigned_capability_keys
        return (capability_kind, capability_name) in assigned_keys

    def _insert_capability_usage(self, connection: sqlite3.Connection, binding: CapabilityBinding,
                                 capability_kind: str, capability_name: str, command_id: str,
                                 request: str) -> CapabilityUsageRecord:
        observed_at = utc_now()
        usage = CapabilityUsageRecord(uuid4().hex, binding.binding_id, capability_kind, capability_name,
                                     CapabilityUsageStatus.UNKNOWN, canonical_json({
                                         "reason": "provider evidence does not establish actual usage",
                                         "verified": False,
                                     }), observed_at)
        connection.execute("""INSERT INTO capability_usage
            (usage_id,schema_version,binding_id,capability_kind,capability_name,usage_status,evidence_json,observed_at,command_id,request_json)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
                          (usage.usage_id, 1, usage.binding_id, usage.capability_kind, usage.capability_name,
                           usage.usage_status, usage.evidence_json, usage.observed_at, command_id, request))
        return usage

    def _bind_capabilities_connection(
        self,
        connection: sqlite3.Connection,
        packet: TaskPacket,
        accepted: AcceptedPacketRecord,
        metadata: ProviderMetadataRecord,
        command_id: str,
        *,
        available_capabilities: tuple[str, ...] = (),
        available_tools: tuple[str, ...] | None = None,
        requested_skill_names: tuple[str, ...] | None = None,
        permission_mode: str = "controller-default",
        output_limit: int = 1_048_576,
        max_workers: int = 2,
        delegation_constraints: dict[str, object] | None = None,
    ) -> CapabilityBinding:
        validate_command_id(command_id)
        if not isinstance(packet, TaskPacket) or not isinstance(accepted, AcceptedPacketRecord) or not isinstance(metadata, ProviderMetadataRecord):
            raise ValidationError("capability binding persistence requires validated packet values")
        request = canonical_json({
            "operation": "capability_bind", "packet_digest": packet.packet_digest(),
            "accepted_packet_id": accepted.accepted_packet_id, "metadata_digest": metadata.metadata_digest,
            "available_capabilities": list(available_capabilities),
            "available_tools": list(available_tools) if available_tools is not None else None,
            "requested_skill_names": list(requested_skill_names) if requested_skill_names is not None else None,
            "permission_mode": permission_mode, "output_limit": output_limit, "max_workers": max_workers,
            "delegation_constraints": delegation_constraints,
        })
        previous = connection.execute("SELECT * FROM capability_bindings WHERE command_id=?", (command_id,)).fetchone()
        if previous is not None:
            if previous["request_json"] != request:
                raise CommandConflictError("capability binding command was reused with different input")
            return self._decode_capability_binding(previous)
        existing = connection.execute("SELECT * FROM capability_bindings WHERE attempt_id=?", (packet.attempt_id,)).fetchone()
        if existing is not None:
            binding = self._decode_capability_binding(existing)
            binding.verify_packet_identity(packet, accepted.accepted_packet_id)
            binding.verify_skill_sources()
            if binding.manifest_digest != metadata.manifest_digest:
                raise ConflictError("capability binding provider metadata is stale")
            return binding
        if accepted.packet_digest != packet.packet_digest() or accepted.attempt_id != packet.attempt_id:
            raise ConflictError("capability binding accepted packet does not match the dispatch")
        binding = CapabilityBinding.from_packet(
            packet, metadata, accepted.accepted_packet_id,
            available_capabilities=available_capabilities, available_tools=available_tools,
            requested_skill_names=requested_skill_names,
            permission_mode=permission_mode, output_limit=output_limit, max_workers=max_workers,
            delegation_constraints=delegation_constraints,
        )
        connection.execute("""INSERT INTO capability_bindings
            (binding_id,schema_version,task_id,task_revision,attempt_id,accepted_packet_id,packet_digest,provider_id,adapter_id,
             adapter_contract_version,manifest_digest,execution_mode,requested_skills_json,assigned_skills_json,
             available_capabilities_json,requested_tools_json,authorized_tools_json,available_tools_json,provider_tools_json,
             mcp_integrations_json,plugin_integrations_json,workspace_root,owned_paths_json,permission_mode,sandbox_profile,
             network_access,resource_limits_json,delegation_constraints_json,created_at,capability_digest,command_id,request_json)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                          self._binding_values(binding, command_id, request))
        # No initial UNKNOWN usage rows are created; usage will be recorded explicitly
        # via record_capability_usage to support loaded vs verified-used distinction
        return binding

    def create_capability_binding(
        self, packet: TaskPacket, accepted: AcceptedPacketRecord, metadata: ProviderMetadataRecord,
        command_id: str, *, available_capabilities: tuple[str, ...] = (), available_tools: tuple[str, ...] | None = None,
        requested_skill_names: tuple[str, ...] | None = None,
        permission_mode: str = "controller-default", output_limit: int = 1_048_576, max_workers: int = 2,
        delegation_constraints: dict[str, object] | None = None,
    ) -> CapabilityBinding:
        with self._connection(write=True) as connection:
            return self._bind_capabilities_connection(
                connection, packet, accepted, metadata, command_id,
                available_capabilities=available_capabilities, available_tools=available_tools,
                requested_skill_names=requested_skill_names,
                permission_mode=permission_mode, output_limit=output_limit, max_workers=max_workers,
                delegation_constraints=delegation_constraints,
            )

    def _verify_capability_binding_connection(self, connection: sqlite3.Connection, packet: TaskPacket,
                                              attempt_id: str) -> CapabilityBinding:
        row = connection.execute("SELECT * FROM capability_bindings WHERE attempt_id=?", (attempt_id,)).fetchone()
        if row is None:
            raise ExecutionGuardError("dispatch requires an immutable capability binding")
        binding = self._decode_capability_binding(row)
        binding.verify_skill_sources()
        accepted_row = connection.execute("SELECT * FROM accepted_packets WHERE accepted_packet_id=?",
                                          (binding.accepted_packet_id,)).fetchone()
        if accepted_row is None:
            raise ExecutionGuardError("capability binding references a missing accepted packet")
        accepted = self._decode_accepted_packet(accepted_row)
        binding.verify_packet_identity(packet, accepted.accepted_packet_id)
        if accepted.packet_digest != binding.packet_digest or accepted.attempt_id != attempt_id:
            raise ConflictError("capability binding packet is stale")
        metadata_row = connection.execute("SELECT * FROM provider_metadata WHERE provider_id=?",
                                          (binding.provider_id,)).fetchone()
        if metadata_row is None:
            raise ExecutionGuardError("capability binding provider metadata is unavailable")
        metadata = self._decode_provider_metadata(metadata_row)
        if metadata.metadata_digest != accepted.binding.metadata_digest or metadata.binding().digest != accepted.binding.digest:
            raise ConflictError("capability binding provider metadata is stale")
        if metadata.manifest_digest != binding.manifest_digest or metadata.adapter_id != binding.adapter_id:
            raise ConflictError("capability binding adapter identity is stale")
        if metadata.authorization_status != "authorized" or metadata.state != "execution_authorized":
            raise ExecutionGuardError("capability binding provider authorization was revoked")
        return binding

    def verify_capability_binding(self, packet: TaskPacket, attempt_id: str | None = None) -> CapabilityBinding:
        if not isinstance(packet, TaskPacket):
            raise ValidationError("capability binding verification requires a TaskPacket")
        with self._connection(write=False) as connection:
            return self._verify_capability_binding_connection(connection, packet, attempt_id or packet.attempt_id)

    def capability_binding(self, attempt_id: str) -> CapabilityBinding:
        task_id(attempt_id)
        with self._connection(write=False) as connection:
            row = connection.execute("SELECT * FROM capability_bindings WHERE attempt_id=?", (attempt_id,)).fetchone()
            if row is None:
                raise NotFoundError(f"capability binding for attempt {attempt_id} does not exist")
            return self._decode_capability_binding(row)

    def capability_usage(self, attempt_id: str) -> tuple[CapabilityUsageRecord, ...]:
        task_id(attempt_id)
        with self._connection(write=False) as connection:
            row = connection.execute("SELECT binding_id FROM capability_bindings WHERE attempt_id=?", (attempt_id,)).fetchone()
            if row is None:
                raise NotFoundError(f"capability binding for attempt {attempt_id} does not exist")
            rows = connection.execute("SELECT * FROM capability_usage WHERE binding_id=? ORDER BY capability_kind,capability_name",
                                      (row["binding_id"],)).fetchall()
            return tuple(self._decode_capability_usage(item) for item in rows)

    def capability_usage_for_binding(self, binding_id: str) -> tuple[CapabilityUsageRecord, ...]:
        validate_command_id(binding_id)
        with self._connection(write=False) as connection:
            rows = connection.execute("SELECT * FROM capability_usage WHERE binding_id=? ORDER BY capability_kind,capability_name",
                                      (binding_id,)).fetchall()
            return tuple(self._decode_capability_usage(item) for item in rows)
