"""Controller-owned persistence mixin for provider metadata bindings."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from pathlib import Path
from shutil import which
from uuid import uuid4

from .domain import TaskStatus
from .dispatch import DispatchClaim
from .errors import ConflictError, CommandConflictError, ExecutionGuardError, NotFoundError, StorageError, ValidationError
from .evidence import ExecutionAttempt, digest_text, redact_text
from .packets import TaskPacket
from .provider_metadata import AcceptedPacketRecord, ProviderBinding, ProviderMetadataRecord
from .validation import bounded_int, canonical_json, command_id as validate_command_id, task_id as validate_task_id, text, utc_now


class ProviderMetadataStoreMixin:
    def _insert_attempt(self, connection: sqlite3.Connection, attempt: ExecutionAttempt,
                        command_id: str, request: str) -> None:
        if redact_text(canonical_json(attempt.to_dict())) != canonical_json(attempt.to_dict()):
            raise ValidationError("attempt contains unredacted credential-like text")
        connection.execute("""INSERT INTO attempts
            (attempt_id,schema_version,task_id,task_revision,role,provider,executable,workspace_root,status,
             requested_model,cli_version,provider_session_id,reported_model,created_at,started_at,completed_at,
             returncode,signal,stdout_bytes,stderr_bytes,stdout_sha256,stderr_sha256,result_status,detail,revision,
             accepted_packet_id,provider_binding_digest,provider_id,adapter_id)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", self._attempt_values_full(attempt))
        connection.execute("INSERT INTO attempt_commands VALUES (?,?,?,?)",
                           (command_id, attempt.attempt_id, request, canonical_json(attempt.to_dict())))
        if attempt.accepted_packet_id is None:
            return
        row = connection.execute("SELECT * FROM accepted_packets WHERE accepted_packet_id=?",
                                 (attempt.accepted_packet_id,)).fetchone()
        if row is None:
            raise StorageError("attempt provider binding references a missing accepted packet")
        binding = self._decode_accepted_packet(row).binding
        if attempt.provider_binding_digest != binding.digest:
            raise ValidationError("attempt provider binding digest does not match accepted packet")
        binding_command = f"attempt-binding-{digest_text(command_id)[:32]}"
        binding_request = canonical_json({"operation": "attempt_provider_binding",
                                          "attempt_id": attempt.attempt_id,
                                          "accepted_packet_id": attempt.accepted_packet_id,
                                          "binding_digest": binding.digest})
        connection.execute("""INSERT INTO attempt_provider_bindings
            (attempt_id,accepted_packet_id,provider_id,adapter_id,adapter_contract_version,manifest_digest,
             executable_identity_json,verified_capabilities_json,metadata_revision,metadata_digest,binding_digest,
             bound_at,command_id,request_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (attempt.attempt_id, attempt.accepted_packet_id, binding.provider_id, binding.adapter_id,
             binding.adapter_contract_version, binding.manifest_digest, binding.executable_identity_json,
             canonical_json(list(binding.verified_capabilities)), binding.metadata_revision, binding.metadata_digest,
             binding.digest, row["accepted_at"], binding_command, binding_request))

    def _bind_attempt_connection(self, connection: sqlite3.Connection, packet: TaskPacket,
                                 attempt: ExecutionAttempt,
                                 provider_metadata: ProviderMetadataRecord | None = None,
                                 available_capabilities: tuple[str, ...] = (),
                                 available_tools: tuple[str, ...] = ()) -> ExecutionAttempt:
        """Attach one immutable accepted provider binding before attempt insertion."""
        provider_id = packet.stable_provider_id
        current_row = connection.execute(
            "SELECT * FROM provider_metadata WHERE provider_id=?", (provider_id,)
        ).fetchone()
        if current_row is None:
            if provider_metadata is None and packet.provider_id is not None:
                raise ExecutionGuardError("generic dispatch requires registered provider metadata")
            metadata = provider_metadata or ProviderMetadataRecord.legacy(
                packet.provider, attempt.executable, which(attempt.executable), utc_now()
            )
            self._insert_provider_metadata(
                connection, metadata, f"metadata-{digest_text(packet.packet_digest())[:40]}",
                canonical_json({"operation": "legacy_packet_binding", "packet_digest": packet.packet_digest()}),
                "REGISTERED",
            )
        else:
            metadata = self._decode_provider_metadata(current_row)
            if provider_metadata is not None and metadata.metadata_digest != provider_metadata.metadata_digest:
                raise ConflictError("provider metadata changed; re-accept the packet")
        if metadata.provider_id != provider_id or metadata.adapter_id != packet.stable_adapter_id:
            raise ValidationError("packet provider identity does not match provider metadata")
        accepted_row = connection.execute(
            "SELECT * FROM accepted_packets WHERE task_id=? AND task_revision=?",
            (packet.task_id, packet.task_revision),
        ).fetchone()
        if accepted_row is None:
            request = canonical_json({"operation": "dispatch_packet_accept", "packet_digest": packet.packet_digest(),
                                      "metadata_digest": metadata.metadata_digest, "attempt_id": packet.attempt_id})
            accepted = self._accept_packet_connection(
                connection, packet, metadata, f"accept-{packet.packet_digest()[:40]}", request
            )
        else:
            accepted = self._decode_accepted_packet(accepted_row)
            if accepted.packet_digest != packet.packet_digest() or accepted.attempt_id != packet.attempt_id:
                raise ConflictError("accepted packet does not match the dispatch attempt")
        return replace(
            attempt,
            accepted_packet_id=accepted.accepted_packet_id,
            provider_binding_digest=accepted.binding.digest,
            provider_id=accepted.binding.provider_id,
            adapter_id=accepted.binding.adapter_id,
        )

    @staticmethod
    def _decode_provider_metadata(row: sqlite3.Row) -> ProviderMetadataRecord:
        try:
            return ProviderMetadataRecord(
                row["provider_id"], row["adapter_id"], row["adapter_contract_version"], row["provider_version"],
                row["manifest_schema_version"], row["manifest_digest"], row["executable"], row["resolved_executable"],
                row["executable_identity_json"], tuple(json.loads(row["declared_capabilities_json"])),
                tuple(json.loads(row["verified_capabilities_json"])), row["validation_status"], row["trust_status"],
                row["authorization_status"], row["state"], row["observed_at"], row["validated_at"], row["updated_at"],
                row["metadata_revision"], row["provenance_json"], row["metadata_json"], row["metadata_digest"],
            )
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            raise StorageError(f"invalid persisted provider metadata: {exc}") from exc

    @staticmethod
    def _decode_accepted_packet(row: sqlite3.Row) -> AcceptedPacketRecord:
        try:
            binding_data = json.loads(row["provider_binding_json"])
            binding_data["verified_capabilities"] = tuple(binding_data["verified_capabilities"])
            binding = ProviderBinding(**binding_data)
            if row["provider_binding_digest"] != binding.digest:
                raise ValidationError("accepted packet binding digest does not match its JSON")
            return AcceptedPacketRecord(
                row["accepted_packet_id"], row["task_id"], row["task_revision"], row["attempt_id"],
                row["packet_digest"], row["packet_json"], binding, row["accepted_at"], row["command_id"],
            )
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            raise StorageError(f"invalid persisted accepted packet: {exc}") from exc

    @staticmethod
    def _provider_metadata_values(record: ProviderMetadataRecord, command_id: str, request: str) -> tuple[object, ...]:
        return (
            record.provider_id, record.metadata_revision, record.adapter_id, record.adapter_contract_version,
            record.provider_version, record.manifest_schema_version, record.manifest_digest, record.executable,
            record.resolved_executable, record.executable_identity_json, canonical_json(list(record.declared_capabilities)),
            canonical_json(list(record.verified_capabilities)), record.validation_status, record.trust_status,
            record.authorization_status, record.state, record.observed_at, record.validated_at, record.updated_at,
            record.provenance_json, record.metadata_json, record.metadata_digest, command_id, request, 1,
        )

    def _insert_provider_metadata(self, connection: sqlite3.Connection, record: ProviderMetadataRecord,
                                  command_id: str, request: str, event_type: str) -> None:
        connection.execute("""INSERT INTO provider_metadata
            (provider_id,metadata_revision,adapter_id,adapter_contract_version,provider_version,manifest_schema_version,
             manifest_digest,executable,resolved_executable,executable_identity_json,declared_capabilities_json,
             verified_capabilities_json,validation_status,trust_status,authorization_status,state,observed_at,validated_at,
             updated_at,provenance_json,metadata_json,metadata_digest,command_id,request_json,schema_version)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            self._provider_metadata_values(record, command_id, request))
        event_command = f"metadata-event-{digest_text(command_id)[:32]}"
        connection.execute("""INSERT INTO provider_metadata_events
            (event_id,provider_id,metadata_revision,event_type,timestamp,metadata_json,metadata_digest,command_id,payload_json,schema_version,revision)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (uuid4().hex, record.provider_id, record.metadata_revision, event_type, record.updated_at,
             record.metadata_json, record.metadata_digest, event_command, request, 1, record.metadata_revision))

    def register_provider_metadata(self, record: ProviderMetadataRecord, command_id: str,
                                   expected_revision: int | None = None) -> ProviderMetadataRecord:
        if not isinstance(record, ProviderMetadataRecord):
            raise ValidationError("provider metadata registration requires a validated record")
        validate_command_id(command_id)
        if expected_revision is not None:
            bounded_int(expected_revision, "provider metadata expected revision", 0, 2**63 - 1)
        request = canonical_json({"operation": "provider_metadata_register", "record": record.to_dict(),
                                  "expected_revision": expected_revision})
        with self._connection(write=True) as connection:
            existing = connection.execute("SELECT * FROM provider_metadata WHERE provider_id=?",
                                          (record.provider_id,)).fetchone()
            if existing is None:
                if record.metadata_revision != 1 or expected_revision not in (None, 0):
                    raise ConflictError("new provider metadata must start at revision 1")
                self._insert_provider_metadata(connection, record, command_id, request, "REGISTERED")
                return record
            current = self._decode_provider_metadata(existing)
            if existing["command_id"] == command_id:
                if existing["request_json"] != request:
                    raise CommandConflictError("provider metadata command was reused with different input")
                return current
            if expected_revision is not None and current.metadata_revision != expected_revision:
                raise ConflictError(f"expected provider metadata revision {expected_revision}, found {current.metadata_revision}")
            if record.metadata_revision != current.metadata_revision + 1:
                raise ConflictError("provider metadata revision must advance by exactly one")
            if not set(current.verified_capabilities) <= set(record.verified_capabilities):
                raise ValidationError("metadata update cannot erase independently verified capabilities")
            if current.authorization_status == "authorized" and record.authorization_status != "authorized":
                raise ExecutionGuardError("authorization revocation requires an explicit revoke operation")
            values = self._provider_metadata_values(record, command_id, request)
            connection.execute("""UPDATE provider_metadata SET metadata_revision=?,adapter_id=?,adapter_contract_version=?
                ,provider_version=?,manifest_schema_version=?,manifest_digest=?,executable=?,resolved_executable=?
                ,executable_identity_json=?,declared_capabilities_json=?,verified_capabilities_json=?,validation_status=?
                ,trust_status=?,authorization_status=?,state=?,observed_at=?,validated_at=?,updated_at=?,provenance_json=?
                ,metadata_json=?,metadata_digest=?,command_id=?,request_json=? WHERE provider_id=?""",
                (*values[1:], record.provider_id))
            event_command = f"metadata-event-{digest_text(command_id)[:32]}"
            connection.execute("""INSERT INTO provider_metadata_events
                 (event_id,provider_id,metadata_revision,event_type,timestamp,metadata_json,metadata_digest,command_id,payload_json)
                 VALUES (?,?,?,?,?,?,?,?,?)""",
                (uuid4().hex, record.provider_id, record.metadata_revision, "UPDATED", record.updated_at,
                 record.metadata_json, record.metadata_digest, event_command, request))
            return record

    def _accept_packet_connection(self, connection: sqlite3.Connection, packet: TaskPacket,
                                  metadata: ProviderMetadataRecord, command_id: str,
                                  request: str) -> AcceptedPacketRecord:
        current_row = connection.execute("SELECT * FROM provider_metadata WHERE provider_id=?",
                                          (metadata.provider_id,)).fetchone()
        if current_row is None:
            self._insert_provider_metadata(connection, metadata, f"metadata-{digest_text(command_id)[:40]}", request, "REGISTERED")
        elif self._decode_provider_metadata(current_row).metadata_digest != metadata.metadata_digest:
            raise ConflictError("provider metadata changed; re-accept the packet")
        if packet.stable_provider_id != metadata.provider_id or packet.stable_adapter_id != metadata.adapter_id:
            raise ValidationError("accepted packet provider reference does not match provider metadata")
        if metadata.authorization_status != "authorized" or metadata.state != "execution_authorized":
            raise ExecutionGuardError("accepted packet requires explicit provider execution authorization")
        existing = connection.execute("SELECT * FROM accepted_packets WHERE task_id=? AND task_revision=?",
                                      (packet.task_id, packet.task_revision)).fetchone()
        if existing is not None:
            accepted = self._decode_accepted_packet(existing)
            if accepted.packet_digest != packet.packet_digest() or accepted.attempt_id != packet.attempt_id:
                raise ConflictError("task revision already has a different accepted packet")
            return accepted
        task = self._read_task(connection, packet.task_id)
        if task.revision != packet.task_revision or task.status is not TaskStatus.CREATED:
            raise ConflictError("accepted packet task revision is stale or not executable")
        binding = metadata.binding()
        accepted = AcceptedPacketRecord(uuid4().hex, packet.task_id, packet.task_revision, packet.attempt_id,
                                        packet.packet_digest(), packet.canonical_json(), binding, utc_now(), command_id)
        connection.execute("""INSERT INTO accepted_packets
            (accepted_packet_id,schema_version,task_id,task_revision,attempt_id,packet_digest,packet_json,provider_id,adapter_id,
             adapter_contract_version,provider_metadata_revision,provider_metadata_digest,provider_binding_json,
             provider_binding_digest,accepted_at,command_id,request_json)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (accepted.accepted_packet_id, 1, accepted.task_id, accepted.task_revision, accepted.attempt_id,
             accepted.packet_digest, accepted.packet_json, binding.provider_id, binding.adapter_id,
             binding.adapter_contract_version, binding.metadata_revision, binding.metadata_digest,
             canonical_json(binding.to_dict()), binding.digest, accepted.accepted_at, command_id, request))
        return accepted

    def accept_packet(self, packet: TaskPacket, metadata: ProviderMetadataRecord, command_id: str) -> AcceptedPacketRecord:
        if not isinstance(packet, TaskPacket) or not isinstance(metadata, ProviderMetadataRecord):
            raise ValidationError("packet acceptance requires a validated packet and provider metadata")
        validate_command_id(command_id)
        request = canonical_json({"operation": "packet_accept", "packet_digest": packet.packet_digest(),
                                  "metadata_digest": metadata.metadata_digest, "attempt_id": packet.attempt_id})
        with self._connection(write=True) as connection:
            previous = connection.execute("SELECT * FROM accepted_packets WHERE command_id=?", (command_id,)).fetchone()
            if previous is not None:
                if previous["request_json"] != request:
                    raise CommandConflictError("packet acceptance command was reused with different input")
                return self._decode_accepted_packet(previous)
            return self._accept_packet_connection(connection, packet, metadata, command_id, request)

    def _ensure_legacy_packet_binding(self, connection: sqlite3.Connection, packet: TaskPacket,
                                      executable: str) -> AcceptedPacketRecord:
        existing = connection.execute("SELECT * FROM accepted_packets WHERE task_id=? AND task_revision=?",
                                      (packet.task_id, packet.task_revision)).fetchone()
        if existing is not None:
            accepted = self._decode_accepted_packet(existing)
            if accepted.packet_digest != packet.packet_digest() or accepted.attempt_id != packet.attempt_id:
                raise ConflictError("accepted packet does not match dispatch request")
            current = connection.execute("SELECT * FROM provider_metadata WHERE provider_id=?",
                                         (accepted.binding.provider_id,)).fetchone()
            if current is None or self._decode_provider_metadata(current).metadata_digest != accepted.binding.metadata_digest:
                raise ConflictError("provider metadata changed after packet acceptance")
            return accepted
        current_row = connection.execute("SELECT * FROM provider_metadata WHERE provider_id=?",
                                         (packet.stable_provider_id,)).fetchone()
        if current_row is not None:
            metadata = self._decode_provider_metadata(current_row)
        else:
            resolved = which(executable) or (executable if Path(executable).is_absolute() else None)
            metadata = ProviderMetadataRecord.legacy(packet.provider, executable, resolved, utc_now())
        request = canonical_json({"operation": "legacy_packet_accept", "packet_digest": packet.packet_digest(),
                                  "metadata_digest": metadata.metadata_digest, "attempt_id": packet.attempt_id})
        return self._accept_packet_connection(connection, packet, metadata,
                                              f"legacy-accept-{packet.packet_digest()[:32]}", request)

    def _verify_accepted_packet_connection(self, connection: sqlite3.Connection, packet: TaskPacket,
                                           attempt_id: str) -> AcceptedPacketRecord:
        row = connection.execute("SELECT * FROM accepted_packets WHERE task_id=? AND task_revision=?",
                                 (packet.task_id, packet.task_revision)).fetchone()
        if row is None:
            raise ExecutionGuardError("dispatch requires an accepted packet binding")
        accepted = self._decode_accepted_packet(row)
        if accepted.packet_digest != packet.packet_digest() or accepted.attempt_id != attempt_id:
            raise ConflictError("accepted packet does not match the dispatch attempt")
        metadata_row = connection.execute("SELECT * FROM provider_metadata WHERE provider_id=?",
                                          (accepted.binding.provider_id,)).fetchone()
        if metadata_row is None:
            raise ExecutionGuardError("accepted packet provider metadata is unavailable")
        current = self._decode_provider_metadata(metadata_row)
        if current.metadata_digest != accepted.binding.metadata_digest or current.binding().digest != accepted.binding.digest:
            raise ConflictError("provider metadata changed after packet acceptance")
        if current.authorization_status != "authorized" or current.state != "execution_authorized":
            raise ExecutionGuardError("provider execution authorization was revoked")
        if packet.stable_provider_id != accepted.binding.provider_id or packet.stable_adapter_id != accepted.binding.adapter_id:
            raise ConflictError("packet provider reference differs from its accepted binding")
        return accepted

    def verify_accepted_packet(self, packet: TaskPacket, attempt_id: str | None = None) -> AcceptedPacketRecord:
        if not isinstance(packet, TaskPacket):
            raise ValidationError("accepted packet verification requires a TaskPacket")
        with self._connection(write=False) as connection:
            return self._verify_accepted_packet_connection(connection, packet, attempt_id or packet.attempt_id)

    def accepted_packet(self, task_id: str, task_revision: int) -> AcceptedPacketRecord:
        validate_task_id(task_id)
        bounded_int(task_revision, "accepted packet task revision", 1, 2**63 - 1)
        with self._connection(write=False) as connection:
            row = connection.execute("SELECT * FROM accepted_packets WHERE task_id=? AND task_revision=?",
                                     (task_id, task_revision)).fetchone()
            if row is None:
                raise NotFoundError(f"accepted packet for {task_id} revision {task_revision} does not exist")
            return self._decode_accepted_packet(row)

    def accepted_packet_by_id(self, accepted_packet_id: str) -> AcceptedPacketRecord:
        """Return one accepted packet by its durable packet identity."""
        validate_command_id(accepted_packet_id)
        with self._connection(write=False) as connection:
            row = connection.execute(
                "SELECT * FROM accepted_packets WHERE accepted_packet_id=?",
                (accepted_packet_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError(f"accepted packet does not exist: {accepted_packet_id}")
            return self._decode_accepted_packet(row)

    def provider_metadata(self, provider_id: str) -> ProviderMetadataRecord:
        text(provider_id, "provider ID", 128)
        with self._connection(write=False) as connection:
            row = connection.execute("SELECT * FROM provider_metadata WHERE provider_id=?", (provider_id,)).fetchone()
            if row is None:
                raise NotFoundError(f"provider metadata does not exist: {provider_id}")
            return self._decode_provider_metadata(row)

    def provider_metadata_list(self) -> tuple[ProviderMetadataRecord, ...]:
        if not self._database_present():
            return ()
        with self._connection(write=False) as connection:
            return tuple(self._decode_provider_metadata(row) for row in connection.execute(
                "SELECT * FROM provider_metadata ORDER BY provider_id"))
