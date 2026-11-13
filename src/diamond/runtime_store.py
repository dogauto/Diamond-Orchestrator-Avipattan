"""EventStore mixin for the controller-owned agent runtime spine."""

from __future__ import annotations

import json
from dataclasses import replace
from sqlite3 import Row
from typing import Any
from uuid import uuid4

from .agent_runtime import (
    AgentIdentity, AgentMessage, AgentSession, AgentSessionStatus, ChildOutcome,
    CompletionReceipt, Conversation, Delegation, DelegationStatus, DeliveryStatus,
    MAX_MESSAGE_BYTES, MessageDelivery, digest, payload_digest, runtime_id,
)
from .domain import Provider, Role
from .errors import CommandConflictError, ConflictError, ExecutionGuardError, NotFoundError, ValidationError
from .evidence import digest_text
from .validation import bounded_int, canonical_json, command_id as validate_command_id, parse_canonical_json, task_id as validate_task_id, text, utc_now


def _enum(enum_type, value: object, name: str):
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"invalid {name}") from exc


class AgentRuntimeStoreMixin:
    """Persistence operations executed inside the existing EventStore ledger."""

    @staticmethod
    def _runtime_command(connection, command: str, request: str) -> str | None:
        validate_command_id(command)
        row = connection.execute("SELECT request_json,result_json FROM agent_runtime_commands WHERE command_id=?", (command,)).fetchone()
        if row is None:
            return None
        if row["request_json"] != request:
            raise CommandConflictError(f"command {command} already committed different input")
        return row["result_json"]

    @staticmethod
    def _runtime_save_command(connection, command: str, operation: str, request: str, result: object) -> None:
        connection.execute("INSERT INTO agent_runtime_commands VALUES (?,?,?,?)",
                           (command, operation, request, canonical_json(result)))

    @staticmethod
    def _runtime_event(connection, entity_type: str, entity_id: str, revision: int,
                       event_type: str, command: str, payload: object) -> None:
        payload_json = canonical_json(payload)
        connection.execute("INSERT INTO agent_runtime_events VALUES (?,?,?,?,?,?,?,?)",
                           (uuid4().hex, entity_type, entity_id, revision, event_type, utc_now(), command, payload_json))

    @staticmethod
    def _identity(row: Row) -> AgentIdentity:
        return AgentIdentity(row["agent_id"], row["agent_name"], _enum(Role, row["role"], "agent role"),
                             _enum(Provider, row["provider"], "agent provider"), row["adapter_id"], row["task_id"],
                             row["attempt_id"], row["workflow_id"], row["parent_agent_id"], row["created_at"])

    @staticmethod
    def _session(row: Row) -> AgentSession:
        return AgentSession(row["session_id"], row["agent_id"], row["delegation_id"],
                            _enum(Provider, row["provider"], "session provider"), row["adapter_id"],
                            row["provider_session_id"], _enum(AgentSessionStatus, row["status"], "session status"),
                            bool(row["identity_verified"]), row["verified_identity_digest"], row["created_at"],
                            row["started_at"], row["completed_at"], row["updated_at"],
                            _enum(ChildOutcome, row["terminal_outcome"], "terminal outcome") if row["terminal_outcome"] else None,
                            row["revision"])

    @staticmethod
    def _delegation(row: Row) -> Delegation:
        return Delegation(row["delegation_id"], row["parent_task_id"], row["parent_attempt_id"], row["parent_agent_id"],
                          row["child_task_id"], row["child_attempt_id"], _enum(Role, row["child_role"], "child role"),
                          _enum(Provider, row["child_provider"], "child provider"), row["child_adapter_id"],
                          row["workflow_id"], _enum(DelegationStatus, row["status"], "delegation status"),
                          row["created_at"], row["updated_at"], row["revision"])

    @staticmethod
    def _conversation(row: Row) -> Conversation:
        return Conversation(row["conversation_id"], row["delegation_id"], row["parent_task_id"], row["parent_attempt_id"],
                             row["parent_agent_id"], row["child_agent_id"], row["created_at"])

    @staticmethod
    def _message(row: Row) -> AgentMessage:
        return AgentMessage(row["message_id"], row["conversation_id"], row["sequence_no"], row["sender_session_id"],
                            row["recipient_session_id"], row["correlation_id"], row["idempotency_key"],
                            row["payload_json"], row["payload_digest"], row["created_at"])

    @staticmethod
    def _delivery(row: Row) -> MessageDelivery:
        return MessageDelivery(row["message_id"], _enum(DeliveryStatus, row["status"], "delivery status"),
                               row["revision"], row["updated_at"], row["failure_reason"])

    @staticmethod
    def _receipt(row: Row) -> CompletionReceipt:
        return CompletionReceipt(row["receipt_id"], row["delegation_id"], row["child_session_id"], row["child_agent_id"],
                                 row["child_task_id"], row["child_attempt_id"], _enum(ChildOutcome, row["outcome"], "child outcome"),
                                 row["provider_session_id"], bool(row["identity_verified"]), row["evidence_digest"],
                                 bool(row["accepted"]), row["created_at"])

    def register_agent(self, agent_id: str, agent_name: str, role: Role, provider: Provider, adapter_id: str,
                       task_id: str, command_id: str, *, attempt_id: str | None = None,
                       workflow_id: str | None = None, parent_agent_id: str | None = None) -> AgentIdentity:
        runtime_id(agent_id, "agent_id")
        text(agent_name, "agent_name", 256)
        text(adapter_id, "agent adapter_id", 256)
        validate_task_id(task_id)
        runtime_id(attempt_id, "attempt_id") if attempt_id is not None else None
        runtime_id(workflow_id, "workflow_id") if workflow_id is not None else None
        runtime_id(parent_agent_id, "parent_agent_id") if parent_agent_id is not None else None
        if not isinstance(role, Role) or not isinstance(provider, Provider):
            raise ValidationError("agent role and provider must be enum values")
        request = canonical_json({"operation": "agent_register", "agent_id": agent_id, "agent_name": agent_name,
                                  "role": role.value, "provider": provider.value, "adapter_id": adapter_id,
                                  "task_id": task_id, "attempt_id": attempt_id, "workflow_id": workflow_id,
                                  "parent_agent_id": parent_agent_id})
        with self._connection(write=True) as connection:
            previous = self._runtime_command(connection, command_id, request)
            if previous is not None:
                return self._identity_from_json(previous)
            if connection.execute("SELECT 1 FROM tasks WHERE task_id=?", (task_id,)).fetchone() is None:
                raise NotFoundError(f"task {task_id} does not exist")
            if attempt_id is not None:
                row = connection.execute("SELECT task_id FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
                if row is None:
                    raise NotFoundError(f"attempt {attempt_id} does not exist")
                if row["task_id"] != task_id:
                    raise ConflictError("agent attempt is not bound to its task")
            if workflow_id is not None and connection.execute("SELECT 1 FROM workflows WHERE workflow_id=?", (workflow_id,)).fetchone() is None:
                raise NotFoundError(f"workflow {workflow_id} does not exist")
            if parent_agent_id is not None and connection.execute("SELECT 1 FROM agent_identities WHERE agent_id=?", (parent_agent_id,)).fetchone() is None:
                raise NotFoundError(f"parent agent {parent_agent_id} does not exist")
            if connection.execute("SELECT 1 FROM agent_identities WHERE agent_id=?", (agent_id,)).fetchone():
                raise ConflictError(f"agent {agent_id} already exists")
            item = AgentIdentity(agent_id, agent_name, role, provider, adapter_id, task_id, attempt_id, workflow_id,
                                 parent_agent_id, utc_now())
            connection.execute("INSERT INTO agent_identities VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                               (item.agent_id, 1, item.agent_name, item.role.value, item.provider.value, item.adapter_id,
                                item.task_id, item.attempt_id, item.workflow_id, item.parent_agent_id, item.created_at))
            self._runtime_event(connection, "agent", item.agent_id, 1, "AGENT_REGISTERED", command_id, item.to_dict())
            self._runtime_save_command(connection, command_id, "agent_register", request, item.to_dict())
            return item

    @staticmethod
    def _identity_from_json(value: str) -> AgentIdentity:
        data = parse_canonical_json(value)
        if not isinstance(data, dict):
            raise ValidationError("runtime command result is not an agent identity")
        return AgentIdentity(data["agent_id"], data["agent_name"], Role(data["role"]), Provider(data["provider"]),
                             data["adapter_id"], data["task_id"], data["attempt_id"], data["workflow_id"],
                             data["parent_agent_id"], data["created_at"])

    def agent_identity(self, agent_id: str) -> AgentIdentity:
        runtime_id(agent_id, "agent_id")
        with self._connection(write=False) as connection:
            row = connection.execute("SELECT * FROM agent_identities WHERE agent_id=?", (agent_id,)).fetchone()
            if row is None:
                raise NotFoundError(f"agent {agent_id} does not exist")
            return self._identity(row)

    def agent_identities(self, task_id: str | None = None) -> tuple[AgentIdentity, ...]:
        if task_id is not None:
            validate_task_id(task_id)
        if not self._database_present():
            return ()
        with self._connection(write=False) as connection:
            query = "SELECT * FROM agent_identities"
            params: tuple[Any, ...] = ()
            if task_id is not None:
                query += " WHERE task_id=?"
                params = (task_id,)
            rows = connection.execute(query + " ORDER BY created_at, agent_id", params).fetchall()
            return tuple(self._identity(row) for row in rows)

    def authorize_delegation(self, delegation_id: str, parent_task_id: str, parent_attempt_id: str,
                             parent_agent_id: str, child_task_id: str, child_role: Role,
                             child_provider: Provider, child_adapter_id: str, command_id: str,
                             *, child_attempt_id: str | None = None, workflow_id: str | None = None,
                             child_packet_digest: str | None = None) -> Delegation:
        runtime_id(delegation_id, "delegation_id")
        validate_task_id(parent_task_id)
        runtime_id(parent_attempt_id, "parent_attempt_id")
        runtime_id(parent_agent_id, "parent_agent_id")
        validate_task_id(child_task_id)
        runtime_id(child_attempt_id, "child_attempt_id") if child_attempt_id is not None else None
        runtime_id(workflow_id, "workflow_id") if workflow_id is not None else None
        text(child_adapter_id, "child adapter_id", 256)
        if not isinstance(child_role, Role) or not isinstance(child_provider, Provider):
            raise ValidationError("child role and provider must be enum values")
        request = canonical_json({"operation": "delegation_authorize", "delegation_id": delegation_id,
                                  "parent_task_id": parent_task_id, "parent_attempt_id": parent_attempt_id,
                                  "parent_agent_id": parent_agent_id, "child_task_id": child_task_id,
                                  "child_attempt_id": child_attempt_id, "child_role": child_role.value,
                                  "child_provider": child_provider.value, "child_adapter_id": child_adapter_id,
                                  "workflow_id": workflow_id, "child_packet_digest": child_packet_digest})
        with self._connection(write=True) as connection:
            previous = self._runtime_command(connection, command_id, request)
            if previous is not None:
                return self._delegation_from_json(previous)
            parent_attempt = connection.execute("SELECT task_id FROM attempts WHERE attempt_id=?", (parent_attempt_id,)).fetchone()
            if parent_attempt is None:
                raise NotFoundError(f"attempt {parent_attempt_id} does not exist")
            if parent_attempt["task_id"] != parent_task_id:
                raise ConflictError("parent attempt is not bound to parent task")
            parent = connection.execute("SELECT * FROM agent_identities WHERE agent_id=?", (parent_agent_id,)).fetchone()
            if parent is None:
                raise NotFoundError(f"parent agent {parent_agent_id} does not exist")
            if parent["task_id"] != parent_task_id or parent["attempt_id"] not in (None, parent_attempt_id):
                raise ConflictError("parent agent is not authorized for the parent task and attempt")
            if connection.execute("SELECT 1 FROM tasks WHERE task_id=?", (child_task_id,)).fetchone() is None:
                raise NotFoundError(f"child task {child_task_id} does not exist")
            if child_attempt_id is not None:
                child_attempt = connection.execute("SELECT task_id FROM attempts WHERE attempt_id=?", (child_attempt_id,)).fetchone()
                if child_attempt is None:
                    raise NotFoundError(f"child attempt {child_attempt_id} does not exist")
                if child_attempt["task_id"] != child_task_id:
                    raise ConflictError("child attempt is not bound to child task")
            if workflow_id is not None and connection.execute("SELECT 1 FROM workflows WHERE workflow_id=?", (workflow_id,)).fetchone() is None:
                raise NotFoundError(f"workflow {workflow_id} does not exist")
            if connection.execute("SELECT 1 FROM delegations WHERE delegation_id=?", (delegation_id,)).fetchone():
                raise ConflictError(f"delegation {delegation_id} already exists")
            if child_packet_digest is not None:
                task_row = connection.execute("SELECT packet_digest FROM tasks WHERE task_id=?", (child_task_id,)).fetchone()
                if task_row is None:
                    raise NotFoundError(f"child task {child_task_id} does not exist")
                from .packets import digest_text
                if task_row["packet_digest"] != child_packet_digest:
                    raise ConflictError("child task packet digest does not match accepted delegation packet")
            item = Delegation(delegation_id, parent_task_id, parent_attempt_id, parent_agent_id, child_task_id,
                              child_attempt_id, child_role, child_provider, child_adapter_id, workflow_id,
                              DelegationStatus.AUTHORIZED, utc_now(), utc_now(), 1)
            connection.execute("INSERT INTO delegations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                               (item.delegation_id, 1, item.parent_task_id, item.parent_attempt_id, item.parent_agent_id,
                                item.child_task_id, item.child_attempt_id, item.child_role.value, item.child_provider.value,
                                item.child_adapter_id, item.workflow_id, item.status.value, item.created_at, item.updated_at, item.revision))
            self._runtime_event(connection, "delegation", item.delegation_id, 1, "DELEGATION_AUTHORIZED", command_id, item.to_dict())
            self._runtime_save_command(connection, command_id, "delegation_authorize", request, item.to_dict())
            return item

    @staticmethod
    def _delegation_from_json(value: str) -> Delegation:
        data = parse_canonical_json(value)
        if not isinstance(data, dict):
            raise ValidationError("runtime command result is not a delegation")
        return Delegation(data["delegation_id"], data["parent_task_id"], data["parent_attempt_id"], data["parent_agent_id"],
                          data["child_task_id"], data["child_attempt_id"], Role(data["child_role"]), Provider(data["child_provider"]),
                          data["child_adapter_id"], data["workflow_id"], DelegationStatus(data["status"]),
                          data["created_at"], data["updated_at"], data["revision"])

    def delegation(self, delegation_id: str) -> Delegation:
        runtime_id(delegation_id, "delegation_id")
        with self._connection(write=False) as connection:
            row = connection.execute("SELECT * FROM delegations WHERE delegation_id=?", (delegation_id,)).fetchone()
            if row is None:
                raise NotFoundError(f"delegation {delegation_id} does not exist")
            return self._delegation(row)

    def create_agent_session(self, session_id: str, agent_id: str, provider: Provider, adapter_id: str,
                             command_id: str, *, provider_session_id: str | None = None) -> AgentSession:
        runtime_id(session_id, "session_id")
        runtime_id(agent_id, "agent_id")
        text(adapter_id, "session adapter_id", 256)
        if provider_session_id is not None:
            text(provider_session_id, "provider session id", 4096)
        if not isinstance(provider, Provider):
            raise ValidationError("session provider must be a Provider")
        request = canonical_json({"operation": "session_create", "session_id": session_id, "agent_id": agent_id,
                                  "provider": provider.value, "adapter_id": adapter_id,
                                  "provider_session_id": provider_session_id})
        with self._connection(write=True) as connection:
            previous = self._runtime_command(connection, command_id, request)
            if previous is not None:
                return self._session_from_json(previous)
            delegation_rows = connection.execute(
                """SELECT d.delegation_id
                   FROM delegations AS d
                   JOIN agent_identities AS i
                     ON i.task_id = d.child_task_id
                    AND i.role = d.child_role
                    AND i.provider = d.child_provider
                    AND i.adapter_id = d.child_adapter_id
                    AND i.parent_agent_id = d.parent_agent_id
                  WHERE i.agent_id = ?
                    AND d.status = ?
                  ORDER BY d.created_at, d.delegation_id""",
                (agent_id, DelegationStatus.AUTHORIZED.value),
            ).fetchall()
            delegation_id = delegation_rows[0]["delegation_id"] if len(delegation_rows) == 1 else None
            self._session_insert(connection, session_id, agent_id, delegation_id, provider, adapter_id,
                                 provider_session_id, command_id)
            row = connection.execute("SELECT * FROM agent_sessions WHERE session_id=?", (session_id,)).fetchone()
            item = self._session(row)
            self._runtime_save_command(connection, command_id, "session_create", request, item.to_dict())
            return item

    def _session_insert(self, connection, session_id: str, agent_id: str, delegation_id: str | None,
                        provider: Provider, adapter_id: str, provider_session_id: str | None, command_id: str) -> None:
        identity = connection.execute("SELECT * FROM agent_identities WHERE agent_id=?", (agent_id,)).fetchone()
        if identity is None:
            raise NotFoundError(f"agent {agent_id} does not exist")
        if identity["provider"] != provider.value or identity["adapter_id"] != adapter_id:
            raise ConflictError("session provider binding does not match agent identity")
        if connection.execute("SELECT 1 FROM agent_sessions WHERE session_id=?", (session_id,)).fetchone():
            raise ConflictError(f"session {session_id} already exists")
        now = utc_now()
        item = AgentSession(session_id, agent_id, delegation_id, provider, adapter_id, provider_session_id,
                            AgentSessionStatus.ACTIVE, False, None, now, now, None, now, None, 1)
        connection.execute("INSERT INTO agent_sessions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           (item.session_id, 1, item.agent_id, item.delegation_id, item.provider.value, item.adapter_id,
                            item.provider_session_id, item.status.value, 0, None, item.created_at, item.started_at,
                            item.completed_at, item.updated_at, None, item.revision))
        self._runtime_event(connection, "session", item.session_id, 1, "SESSION_STARTED", command_id, item.to_dict())

    @staticmethod
    def _session_from_json(value: str) -> AgentSession:
        data = parse_canonical_json(value)
        return AgentSession(data["session_id"], data["agent_id"], data["delegation_id"], Provider(data["provider"]),
                            data["adapter_id"], data["provider_session_id"], AgentSessionStatus(data["status"]),
                            data["identity_verified"], data["verified_identity_digest"], data["created_at"],
                            data["started_at"], data["completed_at"], data["updated_at"],
                            ChildOutcome(data["terminal_outcome"]) if data["terminal_outcome"] else None, data["revision"])

    def child_session(self, delegation_id: str, session_id: str, agent_id: str, command_id: str,
                      *, provider_session_id: str | None = None) -> AgentSession:
        runtime_id(delegation_id, "delegation_id")
        runtime_id(session_id, "session_id")
        runtime_id(agent_id, "agent_id")
        if provider_session_id is not None:
            text(provider_session_id, "provider session id", 4096)
        request = canonical_json({"operation": "child_session_create", "delegation_id": delegation_id,
                                  "session_id": session_id, "agent_id": agent_id,
                                  "provider_session_id": provider_session_id})
        with self._connection(write=True) as connection:
            previous = self._runtime_command(connection, command_id, request)
            if previous is not None:
                return self._session_from_json(previous)
            delegation_row = connection.execute("SELECT * FROM delegations WHERE delegation_id=?", (delegation_id,)).fetchone()
            if delegation_row is None:
                raise NotFoundError(f"delegation {delegation_id} does not exist")
            delegation = self._delegation(delegation_row)
            if delegation.status is not DelegationStatus.AUTHORIZED:
                raise ConflictError("only an authorized delegation can create a child session")
            identity = connection.execute("SELECT * FROM agent_identities WHERE agent_id=?", (agent_id,)).fetchone()
            if identity is None:
                raise NotFoundError(f"agent {agent_id} does not exist")
            if (identity["task_id"], identity["role"], identity["provider"], identity["adapter_id"], identity["parent_agent_id"]) != (
                    delegation.child_task_id, delegation.child_role.value, delegation.child_provider.value,
                    delegation.child_adapter_id, delegation.parent_agent_id):
                raise ConflictError("child agent does not match the authorized delegation")
            self._session_insert(connection, session_id, agent_id, delegation_id, delegation.child_provider,
                                 delegation.child_adapter_id, provider_session_id, command_id)
            now = utc_now()
            connection.execute("UPDATE delegations SET status=?,updated_at=?,revision=revision+1 WHERE delegation_id=? AND revision=?",
                               (DelegationStatus.STARTED.value, now, delegation_id, delegation.revision))
            updated = replace(delegation, status=DelegationStatus.STARTED, updated_at=now, revision=delegation.revision + 1)
            self._runtime_event(connection, "delegation", delegation_id, updated.revision, "DELEGATION_STARTED", f"{command_id}:delegation", updated.to_dict())
            row = connection.execute("SELECT * FROM agent_sessions WHERE session_id=?", (session_id,)).fetchone()
            item = self._session(row)
            self._runtime_save_command(connection, command_id, "child_session_create", request, item.to_dict())
            return item

    def verify_session_identity(self, session_id: str, identity_observation: dict[str, Any], command_id: str) -> AgentSession:
        runtime_id(session_id, "session_id")
        if not isinstance(identity_observation, dict):
            raise ValidationError("identity observation must be a JSON object")
        observation = canonical_json(identity_observation)
        observation_digest = digest_text(observation)
        request = canonical_json({"operation": "session_verify_identity", "session_id": session_id,
                                  "identity_observation": identity_observation})
        with self._connection(write=True) as connection:
            previous = self._runtime_command(connection, command_id, request)
            if previous is not None:
                return self._session_from_json(previous)
            row = connection.execute("SELECT * FROM agent_sessions WHERE session_id=?", (session_id,)).fetchone()
            if row is None:
                raise NotFoundError(f"session {session_id} does not exist")
            current = self._session(row)
            if current.identity_verified:
                raise ConflictError("session identity is already verified")
            updated = replace(current, identity_verified=True, verified_identity_digest=observation_digest,
                              updated_at=utc_now(), revision=current.revision + 1)
            connection.execute("UPDATE agent_sessions SET identity_verified=1,verified_identity_digest=?,updated_at=?,revision=? WHERE session_id=? AND revision=?",
                               (observation_digest, updated.updated_at, updated.revision, session_id, current.revision))
            self._runtime_event(connection, "session", session_id, updated.revision, "SESSION_IDENTITY_VERIFIED",
                                command_id, {"session_id": session_id, "identity_digest": observation_digest})
            self._runtime_save_command(connection, command_id, "session_verify_identity", request, updated.to_dict())
            return updated

    def update_session_provider_session_id(self, session_id: str, provider_session_id: str, command_id: str) -> AgentSession:
        """Update the provider_session_id on an existing session (e.g. after successful CLI invocation)."""
        runtime_id(session_id, "session_id")
        if provider_session_id is not None:
            text(provider_session_id, "provider session id", 4096)
        request = canonical_json({"operation": "session_update_provider", "session_id": session_id,
                                  "provider_session_id": provider_session_id})
        with self._connection(write=True) as connection:
            previous = self._runtime_command(connection, command_id, request)
            if previous is not None:
                return self._session_from_json(previous)
            row = connection.execute("SELECT * FROM agent_sessions WHERE session_id=?", (session_id,)).fetchone()
            if row is None:
                raise NotFoundError(f"session {session_id} does not exist")
            current = self._session(row)
            if current.provider_session_id is not None and current.provider_session_id != provider_session_id:
                raise ConflictError(f"session already has provider_session_id {current.provider_session_id!r}")
            updated = replace(current, provider_session_id=provider_session_id, updated_at=utc_now(), revision=current.revision + 1)
            connection.execute("UPDATE agent_sessions SET provider_session_id=?,updated_at=?,revision=? WHERE session_id=? AND revision=?",
                               (provider_session_id, updated.updated_at, updated.revision, session_id, current.revision))
            self._runtime_event(connection, "session", session_id, updated.revision, "SESSION_PROVIDER_UPDATED",
                                command_id, {"session_id": session_id, "provider_session_id": provider_session_id})
            self._runtime_save_command(connection, command_id, "session_update_provider", request, updated.to_dict())
            return updated

    def agent_session(self, session_id: str) -> AgentSession:
        runtime_id(session_id, "session_id")
        with self._connection(write=False) as connection:
            row = connection.execute("SELECT * FROM agent_sessions WHERE session_id=?", (session_id,)).fetchone()
            if row is None:
                raise NotFoundError(f"session {session_id} does not exist")
            return self._session(row)

    def agent_sessions(self, task_id: str | None = None) -> tuple[AgentSession, ...]:
        if task_id is not None:
            validate_task_id(task_id)
        if not self._database_present():
            return ()
        with self._connection(write=False) as connection:
            query = "SELECT agent_sessions.* FROM agent_sessions JOIN agent_identities ON agent_identities.agent_id=agent_sessions.agent_id"
            params: tuple[Any, ...] = ()
            if task_id is not None:
                query += " WHERE agent_identities.task_id=?"
                params = (task_id,)
            rows = connection.execute(query + " ORDER BY agent_sessions.created_at, agent_sessions.session_id", params).fetchall()
            return tuple(self._session(row) for row in rows)

    def delegations(self, task_id: str | None = None) -> tuple[Delegation, ...]:
        """List delegations, optionally filtered by parent or child task_id."""
        if task_id is not None:
            validate_task_id(task_id)
        if not self._database_present():
            return ()
        with self._connection(write=False) as connection:
            query = "SELECT * FROM delegations"
            params: tuple[Any, ...] = ()
            if task_id is not None:
                query += " WHERE parent_task_id=? OR child_task_id=?"
                params = (task_id, task_id)
            rows = connection.execute(query + " ORDER BY delegations.created_at, delegations.delegation_id", params).fetchall()
            return tuple(self._delegation(row) for row in rows)
