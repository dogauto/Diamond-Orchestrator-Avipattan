"""Durable conversations and controller-governed child completion."""

from __future__ import annotations

from dataclasses import replace
from typing import Any
from uuid import uuid4

from .agent_runtime import (
    AgentMessage, AgentSessionStatus, ChildOutcome, CompletionReceipt, Conversation,
    DelegationStatus, DeliveryStatus, MAX_MESSAGE_BYTES, MessageDelivery, payload_digest,
    runtime_id,
)
from .domain import Provider
from .errors import CommandConflictError, ConflictError, ExecutionGuardError, NotFoundError, ValidationError
from .validation import canonical_json, command_id as validate_command_id, parse_canonical_json, text, utc_now


class AgentMessagingStoreMixin:
    """EventStore operations for ordered, idempotent local conversations."""

    @staticmethod
    def _conversation_from_json(value: str) -> Conversation:
        data = parse_canonical_json(value)
        return Conversation(data["conversation_id"], data["delegation_id"], data["parent_task_id"],
                            data["parent_attempt_id"], data["parent_agent_id"], data["child_agent_id"], data["created_at"])

    def create_conversation(self, conversation_id: str, delegation_id: str, parent_session_id: str,
                            child_session_id: str, command_id: str) -> Conversation:
        runtime_id(conversation_id, "conversation_id")
        runtime_id(delegation_id, "delegation_id")
        runtime_id(parent_session_id, "parent_session_id")
        runtime_id(child_session_id, "child_session_id")
        request = canonical_json({"operation": "conversation_create", "conversation_id": conversation_id,
                                  "delegation_id": delegation_id, "parent_session_id": parent_session_id,
                                  "child_session_id": child_session_id})
        with self._connection(write=True) as connection:
            previous = self._runtime_command(connection, command_id, request)
            if previous is not None:
                return self._conversation_from_json(previous)
            delegation_row = connection.execute("SELECT * FROM delegations WHERE delegation_id=?", (delegation_id,)).fetchone()
            if delegation_row is None:
                raise NotFoundError(f"delegation {delegation_id} does not exist")
            delegation = self._delegation(delegation_row)
            parent = connection.execute("SELECT * FROM agent_sessions WHERE session_id=?", (parent_session_id,)).fetchone()
            child = connection.execute("SELECT * FROM agent_sessions WHERE session_id=?", (child_session_id,)).fetchone()
            if parent is None or child is None:
                raise NotFoundError("conversation participant session does not exist")
            parent_identity = connection.execute("SELECT * FROM agent_identities WHERE agent_id=?", (parent["agent_id"],)).fetchone()
            child_identity = connection.execute("SELECT * FROM agent_identities WHERE agent_id=?", (child["agent_id"],)).fetchone()
            if parent_identity is None or child_identity is None:
                raise NotFoundError("conversation participant identity does not exist")
            if parent["agent_id"] != delegation.parent_agent_id or child["agent_id"] == delegation.parent_agent_id:
                raise ConflictError("conversation sessions are not the authorized parent and child")
            if child["delegation_id"] != delegation_id:
                raise ConflictError("child session is not bound to the delegation")
            if connection.execute("SELECT 1 FROM conversations WHERE delegation_id=?", (delegation_id,)).fetchone():
                raise ConflictError("delegation already has a conversation")
            item = Conversation(conversation_id, delegation_id, delegation.parent_task_id, delegation.parent_attempt_id,
                                delegation.parent_agent_id, child["agent_id"], utc_now())
            connection.execute("INSERT INTO conversations VALUES (?,?,?,?,?,?,?,?)",
                               (item.conversation_id, 1, item.delegation_id, item.parent_task_id, item.parent_attempt_id,
                                item.parent_agent_id, item.child_agent_id, item.created_at))
            connection.execute("INSERT INTO conversation_participants VALUES (?,?,?)",
                               (conversation_id, item.parent_agent_id, "PARENT"))
            connection.execute("INSERT INTO conversation_participants VALUES (?,?,?)",
                               (conversation_id, item.child_agent_id, "CHILD"))
            self._runtime_event(connection, "conversation", conversation_id, 1, "CONVERSATION_CREATED", command_id, item.to_dict())
            self._runtime_save_command(connection, command_id, "conversation_create", request, item.to_dict())
            return item

    def conversation(self, conversation_id: str) -> Conversation:
        runtime_id(conversation_id, "conversation_id")
        with self._connection(write=False) as connection:
            row = connection.execute("SELECT * FROM conversations WHERE conversation_id=?", (conversation_id,)).fetchone()
            if row is None:
                raise NotFoundError(f"conversation {conversation_id} does not exist")
            return self._conversation(row)

    def conversations(self, delegation_id: str) -> tuple[Conversation, ...]:
        """List conversations for a delegation."""
        runtime_id(delegation_id, "delegation_id")
        if not self._database_present():
            return ()
        with self._connection(write=False) as connection:
            rows = connection.execute(
                "SELECT * FROM conversations WHERE delegation_id=? ORDER BY created_at, conversation_id",
                (delegation_id,)).fetchall()
            return tuple(self._conversation(row) for row in rows)

    def send_agent_message(self, conversation_id: str, sender_session_id: str, recipient_session_id: str,
                           payload: dict[str, Any], correlation_id: str, idempotency_key: str,
                           command_id: str) -> AgentMessage:
        runtime_id(conversation_id, "conversation_id")
        runtime_id(sender_session_id, "sender_session_id")
        runtime_id(recipient_session_id, "recipient_session_id")
        if not isinstance(payload, dict):
            raise ValidationError("message payload must be a JSON object")
        text(correlation_id, "correlation_id", 128)
        text(idempotency_key, "idempotency_key", 256)
        payload_json = canonical_json(payload)
        if len(payload_json.encode("utf-8")) > MAX_MESSAGE_BYTES:
            raise ValidationError("message payload exceeds 65536 bytes")
        request = canonical_json({"operation": "message_send", "conversation_id": conversation_id,
                                  "sender_session_id": sender_session_id, "recipient_session_id": recipient_session_id,
                                  "payload": payload, "correlation_id": correlation_id, "idempotency_key": idempotency_key})
        scoped_command_id = f"{conversation_id}:{command_id}"
        with self._connection(write=True) as connection:
            previous = self._runtime_command(connection, scoped_command_id, request)
            if previous is not None:
                return self._message_from_json(previous)
            existing = connection.execute("SELECT * FROM agent_messages WHERE idempotency_key=?", (idempotency_key,)).fetchone()
            if existing is not None:
                item = self._message(existing)
                if (item.conversation_id, item.sender_session_id, item.recipient_session_id, item.correlation_id, item.payload_json) != (
                        conversation_id, sender_session_id, recipient_session_id, correlation_id, payload_json):
                    raise CommandConflictError("idempotency key already identifies a different message")
                self._runtime_save_command(connection, scoped_command_id, "message_send", request, item.to_dict())
                return item
            conversation = connection.execute("SELECT * FROM conversations WHERE conversation_id=?", (conversation_id,)).fetchone()
            sender = connection.execute("SELECT * FROM agent_sessions WHERE session_id=?", (sender_session_id,)).fetchone()
            recipient = connection.execute("SELECT * FROM agent_sessions WHERE session_id=?", (recipient_session_id,)).fetchone()
            if conversation is None or sender is None or recipient is None:
                raise NotFoundError("message conversation or session does not exist")
            if sender["status"] != AgentSessionStatus.ACTIVE.value or recipient["status"] != AgentSessionStatus.ACTIVE.value:
                raise ConflictError("messages require active sender and recipient sessions")
            participant_ids = {row[0] for row in connection.execute("SELECT agent_id FROM conversation_participants WHERE conversation_id=?", (conversation_id,))}
            if sender["agent_id"] not in participant_ids or recipient["agent_id"] not in participant_ids or sender["agent_id"] == recipient["agent_id"]:
                raise ConflictError("message sender and recipient are not conversation participants")
            sequence = connection.execute("SELECT COALESCE(MAX(sequence_no),0)+1 FROM agent_messages WHERE conversation_id=?", (conversation_id,)).fetchone()[0]
            item = AgentMessage(uuid4().hex, conversation_id, sequence, sender_session_id, recipient_session_id,
                                correlation_id, idempotency_key, payload_json, payload_digest(payload_json), utc_now())
            delivery = MessageDelivery(item.message_id, DeliveryStatus.QUEUED, 1, item.created_at, None)
            connection.execute("INSERT INTO agent_messages VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                               (item.message_id, 1, item.conversation_id, item.sequence_no, item.sender_session_id,
                                item.recipient_session_id, item.correlation_id, item.idempotency_key, item.payload_json,
                                item.payload_digest, item.created_at))
            connection.execute("INSERT INTO message_deliveries VALUES (?,?,?,?,?)",
                               (delivery.message_id, delivery.status.value, delivery.revision, delivery.updated_at, None))
            self._delivery_event(connection, item.message_id, delivery,
                                 f"{command_id}:{item.message_id}:1", "MESSAGE_QUEUED")
            self._runtime_save_command(connection, scoped_command_id, "message_send", request, item.to_dict())
            return item

    @staticmethod
    def _message_from_json(value: str) -> AgentMessage:
        data = parse_canonical_json(value)
        return AgentMessage(data["message_id"], data["conversation_id"], data["sequence_no"], data["sender_session_id"],
                            data["recipient_session_id"], data["correlation_id"], data["idempotency_key"],
                            canonical_json(data["payload"]), data["payload_digest"], data["created_at"])

    @staticmethod
    def _delivery_event(connection, message_id: str, delivery: MessageDelivery, command_id: str, event_type: str) -> None:
        payload = canonical_json({"message_id": message_id, "status": delivery.status.value,
                                  "revision": delivery.revision, "failure_reason": delivery.failure_reason})
        connection.execute("INSERT INTO message_delivery_events VALUES (?,?,?,?,?,?,?)",
                           (uuid4().hex, message_id, delivery.revision, delivery.status.value, delivery.updated_at,
                            command_id, payload))

    def _transition_message(self, message_id: str, target: DeliveryStatus, command_id: str,
                            *, failure_reason: str | None = None) -> MessageDelivery:
        runtime_id(message_id, "message_id")
        if not isinstance(target, DeliveryStatus):
            raise ValidationError("delivery target must be a DeliveryStatus")
        if failure_reason is not None:
            text(failure_reason, "delivery failure reason", 4096)
        request = canonical_json({"operation": "message_transition", "message_id": message_id,
                                  "target": target.value, "failure_reason": failure_reason})
        with self._connection(write=True) as connection:
            previous = self._runtime_command(connection, command_id, request)
            if previous is not None:
                return self._delivery_from_json(previous)
            row = connection.execute("SELECT * FROM message_deliveries WHERE message_id=?", (message_id,)).fetchone()
            if row is None:
                raise NotFoundError(f"message {message_id} does not exist")
            current = self._delivery(row)
            allowed = {(DeliveryStatus.QUEUED, DeliveryStatus.DELIVERED),
                       (DeliveryStatus.DELIVERED, DeliveryStatus.ACKNOWLEDGED),
                       (DeliveryStatus.QUEUED, DeliveryStatus.FAILED),
                       (DeliveryStatus.DELIVERED, DeliveryStatus.FAILED),
                       (DeliveryStatus.QUEUED, DeliveryStatus.CANCELLED)}
            if current.status is target:
                updated = current
            elif (current.status, target) not in allowed:
                raise ConflictError(f"cannot transition delivery {current.status.value} to {target.value}")
            else:
                updated = replace(current, status=target, revision=current.revision + 1, updated_at=utc_now(), failure_reason=failure_reason)
                connection.execute("UPDATE message_deliveries SET status=?,revision=?,updated_at=?,failure_reason=? WHERE message_id=? AND revision=?",
                                   (updated.status.value, updated.revision, updated.updated_at, updated.failure_reason, message_id, current.revision))
                self._delivery_event(connection, message_id, updated,
                                     f"{command_id}:{message_id}:{updated.revision}",
                                     f"MESSAGE_{target.value}")
            self._runtime_save_command(connection, command_id, "message_transition", request, updated.to_dict())
            return updated

    @staticmethod
    def _delivery_from_json(value: str) -> MessageDelivery:
        data = parse_canonical_json(value)
        return MessageDelivery(data["message_id"], DeliveryStatus(data["status"]), data["revision"],
                               data["updated_at"], data["failure_reason"])

    def mark_message_delivered(self, message_id: str, command_id: str) -> MessageDelivery:
        return self._transition_message(message_id, DeliveryStatus.DELIVERED, command_id)

    def acknowledge_message(self, message_id: str, command_id: str) -> MessageDelivery:
        return self._transition_message(message_id, DeliveryStatus.ACKNOWLEDGED, command_id)

    def fail_message(self, message_id: str, reason: str, command_id: str) -> MessageDelivery:
        return self._transition_message(message_id, DeliveryStatus.FAILED, command_id, failure_reason=reason)

    def cancel_message(self, message_id: str, command_id: str) -> MessageDelivery:
        return self._transition_message(message_id, DeliveryStatus.CANCELLED, command_id)

    def message_delivery(self, message_id: str) -> MessageDelivery:
        runtime_id(message_id, "message_id")
        with self._connection(write=False) as connection:
            row = connection.execute("SELECT * FROM message_deliveries WHERE message_id=?", (message_id,)).fetchone()
            if row is None:
                raise NotFoundError(f"message {message_id} does not exist")
            return self._delivery(row)

    def conversation_messages(self, conversation_id: str) -> tuple[tuple[AgentMessage, MessageDelivery], ...]:
        runtime_id(conversation_id, "conversation_id")
        with self._connection(write=False) as connection:
            if connection.execute("SELECT 1 FROM conversations WHERE conversation_id=?", (conversation_id,)).fetchone() is None:
                raise NotFoundError(f"conversation {conversation_id} does not exist")
            rows = connection.execute("""SELECT agent_messages.*, message_deliveries.status AS delivery_status,
                    message_deliveries.revision AS delivery_revision, message_deliveries.updated_at AS delivery_updated_at,
                    message_deliveries.failure_reason AS delivery_failure_reason
                    FROM agent_messages JOIN message_deliveries ON message_deliveries.message_id=agent_messages.message_id
                    WHERE agent_messages.conversation_id=? ORDER BY agent_messages.sequence_no""", (conversation_id,)).fetchall()
            return tuple((self._message(row), MessageDelivery(
                row["message_id"],
                DeliveryStatus.ACKNOWLEDGED if row["delivery_status"] == DeliveryStatus.QUEUED.value
                else DeliveryStatus(row["delivery_status"]),
                row["delivery_revision"], row["delivery_updated_at"], row["delivery_failure_reason"]))
                         for row in rows)

    def complete_child(self, delegation_id: str, child_session_id: str, outcome: ChildOutcome,
                       evidence_digest: str, command_id: str) -> CompletionReceipt:
        runtime_id(delegation_id, "delegation_id")
        runtime_id(child_session_id, "child_session_id")
        if not isinstance(outcome, ChildOutcome):
            raise ValidationError("child outcome must be a ChildOutcome")
        from .agent_runtime import digest as validate_digest
        validate_digest(evidence_digest, "completion evidence digest")
        request = canonical_json({"operation": "child_complete", "delegation_id": delegation_id,
                                  "child_session_id": child_session_id, "outcome": outcome.value,
                                  "evidence_digest": evidence_digest})
        with self._connection(write=True) as connection:
            previous = self._runtime_command(connection, command_id, request)
            if previous is not None:
                return self._receipt_from_json(previous)
            delegation_row = connection.execute("SELECT * FROM delegations WHERE delegation_id=?", (delegation_id,)).fetchone()
            session_row = connection.execute("SELECT * FROM agent_sessions WHERE session_id=?", (child_session_id,)).fetchone()
            if delegation_row is None or session_row is None:
                raise NotFoundError("delegation or child session does not exist")
            delegation = self._delegation(delegation_row)
            session = self._session(session_row)
            if session.delegation_id != delegation_id or session.status is not AgentSessionStatus.ACTIVE:
                raise ConflictError("child session is not active for this delegation")
            if not session.identity_verified:
                raise ExecutionGuardError("child completion requires independently verified session identity")
            if delegation.child_attempt_id is None:
                raise ExecutionGuardError("child completion requires an authorized child attempt")
            evidence_row = connection.execute("SELECT * FROM attempt_evidence WHERE attempt_id=? AND digest_sha256=?",
                                               (delegation.child_attempt_id, evidence_digest)).fetchone()
            if evidence_row is None:
                raise ExecutionGuardError("child completion evidence is not present in the authoritative ledger")
            evidence_record = self._decode_evidence(evidence_row)
            evidence_payload = evidence_record.to_dict()["payload"]
            if evidence_record.kind != "child_completion" or evidence_payload.get("session_id") != child_session_id:
                raise ExecutionGuardError("child completion evidence is not bound to the child session")
            if evidence_payload.get("outcome") != outcome.value or evidence_payload.get("identity_verified") is not True:
                raise ExecutionGuardError("child completion evidence does not prove the requested verified outcome")
            conversation = connection.execute("SELECT * FROM conversations WHERE delegation_id=?", (delegation_id,)).fetchone()
            if conversation is None:
                raise ExecutionGuardError("child completion requires a durable conversation")
            open_delivery = connection.execute("""SELECT 1 FROM message_deliveries
                JOIN agent_messages ON agent_messages.message_id=message_deliveries.message_id
                WHERE agent_messages.conversation_id=? AND message_deliveries.status != 'ACKNOWLEDGED'""", (conversation["conversation_id"],)).fetchone()
            accepted = outcome is ChildOutcome.SUCCEEDED and open_delivery is None
            session_status = {ChildOutcome.SUCCEEDED: AgentSessionStatus.SUCCEEDED,
                              ChildOutcome.FAILED: AgentSessionStatus.FAILED,
                              ChildOutcome.CANCELLED: AgentSessionStatus.CANCELLED,
                              ChildOutcome.UNCERTAIN: AgentSessionStatus.UNCERTAIN}[outcome]
            delegation_status = DelegationStatus.ACCEPTED if accepted else {
                ChildOutcome.SUCCEEDED: DelegationStatus.REJECTED,
                ChildOutcome.FAILED: DelegationStatus.REJECTED,
                ChildOutcome.CANCELLED: DelegationStatus.CANCELLED,
                ChildOutcome.UNCERTAIN: DelegationStatus.UNCERTAIN,
            }[outcome]
            now = utc_now()
            receipt = CompletionReceipt(uuid4().hex, delegation_id, child_session_id, session.agent_id,
                                       delegation.child_task_id, delegation.child_attempt_id, outcome,
                                       session.provider_session_id, session.identity_verified, evidence_digest, accepted, now)
            connection.execute("INSERT INTO completion_receipts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                               (receipt.receipt_id, 1, receipt.delegation_id, receipt.child_session_id, receipt.child_agent_id,
                                receipt.child_task_id, receipt.child_attempt_id, receipt.outcome.value, receipt.provider_session_id,
                                1, receipt.evidence_digest, int(receipt.accepted), receipt.created_at))
            updated_session = replace(session, status=session_status, completed_at=now, updated_at=now,
                                      terminal_outcome=outcome, revision=session.revision + 1)
            connection.execute("UPDATE agent_sessions SET status=?,completed_at=?,updated_at=?,terminal_outcome=?,revision=? WHERE session_id=? AND revision=?",
                               (updated_session.status.value, now, now, outcome.value, updated_session.revision, session.session_id, session.revision))
            updated_delegation = replace(delegation, status=delegation_status, updated_at=now, revision=delegation.revision + 1)
            connection.execute("UPDATE delegations SET status=?,updated_at=?,revision=? WHERE delegation_id=? AND revision=?",
                               (updated_delegation.status.value, now, updated_delegation.revision, delegation_id, delegation.revision))
            self._runtime_event(connection, "receipt", receipt.receipt_id, 1, "CHILD_COMPLETED", f"{command_id}:receipt", receipt.to_dict())
            self._runtime_event(connection, "session", session.session_id, updated_session.revision, "SESSION_COMPLETED", f"{command_id}:session", updated_session.to_dict())
            self._runtime_event(connection, "delegation", delegation_id, updated_delegation.revision, "DELEGATION_COMPLETED", f"{command_id}:delegation", updated_delegation.to_dict())
            self._runtime_save_command(connection, command_id, "child_complete", request, receipt.to_dict())
            return receipt

    @staticmethod
    def _receipt_from_json(value: str) -> CompletionReceipt:
        data = parse_canonical_json(value)
        from .agent_runtime import ChildOutcome
        return CompletionReceipt(data["receipt_id"], data["delegation_id"], data["child_session_id"], data["child_agent_id"],
                                data["child_task_id"], data["child_attempt_id"], ChildOutcome(data["outcome"]),
                                data["provider_session_id"], data["identity_verified"], data["evidence_digest"],
                                data["accepted"], data["created_at"])

    def completion_receipt(self, delegation_id: str) -> CompletionReceipt:
        runtime_id(delegation_id, "delegation_id")
        with self._connection(write=False) as connection:
            row = connection.execute("SELECT * FROM completion_receipts WHERE delegation_id=?", (delegation_id,)).fetchone()
            if row is None:
                raise NotFoundError(f"delegation {delegation_id} has no completion receipt")
            return self._receipt(row)

    def accept_child(self, delegation_id: str) -> CompletionReceipt:
        receipt = self.completion_receipt(delegation_id)
        if not receipt.accepted:
            raise ExecutionGuardError("child completion receipt did not satisfy controller acceptance rules")
        return receipt
