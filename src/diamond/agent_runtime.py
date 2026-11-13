"""Controller-owned agent identity, delegation, messaging, and receipt contracts.

These value objects describe the durable runtime spine.  They do not launch
providers or grant capabilities; the controller remains the only authority
that can create sessions, change delivery state, or accept a child result.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .domain import Provider, Role
from .errors import ValidationError
from .validation import bounded_int, canonical_json, exact_keys, task_id, text, utc_timestamp


_ID = re.compile(r"[0-9a-f]{32}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
MAX_MESSAGE_BYTES = 65_536


def runtime_id(value: object, name: str = "runtime ID") -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ValidationError(f"{name} must be 32 lowercase hexadecimal characters")
    return value


def optional_runtime_id(value: object, name: str) -> str | None:
    if value is None:
        return None
    return runtime_id(value, name)


def digest(value: object, name: str = "digest") -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValidationError(f"{name} must be a lowercase SHA-256 digest")
    return value


def payload_digest(payload_json: str) -> str:
    return hashlib.sha256(payload_json.encode("utf-8")).hexdigest()


class AgentSessionStatus(str, Enum):
    CREATED = "CREATED"
    ACTIVE = "ACTIVE"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    UNCERTAIN = "UNCERTAIN"


class DelegationStatus(str, Enum):
    AUTHORIZED = "AUTHORIZED"
    STARTED = "STARTED"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    UNCERTAIN = "UNCERTAIN"


class DeliveryStatus(str, Enum):
    QUEUED = "QUEUED"
    DELIVERED = "DELIVERED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ChildOutcome(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    UNCERTAIN = "UNCERTAIN"


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    agent_name: str
    role: Role
    provider: Provider
    adapter_id: str
    task_id: str
    attempt_id: str | None
    workflow_id: str | None
    parent_agent_id: str | None
    created_at: str

    def __post_init__(self) -> None:
        runtime_id(self.agent_id, "agent_id")
        text(self.agent_name, "agent_name", 256)
        if not isinstance(self.role, Role) or not isinstance(self.provider, Provider):
            raise ValidationError("agent role and provider must be enum values")
        text(self.adapter_id, "agent adapter_id", 256)
        task_id(self.task_id)
        optional_runtime_id(self.attempt_id, "agent attempt_id")
        optional_runtime_id(self.workflow_id, "agent workflow_id")
        optional_runtime_id(self.parent_agent_id, "agent parent_agent_id")
        utc_timestamp(self.created_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id, "agent_name": self.agent_name,
            "role": self.role.value, "provider": self.provider.value,
            "adapter_id": self.adapter_id, "task_id": self.task_id,
            "attempt_id": self.attempt_id, "workflow_id": self.workflow_id,
            "parent_agent_id": self.parent_agent_id, "created_at": self.created_at,
        }


@dataclass(frozen=True)
class AgentSession:
    session_id: str
    agent_id: str
    delegation_id: str | None
    provider: Provider
    adapter_id: str
    provider_session_id: str | None
    status: AgentSessionStatus
    identity_verified: bool
    verified_identity_digest: str | None
    created_at: str
    started_at: str | None
    completed_at: str | None
    updated_at: str
    terminal_outcome: ChildOutcome | None
    revision: int

    def __post_init__(self) -> None:
        runtime_id(self.session_id, "session_id")
        runtime_id(self.agent_id, "session agent_id")
        optional_runtime_id(self.delegation_id, "session delegation_id")
        if not isinstance(self.provider, Provider) or not isinstance(self.status, AgentSessionStatus):
            raise ValidationError("session provider and status must be enum values")
        text(self.adapter_id, "session adapter_id", 256)
        if self.provider_session_id is not None:
            text(self.provider_session_id, "provider session id", 4096)
        if type(self.identity_verified) is not bool:
            raise ValidationError("identity_verified must be boolean")
        if self.verified_identity_digest is not None:
            digest(self.verified_identity_digest, "verified identity digest")
        if self.identity_verified and self.verified_identity_digest is None:
            raise ValidationError("verified sessions require an identity digest")
        for value, name in ((self.created_at, "created_at"), (self.updated_at, "updated_at")):
            utc_timestamp(value)
        if self.started_at is not None:
            utc_timestamp(self.started_at)
        if self.completed_at is not None:
            utc_timestamp(self.completed_at)
        if self.terminal_outcome is not None and not isinstance(self.terminal_outcome, ChildOutcome):
            raise ValidationError("terminal_outcome must be a ChildOutcome")
        bounded_int(self.revision, "session revision", 1, 2**63 - 1)

    def to_dict(self) -> dict[str, Any]:
        return {"session_id": self.session_id, "agent_id": self.agent_id,
                "delegation_id": self.delegation_id, "provider": self.provider.value,
                "adapter_id": self.adapter_id, "provider_session_id": self.provider_session_id,
                "status": self.status.value, "identity_verified": self.identity_verified,
                "verified_identity_digest": self.verified_identity_digest,
                "created_at": self.created_at, "started_at": self.started_at,
                "completed_at": self.completed_at, "updated_at": self.updated_at,
                "terminal_outcome": self.terminal_outcome.value if self.terminal_outcome else None,
                "revision": self.revision}


@dataclass(frozen=True)
class Delegation:
    delegation_id: str
    parent_task_id: str
    parent_attempt_id: str
    parent_agent_id: str
    child_task_id: str
    child_attempt_id: str | None
    child_role: Role
    child_provider: Provider
    child_adapter_id: str
    workflow_id: str | None
    status: DelegationStatus
    created_at: str
    updated_at: str
    revision: int

    def __post_init__(self) -> None:
        runtime_id(self.delegation_id, "delegation_id")
        task_id(self.parent_task_id)
        runtime_id(self.parent_attempt_id, "parent_attempt_id")
        runtime_id(self.parent_agent_id, "parent_agent_id")
        task_id(self.child_task_id)
        optional_runtime_id(self.child_attempt_id, "delegation child_attempt_id")
        if self.parent_task_id == self.child_task_id:
            raise ValidationError("delegation cannot target its parent task")
        if not isinstance(self.child_role, Role) or not isinstance(self.child_provider, Provider):
            raise ValidationError("delegation role and provider must be enum values")
        text(self.child_adapter_id, "child adapter_id", 256)
        optional_runtime_id(self.workflow_id, "delegation workflow_id")
        if not isinstance(self.status, DelegationStatus):
            raise ValidationError("delegation status must be a DelegationStatus")
        utc_timestamp(self.created_at)
        utc_timestamp(self.updated_at)
        bounded_int(self.revision, "delegation revision", 1, 2**63 - 1)

    def to_dict(self) -> dict[str, Any]:
        return {"delegation_id": self.delegation_id, "parent_task_id": self.parent_task_id,
                "parent_attempt_id": self.parent_attempt_id, "parent_agent_id": self.parent_agent_id,
                "child_task_id": self.child_task_id, "child_role": self.child_role.value,
                "child_attempt_id": self.child_attempt_id,
                "child_provider": self.child_provider.value, "child_adapter_id": self.child_adapter_id,
                "workflow_id": self.workflow_id, "status": self.status.value,
                "created_at": self.created_at, "updated_at": self.updated_at,
                "revision": self.revision}


@dataclass(frozen=True)
class Conversation:
    conversation_id: str
    delegation_id: str
    parent_task_id: str
    parent_attempt_id: str
    parent_agent_id: str
    child_agent_id: str
    created_at: str

    def __post_init__(self) -> None:
        runtime_id(self.conversation_id, "conversation_id")
        runtime_id(self.delegation_id, "conversation delegation_id")
        task_id(self.parent_task_id)
        runtime_id(self.parent_attempt_id, "conversation parent_attempt_id")
        runtime_id(self.parent_agent_id, "conversation parent_agent_id")
        runtime_id(self.child_agent_id, "conversation child_agent_id")
        if self.parent_agent_id == self.child_agent_id:
            raise ValidationError("conversation requires distinct participants")
        utc_timestamp(self.created_at)

    def to_dict(self) -> dict[str, Any]:
        return {"conversation_id": self.conversation_id, "delegation_id": self.delegation_id,
                "parent_task_id": self.parent_task_id, "parent_attempt_id": self.parent_attempt_id,
                "parent_agent_id": self.parent_agent_id, "child_agent_id": self.child_agent_id,
                "created_at": self.created_at}


@dataclass(frozen=True)
class AgentMessage:
    message_id: str
    conversation_id: str
    sequence_no: int
    sender_session_id: str
    recipient_session_id: str
    correlation_id: str
    idempotency_key: str
    payload_json: str
    payload_digest: str
    created_at: str

    def __post_init__(self) -> None:
        runtime_id(self.message_id, "message_id")
        runtime_id(self.conversation_id, "message conversation_id")
        bounded_int(self.sequence_no, "message sequence", 1, 2**63 - 1)
        runtime_id(self.sender_session_id, "sender_session_id")
        runtime_id(self.recipient_session_id, "recipient_session_id")
        text(self.correlation_id, "correlation_id", 128)
        text(self.idempotency_key, "idempotency_key", 256)
        try:
            value = json.loads(self.payload_json)
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValidationError("message payload must be canonical JSON") from exc
        if not isinstance(value, dict):
            raise ValidationError("message payload must be a JSON object")
        if len(self.payload_json.encode("utf-8")) > MAX_MESSAGE_BYTES:
            raise ValidationError("message payload exceeds 65536 bytes")
        if canonical_json(value) != self.payload_json:
            raise ValidationError("message payload must be canonical JSON")
        if payload_digest(self.payload_json) != self.payload_digest:
            raise ValidationError("message payload digest does not match")
        utc_timestamp(self.created_at)

    def payload(self) -> dict[str, Any]:
        value = json.loads(self.payload_json)
        if not isinstance(value, dict):
            raise ValidationError("message payload must be a JSON object")
        return value

    def to_dict(self) -> dict[str, Any]:
        return {"message_id": self.message_id, "conversation_id": self.conversation_id,
                "sequence_no": self.sequence_no, "sender_session_id": self.sender_session_id,
                "recipient_session_id": self.recipient_session_id, "correlation_id": self.correlation_id,
                "idempotency_key": self.idempotency_key, "payload": json.loads(self.payload_json),
                "payload_digest": self.payload_digest, "created_at": self.created_at}


@dataclass(frozen=True)
class MessageDelivery:
    message_id: str
    status: DeliveryStatus
    revision: int
    updated_at: str
    failure_reason: str | None

    def __post_init__(self) -> None:
        runtime_id(self.message_id, "delivery message_id")
        if not isinstance(self.status, DeliveryStatus):
            raise ValidationError("delivery status must be a DeliveryStatus")
        bounded_int(self.revision, "delivery revision", 1, 2**63 - 1)
        utc_timestamp(self.updated_at)
        if self.failure_reason is not None:
            text(self.failure_reason, "delivery failure reason", 4096)
        if self.status is not DeliveryStatus.FAILED and self.failure_reason is not None:
            raise ValidationError("only failed deliveries carry a failure reason")

    def to_dict(self) -> dict[str, Any]:
        return {"message_id": self.message_id, "status": self.status.value,
                "revision": self.revision, "updated_at": self.updated_at,
                "failure_reason": self.failure_reason}


@dataclass(frozen=True)
class CompletionReceipt:
    receipt_id: str
    delegation_id: str
    child_session_id: str
    child_agent_id: str
    child_task_id: str
    child_attempt_id: str | None
    outcome: ChildOutcome
    provider_session_id: str | None
    identity_verified: bool
    evidence_digest: str
    accepted: bool
    created_at: str

    def __post_init__(self) -> None:
        runtime_id(self.receipt_id, "receipt_id")
        runtime_id(self.delegation_id, "receipt delegation_id")
        runtime_id(self.child_session_id, "receipt child_session_id")
        runtime_id(self.child_agent_id, "receipt child_agent_id")
        task_id(self.child_task_id)
        optional_runtime_id(self.child_attempt_id, "receipt child_attempt_id")
        if not isinstance(self.outcome, ChildOutcome):
            raise ValidationError("receipt outcome must be a ChildOutcome")
        if self.provider_session_id is not None:
            text(self.provider_session_id, "receipt provider session id", 4096)
        if type(self.identity_verified) is not bool or type(self.accepted) is not bool:
            raise ValidationError("receipt identity_verified and accepted must be boolean")
        digest(self.evidence_digest, "completion evidence digest")
        if self.accepted and not self.identity_verified:
            raise ValidationError("accepted child outcomes require verified session identity")
        utc_timestamp(self.created_at)

    def to_dict(self) -> dict[str, Any]:
        return {"receipt_id": self.receipt_id, "delegation_id": self.delegation_id,
                "child_session_id": self.child_session_id, "child_agent_id": self.child_agent_id,
                "child_task_id": self.child_task_id, "child_attempt_id": self.child_attempt_id,
                "outcome": self.outcome.value, "provider_session_id": self.provider_session_id,
                "identity_verified": self.identity_verified, "evidence_digest": self.evidence_digest,
                "accepted": self.accepted, "created_at": self.created_at}
