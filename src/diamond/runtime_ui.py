"""Read-only UI projections for the controller-owned agent runtime."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .agent_runtime import AgentIdentity, AgentMessage, AgentSession, CompletionReceipt, Conversation, Delegation, MessageDelivery


@dataclass(frozen=True)
class UiAgent:
    agent_id: str
    agent_name: str
    role: str
    provider: str
    adapter_id: str
    task_id: str
    attempt_id: str | None
    workflow_id: str | None
    parent_agent_id: str | None
    created_at: str


@dataclass(frozen=True)
class UiSession:
    session_id: str
    agent_id: str
    delegation_id: str | None
    provider: str
    adapter_id: str
    provider_session_id: str | None
    status: str
    identity_verified: bool
    verified_identity_digest: str | None
    created_at: str
    started_at: str | None
    completed_at: str | None
    updated_at: str
    terminal_outcome: str | None
    revision: int


@dataclass(frozen=True)
class UiConversation:
    conversation_id: str
    delegation_id: str
    parent_task_id: str
    parent_attempt_id: str
    parent_agent_id: str
    child_agent_id: str
    created_at: str


@dataclass(frozen=True)
class UiDelegation:
    delegation_id: str
    parent_task_id: str
    parent_attempt_id: str
    parent_agent_id: str
    child_task_id: str
    child_attempt_id: str | None
    child_role: str
    child_provider: str
    child_adapter_id: str
    workflow_id: str | None
    status: str
    created_at: str
    updated_at: str
    revision: int


@dataclass(frozen=True)
class UiMessage:
    message_id: str
    conversation_id: str
    sequence_no: int
    sender_session_id: str
    recipient_session_id: str
    correlation_id: str
    payload: dict[str, Any]
    payload_digest: str
    created_at: str
    delivery_status: str
    delivery_revision: int
    delivery_updated_at: str
    delivery_failure_reason: str | None


@dataclass(frozen=True)
class UiReceipt:
    receipt_id: str
    delegation_id: str
    child_session_id: str
    child_agent_id: str
    child_task_id: str
    child_attempt_id: str | None
    outcome: str
    provider_session_id: str | None
    identity_verified: bool
    evidence_digest: str
    accepted: bool
    created_at: str


def agent_to_ui(item: AgentIdentity) -> UiAgent:
    return UiAgent(item.agent_id, item.agent_name, item.role.value, item.provider.value, item.adapter_id,
                   item.task_id, item.attempt_id, item.workflow_id, item.parent_agent_id, item.created_at)


def session_to_ui(item: AgentSession) -> UiSession:
    return UiSession(item.session_id, item.agent_id, item.delegation_id, item.provider.value, item.adapter_id,
                     item.provider_session_id, item.status.value, item.identity_verified,
                     item.verified_identity_digest, item.created_at, item.started_at, item.completed_at,
                     item.updated_at, item.terminal_outcome.value if item.terminal_outcome else None, item.revision)


def message_to_ui(item: AgentMessage, delivery: MessageDelivery) -> UiMessage:
    return UiMessage(item.message_id, item.conversation_id, item.sequence_no, item.sender_session_id,
                     item.recipient_session_id, item.correlation_id, item.payload(), item.payload_digest,
                     item.created_at, delivery.status.value, delivery.revision, delivery.updated_at,
                     delivery.failure_reason)


def receipt_to_ui(item: CompletionReceipt) -> UiReceipt:
    return UiReceipt(item.receipt_id, item.delegation_id, item.child_session_id, item.child_agent_id,
                     item.child_task_id, item.child_attempt_id, item.outcome.value, item.provider_session_id,
                     item.identity_verified, item.evidence_digest, item.accepted, item.created_at)


def conversation_to_ui(item: Conversation) -> UiConversation:
    return UiConversation(item.conversation_id, item.delegation_id, item.parent_task_id,
                          item.parent_attempt_id, item.parent_agent_id, item.child_agent_id, item.created_at)


def delegation_to_ui(item: Delegation) -> UiDelegation:
    return UiDelegation(item.delegation_id, item.parent_task_id, item.parent_attempt_id,
                        item.parent_agent_id, item.child_task_id, item.child_attempt_id,
                        item.child_role.value, item.child_provider.value, item.child_adapter_id,
                        item.workflow_id, item.status.value, item.created_at, item.updated_at, item.revision)
