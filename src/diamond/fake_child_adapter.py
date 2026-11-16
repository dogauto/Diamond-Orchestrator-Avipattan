"""Deterministic controller-owned child adapter used only by tests and UAT.

This adapter never launches a provider or reads provider credentials.  It
exercises the same EventStore runtime contract as a future real child adapter.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .agent_runtime import AgentMessage, ChildOutcome, CompletionReceipt
from .evidence import EvidenceRecord, digest_text
from .store import EventStore
from .validation import canonical_json, command_id, utc_now


@dataclass(frozen=True)
class FakeChildExecution:
    session_id: str
    conversation_id: str
    request: AgentMessage
    response: AgentMessage
    receipt: CompletionReceipt


class DeterministicChildAdapter:
    """Run one local, provider-free child conversation through the controller."""

    adapter_id = "test:deterministic-child"

    @staticmethod
    def _id(prefix: str, label: str) -> str:
        return hashlib.sha256(f"{prefix}:{label}".encode("utf-8")).hexdigest()[:32]

    def run(self, store: EventStore, delegation_id: str, parent_session_id: str,
            child_agent_id: str, command_prefix: str, request_payload: dict[str, object],
            *, response_payload: dict[str, object] | None = None,
            outcome: ChildOutcome = ChildOutcome.SUCCEEDED) -> FakeChildExecution:
        if not isinstance(store, EventStore):
            raise TypeError("fake child adapter requires EventStore")
        command_id(command_prefix)
        child_session_id = self._id(command_prefix, "session")
        conversation_id = self._id(command_prefix, "conversation")
        session = store.child_session(delegation_id, child_session_id, child_agent_id,
                                      f"{command_prefix}:session", provider_session_id=f"fake:{child_session_id}")
        store.verify_session_identity(child_session_id, {"adapter_id": self.adapter_id,
                                                         "session_id": child_session_id},
                                      f"{command_prefix}:identity")
        store.create_conversation(conversation_id, delegation_id, parent_session_id, child_session_id,
                                  f"{command_prefix}:conversation")
        request = store.send_agent_message(conversation_id, parent_session_id, child_session_id,
                                           request_payload, f"{command_prefix}:request-correlation",
                                           f"{command_prefix}:request-idempotency", f"{command_prefix}:request")
        store.mark_message_delivered(request.message_id, f"{command_prefix}:request-delivered")
        store.acknowledge_message(request.message_id, f"{command_prefix}:request-ack")
        response_payload = response_payload or {"type": "child_response", "correlation_id": request.correlation_id,
                                                "status": "ok"}
        response = store.send_agent_message(conversation_id, child_session_id, parent_session_id,
                                            response_payload, f"{command_prefix}:response-correlation",
                                            f"{command_prefix}:response-idempotency", f"{command_prefix}:response")
        store.mark_message_delivered(response.message_id, f"{command_prefix}:response-delivered")
        store.acknowledge_message(response.message_id, f"{command_prefix}:response-ack")
        delegation = store.delegation(delegation_id)
        evidence_payload = canonical_json({"adapter_id": self.adapter_id, "session_id": child_session_id,
                                           "outcome": outcome.value, "identity_verified": True,
                                           "response_digest": response.payload_digest})
        evidence_id = self._id(command_prefix, "evidence")
        evidence = EvidenceRecord(evidence_id, delegation.child_attempt_id, "child_completion", utc_now(),
                                  evidence_payload, digest_text(evidence_payload))
        store.record_evidence(evidence, f"{command_prefix}:evidence")
        receipt = store.complete_child(delegation_id, child_session_id, outcome, evidence.digest_sha256,
                                       f"{command_prefix}:complete")
        return FakeChildExecution(child_session_id, conversation_id, request, response, receipt)
