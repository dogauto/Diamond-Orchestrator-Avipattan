"""UI adapter for reading Diamond's authoritative application state.

This adapter provides a clean interface for the UI to consume Diamond state
without knowing implementation details of the controller, database, or scheduler.
It exposes only what the UI needs: tasks, workflows, deliveries, providers, and events.
All data is read-only and derived from the EventStore and controller APIs.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .config import DiamondConfig, load_config
from .delivery_store import DeliveryStore
from .domain import LedgerEvent, Provider, Role, TaskStatus
from .evidence import EvidenceRecord
from .errors import DiamondError, NotFoundError
from .paths import ProjectPaths, resolve_paths
from .store import EventStore
from .ui_streaming import EventCursor, EventStream, StreamEnvelope, StreamMessageType
from .workflow_store import WorkflowStore
from .runtime_ui import (
    UiAgent, UiDelegation, UiConversation, UiMessage, UiReceipt, UiSession,
    agent_to_ui, conversation_to_ui, message_to_ui, receipt_to_ui, session_to_ui, delegation_to_ui,
)


@dataclass(frozen=True)
class UiProvider:
    """Provider status as consumed by the UI."""
    name: str
    status: str  # configured, unavailable, disabled; no live probe is implied
    version: str | None
    auth_status: str  # NOT_CHECKED, AUTHORIZED, UNAUTHORIZED
    enabled: bool


@dataclass(frozen=True)
class UiTask:
    """Task snapshot for UI consumption."""
    task_id: str
    objective: str
    role: str
    provider: str
    status: str
    revision: int
    created_at: str
    updated_at: str
    blocking_reason: str | None
    correction_rounds_used: int
    execution_status: str | None
    current_attempt: str | None
    recovery_reason: str | None
    owned_paths: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()
    allowed_skills: tuple[str, ...] = ()


@dataclass(frozen=True)
class UiWorkflow:
    """Workflow snapshot for UI consumption."""
    workflow_id: str
    objective: str
    builder_provider: str
    debugger_provider: str
    status: str
    revision: int
    updated_at: str


@dataclass(frozen=True)
class UiDelivery:
    """Delivery snapshot for UI consumption."""
    delivery_id: str
    objective: str
    components: tuple[str, ...]
    status: str
    revision: int
    updated_at: str


@dataclass(frozen=True)
class UiEvent:
    """Event for UI streaming."""
    event_id: str
    task_id: str
    revision: int
    event_type: str
    timestamp: str
    actor: str
    command_id: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class UiEvidence:
    """Evidence record for UI consumption, distinct from ledger events."""
    evidence_id: str
    attempt_id: str
    kind: str
    created_at: str
    payload: dict[str, Any]
    digest_sha256: str
    schema_version: int


class UiAdapter:
    """Adapter for UI to read Diamond's authoritative state.

    This is a thin read-only wrapper around the existing EventStore,
    WorkflowStore, and controller APIs. It does not modify state,
    invoke providers, or bypass authorization.
    """

    def __init__(self, project_root: str | None = None, config_path: str | None = None, state_dir: str | None = None):
        self._project_root = project_root
        self._config_path = config_path
        self._state_dir = state_dir
        self._paths: ProjectPaths | None = None
        self._config: DiamondConfig | None = None
        self._store: EventStore | None = None
        self._workflow_store: WorkflowStore | None = None
        self._delivery_store: DeliveryStore | None = None

    def _initialize(self) -> None:
        """Initialize paths, config, and stores."""
        if self._paths is None:
            self._paths = resolve_paths(self._project_root, self._config_path, self._state_dir)
            self._config = load_config(self._paths.config)
            self._store = EventStore(self._paths.database)
            self._workflow_store = WorkflowStore(self._store)
            self._delivery_store = DeliveryStore(self._store)

    # --- READ INTERFACES ---

    def project_status(self) -> dict[str, Any]:
        """Return complete project status for UI dashboard."""
        self._initialize()
        assert self._config is not None
        assert self._store is not None
        assert self._workflow_store is not None
        assert self._delivery_store is not None

        workflows = self._workflow_store.list()
        deliveries = self._delivery_store.list()
        providers = [
            UiProvider(
                name=provider.value,
                status="configured" if provider_config.enabled else "disabled",
                version=None,
                auth_status="NOT_CHECKED",
                enabled=provider_config.enabled,
            )
            for provider, provider_config in self._config.providers.items()
            if provider_config.enabled
        ]

        return {
            "project": str(self._paths.project),
            "config": str(self._paths.config),
            "connection": {
                "status": "connected",
                "mode": "read-only",
                "message": "authoritative ledger readable",
            },
            "event_scope": "task",
            "providers": providers,
            "workflows": [self._workflow_to_ui(w) for w in workflows],
            "deliveries": [self._delivery_to_ui(d) for d in deliveries],
            "tasks": [self._task_to_ui(t) for t in self._store.list()],
            "agents": [agent_to_ui(item) for item in self._store.agent_identities()],
            "sessions": [session_to_ui(item) for item in self._store.agent_sessions()],
        }

    def agents(self, task_id: str | None = None) -> Sequence[UiAgent]:
        self._initialize()
        assert self._store is not None
        return [agent_to_ui(item) for item in self._store.agent_identities(task_id)]

    def sessions(self, task_id: str | None = None) -> Sequence[UiSession]:
        self._initialize()
        assert self._store is not None
        return [session_to_ui(item) for item in self._store.agent_sessions(task_id)]

    def conversation_messages(self, conversation_id: str) -> Sequence[UiMessage]:
        self._initialize()
        assert self._store is not None
        return [message_to_ui(message, delivery)
                for message, delivery in self._store.conversation_messages(conversation_id)]

    def completion_receipt(self, delegation_id: str) -> UiReceipt | None:
        self._initialize()
        assert self._store is not None
        try:
            return receipt_to_ui(self._store.completion_receipt(delegation_id))
        except NotFoundError:
            return None

    def sessions(self, task_id: str | None = None) -> Sequence[UiSession]:
        self._initialize()
        assert self._store is not None
        return [session_to_ui(item) for item in self._store.agent_sessions(task_id)]

    def delegations(self, task_id: str | None = None) -> Sequence[UiDelegation]:
        """List delegations, optionally filtered by parent or child task_id."""
        self._initialize()
        assert self._store is not None
        return [delegation_to_ui(item) for item in self._store.delegations(task_id)]

    def delegation(self, delegation_id: str) -> UiDelegation | None:
        self._initialize()
        assert self._store is not None
        try:
            return delegation_to_ui(self._store.delegation(delegation_id))
        except NotFoundError:
            return None

    def conversations(self, delegation_id: str) -> Sequence[UiConversation]:
        """List conversations for a delegation."""
        self._initialize()
        assert self._store is not None
        return [conversation_to_ui(item) for item in self._store.conversations(delegation_id)]

    def conversation(self, conversation_id: str) -> UiConversation | None:
        self._initialize()
        assert self._store is not None
        try:
            return conversation_to_ui(self._store.conversation(conversation_id))
        except NotFoundError:
            return None

    def message_delivery(self, message_id: str) -> str | None:
        """Return delivery status string for a message, or None if no delivery exists."""
        self._initialize()
        assert self._store is not None
        try:
            return self._store.message_delivery(message_id).status.value
        except NotFoundError:
            return None

    def all_messages(self) -> dict[str, Sequence[UiMessage]]:
        """Return messages keyed by conversation_id for all conversations in the runtime."""
        self._initialize()
        assert self._store is not None
        result: dict[str, Sequence[UiMessage]] = {}
        with self._store._connection(write=False) as connection:
            rows = connection.execute("SELECT DISTINCT conversation_id FROM agent_messages").fetchall()
            for row in rows:
                conv_id = row["conversation_id"]
                result[conv_id] = self.conversation_messages(conv_id)
        return result

    def task_status(self, task_id: str) -> UiTask | None:
        """Get a single task by ID."""
        self._initialize()
        assert self._store is not None

        try:
            snapshot = self._store.get(task_id)
        except NotFoundError:
            return None

        return self._task_to_ui(snapshot)

    def workflow_status(self, workflow_id: str) -> UiWorkflow | None:
        """Get a single workflow by ID."""
        self._initialize()
        assert self._workflow_store is not None

        try:
            item = self._workflow_store.get(workflow_id)
        except NotFoundError:
            return None

        return self._workflow_to_ui(item)

    def delivery_status(self, delivery_id: str) -> UiDelivery | None:
        """Get a single delivery by ID."""
        self._initialize()
        assert self._store is not None

        from .delivery_store import DeliveryStore

        try:
            item = DeliveryStore(self._store).get(delivery_id)
        except NotFoundError:
            return None

        return self._delivery_to_ui(item)

    def task_events(self, task_id: str) -> Sequence[UiEvent]:
        """Get all events for a task."""
        self._initialize()
        assert self._store is not None

        try:
            events = self._store.events(task_id)
        except NotFoundError:
            return []

        return [self._event_to_ui(e) for e in events]

    def task_evidence(self, task_id: str) -> Sequence[UiEvidence]:
        """Get validated evidence records for a task."""
        self._initialize()
        assert self._store is not None

        try:
            evidence = self._store.evidence(task_id)
        except NotFoundError:
            return []

        return [self._evidence_to_ui(record) for record in evidence]

    def task_attempts(self, task_id: str) -> Sequence[dict[str, Any]]:
        """Get attempt history for a task."""
        self._initialize()
        assert self._store is not None

        try:
            attempts = self._store.attempts(task_id)
        except NotFoundError:
            return []

        return [self._attempt_to_dict(a) for a in attempts]

    # --- STREAMING INTERFACE ---

    def event_stream(self, buffer_size: int = 1_000, poll_interval: float = 1.0) -> EventStream:
        """Create a task-scoped stream without exposing the underlying store."""
        self._initialize()
        assert self._store is not None
        return EventStream(self._store, buffer_size=buffer_size, poll_interval=poll_interval)

    async def subscribe_to_events(
        self,
        task_id: str,
        since_revision: int = 0,
        *,
        buffer_size: int = 1_000,
        poll_interval: float = 1.0,
    ) -> AsyncIterator[StreamEnvelope[UiEvent]]:
        """Subscribe to one task and resynchronize after bounded overflow.

        The task snapshot is reloaded through the adapter after an overflow;
        the next stream starts from that snapshot revision. There is no
        project-wide subscription because task, workflow, and delivery
        histories do not share an event cursor in the current ledger model.
        """
        self._initialize()
        cursor = since_revision
        while True:
            stream = self.event_stream(buffer_size, poll_interval)
            should_resync = False
            try:
                async for message in stream.subscribe(task_id, cursor):
                    if message.kind is StreamMessageType.EVENT:
                        assert message.event is not None
                        yield StreamEnvelope(
                            kind=message.kind,
                            task_id=task_id,
                            event=self._event_to_ui(message.event),
                            cursor=message.cursor,
                            last_revision=message.last_revision,
                            current_revision=message.current_revision,
                            dropped_count=message.dropped_count,
                            error=message.error,
                        )
                        if message.cursor is not None:
                            cursor = message.cursor.revision
                    elif message.kind is StreamMessageType.OVERFLOW:
                        yield StreamEnvelope(
                            kind=message.kind,
                            task_id=task_id,
                            cursor=message.cursor,
                            last_revision=message.last_revision,
                            current_revision=message.current_revision,
                            dropped_count=message.dropped_count,
                        )
                        snapshot = self.task_status(task_id)
                        if snapshot is None:
                            yield StreamEnvelope(
                                kind=StreamMessageType.ERROR,
                                task_id=task_id,
                                cursor=message.cursor,
                                error=f"task {task_id} disappeared during resynchronization",
                            )
                            return
                        cursor = snapshot.revision
                        yield StreamEnvelope(
                            kind=StreamMessageType.RESYNC,
                            task_id=task_id,
                            cursor=EventCursor(task_id, snapshot.revision),
                            snapshot=snapshot,
                        )
                        should_resync = True
                        break
                    elif message.kind is StreamMessageType.ERROR:
                        yield StreamEnvelope(
                            kind=message.kind,
                            task_id=task_id,
                            cursor=message.cursor,
                            error=message.error,
                        )
                        return
                    else:
                        yield StreamEnvelope(
                            kind=message.kind,
                            task_id=task_id,
                            cursor=message.cursor,
                            error=message.error,
                        )
                        return
            finally:
                await stream.shutdown()
            if not should_resync:
                return

    # --- CONVERSION HELPERS ---

    def _provider_to_ui(self, probe: Any) -> UiProvider:
        """Convert diagnostics probe to UI provider."""
        return UiProvider(
            name=probe.provider.value,
            status=probe.status,
            version=probe.version,
            auth_status=probe.auth_status,
            enabled=self._config.providers.get(Provider(probe.provider), None) is not None if self._config else False,
        )

    def _task_to_ui(self, snapshot: Any) -> UiTask:
        """Convert TaskSnapshot to UI task."""
        return UiTask(
            task_id=snapshot.spec.task_id,
            objective=snapshot.spec.objective,
            role=snapshot.spec.role.value,
            provider=snapshot.spec.provider.value if snapshot.spec.provider else "none",
            status=snapshot.status.value,
            revision=snapshot.revision,
            created_at=snapshot.created_at,
            updated_at=snapshot.updated_at,
            blocking_reason=snapshot.blocking_reason,
            correction_rounds_used=snapshot.correction_rounds_used,
            execution_status=snapshot.execution_status.value if snapshot.execution_status else None,
            current_attempt=snapshot.current_attempt,
            recovery_reason=snapshot.recovery_reason,
            owned_paths=snapshot.spec.owned_paths or (),
            allowed_tools=snapshot.spec.allowed_tools or (),
            allowed_skills=snapshot.spec.allowed_skills or (),
        )

    def _workflow_to_ui(self, item: Any) -> UiWorkflow:
        """Convert workflow item to UI workflow."""
        return UiWorkflow(
            workflow_id=item.spec.workflow_id,
            objective=item.spec.objective,
            builder_provider=item.spec.builder_provider.value,
            debugger_provider=item.spec.debugger_provider.value,
            status=item.status.value,
            revision=item.revision,
            updated_at=item.updated_at,
        )

    def _delivery_to_ui(self, item: Any) -> UiDelivery:
        """Convert delivery item to UI delivery."""
        from .validation import parse_canonical_json
        components = tuple(
            component["workflow_id"] for component in parse_canonical_json(item.spec.components_json)
        )
        return UiDelivery(
            delivery_id=item.spec.delivery_id,
            objective=item.spec.objective,
            components=components,
            status=item.status.value,
            revision=item.revision,
            updated_at=item.updated_at,
        )

    def _event_to_ui(self, event: LedgerEvent) -> UiEvent:
        """Convert LedgerEvent to UI event."""
        return UiEvent(
            event_id=event.event_id,
            task_id=event.task_id,
            revision=event.revision,
            event_type=event.event_type,
            timestamp=event.timestamp,
            actor=event.actor,
            command_id=event.command_id,
            payload=event.to_dict()["payload"],
        )

    @staticmethod
    def _evidence_to_ui(record: EvidenceRecord) -> UiEvidence:
        """Convert EvidenceRecord without treating it as a ledger event."""
        value = record.to_dict()
        return UiEvidence(
            evidence_id=value["evidence_id"],
            attempt_id=value["attempt_id"],
            kind=value["kind"],
            created_at=value["created_at"],
            payload=value["payload"],
            digest_sha256=value["digest_sha256"],
            schema_version=value["schema_version"],
        )

    def _attempt_to_dict(self, attempt: Any) -> dict[str, Any]:
        """Convert ExecutionAttempt to dict."""
        return {
            "attempt_id": attempt.attempt_id,
            "revision": attempt.revision,
            "task_id": attempt.task_id,
            "task_revision": attempt.task_revision,
            "role": attempt.role.value,
            "provider": attempt.provider.value if attempt.provider else None,
            "adapter_id": attempt.adapter_id,
            "accepted_packet_id": attempt.accepted_packet_id,
            "provider_binding_digest": attempt.provider_binding_digest,
            "status": attempt.status.value,
            "created_at": attempt.created_at,
            "updated_at": attempt.updated_at,
            "dispatch_claim_id": attempt.dispatch_claim_id,
        }

    # --- LIFECYCLE ---

    def close(self) -> None:
        """Close any open resources."""
        # EventStore manages its own connections
        pass


# Synchronous convenience functions for simple use cases
def get_project_status(project_root: str | None = None, config_path: str | None = None, state_dir: str | None = None) -> dict[str, Any]:
    """Get project status for a one-off call."""
    adapter = UiAdapter(project_root, config_path, state_dir)
    try:
        return adapter.project_status()
    finally:
        adapter.close()


def get_task_status(task_id: str, project_root: str | None = None, config_path: str | None = None, state_dir: str | None = None) -> UiTask | None:
    """Get task status for a one-off call."""
    adapter = UiAdapter(project_root, config_path, state_dir)
    try:
        return adapter.task_status(task_id)
    finally:
        adapter.close()
