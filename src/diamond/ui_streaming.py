"""Read-only, task-scoped streaming over the authoritative event ledger.

The ledger has a revision cursor per task. This module intentionally does not
provide a project-wide ``subscribe("")`` convention: workflows and
deliveries are stored in separate event histories and no shared cursor exists
for them in the current event model.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from enum import Enum
from typing import AsyncIterator, Generic, TypeVar
from uuid import uuid4

from .store import EventStore, LedgerEvent
from .validation import bounded_int


class StreamMessageType(str, Enum):
    """Kinds carried by every stream message."""

    EVENT = "event"
    OVERFLOW = "overflow"
    ERROR = "error"
    RESYNC = "resync"
    CLOSED = "closed"


@dataclass(frozen=True)
class EventCursor:
    """Task-local cursor for a persisted event."""

    task_id: str
    revision: int
    event_id: str | None = None


T = TypeVar("T")


@dataclass(frozen=True)
class StreamEnvelope(Generic[T]):
    """Typed envelope for normal events and stream control state."""

    kind: StreamMessageType
    task_id: str
    event: T | None = None
    cursor: EventCursor | None = None
    last_revision: int | None = None
    current_revision: int | None = None
    dropped_count: int = 0
    error: str | None = None
    snapshot: object | None = None

    def __post_init__(self) -> None:
        if self.kind is StreamMessageType.EVENT and self.event is None:
            raise ValueError("event stream messages require an event")
        if self.kind is StreamMessageType.ERROR and not self.error:
            raise ValueError("error stream messages require an error")
        if self.dropped_count < 0:
            raise ValueError("dropped_count cannot be negative")


@dataclass
class _Subscription:
    stop_event: asyncio.Event
    queue: asyncio.Queue[StreamEnvelope[LedgerEvent]]
    producer: asyncio.Task[None]


class EventStream:
    """Bounded, resumable stream for one task's persisted events.

    ``subscribe`` reads through the public ``EventStore.events_since`` API.
    When the bounded queue cannot retain the next event it discards the
    queued batch, emits one explicit overflow envelope, and ends that
    subscription. The UI adapter owns the subsequent authoritative snapshot
    reload and starts a new subscription from that snapshot's revision.
    """

    def __init__(self, store: EventStore, buffer_size: int = 1_000, poll_interval: float = 1.0):
        if buffer_size < 1:
            raise ValueError("buffer_size must be positive")
        if poll_interval < 0:
            raise ValueError("poll_interval cannot be negative")
        self._store = store
        self._buffer_size = buffer_size
        self._poll_interval = poll_interval
        self._subscriptions: dict[str, _Subscription] = {}

    async def subscribe(
        self, task_id: str, since_revision: int = 0
    ) -> AsyncIterator[StreamEnvelope[LedgerEvent]]:
        """Yield a typed task event stream after ``since_revision``.

        Errors are delivered as ``ERROR`` envelopes so a consumer can render
        connection failures instead of silently losing them. ``OVERFLOW`` is
        terminal for this subscription; callers must reload a snapshot before
        resuming with a new cursor.
        """
        bounded_int(since_revision, "event cursor revision", 0, 2**63 - 1)
        subscription_id = uuid4().hex
        queue: asyncio.Queue[StreamEnvelope[LedgerEvent]] = asyncio.Queue(maxsize=self._buffer_size)
        stop_event = asyncio.Event()

        def put_terminal(message: StreamEnvelope[LedgerEvent]) -> None:
            while queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
            queue.put_nowait(message)

        async def produce() -> None:
            last_revision = since_revision
            try:
                while not stop_event.is_set():
                    events = self._store.events_since(task_id, last_revision)
                    for event in events:
                        if stop_event.is_set():
                            return
                        message = StreamEnvelope(
                            kind=StreamMessageType.EVENT,
                            task_id=task_id,
                            event=event,
                            cursor=EventCursor(task_id, event.revision, event.event_id),
                        )
                        try:
                            queue.put_nowait(message)
                        except asyncio.QueueFull:
                            put_terminal(StreamEnvelope(
                                kind=StreamMessageType.OVERFLOW,
                                task_id=task_id,
                                cursor=EventCursor(task_id, last_revision),
                                last_revision=last_revision,
                                current_revision=events[-1].revision,
                                dropped_count=queue.qsize() + 1,
                            ))
                            return
                        last_revision = event.revision
                    await asyncio.sleep(self._poll_interval)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                put_terminal(StreamEnvelope(
                    kind=StreamMessageType.ERROR,
                    task_id=task_id,
                    cursor=EventCursor(task_id, last_revision),
                    error=str(exc),
                ))

        producer = asyncio.create_task(produce())
        subscription = _Subscription(stop_event, queue, producer)
        self._subscriptions[subscription_id] = subscription
        try:
            while True:
                message = await queue.get()
                yield message
                if message.kind in {
                    StreamMessageType.OVERFLOW,
                    StreamMessageType.ERROR,
                    StreamMessageType.CLOSED,
                }:
                    return
        finally:
            stop_event.set()
            producer.cancel()
            await asyncio.gather(producer, return_exceptions=True)
            self._subscriptions.pop(subscription_id, None)

    async def shutdown(self) -> None:
        """Cancel all subscriptions and wake consumers with ``CLOSED``."""
        subscriptions = tuple(self._subscriptions.items())
        for subscription_id, subscription in subscriptions:
            subscription.stop_event.set()
            while subscription.queue.full():
                try:
                    subscription.queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
            try:
                subscription.queue.put_nowait(StreamEnvelope(
                    kind=StreamMessageType.CLOSED,
                    task_id="",
                ))
            except asyncio.QueueFull:
                pass
            subscription.producer.cancel()
            await asyncio.gather(subscription.producer, return_exceptions=True)
            self._subscriptions.pop(subscription_id, None)


async def poll_events(
    store: EventStore, task_id: str, since_revision: int = 0, poll_interval: float = 1.0
) -> AsyncIterator[LedgerEvent]:
    """Compatibility polling iterator yielding only persisted events."""
    bounded_int(since_revision, "event cursor revision", 0, 2**63 - 1)
    last_revision = since_revision
    while True:
        events = store.events_since(task_id, last_revision)
        for event in events:
            yield event
            last_revision = event.revision
        await asyncio.sleep(poll_interval)
