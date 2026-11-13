"""Policy Watchdog — D2-B: supervise critical IPC/Controller services.

The watchdog does NOT:
- Approve operations, override DENY, convert ASK to ALLOW.
- Change agent identity, rewrite task ownership.
- Bypass the Controller or redispatch uncertain tasks.

It DOES:
- Periodically verify PolicyIPCServer reachability.
- Verify Controller event-loop liveness.
- Detect stale/unresponsive services.
- Record supervision evidence in the EventStore.
- Coordinate bounded restart attempts with backoff.
- Preserve fail-closed: if IPC is unavailable, hooks continue to deny.
"""

from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Optional
from uuid import uuid4

from .errors import ValidationError
from .store import EventStore
from .validation import canonical_json, utc_now


class ServiceState(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNREACHABLE = "unreachable"
    RESTARTING = "restarting"
    STOPPED = "stopped"


class FailureKind(str, Enum):
    IPC_CONNECT_FAILED = "ipc_connect_failed"
    IPC_TIMEOUT = "ipc_timeout"
    IPC_MALFORMED = "ipc_malformed"
    EVENT_LOOP_DEAD = "event_loop_dead"
    CONTROLLER_DEAD = "controller_dead"
    STARTUP_FAILED = "startup_failed"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ServiceSnapshot:
    """Point-in-time health record for a supervised service."""
    timestamp: str
    service_name: str
    state: ServiceState
    detail: str
    failure_kind: Optional[FailureKind] = None
    attempt_revision: Optional[int] = None


@dataclass
class WatchdogConfig:
    """Configuration bounds for the watchdog."""
    check_interval_seconds: int = 30
    ipc_connect_timeout: float = 2.0
    ipc_total_timeout: float = 5.0
    max_restart_attempts: int = 3
    restart_backoff_seconds: int = 5
    max_backoff_seconds: int = 60
    stale_threshold_seconds: int = 120
    grace_period_seconds: int = 10


class PolicyWatchdog:
    """Supervises PolicyIPCServer and Controller event loop.

    Runs in the Controller process on a dedicated thread with its own
    event loop. All supervision evidence is recorded through the
    controller's EventStore so it survives restarts.
    """

    def __init__(
        self,
        store: EventStore,
        socket_path: Path,
        capability: str,
        agent_id: str,
        task_id: str,
        attempt_id: Optional[str],
        command_prefix: str,
        config: Optional[WatchdogConfig] = None,
    ):
        self.store = store
        self.socket_path = socket_path
        self.capability = capability
        self.agent_id = agent_id
        self.task_id = task_id
        self.attempt_id = attempt_id
        self.command_prefix = command_prefix
        self.config = config or WatchdogConfig()

        self._running = False
        self._restart_count = 0
        self._last_successful_check = time.monotonic()
        self._last_known_state = ServiceState.UNREACHABLE
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._shutdown_event: Optional[asyncio.Event] = None

    def start(self) -> None:
        """Launch the watchdog on its own thread with persistent event loop."""
        if self._running:
            raise ValidationError("watchdog already running")
        self._running = True
        self._loop = asyncio.new_event_loop()
        self._shutdown_event = asyncio.Event()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Graceful shutdown."""
        if not self._running:
            return
        self._running = False
        loop = self._loop
        shutdown = self._shutdown_event
        if loop is not None and shutdown is not None:
            # set() returns a coroutine in Python 3.14; use a plain callback
            # to avoid run_coroutine_threadsafe requiring a coroutine object.
            loop.call_soon_threadsafe(shutdown.set)
            loop.call_soon_threadsafe(loop.stop)
        thread = self._thread
        if thread is not None:
            thread.join(timeout=5)
        loop = self._loop
        if loop is not None:
            loop.close()
        self._loop = None
        self._thread = None
        self._shutdown_event = None

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._supervise())
        except RuntimeError:
            # Event loop stopped before Future completed — expected when
            # the watchdog is stopped mid-cycle. Not a real error.
            pass

    async def _supervise(self) -> None:
        """Main supervision loop."""
        await asyncio.sleep(self.config.grace_period_seconds)
        while self._running and not self._shutdown_event.is_set():
            try:
                await self._check_and_record()
            except Exception as exc:
                self._record_snapshot(
                    ServiceState.DEGRADED,
                    f"supervision check failed: {exc}",
                    FailureKind.UNKNOWN,
                )
            await asyncio.sleep(self.config.check_interval_seconds)

    async def _check_and_record(self) -> None:
        """Perform one health check cycle."""
        now = time.monotonic()
        state, detail, kind = await self._probe_ipc()
        revision = self._resolve_attempt_revision()

        if state == ServiceState.HEALTHY:
            self._last_successful_check = now
            self._restart_count = 0
        elif state == ServiceState.UNREACHABLE:
            # Check if we should attempt restart
            if now - self._last_successful_check > self.config.stale_threshold_seconds:
                if self._restart_count < self.config.max_restart_attempts:
                    state = ServiceState.RESTARTING
                    detail = "attempting supervised restart"
                    await self._attempt_restart()
                else:
                    detail = "max restart attempts exceeded; service unreachable"
                    kind = FailureKind.CONTROLLER_DEAD

        self._record_snapshot(state, detail, kind, revision)
        self._last_known_state = state

    def _probe_ipc_sync(self) -> tuple[ServiceState, str, Optional[FailureKind]]:
        """Run a synchronous probe in a dedicated thread with its own event loop.

        Returns the probe result. Designed to be called from a fresh thread
        so that `send_policy_decision_sync` (which calls asyncio.run) works
        without conflicting with the watchdog's running event loop.
        """
        from .policy_ipc import PolicyIPCRequest, send_policy_decision_sync

        probe = PolicyIPCRequest(
            version=1,
            request_id="watchdog-probe",
            capability=self.capability,
            agent_id=self.agent_id,
            session_id="watchdog",
            task_id=self.task_id,
            attempt_id=self.attempt_id,
            tool_use_id="watchdog-probe",
            tool_name="WatchdogProbe",
            decision="defer",  # safe no-op decision
            risk_category="internal",
            risk_severity="low",
            reasoning="watchdog health probe",
            timestamp=utc_now(),
            idempotency_key="watchdog-probe-key",
            tool_input_hash=None,
        )

        try:
            resp = send_policy_decision_sync(
                self.socket_path,
                self.capability,
                probe,
                self.config.ipc_total_timeout,
            )
        except asyncio.TimeoutError:
            return ServiceState.UNREACHABLE, "ipc probe timeout", FailureKind.IPC_TIMEOUT
        except (OSError, ConnectionRefusedError, FileNotFoundError) as exc:
            return ServiceState.UNREACHABLE, f"ipc connection failed: {exc}", FailureKind.IPC_CONNECT_FAILED
        except Exception as exc:
            return ServiceState.DEGRADED, f"ipc probe error: {exc}", FailureKind.UNKNOWN

        if resp.success:
            return ServiceState.HEALTHY, "ipc responsive", None
        if resp.error and "malformed" in resp.error.lower():
            return ServiceState.DEGRADED, f"ipc malformed: {resp.error}", FailureKind.IPC_MALFORMED
        return ServiceState.DEGRADED, f"ipc error: {resp.error}", FailureKind.UNKNOWN

    async def _probe_ipc(self) -> tuple[ServiceState, str, Optional[FailureKind]]:
        """Probe the PolicyIPCServer via a minimal connection test.

        Runs the synchronous probe in a separate thread with its own event
        loop so that asyncio.run() inside send_policy_decision_sync does not
        conflict with the watchdog's running event loop.
        """
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return await asyncio.get_event_loop().run_in_executor(
                pool, self._probe_ipc_sync,
            )

    def _resolve_attempt_revision(self) -> Optional[int]:
        try:
            if self.store._database_present() and self.attempt_id:
                with self.store._connection(write=False) as conn:
                    row = conn.execute(
                        "SELECT revision FROM attempts WHERE attempt_id=?",
                        (self.attempt_id,),
                    ).fetchone()
                    if row is not None:
                        return row["revision"]
        except Exception:
            pass
        return None

    async def _attempt_restart(self) -> None:
        """Attempt to restart the PolicyIPCServer. Called from supervision loop."""
        self._restart_count += 1
        backoff = min(
            self.config.restart_backoff_seconds * (2 ** (self._restart_count - 1)),
            self.config.max_backoff_seconds,
        )
        self._record_snapshot(
            ServiceState.RESTARTING,
            f"restart attempt {self._restart_count}/{self.config.max_restart_attempts}; backoff {backoff}s",
            FailureKind.STARTUP_FAILED,
            self._resolve_attempt_revision(),
        )
        await asyncio.sleep(backoff)
        # Actual restart is orchestrated by the Controller — watchdog only records intent.
        # Controller observes RESTARTING snapshots and acts accordingly.

    def _record_snapshot(
        self,
        state: ServiceState,
        detail: str,
        kind: Optional[FailureKind],
        revision: Optional[int] = None,
    ) -> None:
        """Persist a supervision snapshot to the EventStore."""
        if not self.store._database_present():
            return
        snap = ServiceSnapshot(
            timestamp=utc_now(),
            service_name="PolicyIPCServer",
            state=state,
            detail=detail,
            failure_kind=kind,
            attempt_revision=revision,
        )
        command_id = f"{self.command_prefix}:watchdog:{int(time.time() * 1000)}:{uuid4().hex}"
        with self.store._connection(write=True) as conn:
            from .runtime_store import AgentRuntimeStoreMixin
            AgentRuntimeStoreMixin._runtime_event(
                conn,
                entity_type="policy_watchdog",
                entity_id=self.agent_id,
                revision=revision or 1,
                event_type="SNAPSHOT",
                command=command_id,
                payload=canonical_json({
                    "timestamp": snap.timestamp,
                    "service_name": snap.service_name,
                    "state": snap.state.value,
                    "detail": snap.detail,
                    "failure_kind": snap.failure_kind.value if snap.failure_kind else None,
                    "attempt_revision": snap.attempt_revision,
                    "restart_count": self._restart_count,
                }),
            )

    def get_current_state(self) -> ServiceState:
        return self._last_known_state

    def get_restart_count(self) -> int:
        return self._restart_count

    def get_restart_intent(self) -> Optional[dict]:
        """Return the latest restart intent, or None if no restart is pending.

        The watchdog only *reports* intent. The Controller owns the actual
        restart decision and execution. This method lets the Controller
        evaluate the intent and act on it.
        """
        if self._last_known_state != ServiceState.RESTARTING:
            return None
        if self._restart_count == 0:
            return None
        backoff = min(
            self.config.restart_backoff_seconds * (2 ** (self._restart_count - 1)),
            self.config.max_backoff_seconds,
        )
        return {
            "attempt": self._restart_count,
            "max_attempts": self.config.max_restart_attempts,
            "backoff_seconds": backoff,
            "state": self._last_known_state.value,
            "timestamp": utc_now(),
        }

    def clear_restart_intent(self) -> None:
        """Reset restart state after the Controller has handled it."""
        self._restart_count = 0
        self._last_known_state = ServiceState.UNREACHABLE


class ApprovalExpirationSweeper:
    """D2-C: bounded expiration sweep for PENDING approvals.

    Runs on the Controller's event loop (or a dedicated loop) and calls
    `store.expire_approvals()` at a configurable interval. Records
    expiration evidence. Designed to be restart-safe: missed intervals
    on restart are handled by execution-time expiry validation which
    remains authoritative.
    """

    def __init__(
        self,
        store: EventStore,
        command_prefix: str,
        interval_seconds: int = 60,
    ):
        self.store = store
        self.command_prefix = command_prefix
        self.interval = interval_seconds
        self._running = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._shutdown_event: Optional[asyncio.Event] = None

    def start(self) -> None:
        if self._running:
            raise ValidationError("expiration sweeper already running")
        self._running = True
        self._loop = asyncio.new_event_loop()
        self._shutdown_event = asyncio.Event()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        loop = self._loop
        shutdown = self._shutdown_event
        if loop is not None and shutdown is not None:
            # set() returns a coroutine in Python 3.14; use a plain callback
            # to avoid run_coroutine_threadsafe requiring a coroutine object.
            loop.call_soon_threadsafe(shutdown.set)
            loop.call_soon_threadsafe(loop.stop)
        thread = self._thread
        if thread is not None:
            thread.join(timeout=5)
        loop = self._loop
        if loop is not None:
            loop.close()
        self._loop = None
        self._thread = None
        self._shutdown_event = None

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._sweep_loop())
        except RuntimeError:
            pass

    async def _sweep_loop(self) -> None:
        while self._running and not self._shutdown_event.is_set():
            try:
                await asyncio.sleep(self.interval)
                if not self._running:
                    break
                self._do_sweep()
            except Exception:
                pass  # Fail silent; execution-time validation is authoritative

    def _do_sweep(self) -> int:
        """Execute one expiration sweep. Returns count expired."""
        command_id = f"{self.command_prefix}:expiry:{int(time.time() * 1000)}:{uuid4().hex}"
        try:
            return self.store.expire_approvals(command_id)
        except Exception:
            return 0


class CrashRecoveryInspector:
    """D2-D: inspect CONSUMED approval state after Controller crash.

    Does NOT automatically reset CONSUMED → APPROVED or redispatch.
    Provides evidence for human recovery decision.
    """

    def __init__(self, store: EventStore, agent_id: str, task_id: str):
        self.store = store
        self.agent_id = agent_id
        self.task_id = task_id

    def inspect_consumed_approvals(self) -> list[dict]:
        """Find all CONSUMED approvals for this agent/task with execution evidence."""
        if not self.store._database_present():
            return []
        with self.store._connection(write=False) as conn:
            rows = conn.execute(
                """SELECT * FROM agent_approval_state
                   WHERE agent_id=? AND task_id=? AND approval_status='CONSUMED'
                   ORDER BY decided_at DESC""",
                (self.agent_id, self.task_id),
            ).fetchall()
            results = []
            for row in rows:
                d = dict(row)
                # Check for execution records linked to this approval
                exec_rows = conn.execute(
                    """SELECT event_id, event_type, payload_json, timestamp
                       FROM agent_runtime_events
                       WHERE json_extract(payload_json, '$.approval_id') = ?
                       ORDER BY timestamp""",
                    (d["approval_id"],),
                ).fetchall()
                d["execution_events"] = [dict(r) for r in exec_rows]
                results.append(d)
            return results

    def has_execution_evidence(self, approval_id: str) -> tuple[bool, dict]:
        """Return (has_evidence, details) for a CONSUMED approval."""
        if not self.store._database_present():
            return False, {}
        with self.store._connection(write=False) as conn:
            rows = conn.execute(
                """SELECT event_id, event_type, payload_json, timestamp
                   FROM agent_runtime_events
                   WHERE json_extract(payload_json, '$.approval_id') = ?
                   ORDER BY timestamp""",
                (approval_id,),
            ).fetchall()
            events = [dict(r) for r in rows]
            if not events:
                return False, {"events": []}
            # Look for completion evidence
            for ev in events:
                payload = ev.get("payload_json", "")
                if '"event_type":"ALLOW"' in payload or '"event_type": "ALLOW"' in payload:
                    return True, {"events": events, "completed": True}
            return True, {"events": events, "completed": False}

    def recommend_recovery(self, approval_id: str) -> dict:
        """Produce a recovery recommendation without executing it."""
        has_exec, details = self.has_execution_evidence(approval_id)
        approval = self.store.get_approval(approval_id)
        if approval is None or approval["approval_status"] != "CONSUMED":
            return {"action": "none", "reason": "approval not CONSUMED or missing"}
        if has_exec:
            return {"action": "new_approval_required", "reason": "execution completed; new approval needed"}
        return {"action": "human_review", "reason": "execution uncertain; human must decide"}