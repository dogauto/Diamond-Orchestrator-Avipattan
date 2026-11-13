"""Controller-owned policy-decision IPC service.

The hook writes nothing directly to SQLite. Instead it sends a signed request
to a Unix-domain socket owned by the running controller process. The controller
resolves the authoritative task/attempt/revision from its EventStore before
persisting the decision record and acknowledging the hook.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import threading
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from .errors import StorageError, ValidationError
from .paths_utils import safe_prepare_socket
from .validation import canonical_json, utc_now

# Protocol version
IPC_PROTOCOL_VERSION = 1

# Message size limits
MAX_MESSAGE_SIZE = 64 * 1024  # 64 KiB

# Socket directory and permissions
SOCKET_DIR_MODE = 0o700
SOCKET_FILE_MODE = 0o600


@dataclass(frozen=True)
class PolicyIPCRequest:
    """Request from hook to controller."""
    version: int
    request_id: str
    capability: str
    agent_id: str
    session_id: str
    task_id: str
    attempt_id: Optional[str]
    tool_use_id: str
    tool_name: str
    decision: str
    risk_category: str
    risk_severity: str
    reasoning: str
    timestamp: str
    idempotency_key: str
    tool_input_hash: Optional[str] = None

    def to_json(self) -> str:
        obj = {
            "version": self.version,
            "request_id": self.request_id,
            "capability": self.capability,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "task_id": self.task_id,
            "attempt_id": self.attempt_id,
            "tool_use_id": self.tool_use_id,
            "tool_name": self.tool_name,
            "decision": self.decision,
            "risk_category": self.risk_category,
            "risk_severity": self.risk_severity,
            "reasoning": self.reasoning,
            "timestamp": self.timestamp,
            "idempotency_key": self.idempotency_key,
        }
        if self.tool_input_hash is not None:
            obj["tool_input_hash"] = self.tool_input_hash
        return json.dumps(obj, separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_json(cls, data: str) -> "PolicyIPCRequest":
        obj = json.loads(data)
        return cls(
            version=obj["version"],
            request_id=obj["request_id"],
            capability=obj["capability"],
            agent_id=obj["agent_id"],
            session_id=obj["session_id"],
            task_id=obj["task_id"],
            attempt_id=obj.get("attempt_id"),
            tool_use_id=obj["tool_use_id"],
            tool_name=obj["tool_name"],
            decision=obj["decision"],
            risk_category=obj["risk_category"],
            risk_severity=obj["risk_severity"],
            reasoning=obj["reasoning"],
            timestamp=obj["timestamp"],
            idempotency_key=obj["idempotency_key"],
            tool_input_hash=obj.get("tool_input_hash"),
        )


@dataclass(frozen=True)
class PolicyIPCResponse:
    """Response from controller to hook."""
    version: int
    request_id: str
    success: bool
    event_id: Optional[str] = None
    revision: Optional[int] = None
    error: Optional[str] = None

    def to_json(self) -> str:
        obj = {
            "version": self.version,
            "request_id": self.request_id,
            "success": self.success,
        }
        if self.event_id is not None:
            obj["event_id"] = self.event_id
        if self.revision is not None:
            obj["revision"] = self.revision
        if self.error is not None:
            obj["error"] = self.error
        return json.dumps(obj, separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_json(cls, data: str) -> "PolicyIPCResponse":
        obj = json.loads(data)
        return cls(
            version=obj["version"],
            request_id=obj["request_id"],
            success=obj["success"],
            event_id=obj.get("event_id"),
            revision=obj.get("revision"),
            error=obj.get("error"),
        )


def generate_capability() -> str:
    """Generate a cryptographically secure capability token."""
    return secrets.token_urlsafe(32)


def hash_capability_full(capability: str) -> str:
    """Hash capability for storage (never log raw capability)."""
    return hashlib.sha256(capability.encode()).hexdigest()


# Backward-compatible alias for existing tests.
hash_capability = hash_capability_full


def validate_ipc_request(request: PolicyIPCRequest, expected_capability_hash_full: str,
                         registered_agent_id: str, registered_task_id: str,
                         registered_attempt_id: Optional[str]) -> Optional[str]:
    """Validate IPC request. Returns error message if invalid, None if valid."""
    if request.version != IPC_PROTOCOL_VERSION:
        return f"unsupported protocol version: {request.version}"

    actual_hash = hash_capability_full(request.capability)
    if actual_hash != expected_capability_hash_full:
        return "invalid capability"

    if request.agent_id != registered_agent_id:
        return f"agent_id mismatch: expected {registered_agent_id}, got {request.agent_id}"
    if request.task_id != registered_task_id:
        return f"task_id mismatch: expected {registered_task_id}, got {request.task_id}"
    if request.attempt_id != registered_attempt_id:
        return f"attempt_id mismatch: expected {registered_attempt_id}, got {request.attempt_id}"

    if not request.request_id or not request.tool_use_id or not request.tool_name:
        return "missing required fields"

    if request.decision not in ("allow", "deny", "ask", "defer", "indeterminate"):
        return f"invalid decision: {request.decision}"

    return None


class AttemptRevocationResult(Enum):
    """Explicit outcome of an attempt revocation.

    The enum exists because a previous implementation returned ``True`` even
    when socket teardown failed, reporting success while authority persisted.
    Every outcome is observable and never invents success.
    """

    REVOKED = "revoked"
    ALREADY_REVOKED = "already_revoked"
    UNKNOWN_ATTEMPT = "unknown_attempt"
    CLEANUP_FAILED = "cleanup_failed"
    AUTHORITY_REVOKED_RESOURCE_CLEANUP_INCOMPLETE = (
        "authority_revoked_resource_cleanup_incomplete"
    )


class PolicyIPCServer:
    """Unix domain socket server for controller-owned policy decisions.

    Each attempt owns exactly one server. Revocation sets a per-server
    ``_revoked`` flag *before* tearing down resources, so in-flight requests
    that already connected are rejected and no new request can race through
    after the flag is set.
    """

    def __init__(self, socket_path: Path, capability: str,
                 agent_id: str, task_id: str, attempt_id: Optional[str],
                 store, command_prefix: str):
        self.socket_path = socket_path
        self.capability = capability
        self.capability_hash_full = hash_capability_full(capability)
        self.agent_id = agent_id
        self.task_id = task_id
        self.attempt_id = attempt_id
        self.store = store
        self.command_prefix = command_prefix
        self._server: Optional[asyncio.Server] = None
        self._seen_idempotency_keys: set[str] = set()
        self._running = False
        # Revocation state. Set before resource teardown so request handlers
        # observe it on every request, not only at connection setup.
        self._revoked = False
        self._revocation_lock = threading.Lock()

    def revoke(self) -> AttemptRevocationResult:
        """Invalidate authority synchronously.

        Sets the revoked flag first, then closes the server and removes the
        socket. Returns the explicit outcome; never swallows cleanup failures.
        """
        with self._revocation_lock:
            if self._revoked:
                return AttemptRevocationResult.ALREADY_REVOKED
            self._revoked = True

        # Authority is now invalidated. Any in-flight request that already
        # connected is rejected at the next validate_ipc_request() call.
        # No new connections can be accepted because the server is closed.
        loop = getattr(self, "_loop", None)
        cleanup_errors: list[str] = []
        if self._server is not None and loop is not None and loop.is_running():
            try:
                future = asyncio.run_coroutine_threadsafe(self._stop_server(), loop)
                future.result(timeout=5)
            except Exception as exc:
                cleanup_errors.append(f"server stop: {exc}")
        elif self._server is not None:
            # No dedicated loop (should not happen in normal use); stop inline.
            try:
                self._server.close()
                asyncio.run(self._server.wait_closed())
            except Exception as exc:
                cleanup_errors.append(f"server close: {exc}")

        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            cleanup_errors.append(f"socket unlink: {exc}")

        self._running = False
        if cleanup_errors:
            return AttemptRevocationResult.AUTHORITY_REVOKED_RESOURCE_CLEANUP_INCOMPLETE
        return AttemptRevocationResult.REVOKED

    async def _stop_server(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()

    def is_revoked(self) -> bool:
        with self._revocation_lock:
            return self._revoked

    async def start(self) -> None:
        """Start the IPC server."""
        if self._revoked:
            raise ValidationError("cannot start a revoked IPC server")
        safe_prepare_socket(self.socket_path)
        self._server = await asyncio.start_unix_server(
            self._handle_client,
            path=str(self.socket_path)
        )
        self.socket_path.chmod(SOCKET_FILE_MODE)
        self._running = True

    async def stop(self) -> None:
        """Stop the IPC server without revoking authority.

        Used by the context's normal teardown path. Does not set the revoked
        flag; callers that need authority invalidation must call revoke().
        """
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle a single client connection."""
        try:
            data = await reader.read(MAX_MESSAGE_SIZE + 1)
            if len(data) > MAX_MESSAGE_SIZE:
                response = PolicyIPCResponse(
                    version=IPC_PROTOCOL_VERSION,
                    request_id="unknown",
                    success=False,
                    error="message too large"
                )
                writer.write(response.to_json().encode() + b"\n")
                await writer.drain()
                return

            if not data:
                return

            request = PolicyIPCRequest.from_json(data.decode().strip())

            # Revocation is checked at request-processing time, not only at
            # connection setup. A request that connected before revocation
            # began is rejected here; no new connection can be accepted after
            # the server is closed. This is the single enforcement point.
            if self.is_revoked():
                response = PolicyIPCResponse(
                    version=IPC_PROTOCOL_VERSION,
                    request_id=request.request_id,
                    success=False,
                    error="attempt capability revoked"
                )
                writer.write(response.to_json().encode() + b"\n")
                await writer.drain()
                return

            error = validate_ipc_request(
                request, self.capability_hash_full,
                self.agent_id, self.task_id, self.attempt_id
            )

            if error:
                response = PolicyIPCResponse(
                    version=IPC_PROTOCOL_VERSION,
                    request_id=request.request_id,
                    success=False,
                    error=error
                )
                writer.write(response.to_json().encode() + b"\n")
                await writer.drain()
                return

            if request.idempotency_key in self._seen_idempotency_keys and request.decision != "ask":
                # ASK decisions are never short-circuited: a request that was
                # previously blocked for approval must be re-evaluated after the
                # human resolves it, otherwise the agent can never proceed.
                response = PolicyIPCResponse(
                    version=IPC_PROTOCOL_VERSION,
                    request_id=request.request_id,
                    success=True,
                    event_id="duplicate",
                    revision=0
                )
                writer.write(response.to_json().encode() + b"\n")
                await writer.drain()
                return

            try:
                event_id, revision = self._record_policy_decision(request)
                self._seen_idempotency_keys.add(request.idempotency_key)

                response = PolicyIPCResponse(
                    version=IPC_PROTOCOL_VERSION,
                    request_id=request.request_id,
                    success=True,
                    event_id=event_id,
                    revision=revision
                )
            except Exception as exc:
                response = PolicyIPCResponse(
                    version=IPC_PROTOCOL_VERSION,
                    request_id=request.request_id,
                    success=False,
                    error=f"persistence failed: {exc}"
                )

            writer.write(response.to_json().encode() + b"\n")
            await writer.drain()

        except json.JSONDecodeError:
            response = PolicyIPCResponse(
                version=IPC_PROTOCOL_VERSION,
                request_id="unknown",
                success=False,
                error="malformed request"
            )
            writer.write(response.to_json().encode() + b"\n")
            await writer.drain()
        except Exception as exc:
            response = PolicyIPCResponse(
                version=IPC_PROTOCOL_VERSION,
                request_id="unknown",
                success=False,
                error=f"server error: {exc}"
            )
            writer.write(response.to_json().encode() + b"\n")
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    def _record_policy_decision(self, request: PolicyIPCRequest) -> tuple[str, int]:
        """Record via the controller's EventStore with authoritative revision.

        Revision is resolved from the attempt row rather than guessed. Command ID
        carries all identity fields so the immutability triggers reject replays.

        For ASK decisions: checks if a valid APPROVED approval exists. If not,
        treats as DENY (fail-closed). If yes, records the approval binding.
        """
        from uuid import uuid4
        from .runtime_store import AgentRuntimeStoreMixin

        event_id = uuid4().hex

        # For ASK decisions, verify an APPROVED approval exists matching the exact operation
        if request.decision == "ask":
            approval_id = None
            if request.tool_input_hash is not None:
                # Look up APPROVED (not yet consumed) approval by exact operation identity.
                # Must be APPROVED and NOT yet CONSUMED; concurrent consumption is safe
                # because we check rowcount after UPDATE.
                with self.store._connection(write=True) as conn:
                    row = conn.execute(
                        """SELECT approval_id FROM agent_approval_state
                           WHERE agent_id=? AND task_id=? AND attempt_id IS ? AND tool_name=?
                             AND tool_input_hash=? AND approval_status='APPROVED'
                             AND (expires_at IS NULL OR expires_at > datetime('now'))""",
                        (request.agent_id, request.task_id, request.attempt_id,
                         request.tool_name, request.tool_input_hash),
                    ).fetchone()
                    if row is None:
                        # No valid approval - create PENDING request and fail closed.
                        try:
                            self.store.create_approval_request(
                                agent_id=request.agent_id,
                                task_id=request.task_id,
                                attempt_id=request.attempt_id,
                                execution_id=None,
                                tool_name=request.tool_name,
                                tool_input={},  # hash already bound; input not needed here
                                requested_permissions=["tool_execution"],
                                policy_reason=request.reasoning,
                                command_id=self.command_prefix + ":approval:" + request.tool_use_id,
                                expires_after_seconds=1800,
                                tool_input_hash=request.tool_input_hash,
                            )
                        except ConflictError:
                            pass  # Idempotent: request already pending
                        raise ValidationError(f"No valid approval for ASK decision on {request.tool_name}")
                        # Only one execution per approved operation.
                        cursor = conn.execute(
                            "UPDATE agent_approval_state SET approval_status='CONSUMED' WHERE approval_id=? AND approval_status='APPROVED'",
                            (row["approval_id"],),
                        )
                        if cursor.rowcount != 1:
                            raise ValidationError(f"Approval {row['approval_id']} was consumed concurrently")
                        approval_id = row["approval_id"]

            payload = {
                "decision_id": request.request_id,
                "agent_id": request.agent_id,
                "session_id": request.session_id,
                "task_id": request.task_id,
                "attempt_id": request.attempt_id,
                "tool_use_id": request.tool_use_id,
                "tool_name": request.tool_name,
                "decision": "allow",  # ASK + approval = ALLOW
                "risk_category": request.risk_category,
                "risk_severity": request.risk_severity,
                "reasoning": f"{request.reasoning} (approved via {approval_id})",
                "timestamp": request.timestamp,
                "idempotency_key": request.idempotency_key,
                "approval_id": approval_id,
            }
            event_type = "ALLOW"
        else:
            payload = {
                "decision_id": request.request_id,
                "agent_id": request.agent_id,
                "session_id": request.session_id,
                "task_id": request.task_id,
                "attempt_id": request.attempt_id,
                "tool_use_id": request.tool_use_id,
                "tool_name": request.tool_name,
                "decision": request.decision,
                "risk_category": request.risk_category,
                "risk_severity": request.risk_severity,
                "reasoning": request.reasoning,
                "timestamp": request.timestamp,
                "idempotency_key": request.idempotency_key,
            }
            event_type = request.decision.upper()

        if request.tool_input_hash is not None:
            payload["tool_input_hash"] = request.tool_input_hash

        command_id = self.command_prefix + ":policy:" + request.tool_use_id

        attempt_revision = self._resolve_attempt_revision()

        with self.store._connection(write=True) as connection:
            AgentRuntimeStoreMixin._runtime_event(
                connection,
                entity_type="policy_decision",
                entity_id=request.agent_id,
                revision=attempt_revision,
                event_type=event_type,
                command=command_id,
                payload=payload
            )

        return event_id, attempt_revision

    def _resolve_attempt_revision(self) -> int:
        """Resolve the current authoritative revision for the bound attempt."""
        from .store import NotFoundError
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
        return 1


class PolicyIPCClient:
    """Hook-side client for authenticated IPC."""

    def __init__(self, socket_path: Path, capability: str, timeout: float = 5.0):
        self.socket_path = socket_path
        self.capability = capability
        self.timeout = timeout

    async def send_decision(self, request: PolicyIPCRequest) -> PolicyIPCResponse:
        """Send policy decision request and wait for acknowledgement."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(str(self.socket_path)),
                timeout=self.timeout
            )
        except (asyncio.TimeoutError, OSError, FileNotFoundError) as exc:
            return PolicyIPCResponse(
                version=IPC_PROTOCOL_VERSION,
                request_id=request.request_id,
                success=False,
                error=f"connection failed: {exc}"
            )

        try:
            writer.write(request.to_json().encode() + b"\n")
            await writer.drain()

            data = await asyncio.wait_for(reader.read(MAX_MESSAGE_SIZE), timeout=self.timeout)

            if not data:
                return PolicyIPCResponse(
                    version=IPC_PROTOCOL_VERSION,
                    request_id=request.request_id,
                    success=False,
                    error="empty response"
                )

            return PolicyIPCResponse.from_json(data.decode().strip())

        except asyncio.TimeoutError:
            return PolicyIPCResponse(
                version=IPC_PROTOCOL_VERSION,
                request_id=request.request_id,
                success=False,
                error="response timeout"
            )
        except json.JSONDecodeError:
            return PolicyIPCResponse(
                version=IPC_PROTOCOL_VERSION,
                request_id=request.request_id,
                success=False,
                error="malformed response"
            )
        except Exception as exc:
            return PolicyIPCResponse(
                version=IPC_PROTOCOL_VERSION,
                request_id=request.request_id,
                success=False,
                error=f"client error: {exc}"
            )
        finally:
            writer.close()
            await writer.wait_closed()


def send_policy_decision_sync(socket_path: Path, capability: str, request: PolicyIPCRequest,
                               timeout: float = 5.0) -> PolicyIPCResponse:
    """Synchronous wrapper for hook invocation context."""
    client = PolicyIPCClient(socket_path, capability, timeout)
    return asyncio.run(client.send_decision(request))


class PolicyIPCServerContext:
    """Launch-stops a controller-owned IPC server around one attempt.

    Thread-safe for serial use (started/stopped on the same thread). The caller
    holds both the server handle and the raw capability until shutdown completes;
    neither object leaks outside this context.
    """

    def __init__(self, socket_path: Path, store, agent_id: str, task_id: str,
                 attempt_id: Optional[str], command_prefix: str):
        if not isinstance(socket_path, Path):
            raise ValidationError("socket_path must be a pathlib.Path")
        if len(str(socket_path)) > 108:
            raise ValidationError("socket_path too long for macOS")
        self.socket_path = socket_path
        self.store = store
        self.agent_id = agent_id
        self.task_id = task_id
        self.attempt_id = attempt_id
        self.command_prefix = command_prefix
        self.capability = generate_capability()
        self.server: Optional[PolicyIPCServer] = None

    def start(self) -> "PolicyIPCServerContext":
        """Start the server in this context. Returns self for chaining.

        The server runs on a dedicated thread with a persistent event loop so
        that the loop stays alive across multiple client connections. A
        fire-and-forget asyncio.run() closes the loop before any client can
        connect, which makes every request time out.
        """
        if self.server is not None:
            raise ValidationError("context already has a running server")
        # Validate the socket path synchronously before spawning the server
        # thread. This ensures fail-closed errors (symlink, unsafe parent)
        # propagate to the caller instead of being lost in a background thread.
        safe_prepare_socket(self.socket_path)
        self.server = PolicyIPCServer(
            socket_path=self.socket_path,
            capability=self.capability,
            agent_id=self.agent_id,
            task_id=self.task_id,
            attempt_id=self.attempt_id,
            store=self.store,
            command_prefix=self.command_prefix,
        )
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_server_loop, daemon=True
        )
        self._thread.start()
        # Block until the server has actually bound the socket.
        ready = threading.Event()
        self._ready_event = ready
        self._loop.call_soon_threadsafe(
            lambda: asyncio.ensure_future(self._start_and_signal(ready))
        )
        ready.wait()
        return self

    def _run_server_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    async def _start_and_signal(self, ready: threading.Event) -> None:
        await self.server.start()
        ready.set()

    @property
    def ipc_socket_path(self) -> Path:
        if self.server is None:
            raise ValidationError("server not started")
        return self.socket_path

    @property
    def ipc_capability(self) -> str:
        if self.server is None:
            raise ValidationError("server not started")
        return self.capability

    async def stop_async(self) -> None:
        if self.server is not None:
            await self.server.stop()
            self.server = None

    def revoke(self) -> AttemptRevocationResult:
        """Revoke this context's authority and tear down resources.

        Invalidates the capability synchronously before closing the server,
        so no new request can be authorized. Returns the explicit outcome.
        """
        server = self.server
        if server is None:
            return AttemptRevocationResult.ALREADY_REVOKED
        result = server.revoke()
        self._stop_transport()
        return result

    def stop(self) -> None:
        """Sync stop — call after all launches finish.

        Stops the transport without revoking authority. Use revoke() when
        authority invalidation is required; this path is for restart scenarios
        where the server is expected to come back up.
        """
        server = self.server
        self.server = None
        if server is None:
            return
        loop = getattr(self, "_loop", None)
        thread = getattr(self, "_thread", None)
        if loop is not None:
            future = asyncio.run_coroutine_threadsafe(server.stop(), loop)
            try:
                future.result(timeout=5)
            except Exception:
                pass
            loop.call_soon_threadsafe(loop.stop)
            if thread is not None:
                thread.join(timeout=5)
            loop.close()
            self._loop = None
            self._thread = None

    def _stop_transport(self) -> None:
        """Stop the server thread and loop without revoking authority."""
        server = self.server
        self.server = None
        if server is None:
            return
        loop = getattr(self, "_loop", None)
        thread = getattr(self, "_thread", None)
        if loop is not None:
            future = asyncio.run_coroutine_threadsafe(server.stop(), loop)
            try:
                future.result(timeout=5)
            except Exception:
                pass
            loop.call_soon_threadsafe(loop.stop)
            if thread is not None:
                thread.join(timeout=5)
            loop.close()
            self._loop = None
            self._thread = None
