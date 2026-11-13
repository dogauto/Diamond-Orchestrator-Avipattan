"""EventStore mixin for persistent human approval state.

An approval request is created when the policy classifier returns ASK. It is
resolved only by an authorized human operator through the Diamond CLI. The
Controller remains the final authorization authority: an APPROVED record is
evidence that a human approved, never by itself a license to execute. The
PolicyIPCServer binds execution to the exact approved operation before the
hook may return ALLOW.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

from .errors import ConflictError, NotFoundError, ValidationError
from .validation import bounded_int, canonical_json, command_id as validate_command_id, parse_canonical_json, text, utc_now


class ApprovalStoreMixin:
    """Persist and resolve approval requests in the controller-owned ledger."""

    @staticmethod
    def _tool_input_hash(tool_input: object) -> str:
        """Canonical hash of tool input for exact-operation binding."""
        if tool_input is None:
            return hashlib.sha256(b"null").hexdigest()
        return hashlib.sha256(canonical_json(tool_input).encode()).hexdigest()

    @staticmethod
    def _approval_id(agent_id: str, task_id: str, attempt_id: Optional[str],
                     tool_name: str, tool_input_hash: str) -> str:
        """Derive deterministic approval_id from the operation identity."""
        components = [agent_id, task_id, attempt_id or "", tool_name, tool_input_hash]
        return hashlib.sha256(":".join(components).encode()).hexdigest()[:32]

    def create_approval_request(
        self,
        agent_id: str,
        task_id: str,
        attempt_id: Optional[str],
        execution_id: Optional[str],
        tool_name: str,
        tool_input: object,
        requested_permissions: list[str],
        policy_reason: str,
        command_id: str,
        expires_after_seconds: int = 1800,
        tool_input_hash: Optional[str] = None,
    ) -> dict:
        """Create a PENDING approval request. Idempotent on exact operation identity."""
        if not all(isinstance(x, str) and x for x in (agent_id, task_id, tool_name)):
            raise ValidationError("agent_id, task_id, tool_name required")
        validate_command_id(command_id)
        bounded_int(expires_after_seconds, "expires_after_seconds", 1, 86400)
        text(policy_reason, "policy_reason", 4096)

        if tool_input_hash is None:
            tool_input_hash = self._tool_input_hash(tool_input)
        approval_id = self._approval_id(agent_id, task_id, attempt_id, tool_name, tool_input_hash)
        now = utc_now()
        expires_at = (datetime.fromisoformat(now.replace("Z", "+00:00"))
                      + timedelta(seconds=expires_after_seconds)).isoformat().replace("+00:00", "Z")

        with self._connection(write=True) as connection:
            # Idempotency check: same exact operation returns existing record
            row = connection.execute(
                "SELECT * FROM agent_approval_state WHERE approval_id=?", (approval_id,)
            ).fetchone()
            if row is not None:
                existing = dict(row)
                if existing["approval_status"] != "PENDING":
                    raise ConflictError(f"approval {approval_id} already resolved as {existing['approval_status']}")
                return existing

            requested_json = canonical_json(requested_permissions)
            connection.execute(
                """INSERT INTO agent_approval_state
                   (approval_id, schema_version, agent_id, task_id, attempt_id, execution_id,
                    tool_name, tool_input_hash, requested_permissions_json, approval_status,
                    policy_reason, created_at, expires_at, decided_at, approver_identity,
                    decision_evidence_json, command_id, request_json)
                   VALUES (?,1,?,?,?,?,?,?,?,'PENDING',?,?,?,?,?,?,?,?)""",
                (approval_id, agent_id, task_id, attempt_id, execution_id,
                 tool_name, tool_input_hash, requested_json, policy_reason,
                 now, expires_at, None, None, None, command_id, canonical_json({
                     "agent_id": agent_id, "task_id": task_id, "attempt_id": attempt_id,
                     "execution_id": execution_id, "tool_name": tool_name,
                     "tool_input": tool_input, "requested_permissions": requested_permissions,
                     "policy_reason": policy_reason, "created_at": now,
                 })),
            )
        return {
            "approval_id": approval_id, "agent_id": agent_id, "task_id": task_id,
            "attempt_id": attempt_id, "execution_id": execution_id,
            "tool_name": tool_name, "tool_input_hash": tool_input_hash,
            "requested_permissions": requested_permissions, "approval_status": "PENDING",
            "policy_reason": policy_reason, "created_at": now,
        }

    def get_approval(self, approval_id: str) -> Optional[dict]:
        """Fetch approval record by ID."""
        if not self._database_present():
            return None
        with self._connection(write=False) as connection:
            row = connection.execute(
                "SELECT * FROM agent_approval_state WHERE approval_id=?", (approval_id,)
            ).fetchone()
        if row is None:
            return None
        return self._decode_approval(row)

    def list_approvals(
        self,
        status: Optional[str] = None,
        agent_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> list[dict]:
        """List approvals, optionally filtered."""
        if not self._database_present():
            return []
        where = []
        params = []
        if status:
            where.append("approval_status=?")
            params.append(status)
        if agent_id:
            where.append("agent_id=?")
            params.append(agent_id)
        if task_id:
            where.append("task_id=?")
            params.append(task_id)
        sql = "SELECT * FROM agent_approval_state"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY created_at DESC"
        with self._connection(write=False) as connection:
            rows = connection.execute(sql, params).fetchall()
        return [self._decode_approval(row) for row in rows]

    def _decode_approval(self, row) -> dict:
        """Decode approval row to dict with parsed JSON fields."""
        d = dict(row)
        try:
            d["requested_permissions"] = json.loads(d["requested_permissions_json"])
        except Exception:
            d["requested_permissions"] = []
        try:
            d["request"] = parse_canonical_json(d["request_json"])
        except Exception:
            d["request"] = {}
        try:
            d["decision_evidence"] = json.loads(d["decision_evidence_json"]) if d["decision_evidence_json"] else None
        except Exception:
            d["decision_evidence"] = None
        return d

    def resolve_approval(
        self,
        approval_id: str,
        decision: str,  # "APPROVED" or "DENIED"
        approver_identity: str,
        decision_evidence: Optional[dict] = None,
        command_id: str = "",
    ) -> dict:
        """Resolve a PENDING approval to APPROVED or DENIED."""
        if decision not in ("APPROVED", "DENIED"):
            raise ValidationError("decision must be APPROVED or DENIED")
        validate_command_id(command_id)
        text(approver_identity, "approver_identity", 256)

        with self._connection(write=True) as connection:
            row = connection.execute(
                "SELECT * FROM agent_approval_state WHERE approval_id=?", (approval_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError(f"approval {approval_id} not found")
            if row["approval_status"] != "PENDING":
                raise ConflictError(f"approval {approval_id} already resolved as {row['approval_status']}")

            now = utc_now()
            evidence_json = canonical_json(decision_evidence) if decision_evidence else None
            cursor = connection.execute(
                """UPDATE agent_approval_state
                   SET approval_status=?, decided_at=?, approver_identity=?, decision_evidence_json=?
                   WHERE approval_id=? AND approval_status='PENDING'""",
                (decision, now, approver_identity, evidence_json, approval_id),
            )
            if cursor.rowcount != 1:
                raise ConflictError(f"approval {approval_id} changed concurrently")

        return self.get_approval(approval_id)  # type: ignore

    def consume_approval(self, approval_id: str, command_id: str) -> bool:
        """Mark an APPROVED approval as CONSUMED. Returns True if consumed, False if unavailable."""
        validate_command_id(command_id)
        with self._connection(write=True) as connection:
            row = connection.execute(
                "SELECT approval_status FROM agent_approval_state WHERE approval_id=?",
                (approval_id,),
            ).fetchone()
            if row is None or row["approval_status"] != "APPROVED":
                return False
            cursor = connection.execute(
                "UPDATE agent_approval_state SET approval_status='CONSUMED' WHERE approval_id=? AND approval_status='APPROVED'",
                (approval_id,),
            )
            return cursor.rowcount == 1

    def cancel_approval(self, approval_id: str, command_id: str) -> dict:
        """Cancel a PENDING approval."""
        validate_command_id(command_id)
        with self._connection(write=True) as connection:
            row = connection.execute(
                "SELECT * FROM agent_approval_state WHERE approval_id=?", (approval_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError(f"approval {approval_id} not found")
            if row["approval_status"] != "PENDING":
                raise ConflictError(f"approval {approval_id} already resolved as {row['approval_status']}")

            cursor = connection.execute(
                "UPDATE agent_approval_state SET approval_status='CANCELLED' WHERE approval_id=? AND approval_status='PENDING'",
                (approval_id,),
            )
            if cursor.rowcount != 1:
                raise ConflictError(f"approval {approval_id} changed concurrently")

        return self.get_approval(approval_id)  # type: ignore

    def expire_approvals(self, command_id: str) -> int:
        """Expire PENDING approvals past their expires_at. Returns count expired."""
        validate_command_id(command_id)
        now = utc_now()
        with self._connection(write=True) as connection:
            cursor = connection.execute(
                "UPDATE agent_approval_state SET approval_status='EXPIRED' WHERE approval_status='PENDING' AND expires_at IS NOT NULL AND expires_at < ?",
                (now,),
            )
            return cursor.rowcount

    def is_approval_valid_for_execution(self, approval_id: str, tool_input: object) -> bool:
        """Check if an APPROVED record matches the exact operation being executed.

        Verifies: approval exists, is APPROVED, not expired, and tool_input matches.
        """
        if not self._database_present():
            return False
        with self._connection(write=False) as connection:
            row = connection.execute(
                "SELECT * FROM agent_approval_state WHERE approval_id=? AND approval_status='APPROVED'",
                (approval_id,),
            ).fetchone()
            if row is None:
                return False
            if row["expires_at"] is not None and row["expires_at"] < utc_now():
                return False
            # Exact tool input hash match
            tool_input_hash = self._tool_input_hash(tool_input)
            if row["tool_input_hash"] != tool_input_hash:
                return False
            return True