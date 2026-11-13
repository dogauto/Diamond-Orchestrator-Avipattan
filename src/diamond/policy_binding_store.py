"""EventStore mixin for persistent IPC binding records."""

from __future__ import annotations

import hashlib

from .errors import ConflictError, ValidationError


class PolicyIPCStoreMixin:
    """Persist IPC binding metadata so revocation survives memory loss."""

    @staticmethod
    def _capability_hash(prefix_length: int = 16) -> str:
        return hashlib.sha256(b"").hexdigest()[:prefix_length]

    def register_policy_ipc_binding(self, attempt_id: str, capability: str,
                                    command_id: str) -> dict:
        """Register an IPC capability against one attempt. Raises on conflict."""
        from .validation import text as validate_text, utc_now
        if not isinstance(attempt_id, str) or not attempt_id:
            raise ValidationError("attempt_id is required")
        if not isinstance(capability, str) or len(capability) < 8:
            raise ValidationError("capability must be at least 8 chars")
        validate_text(command_id, "command_id", 128)
        with self._connection(write=True) as connection:
            row = connection.execute(
                "SELECT 1 FROM policy_ipc_bindings WHERE attempt_id=?", (attempt_id,)
            ).fetchone()
            if row is not None:
                raise ConflictError(f"ipc binding already registered for {attempt_id}")
            prefix = hashlib.sha256(capability.encode()).hexdigest()[:16]
            now = utc_now()
            connection.execute(
                "INSERT INTO policy_ipc_bindings VALUES (?,?,?,?,?,?)",
                (attempt_id, 1, prefix, 0, now, now),
            )
            return {"attempt_id": attempt_id, "hash_prefix": prefix}

    def is_binding_revoked_or_missing(self, attempt_id: str) -> bool:
        """Return True if no valid binding exists for this attempt."""
        with self._connection(write=False) as connection:
            row = connection.execute(
                "SELECT revoked FROM policy_ipc_bindings WHERE attempt_id=?",
                (attempt_id,),
            ).fetchone()
        return row is None or bool(row["revoked"])

    def revoke_policy_ipc_binding(self, attempt_id: str, command_id: str) -> None:
        """Mark the binding as revoked after attempt lifecycle ends."""
        from .validation import text as validate_text, utc_now
        validate_text(command_id, "command_id", 128)
        with self._connection(write=True) as connection:
            cursor = connection.execute(
                "UPDATE policy_ipc_bindings SET revoked=1,updated_at=? WHERE attempt_id=? AND revoked=0",
                (utc_now(), attempt_id),
            )
            if cursor.rowcount == 0:
                raise ValidationError(f"no active binding found for {attempt_id}")
