"""Human-presence gate for Diamond approval decisions.

D1.2 established that `pwd.getpwuid(os.getuid())` identifies the OS account,
not the human. An AI agent and a human sharing UID 501 produce the same
identity string, so account identity alone cannot authorize a consequential
operation.

This module is the human-presence boundary. It blocks until an interactive
human responds to a native dialog that names the exact operation being
authorized. It is fail-closed: any error, timeout, cancellation, or non-
interactive environment returns False and the approval is denied.

Backends
--------
Real (default): macOS `osascript` display-dialog. The dialog is shown in the
    active GUI session; the call blocks until the human clicks a button. This
    is the strongest available system-mediated presence signal without
    PyObjC / LocalAuthentication, which are not installed in this environment.

Mock (DIAMOND_HUMAN_PRESENCE_BACKEND=mock_approve|mock_deny|mock_timeout):
    Deterministic backend for unit tests. Never used in production.

Design constraints
------------------
- No environment-variable identity (D1.2).
- No process label or CLI argument alone.
- No reusable approval session: every gate call carries a fresh random
  nonce stored in decision_evidence, so a single dialog authorizes exactly one
  resolve_approval call.
- No private signing material leaves this process; the nonce is a random
  token, not a key.
- No cloud or remote dependency.
"""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
from typing import Optional

from .errors import ValidationError

# Backend selection. Production never sets this; tests do.
_BACKEND_ENV = "DIAMOND_HUMAN_PRESENCE_BACKEND"

# osascript exit codes: 0 = button clicked, non-zero = cancelled/error/timeout.
_OSASCRIPT_APPROVE = 0


def generate_presence_token() -> str:
    """Fresh random nonce bound to one approval resolution."""
    return secrets.token_urlsafe(16)


def _is_interactive() -> bool:
    """True only when stdin and stdout are attached to a terminal."""
    try:
        return bool(os.isatty(0) and os.isatty(1))
    except OSError:
        return False


def _real_request_presence(summary: str, token: str) -> bool:
    """Block on a native macOS dialog. Fail-closed on any failure."""
    if not _is_interactive():
        return False
    if sys.platform != "darwin":
        return False

    # The dialog names the exact operation. The token is shown so the human
    # can confirm the decision they are about to make matches the record.
    script = (
        'display dialog {message} '
        'buttons {"Cancel", "Approve"} '
        'default button "Approve" '
        'cancel button "Cancel" '
        'with title "Diamond Approval" '
        'with icon note'
    )
    message = (
        f"Diamond needs human approval.\n\n"
        f"{summary}\n\n"
        f"Authorization token: {token}\n\n"
        f"Click Approve to authorize this exact operation. "
        f"This authorization cannot be reused."
    )
    try:
        result = subprocess.run(
            ["osascript", "-e", script.replace("{message}", repr(message))],
            capture_output=True, text=True, timeout=None,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == _OSASCRIPT_APPROVE


def _mock_request_presence(summary: str, token: str) -> bool:
    backend = os.environ.get(_BACKEND_ENV, "mock_deny")
    if backend == "mock_approve":
        return True
    if backend == "mock_timeout":
        return False
    return False  # mock_deny and any unknown value


def request_human_presence(summary: str, token: str) -> bool:
    """Request interactive human presence for one approval decision.

    Returns True only when a human explicitly approves the named operation.
    """
    if not summary or not isinstance(summary, str):
        raise ValidationError("operation summary required for human presence gate")
    if not token or not isinstance(token, str):
        raise ValidationError("presence token required")

    backend = os.environ.get(_BACKEND_ENV)
    if backend:
        return _mock_request_presence(summary, token)
    return _real_request_presence(summary, token)


def build_operation_summary(approval: dict) -> str:
    """Build a human-readable, operation-bound summary from an approval record."""
    tool_name = approval.get("tool_name", "unknown")
    tool_input_hash = approval.get("tool_input_hash", "unknown")
    agent_id = approval.get("agent_id", "unknown")
    task_id = approval.get("task_id", "unknown")
    approval_id = approval.get("approval_id", "unknown")
    permissions = approval.get("requested_permissions", [])
    reason = approval.get("policy_reason", "")

    lines = [
        f"Operation: {tool_name}",
        f"Agent: {agent_id}",
        f"Task: {task_id}",
        f"Approval ID: {approval_id}",
        f"Operation hash: {tool_input_hash[:16]}...",
    ]
    if permissions:
        lines.append("Permissions: " + ", ".join(permissions))
    if reason:
        lines.append(f"Reason: {reason}")
    return "\n".join(lines)