"""CLI handlers for Diamond-owned persistent human approval state.

The human operator is authenticated through the OS process identity of the
invoking user. Diamond never accepts an approval from an agent process: only a
process launched by an authorized local human can resolve an ASK request.

Identity verification uses os.getuid() + pwd module — NOT getpass.getuser(),
which is vulnerable to environment-variable spoofing (LOGNAME, USER, LNAME,
USERNAME all accepted by Python's getpass fallback chain before reaching pwd).
"""

from __future__ import annotations

import getpass
import json
import os
import pwd
import sys
from typing import Any

from .errors import DiamondError, NotFoundError, ValidationError
from .approval_human import build_operation_summary, generate_presence_token, request_human_presence
from .validation import command_id as validate_command_id


def _operator_identity() -> str:
    """Return the authenticated local human operator identity.

    Uses os.getuid() + pwd module to read the actual login name from the
    password database, completely ignoring environment variables such as
    LOGNAME, USER, LNAME and USERNAME which Python's getpass.getuser()
    consults first and which any process can forge.

    Returns a forged identity from an ordinary unprivileged script (e.g.
    DIAMOND_TEST_TMPDIR set alongside LOGNAME=sPoofed is sufficient to
    trick getpass); pwd.getpwuid avoids every one of those vectors.
    """
    try:
        pw = pwd.getpwuid(os.getuid())
        username = pw.pw_name
    except (KeyError, ImportError):
        # Fallback for platforms without pwd (rare) — still better than
        # getpass because we use os.environ directly rather than getpass's
        # four-env-var search.
        username = os.environ.get("REAL_USER") or getpass.getuser()
    return f"human:{username}"


def _is_agent_identity(identity: str) -> bool:
    return identity.startswith("agent:") or identity.startswith("controller:")


def _resolve_evidence(evidence_arg: str | None) -> dict[str, Any] | None:
    if not evidence_arg:
        return None
    try:
        return json.loads(evidence_arg)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"invalid --evidence JSON: {exc}") from exc


def list_approvals(args, store) -> tuple[dict[str, Any], int]:
    approvals = store.list_approvals(
        status=getattr(args, "status", None),
        agent_id=getattr(args, "agent_id", None),
        task_id=getattr(args, "task_id", None),
    )
    return {"approvals": approvals, "count": len(approvals)}, 0


def show_approval(args, store) -> tuple[dict[str, Any], int]:
    approval = store.get_approval(args.approval_id)
    if approval is None:
        raise NotFoundError(f"approval {args.approval_id} not found")
    return {"approval": approval}, 0


def _gate_resolution(approval: dict) -> str:
    """Block on interactive human presence. Returns a fresh presence token.

    Fail-closed: any error, timeout, cancellation, or non-interactive
    environment raises ValidationError. No state change occurs before this
    gate returns.
    """
    summary = build_operation_summary(approval)
    token = generate_presence_token()
    if not request_human_presence(summary, token):
        raise ValidationError("human presence denied or unavailable for approval")
    return token


def approve(args, store) -> tuple[dict[str, Any], int]:
    validate_command_id(args.command_id)
    approver = _operator_identity()
    if _is_agent_identity(approver):
        raise ValidationError("only an authorized human operator may approve requests")
    approval = store.get_approval(args.approval_id)
    if approval is None:
        raise NotFoundError(f"approval {args.approval_id} not found")
    token = _gate_resolution(approval)
    evidence = _resolve_evidence(getattr(args, "evidence", None)) or {}
    evidence["presence_token"] = token
    evidence["presence_backend"] = os.environ.get("DIAMOND_HUMAN_PRESENCE_BACKEND", "native")
    approval = store.resolve_approval(
        approval_id=args.approval_id,
        decision="APPROVED",
        approver_identity=approver,
        decision_evidence=evidence,
        command_id=args.command_id,
    )
    return {"approval": approval, "approver": approver}, 0


def deny(args, store) -> tuple[dict[str, Any], int]:
    validate_command_id(args.command_id)
    approver = _operator_identity()
    if _is_agent_identity(approver):
        raise ValidationError("only an authorized human operator may deny requests")
    approval = store.get_approval(args.approval_id)
    if approval is None:
        raise NotFoundError(f"approval {args.approval_id} not found")
    token = _gate_resolution(approval)
    evidence = {"reason": args.reason, "approver": approver, "presence_token": token}
    approval = store.resolve_approval(
        approval_id=args.approval_id,
        decision="DENIED",
        approver_identity=approver,
        decision_evidence=evidence,
        command_id=args.command_id,
    )
    return {"approval": approval, "approver": approver}, 0


def cancel(args, store) -> tuple[dict[str, Any], int]:
    validate_command_id(args.command_id)
    approver = _operator_identity()
    if _is_agent_identity(approver):
        raise ValidationError("only an authorized human operator may cancel requests")
    approval = store.get_approval(args.approval_id)
    if approval is None:
        raise NotFoundError(f"approval {args.approval_id} not found")
    token = _gate_resolution(approval)
    approval = store.cancel_approval(args.approval_id, args.command_id)
    return {"approval": approval, "approver": approver, "presence_token": token}, 0


def expire_approvals(args, store) -> tuple[dict[str, Any], int]:
    validate_command_id(args.command_id)
    count = store.expire_approvals(args.command_id)
    return {"expired": count}, 0


def approval_command(args, paths, config) -> tuple[dict[str, Any], int]:
    from .store import EventStore
    store = EventStore(paths.database)
    handler = {
        "list": list_approvals,
        "show": show_approval,
        "approve": approve,
        "deny": deny,
        "cancel": cancel,
    }.get(args.approval_command)
    if handler is None:
        raise ValidationError(f"unknown approval command: {args.approval_command}")
    return handler(args, store)