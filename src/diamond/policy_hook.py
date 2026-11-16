#!/usr/bin/env python3
"""Diamond Policy Hook Handler — PreToolUse/PostToolUse entry point.

This script is invoked by Claude Code hooks. It reads the tool call from stdin,
evaluates it through Diamond's policy classifier, and returns the hook response.

Policy decisions are now recorded via authenticated IPC to the controller-owned
EventStore instead of the hook opening its own SQLite connection.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path

# Ensure src is on path (parent of the diamond package directory)
sys.path.insert(0, str(Path(__file__).parent.parent))

from diamond.policy_classifier import (
    PolicyContext,
    ToolCallRequest,
    PolicyDecision,
    PolicyEvaluator,
    ModelAssistedClassifier,
    FreeLLMAPIConfig,
    build_hook_response,
)
from diamond.paths import resolve_paths
from diamond.freellmapi import load_gateway_config
from diamond.validation import utc_now
from diamond.policy_ipc import (
    PolicyIPCRequest, PolicyIPCResponse, PolicyIPCClient,
    send_policy_decision_sync, generate_capability,
)


def _read_hook_input() -> dict[str, Any]:
    """Read hook input from stdin."""
    try:
        return json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        _fail_hook("Invalid hook input: " + str(exc))


def _fail_hook(reason: str) -> None:
    """Output a fail-closed hook response and exit."""
    response = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
    print(json.dumps(response), file=sys.stdout)
    sys.exit(1)


def _extract_tool_call(hook_input: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    """Extract tool_use_id, tool_name, tool_input from hook payload."""
    tool_use_id = hook_input.get("tool_use_id", "")
    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {})
    return tool_use_id, tool_name, tool_input


def _build_policy_context(hook_input: dict[str, Any]) -> PolicyContext:
    """Build PolicyContext from environment and hook input."""
    # These come from Diamond's agent runtime — injected via environment
    agent_id = os.environ.get("DIAMOND_AGENT_ID", "")
    session_id = os.environ.get("DIAMOND_SESSION_ID", "")
    provider_session_id = os.environ.get("DIAMOND_PROVIDER_SESSION_ID") or None
    provider = os.environ.get("DIAMOND_PROVIDER", "freellmapi")
    adapter_id = os.environ.get("DIAMOND_ADAPTER_ID", "claude-code")
    task_id = os.environ.get("DIAMOND_TASK_ID", "")
    attempt_id = os.environ.get("DIAMOND_ATTEMPT_ID") or None
    workspace_root = os.environ.get("DIAMOND_WORKSPACE_ROOT", os.getcwd())
    owned_paths_str = os.environ.get("DIAMOND_OWNED_PATHS", "")
    owned_paths = tuple(owned_paths_str.split(":")) if owned_paths_str else ()
    network_access = os.environ.get("DIAMOND_NETWORK_ACCESS", "loopback")
    execution_policy_mode = os.environ.get("DIAMOND_EXECUTION_POLICY", "writable")
    delegation_id = os.environ.get("DIAMOND_DELEGATION_ID") or None
    delegation_scope_str = os.environ.get("DIAMOND_DELEGATION_SCOPE", "")
    delegation_scope = tuple(delegation_scope_str.split(":")) if delegation_scope_str else ()
    auth_evidence_str = os.environ.get("DIAMOND_AUTH_EVIDENCE", "")
    authorization_evidence = tuple(auth_evidence_str.split(":")) if auth_evidence_str else ()

    return PolicyContext(
        agent_id=agent_id,
        session_id=session_id,
        provider_session_id=provider_session_id,
        provider=provider,
        adapter_id=adapter_id,
        task_id=task_id,
        attempt_id=attempt_id,
        workspace_root=workspace_root,
        owned_paths=owned_paths,
        network_access=network_access,
        execution_policy_mode=execution_policy_mode,
        delegation_id=delegation_id,
        delegation_scope=delegation_scope,
        authorization_evidence=authorization_evidence,
    )


def _get_gateway_config() -> FreeLLMAPIConfig | None:
    """Load FreeLLMAPI gateway config if available."""
    config_path = Path(".diamond/freellmapi.json")
    if config_path.exists():
        try:
            return load_gateway_config(config_path)
        except Exception:
            return None
    return None


def _build_ipc_request(
    context: PolicyContext, tool_use_id: str, tool_name: str,
    decision: PolicyDecision, reasoning: str,
    capability: str, idempotency_key: str,
    tool_input: dict[str, Any],
) -> PolicyIPCRequest:
    """Build IPC request from policy evaluation context."""
    import hashlib
    from diamond.validation import canonical_json
    tool_input_hash = hashlib.sha256(canonical_json(tool_input).encode()).hexdigest()
    return PolicyIPCRequest(
        version=1,
        request_id=uuid.uuid4().hex,
        capability=capability,
        agent_id=context.agent_id,
        session_id=context.session_id,
        task_id=context.task_id,
        attempt_id=context.attempt_id,
        tool_use_id=tool_use_id,
        tool_name=tool_name,
        decision=decision.value,
        risk_category="UNKNOWN",  # TODO: extract from evaluator output
        risk_severity="NONE",  # TODO: extract from evaluator output
        reasoning=reasoning,
        timestamp=utc_now(),
        idempotency_key=idempotency_key,
        tool_input_hash=tool_input_hash,
    )


def handle_pre_tool_use() -> int:
    hook_input = _read_hook_input()
    tool_use_id, tool_name, tool_input = _extract_tool_call(hook_input)

    # Skip if no tool call info
    if not tool_name:
        response = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": "No tool call to evaluate",
            }
        }
        print(json.dumps(response), file=sys.stdout)
        return 0

    # Build context and request
    context = _build_policy_context(hook_input)
    request = ToolCallRequest(
        tool_use_id=tool_use_id,
        tool_name=tool_name,
        tool_input=tool_input,
        timestamp=utc_now(),
    )

    # Initialize evaluator
    gateway_config = _get_gateway_config()
    model_classifier = ModelAssistedClassifier(gateway_config) if gateway_config else None
    evaluator = PolicyEvaluator(model_classifier=model_classifier)

    # Evaluate
    record, decision = evaluator.evaluate(context, request)

    # Build idempotency key from request identity
    idempotency_key = f"{context.agent_id}:{context.task_id}:{context.attempt_id}:{tool_use_id}"

    # Get IPC socket path and capability from environment
    ipc_socket_path_str = os.environ.get("DIAMOND_IPC_SOCKET_PATH")
    capability = os.environ.get("DIAMOND_POLICY_CAPABILITY")

    # If no IPC socket configured, fail closed
    if not ipc_socket_path_str or not capability:
        response = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "policy record could not be persisted: no IPC socket configured",
            }
        }
        print(json.dumps(response), file=sys.stdout)
        return 0

    ipc_socket_path = Path(ipc_socket_path_str)

    ipc_request = _build_ipc_request(
        context, tool_use_id, tool_name, decision, decision.reasoning if hasattr(decision, 'reasoning') else str(decision),
        capability, idempotency_key, tool_input,
    )

    ipc_response = send_policy_decision_sync(
        socket_path=ipc_socket_path,
        capability=capability,
        request=ipc_request,
        timeout=10.0,
    )

    # Handle IPC response
    if ipc_response.success and ipc_response.event_id == "duplicate":
        # Idempotent retry - use original decision
        response = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision.value,
                "permissionDecisionReason": "Policy decision (idempotent retry)",
            }
        }
    elif ipc_response.success and ipc_response.event_id is not None:
        # IPC recording succeeded - use ALLOW/DENY based on policy decision
        response = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision.value,
                "permissionDecisionReason": ipc_response.error or f"Approved by Diamond policy",
            }
        }
    else:
        # IPC failure - fail closed, but ASK decisions surface as "ask" so the
        # human is prompted instead of silently denying. The server created a
        # PENDING approval request before rejecting.
        if decision == PolicyDecision.ASK:
            response = {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "ask",
                    "permissionDecisionReason": "Requires human approval (approval request created)",
                }
            }
        else:
            response = {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": f"policy record could not be persisted: {ipc_response.error}",
                }
            }

    print(json.dumps(response), file=sys.stdout)
    return 0


def handle_post_tool_use() -> int:
    """PostToolUse hook for result screening (prompt injection detection)."""
    hook_input = _read_hook_input()
    tool_use_id, tool_name, tool_input = _extract_tool_call(hook_input)
    tool_output = hook_input.get("tool_output", "")
    tool_result = hook_input.get("tool_result", {})

    # Basic prompt injection screening on tool output
    suspicious_patterns = [
        "ignore previous instructions",
        "disregard prior",
        "system prompt",
        "you are now",
        "act as",
        "pretend to",
        "roleplay",
        "api key",
        "secret",
        "password",
    ]

    output_text = json.dumps(tool_output) + json.dumps(tool_result)
    output_lower = output_text.lower()

    for pattern in suspicious_patterns:
        if pattern in output_lower:
            # Log but don't block — PostToolUse runs after execution
            print(f"DIAMOND: Suspicious content detected in tool output: {pattern}", file=sys.stderr)
            break

    response = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": "PostToolUse screening passed",
        }
    }
    print(json.dumps(response), file=sys.stdout)
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        _fail_hook("Usage: policy_hook.py <pre-tool-use|post-tool-use>")
        return 1

    command = sys.argv[1]
    if command == "pre-tool-use":
        return handle_pre_tool_use()
    elif command == "post-tool-use":
        return handle_post_tool_use()
    else:
        _fail_hook(f"Unknown command: {command}")
        return 1


if __name__ == "__main__":
    sys.exit(main())