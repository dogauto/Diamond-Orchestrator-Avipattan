"""Real CLI session integration.

Opt-in via DIAMOND_REAL_CLI=1 environment variable.

Launches actual `claude` and `codex` CLI executables in bounded,
non-interactive mode and captures their structured responses.

Uses the existing SessionAdapter (tmux) and MessageTransport (queue-based)
where appropriate, but operates at the subprocess level since real CLI
processes are external to the tmux session abstraction.
"""

import json
import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..transport.real_cli_guard import is_enabled, reason, skip_unless_real_cli
from ..transport.message_transport import MessageTransport, TransportMessage
from ..transport.delivery_queue import DeliveryQueue, DeliveryState
from ..transport.session_adapter import SessionAdapter, TmuxNotAvailableError
from ..errors import (ValidationError, NotFoundError, StorageError)
from ..validation import text


# ── CLI Discovery ──────────────────────────────────────────────────────

def discover_cli_executables() -> dict[str, Path]:
    """Discover and validate claude and codex executables."""
    executables = {}

    # Discover claude
    claude_paths = []
    for candidate in [
        Path("/Users/avipattan/.local/bin/claude"),
        Path("/opt/homebrew/bin/claude"),
        Path("/usr/local/bin/claude"),
        Path.cwd() / "node_modules" / ".bin" / "claude",
    ]:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            claude_paths.append(candidate)

    if claude_paths:
        # Use the first that works
        for p in claude_paths:
            try:
                result = subprocess.run(
                    [str(p), "--version"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0 and "2." in result.stdout:
                    executables["claude"] = p
                    break
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

    # Discover codex
    codex_paths = []
    for candidate in [
        Path("/Users/avipattan/.local/bin/codex"),
        Path("/opt/homebrew/bin/codex"),
        Path("/usr/local/bin/codex"),
        Path.cwd() / "node_modules" / ".bin" / "codex",
    ]:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            codex_paths.append(candidate)

    if codex_paths:
        for p in codex_paths:
            try:
                result = subprocess.run(
                    [str(p), "--version"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0:
                    executables["codex"] = p
                    break
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

    return executables


# ── Claude CLI Non-Interactive Invocation ─────────────────────────────

_CLAUDE_PRINT_FLAG = "-p"
_CLAUDE_JSON_FLAG = "--print"

_CLAUDE_TIMEOUT = 30  # seconds

def _invoke_claude_non_interactive(
    prompt: str,
    timeout: int = _CLAUDE_TIMEOUT,
) -> dict[str, Any]:
    """Invoke claude -p <prompt> and parse JSON output if possible."""
    if not is_enabled():
        raise RuntimeError("Real CLI integration not enabled")

    executables = discover_cli_executables()
    if "claude" not in executables:
        raise RuntimeError(
            "claude executable not found; set DIAMOND_REAL_CLI=1 and "
            "ensureclaude is installed and on PATH, or provide full path"
        )

    claude_bin = str(executables["claude"])

    try:
        result = subprocess.run(
            [claude_bin, _CLAUDE_PRINT_FLAG, prompt],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "error": "command timed out", "output": ""}

    output = result.stdout.strip()
    stderr = result.stderr.strip() if result.stderr else ""

    # Try to parse as JSON
    try:
        parsed = json.loads(output)
        parsed["_cli_raw_stdout"] = output
        parsed["_cli_raw_stderr"] = stderr
        parsed["_cli_exit_code"] = result.returncode
        return parsed
    except json.JSONDecodeError:
        # Not JSON; return what we have
        return {
            "status": "non_json",
            "_cli_raw_stdout": output,
            "_cli_raw_stderr": stderr,
            "_cli_exit_code": result.returncode,
        }


# ── Codex CLI Non-Interactive Invocation ──────────────────────────────

_CODEX_EXEC_FLAG = "exec"
_CODEX_TIMEOUT = 30

def _invoke_codex_non_interactive(
    prompt: str,
    timeout: int = _CODEX_TIMEOUT,
) -> dict[str, Any]:
    """Invoke codex exec <prompt> and parse JSON output if possible."""
    if not is_enabled():
        raise RuntimeError("Real CLI integration not enabled")

    executables = discover_cli_executables()
    if "codex" not in executables:
        raise RuntimeError(
            "codex executable not found; set DIAMOND_REAL_CLI=1 and "
            "ensure codex is installed and on PATH, or provide full path"
        )

    codex_bin = str(executables["codex"])

    try:
        result = subprocess.run(
            [codex_bin, "exec", "--json", prompt],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "error": "command timed out", "output": ""}

    output = result.stdout.strip()
    stderr = result.stderr.strip() if result.stderr else ""

    # Codex --json outputs JSONL; try to parse first/last event
    try:
        # Try full JSON parse first
        parsed = json.loads(output)
        parsed["_codex_raw_stdout"] = output
        parsed["_codex_raw_stderr"] = stderr
        parsed["_codex_exit_code"] = result.returncode
        return parsed
    except json.JSONDecodeError:
        pass

    # Try JSONL: take first line that parses
    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
            parsed["_codex_raw_stdout"] = output
            parsed["_codex_raw_stderr"] = stderr
            parsed["_codex_exit_code"] = result.returncode
            return parsed
        except json.JSONDecodeError:
            continue

    # Last resort
    return {
        "status": "non_json",
        "_codex_raw_stdout": output,
        "_codex_raw_stderr": stderr,
        "_codex_exit_code": result.returncode,
    }


# ── Correlation & Message Handling ────────────────────────────────────

@dataclass
class RealCLITaskRequest:
    """A task request sent to a real CLI process."""
    correlation_id: str
    task_id: str
    agent: str  # "claude" or "codex"
    prompt: str
    timeout: int
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RealCLIResponse:
    """A response received from a real CLI process."""
    correlation_id: str
    task_id: str
    agent: str
    status: str  # "succeeded", "failed", "timeout", "non_json", "unavailable"
    response_data: dict[str, Any] | None = None
    raw_stdout: str | None = None
    raw_stderr: str | None = None
    exit_code: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


# ── Public API ────────────────────────────────────────────────────────

def request_task(
    agent: str,
    prompt: str,
    correlation_id: str,
    task_id: str,
    timeout: int = 30,
    metadata: dict[str, Any] | None = None,
) -> RealCLIResponse:
    """Send a task to a real CLI process and await response.

    Args:
        agent: "claude" or "codex"
        prompt: The prompt/objective to give the agent
        correlation_id: Unique ID for correlating request/response
        task_id: Unique ID for the task
        timeout: Maximum seconds to wait
        metadata: Additional metadata to include

    Returns:
        RealCLIResponse with status and captured data
    """
    if not is_enabled():
        raise RuntimeError("Real CLI integration not enabled")

    if agent not in ("claude", "codex"):
        return RealCLIResponse(
            correlation_id=correlation_id,
            task_id=task_id,
            agent=agent,
            status="unavailable",
            metadata=metadata or {},
        )

    # Send request based on agent type
    if agent == "claude":
        result = _invoke_claude_non_interactive(prompt, timeout)
    else:
        result = _invoke_codex_non_interactive(prompt, timeout)

    # Correlate and build response
    response = RealCLIResponse(
        correlation_id=correlation_id,
        task_id=task_id,
        agent=agent,
        status=result.get("_cli_exit_code", result.get("_codex_exit_code", -1)),
        response_data=result,
        raw_stdout=result.get("_cli_raw_stdout") or result.get("_codex_raw_stdout"),
        raw_stderr=result.get("_cli_raw_stderr") or result.get("_codex_raw_stderr"),
        exit_code=result.get("_cli_exit_code", result.get("_codex_exit_code")),
        metadata=metadata or {},
    )

    # Normalize status based on provider and response content
    response.status = _normalize_status(agent, response)

    return response


def _normalize_status(agent: str, response: RealCLIResponse) -> str:
    """Normalize provider-specific response to a documented status.

    Returns one of: "succeeded", "failed", "timeout", "non_json", "unavailable".
    """
    exit_code = response.exit_code
    raw_stdout = response.raw_stdout or ""
    raw_stderr = response.raw_stderr or ""
    response_data = response.response_data or {}

    # Timeout takes precedence
    if isinstance(response_data, dict) and response_data.get("status") == "timeout":
        return "timeout"

    # Non-zero exit code = failed
    if exit_code is not None and exit_code != 0:
        return "failed"

    # Provider-specific success determination
    if agent == "claude":
        # Claude: non-JSON text output; success if no error indicators
        if raw_stdout and "error" not in raw_stdout.lower() and "failed" not in raw_stdout.lower():
            return "succeeded"
        if "error" in raw_stdout.lower() or "failed" in raw_stdout.lower():
            return "failed"
        # Empty output with zero exit code is non_json
        return "non_json"

    elif agent == "codex":
        # Codex: JSONL output; parse events for completion status.
        #
        # Evaluate the COMPLETE event stream rather than the first
        # completion item.  A recoverable diagnostic/error item may be
        # followed by a successful agent_message and a turn.completed
        # event; in that case the final status is "succeeded".
        if not raw_stdout:
            return "non_json"

        last_item_type = None
        has_turn_completed = False
        has_error_event = False
        has_any_event = False

        for line in raw_stdout.split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            has_any_event = True
            event_type = event.get("type", "")

            if event_type == "item.completed":
                item = event.get("item", {})
                last_item_type = item.get("type", "")
            elif event_type == "turn.completed":
                has_turn_completed = True
            elif event_type == "error":
                has_error_event = True
            # thread.started and other informational events are ignored

        if not has_any_event:
            return "non_json"

        # A completed turn with a final non-error item is a success.
        if has_turn_completed and last_item_type is not None and last_item_type != "error":
            return "succeeded"

        # A completed turn with a final error item is a failure.
        if has_turn_completed and last_item_type == "error":
            return "failed"

        # No turn.completed but the last item completion was an error → failed.
        if last_item_type == "error":
            return "failed"

        # No turn.completed and last item type is not error → succeed.
        if last_item_type is not None:
            return "succeeded"

        # Bare error event with no item completion.
        if has_error_event:
            return "failed"

        # Zero exit but no completion event = non_json.
        return "non_json"

    # Unknown agent
    return "unavailable"


def acknowledge_response(response: RealCLIResponse) -> bool:
    """Acknowledge a received response.

    In the real CLI integration, acknowledgement is implicit upon
    successful response capture. This is a no-op that returns True.
    """
    return response.status in ("succeeded", "failed", "timeout")


# ── Opt-In Guard Integration ──────────────────────────────────────────

# Export the guard functions for use in tests
__all__ = [
    "is_enabled",
    "reason",
    "skip_unless_real_cli",
    "RealCLITaskRequest",
    "RealCLIResponse",
    "request_task",
    "acknowledge_response",
]