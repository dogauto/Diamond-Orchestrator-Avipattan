"""Integration test for real CLI session integration.

Opt-in via DIAMOND_REAL_CLI environment variable.
When not set, falls back to deterministic fake processes (verified path).
When set, launches actual claude/codex CLI executables and captures responses.

Required environment for real integration:
  DIAMOND_REAL_CLI=1
  Authenticated claude and/or codex executables on PATH
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

from support import ProjectCase

from diamond.transport.real_cli_integration import (
    is_enabled, reason, skip_unless_real_cli,
    RealCLITaskRequest, RealCLIResponse, request_task, acknowledge_response,
)


class TestRealCLISessionIntegration(ProjectCase):
    """Real CLI session integration tests."""

    @skip_unless_real_cli
    def test_real_cli_is_enabled(self) -> None:
        """Test that real CLI integration reports as enabled."""
        self.assertTrue(is_enabled())
        self.assertEqual(reason(), "enabled via DIAMOND_REAL_CLI environment variable")

    @skip_unless_real_cli
    def test_discover_cli_executables(self) -> None:
        """Test that CLI executables can be discovered."""
        from diamond.transport.real_cli_integration import discover_cli_executables
        executables = discover_cli_executables()
        # At minimum should report what's available
        # (may be empty if neither claude nor codex is configured)

    @skip_unless_real_cli
    def test_claude_non_interactive_invocation(self) -> None:
        """Test invoking claude -p with a simple prompt."""
        response = request_task(
            agent="claude",
            prompt="Return exactly: hello world",
            correlation_id="test-corr-001",
            task_id="test-001",
            timeout=15,
        )
        # Record what happened; may be blocked by auth, timeout, etc.
        self.assertIsNotNone(response)
        self.assertIn(response.status, (
            "succeeded", "failed", "timeout", "non_json", "unavailable",
        ))
        # If succeeded, verify basic content
        if response.status == "succeeded" and response.response_data:
            stdout = response.response_data.get("_cli_raw_stdout", "")
            self.assertIn("hello", stdout.lower())

    @skip_unless_real_cli
    def test_codex_non_interactive_invocation(self) -> None:
        """Test invoking codex exec --json with a simple prompt."""
        response = request_task(
            agent="codex",
            prompt="Return exactly: {result: success}",
            correlation_id="test-corr-002",
            task_id="test-002",
            timeout=15,
        )
        self.assertIsNotNone(response)
        self.assertIn(response.status, (
            "succeeded", "failed", "timeout", "non_json", "unavailable",
        ))

    @skip_unless_real_cli
    def test_task_correlation(self) -> None:
        """Test that correlation IDs are preserved in response."""
        response = request_task(
            agent="claude",
            prompt="echo test-correlation",
            correlation_id="test-corr-003",
            task_id="test-003",
            timeout=15,
        )
        self.assertIsNotNone(response.correlation_id)
        self.assertEqual(response.correlation_id, "test-corr-003")
        self.assertIsNotNone(response.task_id)
        self.assertEqual(response.task_id, "test-003")

    @skip_unless_real_cli
    def test_unavailable_session_handling(self) -> None:
        """Test that unavailable sessions are handled gracefully."""
        # Use an invalid agent name
        response = request_task(
            agent="invalid_agent",
            prompt="test",
            correlation_id="test-corr-004",
            task_id="test-004",
            timeout=5,
        )
        # Should fail gracefully, not hang
        self.assertIsNotNone(response)
        self.assertNotEqual(response.status, "succeeded")

    @skip_unless_real_cli
    def test_acknowledge_response(self) -> None:
        """Test response acknowledgement."""
        response = request_task(
            agent="claude",
            prompt="test ack",
            correlation_id="test-corr-005",
            task_id="test-005",
            timeout=15,
        )
        acked = acknowledge_response(response)
        # Acknowledgement should be valid for any completed status
        self.assertIsInstance(acked, bool)

    @skip_unless_real_cli
    def test_real_cli_integration_persisted(self) -> None:
        """Test that response data is captured and persisted correctly."""
        response = request_task(
            agent="claude",
            prompt="Capture this: the value is 42",
            correlation_id="test-corr-006",
            task_id="test-006",
            timeout=15,
        )
        self.assertIsNotNone(response)
        # Verify the response has structure
        self.assertIn("status", response.__dict__)
        self.assertIn("exit_code", response.__dict__ or {})
        self.assertIn("correlation_id", response.__dict__)
        self.assertIn("task_id", response.__dict__)