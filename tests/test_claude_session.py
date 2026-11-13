"""Tests for persistent Claude Code session foundation — Phase 4A.

Verifies:
- Session id validation (UUID format, controller-owned identity)
- Per-agent ``CLAUDE_CONFIG_DIR`` isolation
- New-conversation invocation uses ``--session-id`` and validates echo
- Continued conversation uses ``--resume`` with persisted provider_session_id
- Controller never trusts provider output as session identity without validation
- Fallback behavior when no controller-owned session is in play
"""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from diamond.claude_code_adapter import (
    ClaudeCodeAdapter,
    ClaudeCodeRuntimeConfig,
    SESSION_ID_HEADER,
)
from diamond.claude_session import (
    agent_config_dir,
    assert_session_id_matches,
    optional_provider_session_id,
    validate_agent_id,
    validate_provider_session_id,
)
from diamond.errors import ValidationError
from diamond.provider_contracts import ExecutionMode, TaskRequirements
from diamond.provider_execution import (
    ExecutionOutcome,
    ExecutionPolicy,
    ExecutionPolicyMode,
    ProviderRawExecution,
    TaskExecutionRequest,
)
from diamond.validation import utc_now


def _make_request(
    task_id: str,
    correlation_id: str,
    *,
    continuation_session_id: str | None = None,
) -> TaskExecutionRequest:
    return TaskExecutionRequest(
        task_id=task_id,
        correlation_id=correlation_id,
        input_text="test prompt",
        requirements=TaskRequirements(),
        execution_mode=ExecutionMode.ONE_SHOT,
        timeout_seconds=30,
        continuation_session_id=continuation_session_id,
        execution_policy=ExecutionPolicy(
            ExecutionPolicyMode.READ_ONLY, str(Path.cwd())
        ),
    )


class TestSessionIdValidation(unittest.TestCase):
    """Validation of provider session ids before persistence."""

    def test_valid_uuid_is_accepted(self) -> None:
        uid = "550e8400-e29b-41d4-a716-446655440000"
        self.assertEqual(validate_provider_session_id(uid), uid)

    def test_uppercase_hex_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            validate_provider_session_id("550E8400-E29B-41D4-A716-446655440000")

    def test_non_uuid_string_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            validate_provider_session_id("not-a-uuid")

    def test_none_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            validate_provider_session_id(None)

    def test_optional_returns_none_for_none(self) -> None:
        self.assertIsNone(optional_provider_session_id(None))

    def test_optional_delegates_to_validator(self) -> None:
        uid = "550e8400-e29b-41d4-a716-446655440000"
        self.assertEqual(optional_provider_session_id(uid), uid)


class TestAgentIdValidation(unittest.TestCase):
    """Validation of agent identifiers."""

    def test_32_hex_chars_is_accepted(self) -> None:
        aid = "a" * 32
        self.assertEqual(validate_agent_id(aid), aid)

    def test_short_id_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            validate_agent_id("not-enough-chars")

    def test_non_hex_chars_are_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            validate_agent_id("gg" * 16)


class TestAgentConfigDir(unittest.TestCase):
    """Per-agent CLAUDE_CONFIG_DIR resolution."""

    def test_resolves_correct_path(self) -> None:
        aid = "a" * 32
        expected = Path("/tmp/state/agents/" + aid + "/claude-config")
        self.assertEqual(agent_config_dir(Path("/tmp/state"), aid), expected)

    def test_rejects_traversal_in_agent_id(self) -> None:
        with self.assertRaises(ValidationError):
            agent_config_dir(Path("/tmp/state"), "../../../etc/passwd")

    def test_rejects_non_hex_agent_id(self) -> None:
        with self.assertRaises(ValidationError):
            agent_config_dir(Path("/tmp/state"), "not32hexchars!!!")


class TestSessionIdentityValidation(unittest.TestCase):
    """Controller-owned session identity validation."""

    def test_returns_value_when_no_controller_session(self) -> None:
        uid = "550e8400-e29b-41d4-a716-446655440000"
        self.assertEqual(assert_session_id_matches(None, uid), uid)

    def test_matches_controller_expected_id(self) -> None:
        uid = "550e8400-e29b-41d4-a716-446655440000"
        self.assertEqual(assert_session_id_matches(uid, uid), uid)

    def test_rejects_mismatched_id(self) -> None:
        with self.assertRaises(ValidationError):
            assert_session_id_matches(
                "550e8400-e29b-41d4-a716-446655440000",
                "660e8400-e29b-41d4-a716-446655440001",
            )

    def test_rejects_none_returned_when_controller_expected(self) -> None:
        with self.assertRaises(ValidationError):
            assert_session_id_matches("550e8400-e29b-41d4-a716-446655440000", None)

    def test_rejects_invalid_format(self) -> None:
        with self.assertRaises(ValidationError):
            assert_session_id_matches(None, "not-a-uuid")


class TestClaudeCodeAdapterSessionCommands(unittest.TestCase):
    """Adapter invocation uses --session-id and --resume correctly."""

    def _make_adapter(
        self, runtime_config: ClaudeCodeRuntimeConfig | None = None
    ) -> ClaudeCodeAdapter:
        return ClaudeCodeAdapter("/fake/claude", runtime_config)

    def test_new_conversation_includes_session_id_flag(self) -> None:
        uid = "550e8400-e29b-41d4-a716-446655440000"
        config = ClaudeCodeRuntimeConfig(
            "http://127.0.0.1:31415", "fixture-token", session_id=uid
        )
        adapter = self._make_adapter(config)

        with patch("subprocess.Popen") as mock_popen:
            process = MagicMock()
            process.poll.return_value = 0
            process.communicate.return_value = (
                '{"result":"ok","session_id":"'
                + uid
                + '"}',
                "",
            )
            process.returncode = 0
            mock_popen.return_value = process

            request = _make_request("task-1", "corr-1")
            result = adapter.execute(request)

            self.assertEqual(result.outcome, ExecutionOutcome.SUCCEEDED)
            called_args = mock_popen.call_args[0][0]
            self.assertIn("--session-id", called_args)
            self.assertIn(uid, called_args)

    def test_continued_conversation_uses_resume_flag(self) -> None:
        uid = "550e8400-e29b-41d4-a716-446655440000"
        config = ClaudeCodeRuntimeConfig(
            "http://127.0.0.1:31415", "fixture-token"
        )
        adapter = self._make_adapter(config)

        with patch("subprocess.Popen") as mock_popen:
            process = MagicMock()
            process.poll.return_value = 0
            process.communicate.return_value = (
                '{"result":"ok","session_id":"'
                + uid
                + '"}',
                "",
            )
            process.returncode = 0
            mock_popen.return_value = process

            request = _make_request("task-2", "corr-2", continuation_session_id=uid)
            result = adapter.execute(request)

            self.assertEqual(result.outcome, ExecutionOutcome.SUCCEEDED)
            called_args = mock_popen.call_args[0][0]
            self.assertIn("--resume", called_args)
            self.assertIn(uid, called_args)
            self.assertNotIn("--session-id", called_args)

    def test_claude_config_dir_set_when_configured(self) -> None:
        aid = "a" * 32
        config_dir = Path("/tmp/agents/" + aid + "/claude-config")
        config = ClaudeCodeRuntimeConfig(
            "http://127.0.0.1:31415", "fixture-token", agent_config_dir=config_dir
        )
        adapter = self._make_adapter(config)

        with patch("subprocess.Popen") as mock_popen:
            process = MagicMock()
            process.poll.return_value = 0
            process.communicate.return_value = ('{"result":"ok"}', "")
            process.returncode = 0
            mock_popen.return_value = process

            request = _make_request("task-3", "corr-3")
            adapter.execute(request)

            _, kwargs = mock_popen.call_args
            env = kwargs["env"]
            self.assertEqual(env["CLAUDE_CONFIG_DIR"], str(config_dir))

    def test_claude_config_dir_not_set_when_not_configured(self) -> None:
        config = ClaudeCodeRuntimeConfig(
            "http://127.0.0.1:31415", "fixture-token"
        )
        adapter = self._make_adapter(config)

        with patch("subprocess.Popen") as mock_popen:
            process = MagicMock()
            process.poll.return_value = 0
            process.communicate.return_value = ('{"result":"ok"}', "")
            process.returncode = 0
            mock_popen.return_value = process

            request = _make_request("task-4", "corr-4")
            adapter.execute(request)

            _, kwargs = mock_popen.call_args
            env = kwargs["env"]
            self.assertNotIn("CLAUDE_CONFIG_DIR", env)

    def test_normalize_result_validates_session_id_on_success(self) -> None:
        uid = "550e8400-e29b-41d4-a716-446655440000"
        adapter = self._make_adapter(
            ClaudeCodeRuntimeConfig(
                "http://127.0.0.1:31415", "fixture-token", session_id=uid
            )
        )

        raw = ProviderRawExecution(
            provider_id="freellmapi",
            task_id="task-5",
            correlation_id="corr-5",
            outcome=ExecutionOutcome.SUCCEEDED,
            started_at=utc_now(),
            completed_at=utc_now(),
            exit_code=0,
            stdout='{"result":"ok","session_id":"' + uid + '"}',
            process_id=123,
        )
        request = _make_request("task-5", "corr-5")
        normalized = adapter.normalize_result(request, raw)

        self.assertEqual(normalized.session_id, uid)

    def test_normalize_result_rejects_session_id_mismatch(self) -> None:
        config = ClaudeCodeRuntimeConfig(
            "http://127.0.0.1:31415", "fixture-token",
            session_id="550e8400-e29b-41d4-a716-446655440000",
        )
        adapter = self._make_adapter(config)

        raw = ProviderRawExecution(
            provider_id="freellmapi",
            task_id="task-6",
            correlation_id="corr-6",
            outcome=ExecutionOutcome.SUCCEEDED,
            started_at=utc_now(),
            completed_at=utc_now(),
            exit_code=0,
            stdout='{"result":"ok","session_id":"660e8400-e29b-41d4-a716-446655440001"}',
            process_id=123,
        )
        request = _make_request(
            "task-6", "corr-6",
            continuation_session_id="550e8400-e29b-41d4-a716-446655440000",
        )
        with self.assertRaises(ValidationError):
            adapter.normalize_result(request, raw)

    def test_normalize_result_allows_non_success_without_validation(self) -> None:
        adapter = self._make_adapter(
            ClaudeCodeRuntimeConfig(
                "http://127.0.0.1:31415", "fixture-token",
                session_id="550e8400-e29b-41d4-a716-446655440000",
            )
        )

        raw = ProviderRawExecution(
            provider_id="freellmapi",
            task_id="task-7",
            correlation_id="corr-7",
            outcome=ExecutionOutcome.TIMEOUT,
            started_at=utc_now(),
            completed_at=utc_now(),
            exit_code=-1,
            stdout="",
        )
        request = _make_request(
            "task-7", "corr-7",
            continuation_session_id="550e8400-e29b-41d4-a716-446655440000",
        )
        normalized = adapter.normalize_result(request, raw)

        # No validation on non-success outcomes; the controller's known id
        # stands so the persistent session identity survives the attempt.
        self.assertEqual(
            normalized.session_id, "550e8400-e29b-41d4-a716-446655440000"
        )

    def test_runtime_config_rejects_traversal_in_agent_config_dir(self) -> None:
        with self.assertRaises(ValidationError):
            ClaudeCodeRuntimeConfig(
                "http://127.0.0.1:31415",
                "fixture-token",
                agent_config_dir=Path("../../etc"),
            )

    def test_runtime_config_accepts_valid_agent_config_dir(self) -> None:
        config = ClaudeCodeRuntimeConfig(
            "http://127.0.0.1:31415",
            "fixture-token",
            agent_config_dir=Path("/tmp/state/agents/aaaa/claude-config"),
        )
        self.assertEqual(
            config.agent_config_dir,
            Path("/tmp/state/agents/aaaa/claude-config"),
        )


class TestSessionIdHeader(unittest.TestCase):
    """Verify the documented session id header constant."""

    def test_header_constant(self) -> None:
        self.assertEqual(SESSION_ID_HEADER, "session_id")


if __name__ == "__main__":
    unittest.main()
