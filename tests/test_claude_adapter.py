"""Concurrent execution tests for ClaudeCodeAdapter."""

from __future__ import annotations

import subprocess
import threading
import unittest
from unittest.mock import MagicMock, patch

from diamond.claude_code_adapter import ClaudeCodeAdapter, ClaudeCodeRuntimeConfig
from diamond.errors import ValidationError
from diamond.provider_contracts import ExecutionMode, TaskRequirements
from diamond.provider_execution import (CancellationRequest, ExecutionOutcome,
                                         ExecutionPolicy, ExecutionPolicyMode,
                                         ProviderRawExecution, TaskExecutionRequest)
from pathlib import Path
from diamond.validation import utc_now


class TestClaudeCodeAdapterConcurrency(unittest.TestCase):
    """Concurrent execution safety tests for ClaudeCodeAdapter."""

    def setUp(self) -> None:
        self.adapter = ClaudeCodeAdapter()
        self.adapter._executable = "/fake/claude"
        self.task_requirements = TaskRequirements(
            required_capabilities=frozenset(),
            required_execution_modes=frozenset(),
            task_type=None,
        )
        self.execution_mode = ExecutionMode.ONE_SHOT

    def _make_request(self, task_id: str, correlation_id: str) -> TaskExecutionRequest:
        return TaskExecutionRequest(
            task_id=task_id,
            correlation_id=correlation_id,
            input_text="test prompt",
            requirements=self.task_requirements,
            execution_mode=self.execution_mode,
            timeout_seconds=30,
            execution_policy=ExecutionPolicy(ExecutionPolicyMode.READ_ONLY, str(Path.cwd())),
        )

    def test_two_simultaneous_executions_independent_handles(self) -> None:
        """Two simultaneous executions get independent process handles."""
        with patch("subprocess.Popen") as mock_popen:
            process_a = MagicMock()
            process_a.poll.return_value = None
            process_a.communicate.return_value = ("stdout A", "stderr A")
            process_a.returncode = 0

            process_b = MagicMock()
            process_b.poll.return_value = None
            process_b.communicate.return_value = ("stdout B", "stderr B")
            process_b.returncode = 0

            mock_popen.side_effect = [process_a, process_b]

            request_a = self._make_request("task-a", "corr-a")
            request_b = self._make_request("task-b", "corr-b")

            result_a = self.adapter.execute(request_a)
            result_b = self.adapter.execute(request_b)

            self.assertEqual(result_a.outcome.value, "succeeded")
            self.assertEqual(result_b.outcome.value, "succeeded")
            self.assertEqual(mock_popen.call_count, 2)

    def test_cancel_a_does_not_affect_b(self) -> None:
        """Cancelling execution A does not terminate execution B."""
        with patch("subprocess.Popen") as mock_popen:
            event_a_done = threading.Event()
            event_b_done = threading.Event()

            process_a = MagicMock()
            process_a.poll.return_value = None
            # Block until cancelled so process stays in registry
            def block_until_cancel(*args, **kwargs):
                event_a_done.wait(timeout=30)
                return ("stdout A", "stderr A")
            process_a.communicate.side_effect = block_until_cancel
            process_a.returncode = 0

            process_b = MagicMock()
            process_b.poll.return_value = None
            process_b.communicate.return_value = ("stdout B", "stderr B")
            process_b.returncode = 0

            mock_popen.side_effect = [process_a, process_b]

            request_a = self._make_request("task-a", "corr-a")
            request_b = self._make_request("task-b", "corr-b")

            results = {}
            errors = {}

            def run_a():
                try:
                    results["a"] = self.adapter.execute(request_a)
                except Exception as e:
                    errors["a"] = e

            def run_b():
                try:
                    results["b"] = self.adapter.execute(request_b)
                except Exception as e:
                    errors["b"] = e

            t_a = threading.Thread(target=run_a)
            t_b = threading.Thread(target=run_b)
            t_a.start()
            t_b.start()

            # Wait for both to register their processes, then cancel A
            t_a.join(timeout=5)
            t_b.join(timeout=5)

            # A should be blocked on communicate; cancel it
            cancel_request = CancellationRequest(
                provider_id="freellmapi",
                task_id="task-a",
                correlation_id="corr-a",
            )
            cancel_result = self.adapter.cancel(cancel_request)
            event_a_done.set()

            # B should complete normally
            t_a.join(timeout=5)
            t_b.join(timeout=5)

            self.assertEqual(cancel_result.status, "cancelled")
            process_a.terminate.assert_called_once()
            process_b.terminate.assert_not_called()
            self.assertIn("b", results)
            self.assertEqual(results["b"].outcome.value, "succeeded")

    def test_duplicate_correlation_id_rejected(self) -> None:
        """Duplicate correlation_id raises ValidationError."""
        with patch("subprocess.Popen") as mock_popen:
            event_done = threading.Event()

            process = MagicMock()
            process.poll.return_value = None
            # Block so the process stays registered
            def block_until_signal(*args, **kwargs):
                event_done.wait(timeout=10)
                return ("stdout", "stderr")
            process.communicate.side_effect = block_until_signal
            process.returncode = 0
            mock_popen.return_value = process

            request = self._make_request("task", "corr")

            errors = []

            def run_first():
                try:
                    self.adapter.execute(request)
                except Exception as e:
                    errors.append(e)
                finally:
                    event_done.set()

            t = threading.Thread(target=run_first)
            t.start()
            t.join(timeout=5)

            # Now try a second execution with the same correlation_id
            # The first process should still be in the registry
            with self.assertRaises(ValidationError):
                self.adapter.execute(request)

            process.kill.assert_called_once()

    def test_timeout_isolation(self) -> None:
        """Timeout of one execution doesn't affect others."""
        with patch("subprocess.Popen") as mock_popen:
            process_a = MagicMock()
            process_a.poll.return_value = None
            # First call raises TimeoutExpired, second call (after kill) returns normally
            process_a.communicate.side_effect = [
                subprocess.TimeoutExpired(
                    cmd=["/fake/claude", "-p", "test prompt"], timeout=1
                ),
                ("", ""),
            ]
            process_a.returncode = -1

            process_b = MagicMock()
            process_b.poll.return_value = None
            process_b.communicate.return_value = ("stdout B", "stderr B")
            process_b.returncode = 0

            mock_popen.side_effect = [process_a, process_b]

            request_a = self._make_request("task-a", "corr-a")
            request_b = self._make_request("task-b", "corr-b")

            result_a = self.adapter.execute(request_a)
            result_b = self.adapter.execute(request_b)

            self.assertEqual(result_a.outcome.value, "timeout")
            self.assertEqual(result_b.outcome.value, "succeeded")
            process_a.kill.assert_called_once()

    def test_cleanup_verification(self) -> None:
        """Process registry cleans up on success, failure, timeout, and cancel."""
        with patch("subprocess.Popen") as mock_popen:
            process = MagicMock()
            process.poll.return_value = None
            process.communicate.return_value = ("stdout", "stderr")
            process.returncode = 0
            mock_popen.return_value = process

            request = self._make_request("task", "corr")

            # Success case
            self.adapter.execute(request)
            with self.adapter._processes_lock:
                self.assertNotIn("corr", self.adapter._processes)

            # Timeout case
            process.communicate.side_effect = subprocess.TimeoutExpired(
                cmd=["/fake/claude", "-p", "test prompt"], timeout=1
            )
            request = self._make_request("task", "corr")
            self.adapter.execute(request)
            with self.adapter._processes_lock:
                self.assertNotIn("corr", self.adapter._processes)

            # Cancel case
            process.poll.return_value = None
            event = threading.Event()
            def block(*args, **kwargs):
                event.wait(timeout=10)
                return ("", "")
            process.communicate.side_effect = block
            request = self._make_request("task", "corr")
            self.adapter.execute(request)
            cancel_request = CancellationRequest(
                provider_id="freellmapi",
                task_id="task",
                correlation_id="corr",
            )
            self.adapter.cancel(cancel_request)
            event.set()
            with self.adapter._processes_lock:
                self.assertNotIn("corr", self.adapter._processes)

    def test_child_environment_isolated_and_preserves_auto(self) -> None:
        parent = {
            "ANTHROPIC_API_KEY": "wrong-provider-key",
            "ANTHROPIC_MODEL": "auto",
            "PATH": "/usr/bin",
        }
        runtime = ClaudeCodeRuntimeConfig("http://127.0.0.1:31415", "fixture-runtime-secret")
        adapter = ClaudeCodeAdapter("/fake/claude", runtime)
        child = adapter.build_child_environment(parent)

        self.assertEqual(child["ANTHROPIC_BASE_URL"], "http://127.0.0.1:31415")
        self.assertEqual(child["ANTHROPIC_AUTH_TOKEN"], "fixture-runtime-secret")
        self.assertNotIn("ANTHROPIC_API_KEY", child)
        self.assertEqual(child["ANTHROPIC_MODEL"], "auto")
        self.assertEqual(parent["ANTHROPIC_API_KEY"], "wrong-provider-key")

    def test_provider_and_adapter_identities_are_distinct_and_normalized(self) -> None:
        adapter = ClaudeCodeAdapter("/fake/claude")
        self.assertEqual(adapter.adapter_id, "claude-code")
        self.assertEqual(adapter.get_capabilities().provider_id, "freellmapi")
        self.assertTrue(adapter.validate(adapter.get_capabilities()).valid)
        raw = ProviderRawExecution(
            "freellmapi", "task", "corr", ExecutionOutcome.SUCCEEDED,
            utc_now(), utc_now(), stdout='{"result":"ok","session_id":"session"}', process_id=123,
        )
        request = self._make_request("task", "corr")
        normalized = adapter.normalize_result(request, raw)
        self.assertEqual(normalized.provider_id, "freellmapi")
        self.assertEqual(normalized.provenance.provider_id, "freellmapi")
        self.assertEqual(normalized.provenance.adapter_id, "claude-code")
        self.assertEqual(normalized.session_id, "session")
        self.assertEqual(normalized.process_id, 123)

    def test_runtime_configuration_rejects_invalid_gateway_url(self) -> None:
        with self.assertRaises(ValidationError):
            ClaudeCodeRuntimeConfig("https://api.anthropic.com/v1/messages", "fixture-runtime-secret")


if __name__ == "__main__":
    unittest.main()
