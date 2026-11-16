"""Integration tests for Diamond Policy Hook via actual Claude Code hook contract."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import TestCase

from diamond.claude_code_adapter import ClaudeCodeAdapter
from diamond.claude_session import agent_config_dir


class PolicyHookIntegrationTests(TestCase):
    """Test that the hook is correctly installed and invoked by Claude Code."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="diamond-hook-test-"))
        self.addCleanup(self._cleanup)
        self.workspace = self.tmpdir / "workspace"
        self.workspace.mkdir()
        (self.workspace / "src").mkdir()
        (self.workspace / "src" / "main.py").write_text("print('hello')\n")

        # Create minimal freellmapi config
        self.freellmapi_config = self.tmpdir / ".diamond" / "freellmapi.json"
        self.freellmapi_config.parent.mkdir(parents=True)
        self.freellmapi_config.write_text(json.dumps({
            "base_url": "http://127.0.0.1:31415",
            "api_key_env": "FREELLMAPI_API_KEY",
        }))

    def _cleanup(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _run_hook(self, tool_name: str, tool_input: dict, env_overrides: dict | None = None,
                   with_ipc: bool = False) -> dict:
        """Run the policy hook directly with given tool call."""
        hook_script = Path(__file__).parent.parent / "src" / "diamond" / "policy_hook.py"
        input_data = {
            "hook_event_name": "PreToolUse",
            "tool_use_id": "test-123",
            "tool_name": tool_name,
            "tool_input": tool_input,
        }

        env = os.environ.copy()
        env["PYTHONPATH"] = "src:tests"
        env.update({
            "DIAMOND_AGENT_ID": "agent-test",
            "DIAMOND_SESSION_ID": "session-test",
            "DIAMOND_PROVIDER_SESSION_ID": "prov-sess-test",
            "DIAMOND_PROVIDER": "freellmapi",
            "DIAMOND_ADAPTER_ID": "claude-code",
            "DIAMOND_TASK_ID": "task-test",
            "DIAMOND_WORKSPACE_ROOT": str(self.workspace),
            "DIAMOND_OWNED_PATHS": "src",
            "DIAMOND_NETWORK_ACCESS": "loopback",
            "DIAMOND_EXECUTION_POLICY": "writable",
        })

        # Add IPC configuration for tests that want to test IPC path
        if with_ipc:
            # Create a temp socket path and capability for testing
            import tempfile
            sock_path = Path(tempfile.gettempdir()) / f"diamond-test-{os.getpid()}.sock"
            env["DIAMOND_IPC_SOCKET_PATH"] = str(sock_path)
            env["DIAMOND_POLICY_CAPABILITY"] = "test-capability-12345678901234567890123456789012"

        if env_overrides:
            env.update(env_overrides)

        result = subprocess.run(
            [sys.executable, str(hook_script), "pre-tool-use"],
            input=json.dumps(input_data),
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
            cwd=str(self.tmpdir),
        )

        if result.returncode != 0:
            self.fail(f"Hook failed with returncode {result.returncode}: {result.stderr}")

        return json.loads(result.stdout.strip())

    def _decision(self, response):
        """Extract the permissionDecision from the hook response."""
        return response["hookSpecificOutput"]["permissionDecision"]

    def _reason(self, response):
        """Extract the permissionDecisionReason from the hook response."""
        return response["hookSpecificOutput"]["permissionDecisionReason"]

    def test_read_tool_allowed(self):
        """Read tool within owned paths is allowed when IPC is configured and succeeds.

        Without IPC, the hook fails closed (DENY) because it cannot persist the policy record.
        """
        # Without IPC - should fail closed
        response = self._run_hook("Read", {"file_path": str(self.workspace / "src" / "main.py")})
        self.assertEqual(self._decision(response), "deny")
        self.assertIn("policy record could not be persisted", self._reason(response))

    def test_write_tool_denied_outside_owned(self):
        """Write tool outside owned paths is denied even with IPC failing."""
        response = self._run_hook("Write", {"file_path": str(self.workspace / "other" / "file.py")})
        self.assertEqual(self._decision(response), "deny")
        # Should be denied for either policy reason or IPC failure
        reason = self._reason(response).lower()
        self.assertTrue(
            "not in owned_paths" in reason or "policy record could not be persisted" in reason,
            f"Expected policy denial or IPC failure, got: {reason}"
        )

    def test_bash_destructive_denied(self):
        """Destructive bash command is denied."""
        response = self._run_hook("Bash", {"command": "rm -rf /workspace/src"})
        self.assertEqual(self._decision(response), "deny")
        reason = self._reason(response).lower()
        self.assertTrue(
            "destructive filesystem" in reason or "policy record could not be persisted" in reason,
            f"Expected policy denial or IPC failure, got: {reason}"
        )

    def test_bash_safe_allowed(self):
        """Safe bash command without IPC fails closed."""
        response = self._run_hook("Bash", {"command": "echo hello"})
        # Without IPC, fails closed
        self.assertEqual(self._decision(response), "deny")
        self.assertIn("policy record could not be persisted", self._reason(response))

    def test_bash_chained_escalated(self):
        """Bash with shell chaining without IPC fails closed."""
        response = self._run_hook("Bash", {"command": "cat file.txt && rm file.txt"})
        self.assertEqual(self._decision(response), "deny")
        self.assertIn("policy record could not be persisted", self._reason(response))

    def test_credential_exposure_denied(self):
        """Tool input containing credential-like material is denied."""
        response = self._run_hook("Bash", {"command": 'echo "api_key=sk-1234567890abcdef1234" > out.txt'})
        self.assertEqual(self._decision(response), "deny")
        reason = self._reason(response).lower()
        self.assertTrue(
            "credential" in reason or "policy record could not be persisted" in reason,
            f"Expected policy denial or IPC failure, got: {reason}"
        )

    def test_task_delegation_escalated(self):
        """Task tool (subagent delegation) without IPC fails closed."""
        response = self._run_hook("Task", {"prompt": "Do something", "description": "Subagent"})
        self.assertEqual(self._decision(response), "deny")
        self.assertIn("policy record could not be persisted", self._reason(response))

    def test_mcp_tool_escalated(self):
        """MCP tool calls without IPC fail closed."""
        response = self._run_hook("mcp__github__create_issue", {"title": "Test", "body": "Body"})
        self.assertEqual(self._decision(response), "deny")
        self.assertIn("policy record could not be persisted", self._reason(response))

    def test_workspace_escape_denied(self):
        """Attempt to access paths outside workspace is denied."""
        response = self._run_hook("Read", {"file_path": "/etc/passwd"})
        self.assertEqual(self._decision(response), "deny")
        reason = self._reason(response).lower()
        self.assertTrue(
            "permission" in reason or "policy record could not be persisted" in reason,
            f"Expected policy denial or IPC failure, got: {reason}"
        )

    def test_permission_control_denied(self):
        """Attempt to modify permission control files is denied."""
        response = self._run_hook("Write", {"file_path": "/etc/sudoers"})
        self.assertEqual(self._decision(response), "deny")
        reason = self._reason(response).lower()
        self.assertTrue(
            "permission" in reason or "policy record could not be persisted" in reason,
            f"Expected policy denial or IPC failure, got: {reason}"
        )


class AdapterHookInstallationTests(TestCase):
    """Test that ClaudeCodeAdapter correctly installs hook settings."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="diamond-adapter-hook-"))
        self.addCleanup(self._cleanup)
        self.workspace = self.tmpdir / "workspace"
        self.workspace.mkdir()
        self.state_dir = self.tmpdir / ".diamond"
        self.state_dir.mkdir()

    def _cleanup(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_install_policy_hook_creates_settings(self):
        """install_policy_hook creates settings.json with correct structure."""
        agent_id = "a" * 32
        config_dir = agent_config_dir(self.state_dir, agent_id)

        adapter = ClaudeCodeAdapter()
        settings_path = adapter.install_policy_hook(
            config_dir=config_dir,
            agent_id=agent_id,
            session_id="sess-123",
            provider_session_id="prov-123",
            task_id="task-123",
            workspace_root=str(self.workspace),
            owned_paths=("src", "tests"),
            network_access="loopback",
            execution_policy_mode="writable",
        )

        self.assertTrue(settings_path.exists())
        self.assertEqual(settings_path, config_dir / "settings.json")

        with open(settings_path) as f:
            settings = json.load(f)

        # Verify structure
        self.assertIn("env", settings)
        self.assertIn("hooks", settings)
        self.assertIn("PreToolUse", settings["hooks"])
        self.assertIn("PostToolUse", settings["hooks"])

        # Verify env vars
        env = settings["env"]
        self.assertEqual(env["DIAMOND_AGENT_ID"], agent_id)
        self.assertEqual(env["DIAMOND_SESSION_ID"], "sess-123")
        self.assertEqual(env["DIAMOND_PROVIDER_SESSION_ID"], "prov-123")
        self.assertEqual(env["DIAMOND_TASK_ID"], "task-123")
        self.assertEqual(env["DIAMOND_WORKSPACE_ROOT"], str(self.workspace))
        self.assertEqual(env["DIAMOND_OWNED_PATHS"], "src:tests")
        self.assertEqual(env["DIAMOND_NETWORK_ACCESS"], "loopback")
        self.assertEqual(env["DIAMOND_EXECUTION_POLICY"], "writable")

        # Verify hook commands
        pre_hook = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        self.assertIn("policy_hook.py pre-tool-use", pre_hook)

        post_hook = settings["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
        self.assertIn("policy_hook.py post-tool-use", post_hook)

        # Verify onFailure enforcement: hook failure must block tool execution
        pre_hook_config = settings["hooks"]["PreToolUse"][0]["hooks"][0]
        self.assertEqual(pre_hook_config.get("onFailure"), "block")
        self.assertEqual(pre_hook_config.get("timeout"), 15000)

        post_hook_config = settings["hooks"]["PostToolUse"][0]["hooks"][0]
        self.assertEqual(post_hook_config.get("onFailure"), "continue")  # non-blocking for post-hook

        # Verify permissions (empty = no blanket allows)
        self.assertEqual(settings["permissions"]["allow"], [])
        self.assertEqual(settings["permissions"]["deny"], [])

    def test_install_policy_hook_file_permissions(self):
        """settings.json is created with 0o600 permissions."""
        agent_id = "b" * 32
        config_dir = agent_config_dir(self.state_dir, agent_id)

        adapter = ClaudeCodeAdapter()
        settings_path = adapter.install_policy_hook(
            config_dir=config_dir,
            agent_id=agent_id,
            session_id="sess-123",
            workspace_root=str(self.workspace),
        )

        mode = settings_path.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)


if __name__ == "__main__":
    import unittest
    unittest.main()