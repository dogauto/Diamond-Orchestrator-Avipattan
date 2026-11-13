"""Live Policy Enforcement Integration Tests — End-to-End Verification.

These tests validate the complete execution path:
Agent → CLI Policy Hook → PolicyIPCClient → Diamond Policy Service → Controller Authorization → Tool Execution → EventStore Evidence

Unlike unit tests, these use real IPC transport and real EventStore persistence.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from unittest import TestCase

from diamond.policy_ipc import PolicyIPCServerContext, generate_capability
from diamond.store import EventStore
from diamond.paths import resolve_paths
from diamond.config import load_config
from diamond.schema import SCHEMA_VERSION, check_schema, migrate_schema
from diamond.validation import canonical_json, utc_now


class LivePolicyEnforcementTests(TestCase):
    """End-to-end tests proving Diamond controls tool execution via policy."""

    def setUp(self) -> None:
        self.tmpdir = Path(tempfile.mkdtemp(prefix="diamond-live-policy-"))
        self.addCleanup(self._cleanup)
        self.workspace = self.tmpdir / "workspace"
        self.workspace.mkdir()
        (self.workspace / "src").mkdir()
        (self.workspace / "src" / "main.py").write_text("print('hello')\n")

        # Create project config
        self.config_path = self.tmpdir / "config" / "diamond.toml"
        self.config_path.parent.mkdir(parents=True)
        # Use the repo's config as base
        repo_config = Path(__file__).parent.parent / "config" / "diamond.toml"
        shutil.copy(repo_config, self.config_path)

        # Create minimal freellmapi config
        self.freellmapi_config = self.tmpdir / ".diamond" / "freellmapi.json"
        self.freellmapi_config.parent.mkdir(parents=True)
        self.freellmapi_config.write_text(json.dumps({
            "base_url": "http://127.0.0.1:31415",
            "api_key_env": "FREELLMAPI_API_KEY",
        }))

        # Initialize EventStore with schema
        paths = resolve_paths(str(self.tmpdir), str(self.config_path))
        self.store = EventStore(paths.database)
        # Create database with full schema using check_schema with initialize=True
        with self.store._connection(write=True) as conn:
            from diamond.schema import check_schema
            check_schema(conn, initialize=True)

    def _cleanup(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _run_hook_with_ipc(
        self,
        tool_name: str,
        tool_input: dict,
        ipc_socket_path: Path,
        capability: str,
        agent_id: str = "agent-test",
        session_id: str = "session-test",
        task_id: str = "task-test",
        attempt_id: str | None = "attempt-test",
        owned_paths: tuple[str, ...] = ("src",),
        env_overrides: dict | None = None,
        tool_use_id: str | None = None,
    ) -> dict:
        """Run the policy hook with real IPC server."""
        hook_script = Path(__file__).parent.parent / "src" / "diamond" / "policy_hook.py"
        input_data = {
            "hook_event_name": "PreToolUse",
            "tool_use_id": tool_use_id or f"tool-{uuid.uuid4().hex[:8]}",
            "tool_name": tool_name,
            "tool_input": tool_input,
        }

        env = os.environ.copy()
        env["PYTHONPATH"] = "src:tests"
        env.update({
            "DIAMOND_AGENT_ID": agent_id,
            "DIAMOND_SESSION_ID": session_id,
            "DIAMOND_PROVIDER_SESSION_ID": "prov-sess-test",
            "DIAMOND_PROVIDER": "freellmapi",
            "DIAMOND_ADAPTER_ID": "claude-code",
            "DIAMOND_TASK_ID": task_id,
            "DIAMOND_ATTEMPT_ID": attempt_id or "",
            "DIAMOND_WORKSPACE_ROOT": str(self.workspace),
            "DIAMOND_OWNED_PATHS": ":".join(owned_paths),
            "DIAMOND_NETWORK_ACCESS": "loopback",
            "DIAMOND_EXECUTION_POLICY": "writable",
            "DIAMOND_IPC_SOCKET_PATH": str(ipc_socket_path),
            "DIAMOND_POLICY_CAPABILITY": capability,
        })

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

    def _decision(self, response: dict) -> str:
        return response["hookSpecificOutput"]["permissionDecision"]

    def _reason(self, response: dict) -> str:
        return response["hookSpecificOutput"]["permissionDecisionReason"]

    def _start_ipc_context(
        self,
        agent_id: str = "controller",
        task_id: str = "controller-task",
        attempt_id: str | None = None,
        command_prefix: str = "orchestrate:test",
    ) -> tuple[PolicyIPCServerContext, Path, str]:
        """Start a real IPC server context."""
        ipc_dir = self.tmpdir / "ipc"
        ipc_dir.mkdir(parents=True, exist_ok=True)
        # Keep socket path short to avoid AF_UNIX path too long
        socket_path = ipc_dir / "sock"

        ctx = PolicyIPCServerContext(
            socket_path=socket_path,
            store=self.store,
            agent_id=agent_id,
            task_id=task_id,
            attempt_id=attempt_id,
            command_prefix=command_prefix,
        )
        ctx.start()
        # Return the context's OWN capability, not a separately generated one.
        # PolicyIPCServerContext generates its capability internally in __init__;
        # the server validates against that value, so the hook must send it.
        return ctx, socket_path, ctx.ipc_capability

    def test_ALLOW_with_real_ipc(self) -> None:
        """A. ALLOW: Authorized operation → tool allowed, evidence persisted."""
        ctx, socket_path, capability = self._start_ipc_context(
            agent_id="agent-test",
            task_id="task-test",
            attempt_id="attempt-test",
        )
        try:
            response = self._run_hook_with_ipc(
                tool_name="Read",
                tool_input={"file_path": str(self.workspace / "src" / "main.py")},
                ipc_socket_path=socket_path,
                capability=capability,
            )
            self.assertEqual(self._decision(response), "allow")
            self.assertIn("Approved by Diamond policy", self._reason(response))

            # Verify evidence persisted in EventStore
            # Check runtime_events table for policy_decision
            with self.store._connection(write=False) as conn:
                rows = conn.execute(
                    "SELECT entity_type, event_type, payload_json FROM agent_runtime_events WHERE entity_type='policy_decision'"
                ).fetchall()
            self.assertGreater(len(rows), 0, "No policy decision evidence found")
            payload = json.loads(rows[0]["payload_json"])
            self.assertEqual(payload["decision"], "allow")
            self.assertEqual(payload["tool_name"], "Read")
            self.assertEqual(payload["agent_id"], "agent-test")
            self.assertEqual(payload["task_id"], "task-test")
            self.assertEqual(payload["attempt_id"], "attempt-test")
        finally:
            ctx.stop()

    def test_DENY_with_real_ipc(self) -> None:
        """B. DENY: Forbidden operation → tool denied, denial evidence persisted."""
        ctx, socket_path, capability = self._start_ipc_context(
            agent_id="agent-test",
            task_id="task-test",
            attempt_id="attempt-test",
        )
        try:
            # Write outside owned paths should be denied by policy classifier
            response = self._run_hook_with_ipc(
                tool_name="Write",
                tool_input={"file_path": str(self.workspace / "outside" / "file.py")},
                ipc_socket_path=socket_path,
                capability=capability,
            )
            # Policy classifier should deny this
            self.assertEqual(self._decision(response), "deny")

            # Verify denial evidence persisted
            with self.store._connection(write=False) as conn:
                rows = conn.execute(
                    "SELECT entity_type, event_type, payload_json FROM agent_runtime_events WHERE entity_type='policy_decision'"
                ).fetchall()
            self.assertGreater(len(rows), 0, "No policy decision evidence found")
            payload = json.loads(rows[0]["payload_json"])
            self.assertEqual(payload["decision"], "deny")
            self.assertEqual(payload["tool_name"], "Write")
        finally:
            ctx.stop()

    def test_IPC_FAILURE_fails_closed(self) -> None:
        """E. IPC Failure: No server → tool denied, no evidence persisted."""
        # No IPC server running
        socket_path = self.tmpdir / "nonexistent.sock"
        capability = generate_capability()

        response = self._run_hook_with_ipc(
            tool_name="Read",
            tool_input={"file_path": str(self.workspace / "src" / "main.py")},
            ipc_socket_path=socket_path,
            capability=capability,
        )
        self.assertEqual(self._decision(response), "deny")
        self.assertIn("policy record could not be persisted", self._reason(response))

        # No evidence should be persisted for IPC failure
        with self.store._connection(write=False) as conn:
            rows = conn.execute(
                "SELECT entity_type FROM agent_runtime_events WHERE entity_type='policy_decision'"
            ).fetchall()
        self.assertEqual(len(rows), 0, "No evidence should be persisted on IPC failure")

    def test_INVALID_CAPABILITY_fails_closed(self) -> None:
        """E. IPC Failure: Invalid capability → tool denied."""
        ctx, socket_path, capability = self._start_ipc_context()
        try:
            # Use wrong capability
            wrong_capability = generate_capability()
            response = self._run_hook_with_ipc(
                tool_name="Read",
                tool_input={"file_path": str(self.workspace / "src" / "main.py")},
                ipc_socket_path=socket_path,
                capability=wrong_capability,  # Wrong capability
            )
            self.assertEqual(self._decision(response), "deny")
            self.assertIn("policy record could not be persisted", self._reason(response))
        finally:
            ctx.stop()

    def test_IDENTITY_MISMATCH_fails_closed(self) -> None:
        """F. Identity Validation: Unknown agent identity → tool denied."""
        ctx, socket_path, capability = self._start_ipc_context(
            agent_id="registered-agent",
            task_id="task-test",
        )
        try:
            # Hook sends different agent_id than registered
            response = self._run_hook_with_ipc(
                tool_name="Read",
                tool_input={"file_path": str(self.workspace / "src" / "main.py")},
                ipc_socket_path=socket_path,
                capability=capability,
                agent_id="forged-agent",  # Different from registered
            )
            self.assertEqual(self._decision(response), "deny")
            self.assertIn("policy record could not be persisted", self._reason(response))
        finally:
            ctx.stop()

    def test_TASK_OWNERSHIP_MISMATCH_fails_closed(self) -> None:
        """F. Task Ownership: Mismatched task identity → tool denied."""
        ctx, socket_path, capability = self._start_ipc_context(
            agent_id="agent-test",
            task_id="registered-task",
        )
        try:
            response = self._run_hook_with_ipc(
                tool_name="Read",
                tool_input={"file_path": str(self.workspace / "src" / "main.py")},
                ipc_socket_path=socket_path,
                capability=capability,
                task_id="other-task",  # Different from registered
            )
            self.assertEqual(self._decision(response), "deny")
            self.assertIn("policy record could not be persisted", self._reason(response))
        finally:
            ctx.stop()

    def test_ATTEMPT_MISMATCH_fails_closed(self) -> None:
        """F. Attempt Validation: Mismatched attempt identity → tool denied."""
        ctx, socket_path, capability = self._start_ipc_context(
            agent_id="agent-test",
            task_id="task-test",
            attempt_id="registered-attempt",
        )
        try:
            response = self._run_hook_with_ipc(
                tool_name="Read",
                tool_input={"file_path": str(self.workspace / "src" / "main.py")},
                ipc_socket_path=socket_path,
                capability=capability,
                attempt_id="forged-attempt",  # Different from registered
            )
            self.assertEqual(self._decision(response), "deny")
            self.assertIn("policy record could not be persisted", self._reason(response))
        finally:
            ctx.stop()

    def test_IDEMPOTENCY_DUPLICATE_REQUEST(self) -> None:
        """Idempotency: Duplicate idempotency_key returns same event_id."""
        ctx, socket_path, capability = self._start_ipc_context(
            agent_id="agent-test",
            task_id="task-test",
            attempt_id="attempt-test",
        )
        try:
            # First request
            response1 = self._run_hook_with_ipc(
                tool_name="Read",
                tool_input={"file_path": str(self.workspace / "src" / "main.py")},
                ipc_socket_path=socket_path,
                capability=capability,
                tool_use_id="tool-test-123",
            )
            self.assertEqual(self._decision(response1), "allow")

            # Second request with same identity (same idempotency key)
            response2 = self._run_hook_with_ipc(
                tool_name="Read",
                tool_input={"file_path": str(self.workspace / "src" / "main.py")},
                ipc_socket_path=socket_path,
                capability=capability,
                tool_use_id="tool-test-123",
            )
            self.assertEqual(self._decision(response2), "allow")
            self.assertIn("idempotent retry", self._reason(response2))

            # Only one evidence record should exist
            with self.store._connection(write=False) as conn:
                rows = conn.execute(
                    "SELECT COUNT(*) as cnt FROM agent_runtime_events WHERE entity_type='policy_decision'"
                ).fetchone()
            self.assertEqual(rows["cnt"], 1, "Duplicate request should not create duplicate evidence")
        finally:
            ctx.stop()

    def test_EVIDENCE_CONTAINS_CORRECT_METADATA(self) -> None:
        """Evidence: Correct agent/task/attempt IDs, timestamps, operation metadata."""
        ctx, socket_path, capability = self._start_ipc_context(
            agent_id="agent-test",
            task_id="task-test",
            attempt_id="attempt-test",
        )
        try:
            response = self._run_hook_with_ipc(
                tool_name="Read",
                tool_input={"file_path": str(self.workspace / "src" / "main.py")},
                ipc_socket_path=socket_path,
                capability=capability,
                tool_use_id="tool-test-123",
            )
            self.assertEqual(self._decision(response), "allow")

            with self.store._connection(write=False) as conn:
                row = conn.execute(
                    "SELECT entity_id, event_type, command_id, payload_json, timestamp FROM agent_runtime_events WHERE entity_type='policy_decision'"
                ).fetchone()

            self.assertIsNotNone(row)
            self.assertEqual(row["entity_id"], "agent-test")
            self.assertEqual(row["event_type"], "ALLOW")
            self.assertIn("orchestrate:test:policy:", row["command_id"])

            payload = json.loads(row["payload_json"])
            self.assertEqual(payload["agent_id"], "agent-test")
            self.assertEqual(payload["task_id"], "task-test")
            self.assertEqual(payload["attempt_id"], "attempt-test")
            self.assertEqual(payload["tool_name"], "Read")
            self.assertEqual(payload["tool_use_id"], "tool-test-123")  # from hook input
            self.assertIn("reasoning", payload)
            self.assertIn("idempotency_key", payload)
            self.assertIn("timestamp", payload)
        finally:
            ctx.stop()

    def test_CONCURRENT_ATTEMPTS_ISOLATED(self) -> None:
        """B9: Multiple attempts served from one controller with isolation."""
        # Bootstrap context
        bootstrap_ctx, bootstrap_sock, bootstrap_cap = self._start_ipc_context(
            agent_id="controller",
            task_id="controller-task",
            command_prefix="orchestrate:bootstrap",
        )
        try:
            # Two per-attempt contexts, each with its own socket path. In
            # production each attempt gets a distinct socket (one server per
            # attempt), so the two servers never contend for the same bind.
            attempt1_sock = self.tmpdir / "ipc" / "attempt-1.sock"
            attempt2_sock = self.tmpdir / "ipc" / "attempt-2.sock"

            attempt1_ctx = PolicyIPCServerContext(
                socket_path=attempt1_sock,
                store=self.store,
                agent_id="agent-1",
                task_id="task-1",
                attempt_id="attempt-1",
                command_prefix="orchestrate:task-1",
            )
            attempt1_ctx.start()

            attempt2_ctx = PolicyIPCServerContext(
                socket_path=attempt2_sock,
                store=self.store,
                agent_id="agent-2",
                task_id="task-2",
                attempt_id="attempt-2",
                command_prefix="orchestrate:task-2",
            )
            attempt2_ctx.start()

            try:
                # Test attempt 1
                response1 = self._run_hook_with_ipc(
                    tool_name="Read",
                    tool_input={"file_path": str(self.workspace / "src" / "main.py")},
                    ipc_socket_path=attempt1_sock,
                    capability=attempt1_ctx.ipc_capability,
                    agent_id="agent-1",
                    task_id="task-1",
                    attempt_id="attempt-1",
                )
                self.assertEqual(self._decision(response1), "allow")

                # Test attempt 2
                response2 = self._run_hook_with_ipc(
                    tool_name="Read",
                    tool_input={"file_path": str(self.workspace / "src" / "main.py")},
                    ipc_socket_path=attempt2_sock,
                    capability=attempt2_ctx.ipc_capability,
                    agent_id="agent-2",
                    task_id="task-2",
                    attempt_id="attempt-2",
                )
                self.assertEqual(self._decision(response2), "allow")

                # Verify separate evidence for each attempt
                with self.store._connection(write=False) as conn:
                    rows = conn.execute(
                        "SELECT payload_json FROM agent_runtime_events WHERE entity_type='policy_decision' ORDER BY timestamp"
                    ).fetchall()

                self.assertEqual(len(rows), 2)
                payload1 = json.loads(rows[0]["payload_json"])
                payload2 = json.loads(rows[1]["payload_json"])
                self.assertEqual(payload1["attempt_id"], "attempt-1")
                self.assertEqual(payload2["attempt_id"], "attempt-2")
            finally:
                attempt1_ctx.stop()
                attempt2_ctx.stop()
        finally:
            bootstrap_ctx.stop()

    def test_STALE_SOCKET_AUTO_CLEANUP(self) -> None:
        """B13: Stale socket cleaned up on restart."""
        ipc_dir = self.tmpdir / ".diamond" / "ipc"
        ipc_dir.mkdir(parents=True, exist_ok=True)
        socket_path = ipc_dir / "sock"

        # Create stale socket
        socket_path.write_text("stale")

        # Start new context - should replace stale socket
        ctx = PolicyIPCServerContext(
            socket_path=socket_path,
            store=self.store,
            agent_id="agent-test",
            task_id="task-test",
            attempt_id="attempt-test",
            command_prefix="orchestrate:test",
        )
        ctx.start()
        try:
            # Socket should exist and be a valid socket file (not the stale text)
            self.assertTrue(socket_path.exists())
            # Verify it's a socket
            import stat
            self.assertTrue(stat.S_ISSOCK(socket_path.stat().st_mode))
        finally:
            ctx.stop()
            # Socket should be cleaned up after stop
            self.assertFalse(socket_path.exists())

    def test_SOCKET_PERMISSIONS_SECURE(self) -> None:
        """B12: IPC socket path secure (0o700 dir, 0o600 file)."""
        ctx, socket_path, capability = self._start_ipc_context()
        try:
            import stat
            dir_mode = socket_path.parent.stat().st_mode & 0o777
            file_mode = socket_path.stat().st_mode & 0o777
            self.assertEqual(dir_mode, 0o700, f"Socket dir mode {oct(dir_mode)} != 0o700")
            self.assertEqual(file_mode, 0o600, f"Socket file mode {oct(file_mode)} != 0o600")
        finally:
            ctx.stop()


class SchemaMigrationValidationTests(TestCase):
    """Validate schema v12 → v13 migration integrity."""

    def setUp(self) -> None:
        self.tmpdir = Path(tempfile.mkdtemp(prefix="diamond-schema-migration-"))
        self.addCleanup(self._cleanup)

    def _cleanup(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_MIGRATION_12_TO_13_CREATES_POLICY_IPC_BINDINGS(self) -> None:
        """Verify MIGRATION_12_TO_13 creates policy_ipc_bindings table correctly."""
        from diamond.schema import MIGRATION_12_TO_13, SCHEMA_VERSION, SCHEMA_STATEMENTS, POLICY_IPC_SCHEMA_STATEMENTS
        import sqlite3

        # Build a true v12 database: SCHEMA_STATEMENTS minus the v13 policy_ipc_bindings
        # additions. SCHEMA_STATEMENTS itself is the v13 layout, so filtering keeps v12.
        v12_statements = tuple(
            stmt for stmt in SCHEMA_STATEMENTS if stmt not in POLICY_IPC_SCHEMA_STATEMENTS
        )

        db_path = self.tmpdir / "diamond.sqlite3"
        with sqlite3.connect(db_path) as conn:
            for stmt in v12_statements:
                conn.execute(stmt)
            conn.execute("PRAGMA user_version=12")

            # Verify v12 doesn't have policy_ipc_bindings
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertNotIn("policy_ipc_bindings", tables)

            # Apply migration
            for stmt in MIGRATION_12_TO_13:
                conn.execute(stmt)
            conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

            # Verify v13 has policy_ipc_bindings
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertIn("policy_ipc_bindings", tables)

            # Verify structure
            cols = {row[1] for row in conn.execute("PRAGMA table_info(policy_ipc_bindings)")}
            expected_cols = {"attempt_id", "schema_version", "capability_hash_prefix", "revoked", "created_at", "updated_at"}
            self.assertEqual(cols, expected_cols)

            # Verify WITHOUT ROWID
            create_sql = conn.execute(
                "SELECT sql FROM sqlite_master WHERE name='policy_ipc_bindings'"
            ).fetchone()[0]
            self.assertIn("WITHOUT ROWID", create_sql)

            # Verify triggers exist
            triggers = {row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='policy_ipc_bindings'"
            )}
            self.assertIn("policy_ipc_bindings_no_delete", triggers)
            self.assertIn("policy_ipc_bindings_no_replace", triggers)

    def test_EXISTING_DATA_PRESERVED_AFTER_MIGRATION(self) -> None:
        """Verify existing records and tables remain intact after migration."""
        from diamond.schema import MIGRATION_12_TO_13, SCHEMA_VERSION, SCHEMA_STATEMENTS, POLICY_IPC_SCHEMA_STATEMENTS
        import sqlite3

        v12_statements = tuple(
            stmt for stmt in SCHEMA_STATEMENTS if stmt not in POLICY_IPC_SCHEMA_STATEMENTS
        )

        db_path = self.tmpdir / "diamond.sqlite3"
        with sqlite3.connect(db_path) as conn:
            # Create v12 with some data
            for stmt in v12_statements:
                conn.execute(stmt)

            # Insert test data
            conn.execute("INSERT INTO tasks (task_id, revision, status, snapshot_json) VALUES ('task-1', 1, 'CREATED', '{}')")
            conn.execute("INSERT INTO attempts (attempt_id, schema_version, task_id, task_revision, role, provider, executable, workspace_root, status, created_at, revision, stdout_bytes, stderr_bytes, stdout_sha256, stderr_sha256, result_status, detail) VALUES ('attempt-1', 1, 'task-1', 1, 'builder', 'freellmapi', 'claude', '/tmp', 'INTENDED', '2026-01-01T00:00:00Z', 1, 0, 0, '', '', '', '')")

            conn.execute("PRAGMA user_version=12")

            # Apply migration
            for stmt in MIGRATION_12_TO_13:
                conn.execute(stmt)
            conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

            # Verify data preserved
            task_count = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
            attempt_count = conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]
            self.assertEqual(task_count, 1)
            self.assertEqual(attempt_count, 1)

            # Verify new table exists
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertIn("policy_ipc_bindings", tables)


if __name__ == "__main__":
    import unittest
    unittest.main()