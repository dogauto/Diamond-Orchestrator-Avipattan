"""CLI coverage for declarative, provider-neutral orchestration."""

from __future__ import annotations

import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import patch, MagicMock

from diamond.cli import main
from diamond.domain import Provider, Role, TaskSpec
from diamond.evidence import AttemptStatus
from diamond.orchestration import (OrchestrationRuntime, resolve_gateway_runtime_config,
                                    verify_invariants, verify_policy)
from diamond.owner import project_owner
from diamond.packets import OutputContract, PacketContext, TaskPacket
from diamond.provider_contracts import (
    Capability,
    ManifestValidationResult,
    ManifestValidationStatus,
)
from diamond.provider_discovery import DiscoveryRecord, DiscoveryState
from diamond.provider_execution import ExecutionOutcome
from diamond.provider_gateway import ProviderExecutionGateway
from diamond.provider_metadata import ProviderMetadataRecord
from diamond.provider_registry import ProviderRegistry
from diamond.skills import SkillRegistry
from diamond.store import EventStore
from diamond.validation import utc_now
from tests.policy_fixtures import write_valid_policy
from tests.support import ProjectCase, ROOT
from tests.test_generic_execution import CountingAdapter


class OrchestrationCliTests(ProjectCase):
    def setUp(self) -> None:
        super().setUp()
        self.store = EventStore(self.project / ".diamond" / "diamond.sqlite3")
        self.context = PacketContext(1, "1" * 64, "2" * 64, "3" * 64)
        self.adapter = CountingAdapter()
        registry = ProviderRegistry()
        registry.register(self.adapter.manifest, sys.executable, self.adapter.adapter_id, self.adapter)
        registry.record_discovery(
            DiscoveryRecord(
                "synthetic-cli",
                self.adapter.adapter_id,
                sys.executable,
                sys.executable,
                DiscoveryState.DISCOVERED,
                version="1.0.0",
                returncode=0,
            )
        )
        registry.record_validation(
            "synthetic-cli",
            ManifestValidationResult(True, ManifestValidationStatus.VALIDATED, "validated"),
            (Capability.ONE_SHOT_EXECUTION, Capability.TIMEOUT_ENFORCEMENT),
        )
        registry.mark_available("synthetic-cli")
        registry.record_authorization("synthetic-cli", True, ("CLI test",))
        self.registry = registry
        self.gateway = ProviderExecutionGateway(registry)
        self.metadata = ProviderMetadataRecord.from_descriptor(registry.get("synthetic-cli"), utc_now())
        self.store.register_provider_metadata(self.metadata, "metadata:orchestration")
        from diamond.orchestration import OrchestrationLifecycle
        self.lifecycle = OrchestrationLifecycle()
        # Mock IPC context with minimal attributes needed by _trusted_launches
        # Use short path to avoid macOS 108-char socket limit
        short_sock = Path("/tmp/policy-test.sock")
        self.lifecycle.ipc_context = MagicMock(ipc_socket_path=short_sock)
        self.runtime = OrchestrationRuntime(
            registry,
            provider_gateway=self.gateway,
            lifecycle=self.lifecycle,
        )

    def prepare(self, spec: TaskSpec, attempt_id: str) -> str:
        self.store.create(spec, f"create:{spec.task_id}")
        packet = TaskPacket.from_task_spec(
            spec,
            attempt_id,
            self.project,
            1,
            self.context.plan_digest,
            self.context.base_digest,
            self.context.config_digest,
            SkillRegistry(()),
            (),
            OutputContract("text", (), 4096),
        )
        packet = replace(packet, provider_id="synthetic-cli", adapter_id=self.adapter.adapter_id,
                         execution_policy="read_only")
        accepted = self.store.accept_packet(packet, self.metadata, f"accept:{spec.task_id}")
        return accepted.accepted_packet_id

    def write_documents(self, specs: list[TaskSpec], packet_ids: list[str]) -> tuple[Path, Path]:
        tasks = self.base / "tasks.json"
        launches = self.base / "launches.json"
        tasks.write_text(
            json.dumps({"schema_version": 1, "tasks": [spec.to_dict() for spec in specs]}),
            encoding="utf-8",
        )
        launches.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "launches": [
                        {
                            "task_id": spec.task_id,
                            "provider_id": "synthetic-cli",
                            "adapter_id": self.adapter.adapter_id,
                            "accepted_packet_id": packet_id,
                        }
                        for spec, packet_id in zip(specs, packet_ids)
                    ],
                }
            ),
            encoding="utf-8",
        )
        return tasks, launches

    def run_cli(self, tasks: Path, launches: Path) -> tuple[int, dict[str, Any]]:
        output = io.StringIO()
        with patch("diamond.orchestration.build_trusted_runtime", return_value=self.runtime):
            with patch("diamond.policy_ipc.PolicyIPCServerContext") as MockIPC:
                mock_instance = MagicMock()
                mock_instance.ipc_socket_path = Path("/tmp/test-ipc.sock")
                mock_instance.ipc_capability = "test-cap"
                MockIPC.return_value = mock_instance
                with redirect_stdout(output):
                    code = main(
                        [
                            "--project",
                            str(self.project),
                            "--json",
                            "orchestrate",
                            "run",
                            "--tasks",
                            str(tasks),
                            "--launches",
                            str(launches),
                        ]
                    )
        return code, json.loads(output.getvalue())

    def test_cli_runs_fake_adapter_and_persists_evidence(self) -> None:
        task = TaskSpec("a" * 32, "run through the CLI", Role.QA, Provider.CLAUDE)
        packet_id = self.prepare(task, "b" * 32)
        tasks, launches = self.write_documents([task], [packet_id])

        code, response = self.run_cli(tasks, launches)

        self.assertEqual(code, 0)
        self.assertTrue(response["ok"])
        self.assertEqual(response["result"]["outcome"], "success")
        self.assertEqual(self.adapter.execute_calls, 1)
        reopened = EventStore(self.store.database)
        self.assertEqual(reopened.get_attempt("b" * 32).status, AttemptStatus.SUCCEEDED)
        self.assertEqual(len(reopened.evidence(task.task_id)), 3)

    def test_gateway_runtime_resolution_is_bounded_and_fails_closed(self) -> None:
        runtime = resolve_gateway_runtime_config({"FREELLMAPI_API_KEY": "fixture-runtime-secret"})
        self.assertEqual(runtime.base_url, "http://127.0.0.1:31415")
        self.assertNotIn("fixture-runtime-secret", repr(runtime))
        compatibility = resolve_gateway_runtime_config({
            "ANTHROPIC_BASE_URL": "http://127.0.0.1:31415/v1",
            "ANTHROPIC_AUTH_TOKEN": "fixture-runtime-secret",
        })
        self.assertEqual(compatibility.base_url, "http://127.0.0.1:31415/v1")
        with self.assertRaisesRegex(Exception, "credential"):
            resolve_gateway_runtime_config({})
        with self.assertRaisesRegex(Exception, "Anthropic"):
            resolve_gateway_runtime_config({
                "FREELLMAPI_URL": "https://api.anthropic.com",
                "FREELLMAPI_API_KEY": "fixture-runtime-secret",
            })
        with self.assertRaisesRegex(Exception, "conflicting"):
            resolve_gateway_runtime_config({
                "FREELLMAPI_URL": "http://127.0.0.1:31415",
                "ANTHROPIC_BASE_URL": "http://localhost:31415",
                "FREELLMAPI_API_KEY": "fixture-runtime-secret",
            })

    def test_failed_prerequisite_is_not_released_to_the_cli_dependent(self) -> None:
        first = TaskSpec("a" * 32, "first", Role.QA, Provider.CLAUDE)
        second = TaskSpec("b" * 32, "second", Role.QA, Provider.CLAUDE, dependencies=(first.task_id,))
        first_packet = self.prepare(first, "c" * 32)
        second_packet = self.prepare(second, "d" * 32)
        tasks, launches = self.write_documents([first, second], [first_packet, second_packet])
        self.adapter.outcome = ExecutionOutcome.FAILED

        code, response = self.run_cli(tasks, launches)

        self.assertEqual(code, 1)
        self.assertFalse(response["ok"])
        self.assertEqual(response["result"]["outcome"], "partial")
        self.assertEqual(self.adapter.execute_calls, 1)
        self.assertEqual(self.store.attempts(second.task_id), ())

    def test_unauthorized_registered_adapter_is_rejected_before_invocation(self) -> None:
        task = TaskSpec("a" * 32, "reject revoked adapter", Role.QA, Provider.CLAUDE)
        packet_id = self.prepare(task, "b" * 32)
        tasks, launches = self.write_documents([task], [packet_id])
        self.registry.invalidate("synthetic-cli", "test revocation")
        revoked_runtime = OrchestrationRuntime(
            self.registry,
            provider_gateway=ProviderExecutionGateway(self.registry),
        )

        output = io.StringIO()
        with patch("diamond.orchestration.build_trusted_runtime", return_value=revoked_runtime):
            with redirect_stdout(output):
                code = main(
                    [
                        "--project",
                        str(self.project),
                        "--json",
                        "orchestrate",
                        "run",
                        "--tasks",
                        str(tasks),
                        "--launches",
                        str(launches),
                    ]
                )

        response = json.loads(output.getvalue())
        self.assertEqual(code, 2)
        self.assertFalse(response["ok"])
        self.assertEqual(self.adapter.execute_calls, 0)
        self.assertEqual(self.store.attempts(task.task_id), ())

    def test_duplicate_task_entries_are_rejected_before_runtime_construction(self) -> None:
        task = TaskSpec("a" * 32, "duplicate input", Role.QA, Provider.CLAUDE)
        packet_id = self.prepare(task, "b" * 32)
        tasks, launches = self.write_documents([task], [packet_id])
        tasks.write_text(
            json.dumps({"schema_version": 1, "tasks": [task.to_dict(), task.to_dict()]}),
            encoding="utf-8",
        )

        output = io.StringIO()
        with patch("diamond.orchestration.build_trusted_runtime") as build_runtime:
            with redirect_stdout(output):
                code = main(
                    [
                        "--project",
                        str(self.project),
                        "--json",
                        "orchestrate",
                        "run",
                        "--tasks",
                        str(tasks),
                        "--launches",
                        str(launches),
                    ]
                )

        response = json.loads(output.getvalue())
        self.assertEqual(code, 2)
        self.assertFalse(response["ok"])
        build_runtime.assert_not_called()
        self.assertEqual(self.adapter.execute_calls, 0)

    def test_project_owner_blocks_competing_orchestration(self) -> None:
        task = TaskSpec("a" * 32, "owner check", Role.QA, Provider.CLAUDE)
        packet_id = self.prepare(task, "b" * 32)
        tasks, launches = self.write_documents([task], [packet_id])

        with project_owner(self.project):
            code, response = self.run_cli(tasks, launches)

        self.assertEqual(code, 4)
        self.assertFalse(response["ok"])
        self.assertEqual(self.adapter.execute_calls, 0)

    def _run_verify(self, *subcommand: str) -> tuple[int, dict[str, Any]]:
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(["--project", str(self.project), "--json", "orchestrate", *subcommand])
        return code, json.loads(output.getvalue())

    def _copy_policy_inputs(self) -> None:
        write_valid_policy(self.project)
        src = self.project / "src" / "diamond"
        src.mkdir(parents=True, exist_ok=True)
        for name in ("controller.py", "routing.py", "orchestration.py", "scheduler.py"):
            (src / name).write_text((ROOT / "src" / "diamond" / name).read_text(encoding="utf-8"), encoding="utf-8")

    def test_cli_verify_policy_invokes_real_verification(self) -> None:
        self._copy_policy_inputs()
        with patch("diamond.orchestration.verify_policy", wraps=verify_policy) as policy_spy:
            code, response = self._run_verify("verify-policy")

        self.assertEqual(code, 0)
        self.assertTrue(response["ok"])
        self.assertEqual(response["result"]["ok"], True)
        self.assertEqual(response["result"]["issues"], [])
        self.assertTrue(policy_spy.called)
        config_arg, project_arg = policy_spy.call_args[0]
        self.assertEqual(config_arg.resolve(), (self.project / "config" / "diamond.toml").resolve())
        self.assertEqual(project_arg.resolve(), self.project.resolve())

    def test_cli_verify_invariants_invokes_real_verification(self) -> None:
        self._copy_policy_inputs()
        with patch("diamond.orchestration.verify_invariants", wraps=verify_invariants) as invariant_spy:
            code, response = self._run_verify("verify-invariants")

        self.assertEqual(code, 0)
        self.assertTrue(response["ok"])
        self.assertEqual(response["result"]["ok"], True)
        self.assertEqual(response["result"]["issues"], [])
        self.assertTrue(invariant_spy.called)
        config_arg, project_arg = invariant_spy.call_args[0]
        self.assertEqual(config_arg.resolve(), (self.project / "config" / "diamond.toml").resolve())
        self.assertEqual(project_arg.resolve(), self.project.resolve())

    def test_cli_verify_policy_fails_closed_on_invalid_configuration(self) -> None:
        self._copy_policy_inputs()
        bad = self.project / "config" / "diamond.toml"
        bad.write_text("schema_version = 1\n", encoding="utf-8")

        code, response = self._run_verify("verify-policy")

        self.assertNotEqual(code, 0)
        self.assertFalse(response["ok"])
        # CLI loads config before dispatch, so invalid config fails at the
        # load_config boundary (error envelope) rather than inside verify_policy.
        self.assertIn("error", response)
        self.assertEqual(response["error"]["code"], "INVALID_CONFIG")

    def test_cli_verify_policy_fails_closed_on_conflicting_policy(self) -> None:
        self._copy_policy_inputs()
        policy = self.project / "CLAUDE.md"
        policy.write_text(
            policy.read_text(encoding="utf-8") + "\nProvider output is authoritative.\n",
            encoding="utf-8",
        )

        with patch("diamond.orchestration.verify_policy", wraps=verify_policy) as policy_spy:
            code, response = self._run_verify("verify-policy")

        self.assertNotEqual(code, 0)
        self.assertFalse(response["ok"])
        self.assertTrue(any("conflicting policy text" in issue for issue in response["result"]["issues"]))
        self.assertTrue(policy_spy.called)

    def test_cli_verify_invariants_fails_closed_on_missing_policy(self) -> None:
        with patch("diamond.orchestration.verify_invariants", wraps=verify_invariants) as invariant_spy:
            code, response = self._run_verify("verify-invariants")

        self.assertNotEqual(code, 0)
        self.assertFalse(response["ok"])
        self.assertTrue(any("CLAUDE.md" in issue for issue in response["result"]["issues"]))
        self.assertTrue(invariant_spy.called)


if __name__ == "__main__":
    unittest.main(verbosity=2)
