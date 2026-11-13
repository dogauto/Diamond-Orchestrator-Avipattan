"""Fake-adapter acceptance through the durable controller execution path."""

from __future__ import annotations

import asyncio
import json
import sys
import unittest
from dataclasses import replace
from unittest.mock import patch

from diamond.controller import run_persisted
from diamond.domain import Provider, Role, TaskSpec, TaskStatus
from diamond.evidence import AttemptStatus, ExecutionAttempt
from diamond.errors import ConflictError, ValidationError
from diamond.packets import OutputContract, PacketContext, TaskPacket
from diamond.provider_contracts import (
    ADAPTER_CONTRACT_VERSION,
    Capability,
    CapabilityManifest,
    CancellationResult,
    ExecutionMode,
    ExecutionOutcome,
    ManifestValidationResult,
    ManifestValidationStatus,
    NormalizedExecutionResult,
    ProviderProvenance,
    ProviderRawExecution,
    TaskExecutionRequest,
    TaskRequirements,
)
from diamond.provider_execution import ExecutionPolicy, ExecutionPolicyMode
from diamond.provider_discovery import DiscoveryRecord, DiscoveryState
from diamond.provider_gateway import ProviderExecutionGateway
from diamond.provider_metadata import ProviderMetadataRecord
from diamond.provider_registry import ProviderRegistry
from diamond.skills import SkillRegistry
from diamond.store import EventStore
from diamond.validation import utc_now
from tests.support import ProjectCase, TASK_ID


class CountingAdapter:
    adapter_id = "synthetic-adapter"
    adapter_contract_version = ADAPTER_CONTRACT_VERSION

    def __init__(self, provider_id: str = "synthetic-cli") -> None:
        self.provider_id = provider_id
        self.execute_calls = 0
        self.cancel_calls = 0
        self.outcome = ExecutionOutcome.SUCCEEDED
        self.output = "synthetic adapter result"
        self.manifest = CapabilityManifest(
            provider_id,
            capabilities=frozenset({Capability.ONE_SHOT_EXECUTION, Capability.TIMEOUT_ENFORCEMENT}),
            supported_execution_modes=frozenset({ExecutionMode.ONE_SHOT}),
        )
        self._runtime_config = None

    def discover(self, executable, runner):
        return runner.run((str(executable), "--version"), timeout_seconds=2, output_limit=4096)

    def validate(self, manifest):
        return ManifestValidationResult(True, ManifestValidationStatus.VALIDATED, "synthetic validation")

    def health_check(self, request):
        from diamond.provider_execution import HealthCheckResult
        return HealthCheckResult(request.provider_id, "healthy", utc_now())

    def get_capabilities(self):
        return self.manifest

    def execute(self, request: TaskExecutionRequest) -> ProviderRawExecution:
        self.execute_calls += 1
        return ProviderRawExecution(
            self.provider_id,
            request.task_id,
            request.correlation_id,
            self.outcome,
            "2026-10-17T12:00:00.000000Z",
            "2026-10-17T12:00:00.000000Z",
            exit_code=0,
            stdout=self.output,
            provider_version="1.0.0",
            session_id="synthetic-session",
        )

    def normalize_result(self, request, raw):
        return NormalizedExecutionResult(
            raw.provider_id,
            raw.task_id,
            raw.correlation_id,
            raw.outcome,
            raw.stdout,
            "synthetic-model",
            raw.session_id,
            None,
            raw.events,
            raw.artifacts,
            raw.diagnostics,
            ProviderProvenance(
                raw.provider_id,
                raw.provider_version,
                self.adapter_id,
                self.adapter_contract_version,
                self.manifest.digest,
                "synthetic-test-adapter",
            ),
        )

    def cancel(self, request):
        self.cancel_calls += 1
        return CancellationResult(request.provider_id, request.task_id, request.correlation_id, "cancelled")


class GenericExecutionAcceptanceTests(ProjectCase):
    def setUp(self) -> None:
        super().setUp()
        self.store = EventStore(self.project / ".diamond" / "diamond.sqlite3")
        self.context = PacketContext(1, "1" * 64, "2" * 64, "3" * 64)
        self.adapter = CountingAdapter()
        self.registry = ProviderRegistry()
        self.registry.register(self.adapter.manifest, sys.executable, self.adapter.adapter_id, self.adapter)
        self.registry.record_discovery(DiscoveryRecord(
            "synthetic-cli", self.adapter.adapter_id, sys.executable, sys.executable,
            DiscoveryState.DISCOVERED, version="1.0.0", returncode=0,
        ))
        self.registry.record_validation(
            "synthetic-cli",
            ManifestValidationResult(True, ManifestValidationStatus.VALIDATED, "validated"),
            (Capability.ONE_SHOT_EXECUTION, Capability.TIMEOUT_ENFORCEMENT),
        )
        self.registry.mark_available("synthetic-cli")
        self.registry.record_authorization("synthetic-cli", True, ("fake acceptance authorization",))
        self.gateway = ProviderExecutionGateway(self.registry)
        self.metadata = ProviderMetadataRecord.from_descriptor(
            self.registry.get("synthetic-cli"), utc_now(),
        )

    def fixture(self, identifier: str = TASK_ID, attempt_identifier: str = "b" * 32):
        spec = TaskSpec(
            identifier,
            "execute through the provider-neutral gateway",
            Role.QA,
            Provider.CLAUDE,
            allowed_tools=(sys.executable,),
            timeout_seconds=10,
        )
        self.store.create(spec, f"generic-create-{identifier}")
        packet = TaskPacket.from_task_spec(
            spec,
            attempt_identifier,
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
        attempt = ExecutionAttempt(
            packet.attempt_id,
            spec.task_id,
            1,
            spec.role,
            spec.provider,
            sys.executable,
            packet.workspace_root,
            AttemptStatus.INTENDED,
            utc_now(),
        )
        self.store.register_provider_metadata(self.metadata, "generic-metadata")
        return packet, attempt

    def test_fake_adapter_traverses_controller_gateway_and_survives_reopen(self) -> None:
        packet, attempt = self.fixture()
        with patch.object(self.gateway, "execute", wraps=self.gateway.execute) as gateway_execute:
            completed, result, execution, evidence = asyncio.run(
                run_persisted(
                    self.store,
                    packet,
                    attempt,
                    None,
                    self.project,
                    "generic-test-owner",
                    "generic-run",
                    SkillRegistry(()),
                    self.context,
                    provider_gateway=self.gateway,
                )
            )
            self.assertEqual(gateway_execute.call_count, 1)

        self.assertEqual(self.adapter.execute_calls, 1)
        self.assertEqual(completed.status, AttemptStatus.SUCCEEDED)
        self.assertEqual(result.content, "synthetic adapter result")
        self.assertEqual(execution.returncode, 0)
        self.assertEqual(evidence.kind, "provider_result")
        payload = evidence.to_dict()["payload"]
        self.assertEqual(payload["execution_path"], "provider_gateway")
        self.assertEqual(payload["normalized_result"]["provider_id"], "synthetic-cli")
        self.assertEqual(payload["normalized_result"]["task_id"], TASK_ID)
        self.assertEqual(payload["normalized_result"]["correlation_id"], attempt.attempt_id)
        self.assertEqual(payload["normalized_result"]["provenance"]["adapter_id"], self.adapter.adapter_id)
        self.assertEqual(payload["provider_binding_digest"], self.metadata.binding().digest)

        accepted = self.store.accepted_packet(TASK_ID, 1)
        reopened = EventStore(self.store.database)
        persisted = reopened.get_attempt(attempt.attempt_id)
        self.assertEqual(persisted.status, AttemptStatus.SUCCEEDED)
        self.assertEqual(persisted.provider_id, "synthetic-cli")
        self.assertEqual(persisted.adapter_id, self.adapter.adapter_id)
        self.assertEqual(reopened.replay_attempt(attempt.attempt_id), persisted)
        self.assertEqual(reopened.accepted_packet(TASK_ID, 1).binding, accepted.binding)
        provider_evidence = next(item for item in reopened.evidence(TASK_ID) if item.kind == "provider_result")
        self.assertEqual(provider_evidence.to_dict()["payload"], payload)
        self.assertEqual(reopened.get(TASK_ID).status.value, "CREATED")
        self.assertEqual(reopened.get(TASK_ID).execution_status, TaskStatus.SUCCEEDED)

        with self.assertRaises(ConflictError):
            asyncio.run(
                run_persisted(
                    reopened,
                    packet,
                    attempt,
                    None,
                    self.project,
                    "generic-test-owner",
                    "generic-run",
                    SkillRegistry(()),
                    self.context,
                    provider_gateway=self.gateway,
                )
            )
        self.assertEqual(self.adapter.execute_calls, 1)

    def test_gateway_rejects_unauthorized_and_binding_mismatches_before_execution(self) -> None:
        packet, attempt = self.fixture()
        requirements = TaskRequirements(
            frozenset({Capability.ONE_SHOT_EXECUTION}),
            frozenset({ExecutionMode.ONE_SHOT}),
        )
        request = TaskExecutionRequest(TASK_ID, attempt.attempt_id, packet.objective, requirements,
                                       ExecutionMode.ONE_SHOT, 10,
                                       execution_policy=ExecutionPolicy(ExecutionPolicyMode.READ_ONLY,
                                                                       packet.workspace_root))

        unauthorized_registry = ProviderRegistry()
        unauthorized_adapter = CountingAdapter("unauthorized-cli")
        unauthorized_registry.register(unauthorized_adapter.manifest, sys.executable,
                                       unauthorized_adapter.adapter_id, unauthorized_adapter)
        unauthorized_gateway = ProviderExecutionGateway(unauthorized_registry)
        with self.assertRaisesRegex(ValidationError, "not execution-authorized"):
            unauthorized_gateway.execute("unauthorized-cli", request)
        self.assertEqual(unauthorized_adapter.execute_calls, 0)

        with self.assertRaises(ValidationError):
            self.store.accept_packet(replace(packet, adapter_id="wrong-adapter"), self.metadata, "wrong-packet")
        with self.assertRaises(ValidationError):
            self.store.reserve_dispatch(packet, replace(attempt, attempt_id="c" * 32),
                                        "generic-test-owner", "wrong-attempt",
                                        provider_metadata=self.metadata)

    def test_unknown_or_cancelled_adapter_outcomes_remain_ambiguous_and_are_not_rerun(self) -> None:
        for outcome in (ExecutionOutcome.UNKNOWN, ExecutionOutcome.CANCELLED):
            with self.subTest(outcome=outcome):
                identifier = TASK_ID if outcome is ExecutionOutcome.UNKNOWN else "d" * 32
                attempt_identifier = "b" * 32 if outcome is ExecutionOutcome.UNKNOWN else "c" * 32
                packet, attempt = self.fixture(identifier, attempt_identifier)
                self.adapter.outcome = outcome
                calls_before = self.adapter.execute_calls
                completed, _, _, _ = asyncio.run(
                    run_persisted(
                        self.store,
                        packet,
                        attempt,
                        None,
                        self.project,
                        "generic-test-owner",
                        f"generic-ambiguous-{outcome.value}",
                        SkillRegistry(()),
                        self.context,
                        provider_gateway=self.gateway,
                    )
                )
                self.assertEqual(completed.status, AttemptStatus.AMBIGUOUS)
                self.assertEqual(self.adapter.cancel_calls, 0)
                reopened = EventStore(self.store.database)
                self.assertEqual(reopened.get_attempt(attempt.attempt_id).status, AttemptStatus.AMBIGUOUS)
                with self.assertRaises(ConflictError):
                    asyncio.run(
                        run_persisted(
                            reopened,
                            packet,
                            attempt,
                            None,
                            self.project,
                            "generic-test-owner",
                            f"generic-ambiguous-{outcome.value}",
                            SkillRegistry(()),
                            self.context,
                            provider_gateway=self.gateway,
                        )
                    )
                self.assertEqual(self.adapter.execute_calls, calls_before + 1)

    def test_gateway_runtime_secret_is_redacted_from_persisted_evidence(self) -> None:
        secret = "fixture-runtime-secret-27"
        self.adapter.output = f"provider returned {secret}"
        self.gateway = ProviderExecutionGateway(self.registry, (secret,))
        packet, attempt = self.fixture("e" * 32, "f" * 32)
        completed, result, _, evidence = asyncio.run(
            run_persisted(
                self.store, packet, attempt, None, self.project, "generic-test-owner",
                "generic-secret", SkillRegistry(()), self.context, provider_gateway=self.gateway,
            )
        )

        self.assertEqual(completed.status, AttemptStatus.SUCCEEDED)
        self.assertNotIn(secret, evidence.payload_json)
        reopened = EventStore(self.store.database)
        persisted = reopened.get_attempt(attempt.attempt_id)
        self.assertNotIn(secret, persisted.detail)
        self.assertNotIn(secret, json.dumps([item.to_dict() for item in reopened.evidence(packet.task_id)]))


if __name__ == "__main__":
    unittest.main()
