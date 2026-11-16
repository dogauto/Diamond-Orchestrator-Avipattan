"""Explicit adapter execution boundary, separate from discovery and scheduling."""

from __future__ import annotations

import inspect
import os
from dataclasses import replace
from typing import Awaitable, Callable, TypeVar

from .errors import ValidationError
from .provider_contracts import (NormalizedExecutionResult, TaskExecutionRequest,
                                 provider_identifier, validate_adapter_contract)
from .provider_execution import (CancellationRequest, CancellationResult, ExecutionPolicy,
                                 ExecutionPolicyMode, ProviderRawExecution)
from .provider_registry import ProviderRegistry, ProviderState
from .provider_routing import ProviderRouter
from .provider_metadata import ProviderBinding, ProviderMetadataRecord

_T = TypeVar("_T")


class ProviderExecutionGateway:
    """Invoke one already-authorized adapter without retry or fallback.

    The controller must establish the task claim, packet, budget, and
    cancellation policy before calling this boundary.  This class performs no
    scheduling or persistence; it only validates the registry gate and binds
    adapter output to the requested identities.
    """

    def __init__(self, registry: ProviderRegistry, runtime_secrets: tuple[str, ...] = ()) -> None:
        if not isinstance(registry, ProviderRegistry):
            raise ValidationError("execution gateway requires a ProviderRegistry")
        if type(runtime_secrets) is not tuple or any(type(value) is not str or not value for value in runtime_secrets):
            raise ValidationError("execution gateway runtime secrets must be a tuple of nonblank strings")
        self.registry = registry
        self.router = ProviderRouter(registry)
        self._runtime_secrets = runtime_secrets

    @property
    def redaction_secrets(self) -> tuple[str, ...]:
        """Return process-local secret values for evidence redaction only."""
        return self._runtime_secrets

    @staticmethod
    def validate_binding(binding: ProviderBinding, metadata: ProviderMetadataRecord) -> None:
        """Validate the immutable accepted-packet binding at execution time.

        Persistence owns the authoritative record; this gateway check keeps a
        mutable provider ID, manifest, or authorization flag from becoming an
        execution decision by itself.
        """
        if not isinstance(binding, ProviderBinding) or not isinstance(metadata, ProviderMetadataRecord):
            raise ValidationError("gateway binding validation requires provider metadata values")
        if metadata.authorization_status != "authorized" or metadata.state != "execution_authorized":
            raise ValidationError("provider metadata is not execution-authorized")
        if metadata.binding() != binding:
            raise ValidationError("accepted provider binding is stale or inconsistent")

    def validate_execution_binding(self, binding: ProviderBinding,
                                   metadata: ProviderMetadataRecord) -> None:
        """Validate durable metadata against the executable adapter registry.

        The persisted binding is authoritative for the accepted packet, while
        the registry is authoritative for the adapter object that can execute
        it.  Both must describe the same authorized provider before a generic
        adapter is invoked.
        """
        self.validate_binding(binding, metadata)
        descriptor = self.registry.get(binding.provider_id)
        if descriptor.state is not ProviderState.EXECUTION_AUTHORIZED:
            raise ValidationError("registered provider is not execution-authorized")
        if descriptor.adapter is None or descriptor.adapter_id != binding.adapter_id:
            raise ValidationError("registered adapter does not match the accepted provider binding")
        if descriptor.manifest_digest != binding.manifest_digest:
            raise ValidationError("registered manifest does not match the accepted provider binding")
        if descriptor.manifest.adapter_contract_version != binding.adapter_contract_version:
            raise ValidationError("registered adapter contract does not match the accepted provider binding")
        validation = validate_adapter_contract(descriptor.adapter)
        if not validation.valid:
            raise ValidationError(f"registered adapter contract is invalid: {validation.detail}")

    @staticmethod
    async def execute_bound(binding: ProviderBinding, metadata: ProviderMetadataRecord,
                            runner: Callable[[], Awaitable[_T] | _T]) -> _T:
        """Run one already-claimed legacy execution through the gateway gate.

        Existing CLI supervision remains the owner of process groups, output
        limits, and cancellation.  This adapter-neutral bridge makes the
        immutable provider binding an actual execution precondition without
        inventing a second subprocess implementation or enabling a new live
        provider.
        """
        ProviderExecutionGateway.validate_binding(binding, metadata)
        result = runner()
        return await result if inspect.isawaitable(result) else result

    def execute(self, provider_id: str, request: TaskExecutionRequest) -> NormalizedExecutionResult:
        provider_identifier(provider_id)
        if not isinstance(request, TaskExecutionRequest):
            raise ValidationError("execution gateway requires a TaskExecutionRequest")
        descriptor = self.registry.get(provider_id)
        if descriptor.state is not ProviderState.EXECUTION_AUTHORIZED:
            raise ValidationError(f"provider {provider_id} is not execution-authorized")
        if request.execution_policy is None:
            # Preserve the pre-policy gateway API for direct adapter callers.
            # Controller-created requests always carry an explicit policy.
            request = replace(
                request,
                execution_policy=ExecutionPolicy(
                    ExecutionPolicyMode.WRITABLE,
                    os.getcwd(),
                ),
            )
        if descriptor.adapter is None:
            raise ValidationError(f"provider {provider_id} has no execution adapter")
        validation = validate_adapter_contract(descriptor.adapter)
        if not validation.valid:
            raise ValidationError(f"adapter contract is invalid: {validation.detail}")
        if descriptor.adapter.get_capabilities().digest != descriptor.manifest_digest:
            raise ValidationError("adapter capability manifest does not match the registered manifest")
        route = self.router.select(request.requirements, preferred_provider_ids=(provider_id,))
        if route.selected_provider_id != provider_id:
            raise ValidationError(f"provider {provider_id} does not satisfy task requirements: {route.no_eligible_reason}")
        raw = descriptor.adapter.execute(request)
        if not isinstance(raw, ProviderRawExecution):
            raise ValidationError("adapter returned an invalid raw execution result")
        if (raw.provider_id, raw.task_id, raw.correlation_id) != (provider_id, request.task_id, request.correlation_id):
            raise ValidationError("adapter raw result identity does not match the task request")
        normalized = descriptor.adapter.normalize_result(request, raw)
        if not isinstance(normalized, NormalizedExecutionResult):
            raise ValidationError("adapter returned an invalid normalized result")
        if (normalized.provider_id, normalized.task_id, normalized.correlation_id) != (provider_id, request.task_id, request.correlation_id):
            raise ValidationError("adapter normalized result identity does not match the task request")
        if (normalized.provenance.adapter_id, normalized.provenance.adapter_contract_version) != (
                descriptor.adapter_id, descriptor.manifest.adapter_contract_version):
            raise ValidationError("adapter result provenance does not match the registered adapter")
        if normalized.provenance.manifest_digest != descriptor.manifest_digest:
            raise ValidationError("adapter result provenance does not match the registry manifest")
        return normalized

    def cancel(self, provider_id: str, request: CancellationRequest) -> CancellationResult:
        provider_identifier(provider_id)
        if not isinstance(request, CancellationRequest) or request.provider_id != provider_id:
            raise ValidationError("cancellation request does not match the provider")
        descriptor = self.registry.get(provider_id)
        if descriptor.adapter is None:
            raise ValidationError(f"provider {provider_id} has no cancellation adapter")
        result = descriptor.adapter.cancel(request)
        if not isinstance(result, CancellationResult):
            raise ValidationError("adapter returned an invalid cancellation result")
        if (result.provider_id, result.task_id, result.correlation_id) != (provider_id, request.task_id, request.correlation_id):
            raise ValidationError("adapter cancellation identity does not match the request")
        return result
