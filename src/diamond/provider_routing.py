"""Deterministic capability-based provider selection.

Selection is explanation-only.  It does not execute, retry, or silently
substitute a provider, and it never changes the scheduler's dependency or
cancellation decisions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .errors import ValidationError
from .provider_contracts import Capability, ExecutionMode, TaskRequirements, provider_identifier
from .provider_registry import ProviderDescriptor, ProviderRegistry, ProviderState
from .validation import text


@dataclass(frozen=True)
class ProviderDecision:
    provider_id: str
    eligible: bool
    reasons: tuple[str, ...]
    state: str
    manifest_digest: str | None
    declared_capabilities: frozenset[Capability] = frozenset()
    verified_capabilities: frozenset[Capability] = frozenset()


@dataclass(frozen=True)
class RouteSelection:
    requirements: TaskRequirements
    selected_provider_id: str | None
    candidates: tuple[ProviderDecision, ...]
    no_eligible_reason: str | None = None

    @property
    def eligible_provider_ids(self) -> tuple[str, ...]:
        return tuple(item.provider_id for item in self.candidates if item.eligible)


def _ordered_ids(registry: ProviderRegistry, preferred: Iterable[str]) -> tuple[str, ...]:
    values: list[str] = []
    for provider_id in preferred:
        provider_identifier(provider_id)
        if provider_id not in values:
            values.append(provider_id)
    values.extend(item.provider_id for item in registry.list() if item.provider_id not in values)
    return tuple(values)


class ProviderRouter:
    def __init__(self, registry: ProviderRegistry) -> None:
        if not isinstance(registry, ProviderRegistry):
            raise ValidationError("provider router requires a ProviderRegistry")
        self.registry = registry

    def explain(
        self,
        requirements: TaskRequirements,
        *,
        preferred_provider_ids: Iterable[str] = (),
        exclude_provider_ids: Iterable[str] = (),
    ) -> RouteSelection:
        if not isinstance(requirements, TaskRequirements):
            raise ValidationError("provider route requires TaskRequirements")
        excluded = set()
        for provider_id in exclude_provider_ids:
            provider_identifier(provider_id)
            excluded.add(provider_id)
        candidates: list[ProviderDecision] = []
        selected: str | None = None
        for provider_id in _ordered_ids(self.registry, preferred_provider_ids):
            descriptor = self._descriptor(provider_id)
            decision = self._evaluate(provider_id, descriptor, requirements, provider_id in excluded)
            candidates.append(decision)
            if decision.eligible and selected is None:
                selected = provider_id
        reason = None if selected is not None else self._no_route_reason(candidates)
        return RouteSelection(requirements, selected, tuple(candidates), reason)

    def select(
        self,
        requirements: TaskRequirements,
        *,
        preferred_provider_ids: Iterable[str] = (),
        exclude_provider_ids: Iterable[str] = (),
    ) -> RouteSelection:
        """Return an explanation; callers explicitly decide whether to execute."""
        return self.explain(
            requirements,
            preferred_provider_ids=preferred_provider_ids,
            exclude_provider_ids=exclude_provider_ids,
        )

    def _descriptor(self, provider_id: str) -> ProviderDescriptor | None:
        try:
            return self.registry.get(provider_id)
        except ValidationError:
            return None

    @staticmethod
    def _evaluate(
        provider_id: str,
        descriptor: ProviderDescriptor | None,
        requirements: TaskRequirements,
        excluded: bool,
    ) -> ProviderDecision:
        if descriptor is None:
            return ProviderDecision(provider_id, False, ("not_registered",), "not_registered", None)
        reasons: list[str] = []
        if excluded:
            reasons.append("excluded")
        if descriptor.state in {ProviderState.UNAVAILABLE, ProviderState.INCOMPATIBLE, ProviderState.UNTRUSTED, ProviderState.STALE}:
            reasons.append(descriptor.state.value)
        if descriptor.state not in {ProviderState.EXECUTION_AUTHORIZED}:
            reasons.append("execution_not_authorized")
        manifest = descriptor.manifest
        for capability in sorted(requirements.required_capabilities, key=lambda item: item.value):
            if capability in manifest.unsupported_capabilities:
                reasons.append(f"unsupported_capability:{capability.value}")
            elif capability not in descriptor.verified_capabilities:
                reasons.append(f"capability_not_verified:{capability.value}")
        for mode in sorted(requirements.required_execution_modes, key=lambda item: item.value):
            if mode not in manifest.supported_execution_modes:
                reasons.append(f"execution_mode_unsupported:{mode.value}")
        if requirements.task_type is not None and requirements.task_type not in manifest.supported_task_types:
            reasons.append("task_type_unsupported")
        eligible = not reasons
        if eligible:
            reasons.append("eligible")
        return ProviderDecision(
            provider_id, eligible, tuple(reasons), descriptor.state.value, descriptor.manifest_digest,
            manifest.capabilities, descriptor.verified_capabilities,
        )

    @staticmethod
    def _no_route_reason(candidates: list[ProviderDecision]) -> str:
        if not candidates:
            return "no_registered_provider"
        if all("not_registered" in item.reasons for item in candidates):
            return "no_registered_provider"
        return "no_eligible_provider"


def required_capabilities(*capabilities: Capability, modes: Iterable[ExecutionMode] = (), task_type: str | None = None) -> TaskRequirements:
    """Convenience constructor for callers building explicit requirements."""
    values = frozenset(capabilities)
    mode_values = frozenset(modes)
    if not all(isinstance(item, Capability) for item in values):
        raise ValidationError("required capabilities must be Capability values")
    if not all(isinstance(item, ExecutionMode) for item in mode_values):
        raise ValidationError("required modes must be ExecutionMode values")
    if task_type is not None:
        text(task_type, "task type", 128)
    return TaskRequirements(values, mode_values, task_type)
