"""Provider routing policy for Diamond orchestrator.

Implements role-based provider selection with:
- Primary + ordered fallback providers per role
- Rate-limit awareness (skip if remaining < threshold)
- Quarantine awareness (skip quarantined providers)
- Cooldown enforcement (min time between switches)
"""

from dataclasses import dataclass, field
import os
import shutil
import time
from typing import Any, Mapping

from .config import DiamondConfig
from .diagnostics import RateLimitInfo
from .domain import Provider, Role
from .errors import ValidationError
from .provider_health import ProviderHealth, ProviderHealthStore
from .validation import bounded_int


@dataclass(frozen=True)
class RoutingRule:
    """Routing rule for a single role."""
    role: Role
    primary: Provider
    fallbacks: tuple[Provider, ...]
    min_remaining: int
    require_healthy: bool
    cooldown_seconds: float


@dataclass(frozen=True)
class RoutingPolicy:
    """Complete routing policy for all roles."""
    rules: Mapping[Role, RoutingRule]
    default_min_remaining: int = 1
    default_cooldown: float = 300.0


# Default routing rules when not configured in TOML
_DEFAULT_RULES: dict[Role, tuple[Provider, tuple[Provider, ...]]] = {
    Role.BUILDER: (Provider.CLAUDE, (Provider.CODEX, Provider.OMNIRUSH, Provider.COPILOT, Provider.ANTIGRAVITY, Provider.GEMINI)),
    Role.DEBUGGER: (Provider.CODEX, (Provider.CLAUDE, Provider.OMNIRUSH, Provider.COPILOT, Provider.ANTIGRAVITY, Provider.GEMINI)),
    Role.INTEGRATOR: (Provider.CLAUDE, (Provider.CODEX, Provider.OMNIRUSH, Provider.COPILOT)),
    Role.QA: (Provider.COPILOT, (Provider.CODEX, Provider.CLAUDE, Provider.OMNIRUSH)),
    Role.REVIEWER: (Provider.CODEX, (Provider.CLAUDE, Provider.OMNIRUSH, Provider.COPILOT)),
    Role.RELEASE: (Provider.COPILOT, (Provider.CODEX, Provider.CLAUDE, Provider.OMNIRUSH)),
    Role.PLANNER: (Provider.CLAUDE, (Provider.CODEX, Provider.OMNIRUSH, Provider.COPILOT)),
    Role.RESEARCHER: (Provider.CLAUDE, (Provider.CODEX, Provider.OMNIRUSH, Provider.COPILOT)),
    Role.ARCHITECT: (Provider.CLAUDE, (Provider.CODEX, Provider.OMNIRUSH, Provider.COPILOT)),
}


def load_routing_policy(config: DiamondConfig) -> RoutingPolicy:
    """Load routing policy from config. Uses defaults for missing entries."""
    # TODO: parse [routing] section from TOML config
    # For now, use sensible defaults based on role
    rules: dict[Role, RoutingRule] = {}
    if not isinstance(config, DiamondConfig):
        raise ValidationError("routing policy requires a validated DiamondConfig")
    for role, (_, defaults) in _DEFAULT_RULES.items():
        primary = config.roles[role]
        fallbacks = tuple(provider for provider in defaults if provider != primary)
        rules[role] = RoutingRule(
            role=role,
            primary=primary,
            fallbacks=fallbacks,
            min_remaining=1,
            require_healthy=True,
            cooldown_seconds=300.0,
        )
    return RoutingPolicy(rules=rules)


def _reachable(config: DiamondConfig, provider: Provider) -> bool:
    executable = config.providers[provider].executable
    if os.path.isabs(executable):
        return os.path.isfile(executable) and os.access(executable, os.X_OK)
    return shutil.which(executable) is not None


def explain_provider_route(
    config: DiamondConfig,
    policy: RoutingPolicy,
    health_store: ProviderHealthStore,
    role: Role,
    *,
    exclude: set[Provider] | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    """Explain a configured route without probing or mutating provider state."""
    if not isinstance(config, DiamondConfig) or not isinstance(policy, RoutingPolicy):
        raise ValidationError("route explanation requires validated configuration and policy")
    if not isinstance(health_store, ProviderHealthStore) or not isinstance(role, Role):
        raise ValidationError("route explanation requires a role and health store")
    current = time.monotonic() if now is None else now
    excluded = exclude or set()
    rule = policy.rules.get(role)
    if rule is None:
        raise ValidationError(f"no routing rule for role {role.value}")
    candidates: list[dict[str, Any]] = []
    selected: str | None = None
    for index, provider in enumerate((rule.primary, *rule.fallbacks)):
        configured = provider in config.providers
        provider_config = config.providers.get(provider)
        enabled = configured and provider_config.enabled
        reachable = enabled and _reachable(config, provider)
        health = health_store.get_health(provider)
        observed = health.last_probe_ts > 0
        healthy: bool | str = health.is_healthy(rule.min_remaining, current) if observed else "unknown"
        reasons: list[str] = []
        if not configured:
            reasons.append("not_configured")
        if not enabled:
            reasons.append("disabled")
        if enabled and not reachable:
            reasons.append("executable_not_found")
        if not observed:
            reasons.append("health_unobserved")
        elif not healthy:
            reasons.append("unhealthy")
        if provider in excluded:
            reasons.append("excluded")
        if enabled and reachable and healthy is not False and provider not in excluded:
            eligible = True
            if selected is None:
                selected = provider.value
        else:
            eligible = False
        candidates.append({
            "provider": provider.value,
            "priority": "primary" if index == 0 else "fallback",
            "eligible": eligible,
            "reasons": reasons,
            "capabilities": {
                "configured": configured,
                "enabled": enabled,
                "reachable": reachable,
                "healthy": healthy,
                "authorized": "NOT_CHECKED",
            },
            "health": health.to_dict(),
        })
    return {
        "role": role.value,
        "selected_provider": selected,
        "selection_kind": None if selected is None else ("primary" if selected == rule.primary.value else "fallback"),
        "candidates": candidates,
        "no_route_reason": None if selected is not None else "no_eligible_provider",
    }


def select_provider(
    policy: RoutingPolicy,
    health_store: ProviderHealthStore,
    role: Role,
    exclude: set[Provider] | None = None,
    min_remaining: int | None = None,
    now: float | None = None,
    *,
    config: DiamondConfig | None = None,
) -> Provider:
    """Select the best available provider for a role.

    Args:
        policy: The routing policy to use
        health_store: Provider health store for querying state
        role: The role requiring a provider
        exclude: Providers to explicitly exclude
        min_remaining: Override minimum rate limit (uses rule's if None)
        now: Current monotonic timestamp (default: now)

    Returns:
        The selected Provider enum value

    Raises:
        ValidationError: If no provider is available for the role
    """
    if config is None:
        raise ValidationError("select_provider requires a validated DiamondConfig")
    report = explain_provider_route(config, policy, health_store, role, exclude=exclude, now=now)
    if report["selected_provider"] is None:
        raise ValidationError(f"no healthy provider available for role {role.value}")
    selected = Provider(report["selected_provider"])
    if min_remaining is not None:
        rule = policy.rules[role]
        health = health_store.get_health(selected)
        if health.rate_limit is not None and health.rate_limit.remaining is not None and health.rate_limit.remaining < min_remaining:
            raise ValidationError(f"no healthy provider available for role {role.value}")
    return selected


def list_available_providers(
    policy: RoutingPolicy,
    health_store: ProviderHealthStore,
    role: Role,
) -> list[dict[str, Any]]:
    """List all providers that could serve a role, in priority order."""
    rule = policy.rules.get(role)
    if rule is None:
        return []

    all_providers = [rule.primary] + list(rule.fallbacks)
    result = []
    for provider in all_providers:
        health = health_store.get_health(provider)
        available = health.is_healthy(rule.min_remaining)
        result.append({
            "provider": provider.value,
            "available": available,
            "health": health.to_dict(),
        })
    return result


def print_routing_status(policy: RoutingPolicy, health_store: ProviderHealthStore) -> None:
    """Print routing status to stdout (for CLI use)."""
    print("\nProvider Routing Status")
    print("=" * 80)
    for role in sorted(policy.rules.keys()):
        rule = policy.rules[role]
        candidates = [rule.primary] + list(rule.fallbacks)
        print(f"\n{role.value}:")
        print(f"  Primary: {rule.primary.value}")
        print(f"  Fallbacks: {', '.join(p.value for p in rule.fallbacks)}")
        print(f"  Min remaining: {rule.min_remaining}")
        print(f"  Cooldown: {rule.cooldown_seconds}s")
        for provider in candidates:
            health = health_store.get_health(provider)
            status = "✓" if health.is_healthy() else "✗"
            quota = f" quota={health.rate_limit.remaining}" if health.rate_limit else ""
            quar = " QUARANTINED" if health.is_quarantined else ""
            print(f"    {status} {provider.value}: last_probe={health.last_probe_ts:.0f}{quota}{quar}")
    print()
