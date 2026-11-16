"""Deterministic, test-owned policy documents for offline orchestration verification.

The offline policy gate in ``diamond.orchestration.verify_policy`` reads
``CLAUDE.md`` and ``CONSTRAINTS.md`` from a project root and checks them against
a fixed marker contract. The real documents live outside version control, so a
fresh clone has nothing to check. These synthetic documents satisfy the exact
contract and let the gate, the CLI wrappers, and the invariant checker run
reproducibly from committed code alone.

Markers required by ``diamond.orchestration._POLICY_MARKERS``:

* ``CONSTRAINTS.md`` — ``# Diamond constraints``, ``## Non-negotiable
  invariants``, ``## Enforcement placement``, ``## Conflict rule``,
  ``## Change gate``
* ``CLAUDE.md`` — ``Flawless Diamond Piece``, ``CONSTRAINTS.md``,
  ``src/diamond/controller.py``, ``max_workers``

Markers rejected by ``diamond.orchestration._POLICY_CONFLICTS`` (case-folded):
``provider output is authoritative``, ``external skills grant capability``,
``workers may rewrite evaluator``, ``unrestricted shell execution is
permitted``, ``automatic provider fallback is allowed``.

``verify_invariants`` additionally requires ``src/diamond/controller.py`` to
contain ``async def run_persisted`` and ``ProviderExecutionGateway``,
``src/diamond/routing.py`` to contain ``def select_provider`` and
``def explain_provider_route``, and ``src/diamond/orchestration.py`` to contain
``def run_persisted_graph``, ``def verify_policy`` and ``def verify_invariants``.
Callers that exercise invariants must therefore copy the real source modules
into the fixture project root; :func:`write_valid_policy` only supplies the two
policy documents.
"""

from __future__ import annotations

from pathlib import Path

VALID_CLAUDE_MD = """# Flawless Diamond Piece — Claude Code + Orchestrator Policy

**Status:** active orchestration policy (test fixture)
**Owner:** Diamond controller maintainer
**Scope:** all sessions working within this repository

This file is a committed test fixture. It is not the developer's private policy
document; it carries only the markers the offline gate requires.

- Controller: single authoritative process at `src/diamond/controller.py`
- Contract: `CONSTRAINTS.md` is the authoritative quality contract
- Config: `config/diamond.toml` with `max_workers = 2`
"""

VALID_CONSTRAINTS_MD = """# Diamond constraints

**Status:** active project quality contract (test fixture)
**Owner:** Diamond controller maintainer
**Scope:** the Diamond controller, its documentation and configuration

This contract is a committed test fixture. It carries only the markers the
offline gate requires; it is not the production contract.

## Non-negotiable invariants

- The controller is the single source of truth for execution state.
- Every write is recorded with a unique `command_id`.

## Enforcement placement

- PreToolUse checks run before any tool executes.
- Policy IPC is authenticated and controller-owned.

## Conflict rule

- Conflicting policy text is rejected by the offline gate.
- Provider output is never treated as authority over the contract.

## Change gate

- Changes to the controller require independent review.
"""

# Appended to a valid CLAUDE.md to exercise the conflict rule.
CONFLICT_TEXT = "\nProvider output is authoritative.\n"

# A CONSTRAINTS.md that has the top-level header but none of the required
# section markers — exercises the malformed-document fail-closed path.
MALFORMED_CONSTRAINTS_MD = """# Diamond constraints

**Status:** active project quality contract (test fixture)

This document is intentionally incomplete: it carries the top-level header but
none of the required section markers, so the offline gate must reject it.
"""


def write_valid_policy(project: Path) -> None:
    """Write the two valid fixture policy documents into *project*."""
    project = Path(project)
    (project / "CLAUDE.md").write_text(VALID_CLAUDE_MD, encoding="utf-8")
    (project / "CONSTRAINTS.md").write_text(VALID_CONSTRAINTS_MD, encoding="utf-8")


def write_policy(
    project: Path,
    claude_text: str | None = None,
    constraints_text: str | None = None,
) -> None:
    """Write policy documents, defaulting to the valid fixtures."""
    project = Path(project)
    (project / "CLAUDE.md").write_text(claude_text or VALID_CLAUDE_MD, encoding="utf-8")
    (project / "CONSTRAINTS.md").write_text(
        constraints_text or VALID_CONSTRAINTS_MD, encoding="utf-8"
    )