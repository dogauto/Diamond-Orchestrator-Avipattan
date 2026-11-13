"""Diamond Policy Classifier — deterministic + model-assisted tool-execution gate.

This module is the single authority for tool-execution decisions. It replaces
Claude Code's Auto Mode classifier and is invoked via PreToolUse/PostToolUse hooks.
"""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from .errors import ProviderAuthError, ProviderError, ValidationError
from .freellmapi import FreeLLMAPIClient, FreeLLMAPIConfig, load_gateway_config
from .validation import command_id, text, utc_now


# ── Decision Outcomes ──────────────────────────────────────────────────────────

class PolicyDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"
    DEFER = "defer"
    INDETERMINATE = "indeterminate"


class RiskSeverity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskCategory(str, Enum):
    CREDENTIAL_EXPOSURE = "credential_exposure"
    DESTRUCTIVE_FILESYSTEM = "destructive_filesystem"
    DESTRUCTIVE_GIT = "destructive_git"
    DATABASE_DESTRUCTION = "database_destruction"
    EXTERNAL_TRANSMISSION = "external_transmission"
    INFRASTRUCTURE_CHANGE = "infrastructure_change"
    UNTRUSTED_DOWNLOAD = "untrusted_download"
    PERMISSION_CHANGE = "permission_change"
    WORKSPACE_ESCAPE = "workspace_escape"
    DELEGATION_ESCALATION = "delegation_escalation"
    UNAUTHORIZED_RESOURCE = "unauthorized_resource"
    PROMPT_INJECTION = "prompt_injection"
    UNKNOWN = "unknown"


# ── Request / Response Contracts ──────────────────────────────────────────────

@dataclass(frozen=True)
class PolicyContext:
    """Context available at classification time."""
    agent_id: str
    session_id: str
    provider_session_id: str | None
    provider: str
    adapter_id: str
    task_id: str
    attempt_id: str | None
    workspace_root: str
    owned_paths: tuple[str, ...]
    network_access: str
    execution_policy_mode: str
    delegation_id: str | None
    delegation_scope: tuple[str, ...] = ()
    authorization_evidence: tuple[str, ...] = ()
    policy_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "provider_session_id": self.provider_session_id,
            "provider": self.provider,
            "adapter_id": self.adapter_id,
            "task_id": self.task_id,
            "attempt_id": self.attempt_id,
            "workspace_root": self.workspace_root,
            "owned_paths": list(self.owned_paths),
            "network_access": self.network_access,
            "execution_policy_mode": self.execution_policy_mode,
            "delegation_id": self.delegation_id,
            "delegation_scope": list(self.delegation_scope),
            "authorization_evidence": list(self.authorization_evidence),
            "policy_version": self.policy_version,
        }


@dataclass(frozen=True)
class ToolCallRequest:
    """Proposed tool operation from PreToolUse hook."""
    tool_use_id: str
    tool_name: str
    tool_input: dict[str, Any]
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_use_id": self.tool_use_id,
            "tool_name": self.tool_name,
            "tool_input": self.tool_input,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class PolicyDecisionRecord:
    """Complete audit record for a policy decision."""
    decision_id: str
    agent_id: str
    session_id: str
    provider_session_id: str | None
    claude_conversation_id: str | None
    tool_use_id: str
    tool_name: str
    policy_version: str
    decision: PolicyDecision
    risk_category: RiskCategory
    risk_severity: RiskSeverity
    authorization_evidence_refs: tuple[str, ...]
    reasoning: str
    classifier_model: str | None
    gateway_routing_meta: dict[str, Any] | None
    evaluation_latency_ms: float
    timestamp: str
    approval_status: str  # pending|granted|denied|deferred|not_applicable

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "provider_session_id": self.provider_session_id,
            "claude_conversation_id": self.claude_conversation_id,
            "tool_use_id": self.tool_use_id,
            "tool_name": self.tool_name,
            "policy_version": self.policy_version,
            "decision": self.decision.value,
            "risk_category": self.risk_category.value,
            "risk_severity": self.risk_severity.value,
            "authorization_evidence_refs": list(self.authorization_evidence_refs),
            "reasoning": self.reasoning,
            "classifier_model": self.classifier_model,
            "gateway_routing_meta": self.gateway_routing_meta,
            "evaluation_latency_ms": self.evaluation_latency_ms,
            "timestamp": self.timestamp,
            "approval_status": self.approval_status,
        }

    def to_canonical_json(self) -> str:
        import json
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


# ── Deterministic Security Rules ──────────────────────────────────────────────

# Patterns that indicate credential-like material
CREDENTIAL_PATTERNS = (
    re.compile(r"(?i)(api[_-]?key|secret|token|password|auth)[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9_\-]{16,}"),
    re.compile(r"(?i)bearer\s+[a-zA-Z0-9_\-]{16,}"),
    re.compile(r"(?i)sk-[a-zA-Z0-9]{20,}"),
    re.compile(r"(?i)gh[pousr]_[a-zA-Z0-9]{20,}"),
    re.compile(r"(?i)xox[baprs]-[a-zA-Z0-9]{10,}"),
    re.compile(r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"),
    re.compile(r"(?i)aws_access_key_id\s*[:=]\s*[A-Z0-9]{16,}"),
    re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{20,}"),
)

# Shell operators that chain or wrap commands
SHELL_CHAIN_OPERATORS = ("&&", "||", ";", "|", "&", ">","<","<<",">>","2>","2>&1")
SHELL_WRAPPER_COMMANDS = (
    "bash", "sh", "zsh", "fish", "cmd", "powershell", "pwsh",
    "sudo", "su", "doas", "runuser",
    "env", "nohup", "screen", "tmux", "script",
    "python", "python3", "node", "perl", "ruby", "php",
    "xargs", "parallel", "find", "exec",
)

# Destructive filesystem commands
DESTRUCTIVE_FILE_COMMANDS = (
    "rm", "rmdir", "unlink", "shred", "wipe",
    "truncate", "dd", "mkfs", "fdisk", "parted",
    "chmod", "chown", "chgrp", "chattr", "setfacl",
)

# Destructive git commands
DESTRUCTIVE_GIT_COMMANDS = (
    "git reset --hard", "git checkout --", "git clean", "git gc --prune",
    "git push --force", "git push -f", "git rebase", "git filter-branch",
    "git stash drop", "git branch -D", "git tag -d",
)

# Database destructive commands
DB_DESTRUCTIVE_COMMANDS = (
    "drop table", "drop database", "truncate table", "delete from",
    "alter table", "drop schema", "vacuum full",
)

# External transmission destinations (non-loopback)
EXTERNAL_DEST_PATTERNS = (
    re.compile(r"https?://(?!localhost|127\.0\.0\.1|::1|0\.0\.0\.0)"),
    re.compile(r"(?i)(curl|wget|fetch|nc|netcat|telnet|ssh|scp|rsync|sftp)\s+.*(://|@)"),
)

# Untrusted download patterns
UNTRUSTED_DOWNLOAD_PATTERNS = (
    re.compile(r"(?i)(curl|wget|fetch)\s+.*\.(sh|py|js|exe|bin|dmg|pkg|deb|rpm|apk)"),
    re.compile(r"(?i)(npm|pip|gem|cargo|go)\s+install\s+.*(git://|git@|ssh://)"),
)

# Permission/security control files
PERMISSION_CONTROL_FILES = (
    "/etc/sudoers", "/etc/passwd", "/etc/shadow", "/etc/group",
    "/etc/ssh/sshd_config", "/etc/hosts", "/etc/hosts.allow", "/etc/hosts.deny",
    ".ssh/authorized_keys", ".ssh/config", ".ssh/id_rsa", ".ssh/id_ed25519",
    ".git/config", ".github/workflows", ".gitlab-ci.yml",
    "docker-compose.yml", "Dockerfile", "kubernetes/", "k8s/",
    ".aws/credentials", ".aws/config", ".docker/config.json",
)

# Workspace escape patterns (absolute paths, parent traversal outside workspace)
WORKSPACE_ESCAPE_PATTERNS = (
    re.compile(r"(?<!\w)/etc/"),
    re.compile(r"(?<!\w)/usr/"),
    re.compile(r"(?<!\w)/var/"),
    re.compile(r"(?<!\w)/opt/"),
    re.compile(r"(?<!\w)/home/[^/]+/\.ssh/"),
    re.compile(r"(?<!\w)/root/"),
)


def _contains_credential(text: str) -> bool:
    return any(p.search(text) for p in CREDENTIAL_PATTERNS)


def _is_destructive_file_command(argv: list[str]) -> tuple[bool, str | None]:
    if not argv:
        return False, None
    cmd = argv[0].lower()
    for destructive in DESTRUCTIVE_FILE_COMMANDS:
        if cmd == destructive or cmd.endswith("/" + destructive):
            return True, destructive
    return False, None


def _is_destructive_git_command(argv: list[str]) -> tuple[bool, str | None]:
    if len(argv) < 2 or argv[0] != "git":
        return False, None
    # Check for destructive subcommands with any following args
    subcmd = argv[1].lower()
    destructive_subcmds = {
        "reset": ["--hard", "--mixed", "--merge", "--keep"],
        "checkout": ["--"],
        "clean": ["-f", "--force", "-df", "-fd"],
        "gc": ["--prune", "--aggressive"],
        "push": ["--force", "-f"],
        "rebase": [],  # any rebase is risky
        "filter-branch": [],  # rewrite history
        "stash": ["drop"],
        "branch": ["-d", "-D", "--delete"],
        "tag": ["-d", "--delete"],
    }
    for pattern in ("git reset --hard", "git checkout --", "git clean", "git gc --prune",
                    "git push --force", "git push -f", "git rebase", "git filter-branch",
                    "git stash drop", "git branch -D", "git tag -d"):
        if pattern in " ".join(argv).lower():
            return True, pattern
    # Check subcommand-based detection
    if subcmd in destructive_subcmds:
        for flag in destructive_subcmds[subcmd]:
            if flag in argv:
                return True, f"git {subcmd} {flag}"
    return False, None


def _is_db_destructive_command(argv: list[str]) -> tuple[bool, str | None]:
    if not argv:
        return False, None
    cmd_text = " ".join(argv).lower()
    for destructive in DB_DESTRUCTIVE_COMMANDS:
        if destructive in cmd_text:
            return True, destructive
    return False, None


def _is_external_transmission(argv: list[str]) -> tuple[bool, str | None]:
    if not argv:
        return False, None
    cmd_text = " ".join(argv)
    # Exclude localhost:31415 (FreeLLMAPI gateway)
    if "localhost:31415" in cmd_text or "127.0.0.1" in cmd_text:
        return False, None
    for pattern in EXTERNAL_DEST_PATTERNS:
        if pattern.search(cmd_text):
            return True, "external_destination"
    return False, None


def _is_untrusted_download(argv: list[str]) -> tuple[bool, str | None]:
    if not argv:
        return False, None
    cmd_text = " ".join(argv)
    for pattern in UNTRUSTED_DOWNLOAD_PATTERNS:
        if pattern.search(cmd_text):
            return True, "untrusted_download"
    return False, None


def _is_permission_control_change(paths: list[str]) -> tuple[bool, str | None]:
    for path in paths:
        for control in PERMISSION_CONTROL_FILES:
            if control in path:
                return True, control
    return False, None


def _is_workspace_escape(paths: list[str], workspace_root: str) -> tuple[bool, str | None]:
    workspace = Path(workspace_root).resolve()
    for path in paths:
        try:
            p = Path(path).resolve()
            if not p.is_relative_to(workspace):
                return True, f"path {path} escapes workspace {workspace_root}"
        except (ValueError, OSError):
            return True, f"cannot resolve path {path}"
    return False, None


def _extract_paths_from_tool_input(tool_name: str, tool_input: dict[str, Any]) -> list[str]:
    paths = []
    if tool_name in ("Read", "Write", "Edit", "MultiEdit", "NotebookEdit"):
        p = tool_input.get("file_path") or tool_input.get("path")
        if p:
            paths.append(p)
    elif tool_name == "Bash":
        # Crude extraction — real implementation should parse shell
        cmd = tool_input.get("command", "")
        # Look for path-like arguments
        for part in cmd.split():
            if part.startswith("/") or part.startswith("./") or part.startswith("../"):
                paths.append(part)
    elif tool_name in ("Glob", "Grep"):
        p = tool_input.get("path") or tool_input.get("include")
        if p:
            paths.append(p)
    elif tool_name == "Task":
        # Subagent launch — extract from prompt
        prompt = tool_input.get("prompt", "")
        # Basic extraction
        for part in prompt.split():
            if part.startswith("/") or part.startswith("./") or part.startswith("../"):
                paths.append(part)
    return paths


# ── Deterministic Policy Engine ────────────────────────────────────────────────

@dataclass(frozen=True)
class DeterministicResult:
    decision: PolicyDecision
    risk_category: RiskCategory
    risk_severity: RiskSeverity
    reasoning: str
    matched_rule: str | None


class DeterministicPolicyEngine:
    """Hard-coded security rules that cannot be overridden by LLM."""

    def evaluate(self, context: PolicyContext, request: ToolCallRequest) -> DeterministicResult:
        tool_name = request.tool_name
        tool_input = request.tool_input

        # 1. Credential exposure in tool input
        tool_input_text = json.dumps(tool_input)
        if _contains_credential(tool_input_text):
            return DeterministicResult(
                decision=PolicyDecision.DENY,
                risk_category=RiskCategory.CREDENTIAL_EXPOSURE,
                risk_severity=RiskSeverity.CRITICAL,
                reasoning="Tool input contains credential-like material",
                matched_rule="credential_pattern_match",
            )

        # 2. Bash command analysis
        if tool_name == "Bash":
            cmd = tool_input.get("command", "")
            argv = self._parse_shell_command(cmd)

            # Destructive filesystem
            is_destructive, rule = _is_destructive_file_command(argv)
            if is_destructive:
                return DeterministicResult(
                    decision=PolicyDecision.DENY,
                    risk_category=RiskCategory.DESTRUCTIVE_FILESYSTEM,
                    risk_severity=RiskSeverity.HIGH,
                    reasoning=f"Destructive filesystem command detected: {rule}",
                    matched_rule=rule,
                )

            # Destructive git
            is_destructive, rule = _is_destructive_git_command(argv)
            if is_destructive:
                return DeterministicResult(
                    decision=PolicyDecision.DENY,
                    risk_category=RiskCategory.DESTRUCTIVE_GIT,
                    risk_severity=RiskSeverity.HIGH,
                    reasoning=f"Destructive git command detected: {rule}",
                    matched_rule=rule,
                )

            # Database destruction
            is_destructive, rule = _is_db_destructive_command(argv)
            if is_destructive:
                return DeterministicResult(
                    decision=PolicyDecision.DENY,
                    risk_category=RiskCategory.DATABASE_DESTRUCTION,
                    risk_severity=RiskSeverity.CRITICAL,
                    reasoning=f"Database destructive command detected: {rule}",
                    matched_rule=rule,
                )

            # External transmission
            is_external, rule = _is_external_transmission(argv)
            if is_external:
                return DeterministicResult(
                    decision=PolicyDecision.DENY,
                    risk_category=RiskCategory.EXTERNAL_TRANSMISSION,
                    risk_severity=RiskSeverity.HIGH,
                    reasoning=f"External data transmission detected: {rule}",
                    matched_rule=rule,
                )

            # Untrusted download
            is_untrusted, rule = _is_untrusted_download(argv)
            if is_untrusted:
                return DeterministicResult(
                    decision=PolicyDecision.DENY,
                    risk_category=RiskCategory.UNTRUSTED_DOWNLOAD,
                    risk_severity=RiskSeverity.HIGH,
                    reasoning=f"Untrusted download detected: {rule}",
                    matched_rule=rule,
                )

            # Shell chaining/wrapping — escalate to model-assisted
            if self._has_shell_chain_or_wrapper(argv):
                return DeterministicResult(
                    decision=PolicyDecision.ASK,
                    risk_category=RiskCategory.UNKNOWN,
                    risk_severity=RiskSeverity.MEDIUM,
                    reasoning="Shell command uses chaining or wrapper; requires model-assisted analysis",
                    matched_rule="shell_chain_wrapper",
                )

        # 3. File operation path analysis
        paths = _extract_paths_from_tool_input(tool_name, tool_input)

        # Permission control files
        is_perm, rule = _is_permission_control_change(paths)
        if is_perm:
            return DeterministicResult(
                decision=PolicyDecision.DENY,
                risk_category=RiskCategory.PERMISSION_CHANGE,
                risk_severity=RiskSeverity.CRITICAL,
                reasoning=f"Attempt to modify permission/security control file: {rule}",
                matched_rule=rule,
            )

        # Workspace escape
        is_escape, rule = _is_workspace_escape(paths, context.workspace_root)
        if is_escape:
            return DeterministicResult(
                decision=PolicyDecision.DENY,
                risk_category=RiskCategory.WORKSPACE_ESCAPE,
                risk_severity=RiskSeverity.CRITICAL,
                reasoning=f"Workspace escape attempt: {rule}",
                matched_rule=rule,
            )

        # 4. Path not in owned_paths for write operations
        if tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
            for path in paths:
                if not self._path_in_owned(path, context.owned_paths, context.workspace_root):
                    return DeterministicResult(
                        decision=PolicyDecision.DENY,
                        risk_category=RiskCategory.UNAUTHORIZED_RESOURCE,
                        risk_severity=RiskSeverity.HIGH,
                        reasoning=f"Write to path not in owned_paths: {path}",
                        matched_rule="unauthorized_write",
                    )

        # 5. Delegation/escalation via Task tool
        if tool_name == "Task":
            return DeterministicResult(
                decision=PolicyDecision.ASK,
                risk_category=RiskCategory.DELEGATION_ESCALATION,
                risk_severity=RiskSeverity.MEDIUM,
                reasoning="Subagent delegation requires explicit approval",
                matched_rule="subagent_delegation",
            )

        # 6. MCP tool calls — always escalate to model-assisted
        if tool_name.startswith("mcp__"):
            return DeterministicResult(
                decision=PolicyDecision.ASK,
                risk_category=RiskCategory.UNKNOWN,
                risk_severity=RiskSeverity.MEDIUM,
                reasoning="MCP tool call requires model-assisted risk evaluation",
                matched_rule="mcp_tool",
            )

        # Default: allow read-only, ask for others
        if tool_name in ("Read", "Glob", "Grep", "LS", "WebFetch", "WebSearch"):
            return DeterministicResult(
                decision=PolicyDecision.ALLOW,
                risk_category=RiskCategory.UNKNOWN,
                risk_severity=RiskSeverity.NONE,
                reasoning="Read-only tool within workspace",
                matched_rule="read_only_tool",
            )

        return DeterministicResult(
            decision=PolicyDecision.ASK,
            risk_category=RiskCategory.UNKNOWN,
            risk_severity=RiskSeverity.LOW,
            reasoning="Tool requires explicit approval",
            matched_rule="default_ask",
        )

    def _parse_shell_command(self, cmd: str) -> list[str]:
        """Crude shell parsing — real impl should use shlex or similar."""
        # Handle quoted strings
        import shlex
        try:
            return shlex.split(cmd)
        except ValueError:
            return cmd.split()

    def _has_shell_chain_or_wrapper(self, argv: list[str]) -> bool:
        cmd_text = " ".join(argv)
        for op in SHELL_CHAIN_OPERATORS:
            if op in cmd_text:
                return True
        for wrapper in SHELL_WRAPPER_COMMANDS:
            if argv and argv[0].lower() == wrapper:
                return True
        return False

    def _path_in_owned(self, path: str, owned_paths: tuple[str, ...], workspace_root: str) -> bool:
        try:
            p = Path(path).resolve()
            workspace = Path(workspace_root).resolve()
            if not p.is_relative_to(workspace):
                return False
            for owned in owned_paths:
                owned_path = (workspace / owned).resolve()
                if p.is_relative_to(owned_path) or p == owned_path:
                    return True
        except (ValueError, OSError):
            return False
        return False


# ── Model-Assisted Risk Evaluation ────────────────────────────────────────────

class ClassifierRequest:
    """Structured request to the model classifier."""
    tool_call: ToolCallRequest
    context: PolicyContext
    deterministic_result: DeterministicResult

    def __init__(self, tool_call: ToolCallRequest, context: PolicyContext, deterministic_result: DeterministicResult) -> None:
        self.tool_call = tool_call
        self.context = context
        self.deterministic_result = deterministic_result

    def to_prompt(self) -> str:
        return f"""You are Diamond's policy classifier. Evaluate this tool call for risk.

## Tool Call
- Tool: {self.tool_call.tool_name}
- ID: {self.tool_call.tool_use_id}
- Input: {json.dumps(self.tool_call.tool_input, sort_keys=True)}

## Context
- Agent: {self.context.agent_id} ({self.context.provider} via {self.context.adapter_id})
- Session: {self.context.session_id}
- Task: {self.context.task_id}
- Workspace: {self.context.workspace_root}
- Owned paths: {list(self.context.owned_paths)}
- Network access: {self.context.network_access}
- Execution policy: {self.context.execution_policy_mode}
- Delegation: {self.context.delegation_id or "none"}
- Delegation scope: {list(self.context.delegation_scope)}
- Authorization evidence: {list(self.context.authorization_evidence)}

## Deterministic Analysis
- Decision: {self.deterministic_result.decision.value}
- Risk category: {self.deterministic_result.risk_category.value}
- Risk severity: {self.deterministic_result.risk_severity.value}
- Reasoning: {self.deterministic_result.reasoning}
- Matched rule: {self.deterministic_result.matched_rule}

## Your Task
Return a JSON object with exactly these fields:
{{
  "recommendation": "allow|deny|ask|defer",
  "risk_category": "credential_exposure|destructive_filesystem|destructive_git|database_destruction|external_transmission|infrastructure_change|untrusted_download|permission_change|workspace_escape|delegation_escalation|unauthorized_resource|prompt_injection|unknown",
  "risk_severity": "none|low|medium|high|critical",
  "reasoning": "concise explanation",
  "confidence": 0.0-1.0
}}

IMPORTANT:
- Never recommend "allow" for deterministic DENY decisions.
- If deterministic decision is ASK or DEFER, you may refine but not downgrade to ALLOW.
- For ambiguous cases, prefer ASK or DEFER over ALLOW.
- Do not invent user consent. Authorization evidence must be explicit.
- For delegated agents, verify delegation scope covers the operation.
- Keep reasoning concise and auditable.
"""


@dataclass(frozen=True)
class ClassifierResult:
    recommendation: PolicyDecision
    risk_category: RiskCategory
    risk_severity: RiskSeverity
    reasoning: str
    confidence: float
    model: str
    latency_ms: float


class ModelAssistedClassifier:
    """Uses FreeLLMAPI with model=auto for context-sensitive risk evaluation."""

    def __init__(self, gateway_config: FreeLLMAPIConfig | None = None, timeout_seconds: float = 15.0) -> None:
        self.gateway_config = gateway_config
        self.timeout_seconds = timeout_seconds
        self._client: FreeLLMAPIClient | None = None

    def _get_client(self) -> FreeLLMAPIClient:
        if self._client is not None:
            return self._client
        if self.gateway_config is None:
            config_path = Path(".diamond/freellmapi.json")
            if not config_path.exists():
                raise ProviderError("FreeLLMAPI gateway not configured")
            self.gateway_config = load_gateway_config(config_path)
        self._client = FreeLLMAPIClient(self.gateway_config, timeout_seconds=self.timeout_seconds)
        return self._client

    def evaluate(self, request: ClassifierRequest) -> ClassifierResult:
        prompt = request.to_prompt()
        started = time.monotonic()

        try:
            client = self._get_client()
            payload = client._request("/chat/completions", {
                "model": "auto",
                "messages": [
                    {"role": "system", "content": "Return only JSON matching the schema: {recommendation: 'allow|deny|ask|defer', risk_category: 'credential_exposure|destructive_filesystem|...|unknown', risk_severity: 'none|low|medium|high|critical', reasoning: 'string', confidence: 0.0-1.0}. No explanations, no formatting, no markdown. Only output valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0,
                "max_tokens": 512,
                "stream": False,
            })
        except Exception as exc:
            latency = round((time.monotonic() - started) * 1000, 3)
            return ClassifierResult(
                recommendation=PolicyDecision.INDETERMINATE,
                risk_category=RiskCategory.UNKNOWN,
                risk_severity=RiskSeverity.HIGH,
                reasoning=f"Gateway error: {exc}",
                confidence=0.0,
                model="auto",
                latency_ms=latency,
            )

        latency = round((time.monotonic() - started) * 1000, 3)

        # Extract content from chat completions response
        try:
            if not isinstance(payload, dict):
                raise ValueError("not a dict")
            choices = payload.get("choices")
            if not isinstance(choices, list) or not choices:
                raise ValueError("no choices")
            message = choices[0].get("message")
            if not isinstance(message, dict):
                raise ValueError("no message")
            content = message.get("content")
            if not isinstance(content, str):
                raise ValueError("no content")
            # Strip any markdown code fences from content
            if content.startswith("```json"):
                content = content[7:]
            if content.endswith("```"):
                content = content[:-3]
            content = content.strip()
            reported_model = payload.get("model") if isinstance(payload.get("model"), str) else "auto"
            return self._parse_classifier_response(reported_model, content, latency)
        except (TypeError, ValueError, json.JSONDecodeError):
            return ClassifierResult(
                recommendation=PolicyDecision.INDETERMINATE,
                risk_category=RiskCategory.UNKNOWN,
                risk_severity=RiskSeverity.HIGH,
                reasoning="Classifier returned invalid response",
                confidence=0.0,
                model="auto",
                latency_ms=latency,
            )

    def _parse_classifier_response(self, model: str, content: str, latency: float) -> ClassifierResult:
        """Parse classifier response. For smoke, we get plain text — need structured Parquet."""
        # In production, would use /chat/completions with structured output
        # For now, return indeterminate on any failure
        try:
            # Strip markdown code fences if present
            if content.startswith("```json"):
                content = content[7:]
            if content.endswith("```"):
                content = content[:-3]
            # Strip whitespace
            content = content.strip()
            data = json.loads(content)
            rec = PolicyDecision(data.get("recommendation", "indeterminate"))
            cat = RiskCategory(data.get("risk_category", "unknown"))
            sev = RiskSeverity(data.get("risk_severity", "high"))
            return ClassifierResult(
                recommendation=rec,
                risk_category=cat,
                risk_severity=sev,
                reasoning=data.get("reasoning", "no reasoning provided"),
                confidence=float(data.get("confidence", 0.0)),
                model=model,
                latency_ms=latency,
            )
        except (json.JSONDecodeError, TypeError, ValueError):
            return ClassifierResult(
                recommendation=PolicyDecision.INDETERMINATE,
                risk_category=RiskCategory.UNKNOWN,
                risk_severity=RiskSeverity.HIGH,
                reasoning="Classifier response not valid JSON",
                confidence=0.0,
                model=model,
                latency_ms=latency,
            )


# ── Policy Evaluator (Combines Both Levels) ────────────────────────────────────

@dataclass
class PolicyEvaluator:
    """Main policy evaluation entry point."""

    deterministic_engine: DeterministicPolicyEngine = field(default_factory=DeterministicPolicyEngine)
    model_classifier: ModelAssistedClassifier | None = None

    def evaluate(self, context: PolicyContext, request: ToolCallRequest) -> tuple[PolicyDecisionRecord, PolicyDecision]:
        """Evaluate a tool call and return (audit_record, effective_decision)."""
        overall_start = time.monotonic()

        # Level 1: Deterministic rules
        det_result = self.deterministic_engine.evaluate(context, request)

        # Hard-deny: never override
        if det_result.decision == PolicyDecision.DENY:
            return self._build_record(context, request, det_result, None, overall_start), PolicyDecision.DENY

        # If deterministic says ALLOW for read-only, we can short-circuit
        if det_result.decision == PolicyDecision.ALLOW and det_result.risk_severity == RiskSeverity.NONE:
            return self._build_record(context, request, det_result, None, overall_start), PolicyDecision.ALLOW

        # Level 2: Model-assisted evaluation (for ASK, DEFER, or ambiguous)
        model_result = None
        if self.model_classifier is not None and det_result.decision in (PolicyDecision.ASK, PolicyDecision.DEFER):
            classifier_request = ClassifierRequest(request, context, det_result)
            model_result = self.model_classifier.evaluate(classifier_request)

            # Combine: deterministic hard rules + model recommendation
            effective = self._combine_decisions(det_result, model_result)
        else:
            effective = det_result.decision

        return self._build_record(context, request, det_result, model_result, overall_start), effective

    def _combine_decisions(self, det: DeterministicResult, model: ClassifierResult) -> PolicyDecision:
        # Deterministic DENY already handled above
        # Model can't override hard deny
        if model.recommendation == PolicyDecision.DENY:
            return PolicyDecision.DENY
        if model.recommendation == PolicyDecision.ALLOW:
            # Only allow if model is confident and deterministic wasn't ASK/DEFER for high risk
            if model.confidence >= 0.8 and det.risk_severity in (RiskSeverity.NONE, RiskSeverity.LOW):
                return PolicyDecision.ALLOW
            return PolicyDecision.ASK
        if model.recommendation == PolicyDecision.DEFER:
            return PolicyDecision.DEFER
        # Indeterminate or ASK from model
        return PolicyDecision.ASK

    def _build_record(
        self,
        context: PolicyContext,
        request: ToolCallRequest,
        det: DeterministicResult,
        model: ClassifierResult | None,
        overall_start: float,
    ) -> PolicyDecisionRecord:
        decision_id = uuid.uuid4().hex
        total_latency = round((time.monotonic() - overall_start) * 1000, 3)

        if model is not None:
            decision = model.recommendation
            risk_cat = model.risk_category
            risk_sev = model.risk_severity
            reasoning = f"Deterministic: {det.reasoning}. Model: {model.reasoning}"
            classifier_model = model.model
            gateway_meta = {
                "model_latency_ms": model.latency_ms,
                "model_confidence": model.confidence,
            }
        else:
            decision = det.decision
            risk_cat = det.risk_category
            risk_sev = det.risk_severity
            reasoning = det.reasoning
            classifier_model = None
            gateway_meta = None

        return PolicyDecisionRecord(
            decision_id=decision_id,
            agent_id=context.agent_id,
            session_id=context.session_id,
            provider_session_id=context.provider_session_id,
            claude_conversation_id=None,  # Filled by hook
            tool_use_id=request.tool_use_id,
            tool_name=request.tool_name,
            policy_version=context.policy_version,
            decision=decision,
            risk_category=risk_cat,
            risk_severity=risk_sev,
            authorization_evidence_refs=context.authorization_evidence,
            reasoning=reasoning,
            classifier_model=classifier_model,
            gateway_routing_meta=gateway_meta,
            evaluation_latency_ms=total_latency,
            timestamp=utc_now(),
            approval_status="not_applicable",
        )


# ── Hook Response Builders ────────────────────────────────────────────────────

def build_hook_response(decision: PolicyDecision, reasoning: str) -> dict[str, Any]:
    """Build Claude Code hook response using the supported hookSpecificOutput contract.

    Claude Code 2.1.x requires PreToolUse/PostToolUse hooks to return responses
    under the ``hookSpecificOutput`` key with ``permissionDecision`` and
    ``permissionDecisionReason`` fields.  The legacy ``decision`` key format is
    no longer accepted by the installed CLI.
    """
    if decision == PolicyDecision.ALLOW:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": reasoning or "Approved by Diamond policy",
            }
        }
    if decision == PolicyDecision.DENY:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reasoning or "Denied by Diamond policy",
            }
        }
    if decision == PolicyDecision.ASK:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": reasoning or "Requires human approval",
            }
        }
    if decision == PolicyDecision.DEFER:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "defer",
                "permissionDecisionReason": reasoning or "Deferred for external approval",
            }
        }
    # INDETERMINATE → fail closed
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": f"Indeterminate evaluation: {reasoning}",
        }
    }


# ── Policy Store Integration (EventStore) ─────────────────────────────────────

class PolicyDecisionStore:
    """Persists policy decisions to the existing EventStore via agent_runtime_events."""

    def __init__(self, store: Any) -> None:  # EventStore type
        self._store = store

    def record(self, record: PolicyDecisionRecord, command_id: str) -> None:
        """Record decision as an agent_runtime_event."""
        if not self._store._database_present():
            return
        with self._store._connection(write=True) as connection:
            connection.execute(
                "INSERT INTO agent_runtime_events VALUES (?,?,?,?,?,?,?,?)",
                (
                    record.decision_id,
                    "policy_decision",
                    record.agent_id,
                    1,  # revision
                    record.decision.value.upper(),
                    record.timestamp,
                    command_id,
                    record.to_canonical_json(),
                ),
            )


__all__ = [
    "PolicyDecision",
    "RiskSeverity",
    "RiskCategory",
    "PolicyContext",
    "ToolCallRequest",
    "PolicyDecisionRecord",
    "DeterministicPolicyEngine",
    "ModelAssistedClassifier",
    "ClassifierRequest",
    "ClassifierResult",
    "PolicyEvaluator",
    "PolicyDecisionStore",
    "build_hook_response",
]