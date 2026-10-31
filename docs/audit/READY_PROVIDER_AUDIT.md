# Provider Readiness and Native Delegation Audit
## Flawless Diamond Piece — Read-Only Audit

**Scope**: Audit all provider execution paths in the Diamond controller codebase.
**Constraints**: Read-only. Do not modify any files. Do not invoke providers or launch live sessions.

---

## 1. EXECUTIVE VERDICT

**Status: NO REAL PROVIDER INTEGRATIONS EXIST.**

The codebase defines a comprehensive provider execution contract (`ProviderAdapter` protocol at `src/diamond/provider_execution.py:310`) and supporting runtime spine (`AgentSession`, `Delegation`, `CompletionReceipt` at `src/diamond/agent_runtime.py`), but **no concrete adapter implementations exist** for any of the six listed providers (Claude, Codex, Gemini, Antigravity, OmniRush, Copilot). The `ProviderAdapter` Protocol is never instantiated — only the protocol definition, a test helper (`FakeChildAdapter`), and unrelated adapters (SessionAdapter for tmux) exist.

Provider execution paths are gated and validated but never exercised. The `ProviderExecutionGateway.execute()` at `src/diamond/provider_gateway.py:87` validates registry state, binding, and adapter identity before every call, but the adapter's `execute()` method is never called because no registered adapter implements it. Real CLI integration (`src/diamond/transport/real_cli_integration.py`) exists as an opt-in guard behind `DIAMOND_REAL_CLI=1` but operates at the subprocess level and does not integrate with Diamond's persisted conversation model or child-session spine.

**Conclusion**: The codebase has the *contract architecture* for provider integration but lacks the *implementations*. The next implementation slice must create concrete ProviderAdapter instances for at least one provider and wire them through the gateway → discovery → registry spine.

---

## 2. PROVIDER-BY-PROVIDER READINESS MATRIX

| Capability | Claude | Codex | Gemini | Antigravity | OmniRush | Copilot |
|---|---|---|---|---|---|---|
| **Provider listed in code** | ✅ `Provider.CLAUDE` (adapters.py:69) | ✅ `Provider.CODEX` (adapters.py:78) | ❌ Not found in `adapters.py` argv builders | ❌ Not found in `adapters.py` argv builders | ✅ `Provider.OMNIRUSH` (adapters.py:140) | ✅ `Provider.COPILOT` (adapters.py:147) |
| **One-shot execution** | ❌ No adapter implements `execute()` | ❌ No adapter implements `execute()` | ❌ Not in scope | ❌ Not in scope | ❌ No adapter implements `execute()` | ❌ No adapter implements `execute()` |
| **Persistent/interactive sessions** | ❌ Not implemented | ❌ Not implemented | ❌ Not implemented | ❌ Not implemented | ❌ Not implemented | ❌ Not implemented |
| **Native subagent dispatch** | ❌ No adapter protocol implementation | ❌ No adapter protocol implementation | ❌ Not in scope | ❌ Not in scope | ❌ No adapter protocol implementation | ❌ No adapter protocol implementation |
| **Diamond-managed child sessions** | ❌ No execution path | ❌ No execution path | ❌ No execution path | ❌ No execution path | ❌ No execution path | ❌ No execution path |
| **Bidirectional messaging** | ❌ No message path established | ❌ No message path established | ❌ Not in scope | ❌ Not in scope | ❌ No message path established | ❌ No message path established |
| **Streaming events** | ❌ Not in contract | ❌ Not in contract | ❌ Not in scope | ❌ Not in scope | ❌ Not in contract | ❌ Not in contract |
| **Cancellation and cleanup** | ❌ Protocol defined but not implemented | ❌ Protocol defined but not implemented | ❌ Not in scope | ❌ Not in scope | ❌ Protocol defined but not implemented | ❌ Protocol defined but not implemented |
| **Verified model identity** | ❌ Not exercised | ❌ Not exercised | ❌ Not in scope | ❌ Not in scope | ❌ Not exercised | ❌ Not exercised |
| **Capability and tool binding** | ❌ No adapter registered | ❌ No adapter registered | ❌ Not in scope | ❌ Not in scope | ❌ No adapter registered | ❌ No adapter registered |

**Underlying provider-product capabilities vs Diamond implementation**: All six providers advertise capabilities in their own products (Claude Code, Codex CLI, Gemini API, etc.), but Diamond's codebase implements only the *contract skeleton*. The `adapters.py` file builds invocation argv for all six providers, but these are pureargv builders — they do not connect to actual provider CLIs through Diamond's execution spine.

---

## 3. EVIDENCE WITH EXACT FILE PATHS AND LINE RANGES

### 3.1 ProviderAdapter Protocol — Defined but Never Implemented

- **File**: `src/diamond/provider_execution.py:310-335`
- **Content**: `class ProviderAdapter(Protocol)` with methods: `discover`, `validate`, `health_check`, `execute`, `normalize_result`, `cancel`
- **Status**: Protocol only. No class implements this protocol. Comment at `src/diamond/provider_execution.py:5533` confirms: *"grep reveals no concrete ProviderAdapter implementations; only the Protocol, a test helper, and unrelated adapters exist."*

### 3.2 ProviderExecutionGateway — Validates but Cannot Execute

- **File**: `src/diamond/provider_gateway.py:87-133`
- **Method**: `execute(provider_id: str, request: TaskExecutionRequest) -> NormalizedExecutionResult`
- **What it does**: Validates registry state (`descriptor.state is ProviderState.EXECUTION_AUTHORIZED`), adapter contract, routing, then calls `descriptor.adapter.execute(request)` at line 104
- **The gap**: Line 104 calls `adapter.execute(request)` but no registered adapter implements this method. The gateway would raise `ValidationError("adapter returned an invalid raw execution result")` at line 105-106 because the result wouldn't be a `ProviderRawExecution`.

### 3.3 DiscoveryEngine — Uses Adapters That Don't Exist

- **File**: `src/diamond/provider_discovery.py:206-244`
- **Method**: `discover(candidates, adapters) -> tuple[DiscoveryRecord, ...]`
- **The gap**: At line 214-215, it looks up `adapters.get(candidate.adapter_id)`. If the adapter is None or doesn't have a `discover` method, it records `DiscoveryState.UNTRUSTED` with detail `"no compatible trusted adapter is registered"`. No trusted adapters are registered in the codebase.

### 3.4 Registry State Transitions — No Execution Path

- **File**: `src/diamond/provider_registry.py:235-260`
- **Method**: `mark_available(provider_id)` — requires `ProviderState.VALIDATED`
- **Problem**: Providers can never reach `VALIDATED` state because discovery never produces a trusted adapter, and the registry has no mechanism to create one.

### 3.5 Real CLI Integration — Opt-In, Not Integrated

- **File**: `src/diamond/transport/real_cli_integration.py:238-287`
- **Method**: `request_task(agent, prompt, correlation_id, task_id, timeout, metadata) -> RealCLIResponse`
- **Mechanism**: Invokes `claude -p <prompt>` or `codex exec --json <prompt>` via subprocess, captures JSON or JSONL output
- **Limitation**: Standalone subprocess invocation. Does NOT:
  - Create `AgentSession` records in the EventStore
  - Wire responses into the `Delegation` / `CompletionReceipt` spine
  - Produce normalized results through `ProviderExecutionGateway`
  - Link to the persisted conversation model
- **Guard**: `src/diamond/transport/real_cli_guard.py:31-49` — enabled via `DIAMOND_REAL_CLI=1` env var. All integration tests fall back to deterministic fake processes when not enabled.

### 3.6 Fake Child Adapter — Exercises Contract Without Provider

- **File**: `src/diamond/fake_child_adapter.py:27-74`
- **Class**: `DeterministicChildAdapter`
- **Purpose**: Runs one local, provider-free child conversation through the controller. Exercises the same `EventStore` runtime contract as a future real child adapter. Never launches a provider or reads provider credentials.
- **Role**: Test double. Confirms the spine (`child_session`, `verify_session_identity`, `complete_child`, `record_evidence`) works deterministically.

### 3.7 Agent Runtime Spine — Value Objects Ready for Provider Binding

- **File**: `src/diamond/agent_runtime.py:83-361`
- **Classes**: `AgentIdentity`, `AgentSession`, `Delegation`, `Conversation`, `AgentMessage`, `CompletionReceipt`, `ChildOutcome`, `DelegationStatus`, `DeliveryStatus`
- **Status**: Fully defined with durable identities (32-char hex IDs, SHA-256 digests), status enums, and `to_dict()` serialization. These are the acceptance target for any provider integration.

### 3.8 Store Mixin — Persistence Ready for Child Sessions

- **File**: `src/diamond/runtime_store.py:299-336`
- **Method**: `child_session(delegation_id, session_id, agent_id, command_id, *, provider_session_id=None) -> AgentSession`
- **What it does**: Creates a child session under an authorized delegation, verifies agent identity matches delegation, updates delegation status to `STARTED`, persists events
- **Readiness**: The persistence path is complete. What's missing is the provider execution that creates the delegation in the first place.

### 3.9 Controller Dispatch — References ProviderGateway but Never Calls Adapter.execute

- **File**: `src/diamond/controller.py:221-224`
- **Code**: `generic_result = provider_gateway.execute(accepted_packet.binding.provider_id, _generic_request(packet, started))`
- **Flow**: Controller calls `ProviderExecutionGateway.execute()` which should call `adapter.execute(request)`, but since no adapter exists, this path would fail at the gateway validation step.

---

## 4. CURRENT EXECUTION AND DELEGATION LIMITATIONS

### 4.1 No Provider Execution Path from Controller to Adapter

The controller's `run_persisted` flow (controller.py) reaches `provider_gateway.execute()` but the gateway cannot complete because:

1. **Registry has no valid advisor**: `descriptor.adapter is None` (provider_gateway.py:94-95) or `descriptor.state ≠ ProviderState.EXECUTION_AUTHORIZED`
2. **No binding exists**: The accepted packet binding references a provider whose adapter is not registered
3. **Adapter contract invalid**: Even if an adapter were registered, `validate_adapter_contract()` would need to pass

### 4.2 No Child Session Launch Through Provider

The `child_session()` method at `runtime_store.py:299` requires an `AUTHORIZED` delegation (line 317: `if delegation.status is not DelegationStatus.AUTHORIZED`). But there is no code path that:

- Creates a delegation via `authorize_delegation()` with a child provider that has an executable adapter
- Launches a provider session and binds its `provider_session_id` back to the child session
- Persists the child's completion as a `CompletionReceipt` with verified identity

### 4.3 No Bidir Messaging Between Providers

The message-delivery spine (`AgentMessage`, `MessageDelivery` at agent_runtime.py:249-319) exists but has no operational path:

- `send_agent_message()` / `acknowledge_message()` exist in `fake_child_adapter.py` but only for test determinism
- No real provider adapter sends messages through the conversation model
- No routing bus exists to forward messages from Claude Builder → Diamond message bus → Codex Reviewer

### 4.4 Cancellation Not Integrated

`ProviderExecutionGateway.cancel()` at provider_gateway.py:121-133 validates and calls `descriptor.adapter.cancel(request)`, but no adapter implements `cancel()`. The `CancellationRequest` and `CancellationResult` dataclasses are fully defined but never instantiated in an execution context.

### 4.5 Normalization Never Reached

`AdapterContract.normalize_result()` at provider_execution.py:331 is part of the protocol but is never called because `adapter.execute()` is never reached. The `NormalizedExecutionResult` dataclass (provider_execution.py:149-201) with its `verified_model`, `model_selection`, and provenance fields is construct-ready but structurally untested.

---

## 5. RECOMMENDED FIRST REAL-PROVIDER INTEGRATION SLICE

**Recommendation**: Integrate **Claude Code** as the first real provider, because:

1. **Evidence availability**: `DIAMOND_REAL_CLI=1` already has a mechanism to invoke `claude -p <prompt>` (real_cli_integration.py:97-139). The infrastructure to launch Claude and capture output exists.
2. **Auth status**: Claude's auth status is already reported as `NOT_CHECKED` by `diamond doctor` and all CLI probes (observation at provider_execution.py:5509). This means the integration can start from a known baseline.
3. **Model identity**: Claude provides explicit model reporting via `--model` flag and JSON output, enabling `verified_model` tracking.
4. **Existing argv builder**: `adapters.py:74-168` already builds `Invocation` for `Provider.CLAUDE` with all per-provider capability gates.

**Minimum acceptance sequence to implement**:

```
Step 1: Register a ClaudeCodeAdapter implementing ProviderAdapter Protocol
  - discover(): probe `claude --version`, return VersionProbeResult
  - validate(): validate CapabilityManifest contract
  - health_check(): check auth readiness (currently NOT_CHECKED)
  - get_capabilities(): return CapabilityManifest with ONE_SHOT_EXECUTION
  - execute(): launch `claude -p <prompt>` via subprocess, capture output, return ProviderRawExecution
  - normalize_result(): map raw output to NormalizedExecutionResult with provenance
  - cancel(): terminate outstanding claude process

Step 2: Wire through registry
  - Register adapter in ProviderRegistry with adapter_id="claude-code"
  - Run DiscoveryEngine.discover() to transition state from DECLARED → DISCOVERED
  - mark_available() to reach AVAILABLE state

Step 3: Execute through gateway
  - ProviderExecutionGateway.execute() validates binding + registry + adapter contract
  - Calls adapter.execute(request) → returns ProviderRawExecution
  - adapter.normalize_result() → NormalizedExecutionResult with verified_model

Step 4: Persist in spine
  - Create delegation via authorize_delegation() with child_provider=Provider.CLAUDE
  - Create agent session via child_session() with provider_session_id from step 3
  - Persist CompletionReceipt with evidence_digest from normalized result

Step 5: Verify closure
  - Controller reads completion status from Attempt record
  - result.session_id, result.reported_model, result.evidence_digest are authoritative
```

**Why not Codex first?** Codex CLI integration exists (real_cli_integration.py:147-206) but Codex's JSONL output format is more complex to parse for normalized results. Claude's `-p` flag produces simpler JSON or text output, making the initial normalization path less fragile.

**Why not Gemini?** Gemini is not in the `adapters.py` argv builders, meaning no invocation template exists. Would need to build from scratch.

---

## 6. ACCEPTANCE TESTS AND SAFETY CONDITIONS

### 6.1 Minimum Acceptance Test Sequence

**Test**: End-to-end provider execution through Diamond spine

1. `DIAMOND_REAL_CLI=1` is set (opt-in only)
2. Provider registry has a registered ClaudeCodeAdapter
3. `DiscoveryEngine.discover()` returns `DISCOVERED` state for Claude
4. `ProviderExecutionGateway.execute()` completes without ValidationError
5. `NormalizedExecutionResult` is returned with:
   - `provider_id` matching the requested provider
   - `task_id` and `correlation_id` matching the request
   - `reported_model` populated from Claude's output
   - `events` tuple containing at least one `ExecutionEvent`
   - `provenance` matching the registered adapter's identity
6. Controller records `Attempt` with `status = AttemptStatus.SUCCEEDED` or `AttemptStatus.FAILED`
7. No secrets are logged or persisted in evidence

**Safety conditions that must hold**:

- [ ] `DIAMOND_REAL_CLI=1` must be explicitly set by operator — never default on
- [ ] No provider CLI executable path is hardcoded; all paths come from registry/config
- [ ] `execute()` has a bounded timeout (30s default, configurable via `TaskExecutionRequest.timeout_seconds`)
- [ ] `cancel()` can interrupt an outstanding provider process
- [ ] `stderr` is captured but never exposed in `evidence` digests unless it's the diagnostic payload
- [ ] `ProviderRawExecution.exit_code` and `signal` are recorded for cancellation decisions
- [ ] No `rm -rf` or destructive operations are triggered by provider output
- [ ] Captured `stdout`/`stderr` is redacted if it contains credential-like patterns before persistence

### 6.2 Re-check Required After Other Implementation Session

The concurrent engineering session implementing "capability binding, scheduler concurrency, and the Live Agent Council TUI" may have:

- Added concrete `ProviderAdapter` implementations
- Wired `ProviderExecutionGateway` through the controller flow
- Created real child session launch paths
- Integrated bidirectional messaging between providers

**Before concluding this audit**, re-read these files to confirm whether any concrete adapters have been added:
- `src/diamond/provider_execution.py` — check for any class implementing `ProviderAdapter`
- `src/diamond/provider_registry.py` — check for any registered descriptors with `adapter !== None`
- `src/diamond/provider_gateway.py` — check if `adapter.execute()` calls now succeed
- `src/diamond/transport/real_cli_integration.py` — check if spine wiring has been added

---

## 7. FINDINGS REQUIRING RECHECK AFTER OTHER SESSION

| Finding | File | Current State | Needs Recheck |
|---|---|---|---|
| No `ProviderAdapter` implementations exist | `provider_execution.py:310` | Protocol only, no subclasses | ✅ After concurrent session |
| No adapters registered in registry | `provider_registry.py:132` | Empty registry by default | ✅ After concurrent session |
| `ProviderExecutionGateway.execute()` cannot complete | `provider_gateway.py:87` | Gateway validates but adapter.execute() never called | ✅ After concurrent session |
| Real CLI integration opt-in only, not spine-wired | `real_cli_integration.py:238` | Standalone subprocess, no EventStore binding | ✅ After concurrent session |
| Child session launch path non-existent | `runtime_store.py:299` | Method exists but no caller creates delegations with executable adapters | ✅ After concurrent session |
| Bidirectional provider messaging not implemented | `agent_runtime.py:249` | Message types defined but no operational routing | ✅ After concurrent session |
| Cancellation not integrated | `provider_gateway.py:121` | Protocol defined callers | ✅ After concurrent session |
| `verified_model` tracking never exercised | `normalized_result.py:159` | Field defined but never populated | ✅ After concurrent session |

---
*End of Audit Report. This is a read-only document. Do not modify any code files.*