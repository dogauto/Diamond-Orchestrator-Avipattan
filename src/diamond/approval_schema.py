"""SQLite schema for Diamond-owned persistent human approval state.

An approval request is created when the policy classifier returns ASK. It is
resolved only by an authorized human operator through the Diamond CLI. The
Controller remains the final authorization authority: an APPROVED record is
evidence that a human approved, never by itself a license to execute. The
PolicyIPCServer binds execution to the exact approved operation before the
hook may return ALLOW.

Immutability: resolved approvals cannot be overwritten. Pending requests may
be updated exactly once to a terminal decision or CANCELLED. After consumption
(approval granted and used for one execution), the record becomes CONSUMED.
Expire is set by the store.expire_approvals() helper.
"""

APPROVAL_SCHEMA_STATEMENTS = (
    """CREATE TABLE agent_approval_state (
        approval_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL CHECK(schema_version = 1),
        agent_id TEXT NOT NULL, task_id TEXT NOT NULL,
        attempt_id TEXT, execution_id TEXT,
        tool_name TEXT NOT NULL, tool_input_hash TEXT NOT NULL,
        requested_permissions_json TEXT NOT NULL, approval_status TEXT NOT NULL
            CHECK(approval_status IN ('PENDING','APPROVED','DENIED','EXPIRED','CANCELLED','CONSUMED')),
        policy_reason TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT,
        decided_at TEXT, approver_identity TEXT, decision_evidence_json TEXT,
        command_id TEXT NOT NULL UNIQUE, request_json TEXT NOT NULL,
        UNIQUE(agent_id, task_id, attempt_id, tool_name, tool_input_hash)) WITHOUT ROWID""",
    """CREATE INDEX agent_approval_state_status ON agent_approval_state(approval_status, created_at)""",
    """CREATE INDEX agent_approval_state_agent ON agent_approval_state(agent_id, task_id, approval_status)""",
    # Allow updating PENDING and APPROVED states; reject all other mutations including overwrite of resolved records.
    """CREATE TRIGGER agent_approval_state_only_pending_update
       BEFORE UPDATE ON agent_approval_state
       WHEN OLD.approval_status NOT IN ('PENDING', 'EXPIRED', 'APPROVED')
       BEGIN SELECT RAISE(ABORT, 'approval state is immutable once resolved'); END""",
    """CREATE TRIGGER agent_approval_state_no_delete BEFORE DELETE ON agent_approval_state
        BEGIN SELECT RAISE(ABORT, 'approval state is immutable'); END""",
    """CREATE TRIGGER agent_approval_state_no_replace BEFORE INSERT ON agent_approval_state
        WHEN EXISTS (SELECT 1 FROM agent_approval_state WHERE approval_id=NEW.approval_id
            OR command_id=NEW.command_id
            OR (agent_id=NEW.agent_id AND task_id=NEW.task_id AND attempt_id IS NEW.attempt_id
                AND tool_name=NEW.tool_name AND tool_input_hash=NEW.tool_input_hash))
        BEGIN SELECT RAISE(ABORT, 'approval state cannot be replaced'); END""",
)