"""SQLite layout for the controller-owned agent runtime spine."""

RUNTIME_SCHEMA_STATEMENTS = (
    """CREATE TABLE agent_identities (
        agent_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL CHECK(schema_version = 1),
        agent_name TEXT NOT NULL, role TEXT NOT NULL, provider TEXT NOT NULL, adapter_id TEXT NOT NULL,
        task_id TEXT NOT NULL REFERENCES tasks(task_id), attempt_id TEXT REFERENCES attempts(attempt_id),
        workflow_id TEXT REFERENCES workflows(workflow_id), parent_agent_id TEXT REFERENCES agent_identities(agent_id),
        created_at TEXT NOT NULL, UNIQUE(agent_name, task_id)) WITHOUT ROWID""",
    """CREATE TABLE delegations (
        delegation_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL CHECK(schema_version = 1),
        parent_task_id TEXT NOT NULL REFERENCES tasks(task_id), parent_attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
        parent_agent_id TEXT NOT NULL REFERENCES agent_identities(agent_id), child_task_id TEXT NOT NULL REFERENCES tasks(task_id),
        child_attempt_id TEXT REFERENCES attempts(attempt_id),
        child_role TEXT NOT NULL, child_provider TEXT NOT NULL, child_adapter_id TEXT NOT NULL,
        workflow_id TEXT REFERENCES workflows(workflow_id), status TEXT NOT NULL,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision >= 1),
        UNIQUE(parent_task_id, parent_attempt_id, child_task_id)) WITHOUT ROWID""",
    """CREATE TABLE agent_sessions (
        session_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL CHECK(schema_version = 1),
        agent_id TEXT NOT NULL REFERENCES agent_identities(agent_id), delegation_id TEXT UNIQUE REFERENCES delegations(delegation_id),
        provider TEXT NOT NULL, adapter_id TEXT NOT NULL, provider_session_id TEXT,
        status TEXT NOT NULL, identity_verified INTEGER NOT NULL CHECK(identity_verified IN (0,1)),
        verified_identity_digest TEXT, created_at TEXT NOT NULL, started_at TEXT, completed_at TEXT,
        updated_at TEXT NOT NULL, terminal_outcome TEXT, revision INTEGER NOT NULL CHECK(revision >= 1)) WITHOUT ROWID""",
    """CREATE TABLE conversations (
        conversation_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL CHECK(schema_version = 1),
        delegation_id TEXT NOT NULL UNIQUE REFERENCES delegations(delegation_id), parent_task_id TEXT NOT NULL REFERENCES tasks(task_id),
        parent_attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id), parent_agent_id TEXT NOT NULL REFERENCES agent_identities(agent_id),
        child_agent_id TEXT NOT NULL REFERENCES agent_identities(agent_id), created_at TEXT NOT NULL) WITHOUT ROWID""",
    """CREATE TABLE conversation_participants (
        conversation_id TEXT NOT NULL REFERENCES conversations(conversation_id), agent_id TEXT NOT NULL REFERENCES agent_identities(agent_id),
        participant_role TEXT NOT NULL CHECK(participant_role IN ('PARENT','CHILD')),
        PRIMARY KEY(conversation_id, agent_id)) WITHOUT ROWID""",
    """CREATE TABLE agent_messages (
        message_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL CHECK(schema_version = 1),
        conversation_id TEXT NOT NULL REFERENCES conversations(conversation_id), sequence_no INTEGER NOT NULL CHECK(sequence_no >= 1),
        sender_session_id TEXT NOT NULL REFERENCES agent_sessions(session_id), recipient_session_id TEXT NOT NULL REFERENCES agent_sessions(session_id),
        correlation_id TEXT NOT NULL, idempotency_key TEXT NOT NULL UNIQUE, payload_json TEXT NOT NULL,
        payload_digest TEXT NOT NULL, created_at TEXT NOT NULL,
        UNIQUE(conversation_id, sequence_no), UNIQUE(conversation_id, correlation_id)) WITHOUT ROWID""",
    """CREATE TABLE message_deliveries (
        message_id TEXT PRIMARY KEY REFERENCES agent_messages(message_id), status TEXT NOT NULL,
        revision INTEGER NOT NULL CHECK(revision >= 1), updated_at TEXT NOT NULL, failure_reason TEXT) WITHOUT ROWID""",
    """CREATE TABLE message_delivery_events (
        event_id TEXT PRIMARY KEY, message_id TEXT NOT NULL REFERENCES agent_messages(message_id), revision INTEGER NOT NULL CHECK(revision >= 1),
        status TEXT NOT NULL, timestamp TEXT NOT NULL, command_id TEXT NOT NULL UNIQUE, payload_json TEXT NOT NULL,
        UNIQUE(message_id, revision)) WITHOUT ROWID""",
    """CREATE TABLE completion_receipts (
        receipt_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL CHECK(schema_version = 1),
        delegation_id TEXT NOT NULL UNIQUE REFERENCES delegations(delegation_id), child_session_id TEXT NOT NULL REFERENCES agent_sessions(session_id),
        child_agent_id TEXT NOT NULL REFERENCES agent_identities(agent_id), child_task_id TEXT NOT NULL REFERENCES tasks(task_id),
        child_attempt_id TEXT REFERENCES attempts(attempt_id), outcome TEXT NOT NULL, provider_session_id TEXT,
        identity_verified INTEGER NOT NULL CHECK(identity_verified IN (0,1)), evidence_digest TEXT NOT NULL,
        accepted INTEGER NOT NULL CHECK(accepted IN (0,1)), created_at TEXT NOT NULL) WITHOUT ROWID""",
    """CREATE TABLE agent_runtime_events (
        event_id TEXT PRIMARY KEY, entity_type TEXT NOT NULL, entity_id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision >= 1),
        event_type TEXT NOT NULL, timestamp TEXT NOT NULL, command_id TEXT NOT NULL UNIQUE, payload_json TEXT NOT NULL) WITHOUT ROWID""",
    """CREATE TABLE agent_runtime_commands (
        command_id TEXT PRIMARY KEY, operation TEXT NOT NULL, request_json TEXT NOT NULL, result_json TEXT NOT NULL) WITHOUT ROWID""",
    """CREATE TRIGGER agent_runtime_events_no_update BEFORE UPDATE ON agent_runtime_events
        BEGIN SELECT RAISE(ABORT, 'agent runtime events are immutable'); END""",
    """CREATE TRIGGER agent_runtime_events_no_delete BEFORE DELETE ON agent_runtime_events
        BEGIN SELECT RAISE(ABORT, 'agent runtime events are immutable'); END""",
    """CREATE TRIGGER agent_runtime_events_no_replace BEFORE INSERT ON agent_runtime_events WHEN EXISTS (
        SELECT 1 FROM agent_runtime_events WHERE event_id=NEW.event_id OR command_id=NEW.command_id)
        BEGIN SELECT RAISE(ABORT, 'agent runtime events cannot be replaced'); END""",
    """CREATE TRIGGER agent_runtime_commands_no_update BEFORE UPDATE ON agent_runtime_commands
        BEGIN SELECT RAISE(ABORT, 'agent runtime commands are immutable'); END""",
    """CREATE TRIGGER agent_runtime_commands_no_delete BEFORE DELETE ON agent_runtime_commands
        BEGIN SELECT RAISE(ABORT, 'agent runtime commands are immutable'); END""",
    """CREATE TRIGGER agent_runtime_commands_no_replace BEFORE INSERT ON agent_runtime_commands WHEN EXISTS (
        SELECT 1 FROM agent_runtime_commands WHERE command_id=NEW.command_id)
        BEGIN SELECT RAISE(ABORT, 'agent runtime commands cannot be replaced'); END""",
    """CREATE TRIGGER completion_receipts_no_update BEFORE UPDATE ON completion_receipts
        BEGIN SELECT RAISE(ABORT, 'completion receipts are immutable'); END""",
    """CREATE TRIGGER completion_receipts_no_delete BEFORE DELETE ON completion_receipts
        BEGIN SELECT RAISE(ABORT, 'completion receipts are immutable'); END""",
    """CREATE TRIGGER completion_receipts_no_replace BEFORE INSERT ON completion_receipts WHEN EXISTS (
        SELECT 1 FROM completion_receipts WHERE receipt_id=NEW.receipt_id OR delegation_id=NEW.delegation_id)
        BEGIN SELECT RAISE(ABORT, 'completion receipts cannot be replaced'); END""",
    """CREATE TRIGGER agent_messages_no_update BEFORE UPDATE ON agent_messages
        BEGIN SELECT RAISE(ABORT, 'agent messages are immutable'); END""",
    """CREATE TRIGGER agent_messages_no_delete BEFORE DELETE ON agent_messages
        BEGIN SELECT RAISE(ABORT, 'agent messages are immutable'); END""",
    """CREATE TRIGGER agent_messages_no_replace BEFORE INSERT ON agent_messages WHEN EXISTS (
        SELECT 1 FROM agent_messages WHERE message_id=NEW.message_id OR idempotency_key=NEW.idempotency_key)
        BEGIN SELECT RAISE(ABORT, 'agent messages cannot be replaced'); END""",
    """CREATE TRIGGER message_delivery_events_no_update BEFORE UPDATE ON message_delivery_events
        BEGIN SELECT RAISE(ABORT, 'message delivery events are immutable'); END""",
    """CREATE TRIGGER message_delivery_events_no_delete BEFORE DELETE ON message_delivery_events
        BEGIN SELECT RAISE(ABORT, 'message delivery events are immutable'); END""",
    """CREATE TRIGGER message_delivery_events_no_replace BEFORE INSERT ON message_delivery_events WHEN EXISTS (
        SELECT 1 FROM message_delivery_events WHERE event_id=NEW.event_id OR command_id=NEW.command_id
            OR (message_id=NEW.message_id AND revision=NEW.revision))
        BEGIN SELECT RAISE(ABORT, 'message delivery events cannot be replaced'); END""",
)

RUNTIME_SCHEMA_OBJECTS = frozenset(
    statement.split()[2] for statement in RUNTIME_SCHEMA_STATEMENTS
)
