"""Immutable SQLite layout for capability assignments and usage audit rows."""

CAPABILITY_SCHEMA_STATEMENTS = (
    """CREATE TABLE capability_bindings (
        binding_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL CHECK(schema_version = 1),
        task_id TEXT NOT NULL REFERENCES tasks(task_id), task_revision INTEGER NOT NULL CHECK(task_revision >= 1),
        attempt_id TEXT NOT NULL UNIQUE REFERENCES attempts(attempt_id), accepted_packet_id TEXT NOT NULL REFERENCES accepted_packets(accepted_packet_id),
        packet_digest TEXT NOT NULL,
        provider_id TEXT NOT NULL, adapter_id TEXT NOT NULL, adapter_contract_version TEXT NOT NULL,
        manifest_digest TEXT NOT NULL, execution_mode TEXT NOT NULL,
        requested_skills_json TEXT NOT NULL, assigned_skills_json TEXT NOT NULL, available_capabilities_json TEXT NOT NULL,
        requested_tools_json TEXT NOT NULL, authorized_tools_json TEXT NOT NULL, available_tools_json TEXT NOT NULL,
        provider_tools_json TEXT NOT NULL, mcp_integrations_json TEXT NOT NULL, plugin_integrations_json TEXT NOT NULL,
        workspace_root TEXT NOT NULL, owned_paths_json TEXT NOT NULL, permission_mode TEXT NOT NULL,
        sandbox_profile TEXT NOT NULL, network_access TEXT NOT NULL, resource_limits_json TEXT NOT NULL,
        delegation_constraints_json TEXT NOT NULL, created_at TEXT NOT NULL, capability_digest TEXT NOT NULL,
        command_id TEXT NOT NULL UNIQUE, request_json TEXT NOT NULL,
        UNIQUE(task_id, task_revision)) WITHOUT ROWID""",
    """CREATE TABLE capability_usage (
        usage_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL CHECK(schema_version = 1),
        binding_id TEXT NOT NULL REFERENCES capability_bindings(binding_id), capability_kind TEXT NOT NULL,
        capability_name TEXT NOT NULL, usage_status TEXT NOT NULL CHECK(usage_status IN ('UNKNOWN','VERIFIED','NOT_USED')),
        evidence_json TEXT NOT NULL, observed_at TEXT NOT NULL, command_id TEXT NOT NULL UNIQUE,
        request_json TEXT NOT NULL) WITHOUT ROWID""",
    """CREATE TRIGGER capability_bindings_no_update BEFORE UPDATE ON capability_bindings
        BEGIN SELECT RAISE(ABORT, 'capability bindings are immutable'); END""",
    """CREATE TRIGGER capability_bindings_no_delete BEFORE DELETE ON capability_bindings
        BEGIN SELECT RAISE(ABORT, 'capability bindings are immutable'); END""",
    """CREATE TRIGGER capability_bindings_no_replace BEFORE INSERT ON capability_bindings WHEN EXISTS (
        SELECT 1 FROM capability_bindings WHERE binding_id=NEW.binding_id OR command_id=NEW.command_id
            OR attempt_id=NEW.attempt_id OR (task_id=NEW.task_id AND task_revision=NEW.task_revision))
        BEGIN SELECT RAISE(ABORT, 'capability bindings cannot be replaced'); END""",
    """CREATE TRIGGER capability_usage_no_update BEFORE UPDATE ON capability_usage
        BEGIN SELECT RAISE(ABORT, 'capability usage is immutable'); END""",
    """CREATE TRIGGER capability_usage_no_delete BEFORE DELETE ON capability_usage
        BEGIN SELECT RAISE(ABORT, 'capability usage is immutable'); END""",
    """CREATE TRIGGER capability_usage_no_replace BEFORE INSERT ON capability_usage WHEN EXISTS (
        SELECT 1 FROM capability_usage WHERE usage_id=NEW.usage_id OR command_id=NEW.command_id)
        BEGIN SELECT RAISE(ABORT, 'capability usage cannot be replaced'); END""",
)

CAPABILITY_SCHEMA_OBJECTS = frozenset(statement.split()[2] for statement in CAPABILITY_SCHEMA_STATEMENTS)
