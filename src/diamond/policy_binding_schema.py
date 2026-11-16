"""SQLite schema for policy-IPC binding records."""

POLICY_IPC_SCHEMA_STATEMENTS = (
    """CREATE TABLE policy_ipc_bindings (
        attempt_id TEXT PRIMARY KEY REFERENCES attempts(attempt_id),
        schema_version INTEGER NOT NULL CHECK(schema_version = 1),
        capability_hash_prefix TEXT NOT NULL,
        revoked INTEGER NOT NULL CHECK(revoked IN (0,1)),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL) WITHOUT ROWID""",
    """CREATE TRIGGER policy_ipc_bindings_no_delete
        BEFORE DELETE ON policy_ipc_bindings
        BEGIN SELECT RAISE(ABORT, 'policy ipc bindings are immutable'); END""",
    """CREATE TRIGGER policy_ipc_bindings_no_replace
        BEFORE INSERT ON policy_ipc_bindings
        WHEN EXISTS (SELECT 1 FROM policy_ipc_bindings WHERE attempt_id=NEW.attempt_id)
        BEGIN SELECT RAISE(ABORT, 'policy ipc bindings cannot be replaced'); END""",
)
