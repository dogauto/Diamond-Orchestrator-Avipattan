"""Phase 3A tests: EventStore execution-state methods."""
from unittest import TestCase
import sqlite3
import tempfile
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from diamond.domain import (
    TaskSnapshot,
    TaskSpec,
    TaskStatus,
    Role,
    Provider,
)
from diamond.store import EventStore
from diamond.errors import (
    CommandConflictError,
    ConflictError,
    ExecutionGuardError,
    NotFoundError,
    StorageError,
    ValidationError,
)
from diamond.replay import replay_events
from diamond.validation import canonical_json
from tests.support import OTHER_ID, TASK_ID, ProjectCase


class TestBeginExecution(TestCase):
    def _make_store(self, database_path: Path | None = None) -> EventStore:
        if database_path is None:
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            database_path = Path(temporary.name) / "test.db"
        return EventStore(database_path)

    def _make_spec(self) -> TaskSpec:
        return TaskSpec(TASK_ID, "test objective", Role.BUILDER, Provider.CLAUDE)

    def test_begin_execution_sets_running(self) -> None:
        store = self._make_store()
        spec = self._make_spec()
        store.create(spec, "create:1")
        snap = store.begin_execution(TASK_ID, "a"*32, 1, "begin:1")
        self.assertEqual(snap.status, TaskStatus.CREATED)
        self.assertEqual(snap.execution_status, TaskStatus.RUNNING)
        self.assertEqual(snap.execution_attempt_id, "a"*32)

    def test_begin_execution_idempotent(self) -> None:
        store = self._make_store()
        spec = self._make_spec()
        store.create(spec, "create:1")
        # First call succeeds
        snap1 = store.begin_execution(TASK_ID, "a"*32, 1, "begin:1")
        # Only an identical request can reuse a command ID.
        snap2 = store.begin_execution(TASK_ID, "a"*32, 1, "begin:1")
        self.assertEqual(snap1, snap2)
        for attempt_id, revision in (("b" * 32, 1), ("a" * 32, 2)):
            with self.subTest(attempt_id=attempt_id, revision=revision), self.assertRaises(CommandConflictError):
                store.begin_execution(TASK_ID, attempt_id, revision, "begin:1")
        self.assertEqual(store.get(TASK_ID), snap1)
        self.assertEqual(len(store.events(TASK_ID)), 2)

    def test_begin_execution_wrong_revision(self) -> None:
        store = self._make_store()
        spec = self._make_spec()
        store.create(spec, "create:1")
        with self.assertRaises(ConflictError):
            store.begin_execution(TASK_ID, "a"*32, 999, "begin:1")

    def test_begin_execution_non_creatable_status(self) -> None:
        store = self._make_store()
        spec = self._make_spec()
        # BLOCKED task should not be able to begin execution
        store.create(spec, "create:1")
        store.transition(TASK_ID, TaskStatus.BLOCKED, 1, "block:1", "awaiting prerequisite")
        with self.assertRaises(ExecutionGuardError):
            store.begin_execution(TASK_ID, "a"*32, 2, "begin:1")

    def test_begin_execution_already_has_record(self) -> None:
        store = self._make_store()
        spec = self._make_spec()
        store.create(spec, "create:1")
        store.begin_execution(TASK_ID, "a"*32, 1, "begin:1")
        with self.assertRaises(ExecutionGuardError):
            store.begin_execution(TASK_ID, "b"*32, 2, "begin:2")


class TestCompleteExecution(TestCase):
    def _make_store(self, database_path: Path | None = None) -> EventStore:
        if database_path is None:
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            database_path = Path(temporary.name) / "test.db"
        return EventStore(database_path)

    def _make_spec(self) -> TaskSpec:
        return TaskSpec(TASK_ID, "test objective", Role.BUILDER, Provider.CLAUDE)

    def test_complete_execution_sets_succeeded(self) -> None:
        store = self._make_store()
        spec = self._make_spec()
        store.create(spec, "create:1")
        store.begin_execution(TASK_ID, "a"*32, 1, "begin:1")
        snap = store.complete_execution(TASK_ID, TaskStatus.SUCCEEDED, 2, "complete:1", "done")
        self.assertEqual(snap.execution_status, TaskStatus.SUCCEEDED)

    def test_complete_execution_sets_failed(self) -> None:
        store = self._make_store()
        spec = self._make_spec()
        store.create(spec, "create:1")
        store.begin_execution(TASK_ID, "a"*32, 1, "begin:1")
        snap = store.complete_execution(TASK_ID, TaskStatus.FAILED, 2, "complete:1", "error detail")
        self.assertEqual(snap.execution_status, TaskStatus.FAILED)

    def test_complete_execution_idempotent(self) -> None:
        store = self._make_store()
        spec = self._make_spec()
        store.create(spec, "create:1")
        store.begin_execution(TASK_ID, "a"*32, 1, "begin:1")
        # First completion succeeds
        snap1 = store.complete_execution(TASK_ID, TaskStatus.SUCCEEDED, 2, "complete:1", "first")
        snap2 = store.complete_execution(TASK_ID, TaskStatus.SUCCEEDED, 2, "complete:1", "first")
        self.assertEqual(snap1, snap2)
        for status, revision, detail in ((TaskStatus.FAILED, 2, "first"),
                                         (TaskStatus.SUCCEEDED, 3, "first"),
                                         (TaskStatus.SUCCEEDED, 2, "second")):
            with self.subTest(status=status, revision=revision, detail=detail), self.assertRaises(CommandConflictError):
                store.complete_execution(TASK_ID, status, revision, "complete:1", detail)
        self.assertEqual(store.get(TASK_ID), snap1)
        self.assertEqual(len(store.events(TASK_ID)), 3)

    def test_complete_execution_wrong_status(self) -> None:
        store = self._make_store()
        spec = self._make_spec()
        store.create(spec, "create:1")
        # Cannot complete without begin_execution
        with self.assertRaises(ExecutionGuardError):
            store.complete_execution(TASK_ID, TaskStatus.FAILED, 1, "complete:1")

    def test_complete_execution_wrong_revision(self) -> None:
        store = self._make_store()
        spec = self._make_spec()
        store.create(spec, "create:1")
        store.begin_execution(TASK_ID, "a"*32, 1, "begin:1")
        with self.assertRaises(ConflictError):
            store.complete_execution(TASK_ID, TaskStatus.SUCCEEDED, 999, "complete:1")

    def test_complete_execution_non_running_fails(self) -> None:
        store = self._make_store()
        spec = self._make_spec()
        store.create(spec, "create:1")
        # Status is CREATED, not RUNNING
        with self.assertRaises(ExecutionGuardError):
            store.complete_execution(TASK_ID, TaskStatus.FAILED, 1, "complete:1")

    def test_complete_execution_non_succeeded_or_failed(self) -> None:
        store = self._make_store()
        spec = self._make_spec()
        store.create(spec, "create:1")
        store.begin_execution(TASK_ID, "a"*32, 1, "begin:1")
        with self.assertRaises(ValidationError):
            store.complete_execution(TASK_ID, TaskStatus.BLOCKED, 2, "complete:1")


class TestRecoveryInterruptedTasks(TestCase):
    def _make_store(self, database_path: Path | None = None) -> EventStore:
        if database_path is None:
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            database_path = Path(temporary.name) / "test.db"
        return EventStore(database_path)

    def _make_spec(self) -> TaskSpec:
        return TaskSpec(TASK_ID, "test objective", Role.BUILDER, Provider.CLAUDE)

    def test_recover_interrupted_tasks_finds_running(self) -> None:
        store = self._make_store()
        spec = self._make_spec()
        store.create(spec, "recover:1")
        store.begin_execution(TASK_ID, "a"*32, 1, "begin:1")
        # Recovery marks task UNCERTAIN (outcome unknown, not confirmed failure)
        recovered = store.recover_interrupted_tasks("recover:1", "process crashed")
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0].execution_status, TaskStatus.UNCERTAIN)

    def test_recover_interrupted_tasks_idempotent(self) -> None:
        store = self._make_store()
        spec = self._make_spec()
        store.create(spec, "recover:1")
        store.begin_execution(TASK_ID, "a"*32, 1, "begin:1")
        # First recovery
        r1 = store.recover_interrupted_tasks("recover:1", "process crashed")
        self.assertEqual(len(r1), 1)
        # Second recovery finds nothing already recovered
        r2 = store.recover_interrupted_tasks("recover:1", "process crashed")
        self.assertEqual(len(r2), 0)

    def test_recover_interrupted_tasks_no_running(self) -> None:
        store = self._make_store()
        spec = self._make_spec()
        store.create(spec, "recover:1")
        # No execution started, so nothing to recover
        recovered = store.recover_interrupted_tasks("recover:1", "process crashed")
        self.assertEqual(len(recovered), 0)


class TestTransitionGuards(TestCase):
    def _make_store(self, database_path: Path | None = None) -> EventStore:
        if database_path is None:
            temporary = tempfile.TemporaryDirectory()
            self.addCleanup(temporary.cleanup)
            database_path = Path(temporary.name) / "test.db"
        return EventStore(database_path)

    def _make_spec(self) -> TaskSpec:
        return TaskSpec(TASK_ID, "test objective", Role.BUILDER, Provider.CLAUDE)

    def test_transition_requires_valid_target(self) -> None:
        store = self._make_store()
        spec = self._make_spec()
        store.create(spec, "create:1")
        # READY is not a valid target (not in foundation or execution states)
        with self.assertRaises(ExecutionGuardError):
            store.transition(TASK_ID, TaskStatus.READY, 1, "trans:1")

    def test_transition_to_execution_state_requires_begin(self) -> None:
        store = self._make_store()
        spec = self._make_spec()
        store.create(spec, "create:1")
        # Cannot transition to RUNNING without begin_execution
        with self.assertRaises(ExecutionGuardError):
            store.transition(TASK_ID, TaskStatus.RUNNING, 1, "trans:1")

    def test_transition_foundation_still_works(self) -> None:
        store = self._make_store()
        spec = self._make_spec()
        store.create(spec, "create:1")
        # Foundation transitions remain valid
        snap = store.transition(TASK_ID, TaskStatus.BLOCKED, 1, "trans:1", "reason")
        self.assertEqual(snap.status, TaskStatus.BLOCKED)
        snap2 = store.transition(TASK_ID, TaskStatus.CREATED, 2, "trans:2", "resolved")
        self.assertEqual(snap2.status, TaskStatus.CREATED)


class TestExecutionPersistence(ProjectCase):
    def setUp(self) -> None:
        super().setUp()
        self.database = self.project / "state" / "ledger.sqlite3"
        self.store = EventStore(self.database)
        self.spec = TaskSpec(TASK_ID, "durable execution projection", Role.BUILDER, Provider.CLAUDE)

    def test_command_ids_conflict_across_creation_start_and_completion(self) -> None:
        initial = self.store.create(self.spec, "create")
        with self.assertRaises(CommandConflictError):
            self.store.begin_execution(TASK_ID, OTHER_ID, 1, "create")
        self.assertEqual(self.store.get(TASK_ID), initial)
        running = self.store.begin_execution(TASK_ID, OTHER_ID, 1, "begin")
        for command in ("create", "begin"):
            with self.subTest(command=command), self.assertRaises(CommandConflictError):
                self.store.complete_execution(TASK_ID, TaskStatus.SUCCEEDED, 2, command)
        with self.assertRaises(CommandConflictError):
            self.store.transition(TASK_ID, TaskStatus.CANCELLED, 2, "begin")
        self.assertEqual(self.store.get(TASK_ID), running)
        self.assertEqual([event.command_id for event in self.store.events(TASK_ID)], ["create", "begin"])

    def test_reopen_replay_and_identical_retries_preserve_exact_snapshots(self) -> None:
        self.store.create(self.spec, "create")
        running = self.store.begin_execution(TASK_ID, OTHER_ID, 1, "begin")
        self.assertEqual(EventStore(self.database).replay(TASK_ID), running)
        completed = self.store.complete_execution(TASK_ID, TaskStatus.SUCCEEDED, 2, "complete", "done")
        reopened = EventStore(self.database)
        self.assertEqual(reopened.get(TASK_ID), completed)
        self.assertEqual(reopened.replay(TASK_ID), completed)
        self.assertEqual(completed.status, TaskStatus.CREATED)
        self.assertEqual(reopened.begin_execution(TASK_ID, OTHER_ID, 1, "begin"), running)
        self.assertEqual(reopened.complete_execution(TASK_ID, TaskStatus.SUCCEEDED, 2, "complete", "done"), completed)
        self.assertEqual([event.revision for event in reopened.events(TASK_ID)], [1, 2, 3])

    def test_failed_event_insert_rolls_back_projection_and_command_then_retries(self) -> None:
        initial = self.store.create(self.spec, "create")
        for event_type, operation in (
            ("TASK_EXECUTION_STARTED", lambda: self.store.begin_execution(TASK_ID, OTHER_ID, 1, "begin")),
            ("TASK_EXECUTION_COMPLETED", lambda: self.store.complete_execution(TASK_ID, TaskStatus.FAILED, 2, "complete")),
        ):
            with self.subTest(event_type=event_type):
                with closing(sqlite3.connect(self.database)) as connection, connection:
                    connection.execute(f"""CREATE TRIGGER reject_execution BEFORE INSERT ON events
                        WHEN NEW.event_type='{event_type}' BEGIN SELECT RAISE(ABORT, 'injected failure'); END""")
                with self.assertRaises(StorageError):
                    operation()
                reopened = EventStore(self.database)
                self.assertEqual(reopened.get(TASK_ID), initial)
                self.assertEqual(reopened.replay(TASK_ID), initial)
                with closing(sqlite3.connect(self.database)) as connection, connection:
                    self.assertEqual(connection.execute("SELECT COUNT(*) FROM commands").fetchone()[0], initial.revision)
                    connection.execute("DROP TRIGGER reject_execution")
                initial = operation()
                self.assertEqual(reopened.replay(TASK_ID), initial)

    def test_missing_task_and_invalid_input_do_not_create_a_ledger(self) -> None:
        for operation in (
            lambda: self.store.begin_execution(TASK_ID, OTHER_ID, 1, "begin"),
            lambda: self.store.complete_execution(TASK_ID, TaskStatus.FAILED, 1, "complete"),
        ):
            with self.assertRaises(NotFoundError):
                operation()
            self.assertFalse(self.database.parent.exists())
        for value in ("SUCCEEDED", [], {}, True):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                self.store.complete_execution(TASK_ID, value, 1, "invalid")
        self.assertFalse(self.database.parent.exists())

    def test_recovery_uses_full_task_identity_and_accepts_maximum_length_command(self) -> None:
        other = replace(self.spec, task_id=TASK_ID[:8] + "b" * 24)
        self.store.create(self.spec, "create")
        self.store.create(other, "create-other")
        self.store.begin_execution(TASK_ID, OTHER_ID, 1, "begin")
        self.store.begin_execution(other.task_id, "c" * 32, 1, "begin-other")
        reopened = EventStore(self.database)
        with patch("subprocess.Popen", side_effect=AssertionError("recovery cannot launch providers")):
            recovered = reopened.recover_interrupted_tasks("r" * 128, "process crashed")
        self.assertEqual({snapshot.spec.task_id for snapshot in recovered}, {TASK_ID, other.task_id})
        for snapshot in recovered:
            self.assertEqual(snapshot.execution_status, TaskStatus.UNCERTAIN)
            self.assertEqual(reopened.replay(snapshot.spec.task_id), snapshot)
        self.assertEqual(reopened.recover_interrupted_tasks("r" * 128, "process crashed"), ())
        before = reopened.get(TASK_ID)
        # UNCERTAIN tasks accept late results
        completed = reopened.complete_execution(TASK_ID, TaskStatus.SUCCEEDED, before.revision, "late-success")
        self.assertEqual(completed.execution_status, TaskStatus.SUCCEEDED)
        self.assertEqual(completed.recovery_reason, None)
        self.assertEqual(reopened.get(TASK_ID), completed)

    def test_cancelled_execution_cannot_accept_late_success(self) -> None:
        self.store.create(self.spec, "create")
        self.store.begin_execution(TASK_ID, OTHER_ID, 1, "begin")
        cancelled = self.store.transition(TASK_ID, TaskStatus.CANCELLED, 2, "cancel")
        with self.assertRaises(ExecutionGuardError):
            self.store.complete_execution(TASK_ID, TaskStatus.SUCCEEDED, 3, "late-success")
        self.assertEqual(self.store.get(TASK_ID), cancelled)
        recovered = self.store.recover_interrupted_tasks("recover", "cancelled execution interrupted")
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0].status, TaskStatus.CANCELLED)
        self.assertEqual(recovered[0].execution_status, TaskStatus.UNCERTAIN)
        self.assertEqual(self.store.replay(TASK_ID), recovered[0])

    def test_replay_rejects_duplicate_completion_and_start_from_blocked(self) -> None:
        self.store.create(self.spec, "create")
        self.store.begin_execution(TASK_ID, OTHER_ID, 1, "begin")
        self.store.complete_execution(TASK_ID, TaskStatus.FAILED, 2, "complete", "failure")
        events = self.store.events(TASK_ID)
        duplicate = replace(events[-1], event_id="d" * 32, command_id="duplicate", revision=4)
        with self.assertRaises(StorageError):
            replay_events(events + (duplicate,))
        blocked = replace(events[1], event_type="TASK_TRANSITIONED", payload_json=canonical_json({
            "schema_version": 1, "from_status": "CREATED", "to_status": "BLOCKED",
            "reason": "waiting", "resume_status": "CREATED"}))
        started = replace(events[1], revision=3)
        with self.assertRaises(StorageError):
            replay_events((events[0], blocked, started))

    def test_recovery_does_not_hide_conflicts_while_execution_is_still_running(self) -> None:
        self.store.create(self.spec, "create")
        running = self.store.begin_execution(TASK_ID, OTHER_ID, 1, "begin")
        for error in (ConflictError, CommandConflictError):
            with self.subTest(error=error), patch.object(self.store, "_mark_uncertain", side_effect=error("conflict")):
                with self.assertRaises(error):
                    self.store.recover_interrupted_tasks("recover", "restart")
        self.assertEqual(self.store.get(TASK_ID), running)

    def test_replay_validates_execution_schema_and_completion_detail(self) -> None:
        self.store.create(self.spec, "create")
        self.store.begin_execution(TASK_ID, OTHER_ID, 1, "begin")
        self.store.complete_execution(TASK_ID, TaskStatus.FAILED, 2, "complete")
        events = self.store.events(TASK_ID)
        for index, payload in (
            (1, {"schema_version": True, "attempt_id": OTHER_ID}),
            (2, {"schema_version": 2, "result_status": "FAILED", "detail": None}),
            (2, {"schema_version": 1, "result_status": "FAILED", "detail": {}}),
        ):
            with self.subTest(index=index, payload=payload), self.assertRaises(StorageError):
                altered = list(events)
                altered[index] = replace(events[index], payload_json=canonical_json(payload))
                replay_events(tuple(altered))
