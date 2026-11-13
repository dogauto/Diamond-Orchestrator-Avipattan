"""Task execution projections; these records never grant provider launch authority."""

from __future__ import annotations

from dataclasses import replace

from .domain import TaskSnapshot, TaskStatus
from .errors import CommandConflictError, ConflictError, ExecutionGuardError, NotFoundError, ValidationError
from .validation import bounded_int, canonical_json, command_id, task_id as validate_task_id, text, utc_now
from .evidence import digest_text


class ExecutionStateStoreMixin:
    def begin_execution(self, task_id: str, attempt_id: str, expected_revision: int,
                        command_id_value: str) -> TaskSnapshot:
        validate_task_id(task_id)
        validate_task_id(attempt_id)
        command_id(command_id_value)
        bounded_int(expected_revision, "expected_revision", 1, 2**63 - 1)
        request = canonical_json({"operation": "begin_execution", "task_id": task_id,
                                  "attempt_id": attempt_id, "expected_revision": expected_revision})
        if not self._database_present():
            raise NotFoundError(f"task {task_id} does not exist; no ledger has been created")
        with self._connection(write=True) as connection:
            previous = self._deduplicated(connection, command_id_value, request)
            if previous is not None:
                return previous
            current = self._read_task(connection, task_id)
            if current.revision != expected_revision:
                raise ConflictError(f"expected revision {expected_revision}, found {current.revision}")
            if current.execution_status is not None:
                if current.execution_status is TaskStatus.UNCERTAIN:
                    raise ExecutionGuardError(
                        "task has an uncertain execution record; resolve it first via complete_execution"
                    )
                raise ExecutionGuardError("task already has an execution record")
            if current.status is not TaskStatus.CREATED:
                raise ExecutionGuardError("only CREATED tasks can begin execution")
            snapshot = replace(current, execution_status=TaskStatus.RUNNING,
                               execution_attempt_id=attempt_id, revision=current.revision + 1,
                               updated_at=utc_now())
            cursor = connection.execute("UPDATE tasks SET revision=?,snapshot_json=? WHERE task_id=? AND revision=?",
                                        (snapshot.revision, canonical_json(snapshot.to_dict()), task_id, expected_revision))
            if cursor.rowcount != 1:
                raise ConflictError("task changed concurrently; reload its revision")
            self._record(connection, snapshot, "TASK_EXECUTION_STARTED", command_id_value, request,
                         canonical_json({"schema_version": 1, "attempt_id": attempt_id}))
            return snapshot

    def complete_execution(self, task_id: str, result_status: TaskStatus, expected_revision: int,
                           command_id_value: str, detail: str | None = None) -> TaskSnapshot:
        """Record that execution has completed for a task.

        Accepts transitions from RUNNING or UNCERTAIN to SUCCEEDED or FAILED.
        UNCERTAIN -> SUCCEEDED/FAILED allows late results after interruption.
        RUNNING -> SUCCEEDED/FAILED is the normal completion path.
        Blocked or cancelled tasks cannot accept execution success.
        """
        validate_task_id(task_id)
        command_id(command_id_value)
        bounded_int(expected_revision, "expected_revision", 1, 2**63 - 1)
        if not isinstance(result_status, TaskStatus) or result_status not in {TaskStatus.SUCCEEDED, TaskStatus.FAILED}:
            raise ValidationError("result_status must be SUCCEEDED or FAILED")
        if detail is not None:
            text(detail, "execution detail", 4096)
        request = canonical_json({"operation": "complete_execution", "task_id": task_id,
                                  "result_status": result_status.value, "expected_revision": expected_revision,
                                  "detail": detail})
        if not self._database_present():
            raise NotFoundError(f"task {task_id} does not exist; no ledger has been created")
        with self._connection(write=True) as connection:
            previous = self._deduplicated(connection, command_id_value, request)
            if previous is not None:
                return previous
            current = self._read_task(connection, task_id)
            if current.revision != expected_revision:
                raise ConflictError(f"expected revision {expected_revision}, found {current.revision}")
            if current.execution_status is None:
                raise ExecutionGuardError("task has no execution record; call begin_execution first")
            if current.execution_status not in {TaskStatus.RUNNING, TaskStatus.UNCERTAIN}:
                raise ExecutionGuardError(
                    f"cannot complete execution for task with execution_status={current.execution_status.value}; "
                    "only RUNNING or UNCERTAIN tasks can be completed"
                )
            if result_status is TaskStatus.SUCCEEDED and current.status is not TaskStatus.CREATED:
                raise ExecutionGuardError("blocked or cancelled tasks cannot accept execution success")
            snapshot = replace(current, execution_status=result_status,
                               recovery_reason=None,
                               revision=current.revision + 1, updated_at=utc_now())
            cursor = connection.execute("UPDATE tasks SET revision=?,snapshot_json=? WHERE task_id=? AND revision=?",
                                        (snapshot.revision, canonical_json(snapshot.to_dict()), task_id, expected_revision))
            if cursor.rowcount != 1:
                raise ConflictError("task changed concurrently; reload its revision")
            self._record(connection, snapshot, "TASK_EXECUTION_COMPLETED", command_id_value, request,
                         canonical_json({"schema_version": 1, "result_status": result_status.value, "detail": detail}))
            return snapshot

    def recover_interrupted_tasks(self, command_id_value: str, reason: str | None = None) -> tuple[TaskSnapshot, ...]:
        """Find tasks with RUNNING execution and mark them UNCERTAIN.

        This is an idempotent recovery operation. Calling it multiple times
        will only recover tasks that are still in RUNNING state.

        UNCERTAIN means the external execution's outcome cannot be established.
        The task remains in its foundation status (CREATED/BLOCKED) and can
        later be resolved to SUCCEEDED or FAILED via complete_execution with
        a new command_id (late result).

        Args:
            command_id_value: Command ID for the recovery operation.
            reason: Optional human-readable reason (e.g., "process crashed").

        Returns:
            Tuple of recovered snapshots (execution_status=UNCERTAIN), ordered by task_id.
        """
        command_id(command_id_value)
        if reason is not None:
            text(reason, "recovery reason", 4096)
        recovered: list[TaskSnapshot] = []
        for snapshot in self.list():
            if snapshot.execution_status is TaskStatus.RUNNING:
                try:
                    recovery_id = "execution-recover-" + digest_text(canonical_json({
                        "command_id": command_id_value, "task_id": snapshot.spec.task_id}))
                    recovered.append(self._mark_uncertain(snapshot.spec.task_id, snapshot.revision,
                                                          recovery_id, reason))
                except CommandConflictError:
                    raise
                except (ConflictError, ExecutionGuardError):
                    if self.get(snapshot.spec.task_id).execution_status is TaskStatus.RUNNING:
                        raise
        return tuple(recovered)

    def _mark_uncertain(self, task_id: str, expected_revision: int,
                        command_id_value: str, reason: str | None) -> TaskSnapshot:
        """Mark a RUNNING task as UNCERTAIN with optional recovery reason.

        Records a TASK_EXECUTION_RECOVERED event. Does not change tasks.status.
        The task can later be resolved via complete_execution (late result).
        """
        if not self._database_present():
            raise NotFoundError(f"task {task_id} does not exist; no ledger has been created")
        with self._connection(write=True) as connection:
            current = self._read_task(connection, task_id)
            if current.revision != expected_revision:
                raise ConflictError(f"expected revision {expected_revision}, found {current.revision}")
            if current.execution_status is not TaskStatus.RUNNING:
                raise ExecutionGuardError(
                    f"cannot mark uncertain: task has execution_status={current.execution_status.value}; "
                    "only RUNNING tasks can be marked UNCERTAIN"
                )
            timestamp = utc_now()
            snapshot = replace(
                current,
                execution_status=TaskStatus.UNCERTAIN,
                recovery_reason=reason,
                revision=current.revision + 1,
                updated_at=timestamp,
            )
            cursor = connection.execute(
                "UPDATE tasks SET revision=?,snapshot_json=? WHERE task_id=? AND revision=?",
                (snapshot.revision, canonical_json(snapshot.to_dict()), task_id, expected_revision))
            if cursor.rowcount != 1:
                raise ConflictError("task changed concurrently; reload its revision")
            payload = canonical_json({"schema_version": 1, "reason": reason})
            self._record(connection, snapshot, "TASK_EXECUTION_RECOVERED", command_id_value,
                         canonical_json({"operation": "recover_interrupted_tasks", "task_id": task_id,
                                         "expected_revision": expected_revision}),
                         payload)
            return snapshot
