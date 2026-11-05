from dataclasses import replace

from .domain import LedgerEvent, TaskSnapshot, TaskSpec, TaskStatus, validate_transition
from .errors import StorageError, ValidationError
from .validation import exact_keys, parse_canonical_json


def next_snapshot(current: TaskSnapshot, target: TaskStatus, reason: str | None, timestamp: str) -> TaskSnapshot:
    validate_transition(current, target, reason)
    return replace(current, status=target, revision=current.revision + 1, updated_at=timestamp,
                   blocking_reason=reason if target is TaskStatus.BLOCKED else None,
                   resume_status=TaskStatus.CREATED if target is TaskStatus.BLOCKED else None)


def replay_events(events: tuple[LedgerEvent, ...]) -> TaskSnapshot:
    if not events:
        raise StorageError("task has no creation event; ledger is inconsistent")
    current: TaskSnapshot | None = None
    try:
        for index, event in enumerate(events, 1):
            if event.revision != index or event.task_id != events[0].task_id:
                raise StorageError("event stream has a task/revision gap")
            payload = parse_canonical_json(event.payload_json)
            if event.event_type == "TASK_CREATED" and index == 1:
                data = exact_keys(payload, {"schema_version", "spec"}, "creation payload")
                if type(data["schema_version"]) is not int or data["schema_version"] != 1:
                    raise StorageError("unsupported creation payload schema")
                spec = TaskSpec.from_dict(data["spec"])
                if spec.task_id != event.task_id:
                    raise StorageError("creation event task ID does not match its spec")
                current = TaskSnapshot(spec, TaskStatus.CREATED, 1, event.timestamp, event.timestamp)
            elif event.event_type == "TASK_TRANSITIONED" and current is not None:
                data = exact_keys(payload, {"schema_version", "from_status", "to_status", "reason", "resume_status"}, "transition payload")
                if type(data["schema_version"]) is not int or data["schema_version"] != 1:
                    raise StorageError("unsupported transition payload schema")
                if data["from_status"] != current.status.value:
                    raise StorageError("transition source disagrees with event history")
                target = TaskStatus(data["to_status"])
                current = next_snapshot(current, target, data["reason"], event.timestamp)
                if data["resume_status"] != (current.resume_status.value if current.resume_status else None):
                    raise StorageError("transition resume state disagrees with event history")
            elif event.event_type == "TASK_EXECUTION_STARTED" and current is not None:
                data = exact_keys(payload, {"schema_version", "attempt_id"}, "execution started payload")
                if type(data["schema_version"]) is not int or data["schema_version"] != 1:
                    raise StorageError("unsupported execution started payload schema")
                if type(data["attempt_id"]) is not str:
                    raise StorageError("execution started payload attempt_id must be string")
                if current.execution_status is not None:
                    raise StorageError("execution already started; duplicate start event")
                if current.status is not TaskStatus.CREATED:
                    raise StorageError("cannot start execution from current status")
                current = replace(current,
                                  execution_status=TaskStatus.RUNNING,
                                  execution_attempt_id=data["attempt_id"],
                                  revision=index,
                                  updated_at=event.timestamp)
            elif event.event_type == "TASK_EXECUTION_COMPLETED" and current is not None:
                data = exact_keys(payload, {"schema_version", "result_status", "detail"}, "execution completed payload")
                if type(data["schema_version"]) is not int or data["schema_version"] != 1:
                    raise StorageError("unsupported execution completed payload schema")
                if current.execution_status is None:
                    raise StorageError("completion event without prior start event")
                if current.execution_status not in {TaskStatus.RUNNING, TaskStatus.UNCERTAIN}:
                    raise StorageError("cannot complete execution; not in RUNNING or UNCERTAIN state")
                result = TaskStatus(data["result_status"])
                if result not in {TaskStatus.SUCCEEDED, TaskStatus.FAILED}:
                    raise StorageError(f"execution result must be SUCCEEDED or FAILED, got {result.value}")
                if data["detail"] is not None and type(data["detail"]) is not str:
                    raise StorageError("execution completed payload detail must be string or null")
                current = replace(current,
                                  execution_status=result,
                                  recovery_reason=None,
                                  revision=index,
                                  updated_at=event.timestamp)
                # Foundation status (task.status) remains unchanged; only execution_status updates.
            elif event.event_type == "TASK_EXECUTION_RECOVERED" and current is not None:
                data = exact_keys(payload, {"schema_version", "reason"}, "execution recovered payload")
                if type(data["schema_version"]) is not int or data["schema_version"] != 1:
                    raise StorageError("unsupported execution recovered payload schema")
                if data["reason"] is not None and type(data["reason"]) is not str:
                    raise StorageError("execution recovered payload reason must be string or null")
                if current.execution_status not in {TaskStatus.RUNNING,}:
                    raise StorageError("cannot recover execution; not in RUNNING state")
                current = replace(current,
                                  execution_status=TaskStatus.UNCERTAIN,
                                  recovery_reason=data["reason"],
                                  revision=index,
                                  updated_at=event.timestamp)
            else:
                raise StorageError("event stream must begin with exactly one creation event")
        assert current is not None
        return current
    except (ValidationError, ValueError, TypeError, KeyError) as exc:
        raise StorageError(f"invalid event stream: {exc}") from exc
