"""Optional transport-backed scheduler dispatcher."""

from __future__ import annotations

from typing import Any

from .domain import TaskSpec, TaskStatus
from .scheduler import Dispatcher, TaskResult, cli_status_to_task_status, provider_to_agent


class CLIDispatcher(Dispatcher):
    """Compatibility dispatcher that delegates to the external CLI transport."""

    def __init__(self, correlation_prefix: str = "diamond", timeout: int = 30,
                 metadata: dict[str, Any] | None = None) -> None:
        self.correlation_prefix = correlation_prefix
        self.timeout = timeout
        self.metadata = metadata or {}
        self._dispatch_count = 0
        self._dispatched: set[str] = set()

    def dispatch(self, task: TaskSpec) -> TaskResult:
        from .transport.real_cli_integration import RealCLIResponse, request_task

        self._dispatch_count += 1
        self._dispatched.add(task.task_id)
        try:
            response: RealCLIResponse = request_task(
                agent=provider_to_agent(task.provider.value),
                prompt=task.objective,
                correlation_id=f"{self.correlation_prefix}-{task.task_id[:8]}",
                task_id=task.task_id,
                timeout=self.timeout,
                metadata=self.metadata,
            )
        except RuntimeError:
            return TaskResult(task.task_id, TaskStatus.FAILED, "real CLI integration not enabled")
        except Exception as exc:
            from .scheduler import SchedulerException
            raise SchedulerException(f"dispatch failed: {exc}") from exc

        status = cli_status_to_task_status(response.status)
        error = None if status is not TaskStatus.FAILED else response.raw_stderr or response.raw_stdout or "execution failed"
        return TaskResult(task.task_id, status, error, {
            "agent": response.agent,
            "cli_status": response.status,
            "exit_code": response.exit_code,
            "correlation_id": response.correlation_id,
            "raw_stdout": response.raw_stdout,
            "raw_stderr": response.raw_stderr,
        })

    @property
    def dispatch_count(self) -> int:
        return self._dispatch_count

    @property
    def dispatched_tasks(self) -> set[str]:
        return set(self._dispatched)
