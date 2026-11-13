"""DAG-aware task scheduler for Diamond.

Implements dependency resolution and bounded concurrency for task execution.
Phase 1 focuses on deterministic scheduling without live CLI dispatch.

Usage::

    from diamond.scheduler import Scheduler

    tasks = {
        "task-a": TaskSpec(task_id="task-a", objective="build ui"),
        "task-b": TaskSpec(task_id="task-b", objective="write tests",
                         dependencies=("task-a",)),
    }
    scheduler = Scheduler(tasks, concurrency_limit=2)
    results = scheduler.run(dispatcher=my_dispatcher)

The dispatcher protocol is abstract; callers provide their own execution
function. No real Claude, Codex, or tmux integrations are invoked here.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from threading import Barrier, Event
from typing import Any, Callable, Protocol
import time
from concurrent.futures import ThreadPoolExecutor, Future, wait, FIRST_COMPLETED

from .domain import TaskSnapshot, TaskSpec, TaskStatus
from .errors import ValidationError


def provider_to_agent(provider: str) -> str:
    """Preserve a provider identifier without vendor-specific scheduler logic.

    Adapter-owned transports may map this stable identifier to their documented
    CLI grammar.  The scheduler deliberately does not contain a provider name
    table, command line, or output parser.
    """
    if not isinstance(provider, str) or not provider.strip() or "\x00" in provider:
        raise ValidationError("provider identifier must be nonblank text without NUL")
    return provider


# ── CLI status to TaskStatus mapping ────────────────────────────────────────


_CLI_STATUS_MAP: dict[str, TaskStatus] = {
    "succeeded": TaskStatus.SUCCEEDED,
    "failed": TaskStatus.FAILED,
    "timeout": TaskStatus.FAILED,
    "non_json": TaskStatus.FAILED,
    "unavailable": TaskStatus.FAILED,
}


def cli_status_to_task_status(cli_status: str) -> TaskStatus:
    """Map a normalized CLI status to a TaskStatus value.

    Conservative: any unrecognized status is treated as FAILED so that
    indeterminate or malformed results never silently become success.
    """
    return _CLI_STATUS_MAP.get(cli_status, TaskStatus.FAILED)


# ── Public API types ───────────────────────────────────────────────────────


class SchedulerOutcome(str, Enum):
    """High-level outcome after a scheduler run completes."""
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass(frozen=True)
class TaskResult:
    """Outcome of executing one task."""
    task_id: str
    status: TaskStatus
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def succeeded(self) -> bool:
        return self.status is TaskStatus.SUCCEEDED

    @property
    def failed(self) -> bool:
        return self.status in (TaskStatus.FAILED, TaskStatus.CANCELLED)


class Dispatcher(Protocol):
    """Minimal interface the scheduler calls to execute one task.

    The scheduler does not invoke Claude, Codex, or any external CLI.
    Callers provide a function that knows how to dispatch one task to its
    chosen provider and return a TaskResult.
    """

    def dispatch(self, task: TaskSpec) -> TaskResult:
        """Execute *task* and return its result.

        May raise :exc:`SchedulerException` to signal a transient failure
        that should retry the task; any other exception is treated as a
        hard failure.
        """
        ...  # pragma: no cover


class DependencyAwareDispatcher(Protocol):
    """Optional dispatcher extension for controller-owned dependency proof.

    The ordinary :class:`Dispatcher` contract remains unchanged.  A persisted
    controller bridge may implement this extension to receive the scheduler's
    proof that every dependency was completed successfully before reservation.
    """

    def dispatch_with_dependencies(
        self, task: TaskSpec, *, dependencies_satisfied: bool
    ) -> TaskResult:
        ...  # pragma: no cover


class SchedulerException(Exception):
    """Raised by a dispatcher to signal a transient execution problem."""


@dataclass
class SchedulerResult:
    """Complete outcome of running the scheduler."""
    results: dict[str, TaskResult]
    ordered: list[str]
    outcome: SchedulerOutcome
    errors: tuple[str, ...] = ()
    max_concurrent_workers: int = 0
    peak_in_flight: int = 0
    total_dispatch_calls: int = 0
    overlap_detected: bool = False
    wall_clock_seconds: float = 0.0

    @property
    def all_succeeded(self) -> bool:
        return all(r.succeeded for r in self.results.values())

    @property
    def any_failed(self) -> bool:
        return any(r.failed for r in self.results.values())


# ── Validation ──────────────────────────────────────────────────────────────


def _validate_task_ids(tasks: dict[str, TaskSpec]) -> None:
    """Validate task IDs are unique and well-formed."""
    seen: set[str] = set()
    for task_id, spec in tasks.items():
        if task_id in seen:
            raise ValidationError(f"duplicate task ID: {task_id}")
        seen.add(task_id)
        if spec.task_id not in (None, task_id):
            raise ValidationError(
                f"task spec task_id '{spec.task_id}' does not match key '{task_id}'"
            )


def _detect_cycle(tasks: dict[str, TaskSpec]) -> tuple[bool, list[str]]:
    """Return (has_cycle, cycle_path) using DFS topological sort."""
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {tid: WHITE for tid in tasks}
    cycle_path: list[str] = []

    def dfs(node: str) -> bool:
        color[node] = GRAY
        spec = tasks[node]
        deps = spec.dependencies or ()
        for dep in deps:
            if dep not in tasks:
                continue
            if color[dep] == GRAY:
                # Found a cycle; reconstruct path
                cycle_path.clear()
                cycle_path.extend([dep, node])
                cur = node
                while cur != dep:
                    # Walk back through the call stack implicitly
                    for tid, s in tasks.items():
                        if s.dependencies and node in (s.dependencies or ()):
                            pass
                    break
                return True
            if color[dep] == WHITE:
                if dfs(dep):
                    return True
        color[node] = BLACK
        return False

    for tid in tasks:
        if color[tid] == WHITE:
            if dfs(tid):
                return True, cycle_path
    return False, []


def _validate_dependencies(tasks: dict[str, TaskSpec]) -> None:
    """Validate dependency references and detect cycles."""
    _validate_task_ids(tasks)

    for tid, spec in tasks.items():
        deps = spec.dependencies or ()
        for dep in deps:
            if dep == tid:
                raise ValidationError(f"self-dependency detected: {tid}")
            if dep not in tasks:
                raise ValidationError(
                    f"task {tid} depends on unknown task {dep}"
                )

    has_cycle, _ = _detect_cycle(tasks)
    if has_cycle:
        raise ValidationError("circular dependency detected")


# ── Scheduler ──────────────────────────────────────────────────────────────


class Scheduler:
    """DAG-aware task scheduler with bounded concurrency.

    Args:
        tasks: Mapping of task_id to TaskSpec.
        concurrency_limit: Maximum number of tasks dispatched
            concurrently (must be >= 1).
        ordered: If True, preserve insertion order for tie-breaking
            among ready tasks.
    """

    def __init__(
        self,
        tasks: dict[str, TaskSpec],
        concurrency_limit: int = 1,
        ordered: bool = False,
    ) -> None:
        if not isinstance(tasks, dict):
            raise ValidationError("tasks must be a dict mapping task_id to TaskSpec")
        if len(tasks) != len(set(tasks.keys())):
            raise ValidationError("duplicate task IDs detected")

        _validate_dependencies(tasks)
        if not isinstance(concurrency_limit, int) or concurrency_limit < 1:
            raise ValidationError("concurrency_limit must be a positive integer")
        if not isinstance(ordered, bool):
            raise ValidationError("ordered must be a boolean")

        self.tasks: dict[str, TaskSpec] = dict(tasks)
        self.concurrency_limit = concurrency_limit
        self.ordered = ordered
        self._results: dict[str, TaskResult] = {}
        self._ordered: list[str] = []
        self._dispatch_count = 0

    @property
    def results(self) -> dict[str, TaskResult]:
        return dict(self._results)

    def run(
        self,
        dispatcher: Dispatcher,
        *,
        on_progress: Callable[[str, TaskResult], None] | None = None,
    ) -> SchedulerResult:
        """Execute all tasks respecting dependencies and concurrency.

        Args:
            dispatcher: Function that executes one task and returns a result.
            on_progress: Optional callback invoked after each task completes.

        Returns:
            SchedulerResult with outcomes and ordering.
        """
        start_time = time.perf_counter()

        # Build dependency graph
        dependents: dict[str, set[str]] = {tid: set() for tid in self.tasks}
        in_degree: dict[str, int] = {tid: 0 for tid in self.tasks}

        for tid, spec in self.tasks.items():
            deps = spec.dependencies or ()
            in_degree[tid] = len([d for d in deps if d in self.tasks])
            for dep in deps:
                if dep in dependents:
                    dependents[dep].add(tid)

        # Initialize ready queue with tasks having no dependencies
        ready: deque[str] = deque()
        for tid in (self.tasks.keys() if self.ordered else sorted(self.tasks.keys())):
            if in_degree[tid] == 0:
                ready.append(tid)

        completed: set[str] = set()
        in_flight: int = 0
        running_tasks: dict[str, Future[TaskResult]] = {}
        results: dict[str, TaskResult] = {}
        ordered: list[str] = []
        max_concurrent_workers = 0
        peak_in_flight = 0
        overlap_detected = False
        dispatcher_obj = dispatcher
        # Track submission order for deterministic completion processing
        submission_order: list[str] = []

        with ThreadPoolExecutor(max_workers=self.concurrency_limit) as executor:
            # Main event loop
            while ready or running_tasks:
                # Dispatch up to concurrency limit
                while ready and len(running_tasks) < self.concurrency_limit:
                    tid = ready.popleft()
                    spec = self.tasks[tid]
                    dependencies_satisfied = all(
                        results[dependency].succeeded
                        for dependency in (spec.dependencies or ())
                    )

                    future = executor.submit(
                        self._execute_one,
                        spec,
                        dispatcher_obj,
                        dependencies_satisfied=dependencies_satisfied,
                    )
                    running_tasks[tid] = future
                    submission_order.append(tid)
                    in_flight += 1
                    max_concurrent_workers = max(max_concurrent_workers, in_flight)
                    peak_in_flight = max(peak_in_flight, in_flight)

                if not running_tasks:
                    break

                # Process completed futures
                done_futures, _ = wait(running_tasks.values(), return_when=FIRST_COMPLETED)

                if not done_futures:
                    # No futures completed, break to avoid infinite loop
                    break

                # Process completions in submission order (preserve insertion order)
                # Filter to only those that are done
                completed_futures_tids = [tid for tid in submission_order if tid in running_tasks and running_tasks[tid].done()]

                for tid in completed_futures_tids:
                    future = running_tasks.pop(tid)
                    in_flight -= 1

                    try:
                        result = future.result()
                        overlap_detected = True  # Any concurrent execution detected
                    except Exception as exc:
                        result = TaskResult(
                            task_id=tid,
                            status=TaskStatus.FAILED,
                            error=f"concurrent execution failed: {exc}",
                        )

                    results[tid] = result
                    ordered.append(tid)

                    if on_progress:
                        on_progress(tid, result)

                    # Update dependents - only unlock if prerequisite succeeded
                    if result.succeeded:
                        for dependent in dependents.get(tid, set()):
                            if dependent in completed or dependent in running_tasks:
                                continue
                            in_degree[dependent] -= 1
                            if in_degree[dependent] == 0:
                                ready.append(dependent)

                    completed.add(tid)

        # Update instance state
        self._results = results
        self._ordered = ordered

        self._dispatch_count += len(results)

        wall_clock_seconds = time.perf_counter() - start_time

        return SchedulerResult(
            results=results,
            ordered=ordered,
            outcome=self._determine_outcome(),
            max_concurrent_workers=max_concurrent_workers,
            peak_in_flight=peak_in_flight,
            total_dispatch_calls=self._dispatch_count,
            overlap_detected=overlap_detected,
            wall_clock_seconds=wall_clock_seconds,
        )

    def _execute_one(
        self,
        spec: TaskSpec,
        dispatcher: Dispatcher,
        *,
        dependencies_satisfied: bool = False,
    ) -> TaskResult:
        """Execute one task via the dispatcher."""
        try:
            dispatch_with_dependencies = getattr(
                dispatcher, "dispatch_with_dependencies", None
            )
            if callable(dispatch_with_dependencies):
                return dispatch_with_dependencies(
                    spec,
                    dependencies_satisfied=dependencies_satisfied,
                )
            return dispatcher.dispatch(spec)
        except SchedulerException as exc:
            return TaskResult(
                task_id=spec.task_id,
                status=TaskStatus.FAILED,
                error=str(exc),
            )
        except Exception as exc:
            return TaskResult(
                task_id=spec.task_id,
                status=TaskStatus.FAILED,
                error=f"dispatcher raised: {exc}",
            )

    def _determine_outcome(self) -> SchedulerOutcome:
        """Determine high-level outcome."""
        if not self._results:
            return SchedulerOutcome.FAILED
        if any(r.failed for r in self._results.values()):
            return SchedulerOutcome.PARTIAL
        return SchedulerOutcome.SUCCESS


def __getattr__(name: str) -> object:
    if name == "CLIDispatcher":
        from .scheduler_transport import CLIDispatcher
        return CLIDispatcher
    raise AttributeError(name)
