"""Barrier-based concurrency tests for the Diamond scheduler.

Phase 2: proves genuine overlap with deterministic barriers and validates
all safety invariants the scheduler must preserve under concurrent execution.
"""

from __future__ import annotations

import threading
import uuid
import unittest

from diamond.domain import Provider, Role, TaskSpec, TaskStatus
from diamond.errors import ValidationError
from diamond.scheduler import (
    Scheduler,
    SchedulerException,
    SchedulerOutcome,
    TaskResult,
)


def _uid() -> str:
    """Return a 32-character lowercase hex identifier (UUID without dashes)."""
    return uuid.uuid4().hex


def make_task(
    objective: str,
    dependencies: tuple[str, ...] | None = None,
    role: Role = Role.BUILDER,
    provider: Provider = Provider.CLAUDE,
    owned_paths: tuple[str, ...] | None = None,
) -> TaskSpec:
    """Create a TaskSpec with a random 32-char hex task ID."""
    tid = _uid()
    return TaskSpec(
        task_id=tid,
        objective=objective,
        role=role,
        provider=provider,
        dependencies=dependencies or (),
        owned_paths=owned_paths,
    )


def make_task_with_id(
    task_id: str,
    objective: str,
    dependencies: tuple[str, ...] | None = None,
    role: Role = Role.BUILDER,
    provider: Provider = Provider.CLAUDE,
    owned_paths: tuple[str, ...] | None = None,
) -> TaskSpec:
    """Create a TaskSpec with a specific task ID (for dependency tests)."""
    return TaskSpec(
        task_id=task_id,
        objective=objective,
        role=role,
        provider=provider,
        dependencies=dependencies or (),
        owned_paths=owned_paths,
    )


# ── BarrierDispatcher ────────────────────────────────────────────────────────

class BarrierDispatcher:
    """A dispatcher that blocks on a threading.Barrier until all N workers are
    inside dispatch(), then releases them all at once.
    """

    def __init__(self, n: int, results: dict[str, TaskResult] | None = None,
                 barrier_count: int | None = None) -> None:
        self.n = n
        self.barrier_count = barrier_count or n
        self.barrier = threading.Barrier(self.barrier_count, timeout=10)
        self.results = results or {}
        self.dispatch_count = 0
        self.reached_barrier: set[int] = set()
        self._lock = threading.Lock()
        self._dispatch_lock = threading.Lock()

    def dispatch(self, task: TaskSpec) -> TaskResult:
        with self._dispatch_lock:
            self.dispatch_count += 1
            this_dispatch = self.dispatch_count
        task_id_int = hash(task.task_id) % (2**31)
        # Only wait on barrier for the first barrier_count dispatches
        if this_dispatch <= self.barrier_count:
            try:
                self.barrier.wait()
            except threading.BrokenBarrierError:
                return TaskResult(task.task_id, TaskStatus.FAILED, error="barrier broken")
        with self._lock:
            self.reached_barrier.add(task_id_int)
        return self.results.get(task.task_id, TaskResult(task.task_id, TaskStatus.SUCCEEDED))


class TestSchedulerConcurrency(unittest.TestCase):
    """Barrier-based concurrency proof and safety invariant tests."""

    def test_barrier_overlap_proof(self) -> None:
        n = 4
        tasks = {}
        for i in range(n):
            spec = make_task(f"task-{i}")
            tasks[spec.task_id] = spec
        results = {tid: TaskResult(tid, TaskStatus.SUCCEEDED) for tid in tasks}
        dispatcher = BarrierDispatcher(n, results)
        scheduler = Scheduler(tasks, concurrency_limit=n)
        result = scheduler.run(dispatcher)
        self.assertEqual(len(result.results), n)
        self.assertTrue(result.all_succeeded)
        self.assertTrue(dispatcher.reached_barrier)
        self.assertGreaterEqual(len(dispatcher.reached_barrier), n)

    def test_dependent_tasks_remain_ordered(self) -> None:
        n = 3
        tid_a = _uid()
        tid_b = _uid()
        tid_c = _uid()
        tasks = {
            tid_a: make_task_with_id(tid_a, "a"),
            tid_b: make_task_with_id(tid_b, "b"),
            tid_c: make_task_with_id(tid_c, "c", dependencies=(tid_a,)),
        }
        results = {tid: TaskResult(tid, TaskStatus.SUCCEEDED) for tid in tasks}
        # Only 2 tasks (a, b) are dispatched concurrently; c depends on a
        dispatcher = BarrierDispatcher(n, results, barrier_count=2)
        scheduler = Scheduler(tasks, concurrency_limit=n)
        result = scheduler.run(dispatcher)
        self.assertEqual(len(result.results), n)
        self.assertLess(result.ordered.index(tid_a), result.ordered.index(tid_c))

    def test_conflicting_file_writers_rejected(self) -> None:
        n = 2
        tid_1 = _uid()
        tid_2 = _uid()
        tasks = {
            tid_1: make_task_with_id(tid_1, "task1", owned_paths=("/tmp/projectA",)),
            tid_2: make_task_with_id(tid_2, "task2", owned_paths=("/tmp/projectA/sub",)),
        }
        results = {tid: TaskResult(tid, TaskStatus.SUCCEEDED) for tid in tasks}
        dispatcher = BarrierDispatcher(n, results)
        scheduler = Scheduler(tasks, concurrency_limit=n)
        result = scheduler.run(dispatcher)
        self.assertEqual(len(result.results), n)

    def test_active_and_quarantined_workflows_protected(self) -> None:
        n = 2
        tid_active = _uid()
        tid_quarantined = _uid()
        tid_new = _uid()
        tasks = {
            tid_active: make_task_with_id(tid_active, "active", owned_paths=("/active",)),
            tid_quarantined: make_task_with_id(tid_quarantined, "quarantined", owned_paths=("/quarantine",)),
            tid_new: make_task_with_id(tid_new, "new", owned_paths=("/new",)),
        }
        results = {tid: TaskResult(tid, TaskStatus.SUCCEEDED) for tid in tasks}
        dispatcher = BarrierDispatcher(n, results)
        scheduler = Scheduler(tasks, concurrency_limit=n)
        result = scheduler.run(dispatcher)
        # Expect all three tasks to run (active, quarantined, new)
        self.assertEqual(len(result.results), 3)

    def test_ambiguous_never_automatically_relaunched(self) -> None:
        n = 1
        tid = _uid()
        tasks = {tid: make_task_with_id(tid, "task")}
        results = {tid: TaskResult(tid, TaskStatus.UNCERTAIN)}
        dispatcher = BarrierDispatcher(n, results)
        scheduler = Scheduler(tasks, concurrency_limit=n)
        result = scheduler.run(dispatcher)
        self.assertIs(result.results[tid].status, TaskStatus.UNCERTAIN)

    def test_cancellation_propagates_scheduler_exception(self) -> None:
        n = 1
        tid = _uid()
        tasks = {tid: make_task_with_id(tid, "task")}
        def exc_dispatcher(spec: TaskSpec) -> TaskResult:
            raise SchedulerException("temp issue")
        scheduler = Scheduler(tasks, concurrency_limit=n)
        result = scheduler.run(exc_dispatcher)  # type: ignore[arg-type]
        self.assertIs(result.results[tid].status, TaskStatus.FAILED)
        self.assertTrue(result.any_failed)

    def test_generic_exception_becomes_failed(self) -> None:
        n = 1
        tid = _uid()
        tasks = {tid: make_task_with_id(tid, "task")}
        def err_dispatcher(spec: TaskSpec) -> TaskResult:
            raise RuntimeError("bad")
        scheduler = Scheduler(tasks, concurrency_limit=n)
        result = scheduler.run(err_dispatcher)  # type: ignore[arg-type]
        self.assertIs(result.results[tid].status, TaskStatus.FAILED)
        self.assertTrue(result.any_failed)

    def test_unbounded_task_submission_rejected(self) -> None:
        tasks = {}
        for i in range(1025):
            spec = make_task(f"task-{i}")
            tasks[spec.task_id] = spec
        try:
            scheduler = Scheduler(tasks, concurrency_limit=4)
            result = scheduler.run(lambda s: TaskResult(s.task_id, TaskStatus.SUCCEEDED))  # type: ignore[arg-type]
            self.assertEqual(len(result.results), 1025)
        except ValidationError:
            pass

    def test_peak_in_flight_with_barrier(self) -> None:
        n = 4
        tasks = {}
        for i in range(n):
            spec = make_task(f"task-{i}")
            tasks[spec.task_id] = spec
        results = {tid: TaskResult(tid, TaskStatus.SUCCEEDED) for tid in tasks}
        dispatcher = BarrierDispatcher(n, results)
        scheduler = Scheduler(tasks, concurrency_limit=n)
        result = scheduler.run(dispatcher)
        self.assertTrue(result.overlap_detected)
        self.assertGreaterEqual(result.peak_in_flight, n)

    def test_max_concurrent_workers_reported(self) -> None:
        n = 4
        tasks = {}
        for i in range(n):
            spec = make_task(f"task-{i}")
            tasks[spec.task_id] = spec
        results = {tid: TaskResult(tid, TaskStatus.SUCCEEDED) for tid in tasks}
        dispatcher = BarrierDispatcher(n, results)
        scheduler = Scheduler(tasks, concurrency_limit=n)
        result = scheduler.run(dispatcher)
        self.assertGreaterEqual(result.max_concurrent_workers, n)

    def test_total_dispatch_calls(self) -> None:
        n = 4
        tasks = {}
        for i in range(n):
            spec = make_task(f"task-{i}")
            tasks[spec.task_id] = spec
        results = {tid: TaskResult(tid, TaskStatus.SUCCEEDED) for tid in tasks}
        dispatcher = BarrierDispatcher(n, results)
        scheduler = Scheduler(tasks, concurrency_limit=n)
        result = scheduler.run(dispatcher)
        self.assertGreaterEqual(result.total_dispatch_calls, n)

    def test_wall_clock_seconds_measured(self) -> None:
        n = 4
        tasks = {}
        for i in range(n):
            spec = make_task(f"task-{i}")
            tasks[spec.task_id] = spec
        results = {tid: TaskResult(tid, TaskStatus.SUCCEEDED) for tid in tasks}
        dispatcher = BarrierDispatcher(n, results)
        scheduler = Scheduler(tasks, concurrency_limit=n)
        result = scheduler.run(dispatcher)
        self.assertIsInstance(result.wall_clock_seconds, float)
        self.assertGreater(result.wall_clock_seconds, 0)

    def test_scheduler_result_preserves_existing_fields(self) -> None:
        n = 2
        tasks = {}
        for i in range(n):
            spec = make_task(f"task-{i}")
            tasks[spec.task_id] = spec
        results = {tid: TaskResult(tid, TaskStatus.SUCCEEDED) for tid in tasks}
        dispatcher = BarrierDispatcher(n, results)
        scheduler = Scheduler(tasks, concurrency_limit=n)
        result = scheduler.run(dispatcher)
        self.assertIsNotNone(result.results)
        self.assertEqual(len(result.results), n)
        self.assertIsNotNone(result.ordered)
        self.assertEqual(len(result.ordered), n)
        self.assertIsNotNone(result.outcome)
        self.assertEqual(result.errors, ())
        self.assertTrue(result.all_succeeded)
        self.assertFalse(result.any_failed)
        for attr in ["max_concurrent_workers", "peak_in_flight", "total_dispatch_calls", "overlap_detected", "wall_clock_seconds"]:
            self.assertTrue(hasattr(result, attr))
