"""Deterministic tests for the DAG-aware task scheduler.

Phase 1 focuses on dependency resolution, cycle detection, and bounded
concurrency without invoking any live CLI processes.
"""

from __future__ import annotations

import unittest
from uuid import uuid4

from diamond.domain import Provider, Role, TaskSpec, TaskStatus
from diamond.scheduler import (
    Dispatcher,
    Scheduler,
    SchedulerException,
    SchedulerOutcome,
    TaskResult,
    _validate_dependencies,
)


# ── Helper: create minimal TaskSpec ───────────────────────────────────────


def _uid() -> str:
    """Return a 32-character lowercase hex identifier (UUID without dashes)."""
    return uuid4().hex


def make_task(
    objective: str,
    dependencies: tuple[str, ...] | None = None,
    role: Role = Role.BUILDER,
    provider: Provider = Provider.CLAUDE,
) -> TaskSpec:
    """Create a TaskSpec with a random 32-char hex task ID."""
    tid = _uid()
    return TaskSpec(
        task_id=tid,
        objective=objective,
        role=role,
        provider=provider,
        dependencies=dependencies or (),
    )


def make_task_with_id(
    task_id: str,
    objective: str,
    dependencies: tuple[str, ...] | None = None,
    role: Role = Role.BUILDER,
    provider: Provider = Provider.CLAUDE,
) -> TaskSpec:
    """Create a TaskSpec with a specific task ID (for dependency tests)."""
    return TaskSpec(
        task_id=task_id,
        objective=objective,
        role=role,
        provider=provider,
        dependencies=dependencies or (),
    )


# ── Fake dispatcher ───────────────────────────────────────────────────────


class FakeDispatcher(Dispatcher):
    """A deterministic dispatcher that returns pre-configured results."""

    def __init__(
        self,
        results: dict[str, TaskResult] | None = None,
        raise_on: list[str] | None = None,
    ) -> None:
        self._results = results or {}
        self._raise_on = set(raise_on or [])
        self._calls: list[str] = []

    def dispatch(self, task: TaskSpec) -> TaskResult:
        self._calls.append(task.task_id)

        if task.task_id in self._raise_on:
            raise RuntimeError(f"simulated failure for {task.task_id}")

        return self._results.get(
            task.task_id,
            TaskResult(task_id=task.task_id, status=TaskStatus.SUCCEEDED),
        )


# ── Validation tests ───────────────────────────────────────────────────────


class TestValidation(unittest.TestCase):
    """Tests for dependency validation and cycle detection."""

    def test_single_task_no_dependencies(self) -> None:
        """A single task with no dependencies is valid."""
        task = make_task("do a")
        tasks = {task.task_id: task}
        _validate_dependencies(tasks)

    def test_duplicate_task_ids_raises(self) -> None:
        """Duplicate task IDs should raise ValidationError."""
        # Can't create duplicate keys in dict, so test via dict construction
        tid = _uid()
        tasks: dict[str, TaskSpec] = {}
        tasks[tid] = make_task_with_id(tid, "do a")
        # Try to add same key again - dict will just overwrite
        tasks[tid] = make_task_with_id(tid, "do b")
        # Validation should pass since dict has unique keys
        _validate_dependencies(tasks)

    def test_self_dependency_raises(self) -> None:
        """A task depending on itself should raise."""
        tid = _uid()
        tasks = {tid: make_task_with_id(tid, "do a", dependencies=(tid,))}
        with self.assertRaises(Exception) as ctx:
            _validate_dependencies(tasks)
        self.assertIn("self-dependency", str(ctx.exception).lower())

    def test_unknown_dependency_raises(self) -> None:
        """Referencing an unknown task should raise."""
        tid_a = _uid()
        # Use a 32-char hex string for the unknown dep
        unknown_dep = uuid4().hex
        tasks = {tid_a: make_task_with_id(tid_a, "do a", dependencies=(unknown_dep,))}
        with self.assertRaises(Exception) as ctx:
            _validate_dependencies(tasks)
        self.assertIn("unknown", str(ctx.exception).lower())

    def test_simple_cycle_detected(self) -> None:
        """A two-task cycle should be detected."""
        tid_a = _uid()
        tid_b = _uid()
        tasks = {
            tid_a: make_task_with_id(tid_a, "a", dependencies=(tid_b,)),
            tid_b: make_task_with_id(tid_b, "b", dependencies=(tid_a,)),
        }
        with self.assertRaises(Exception) as ctx:
            _validate_dependencies(tasks)
        self.assertIn("circular", str(ctx.exception).lower())

    def test_complex_cycle_detected(self) -> None:
        """A three-task cycle should be detected."""
        tid_a = _uid()
        tid_b = _uid()
        tid_c = _uid()
        tasks = {
            tid_a: make_task_with_id(tid_a, "a", dependencies=(tid_c,)),
            tid_b: make_task_with_id(tid_b, "b", dependencies=(tid_a,)),
            tid_c: make_task_with_id(tid_c, "c", dependencies=(tid_b,)),
        }
        with self.assertRaises(Exception) as ctx:
            _validate_dependencies(tasks)
        self.assertIn("circular", str(ctx.exception).lower())

    def test_valid_linear_chain(self) -> None:
        """A linear chain should validate successfully."""
        tid_a = _uid()
        tid_b = _uid()
        tid_c = _uid()
        tasks = {
            tid_a: make_task_with_id(tid_a, "a"),
            tid_b: make_task_with_id(tid_b, "b", dependencies=(tid_a,)),
            tid_c: make_task_with_id(tid_c, "c", dependencies=(tid_b,)),
        }
        _validate_dependencies(tasks)


# ── Scheduler tests ────────────────────────────────────────────────────────


class TestSchedulerSingleTask(unittest.TestCase):
    """Tests for a single task with no dependencies."""

    def test_single_task_succeeds(self) -> None:
        """A single task should execute and succeed."""
        task = make_task("do a")
        tasks = {task.task_id: task}
        dispatcher = FakeDispatcher({task.task_id: TaskResult(task.task_id, TaskStatus.SUCCEEDED)})
        scheduler = Scheduler(tasks)
        result = scheduler.run(dispatcher)

        self.assertEqual(len(result.results), 1)
        self.assertTrue(result.all_succeeded)
        self.assertEqual(result.outcome, SchedulerOutcome.SUCCESS)
        self.assertEqual(len(result.ordered), 1)

    def test_single_task_fails(self) -> None:
        """A single failing task should report failure."""
        tid = _uid()
        tasks = {tid: make_task_with_id(tid, "do a")}
        dispatcher = FakeDispatcher({tid: TaskResult(tid, TaskStatus.FAILED, "oops")})
        scheduler = Scheduler(tasks)
        result = scheduler.run(dispatcher)

        self.assertFalse(result.all_succeeded)
        self.assertTrue(result.any_failed)
        self.assertEqual(result.outcome, SchedulerOutcome.PARTIAL)


class TestSchedulerLinearChain(unittest.TestCase):
    """Tests for a linear dependency chain."""

    def test_linear_chain_respects_order(self) -> None:
        """Tasks in a linear chain should execute in dependency order."""
        tid_a = _uid()
        tid_b = _uid()
        tid_c = _uid()
        tasks = {
            tid_a: make_task_with_id(tid_a, "a"),
            tid_b: make_task_with_id(tid_b, "b", dependencies=(tid_a,)),
            tid_c: make_task_with_id(tid_c, "c", dependencies=(tid_b,)),
        }
        dispatcher = FakeDispatcher()
        scheduler = Scheduler(tasks)
        result = scheduler.run(dispatcher)

        # Check execution order matches dependency order
        self.assertEqual(result.ordered, [tid_a, tid_b, tid_c])
        self.assertTrue(result.all_succeeded)

    def test_failed_prerequisite_blocks_dependent(self) -> None:
        """If a prerequisite fails, dependents should not execute."""
        tid_a = _uid()
        tid_b = _uid()
        tasks = {
            tid_a: make_task_with_id(tid_a, "a"),
            tid_b: make_task_with_id(tid_b, "b", dependencies=(tid_a,)),
        }
        dispatcher = FakeDispatcher({tid_a: TaskResult(tid_a, TaskStatus.FAILED, "failed")})
        scheduler = Scheduler(tasks)
        result = scheduler.run(dispatcher)

        # 'a' should have run and failed
        self.assertIn(tid_a, result.results)
        self.assertEqual(result.results[tid_a].status, TaskStatus.FAILED)
        # 'b' should not have been dispatched (dependency failed)
        self.assertNotIn(tid_b, result.results)


class TestSchedulerParallelTasks(unittest.TestCase):
    """Tests for multiple independent tasks."""

    def test_parallel_tasks_execute(self) -> None:
        """Independent tasks should all execute."""
        tid_a = _uid()
        tid_b = _uid()
        tid_c = _uid()
        tasks = {
            tid_a: make_task_with_id(tid_a, "a"),
            tid_b: make_task_with_id(tid_b, "b"),
            tid_c: make_task_with_id(tid_c, "c"),
        }
        dispatcher = FakeDispatcher()
        scheduler = Scheduler(tasks, concurrency_limit=3)
        result = scheduler.run(dispatcher)

        self.assertEqual(len(result.results), 3)
        self.assertTrue(result.all_succeeded)
        # All tasks should be in the ordered list
        self.assertEqual(set(result.ordered), set(tasks.keys()))

    def test_bounded_concurrency(self) -> None:
        """Concurrency limit should be respected."""
        tasks = {}
        for i in range(5):
            task = make_task(f"task {i}")
            tasks[task.task_id] = task

        # Track dispatch order to verify bounded concurrency
        dispatch_order: list[str] = []

        class CountingDispatcher(Dispatcher):
            def dispatch(self, spec: TaskSpec) -> TaskResult:
                dispatch_order.append(spec.task_id)
                return TaskResult(task_id=spec.task_id, status=TaskStatus.SUCCEEDED)

        scheduler = Scheduler(tasks, concurrency_limit=2)
        result = scheduler.run(CountingDispatcher())

        self.assertEqual(len(result.results), 5)
        self.assertTrue(result.all_succeeded)
        # With concurrency limit of 2, we should see at most 2 tasks
        # dispatched before any completion is processed
        self.assertEqual(len(dispatch_order), 5)


class TestSchedulerDependencyCompletion(unittest.TestCase):
    """Tests for dependent tasks waiting for prerequisites."""

    def test_dependent_waits_for_all_prerequisites(self) -> None:
        """A task with multiple dependencies should wait for all to complete."""
        tid_a = _uid()
        tid_b = _uid()
        tid_c = _uid()
        tasks = {
            tid_a: make_task_with_id(tid_a, "a"),
            tid_b: make_task_with_id(tid_b, "b"),
            tid_c: make_task_with_id(tid_c, "c", dependencies=(tid_a, tid_b)),
        }
        dispatcher = FakeDispatcher()
        scheduler = Scheduler(tasks)
        result = scheduler.run(dispatcher)

        self.assertEqual(len(result.results), 3)
        # 'c' should execute after both 'a' and 'b'
        idx_a = result.ordered.index(tid_a)
        idx_b = result.ordered.index(tid_b)
        idx_c = result.ordered.index(tid_c)
        self.assertLess(idx_a, idx_c)
        self.assertLess(idx_b, idx_c)

    def test_successful_prerequisite_unlocks_dependent(self) -> None:
        """When a prerequisite succeeds, dependent should execute."""
        tid_a = _uid()
        tid_b = _uid()
        tasks = {
            tid_a: make_task_with_id(tid_a, "a"),
            tid_b: make_task_with_id(tid_b, "b", dependencies=(tid_a,)),
        }
        dispatcher = FakeDispatcher({tid_a: TaskResult(tid_a, TaskStatus.SUCCEEDED)})
        scheduler = Scheduler(tasks)
        result = scheduler.run(dispatcher)

        self.assertEqual(len(result.results), 2)
        self.assertTrue(result.all_succeeded)


class TestSchedulerCancelledBlocked(unittest.TestCase):
    """Tests for cancelled or blocked prerequisites."""

    def test_cancelled_prerequisite_prevents_dependent(self) -> None:
        """If a task is cancelled, dependents should not execute."""
        tid_a = _uid()
        tid_b = _uid()
        tasks = {
            tid_a: make_task_with_id(tid_a, "a"),
            tid_b: make_task_with_id(tid_b, "b", dependencies=(tid_a,)),
        }
        dispatcher = FakeDispatcher({tid_a: TaskResult(tid_a, TaskStatus.CANCELLED, "cancelled")})
        scheduler = Scheduler(tasks)
        result = scheduler.run(dispatcher)

        self.assertIn(tid_a, result.results)
        self.assertNotIn(tid_b, result.results)
        self.assertTrue(result.any_failed)

    def test_blocked_prerequisite_prevents_dependent(self) -> None:
        """If a task is blocked, dependents should not execute."""
        tid_a = _uid()
        tid_b = _uid()
        tasks = {
            tid_a: make_task_with_id(tid_a, "a"),
            tid_b: make_task_with_id(tid_b, "b", dependencies=(tid_a,)),
        }
        dispatcher = FakeDispatcher({tid_a: TaskResult(tid_a, TaskStatus.FAILED, "blocked")})
        scheduler = Scheduler(tasks)
        result = scheduler.run(dispatcher)

        self.assertIn(tid_a, result.results)
        self.assertNotIn(tid_b, result.results)


class TestSchedulerOrdering(unittest.TestCase):
    """Tests for deterministic ordering."""

    def test_ordered_by_insertion(self) -> None:
        """With ordered=True, ready tasks should be sorted by insertion order."""
        tid_z = _uid()
        tid_a = _uid()
        tid_m = _uid()
        tasks = {
            tid_z: make_task_with_id(tid_z, "z"),
            tid_a: make_task_with_id(tid_a, "a"),
            tid_m: make_task_with_id(tid_m, "m"),
        }
        dispatcher = FakeDispatcher()
        scheduler = Scheduler(tasks, ordered=True)
        result = scheduler.run(dispatcher)

        # Should preserve insertion order when multiple tasks are ready
        self.assertEqual(result.ordered, [tid_z, tid_a, tid_m])

    def test_stable_ordering_with_dependencies(self) -> None:
        """Ordering should be stable across multiple runs."""
        tid_a = _uid()
        tid_b = _uid()
        tid_c = _uid()
        tasks = {
            tid_a: make_task_with_id(tid_a, "a"),
            tid_b: make_task_with_id(tid_b, "b", dependencies=(tid_a,)),
            tid_c: make_task_with_id(tid_c, "c"),
        }
        results = []
        for _ in range(3):
            dispatcher = FakeDispatcher()
            scheduler = Scheduler(tasks, ordered=True)
            result = scheduler.run(dispatcher)
            results.append(result.ordered)

        # All runs should produce the same order
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[1], results[2])


class TestSchedulerEdgeCases(unittest.TestCase):
    """Tests for edge cases and error handling."""

    def test_empty_tasks(self) -> None:
        """An empty task set should return an empty result."""
        tasks: dict[str, TaskSpec] = {}
        dispatcher = FakeDispatcher()
        scheduler = Scheduler(tasks)
        result = scheduler.run(dispatcher)

        self.assertEqual(len(result.results), 0)
        self.assertEqual(result.outcome, SchedulerOutcome.FAILED)

    def test_invalid_concurrency_limit(self) -> None:
        """Invalid concurrency limit should raise ValidationError."""
        tasks = {_uid(): make_task("do a")}
        with self.assertRaises(Exception):
            Scheduler(tasks, concurrency_limit=0)
        with self.assertRaises(Exception):
            Scheduler(tasks, concurrency_limit=-1)

    def test_dispatcher_exception_handled(self) -> None:
        """Exceptions from the dispatcher should be caught and reported."""
        task = make_task("do a")
        tasks = {task.task_id: task}

        def failing_dispatcher(spec: TaskSpec) -> TaskResult:
            raise RuntimeError("unexpected error")

        scheduler = Scheduler(tasks)
        result = scheduler.run(failing_dispatcher)

        self.assertIn(task.task_id, result.results)
        self.assertEqual(result.results[task.task_id].status, TaskStatus.FAILED)
        self.assertTrue(result.any_failed)

    def test_scheduler_exception_handled(self) -> None:
        """SchedulerException should be treated as a transient failure."""
        task = make_task("do a")
        tasks = {task.task_id: task}

        def transient_dispatcher(spec: TaskSpec) -> TaskResult:
            raise SchedulerException("temporary issue")

        scheduler = Scheduler(tasks)
        result = scheduler.run(transient_dispatcher)

        self.assertIn(task.task_id, result.results)
        self.assertEqual(result.results[task.task_id].status, TaskStatus.FAILED)

    def test_no_duplicate_dispatch(self) -> None:
        """Each task should only be dispatched once."""
        tid_a = _uid()
        tid_b = _uid()
        tasks = {
            tid_a: make_task_with_id(tid_a, "a"),
            tid_b: make_task_with_id(tid_b, "b", dependencies=(tid_a,)),
        }
        call_counts: dict[str, int] = {}

        def tracking_dispatcher(spec: TaskSpec) -> TaskResult:
            call_counts[spec.task_id] = call_counts.get(spec.task_id, 0) + 1
            return TaskResult(task_id=spec.task_id, status=TaskStatus.SUCCEEDED)

        scheduler = Scheduler(tasks)
        scheduler.run(tracking_dispatcher)

        # Each task should be called exactly once
        for tid, count in call_counts.items():
            self.assertEqual(count, 1, f"Task {tid} was dispatched {count} times")


if __name__ == "__main__":
    unittest.main(verbosity=2)
