"""Project ownership via OS-managed exclusive lock.

Ensures only one orchestrator process can actively manage a project's
execution-state store at a time. Prevents startup recovery in one process
from incorrectly marking another live process's RUNNING execution as UNCERTAIN.

Uses fcntl.flock on Unix (Linux, macOS, BSD) and Windows ExclusiveFileLock
(NTFS). On unknown platforms, falls back to a no-op advisory lock that
prints a warning — the project prefers single-process operation.
"""

from __future__ import annotations

import os
import platform
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .errors import ConflictError, ValidationError
from .validation import bounded_int

if sys.platform == "win32":
    import msvcrt  # type: ignore[import-untyped]


class _LockFile:
    """Thin wrapper around an OS file descriptor for flock/exclusive locking."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._descriptor: int | None = None
        if sys.platform == "win32":
            self._ms_handle = None  # type: ignore[attr-defined]
        else:
            self._fd: int | None = None

    def acquire_exclusive(self) -> None:
        if self._descriptor is not None or self._fd is not None:
            raise ValidationError("lock already held")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if sys.platform == "win32":
            try:
                self._ms_handle = open(self._path, "r+b")
            except FileNotFoundError:
                self._ms_handle = open(self._path, "wb+")
            try:
                msvcrt.locking(self._ms_handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                self._ms_handle.close()
                self._ms_handle = None
                raise ConflictError(
                    f"project {self._path.parent} already has an active orchestrator"
                ) from exc
            self._descriptor = self._ms_handle.fileno()
        else:
            flags = os.O_CREAT | os.O_RDWR
            descriptor = os.open(self._path, flags, 0o600)
            try:
                st = os.fstat(descriptor)
                if not (st.st_mode & 0o100000):  # S_ISREG
                    os.close(descriptor)
                    raise ConflictError(
                        f"lock path {self._path} is not a regular file"
                    )
                import fcntl
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except (BlockingIOError, OSError) as exc:
                    os.close(descriptor)
                    raise ConflictError(
                        f"project {self._path.parent} already has an active orchestrator"
                    ) from exc
            except ConflictError:
                raise
            except Exception as exc:
                os.close(descriptor)
                raise ConflictError(
                    f"cannot acquire exclusive lock for project {self._path.parent}: {exc}"
                )
            self._fd = descriptor
            self._descriptor = descriptor

    def release(self) -> None:
        if self._descriptor is None and self._fd is None:
            return
        if sys.platform == "win32" and self._ms_handle is not None:
            try:
                import msvcrt
                msvcrt.locking(self._ms_handle.fileno(), msvcrt.LK_UNLCK, 1)
                self._ms_handle.close()
            except Exception:
                pass
            self._ms_handle = None
        if self._fd is not None:
            try:
                import fcntl
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                os.close(self._fd)
            except Exception:
                pass
            self._fd = None
        self._descriptor = None

    def __enter__(self) -> "_LockFile":
        return self

    def __exit__(self, *args: object) -> None:
        self.release()


def _lock_path(project_root: Path, state_dir: Path | None = None) -> Path:
    """Derive the canonical lock file path from the project root.

    Uses the state directory if provided, otherwise .diamond/lock inside
    the project root. The lock identity is derived from the resolved
    project/store location, not the current working directory.
    """
    storage_base = state_dir.resolve() if state_dir else project_root.resolve() / ".diamond"
    storage_base.mkdir(parents=True, exist_ok=True)
    return storage_base / "orchestrator.lock"


@contextmanager
def project_owner(project_root: Path, state_dir: Path | None = None) -> Iterator[None]:
    """Acquire exclusive ownership of a project for the duration of an orchestrator.

    Only one process can hold this lock at a time. OS process termination
    (normal exit, SIGKILL, etc.) releases the lock automatically.

    Raises:
        ConflictError: if another process already owns this project.
    """
    if not isinstance(project_root, Path):
        raise ValidationError("project_root must be a pathlib.Path")
    if state_dir is not None and not isinstance(state_dir, Path):
        raise ValidationError("state_dir must be a pathlib.Path or None")

    locked = False
    lock = _LockFile(_lock_path(project_root, state_dir))
    try:
        lock.acquire_exclusive()
        locked = True
        yield
    finally:
        if locked:
            lock.release()


def is_owned(project_root: Path, state_dir: Path | None = None) -> bool:
    """Check whether another process currently owns this project.

    Uses a non-blocking acquisition attempt. Returns True if the lock
    is held by another process, False otherwise. Does NOT acquire the
    lock.
    """
    if not isinstance(project_root, Path):
        raise ValidationError("project_root must be a pathlib.Path")
    lock = _LockFile(_lock_path(project_root, state_dir))
    try:
        lock.acquire_exclusive()
        lock.release()
        return False
    except ConflictError:
        return True


# Commands that own execution state and may trigger startup recovery.
# Read-only/administrative commands never recover RUNNING executions.
_EXECUTION_COMMANDS: frozenset[str] = frozenset({
    "autonomy", "delivery", "orchestrate", "self-improve", "smoke", "workflow",
})

# Commands that must refuse to modify execution state while locked.
# The recover command itself must be blocked when an owner exists.
_LOCKED_WRITE_COMMANDS: frozenset[str] = frozenset({
    "recover",
})


def _startup_recovery(args: Any) -> None:
    """Recover interrupted executions before processing CLI commands.

    Idempotent: calling multiple times is safe.
    Only recovers tasks from this project's store (paths.database).
    Does not redispatch uncertain tasks — they remain visible for manual resolution.
    Acquires exclusive project ownership before running recovery.
    """
    from .controller import recover_on_startup
    from .paths import resolve_paths
    from .store import EventStore
    paths = resolve_paths(args.project, args.config, getattr(args, "state_dir", None))
    store = EventStore(paths.database)
    try:
        with project_owner(paths.project, paths.state):
            recovered = recover_on_startup(store, "CLI startup recovery")
            if recovered:
                print(f"Recovered {len(recovered)} interrupted execution(s) to UNCERTAIN state", file=sys.stderr)
    except StorageError:
        # Let the requested CLI operation report the storage failure through
        # its normal JSON/error-code path; recovery must not add a warning.
        return
    except Exception as exc:
        # Recovery failure should not block CLI operations
        print(f"WARNING: startup recovery skipped: {exc}", file=sys.stderr)


def _require_ownable_command(args: Any) -> None:
    """Refuse to start an execution owner while another owns this project.

    Raises ConflictError if the project is already owned.
    """
    from .errors import ConflictError
    from .paths import resolve_paths
    paths = resolve_paths(args.project, args.config, getattr(args, "state_dir", None))
    if is_owned(paths.project, paths.state):
        raise ConflictError(
            f"project {paths.project} already has an active orchestrator; "
            "another process is managing execution for this project"
        )
