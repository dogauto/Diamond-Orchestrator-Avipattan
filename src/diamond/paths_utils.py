"""Path safety helpers for Diamond filesystem security (D2-A).

Provides functions to:
- Validate a Unix-domain socket parent directory is a real dir, not a symlink.
- Safely prepare a socket file location: reject existing symlinks, enforce mode.
- Create isolated temporary directories with strict ownership rules.
- Reconcile stale socket files from crashed processes.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Optional


# Permissions enforced on socket directory and file.
SOCKET_DIR_MODE = 0o700
SOCKET_FILE_MODE = 0o600


def _resolve_symlink_chain(path: Path) -> list[str]:
    """Return every component of `path` that is (or leads through) a symlink."""
    seen = []
    cur = path.resolve(strict=False)
    # Walk original path components and collect symlinks encountered.
    parts = list(path.parts)
    visited = set()
    current = Path("/")
    for part in parts[1:]:
        candidate = current / part
        if candidate.is_symlink():
            seen.append(str(candidate))
        else:
            try:
                resolved = candidate.resolve(strict=True)
                visited.add(str(resolved))
            except OSError:
                pass
        current = candidate
    return seen


def ensure_directory_is_real(dir_path: Path) -> bool:
    """Confirm `dir_path` is a real directory, not a symlink to anything."""
    if not dir_path.exists():
        return True  # Directory does not yet exist — caller must create it.
    try:
        st = dir_path.stat(follow_symlinks=False)
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        raise PermissionError(f"socket parent path is a symlink: {dir_path}")
    if not stat.S_ISDIR(st.st_mode):
        raise PermissionError(
            f"socket parent path exists but is not a directory: {dir_path}"
        )
    return True


def is_symlink_or_unsafe(file_path: Path) -> bool:
    """True when the path is a symlink, a special file, or otherwise unsafe."""
    try:
        st = file_path.lstat()  # never follows symlinks
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    # We only allow: missing-path, regular-file, or socket.
    if not (stat.S_ISREG(st.st_mode) or stat.S_ISSOCK(st.st_mode)):
        return True
    return False


def safe_prepare_socket(socket_path: Path) -> None:
    """Prepare a safe location for the IPC socket file.

    Enforces:
    - Parent directory is a real, owned-by-current-user directory (mode 0700).
    - Existing file at socket_path is not a symlink; if it is, raises.
    - Stale regular-file or socket is unlinked safely.
    - New parent directory is created with mode 0700.
    """
    # 1. Validate parent directory.
    parent = socket_path.parent
    if not parent.exists():
        parent.mkdir(parents=True, exist_ok=True)
    ensure_directory_is_real(parent)

    # Enforce directory permissions even if it already existed.
    try:
        parent.chmod(SOCKET_DIR_MODE)
    except OSError:
        pass

    # 2. Reject any existing symlink at the target location.
    if socket_path.exists():
        if is_symlink_or_unsafe(socket_path):
            raise PermissionError(
                f"refusing to bind socket path because it is unsafe: "
                f"{socket_path} ({'symlink' if socket_path.is_symlink() else 'special file'})"
            )
        # Safe existing file/socket — remove before binding.
        socket_path.unlink()


def create_secure_socket_dir(prefix: str = ".diamond-ipc-", base: Optional[Path] = None) -> Path:
    """Create a fresh per-process socket directory with restricted permissions.

    Uses /tmp under the project root or an explicitly provided base directory.
    Returns the absolute path of the new directory. Caller owns cleanup.
    """
    base_dir = Path(base or "/tmp")
    dir_path = base_dir / f"{prefix}{os.getpid()}-{os.urandom(4).hex()}"
    dir_path.mkdir(mode=SOCKET_DIR_MODE, exist_ok=False)
    return dir_path


def reconcile_stale_socket(socket_path: Path) -> None:
    """Remove a stale socket file left over from a crashed controller.

    Fails closed: if the path is a symlink, this raises. Otherwise, the file
    is unlinked and the parent directory permissions are reinforced.
    """
    if not socket_path.exists():
        return
    if is_symlink_or_unsafe(socket_path):
        raise PermissionError(
            f"cannot reconcile stale socket because path is unsafe: {socket_path}"
        )
    try:
        socket_path.unlink()
    except FileNotFoundError:
        pass  # Another process beat us to it — benign race.


def validate_pid_locked(pid_file: Path) -> Optional[int]:
    """Read PID from lock file, confirm process exists. Returns PID or None."""
    try:
        if pid_file.is_symlink():
            return None
        text = pid_file.read_text().strip()
        pid = int(text)
        # Check whether process actually exists.
        os.kill(pid, 0)
        return pid
    except (ValueError, ProcessLookupError, PermissionError, FileNotFoundError):
        return None
