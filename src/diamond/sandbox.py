import os
import shutil
import tempfile
from pathlib import Path

from .errors import ValidationError


_OWNERSHIP_MARKER = ".diamond-sandbox-owned"


def executable() -> str | None:
    """Return macOS's host sandbox executable when the capability exists."""
    if os.uname().sysname != "Darwin":
        return None
    return shutil.which("sandbox-exec")


def claude_runtime_directory(base: Path, uid: int | None = None) -> Path:
    if not isinstance(base, Path) or not base.is_dir():
        raise ValidationError("Claude runtime base must be an existing directory")
    value = os.getuid() if uid is None else uid
    if type(value) is not int or value < 0:
        raise ValidationError("Claude runtime uid must be a non-negative integer")
    return base / f"claude-{value}"


def cleanup_runtime(path: Path) -> bool:
    if not isinstance(path, Path) or not path.is_dir():
        return False
    marker = path / _OWNERSHIP_MARKER
    if not marker.is_file():
        return False
    try:
        marker.unlink()
        shutil.rmtree(path)
        return True
    except OSError:
        return False


def _profile_path(path: Path) -> str:
    value = str(path.resolve())
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _profile_literal_path(path: Path) -> str:
    value = str(path)
    return value.replace("\\", "\\\\").replace('"', '\\"')


def read_only_profile(workspace: Path, runtime_dir: Path, provider: str = "omnirush",
                      owned_paths: tuple[str, ...] = (), *, network_access: str = "full",
                      restrict_workspace_reads: bool = False,
                      allow_provider_state_writes: bool = True) -> str:
    if not workspace.is_dir() or not runtime_dir.is_absolute():
        raise ValidationError("sandbox profile paths must be valid directories/absolute paths")
    workspace_path = _profile_path(workspace)
    runtime_path = _profile_path(runtime_dir) if provider == "claude" else _profile_literal_path(runtime_dir)
    state_paths = {
        "omnirush": (".omnirush", ".config/omnirush", ".cache/omnirush"),
        "claude": (".claude", ".cache/claude", ".config/claude"),
        "codex": (".codex",), "copilot": (".copilot",),
        "gemini": (".gemini",), "antigravity": (".gemini/antigravity-cli", ".antigravity", ".config/agy", ".agy"),
    }
    if provider not in state_paths:
        raise ValidationError("unknown sandbox provider")
    if network_access not in {"denied", "loopback", "full"}:
        raise ValidationError("sandbox network access is invalid")
    provider_paths = "\n".join(
        f'(allow file-write* (subpath "{_profile_path(path)}"))'
        for path in (Path.home() / name for name in state_paths[provider])
    ) if allow_provider_state_writes else ""
    grants = []
    root = workspace.resolve(strict=True)
    if runtime_dir.resolve().is_relative_to(root):
        raise ValidationError("sandbox runtime directory must be outside the workspace")
    for relative in owned_paths:
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise ValidationError("sandbox owned paths must be contained relative paths")
        target = (root / path).resolve()
        if not target.is_relative_to(root) or target == root:
            raise ValidationError("sandbox owned path escapes or grants the whole workspace")
        selector = "subpath" if target.is_dir() else "literal"
        grants.append(f'(allow file-write* ({selector} "{_profile_path(target)}"))')
    if provider == "claude" and allow_provider_state_writes:
        for name in (".claude.json", ".claude.json.lock"):
            grants.append(f'(allow file-write* (literal "{_profile_path(Path.home() / name)}"))')
    owned_grants = "\n".join(grants)
    if network_access == "full":
        network = "(allow network-outbound)"
    elif network_access == "loopback":
        # Seatbelt accepts the loopback host name (and rejects a raw
        # 127.0.0.1 address in this rule); the port keeps this narrower than
        # general localhost access while covering the local FreeLLMAPI port.
        network = '(allow network-outbound (remote ip "localhost:31415"))'
    else:
        network = ""
    loopback = '''(allow network-bind (local ip "localhost:*"))
(allow network-inbound (local ip "localhost:*"))''' if provider == "antigravity" else ""
    if restrict_workspace_reads:
        allowed_reads = tuple(
            path for path in (
                workspace.resolve(strict=True), runtime_dir.resolve(strict=True),
                Path.home() / ".local", Path.home() / ".npm",
            ) if path.exists()
        )
        denied_reads = tuple(dict.fromkeys(
            path for path in (
                Path.home(), workspace.resolve(strict=True).parent,
                runtime_dir.resolve(strict=True).parent,
            ) if path != Path("/") and path.exists()
        ))
        read_rules = "(allow file-read*)\n" + "\n".join(
            f'(deny file-read* (subpath "{_profile_path(path)}"))' for path in denied_reads
        ) + "\n" + "\n".join(
            f'(allow file-read* (subpath "{_profile_path(path)}"))'
            for path in allowed_reads
        )
    else:
        read_rules = "(allow file-read*)"
    workspace_runtime_writes = f'(allow file-write* (subpath "{runtime_path}"))'
    if not restrict_workspace_reads:
        workspace_runtime_writes += f'\n(allow file-write* (subpath "{workspace_path}/.claude-flow"))'
    return f'''(version 1)
(deny default)
(allow process-exec)
(allow process-fork)
{read_rules}
{workspace_runtime_writes}
{provider_paths}
{owned_grants}
(allow file-write* (literal "/dev/null"))
(allow sysctl-read)
{network}
{loopback}
(allow mach-lookup)
(allow ipc-posix-shm*)'''


def prepare_read_only(workspace: Path, argv: tuple[str, ...], environment: dict[str, str],
                      provider: str = "omnirush", owned_paths: tuple[str, ...] = (), *,
                      network_access: str = "full", restrict_workspace_reads: bool = False,
                      allow_provider_state_writes: bool = True) -> tuple[tuple[str, ...], Path]:
    sandbox = executable()
    if sandbox is None:
        raise ValidationError("macOS sandbox-exec is unavailable; packet write policy cannot be enforced")
    parent = Path(environment.get("TMPDIR") or tempfile.gettempdir())
    if not parent.is_dir():
        raise ValidationError(f"sandbox temporary parent is unavailable: {parent}")
    cleanup_root = Path(tempfile.mkdtemp(prefix="diamond-sandbox-", dir=parent))
    (cleanup_root / _OWNERSHIP_MARKER).write_text("owned\n", encoding="utf-8")
    runtime_dir = cleanup_root
    if provider == "claude":
        runtime_dir = claude_runtime_directory(cleanup_root)
        runtime_dir.mkdir()
        environment["CLAUDE_CODE_TMPDIR"] = str(cleanup_root)
    try:
        profile = read_only_profile(
            workspace, runtime_dir, provider, owned_paths,
            network_access=network_access,
            restrict_workspace_reads=restrict_workspace_reads,
            allow_provider_state_writes=allow_provider_state_writes,
        )
    except Exception:
        cleanup_runtime(cleanup_root)
        raise
    environment["TMPDIR"] = str(runtime_dir)
    environment["XDG_CACHE_HOME"] = str(runtime_dir)
    environment["XDG_STATE_HOME"] = str(runtime_dir)
    return (sandbox, "-p", profile, *argv), cleanup_root
