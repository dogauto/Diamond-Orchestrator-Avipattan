"""Bounded, read-only discovery of configured CLI provider candidates."""

from __future__ import annotations

import os
import selectors
import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, Mapping, Protocol

from .errors import ValidationError
from .provider_contracts import ProviderAdapter, VersionProbeResult, VersionProbeRunner, provider_identifier
from .validation import bounded_int, text


class DiscoveryState(str, Enum):
    DISCOVERED = "discovered"
    UNAVAILABLE = "unavailable"
    INCOMPATIBLE = "incompatible"
    UNTRUSTED = "untrusted"


@dataclass(frozen=True)
class ExecutableCandidate:
    provider_id: str
    executable: str
    adapter_id: str

    def __post_init__(self) -> None:
        provider_identifier(self.provider_id)
        text(self.executable, "configured executable", 4096)
        if "\x00" in self.executable or "\n" in self.executable or "\r" in self.executable:
            raise ValidationError("configured executable contains a forbidden character")
        text(self.adapter_id, "adapter ID", 256)


@dataclass(frozen=True)
class DiscoveryRecord:
    provider_id: str
    adapter_id: str
    configured_executable: str
    resolved_executable: str | None
    state: DiscoveryState
    version: str | None = None
    detail: str = ""
    returncode: int | None = None
    auth_status: str = "NOT_CHECKED"
    execution_authorized: bool = False

    def __post_init__(self) -> None:
        provider_identifier(self.provider_id)
        text(self.adapter_id, "adapter ID", 256)
        text(self.configured_executable, "configured executable", 4096)
        if self.resolved_executable is not None:
            text(self.resolved_executable, "resolved executable", 4096)
        if not isinstance(self.state, DiscoveryState):
            raise ValidationError("discovery state is invalid")
        if self.version is not None:
            text(self.version, "discovered version", 256)
        if self.detail:
            text(self.detail, "discovery detail", 4096)
        if self.returncode is not None and type(self.returncode) is not int:
            raise ValidationError("discovery returncode must be an integer or None")
        if self.auth_status != "NOT_CHECKED":
            raise ValidationError("discovery cannot establish authentication")
        if self.execution_authorized:
            raise ValidationError("discovery cannot grant execution authorization")


class ExecutableResolver(Protocol):
    def resolve(self, executable: str) -> Path | None:
        ...


class SafeExecutableResolver:
    """Resolve only an explicit command name or explicit absolute path."""

    def resolve(self, executable: str) -> Path | None:
        text(executable, "configured executable", 4096)
        candidate = Path(executable)
        if candidate.is_absolute():
            return candidate if candidate.is_file() and os.access(candidate, os.X_OK) else None
        if "/" in executable or "\\" in executable:
            raise ValidationError("relative executable paths are not allowed")
        resolved = shutil.which(executable)
        return Path(resolved) if resolved else None


class SubprocessVersionRunner(VersionProbeRunner):
    """Run a trusted adapter-owned version argv with bounded capture."""

    def run(self, argv: tuple[str, ...] | list[str], *, timeout_seconds: float, output_limit: int) -> VersionProbeResult:
        if type(argv) not in (tuple, list) or not argv or not all(isinstance(item, str) for item in argv):
            raise ValidationError("version probe argv must be a nonempty argument list")
        if any("\x00" in item for item in argv):
            raise ValidationError("version probe argv must not contain NUL")
        if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 30:
            raise ValidationError("version probe timeout must be in (0, 30] seconds")
        bounded_int(output_limit, "version probe output limit", 1, 1_048_576)
        try:
            process = subprocess.Popen(
                list(argv), shell=False, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=os.name == "posix",
            )
        except PermissionError as exc:
            return VersionProbeResult("permission_denied", None, "", "", permission_denied=True, detail=str(exc))
        except OSError as exc:
            return VersionProbeResult("missing", None, "", "", detail=str(exc))

        stdout, stderr, timed_out, output_limited = self._capture(process, float(timeout_seconds), output_limit)
        if timed_out or output_limited:
            self._terminate(process)
            return VersionProbeResult(
                "timeout" if timed_out else "invalid_output", process.returncode, stdout, stderr,
                timed_out=timed_out, output_limited=output_limited,
                detail="version probe timed out" if timed_out else "version probe output limit exceeded",
            )
        if process.returncode != 0:
            return VersionProbeResult("nonzero", process.returncode, stdout, stderr, detail="version probe returned nonzero")
        version = _extract_version(stdout + "\n" + stderr)
        if version is None:
            return VersionProbeResult("invalid_output", process.returncode, stdout, stderr, detail="version was not recognizable")
        return VersionProbeResult("available", process.returncode, stdout, stderr, version=version)

    @staticmethod
    def _capture(process: subprocess.Popen[bytes], timeout: float, limit: int) -> tuple[str, str, bool, bool]:
        assert process.stdout is not None and process.stderr is not None
        selector = selectors.DefaultSelector()
        buffers = [bytearray(), bytearray()]
        timed_out = False
        output_limited = False
        deadline = time.monotonic() + timeout
        try:
            for index, stream in enumerate((process.stdout, process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, index)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                for key, _ in selector.select(min(remaining, 0.05)):
                    capacity = limit - sum(len(item) for item in buffers)
                    try:
                        chunk = os.read(key.fd, min(8192, capacity + 1))
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffers[key.data].extend(chunk[:max(0, capacity)])
                    if len(chunk) > max(0, capacity):
                        output_limited = True
                        return tuple(_decode(item) for item in buffers) + (timed_out, output_limited)  # type: ignore[return-value]
            if not timed_out and not output_limited:
                try:
                    process.wait(timeout=max(0.001, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    timed_out = True
        finally:
            selector.close()
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        return tuple(_decode(item) for item in buffers) + (timed_out, output_limited)  # type: ignore[return-value]

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except (OSError, ProcessLookupError):
            pass
        try:
            process.wait(timeout=1.0)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _decode(value: bytearray) -> str:
    return bytes(value).decode("utf-8", "replace")


def _extract_version(output: str) -> str | None:
    import re

    match = re.search(r"(?<![A-Za-z0-9])v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)(?![A-Za-z0-9])", output)
    return match.group(1) if match else None


class DiscoveryEngine:
    """Discover only configured candidates through trusted adapter probes."""

    def __init__(self, resolver: ExecutableResolver | None = None, runner: VersionProbeRunner | None = None) -> None:
        self.resolver = resolver or SafeExecutableResolver()
        self.runner = runner or SubprocessVersionRunner()

    def discover(
        self,
        candidates: Iterable[ExecutableCandidate],
        adapters: Mapping[str, ProviderAdapter],
    ) -> tuple[DiscoveryRecord, ...]:
        ordered = sorted(candidates, key=lambda item: (item.provider_id, item.executable, item.adapter_id))
        records: list[DiscoveryRecord] = []
        for candidate in ordered:
            adapter = adapters.get(candidate.adapter_id)
            if adapter is None or not callable(getattr(adapter, "discover", None)):
                records.append(DiscoveryRecord(
                    candidate.provider_id, candidate.adapter_id, candidate.executable, None,
                    DiscoveryState.UNTRUSTED, detail="no compatible trusted adapter is registered",
                ))
                continue
            try:
                resolved = self.resolver.resolve(candidate.executable)
            except (OSError, ValidationError) as exc:
                records.append(DiscoveryRecord(
                    candidate.provider_id, candidate.adapter_id, candidate.executable, None,
                    DiscoveryState.UNAVAILABLE, detail=str(exc),
                ))
                continue
            if resolved is None:
                records.append(DiscoveryRecord(
                    candidate.provider_id, candidate.adapter_id, candidate.executable, None,
                    DiscoveryState.UNAVAILABLE, detail="configured executable was not found or is not executable",
                ))
                continue
            try:
                probe = adapter.discover(resolved, self.runner)
            except (OSError, ValidationError) as exc:
                records.append(DiscoveryRecord(
                    candidate.provider_id, candidate.adapter_id, candidate.executable, str(resolved),
                    DiscoveryState.UNTRUSTED, detail=f"adapter discovery failed safely: {exc}",
                ))
                continue
            records.append(self._record(candidate, resolved, probe))
        return tuple(records)

    @staticmethod
    def _record(candidate: ExecutableCandidate, resolved: Path, probe: VersionProbeResult) -> DiscoveryRecord:
        state = DiscoveryState.DISCOVERED if probe.status == "available" else DiscoveryState.UNAVAILABLE
        if probe.status == "permission_denied":
            state = DiscoveryState.UNTRUSTED
        elif probe.status == "incompatible":
            state = DiscoveryState.INCOMPATIBLE
        elif probe.status == "untrusted":
            state = DiscoveryState.UNTRUSTED
        return DiscoveryRecord(
            candidate.provider_id, candidate.adapter_id, candidate.executable, str(resolved), state,
            version=probe.version, detail=probe.detail, returncode=probe.returncode,
        )


class VersionOnlyAdapter:
    """Small trusted adapter helper for deterministic discovery tests.

    It intentionally implements only the discovery operation and is not a
    provider execution adapter.  Registry registration rejects it as an
    execution adapter, while ``DiscoveryEngine`` can use it for probe tests.
    """

    def __init__(self, adapter_id: str, version_args: tuple[str, ...] = ("--version",), timeout_seconds: float = 5.0) -> None:
        text(adapter_id, "adapter ID", 256)
        if type(version_args) is not tuple or not version_args or not all(isinstance(item, str) for item in version_args):
            raise ValidationError("version probe arguments must be a nonempty tuple")
        self.adapter_id = adapter_id
        self.adapter_contract_version = "1.0"
        self.version_args = version_args
        self.timeout_seconds = timeout_seconds

    def discover(self, executable: Path, runner: VersionProbeRunner) -> VersionProbeResult:
        return runner.run((str(executable), *self.version_args), timeout_seconds=self.timeout_seconds, output_limit=65_536)
