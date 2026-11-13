"""Offline capability checks; instructions never become execution authority."""

from dataclasses import asdict
from pathlib import Path
import os
import shutil

from .errors import ExecutionGuardError, ValidationError
from .packets import TaskPacket
from .skill_catalog import load_skill_catalog
from .skills import SkillRegistry


def tool_identity(value: str) -> str:
    candidate = Path(value)
    if not candidate.is_absolute():
        if len(candidate.parts) != 1:
            raise ValidationError("tool must be an absolute path or PATH command")
        resolved = shutil.which(value)
        if resolved is None:
            raise ExecutionGuardError(f"requested tool is unavailable: {value}")
        candidate = Path(resolved)
    try:
        candidate = candidate.resolve(strict=True)
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            raise ExecutionGuardError(f"requested tool is not executable: {value}")
        return str(candidate)
    except (OSError, RuntimeError) as exc:
        raise ExecutionGuardError(f"requested tool is unavailable: {value}") from exc


def skill_assignment(packet: TaskPacket, requested: tuple[str, ...],
                     available: tuple[str, ...]) -> list[dict[str, object]]:
    registry = SkillRegistry(packet.skills)
    resolved = registry.resolve(requested, packet.role, available)
    if set(resolved) != set(packet.skills):
        raise ExecutionGuardError("packet contains skills outside the requested dependency closure")
    catalog = load_skill_catalog(Path(packet.workspace_root)) if packet.skills else None
    records = {item.name: item for item in catalog.registry.records} if catalog else {}
    result = []
    for skill in sorted(resolved, key=lambda item: item.name):
        provenance = {"source": "local_skill_record", "source_path": skill.source_path,
                      "source_sha256": skill.digest_sha256, "supplied_version": skill.supplied_version}
        if skill.name in records:
            if records[skill.name] != skill:
                raise ExecutionGuardError("skill assignment differs from the verified catalog")
            provenance = {"source": "skill_catalog", **asdict(catalog.provenance_for(skill.name))}
        result.append({"name": skill.name, "content_digest": skill.digest_sha256,
                       "source_path": skill.source_path, "supplied_version": skill.supplied_version,
                       "scope": skill.scope, "provenance": provenance,
                       "applicable_roles": [role.value for role in skill.applicable_roles],
                       "dependencies": list(skill.dependencies),
                       "required_capabilities": list(skill.required_capabilities)})
    return result
