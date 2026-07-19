"""Read-only package maintenance inspection adapters."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True)
class PackageUpdate:
    name: str
    repository: str
    candidate_version: str
    architecture: str
    installed_version: str | None = None


@dataclass(frozen=True)
class PackageInspectionSnapshot:
    id: str
    captured_at: str
    command: tuple[str, ...]
    exit_code: int
    updates: tuple[PackageUpdate, ...]
    stderr: str = ""

    def succeeded(self) -> bool:
        return self.exit_code == 0


PackageCommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


class AptPackageInspectionAdapter:
    def __init__(self, command_runner: PackageCommandRunner | None = None) -> None:
        self.command_runner = command_runner or self._run

    def inspect(self, captured_at: str | None = None) -> PackageInspectionSnapshot:
        observed_at = captured_at or datetime.now(UTC).isoformat()
        command = ("apt", "list", "--upgradable")
        completed = self.command_runner(command)
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        return PackageInspectionSnapshot(
            id=f"package-inspection.{_snapshot_suffix(observed_at)}",
            captured_at=observed_at,
            command=command,
            exit_code=completed.returncode,
            updates=parse_apt_upgradable(stdout) if completed.returncode == 0 else (),
            stderr=stderr.strip(),
        )

    @staticmethod
    def _run(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(command, check=False, capture_output=True, text=True)


def parse_apt_upgradable(output: str) -> tuple[PackageUpdate, ...]:
    updates: list[PackageUpdate] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("Listing..."):
            continue
        parsed = _parse_apt_upgradable_line(line)
        if parsed is not None:
            updates.append(parsed)
    return tuple(updates)


def _parse_apt_upgradable_line(line: str) -> PackageUpdate | None:
    match = re.match(
        r"^(?P<name>[^/]+)/(?P<repository>\S+)\s+(?P<candidate_version>\S+)\s+(?P<architecture>\S+)(?:\s+\[upgradable from: (?P<installed_version>[^\]]+)\])?",
        line,
    )
    if match is None:
        return None
    return PackageUpdate(
        name=match.group("name"),
        repository=match.group("repository"),
        candidate_version=match.group("candidate_version"),
        architecture=match.group("architecture"),
        installed_version=match.group("installed_version"),
    )


def _snapshot_suffix(value: str) -> str:
    return re.sub(r"[^0-9A-Za-z]+", "-", value).strip("-").lower() or "unknown"
