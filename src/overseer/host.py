"""Read-only host inspection for Overseer admin evidence."""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


CommandRunner = Callable[[Sequence[str], float], "HostCommandObservation"]
FileReader = Callable[[str], str]


@dataclass(frozen=True)
class HostCommandObservation:
    name: str
    command: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str = ""


@dataclass(frozen=True)
class HostInspectionSnapshot:
    id: str
    captured_at: str
    hostname: str
    os_release: dict[str, str]
    observations: tuple[HostCommandObservation, ...]

    def observation(self, name: str) -> HostCommandObservation:
        for item in self.observations:
            if item.name == name:
                return item
        raise KeyError(name)


class HostInspectionAdapter:
    """Collects read-only system evidence with injectable I/O for tests."""

    def __init__(
        self,
        command_runner: CommandRunner | None = None,
        file_reader: FileReader | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.command_runner = command_runner or run_read_only_command
        self.file_reader = file_reader or _read_file
        self.timeout_seconds = timeout_seconds

    def inspect(self, captured_at: str | None = None) -> HostInspectionSnapshot:
        captured = captured_at or datetime.now(UTC).isoformat()
        hostname = self.command_runner(("hostname",), self.timeout_seconds).stdout.strip()
        observations = (
            self.command_runner(("uname", "-a"), self.timeout_seconds),
            self.command_runner(("systemctl", "--user", "list-units", "--type=service", "--state=running", "--no-pager"), self.timeout_seconds),
            self.command_runner(("ss", "-ltnp"), self.timeout_seconds),
            self.command_runner(("df", "-h", "--output=source,size,used,avail,pcent,target"), self.timeout_seconds),
        )
        return HostInspectionSnapshot(
            id=f"host.{_safe_id(hostname)}.{_safe_id(captured)}",
            captured_at=captured,
            hostname=hostname,
            os_release=parse_os_release(self.file_reader("/etc/os-release")),
            observations=observations,
        )


def run_read_only_command(command: Sequence[str], timeout_seconds: float) -> HostCommandObservation:
    completed = subprocess.run(
        tuple(command),
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )
    return HostCommandObservation(
        name=command[0],
        command=tuple(command),
        exit_code=completed.returncode,
        stdout=completed.stdout.strip(),
        stderr=completed.stderr.strip(),
    )


def parse_os_release(content: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in content.splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key] = value.strip().strip('"')
    return parsed


def host_snapshot_status(snapshot: HostInspectionSnapshot) -> dict[str, object]:
    return {
        "id": snapshot.id,
        "captured_at": snapshot.captured_at,
        "hostname": snapshot.hostname,
        "os": {
            "id": snapshot.os_release.get("ID", ""),
            "name": snapshot.os_release.get("PRETTY_NAME", snapshot.os_release.get("NAME", "")),
            "version": snapshot.os_release.get("VERSION_ID", ""),
        },
        "observations": [
            {
                "name": observation.name,
                "command": list(observation.command),
                "exit_code": observation.exit_code,
                "stdout": observation.stdout,
                "stderr": observation.stderr,
            }
            for observation in snapshot.observations
        ],
    }


def _read_file(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def _safe_id(value: str) -> str:
    return "".join(character if character.isalnum() else "-" for character in value.lower()).strip("-")
