"""Read-only host inspection for Overseer admin evidence."""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
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


class HostFindingSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    HIGH = "high"


@dataclass(frozen=True)
class HostSecurityFinding:
    id: str
    severity: HostFindingSeverity
    owner_domain: str
    summary: str
    evidence: str
    recommended_action: str


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
        established_tcp = self.command_runner(("ss", "-tnp"), self.timeout_seconds)
        observations = (
            self.command_runner(("uname", "-a"), self.timeout_seconds),
            self.command_runner(("systemctl", "--user", "list-units", "--type=service", "--state=running", "--no-pager"), self.timeout_seconds),
            self.command_runner(("ss", "-ltnp"), self.timeout_seconds),
            HostCommandObservation(
                name="ss-established",
                command=established_tcp.command,
                exit_code=established_tcp.exit_code,
                stdout=established_tcp.stdout,
                stderr=established_tcp.stderr,
            ),
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


def assess_host_security(snapshot: HostInspectionSnapshot) -> tuple[HostSecurityFinding, ...]:
    findings: list[HostSecurityFinding] = []
    try:
        ss_output = snapshot.observation("ss").stdout
    except KeyError:
        return (
            HostSecurityFinding(
                id=f"finding.{snapshot.id}.missing-ss",
                severity=HostFindingSeverity.WARNING,
                owner_domain="odo",
                summary="listening socket evidence is missing",
                evidence="snapshot has no ss observation",
                recommended_action="capture a fresh host inspection snapshot",
            ),
        )

    for index, line in enumerate(ss_output.splitlines()):
        if "LISTEN" not in line:
            continue
        local = _local_socket(line)
        if not local:
            continue
        address, port = _split_address_port(local)
        if address in {"127.0.0.1", "::1", "[::1]", "localhost"}:
            continue
        severity = HostFindingSeverity.WARNING
        recommendation = "confirm this listener is expected and protected"
        if address in {"0.0.0.0", "*", "[::]", "::"}:
            severity = HostFindingSeverity.HIGH
            recommendation = "prepare an approval-gated exposure review before changing firewall or bind state"
        findings.append(
            HostSecurityFinding(
                id=f"finding.{snapshot.id}.listener.{index}",
                severity=severity,
                owner_domain="odo",
                summary=f"non-loopback TCP listener detected on {local}",
                evidence=line.strip(),
                recommended_action=recommendation,
            )
        )

    if not findings:
        findings.append(
            HostSecurityFinding(
                id=f"finding.{snapshot.id}.loopback-only",
                severity=HostFindingSeverity.INFO,
                owner_domain="odo",
                summary="no non-loopback TCP listeners detected",
                evidence="all parsed LISTEN sockets were loopback-bound",
                recommended_action="continue periodic inspection",
            )
        )
    return tuple(findings)


def host_security_status(snapshot: HostInspectionSnapshot) -> dict[str, object]:
    findings = assess_host_security(snapshot)
    return {
        "snapshot_id": snapshot.id,
        "captured_at": snapshot.captured_at,
        "hostname": snapshot.hostname,
        "findings": [
            {
                "id": finding.id,
                "severity": HostFindingSeverity(finding.severity).value,
                "owner_domain": finding.owner_domain,
                "summary": finding.summary,
                "evidence": finding.evidence,
                "recommended_action": finding.recommended_action,
            }
            for finding in findings
        ],
        "high_findings": sum(1 for finding in findings if finding.severity == HostFindingSeverity.HIGH),
        "warning_findings": sum(1 for finding in findings if finding.severity == HostFindingSeverity.WARNING),
    }


def _read_file(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def _safe_id(value: str) -> str:
    return "".join(character if character.isalnum() else "-" for character in value.lower()).strip("-")


def _local_socket(line: str) -> str:
    columns = line.split()
    if len(columns) < 4:
        return ""
    return columns[3]


def _split_address_port(local_socket: str) -> tuple[str, str]:
    if local_socket.startswith("[") and "]:" in local_socket:
        address, port = local_socket.rsplit("]:", 1)
        return f"{address}]", port
    if ":" not in local_socket:
        return local_socket, ""
    address, port = local_socket.rsplit(":", 1)
    return address, port
