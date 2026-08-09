"""Read-only package maintenance inspection adapters."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path


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


@dataclass(frozen=True)
class PackageInspectionRecord:
    id: str
    captured_at: str
    command: tuple[str, ...]
    exit_code: int
    updates: tuple[PackageUpdate, ...]
    state_fingerprint: str
    stderr: str = ""

    def succeeded(self) -> bool:
        return self.exit_code == 0


@dataclass(frozen=True)
class PackageReconciliationEvidence:
    id: str
    snapshot_id: str
    maintenance_batch_id: str
    observed_at: str
    outcome: str
    plan_ids: tuple[str, ...] = ()
    message_ids: tuple[str, ...] = ()


def package_state_fingerprint(snapshot: PackageInspectionSnapshot) -> str:
    rows = [
        {
            "architecture": item.architecture or "",
            "candidate_version": item.candidate_version or "",
            "installed_version": item.installed_version or "",
            "name": item.name or "",
            "repository": item.repository or "",
        }
        for item in sorted(snapshot.updates, key=lambda value: (value.name, value.architecture))
    ]
    payload = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def package_inspection_record(snapshot: PackageInspectionSnapshot) -> PackageInspectionRecord:
    fingerprint = package_state_fingerprint(snapshot)
    record_payload = json.dumps(
        {
            "captured_at": snapshot.captured_at,
            "command": snapshot.command,
            "exit_code": snapshot.exit_code,
            "fingerprint": fingerprint,
            "stderr": snapshot.stderr,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    digest = hashlib.sha256(record_payload).hexdigest()
    return PackageInspectionRecord(
        id=f"{snapshot.id}.{digest[:16]}",
        captured_at=snapshot.captured_at,
        command=snapshot.command,
        exit_code=snapshot.exit_code,
        updates=snapshot.updates,
        state_fingerprint=fingerprint,
        stderr=snapshot.stderr,
    )


@dataclass(frozen=True)
class FirmwareUpdate:
    device: str
    title: str
    current_version: str = ""
    new_version: str = ""
    urgency: str = ""
    vendor: str = ""
    release_id: str = ""
    remote_id: str = ""
    summary: str = ""
    update_error: str = ""
    reboot_required: bool = False


@dataclass(frozen=True)
class FirmwareInspectionSnapshot:
    id: str
    captured_at: str
    command: tuple[str, ...]
    exit_code: int
    updates: tuple[FirmwareUpdate, ...]
    no_update_devices: tuple[str, ...] = ()
    stderr: str = ""

    def succeeded(self) -> bool:
        return self.exit_code == 0


@dataclass(frozen=True)
class EfivarEntry:
    name: str
    size_bytes: int


@dataclass(frozen=True)
class FirmwarePreflightSnapshot:
    id: str
    captured_at: str
    efivar_path: str
    efivar_accessible: bool
    efivars: tuple[EfivarEntry, ...]
    error: str = ""

    def succeeded(self) -> bool:
        return self.efivar_accessible and not self.error


PackageCommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")


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


class FwupdFirmwareInspectionAdapter:
    def __init__(self, command_runner: PackageCommandRunner | None = None) -> None:
        self.command_runner = command_runner or self._run

    def inspect(self, captured_at: str | None = None) -> FirmwareInspectionSnapshot:
        observed_at = captured_at or datetime.now(UTC).isoformat()
        command = ("fwupdmgr", "get-upgrades", "--no-reboot-check")
        completed = self.command_runner(command)
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        updates, no_update_devices = parse_fwupd_upgrades(stdout) if completed.returncode == 0 else ((), ())
        return FirmwareInspectionSnapshot(
            id=f"firmware-inspection.{_snapshot_suffix(observed_at)}",
            captured_at=observed_at,
            command=command,
            exit_code=completed.returncode,
            updates=updates,
            no_update_devices=no_update_devices,
            stderr=stderr.strip(),
        )

    @staticmethod
    def _run(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(command, check=False, capture_output=True, text=True, timeout=30)
        except FileNotFoundError as exc:
            return subprocess.CompletedProcess(command, 127, "", str(exc))
        except subprocess.TimeoutExpired as exc:
            return subprocess.CompletedProcess(command, 124, exc.stdout or "", exc.stderr or "fwupdmgr timed out")


class FirmwarePreflightAdapter:
    def __init__(self, efivar_path: str | Path = "/sys/firmware/efi/efivars") -> None:
        self.efivar_path = Path(efivar_path)

    def inspect(self, captured_at: str | None = None) -> FirmwarePreflightSnapshot:
        observed_at = captured_at or datetime.now(UTC).isoformat()
        try:
            if not self.efivar_path.exists():
                return FirmwarePreflightSnapshot(
                    id=f"firmware-preflight.{_snapshot_suffix(observed_at)}",
                    captured_at=observed_at,
                    efivar_path=str(self.efivar_path),
                    efivar_accessible=False,
                    efivars=(),
                    error="efivarfs path is not present",
                )
            entries = tuple(
                sorted(
                    (
                        EfivarEntry(name=entry.name, size_bytes=entry.stat().st_size)
                        for entry in self.efivar_path.iterdir()
                        if entry.is_file()
                    ),
                    key=lambda item: item.size_bytes,
                    reverse=True,
                )
            )
            return FirmwarePreflightSnapshot(
                id=f"firmware-preflight.{_snapshot_suffix(observed_at)}",
                captured_at=observed_at,
                efivar_path=str(self.efivar_path),
                efivar_accessible=True,
                efivars=entries,
            )
        except OSError as exc:
            return FirmwarePreflightSnapshot(
                id=f"firmware-preflight.{_snapshot_suffix(observed_at)}",
                captured_at=observed_at,
                efivar_path=str(self.efivar_path),
                efivar_accessible=False,
                efivars=(),
                error=str(exc),
            )


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


def parse_fwupd_upgrades(output: str) -> tuple[tuple[FirmwareUpdate, ...], tuple[str, ...]]:
    updates: list[FirmwareUpdate] = []
    no_update_devices: list[str] = []
    current_device = ""
    update_error = ""
    current_version = ""
    current_reboot_required = False
    current_release: dict[str, object] | None = None
    release_description = False
    in_no_updates = False

    def finish_release() -> None:
        nonlocal current_release
        if current_release is None:
            return
        updates.append(
            FirmwareUpdate(
                device=current_device,
                title=str(current_release.get("title") or ""),
                current_version=current_version,
                new_version=str(current_release.get("new_version") or ""),
                urgency=str(current_release.get("urgency") or ""),
                vendor=str(current_release.get("vendor") or ""),
                release_id=str(current_release.get("release_id") or ""),
                remote_id=str(current_release.get("remote_id") or ""),
                summary=str(current_release.get("summary") or ""),
                update_error=update_error,
                reboot_required=current_reboot_required or bool(current_release.get("reboot_required")),
            )
        )
        current_release = None

    for raw_line in output.splitlines():
        raw_line = _clean_fwupd_text(raw_line)
        raw_stripped = raw_line.strip()
        line = raw_line.strip(" │├└─\t")
        if not line or line.startswith("Idle"):
            continue
        if line.startswith("Devices with no available firmware updates"):
            in_no_updates = True
            continue
        if in_no_updates:
            if line.startswith("•"):
                no_update_devices.append(line.lstrip("• ").strip())
                continue
            in_no_updates = False
        if line == "LENOVO 80VR" or (not ":" in line and not line.startswith("•") and not line.startswith("│")):
            continue
        if line and not ":" in line and not line.startswith("•"):
            continue
        if any(marker in raw_stripped for marker in ("├─", "└─")):
            heading = line.rstrip(":")
            finish_release()
            if "Update" in heading or "Configuration" in heading:
                current_release = {"title": heading, "reboot_required": False}
            else:
                current_device = heading
                update_error = ""
                current_version = ""
                current_reboot_required = False
            release_description = False
            continue
        if "Needs a reboot after installation" in line:
            if current_release is None:
                current_reboot_required = True
            else:
                current_release["reboot_required"] = True
        if ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        if current_release is None:
            if key == "Current version":
                current_version = value
            elif key == "Update Error":
                update_error = value
            continue
        if key == "New version":
            current_release["new_version"] = value
        elif key == "Remote ID":
            current_release["remote_id"] = value
        elif key == "Release ID":
            current_release["release_id"] = value
        elif key == "Summary":
            current_release["summary"] = value
        elif key == "Vendor":
            current_release["vendor"] = value
        elif key == "Urgency":
            current_release["urgency"] = value
        elif key == "Description":
            release_description = True
        elif key == "Device Flags":
            release_description = False
        elif release_description and value:
            current_release["summary"] = value
    finish_release()
    return tuple(updates), tuple(dict.fromkeys(no_update_devices))


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


def _clean_fwupd_text(value: str) -> str:
    return ANSI_ESCAPE_RE.sub("", value).replace("\u00a0", " ")


def _snapshot_suffix(value: str) -> str:
    return re.sub(r"[^0-9A-Za-z]+", "-", value).strip("-").lower() or "unknown"
