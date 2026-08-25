"""Durable package and firmware projections for dashboard reads."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from .packages import FirmwarePreflightAdapter, FwupdFirmwareInspectionAdapter
from .store import SQLiteStore

FIRMWARE_STATUS_PROJECTION_ID = "dashboard.maintenance.firmware"
FIRMWARE_PREFLIGHT_PROJECTION_ID = "dashboard.maintenance.firmware-preflight"
MAX_PROJECTED_ITEMS = 100
MAX_PROJECTED_TEXT_LENGTH = 2048


def _text(value: object, limit: int = MAX_PROJECTED_TEXT_LENGTH) -> str:
    return str(value or "")[:limit]


def package_status_projection(store_path: str | Path) -> dict[str, object]:
    with SQLiteStore(store_path) as store:
        records = sorted(
            store.list_package_inspection_records(),
            key=lambda item: (item.captured_at, item.id),
            reverse=True,
        )
    if not records:
        return {
            "id": "",
            "captured_at": "",
            "command": [],
            "exit_code": None,
            "status": "awaiting_scheduled_inspection",
            "upgradable": 0,
            "stderr": "",
            "items": [],
            "collection_mode": "durable_sqlite_projection",
        }
    record = records[0]
    return {
        "id": record.id,
        "captured_at": record.captured_at,
        "command": list(record.command),
        "exit_code": record.exit_code,
        "status": "ok" if record.succeeded() else "failed",
        "upgradable": len(record.updates),
        "stderr": "package inspection reported an error" if record.stderr else "",
        "items": [
            {
                "name": item.name,
                "repository": item.repository,
                "candidate_version": item.candidate_version,
                "architecture": item.architecture,
                "installed_version": item.installed_version,
            }
            for item in record.updates[:MAX_PROJECTED_ITEMS]
        ],
        "collection_mode": "durable_sqlite_projection",
    }


def capture_firmware_projections_subprocess(
    store_path: str | Path,
    *,
    timeout_seconds: float = 15.0,
) -> dict[str, object]:
    """Run the complete firmware collector in a killable process boundary."""

    timeout_seconds = max(0.1, float(timeout_seconds))
    command = (
        sys.executable,
        "-m",
        "overseer.maintenance_projections",
        "--capture-firmware",
        str(Path(store_path)),
        str(max(0.1, timeout_seconds - 0.25)),
    )
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return {
            "outcome": "failed",
            "failure_category": "timeout",
            "evidence_ids": (),
        }
    except OSError:
        return {
            "outcome": "failed",
            "failure_category": "unavailable",
            "evidence_ids": (),
        }
    if completed.returncode != 0:
        return {
            "outcome": "failed",
            "failure_category": "internal_error",
            "evidence_ids": (),
        }
    try:
        payload = json.loads(completed.stdout or "")
        if not isinstance(payload, dict):
            raise ValueError("firmware collector result must be an object")
        outcome = str(payload.get("outcome") or "failed")
        if outcome not in {"succeeded", "failed", "blocked", "timed_out"}:
            raise ValueError("firmware collector outcome is invalid")
        evidence_ids = tuple(
            str(item)[:160]
            for item in list(payload.get("evidence_ids") or [])[:2]
        )
        return {
            "outcome": outcome,
            "failure_category": str(payload.get("failure_category") or "")[:160],
            "evidence_ids": evidence_ids,
        }
    except (TypeError, ValueError, json.JSONDecodeError):
        return {
            "outcome": "failed",
            "failure_category": "contract_mismatch",
            "evidence_ids": (),
        }


def firmware_status_projection(store_path: str | Path) -> dict[str, object]:
    return _load_projection(
        store_path,
        FIRMWARE_STATUS_PROJECTION_ID,
        {
            "id": "",
            "captured_at": "",
            "command": [],
            "exit_code": None,
            "status": "awaiting_scheduled_inspection",
            "updates": 0,
            "blocked_updates": 0,
            "high_urgency": 0,
            "reboot_required": 0,
            "stderr": "",
            "items": [],
            "no_update_devices": [],
            "next_step": "wait for the scheduled firmware inspection",
            "mutation_performed": False,
            "host_mutation_performed": False,
        },
    )


def firmware_preflight_projection(store_path: str | Path) -> dict[str, object]:
    return _load_projection(
        store_path,
        FIRMWARE_PREFLIGHT_PROJECTION_ID,
        {
            "id": "",
            "captured_at": "",
            "status": "awaiting_scheduled_inspection",
            "efivar_path": ".../efivars",
            "efivar_accessible": None,
            "efivar_count": 0,
            "total_bytes": 0,
            "largest": [],
            "stale_dump_candidates": [],
            "stale_dump_candidate_count": 0,
            "error": "",
            "mutation_performed": False,
            "host_mutation_performed": False,
            "next_step": "wait for the scheduled firmware preflight inspection",
        },
    )


def capture_firmware_projections(
    store_path: str | Path,
    *,
    timeout_seconds: float = 15.0,
    captured_at: str | None = None,
    monotonic: Callable[[], float] | None = None,
) -> dict[str, object]:
    clock = monotonic or time.monotonic
    timeout_seconds = max(0.1, float(timeout_seconds))
    deadline = clock() + timeout_seconds
    observed_at = captured_at or datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    firmware = FwupdFirmwareInspectionAdapter(
        timeout_seconds=max(0.05, timeout_seconds * 0.75)
    ).inspect(observed_at)
    remaining = deadline - clock()
    if remaining <= 0.1:
        return {
            "outcome": "failed",
            "failure_category": "timeout",
            "evidence_ids": (firmware.id,),
        }
    preflight = FirmwarePreflightAdapter(
        timeout_seconds=max(0.05, remaining - 0.05),
        deadline=deadline,
        clock=clock,
    ).inspect(observed_at)
    if clock() >= deadline:
        return {
            "outcome": "failed",
            "failure_category": "timeout",
            "evidence_ids": (firmware.id, preflight.id),
        }
    firmware_payload = _firmware_payload(firmware)
    preflight_payload = _preflight_payload(preflight)
    remaining = deadline - clock()
    if remaining <= 0.05:
        return {
            "outcome": "failed",
            "failure_category": "timeout",
            "evidence_ids": (firmware.id, preflight.id),
        }
    try:
        with SQLiteStore(
            store_path,
            timeout_seconds=max(0.01, remaining * 0.5),
        ) as store:
            if clock() >= deadline:
                return {
                    "outcome": "failed",
                    "failure_category": "timeout",
                    "evidence_ids": (firmware.id, preflight.id),
                }
            store.save_dashboard_projections(
                {
                    FIRMWARE_STATUS_PROJECTION_ID: firmware_payload,
                    FIRMWARE_PREFLIGHT_PROJECTION_ID: preflight_payload,
                }
            )
    except sqlite3.OperationalError:
        return {
            "outcome": "failed",
            "failure_category": "timeout",
            "evidence_ids": (firmware.id, preflight.id),
        }
    succeeded = firmware.succeeded() and preflight.succeeded()
    timed_out = firmware.exit_code == 124 or "timed out" in preflight.error.lower()
    return {
        "outcome": "succeeded" if succeeded else "failed",
        "failure_category": "" if succeeded else ("timeout" if timed_out else "unavailable"),
        "evidence_ids": (firmware.id, preflight.id),
    }


def _firmware_payload(snapshot) -> dict[str, object]:
    projected_updates = snapshot.updates[:MAX_PROJECTED_ITEMS]
    blocked = [item for item in snapshot.updates if item.update_error]
    high = [item for item in snapshot.updates if item.urgency.lower() in {"high", "critical"}]
    reboot_required = [item for item in snapshot.updates if item.reboot_required]
    return {
        "id": snapshot.id,
        "captured_at": snapshot.captured_at,
        "command": list(snapshot.command),
        "exit_code": snapshot.exit_code,
        "status": "ok" if snapshot.succeeded() else "failed",
        "updates": len(snapshot.updates),
        "blocked_updates": len(blocked),
        "high_urgency": len(high),
        "reboot_required": len(reboot_required),
        "stderr": "firmware inspection reported an error" if snapshot.stderr else "",
        "items": [
            {
                "device": _text(item.device, 256),
                "title": _text(item.title, 256),
                "current_version": _text(item.current_version, 160),
                "new_version": _text(item.new_version, 160),
                "urgency": _text(item.urgency, 32),
                "vendor": _text(item.vendor, 160),
                "release_id": _text(item.release_id, 160),
                "remote_id": _text(item.remote_id, 160),
                "summary": _text(item.summary),
                "update_error": "firmware update reported an error" if item.update_error else "",
                "blocker_type": _firmware_blocker_type(item.update_error),
                "blocker_resolution": _firmware_blocker_resolution(
                    _firmware_blocker_type(item.update_error)
                ),
                "safe_preflight": _firmware_safe_preflight(
                    _firmware_blocker_type(item.update_error)
                ),
                "reboot_required": item.reboot_required,
                "status": "blocked" if item.update_error else "available",
                "next_step": (
                    "resolve firmware update blocker before approval"
                    if item.update_error
                    else "stage approval-gated firmware update plan"
                ),
            }
            for item in projected_updates
        ],
        "no_update_devices": [
            _text(item, 256)
            for item in snapshot.no_update_devices[:MAX_PROJECTED_ITEMS]
        ],
        "next_step": _firmware_next_step(snapshot),
        "mutation_performed": False,
        "host_mutation_performed": False,
        "collection_mode": "durable_sqlite_projection",
    }


def _preflight_payload(snapshot) -> dict[str, object]:
    entries = list(snapshot.efivars[:100])
    dump_entries = [
        entry
        for entry in entries
        if any(marker in entry.name.lower() for marker in ("dump", "crash", "panic", "morc"))
    ]
    return {
        "id": snapshot.id,
        "captured_at": snapshot.captured_at,
        "status": "ok" if snapshot.succeeded() else "failed",
        "efivar_path": f".../{Path(snapshot.efivar_path).name}",
        "efivar_accessible": snapshot.efivar_accessible,
        "efivar_count": len(snapshot.efivars),
        "total_bytes": sum(entry.size_bytes for entry in snapshot.efivars),
        "largest": [
            {"name": _text(entry.name, 256), "size_bytes": entry.size_bytes}
            for entry in entries[:10]
        ],
        "stale_dump_candidates": [
            {"name": _text(entry.name, 256), "size_bytes": entry.size_bytes}
            for entry in dump_entries
        ],
        "stale_dump_candidate_count": len(dump_entries),
        "error": "firmware preflight reported an error" if snapshot.error else "",
        "mutation_performed": False,
        "host_mutation_performed": False,
        "next_step": (
            "repair efivarfs access before firmware blocker analysis"
            if not snapshot.succeeded()
            else (
                "review stale dump candidates and stage explicit human-approved efivar cleanup before fwupd update"
                if dump_entries
                else "no obvious stale dump efivars detected; review firmware settings or vendor guidance before fwupd update"
            )
        ),
        "collection_mode": "durable_sqlite_projection",
    }


def _firmware_next_step(snapshot) -> str:
    if not snapshot.succeeded():
        return "repair fwupd firmware inspection before staging firmware maintenance"
    if any(item.update_error for item in snapshot.updates):
        return "resolve blocked firmware update preconditions before staging firmware execution"
    if snapshot.updates:
        return "stage approval-gated firmware update plan with reboot and rollback notes"
    return "no firmware updates detected"


def _firmware_blocker_type(update_error: str) -> str:
    normalized = update_error.lower()
    if "efivarfs" in normalized or "efi variable" in normalized:
        return "efivarfs_space"
    if "reboot" in normalized:
        return "reboot_required"
    if "not enough" in normalized and "space" in normalized:
        return "space"
    return "unknown" if normalized else ""


def _firmware_blocker_resolution(blocker_type: str) -> str:
    if blocker_type == "efivarfs_space":
        return "Inspect EFI variable usage and stage explicit human-approved remediation before running fwupd."
    if blocker_type == "reboot_required":
        return "Schedule a reboot window, re-run inspection, and then stage the update."
    if blocker_type == "space":
        return "Inspect firmware-provider storage and stage a targeted cleanup before update execution."
    if blocker_type == "unknown":
        return "Review fwupd device details and vendor guidance before staging live execution."
    return "No blocker reported; stage an approval-gated firmware update plan."


def _firmware_safe_preflight(blocker_type: str) -> list[str]:
    if blocker_type == "efivarfs_space":
        return [
            "fwupdmgr get-devices",
            "fwupdmgr get-upgrades --no-reboot-check",
            "find /sys/firmware/efi/efivars -maxdepth 1 -type f -printf '%f %s\\n'",
        ]
    if blocker_type:
        return ["fwupdmgr get-devices", "fwupdmgr get-upgrades --no-reboot-check"]
    return ["fwupdmgr get-upgrades --no-reboot-check"]


def _load_projection(
    store_path: str | Path,
    projection_id: str,
    fallback: dict[str, object],
) -> dict[str, object]:
    try:
        with SQLiteStore(store_path) as store:
            payload = store.load_dashboard_projection(projection_id)
    except (KeyError, OSError, ValueError):
        payload = fallback
    return {**payload, "collection_mode": "durable_sqlite_projection"}


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 3 or arguments[0] != "--capture-firmware":
        return 2
    try:
        timeout_seconds = float(arguments[2])
    except ValueError:
        return 2
    result = capture_firmware_projections(
        arguments[1],
        timeout_seconds=timeout_seconds,
    )
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
