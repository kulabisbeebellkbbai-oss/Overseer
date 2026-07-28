"""Staged backup, restore-test, and cleanup records for Kira."""

from __future__ import annotations

import json
import re
import shutil
import hashlib
from datetime import UTC, datetime
from pathlib import Path


MEDIASTORE_CREDENTIAL_PATH = Path("local-secrets/backup-providers/mediastore/credentials.conf")
MEDIASTORE_MOUNT_PATH = Path("local-secrets/mounts/mediastore")
MEDIASTORE_SHARE = "//MediaStore/Overseer"


def backup_operations_status(project_root: str | Path) -> dict[str, object]:
    root = Path(project_root)
    data = _read_registry(root)
    provider_readiness = backup_provider_readiness_status(root)
    return {
        "root": str(root),
        "jobs": data["jobs"],
        "job_count": len(data["jobs"]),
        "restore_tests": data["restore_tests"],
        "restore_test_count": len(data["restore_tests"]),
        "backup_requests": data["backup_requests"],
        "backup_request_count": len(data["backup_requests"]),
        "restore_requests": data["restore_requests"],
        "restore_request_count": len(data["restore_requests"]),
        "cleanup_requests": data["cleanup_requests"],
        "cleanup_request_count": len(data["cleanup_requests"]),
        "provider_targets": provider_readiness["targets"],
        "provider_classes": provider_readiness["provider_classes"],
        "provider_readiness": provider_readiness["readiness"],
        "provider_standard": provider_readiness["standard"],
        "provider_local_profiles": provider_readiness["local_profiles"],
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def backup_provider_readiness_status(project_root: str | Path) -> dict[str, object]:
    root = Path(project_root)
    local_profiles = _local_provider_profiles(root)
    targets = _provider_target_rows(root, local_profiles)
    classes = _provider_class_rows()
    readiness = [_provider_readiness_row(row) for row in targets]
    return {
        "root": str(root),
        "standard": "3-2-1 backups with restore testing, immutable retention where supported, encryption, and monitored offsite copies",
        "targets": targets,
        "provider_classes": classes,
        "readiness": readiness,
        "local_profiles": local_profiles,
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def record_backup_job_status(
    project_root: str | Path,
    job_id: str,
    target: str,
    schedule: str = "manual",
    retention: str = "operator-defined",
    requested_by: str = "kira",
    risk_level: str = "medium",
    status: str = "staged",
    notes: str = "",
) -> dict[str, object]:
    root = Path(project_root)
    data = _read_registry(root)
    now = _now()
    row = {
        "id": _safe_id(job_id),
        "target": _redact_path(target),
        "schedule": schedule,
        "retention": retention,
        "requested_by": requested_by,
        "risk_level": risk_level,
        "status": status,
        "notes": notes,
        "updated_at": now,
        "next_step": "stage backup execution plan with validation and rollback before live file operations",
    }
    existing = next((index for index, item in enumerate(data["jobs"]) if item["id"] == row["id"]), None)
    if existing is None:
        row["created_at"] = now
        data["jobs"].append(row)
    else:
        row["created_at"] = data["jobs"][existing].get("created_at") or now
        data["jobs"][existing] = row
    _write_registry(root, data)
    return {"job": row, "mutation_performed": True, "host_mutation_performed": False}


def record_restore_test_status(
    project_root: str | Path,
    test_id: str,
    job_id: str,
    restore_point: str,
    status: str = "planned",
    validated_by: str = "kira",
    notes: str = "",
) -> dict[str, object]:
    root = Path(project_root)
    data = _read_registry(root)
    now = _now()
    row = {
        "id": _safe_id(test_id),
        "job_id": _safe_id(job_id),
        "restore_point": _redact_path(restore_point),
        "status": status,
        "validated_by": validated_by,
        "notes": notes,
        "updated_at": now,
        "next_step": "perform restore verification only in an approved isolated target",
    }
    existing = next((index for index, item in enumerate(data["restore_tests"]) if item["id"] == row["id"]), None)
    if existing is None:
        row["created_at"] = now
        data["restore_tests"].append(row)
    else:
        row["created_at"] = data["restore_tests"][existing].get("created_at") or now
        data["restore_tests"][existing] = row
    _write_registry(root, data)
    return {"restore_test": row, "mutation_performed": True, "host_mutation_performed": False}


def stage_backup_execution_request_status(
    project_root: str | Path,
    source_path: str,
    requested_by: str = "kira",
    reason: str = "stage approved local backup execution",
    backup_name: str | None = None,
) -> dict[str, object]:
    root = Path(project_root)
    data = _read_registry(root)
    now = _now()
    request_id = f"backup-exec.{_safe_id(backup_name or source_path)}"
    row = {
        "id": request_id,
        "source_path": _redact_path(source_path),
        "backup_name": _safe_id(backup_name or source_path),
        "requested_by": requested_by,
        "reason": reason,
        "status": "waiting_approval",
        "approval_required": True,
        "created_at": now,
        "updated_at": now,
        "next_step": "approve backup execution before copying project-local data to ignored backups/",
    }
    _upsert(data["backup_requests"], row)
    _write_registry(root, data)
    return {"backup_request": row, "mutation_performed": True, "host_mutation_performed": False}


def approve_backup_execution_request_status(
    project_root: str | Path,
    request_id: str,
    approved_by: str = "kira",
    approved_at: str | None = None,
) -> dict[str, object]:
    if not approved_by.strip():
        raise ValueError("approved_by is required")
    root = Path(project_root)
    data = _read_registry(root)
    row = _find_request(data["backup_requests"], request_id, "backup-exec")
    if row.get("status") not in {"waiting_approval", "approved"}:
        raise ValueError(f"backup request is not approvable: {row.get('status')}")
    now = approved_at or _now()
    row.update(
        {
            "status": "approved",
            "approved_by": approved_by,
            "approved_at": now,
            "updated_at": now,
            "next_step": "execute approved backup after final source and exclusion validation",
        }
    )
    _write_registry(root, data)
    return {"backup_request": row, "mutation_performed": True, "host_mutation_performed": False}


def execute_backup_execution_request_status(
    project_root: str | Path,
    request_id: str,
    executed_by: str = "kira",
    executed_at: str | None = None,
) -> dict[str, object]:
    if not executed_by.strip():
        raise ValueError("executed_by is required")
    root = Path(project_root)
    data = _read_registry(root)
    row = _find_request(data["backup_requests"], request_id, "backup-exec")
    now = executed_at or _now()
    try:
        _validate_approved_request(row, "backup request")
        source = _backup_source(root, str(row.get("source_path") or ""))
        destination = _backup_destination(root, str(row.get("backup_name") or request_id), now)
        manifest = _copy_with_manifest(root, source, destination, request_id, "backup", now)
    except ValueError as error:
        row.update(_blocked_fields(executed_by, now, str(error), "review blocked backup request and stage a corrected project-relative source"))
        _write_registry(root, data)
        return {"backup_request": row, "status": "blocked", "summary": str(error), "mutation_performed": True, "host_mutation_performed": False}
    except OSError as error:
        row.update(_failed_fields(executed_by, now, str(error), "inspect partial backup artifact and retry after Kira verifies storage safety"))
        _write_registry(root, data)
        return {"backup_request": row, "status": "failed", "summary": str(error), "mutation_performed": True, "host_mutation_performed": True}

    row.update(
        {
            "status": "completed",
            "executed_by": executed_by,
            "executed_at": now,
            "updated_at": now,
            "backup_path": manifest["destination"],
            "manifest_path": manifest["manifest_path"],
            "entry_count": manifest["entry_count"],
            "total_bytes": manifest["total_bytes"],
            "next_step": "backup completed; stage a restore test before relying on this restore point",
        }
    )
    _write_registry(root, data)
    return {"backup_request": row, "status": "completed", "manifest": manifest, "mutation_performed": True, "host_mutation_performed": True}


def stage_restore_execution_request_status(
    project_root: str | Path,
    backup_path: str,
    restore_target: str,
    requested_by: str = "kira",
    reason: str = "stage approved local restore execution",
) -> dict[str, object]:
    root = Path(project_root)
    data = _read_registry(root)
    now = _now()
    request_id = f"restore-exec.{_safe_id(backup_path)}.{_safe_id(restore_target)}"
    row = {
        "id": request_id,
        "backup_path": _redact_path(backup_path),
        "restore_target": _redact_path(restore_target),
        "requested_by": requested_by,
        "reason": reason,
        "status": "waiting_approval",
        "approval_required": True,
        "created_at": now,
        "updated_at": now,
        "next_step": "approve restore execution before copying backup data into an isolated project-local target",
    }
    _upsert(data["restore_requests"], row)
    _write_registry(root, data)
    return {"restore_request": row, "mutation_performed": True, "host_mutation_performed": False}


def approve_restore_execution_request_status(
    project_root: str | Path,
    request_id: str,
    approved_by: str = "kira",
    approved_at: str | None = None,
) -> dict[str, object]:
    if not approved_by.strip():
        raise ValueError("approved_by is required")
    root = Path(project_root)
    data = _read_registry(root)
    row = _find_request(data["restore_requests"], request_id, "restore-exec")
    if row.get("status") not in {"waiting_approval", "approved"}:
        raise ValueError(f"restore request is not approvable: {row.get('status')}")
    now = approved_at or _now()
    row.update(
        {
            "status": "approved",
            "approved_by": approved_by,
            "approved_at": now,
            "updated_at": now,
            "next_step": "execute approved restore after final backup and target validation",
        }
    )
    _write_registry(root, data)
    return {"restore_request": row, "mutation_performed": True, "host_mutation_performed": False}


def execute_restore_execution_request_status(
    project_root: str | Path,
    request_id: str,
    executed_by: str = "kira",
    executed_at: str | None = None,
) -> dict[str, object]:
    if not executed_by.strip():
        raise ValueError("executed_by is required")
    root = Path(project_root)
    data = _read_registry(root)
    row = _find_request(data["restore_requests"], request_id, "restore-exec")
    now = executed_at or _now()
    try:
        _validate_approved_request(row, "restore request")
        backup = _restore_source(root, str(row.get("backup_path") or ""))
        target = _restore_target(root, str(row.get("restore_target") or ""))
        manifest = _copy_with_manifest(root, backup, target, request_id, "restore", now)
    except ValueError as error:
        row.update(_blocked_fields(executed_by, now, str(error), "review blocked restore request and stage a corrected backup/target pair"))
        _write_registry(root, data)
        return {"restore_request": row, "status": "blocked", "summary": str(error), "mutation_performed": True, "host_mutation_performed": False}
    except OSError as error:
        row.update(_failed_fields(executed_by, now, str(error), "inspect partial restore target and retry only after Kira verifies storage safety"))
        _write_registry(root, data)
        return {"restore_request": row, "status": "failed", "summary": str(error), "mutation_performed": True, "host_mutation_performed": True}

    row.update(
        {
            "status": "completed",
            "executed_by": executed_by,
            "executed_at": now,
            "updated_at": now,
            "restored_path": manifest["destination"],
            "manifest_path": manifest["manifest_path"],
            "entry_count": manifest["entry_count"],
            "total_bytes": manifest["total_bytes"],
            "next_step": "restore completed; record a restore test result and validate service health",
        }
    )
    _write_registry(root, data)
    return {"restore_request": row, "status": "completed", "manifest": manifest, "mutation_performed": True, "host_mutation_performed": True}


def stage_backup_cleanup_request_status(
    project_root: str | Path,
    path: str,
    requested_by: str = "kira",
    reason: str = "review generated storage cleanup candidate",
) -> dict[str, object]:
    root = Path(project_root)
    data = _read_registry(root)
    now = _now()
    request_id = f"backup-cleanup.{_safe_id(path)}"
    row = {
        "id": request_id,
        "path": _redact_path(path),
        "requested_by": requested_by,
        "reason": reason,
        "status": "waiting_approval",
        "approval_required": True,
        "created_at": now,
        "updated_at": now,
        "next_step": "human approval required before deleting backup, restore, or generated storage files",
    }
    existing = next((index for index, item in enumerate(data["cleanup_requests"]) if item["id"] == row["id"]), None)
    if existing is None:
        data["cleanup_requests"].append(row)
    else:
        row["created_at"] = data["cleanup_requests"][existing].get("created_at") or now
        data["cleanup_requests"][existing] = row
    _write_registry(root, data)
    return {"cleanup_request": row, "mutation_performed": True, "host_mutation_performed": False}


def approve_backup_cleanup_request_status(
    project_root: str | Path,
    request_id: str,
    approved_by: str = "kira",
    approved_at: str | None = None,
) -> dict[str, object]:
    if not approved_by.strip():
        raise ValueError("approved_by is required")
    root = Path(project_root)
    data = _read_registry(root)
    row = _find_cleanup_request(data, request_id)
    if row.get("status") not in {"waiting_approval", "approved"}:
        raise ValueError(f"cleanup request is not approvable: {row.get('status')}")
    now = approved_at or _now()
    row.update(
        {
            "status": "approved",
            "approved_by": approved_by,
            "approved_at": now,
            "updated_at": now,
            "next_step": "execute approved backup cleanup after final path and manifest validation",
        }
    )
    _write_registry(root, data)
    return {"cleanup_request": row, "mutation_performed": True, "host_mutation_performed": False}


def execute_backup_cleanup_request_status(
    project_root: str | Path,
    request_id: str,
    executed_by: str = "kira",
    executed_at: str | None = None,
) -> dict[str, object]:
    if not executed_by.strip():
        raise ValueError("executed_by is required")
    root = Path(project_root)
    data = _read_registry(root)
    row = _find_cleanup_request(data, request_id)
    now = executed_at or _now()
    try:
        _validate_cleanup_request_ready(row)
        target = _cleanup_target(root, str(row.get("path") or ""))
        manifest = _cleanup_manifest(root, target, request_id, now)
        _delete_cleanup_target(target)
    except ValueError as error:
        row.update(
            {
                "status": "blocked",
                "executed_by": executed_by,
                "executed_at": now,
                "updated_at": now,
                "execution_error": str(error),
                "next_step": "review blocked cleanup request and stage a corrected project-relative cleanup path",
            }
        )
        _write_registry(root, data)
        return {
            "cleanup_request": row,
            "status": "blocked",
            "summary": str(error),
            "mutation_performed": True,
            "host_mutation_performed": False,
        }
    except OSError as error:
        row.update(
            {
                "status": "failed",
                "executed_by": executed_by,
                "executed_at": now,
                "updated_at": now,
                "execution_error": str(error),
                "next_step": "inspect partial cleanup state and retry only after Kira verifies storage safety",
            }
        )
        _write_registry(root, data)
        return {
            "cleanup_request": row,
            "status": "failed",
            "summary": str(error),
            "mutation_performed": True,
            "host_mutation_performed": True,
        }

    row.update(
        {
            "status": "completed",
            "executed_by": executed_by,
            "executed_at": now,
            "updated_at": now,
            "manifest_path": manifest["manifest_path"],
            "deleted_entries": manifest["entry_count"],
            "deleted_bytes": manifest["total_bytes"],
            "next_step": "cleanup completed; continue monitoring backup and restore evidence",
        }
    )
    _write_registry(root, data)
    return {
        "cleanup_request": row,
        "status": "completed",
        "manifest": manifest,
        "mutation_performed": True,
        "host_mutation_performed": True,
    }


def _registry_path(root: Path) -> Path:
    return root / "state" / "backup-operations.json"


def _read_registry(root: Path) -> dict[str, list[dict[str, object]]]:
    path = _registry_path(root)
    if not path.exists():
        return _empty_registry()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _empty_registry()
    return {
        "jobs": list(data.get("jobs") or []),
        "restore_tests": list(data.get("restore_tests") or []),
        "backup_requests": list(data.get("backup_requests") or []),
        "restore_requests": list(data.get("restore_requests") or []),
        "cleanup_requests": list(data.get("cleanup_requests") or []),
    }


def _empty_registry() -> dict[str, list[dict[str, object]]]:
    return {"jobs": [], "restore_tests": [], "backup_requests": [], "restore_requests": [], "cleanup_requests": []}


def _provider_target_rows(root: Path, local_profiles: list[dict[str, object]]) -> list[dict[str, object]]:
    mediastore_profile = next((row for row in local_profiles if row.get("id") == "backup-profile.nas.mediastore"), {})
    mediastore_credential_ready = mediastore_profile.get("credential_status") == "present" and mediastore_profile.get("credential_mode") == "owner_only"
    mediastore_mounted = bool(mediastore_profile.get("mounted"))
    mediastore_status = "mounted_pending_restore_test" if mediastore_mounted else "credentials_configured_pending_mount"
    if not mediastore_credential_ready:
        mediastore_status = "planned_local_nas"
    return [
        {
            "id": "backup-target.nas.mediastore",
            "name": "MediaStore",
            "target": MEDIASTORE_SHARE,
            "provider_class": "network_nas",
            "protocols": "SMB/CIFS, NFS capable",
            "tooling": "restic, borg, rclone, rsync",
            "role": "first remote backup target",
            "status": mediastore_status,
            "connection_status": str(mediastore_profile.get("connection_status") or "not_checked"),
            "credential_status": str(mediastore_profile.get("credential_status") or "missing"),
            "credential_reference": str(MEDIASTORE_CREDENTIAL_PATH),
            "mount_path": str(MEDIASTORE_MOUNT_PATH),
            "execution_available": False,
            "future_work": False,
            "next_step": _mediastore_target_next_step(mediastore_profile),
        },
        {
            "id": "backup-target.cloud.object-storage",
            "name": "Object Storage",
            "target": "s3-compatible://future-overseer-backups",
            "provider_class": "cloud_object_storage",
            "protocols": "S3 API, Backblaze B2, Azure Blob, Google Cloud Storage",
            "tooling": "restic, rclone, cloud lifecycle policies, object lock where available",
            "role": "future offsite cloud backup",
            "status": "future_unavailable",
            "connection_status": "not_configured",
            "execution_available": False,
            "future_work": True,
            "next_step": "select provider, credentials, bucket policy, encryption, retention, and egress budget before implementation",
        },
        {
            "id": "backup-target.clone.full-system",
            "name": "Full Clone",
            "target": "clone://future-full-system-image",
            "provider_class": "full_clone",
            "protocols": "ZFS/Btrfs snapshots, LVM snapshots, rsync, Clonezilla-style image export",
            "tooling": "zfs send/receive, btrfs send/receive, rsync, qemu-img, disk image manifests",
            "role": "future full cloning and bare-metal recovery",
            "status": "future_unavailable",
            "connection_status": "not_configured",
            "execution_available": False,
            "future_work": True,
            "next_step": "inventory filesystems, boot mode, exclusion policy, quiesce plan, and restore host before implementation",
        },
        {
            "id": "backup-target.failover.hosted-instance",
            "name": "Hosted Failover",
            "target": "failover://future-hosted-instance",
            "provider_class": "hosted_failover",
            "protocols": "cloud-init, Terraform/OpenTofu, Packer, container registry, DNS cutover",
            "tooling": "infrastructure-as-code, image promotion, health probes, runbook automation",
            "role": "future offsite hosted failover instance",
            "status": "future_unavailable",
            "connection_status": "not_configured",
            "execution_available": False,
            "future_work": True,
            "next_step": "define provider, recovery point objective, recovery time objective, DNS, secrets bootstrap, and failover test window",
        },
    ]


def _provider_class_rows() -> list[dict[str, object]]:
    return [
        {
            "provider_class": "network_nas",
            "standard_options": "SMB/CIFS, NFS, restic repository, borg repository, rsync mirror",
            "current_target": "//MediaStore/Overseer",
            "status": "planned_first",
            "test_status": "not_connected",
        },
        {
            "provider_class": "cloud_object_storage",
            "standard_options": "S3-compatible, Backblaze B2, Azure Blob, Google Cloud Storage",
            "current_target": "future",
            "status": "future_work",
            "test_status": "no_service_available",
        },
        {
            "provider_class": "full_clone",
            "standard_options": "ZFS/Btrfs send, LVM snapshot, rsync image, qemu-img conversion",
            "current_target": "future",
            "status": "future_work",
            "test_status": "no_service_available",
        },
        {
            "provider_class": "hosted_failover",
            "standard_options": "VM image promotion, IaC redeploy, containerized service restore, DNS cutover",
            "current_target": "future",
            "status": "future_work",
            "test_status": "no_service_available",
        },
    ]


def _provider_readiness_row(target: dict[str, object]) -> dict[str, object]:
    blockers = []
    if target.get("connection_status") != "ready":
        blockers.append("connection not mounted and tested")
    if target.get("credential_status") == "missing":
        blockers.append("credentials not configured")
    if target.get("credential_status") == "present" and target.get("provider_class") == "network_nas":
        blockers.append("live mount approval and connectivity test pending")
    if target.get("future_work"):
        blockers.append("provider/service unavailable for testing")
    if target.get("provider_class") == "network_nas":
        blockers.append("retention, encryption, and restore test are not finalized")
    return {
        "id": target["id"],
        "name": target["name"],
        "provider_class": target["provider_class"],
        "target": target["target"],
        "role": target["role"],
        "status": target["status"],
        "connection_status": target["connection_status"],
        "credential_status": target.get("credential_status", "not_applicable"),
        "credential_reference": target.get("credential_reference", ""),
        "mount_path": target.get("mount_path", ""),
        "execution_available": False,
        "can_stage": True,
        "can_execute": False,
        "blockers": "; ".join(blockers),
        "next_step": target["next_step"],
    }


def _local_provider_profiles(root: Path) -> list[dict[str, object]]:
    return [_mediastore_local_profile(root)]


def _mediastore_local_profile(root: Path) -> dict[str, object]:
    credential_path = root / MEDIASTORE_CREDENTIAL_PATH
    mount_path = root / MEDIASTORE_MOUNT_PATH
    credential_status = "missing"
    username_status = "missing"
    credential_mode = "missing"
    if credential_path.exists():
        credential_status = "present"
        username_status = "configured" if _credential_key_present(credential_path, "username") else "missing"
        credential_mode = _credential_file_mode_status(credential_path)
    mounted = mount_path.exists() and mount_path.is_mount()
    connection_status = "ready" if mounted else "credentials_configured"
    if credential_status == "missing" or username_status == "missing":
        connection_status = "not_configured"
    return {
        "id": "backup-profile.nas.mediastore",
        "name": "MediaStore",
        "provider_class": "network_nas",
        "share": MEDIASTORE_SHARE,
        "credential_reference": str(MEDIASTORE_CREDENTIAL_PATH),
        "credential_status": credential_status,
        "credential_mode": credential_mode,
        "username_status": username_status,
        "mount_path": str(MEDIASTORE_MOUNT_PATH),
        "mounted": mounted,
        "connection_status": connection_status,
        "mutation_performed": False,
        "host_mutation_performed": False,
        "next_step": _mediastore_profile_next_step(credential_status, credential_mode, mounted),
    }


def _mediastore_target_next_step(profile: dict[str, object]) -> str:
    if profile.get("credential_status") != "present":
        return "create ignored MediaStore credential file before staging NAS mount approval"
    if profile.get("credential_mode") != "owner_only":
        return "restrict MediaStore credential file to owner-only permissions before use"
    if not profile.get("mounted"):
        return "stage Sisko/Kira approval for SMB/CIFS mount test at the configured local mount path"
    return "stage disposable restore test and retention/encryption policy before enabling scheduled NAS backups"


def _mediastore_profile_next_step(credential_status: str, credential_mode: str, mounted: bool) -> str:
    if credential_status != "present":
        return "store credentials only in ignored local-secrets before connection testing"
    if credential_mode != "owner_only":
        return "fix credential file permissions before any mount or backup attempt"
    if not mounted:
        return "mount/connectivity test requires explicit live system-change approval"
    return "record restore-test evidence before marking MediaStore execution-ready"


def _credential_key_present(path: Path, key: str) -> bool:
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            name, separator, value = line.partition("=")
            if separator and name.strip() == key and value.strip():
                return True
    except OSError:
        return False
    return False


def _credential_file_mode_status(path: Path) -> str:
    try:
        mode = path.stat().st_mode & 0o777
    except OSError:
        return "unreadable"
    return "owner_only" if mode & 0o077 == 0 else "too_open"


def _write_registry(root: Path, data: dict[str, object]) -> None:
    path = _registry_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _find_cleanup_request(data: dict[str, list[dict[str, object]]], request_id: str) -> dict[str, object]:
    cleaned = _safe_id(request_id.removeprefix("backup-cleanup."))
    candidates = {request_id, f"backup-cleanup.{cleaned}"}
    for row in data["cleanup_requests"]:
        if row.get("id") in candidates:
            return row
    raise ValueError(f"backup cleanup request does not exist: {request_id}")


def _find_request(rows: list[dict[str, object]], request_id: str, prefix: str) -> dict[str, object]:
    cleaned = _safe_id(request_id.removeprefix(f"{prefix}."))
    candidates = {request_id, f"{prefix}.{cleaned}"}
    for row in rows:
        if row.get("id") in candidates:
            return row
    raise ValueError(f"{prefix} request does not exist: {request_id}")


def _upsert(rows: list[dict[str, object]], row: dict[str, object]) -> None:
    existing = next((index for index, item in enumerate(rows) if item["id"] == row["id"]), None)
    if existing is None:
        rows.append(row)
        return
    row["created_at"] = rows[existing].get("created_at") or row["created_at"]
    rows[existing] = row


def _validate_cleanup_request_ready(row: dict[str, object]) -> None:
    _validate_approved_request(row, "backup cleanup request")


def _validate_approved_request(row: dict[str, object], label: str) -> None:
    if row.get("status") != "approved":
        raise ValueError(f"{label} must be approved before execution")
    if not row.get("approved_by"):
        raise ValueError(f"{label} approval metadata is missing")


def _backup_source(root: Path, raw_path: str) -> Path:
    return _safe_existing_project_path(root, raw_path, {"state", "docs", "assets", "src", "tests", "artifacts", "backups"}, "backup source")


def _backup_destination(root: Path, backup_name: str, created_at: str) -> Path:
    return root / "backups" / "overseer-managed" / f"{_safe_id(backup_name)}-{_safe_id(created_at)}"


def _restore_source(root: Path, raw_path: str) -> Path:
    return _safe_existing_project_path(root, raw_path, {"backups"}, "restore source")


def _restore_target(root: Path, raw_path: str) -> Path:
    if not raw_path.strip():
        raise ValueError("restore target is required")
    target = _safe_project_path(root, raw_path, {"artifacts", "backups"}, "restore target")
    if target.exists():
        raise ValueError("restore target already exists")
    return target


def _safe_existing_project_path(root: Path, raw_path: str, allowed_roots: set[str], label: str) -> Path:
    target = _safe_project_path(root, raw_path, allowed_roots, label)
    if not target.exists():
        raise ValueError(f"{label} does not exist")
    return target


def _safe_project_path(root: Path, raw_path: str, allowed_roots: set[str], label: str) -> Path:
    if not raw_path.strip():
        raise ValueError(f"{label} path is required")
    candidate = Path(raw_path)
    if candidate.is_absolute() or "~" in candidate.parts or ".." in candidate.parts:
        raise ValueError(f"{label} path must be project-relative and cannot include parent traversal")
    if not candidate.parts:
        raise ValueError(f"{label} path is required")
    if candidate.parts[0] not in allowed_roots:
        raise ValueError(f"{label} is limited to {', '.join(sorted(allowed_roots))} paths")
    target = (root / candidate).resolve()
    root_resolved = root.resolve()
    if target == root_resolved or root_resolved not in target.parents:
        raise ValueError(f"{label} must stay inside the project root")
    blocked_parts = {".git", ".codex", ".agents", "local-secrets", "secrets", "credentials", "exports", "node_modules", "__pycache__"}
    if blocked_parts.intersection(candidate.parts):
        raise ValueError(f"{label} cannot include local-only, secret, VCS, dependency, or cache paths")
    return target


def _copy_with_manifest(root: Path, source: Path, destination: Path, request_id: str, operation: str, created_at: str) -> dict[str, object]:
    if destination.exists():
        raise ValueError(f"{operation} destination already exists")
    entries = _path_manifest(root, source)
    if source.is_dir():
        shutil.copytree(source, destination, ignore=_copy_ignore)
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    manifest = {
        "request_id": request_id,
        "operation": operation,
        "created_at": created_at,
        "source": _relative_or_name(root, source),
        "destination": _relative_or_name(root, destination),
        "entry_count": len(entries),
        "total_bytes": sum(int(entry["bytes"]) for entry in entries),
        "entries": entries,
    }
    manifest_dir = root / "local-secrets" / "backup-execution-manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = manifest_dir / f"{_safe_id(operation)}-{_safe_id(request_id)}-{_safe_id(created_at)}.json"
    manifest["manifest_path"] = _relative_or_name(root, manifest_path)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def _copy_ignore(directory: str, names: list[str]) -> set[str]:
    blocked = {".git", ".codex", ".agents", "local-secrets", "secrets", "credentials", "exports", "node_modules", "__pycache__"}
    return {name for name in names if name in blocked}


def _path_manifest(root: Path, target: Path) -> list[dict[str, object]]:
    entries = []
    paths = [target, *sorted(target.rglob("*"))] if target.is_dir() else [target]
    for path in paths:
        if any(part in {".git", ".codex", ".agents", "local-secrets", "secrets", "credentials", "exports", "node_modules", "__pycache__"} for part in path.relative_to(root).parts if root in path.parents):
            continue
        try:
            stat = path.stat()
        except OSError:
            continue
        size = 0 if path.is_dir() else stat.st_size
        row = {
            "path": _relative_or_name(root, path),
            "kind": "directory" if path.is_dir() else "file",
            "bytes": size,
        }
        if path.is_file():
            row["sha256"] = _sha256(path)
        entries.append(row)
    return entries


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _blocked_fields(executed_by: str, executed_at: str, error: str, next_step: str) -> dict[str, object]:
    return {"status": "blocked", "executed_by": executed_by, "executed_at": executed_at, "updated_at": executed_at, "execution_error": error, "next_step": next_step}


def _failed_fields(executed_by: str, executed_at: str, error: str, next_step: str) -> dict[str, object]:
    return {"status": "failed", "executed_by": executed_by, "executed_at": executed_at, "updated_at": executed_at, "execution_error": error, "next_step": next_step}


def _cleanup_target(root: Path, raw_path: str) -> Path:
    if not raw_path.strip():
        raise ValueError("cleanup path is required")
    candidate = Path(raw_path)
    if candidate.is_absolute() or "~" in candidate.parts or ".." in candidate.parts:
        raise ValueError("cleanup path must be project-relative and cannot include parent traversal")
    if candidate.parts[0] not in {"artifacts", "backups"}:
        raise ValueError("cleanup execution is limited to project artifacts/ and backups/ paths")
    target = (root / candidate).resolve()
    root_resolved = root.resolve()
    if target == root_resolved or root_resolved not in target.parents:
        raise ValueError("cleanup target must stay inside the project root")
    if not target.exists():
        raise ValueError("cleanup target does not exist")
    return target


def _cleanup_manifest(root: Path, target: Path, request_id: str, created_at: str) -> dict[str, object]:
    entries = []
    total_bytes = 0
    paths = [target, *sorted(target.rglob("*"))] if target.is_dir() else [target]
    for path in paths:
        try:
            stat = path.stat()
        except OSError:
            continue
        size = 0 if path.is_dir() else stat.st_size
        total_bytes += size
        entries.append(
            {
                "path": _relative_or_name(root, path),
                "kind": "directory" if path.is_dir() else "file",
                "bytes": size,
            }
        )
    manifest = {
        "request_id": request_id,
        "created_at": created_at,
        "target": _relative_or_name(root, target),
        "entry_count": len(entries),
        "total_bytes": total_bytes,
        "entries": entries,
    }
    manifest_dir = root / "local-secrets" / "backup-cleanup-manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = manifest_dir / f"{_safe_id(request_id)}-{_safe_id(created_at)}.json"
    manifest["manifest_path"] = _relative_or_name(root, manifest_path)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def _delete_cleanup_target(target: Path) -> None:
    if target.is_dir():
        shutil.rmtree(target)
    else:
        target.unlink()


def _safe_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value).strip()).strip("-")
    return cleaned or "item"


def _redact_path(value: str) -> str:
    if not value:
        return ""
    path = Path(value)
    if str(value).startswith("/"):
        return f".../{path.name}" if path.name else "local-path"
    return str(value)


def _relative_or_name(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
