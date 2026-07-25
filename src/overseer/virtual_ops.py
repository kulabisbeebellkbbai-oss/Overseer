"""Staged virtual runtime, snapshot, and restore records for Dax."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path


def virtual_operations_status(project_root: str | Path) -> dict[str, object]:
    root = Path(project_root)
    data = _read_registry(root)
    return {
        "root": str(root),
        "runtime_records": data["runtime_records"],
        "runtime_record_count": len(data["runtime_records"]),
        "snapshot_requests": data["snapshot_requests"],
        "snapshot_request_count": len(data["snapshot_requests"]),
        "restore_requests": data["restore_requests"],
        "restore_request_count": len(data["restore_requests"]),
        "execution_records": data["execution_records"],
        "execution_record_count": len(data["execution_records"]),
        "target_setup_requests": data["target_setup_requests"],
        "target_setup_request_count": len(data["target_setup_requests"]),
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def record_virtual_runtime_status(
    project_root: str | Path,
    resource_id: str,
    kind: str = "vm",
    state: str = "observed",
    adapter: str = "manual",
    ports: tuple[int, ...] | list[int] | None = None,
    snapshot_hint: str = "",
    notes: str = "",
) -> dict[str, object]:
    root = Path(project_root)
    data = _read_registry(root)
    now = _now()
    row = {
        "resource_id": _safe_id(resource_id),
        "kind": kind,
        "state": state,
        "adapter": adapter,
        "ports": sorted(int(port) for port in (ports or ())),
        "snapshot_hint": _redact_path(snapshot_hint),
        "notes": notes,
        "updated_at": now,
        "next_step": "request checkout or stage snapshot/restore plan before mutating this virtual asset",
    }
    existing = next((index for index, item in enumerate(data["runtime_records"]) if item["resource_id"] == row["resource_id"]), None)
    if existing is None:
        row["created_at"] = now
        data["runtime_records"].append(row)
    else:
        row["created_at"] = data["runtime_records"][existing].get("created_at") or now
        data["runtime_records"][existing] = row
    _write_registry(root, data)
    return {"runtime_record": row, "mutation_performed": True, "host_mutation_performed": False}


def stage_virtual_snapshot_request_status(
    project_root: str | Path,
    resource_id: str,
    requested_by: str = "dax",
    reason: str = "stage virtual snapshot before maintenance",
    snapshot_name: str = "",
) -> dict[str, object]:
    root = Path(project_root)
    data = _read_registry(root)
    now = _now()
    row = {
        "id": f"virtual-snapshot.{_safe_id(resource_id)}",
        "resource_id": _safe_id(resource_id),
        "snapshot_name": _safe_id(snapshot_name) if snapshot_name else "",
        "requested_by": requested_by,
        "reason": reason,
        "status": "waiting_approval",
        "approval_required": True,
        "created_at": now,
        "updated_at": now,
        "guardrails": [
            "verify checkout claim before touching runtime state",
            "capture rollback target before destructive maintenance",
            "do not start, stop, pause, snapshot, restore, or delete without an approved live adapter plan",
        ],
        "next_step": "human approval required before invoking VM, container, emulator, gateway, or proxy snapshot adapters",
    }
    _upsert(data["snapshot_requests"], row)
    _write_registry(root, data)
    return {"snapshot_request": row, "mutation_performed": True, "host_mutation_performed": False}


def stage_virtual_restore_request_status(
    project_root: str | Path,
    resource_id: str,
    restore_point: str,
    requested_by: str = "dax",
    reason: str = "stage virtual restore after failed change",
) -> dict[str, object]:
    root = Path(project_root)
    data = _read_registry(root)
    now = _now()
    row = {
        "id": f"virtual-restore.{_safe_id(resource_id)}",
        "resource_id": _safe_id(resource_id),
        "restore_point": _redact_path(restore_point),
        "requested_by": requested_by,
        "reason": reason,
        "status": "waiting_approval",
        "approval_required": True,
        "created_at": now,
        "updated_at": now,
        "guardrails": [
            "confirm active users and claims before restore",
            "preserve failed-state evidence before rollback",
            "do not start, stop, pause, snapshot, restore, or delete without an approved live adapter plan",
        ],
        "next_step": "human approval required before invoking VM, container, emulator, gateway, or proxy restore adapters",
    }
    _upsert(data["restore_requests"], row)
    _write_registry(root, data)
    return {"restore_request": row, "mutation_performed": True, "host_mutation_performed": False}


def stage_virtual_target_setup_batch_status(
    project_root: str | Path,
    requested_by: str = "dax",
    scope: str = "all",
    reason: str = "prepare approved disposable real-provider targets for Dax lifecycle development",
) -> dict[str, object]:
    root = Path(project_root)
    data = _read_registry(root)
    now = _now()
    selected = _target_setup_templates(scope)
    rows = []
    for template in selected:
        row = {
            **template,
            "id": f"virtual-target-setup.{template['provider']}",
            "requested_by": requested_by,
            "reason": reason,
            "status": "waiting_human_approval",
            "approval_required": True,
            "created_at": now,
            "updated_at": now,
            "next_step": "human approval required before creating or changing this live provider target",
        }
        _upsert(data["target_setup_requests"], row)
        rows.append(row)
    _write_registry(root, data)
    return {
        "target_setup_requests": rows,
        "target_setup_request_count": len(rows),
        "approval_required": True,
        "mutation_performed": True,
        "host_mutation_performed": False,
    }


def record_virtual_target_setup_result_status(
    project_root: str | Path,
    provider: str,
    status: str,
    executed_by: str = "dax",
    evidence: str = "",
    next_step: str = "",
    executed_at: str | None = None,
) -> dict[str, object]:
    """Record the outcome of an approved provider target setup.

    This records evidence only. The caller is responsible for any already
    approved host mutation and for supplying redacted evidence.
    """
    cleaned_provider = _safe_id(provider).replace("-", "_")
    cleaned_status = _safe_id(status).replace("-", "_")
    if cleaned_status not in {"completed", "blocked", "failed", "partial"}:
        raise ValueError("virtual target setup status must be completed, blocked, failed, or partial")
    root = Path(project_root)
    data = _read_registry(root)
    now = executed_at or _now()
    request_id = f"virtual-target-setup.{cleaned_provider}"
    row = next((item for item in data["target_setup_requests"] if item.get("id") == request_id), None)
    if row is None:
        templates = [item for item in _all_target_setup_templates() if item["provider"] == cleaned_provider]
        if not templates:
            raise ValueError(f"virtual target setup request does not exist: {provider}")
        row = {
            **templates[0],
            "id": request_id,
            "requested_by": executed_by,
            "reason": "record externally approved provider target setup result",
            "created_at": now,
        }
        data["target_setup_requests"].append(row)
    row.update(
        {
            "status": cleaned_status,
            "approval_required": False if cleaned_status == "completed" else True,
            "executed_by": executed_by,
            "executed_at": now,
            "updated_at": now,
            "evidence": evidence,
            "next_step": next_step
            or (
                "target is ready for Dax checkout and provider lifecycle testing"
                if cleaned_status == "completed"
                else "resolve setup blocker before Dax uses this provider target"
            ),
        }
    )
    data["execution_records"].append(
        {
            "id": f"virtual-execution.{request_id}.{_safe_id(now)}",
            "request_id": request_id,
            "resource_id": str(row.get("target_name") or request_id),
            "action": "target_setup",
            "status": cleaned_status,
            "provider": cleaned_provider,
            "executed_by": executed_by,
            "executed_at": now,
            "manifest_path": "",
            "error": "" if cleaned_status == "completed" else evidence,
        }
    )
    _write_registry(root, data)
    return {
        "target_setup_request": row,
        "status": cleaned_status,
        "mutation_performed": True,
        "host_mutation_performed": False,
    }


def approve_virtual_snapshot_request_status(
    project_root: str | Path,
    request_id: str,
    approved_by: str = "sisko",
    approved_at: str | None = None,
) -> dict[str, object]:
    if not approved_by.strip():
        raise ValueError("approved_by is required")
    root = Path(project_root)
    data = _read_registry(root)
    row = _find_request(data, "snapshot_requests", request_id, "virtual-snapshot")
    if row.get("status") not in {"waiting_approval", "approved"}:
        raise ValueError(f"snapshot request is not approvable: {row.get('status')}")
    now = approved_at or _now()
    row.update(
        {
            "status": "approved",
            "approved_by": approved_by,
            "approved_at": now,
            "updated_at": now,
            "next_step": "execute approved virtual snapshot after checkout, provider, and target validation",
        }
    )
    _write_registry(root, data)
    return {"snapshot_request": row, "mutation_performed": True, "host_mutation_performed": False}


def approve_virtual_restore_request_status(
    project_root: str | Path,
    request_id: str,
    approved_by: str = "sisko",
    approved_at: str | None = None,
) -> dict[str, object]:
    if not approved_by.strip():
        raise ValueError("approved_by is required")
    root = Path(project_root)
    data = _read_registry(root)
    row = _find_request(data, "restore_requests", request_id, "virtual-restore")
    if row.get("status") not in {"waiting_approval", "approved"}:
        raise ValueError(f"restore request is not approvable: {row.get('status')}")
    now = approved_at or _now()
    row.update(
        {
            "status": "approved",
            "approved_by": approved_by,
            "approved_at": now,
            "updated_at": now,
            "next_step": "execute approved virtual restore after checkout, evidence-preservation, provider, and target validation",
        }
    )
    _write_registry(root, data)
    return {"restore_request": row, "mutation_performed": True, "host_mutation_performed": False}


def execute_virtual_snapshot_request_status(
    project_root: str | Path,
    request_id: str,
    executed_by: str = "dax",
    provider: str = "local_fixture",
    executed_at: str | None = None,
) -> dict[str, object]:
    if not executed_by.strip():
        raise ValueError("executed_by is required")
    root = Path(project_root)
    data = _read_registry(root)
    row = _find_request(data, "snapshot_requests", request_id, "virtual-snapshot")
    now = executed_at or _now()
    try:
        _validate_request_ready(row, "snapshot")
        runtime = _find_runtime_record(data, str(row.get("resource_id") or ""))
        manifest = _execute_snapshot(root, row, runtime, provider, now)
    except ValueError as error:
        return _record_blocked_execution(root, data, row, "snapshot", request_id, executed_by, now, str(error))
    except OSError as error:
        return _record_failed_execution(root, data, row, "snapshot", request_id, executed_by, now, str(error))
    row.update(
        {
            "status": "completed",
            "executed_by": executed_by,
            "executed_at": now,
            "updated_at": now,
            "manifest_path": manifest["manifest_path"],
            "next_step": "snapshot completed; use this restore point for rollback if later runtime work fails",
        }
    )
    _append_execution(data, row, "snapshot", request_id, executed_by, now, "completed", provider, manifest=manifest)
    _write_registry(root, data)
    return {
        "snapshot_request": row,
        "status": "completed",
        "manifest": manifest,
        "mutation_performed": True,
        "host_mutation_performed": provider != "local_fixture",
    }


def execute_virtual_restore_request_status(
    project_root: str | Path,
    request_id: str,
    executed_by: str = "dax",
    provider: str = "local_fixture",
    executed_at: str | None = None,
) -> dict[str, object]:
    if not executed_by.strip():
        raise ValueError("executed_by is required")
    root = Path(project_root)
    data = _read_registry(root)
    row = _find_request(data, "restore_requests", request_id, "virtual-restore")
    now = executed_at or _now()
    try:
        _validate_request_ready(row, "restore")
        runtime = _find_runtime_record(data, str(row.get("resource_id") or ""))
        manifest = _execute_restore(root, row, runtime, provider, now)
    except ValueError as error:
        return _record_blocked_execution(root, data, row, "restore", request_id, executed_by, now, str(error))
    except OSError as error:
        return _record_failed_execution(root, data, row, "restore", request_id, executed_by, now, str(error))
    row.update(
        {
            "status": "completed",
            "executed_by": executed_by,
            "executed_at": now,
            "updated_at": now,
            "manifest_path": manifest["manifest_path"],
            "next_step": "restore completed; run Julian health validation before returning the runtime to service",
        }
    )
    _append_execution(data, row, "restore", request_id, executed_by, now, "completed", provider, manifest=manifest)
    _write_registry(root, data)
    return {
        "restore_request": row,
        "status": "completed",
        "manifest": manifest,
        "mutation_performed": True,
        "host_mutation_performed": provider != "local_fixture",
    }


def execute_virtual_lifecycle_status(
    project_root: str | Path,
    resource_id: str,
    action: str,
    executed_by: str = "dax",
    provider: str = "",
    executed_at: str | None = None,
) -> dict[str, object]:
    if not executed_by.strip():
        raise ValueError("executed_by is required")
    cleaned_action = _safe_id(action).replace("-", "_")
    if cleaned_action not in {"inspect", "start", "stop"}:
        raise ValueError("virtual lifecycle action must be inspect, start, or stop")
    root = Path(project_root)
    data = _read_registry(root)
    runtime = _find_runtime_record(data, resource_id)
    runtime_provider = provider or str(runtime.get("adapter") or "")
    now = executed_at or _now()
    request_id = f"virtual-lifecycle.{_safe_id(str(runtime['resource_id']))}.{cleaned_action}"
    try:
        _validate_lifecycle_runtime(root, runtime, runtime_provider)
        result = _execute_lifecycle_provider(root, runtime, runtime_provider, cleaned_action)
        runtime.update(
            {
                "state": result["state"],
                "updated_at": now,
                "last_lifecycle_action": cleaned_action,
                "last_lifecycle_at": now,
                "next_step": result["next_step"],
            }
        )
        manifest = _write_lifecycle_manifest(root, runtime, cleaned_action, runtime_provider, result, now)
    except ValueError as error:
        row = {"id": request_id, "resource_id": _safe_id(resource_id)}
        _append_execution(data, row, f"lifecycle_{cleaned_action}", request_id, executed_by, now, "blocked", runtime_provider, error=str(error))
        _write_registry(root, data)
        return {
            "status": "blocked",
            "summary": str(error),
            "runtime_record": runtime,
            "mutation_performed": True,
            "host_mutation_performed": False,
        }
    except OSError as error:
        row = {"id": request_id, "resource_id": _safe_id(resource_id)}
        _append_execution(data, row, f"lifecycle_{cleaned_action}", request_id, executed_by, now, "failed", runtime_provider, error=str(error))
        _write_registry(root, data)
        return {
            "status": "failed",
            "summary": str(error),
            "runtime_record": runtime,
            "mutation_performed": True,
            "host_mutation_performed": cleaned_action != "inspect",
        }
    row = {"id": request_id, "resource_id": runtime["resource_id"]}
    _append_execution(data, row, f"lifecycle_{cleaned_action}", request_id, executed_by, now, "completed", runtime_provider, manifest=manifest)
    _write_registry(root, data)
    return {
        "status": "completed",
        "runtime_record": runtime,
        "manifest": manifest,
        "provider_result": result,
        "mutation_performed": True,
        "host_mutation_performed": cleaned_action != "inspect",
    }


def _registry_path(root: Path) -> Path:
    return root / "state" / "virtual-operations.json"


def _read_registry(root: Path) -> dict[str, list[dict[str, object]]]:
    path = _registry_path(root)
    if not path.exists():
        return {"runtime_records": [], "snapshot_requests": [], "restore_requests": [], "execution_records": [], "target_setup_requests": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"runtime_records": [], "snapshot_requests": [], "restore_requests": [], "execution_records": [], "target_setup_requests": []}
    return {
        "runtime_records": list(data.get("runtime_records") or []),
        "snapshot_requests": list(data.get("snapshot_requests") or []),
        "restore_requests": list(data.get("restore_requests") or []),
        "execution_records": list(data.get("execution_records") or []),
        "target_setup_requests": list(data.get("target_setup_requests") or []),
    }


def _write_registry(root: Path, data: dict[str, object]) -> None:
    path = _registry_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _upsert(rows: list[dict[str, object]], row: dict[str, object]) -> None:
    existing = next((index for index, item in enumerate(rows) if item["id"] == row["id"]), None)
    if existing is None:
        rows.append(row)
        return
    row["created_at"] = rows[existing].get("created_at") or row["created_at"]
    rows[existing] = row


def _target_setup_templates(scope: str) -> list[dict[str, object]]:
    templates = _all_target_setup_templates()
    cleaned = _safe_id(scope).replace("-", "_")
    if cleaned in {"all", "targets", "batch"}:
        return templates
    selected = [item for item in templates if item["provider"] == cleaned]
    if not selected:
        raise ValueError(f"unknown virtual target setup scope: {scope}")
    return selected


def _all_target_setup_templates() -> list[dict[str, object]]:
    return [
        {
            "provider": "docker",
            "target_name": "overseer-dax-disposable-docker",
            "current_state": "docker CLI is present but the current user cannot access /var/run/docker.sock",
            "proposed_state": "current user can run read-only and disposable-container Docker lifecycle commands; a disposable Overseer container exists",
            "required_changes": [
                "grant current user Docker daemon access or provide an approved sudo-wrapper path",
                "create disposable container/image target named overseer-dax-disposable-docker",
            ],
            "proposed_commands": [
                "sudo usermod -aG docker god",
                "newgrp docker or restart the user session before Docker commands are expected to work",
                "docker create --name overseer-dax-disposable-docker alpine:latest sleep 3600",
            ],
            "risks": [
                "docker group membership is root-equivalent on this host",
                "container networking and mounts can expose host resources if not constrained",
            ],
            "rollback_plan": [
                "docker rm -f overseer-dax-disposable-docker",
                "sudo gpasswd -d god docker if Docker group access should be removed",
            ],
        },
        {
            "provider": "podman",
            "target_name": "overseer-dax-disposable-podman",
            "current_state": "podman CLI is not available",
            "proposed_state": "Podman is installed and a rootless disposable container target exists",
            "required_changes": [
                "install Podman packages",
                "create rootless disposable container named overseer-dax-disposable-podman",
            ],
            "proposed_commands": [
                "sudo apt-get install -y podman",
                "podman create --name overseer-dax-disposable-podman docker.io/library/alpine:latest sleep 3600",
            ],
            "risks": [
                "package installation changes host software state",
                "rootless container storage consumes user disk space",
            ],
            "rollback_plan": [
                "podman rm -f overseer-dax-disposable-podman",
                "sudo apt-get remove -y podman if Podman is not wanted after testing",
            ],
        },
        {
            "provider": "libvirt",
            "target_name": "overseer-dax-disposable-libvirt",
            "current_state": "virsh is available and no disposable domain is currently declared",
            "proposed_state": "a stopped disposable libvirt domain exists for Dax start/stop/snapshot/restore testing",
            "required_changes": [
                "create disposable qcow2 disk image",
                "define a minimal libvirt domain named overseer-dax-disposable-libvirt",
            ],
            "proposed_commands": [
                "qemu-img create -f qcow2 local-secrets/virtual-runtime-targets/overseer-dax-disposable-libvirt.qcow2 1G",
                "virt-install or virsh define a minimal non-autostart domain using that image",
            ],
            "risks": [
                "a running VM consumes CPU, memory, disk, and possible network resources",
                "incorrect network selection can expose a test VM",
            ],
            "rollback_plan": [
                "virsh destroy overseer-dax-disposable-libvirt if running",
                "virsh undefine overseer-dax-disposable-libvirt --remove-all-storage where supported",
                "remove local-secrets/virtual-runtime-targets/overseer-dax-disposable-libvirt.qcow2",
            ],
        },
        {
            "provider": "qemu_process",
            "target_name": "overseer-dax-disposable-qemu-process",
            "current_state": "qemu-system binaries are available and no disposable qemu process is currently running",
            "proposed_state": "a Dax-owned qemu process target can be launched, monitored, and stopped",
            "required_changes": [
                "create disposable qcow2 image",
                "launch qemu with no external networking and a pidfile under local-secrets",
            ],
            "proposed_commands": [
                "qemu-img create -f qcow2 local-secrets/virtual-runtime-targets/overseer-dax-disposable-qemu-process.qcow2 64M",
                "qemu-system-x86_64 -display none -no-reboot -net none -pidfile local-secrets/virtual-runtime-targets/overseer-dax-disposable-qemu-process.pid -drive file=local-secrets/virtual-runtime-targets/overseer-dax-disposable-qemu-process.qcow2,format=qcow2",
            ],
            "risks": [
                "a qemu process consumes CPU and memory",
                "incorrect networking flags can expose a virtual network path",
            ],
            "rollback_plan": [
                "kill the pid in local-secrets/virtual-runtime-targets/overseer-dax-disposable-qemu-process.pid",
                "remove the disposable qcow2 and pidfile",
            ],
        },
        {
            "provider": "renode",
            "target_name": "overseer-dax-disposable-renode",
            "current_state": "Renode CLI is available and no disposable platform target is declared",
            "proposed_state": "a minimal Renode script exists and can be launched/stopped by Dax",
            "required_changes": [
                "create a minimal Renode platform/script under local-secrets",
                "define launch and stop evidence for the Renode process",
            ],
            "proposed_commands": [
                "write local-secrets/virtual-runtime-targets/overseer-dax-disposable-renode.resc",
                "renode --disable-xwt --console local-secrets/virtual-runtime-targets/overseer-dax-disposable-renode.resc",
            ],
            "risks": [
                "Renode process can hang if launched with an unsuitable console mode",
                "emulated peripherals may consume CPU unexpectedly",
            ],
            "rollback_plan": [
                "terminate the Renode process owned by the disposable target",
                "remove the disposable Renode script",
            ],
        },
        {
            "provider": "android_emulator",
            "target_name": "overseer-dax-disposable-avd",
            "current_state": "Android emulator CLI is not available in the current PATH",
            "proposed_state": "a disposable AVD exists for Dax emulator lifecycle testing",
            "required_changes": [
                "install or expose Android emulator tooling",
                "create a disposable AVD named overseer-dax-disposable-avd",
            ],
            "proposed_commands": [
                "sdkmanager 'emulator' 'platform-tools' '<approved system image>'",
                "avdmanager create avd -n overseer-dax-disposable-avd -k '<approved system image>'",
            ],
            "risks": [
                "Android system images are large downloads",
                "emulator networking and adb exposure need explicit containment",
            ],
            "rollback_plan": [
                "avdmanager delete avd -n overseer-dax-disposable-avd",
                "remove any downloaded system image only if no other project uses it",
            ],
        },
        {
            "provider": "gateway_proxy",
            "target_name": "overseer-dax-disposable-proxy",
            "current_state": "no disposable gateway/proxy target is declared",
            "proposed_state": "a loopback-only disposable proxy exists with a known port, upstream, config path, and health check",
            "required_changes": [
                "choose a loopback-only port",
                "create disposable proxy config under local-secrets",
                "define upstream and health check",
            ],
            "proposed_commands": [
                "start a loopback-only disposable proxy bound to 127.0.0.1 on an approved unused port",
                "record Dax resource, port claim, rollback, and Julian health check",
            ],
            "risks": [
                "wrong bind address can expose the proxy beyond loopback",
                "port conflicts can disrupt local services",
            ],
            "rollback_plan": [
                "stop the disposable proxy process",
                "remove disposable proxy config and release the Dax port claim",
            ],
        },
    ]


def _find_request(data: dict[str, list[dict[str, object]]], key: str, request_id: str, prefix: str) -> dict[str, object]:
    cleaned = _safe_id(request_id.removeprefix(f"{prefix}."))
    candidates = {request_id, f"{prefix}.{cleaned}"}
    for row in data[key]:
        if row.get("id") in candidates:
            return row
    raise ValueError(f"{prefix} request does not exist: {request_id}")


def _find_runtime_record(data: dict[str, list[dict[str, object]]], resource_id: str) -> dict[str, object]:
    cleaned = _safe_id(resource_id)
    for row in data["runtime_records"]:
        if row.get("resource_id") == cleaned:
            return row
    raise ValueError(f"virtual runtime record does not exist: {cleaned}")


def _validate_request_ready(row: dict[str, object], action: str) -> None:
    if row.get("status") != "approved":
        raise ValueError(f"virtual {action} request must be approved before execution")
    if not row.get("approved_by"):
        raise ValueError(f"virtual {action} request approval metadata is missing")


def _execute_snapshot(root: Path, row: dict[str, object], runtime: dict[str, object], provider: str, executed_at: str) -> dict[str, object]:
    if provider in {"docker", "podman"}:
        return _execute_container_snapshot(root, row, runtime, provider, executed_at)
    if provider in {"libvirt", "qemu_process"}:
        return _execute_qemu_snapshot(root, row, _qemu_backed_runtime(root, runtime, provider), executed_at, manifest_provider=provider)
    if provider in {"renode", "android_emulator", "gateway_proxy"}:
        return _execute_file_backed_snapshot(root, row, runtime, provider, executed_at)
    if provider == "qemu_img":
        return _execute_qemu_snapshot(root, row, runtime, executed_at)
    if provider != "local_fixture":
        raise ValueError(f"virtual provider is not implemented for live execution: {provider}")
    target = _fixture_target(root, runtime)
    snapshot_name = _safe_id(str(row.get("snapshot_name") or row.get("id") or "snapshot"))
    snapshot_dir = root / "local-secrets" / "virtual-runtime-snapshots" / _safe_id(str(row["resource_id"])) / snapshot_name
    if snapshot_dir.exists():
        shutil.rmtree(snapshot_dir)
    snapshot_dir.parent.mkdir(parents=True, exist_ok=True)
    if target.is_dir():
        shutil.copytree(target, snapshot_dir)
    else:
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(target, snapshot_dir / target.name)
    return _write_manifest(root, row, "snapshot", provider, target, snapshot_dir, executed_at)


def _execute_restore(root: Path, row: dict[str, object], runtime: dict[str, object], provider: str, executed_at: str) -> dict[str, object]:
    if provider in {"docker", "podman"}:
        return _execute_container_restore(root, row, runtime, provider, executed_at)
    if provider in {"libvirt", "qemu_process"}:
        return _execute_qemu_restore(root, row, _qemu_backed_runtime(root, runtime, provider), executed_at, manifest_provider=provider)
    if provider in {"renode", "android_emulator", "gateway_proxy"}:
        return _execute_file_backed_restore(root, row, runtime, provider, executed_at)
    if provider == "qemu_img":
        return _execute_qemu_restore(root, row, runtime, executed_at)
    if provider != "local_fixture":
        raise ValueError(f"virtual provider is not implemented for live execution: {provider}")
    target = _fixture_target(root, runtime)
    restore_point = _fixture_restore_point(root, str(row.get("resource_id") or ""), str(row.get("restore_point") or ""))
    preserved = root / "local-secrets" / "virtual-runtime-preserved" / _safe_id(str(row["resource_id"])) / _safe_id(executed_at)
    if target.exists():
        preserved.parent.mkdir(parents=True, exist_ok=True)
        if target.is_dir():
            shutil.copytree(target, preserved)
            shutil.rmtree(target)
        else:
            preserved.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, preserved / target.name)
            target.unlink()
    if restore_point.is_dir():
        shutil.copytree(restore_point, target)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(restore_point, target)
    return _write_manifest(root, row, "restore", provider, restore_point, target, executed_at, preserved=preserved)


def _execute_container_snapshot(root: Path, row: dict[str, object], runtime: dict[str, object], provider: str, executed_at: str) -> dict[str, object]:
    _validate_lifecycle_runtime(root, runtime, provider)
    _validate_runtime_adapter(runtime, provider)
    resource_id = str(runtime["resource_id"])
    snapshot_name = _safe_id(str(row.get("snapshot_name") or row.get("id") or "snapshot"))
    snapshot_dir = root / "local-secrets" / "virtual-runtime-snapshots" / _safe_id(resource_id) / snapshot_name
    archive = snapshot_dir / "container.tar"
    if snapshot_dir.exists():
        shutil.rmtree(snapshot_dir)
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    command = _container_provider_command(provider, ("export", "-o", str(archive), resource_id), timeout=60.0)
    metadata = {
        "snapshot_name": snapshot_name,
        "archive": _relative_or_name(root, archive),
        "command": command,
        "runtime_state": runtime.get("state"),
    }
    (snapshot_dir / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return _write_manifest(root, row, "snapshot", provider, Path(resource_id), snapshot_dir, executed_at, provider_metadata=metadata)


def _execute_container_restore(root: Path, row: dict[str, object], runtime: dict[str, object], provider: str, executed_at: str) -> dict[str, object]:
    _validate_lifecycle_runtime(root, runtime, provider)
    _validate_runtime_adapter(runtime, provider)
    resource_id = str(runtime["resource_id"])
    restore_point = _provider_restore_point(root, str(row["resource_id"]), str(row.get("restore_point") or ""))
    archive = restore_point / "container.tar" if restore_point.is_dir() else restore_point
    if archive.name != "container.tar" or not archive.exists():
        raise ValueError("container restore point must contain container.tar")
    preserved = root / "local-secrets" / "virtual-runtime-preserved" / _safe_id(resource_id) / _safe_id(executed_at)
    preserved.mkdir(parents=True, exist_ok=True)
    preserved_archive = preserved / "container-before-restore.tar"
    inspected = _container_provider_command(provider, ("inspect", resource_id), timeout=10.0, check=False)
    if inspected:
        _container_provider_command(provider, ("export", "-o", str(preserved_archive), resource_id), timeout=60.0, check=False)
        _container_provider_command(provider, ("rm", "-f", resource_id), timeout=30.0, check=False)
    image_tag = f"overseer-restore-{_safe_id(resource_id)}:{_safe_id(executed_at)}"
    _container_provider_command(provider, ("import", str(archive), image_tag), timeout=60.0)
    _container_provider_command(
        provider,
        (
            "create",
            "--name",
            resource_id,
            "--network",
            "none",
            "--label",
            "overseer.owner=dax",
            "--label",
            "overseer.disposable=true",
            image_tag,
            "sleep",
            "3600",
        ),
        timeout=30.0,
    )
    metadata = {
        "restore_point": _relative_or_name(root, restore_point),
        "archive": _relative_or_name(root, archive),
        "image_tag": image_tag,
        "preserved_archive": _relative_or_name(root, preserved_archive) if preserved_archive.exists() else "",
    }
    return _write_manifest(root, row, "restore", provider, archive, Path(resource_id), executed_at, preserved=preserved, provider_metadata=metadata)


def _execute_file_backed_snapshot(root: Path, row: dict[str, object], runtime: dict[str, object], provider: str, executed_at: str) -> dict[str, object]:
    _validate_lifecycle_runtime(root, runtime, provider)
    _validate_runtime_adapter(runtime, provider)
    target = _file_backed_target(root, runtime, provider)
    snapshot_name = _safe_id(str(row.get("snapshot_name") or row.get("id") or "snapshot"))
    snapshot_dir = root / "local-secrets" / "virtual-runtime-snapshots" / _safe_id(str(row["resource_id"])) / snapshot_name
    if snapshot_dir.exists():
        shutil.rmtree(snapshot_dir)
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    copied = _copy_into_snapshot(target, snapshot_dir)
    metadata = {"snapshot_name": snapshot_name, "copied_path": _relative_or_name(root, copied), "provider": provider}
    (snapshot_dir / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return _write_manifest(root, row, "snapshot", provider, target, snapshot_dir, executed_at, provider_metadata=metadata)


def _execute_file_backed_restore(root: Path, row: dict[str, object], runtime: dict[str, object], provider: str, executed_at: str) -> dict[str, object]:
    _validate_lifecycle_runtime(root, runtime, provider)
    _validate_runtime_adapter(runtime, provider)
    target = _file_backed_target(root, runtime, provider)
    restore_point = _provider_restore_point(root, str(row["resource_id"]), str(row.get("restore_point") or ""))
    restored_source = _snapshot_payload_path(restore_point, target.name)
    preserved = root / "local-secrets" / "virtual-runtime-preserved" / _safe_id(str(row["resource_id"])) / _safe_id(executed_at)
    if target.exists():
        _copy_path(target, preserved)
        _remove_path(target)
    _copy_path(restored_source, target)
    return _write_manifest(root, row, "restore", provider, restored_source, target, executed_at, preserved=preserved)


def _fixture_target(root: Path, runtime: dict[str, object]) -> Path:
    if runtime.get("adapter") != "local_fixture":
        raise ValueError("local_fixture execution requires a runtime record with adapter=local_fixture")
    hint = str(runtime.get("snapshot_hint") or "")
    if not hint.strip():
        raise ValueError("local_fixture execution requires a project-relative snapshot_hint target")
    target = _project_relative_path(root, hint)
    allowed = (root / "local-secrets" / "virtual-runtime-targets").resolve()
    if target != allowed and allowed not in target.parents:
        raise ValueError("local_fixture target must stay under local-secrets/virtual-runtime-targets")
    if not target.exists():
        raise ValueError("local_fixture target does not exist")
    return target


def _fixture_restore_point(root: Path, resource_id: str, restore_point: str) -> Path:
    if not restore_point.strip():
        raise ValueError("restore_point is required")
    candidate = _project_relative_path(root, restore_point)
    snapshots_root = (root / "local-secrets" / "virtual-runtime-snapshots" / _safe_id(resource_id)).resolve()
    if not candidate.exists():
        candidate = snapshots_root / _safe_id(restore_point)
    candidate = candidate.resolve()
    if candidate != snapshots_root and snapshots_root not in candidate.parents:
        raise ValueError("local_fixture restore point must stay under local-secrets/virtual-runtime-snapshots")
    if not candidate.exists():
        raise ValueError("local_fixture restore point does not exist")
    return candidate


def _validate_runtime_adapter(runtime: dict[str, object], provider: str) -> None:
    adapter = str(runtime.get("adapter") or "")
    if adapter != provider:
        raise ValueError(f"{provider} execution requires a runtime record with adapter={provider}")


def _provider_restore_point(root: Path, resource_id: str, restore_point: str) -> Path:
    if not restore_point.strip():
        raise ValueError("restore_point is required")
    snapshots_root = (root / "local-secrets" / "virtual-runtime-snapshots" / _safe_id(resource_id)).resolve()
    try:
        candidate = _project_relative_path(root, restore_point).resolve()
    except ValueError:
        candidate = snapshots_root / _safe_id(restore_point)
    if not candidate.exists():
        candidate = snapshots_root / _safe_id(restore_point)
    candidate = candidate.resolve()
    if candidate != snapshots_root and snapshots_root not in candidate.parents:
        raise ValueError("provider restore point must stay under local-secrets/virtual-runtime-snapshots")
    if not candidate.exists():
        raise ValueError("provider restore point does not exist")
    return candidate


def _container_provider_command(
    provider: str,
    args: tuple[str, ...],
    timeout: float = 15.0,
    check: bool = True,
) -> str:
    if provider == "podman":
        return _run_provider_command(("podman", *args), timeout=timeout, check=check)
    if provider != "docker":
        raise ValueError(f"container provider is not implemented: {provider}")
    if not check:
        output = _run_provider_command(("docker", *args), timeout=timeout, check=False)
        if "permission denied" not in output.lower() or shutil.which("sudo") is None:
            return output
        return _run_provider_command(("sudo", "docker", *args), timeout=timeout, check=False)
    try:
        return _run_provider_command(("docker", *args), timeout=timeout, check=check)
    except ValueError as error:
        if "permission denied" not in str(error).lower() or shutil.which("sudo") is None:
            raise
    return _run_provider_command(("sudo", "docker", *args), timeout=timeout, check=check)


def _file_backed_target(root: Path, runtime: dict[str, object], provider: str) -> Path:
    resource_id = str(runtime.get("resource_id") or "")
    if provider == "android_emulator":
        target = (Path.home() / ".android" / "avd" / f"{resource_id}.avd").resolve()
        allowed_parent = (Path.home() / ".android" / "avd").resolve()
        if target.parent != allowed_parent or not resource_id.startswith("overseer-dax-disposable"):
            raise ValueError("android_emulator file snapshot is limited to approved disposable AVD directories")
    else:
        target = _project_relative_path(root, str(runtime.get("snapshot_hint") or ""))
        allowed_roots = [
            (root / "local-secrets" / "virtual-runtime-targets").resolve(),
            (root / "local-secrets" / "virtual-runtime-configs").resolve(),
        ]
        if not any(target == allowed or allowed in target.parents for allowed in allowed_roots):
            raise ValueError(f"{provider} file-backed target must stay under local-secrets/virtual-runtime-targets or local-secrets/virtual-runtime-configs")
    if not target.exists():
        raise ValueError(f"{provider} file-backed target does not exist")
    return target


def _copy_into_snapshot(source: Path, snapshot_dir: Path) -> Path:
    copied = snapshot_dir / source.name
    _copy_path(source, copied)
    return copied


def _snapshot_payload_path(restore_point: Path, target_name: str) -> Path:
    if restore_point.is_file():
        return restore_point
    candidate = restore_point / target_name
    if candidate.exists():
        return candidate
    children = [item for item in restore_point.iterdir() if item.name != "metadata.json"]
    if len(children) == 1:
        return children[0]
    raise ValueError("file-backed restore point payload could not be identified")


def _copy_path(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    if source.is_dir():
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(source, target)
        return
    shutil.copy2(source, target)


def _remove_path(target: Path) -> None:
    if target.is_dir():
        shutil.rmtree(target)
    elif target.exists():
        target.unlink()


def _qemu_backed_runtime(root: Path, runtime: dict[str, object], provider: str) -> dict[str, object]:
    _validate_lifecycle_runtime(root, runtime, provider)
    _validate_runtime_adapter(runtime, provider)
    if provider == "libvirt":
        state = _libvirt_state(str(runtime["resource_id"]))
        if state == "running":
            raise ValueError("libvirt snapshot/restore requires a stopped disposable domain")
    if provider == "qemu_process":
        pidfile = root / "local-secrets" / "virtual-runtime-targets" / f"{_safe_id(str(runtime['resource_id']))}.pid"
        if _pid_running(pidfile):
            raise ValueError("qemu_process snapshot/restore requires the disposable qemu process to be stopped")
    return {**runtime, "adapter": "qemu_img"}


def _execute_qemu_snapshot(
    root: Path,
    row: dict[str, object],
    runtime: dict[str, object],
    executed_at: str,
    manifest_provider: str = "qemu_img",
) -> dict[str, object]:
    target = _qemu_image_target(root, runtime)
    snapshot_name = _safe_id(str(row.get("snapshot_name") or row.get("id") or "snapshot"))
    before = _qemu_image_info(target)
    _run_qemu_img(("snapshot", "-c", snapshot_name, str(target)))
    after = _qemu_image_info(target)
    return _write_manifest(
        root,
        row,
        "snapshot",
        manifest_provider,
        target,
        target,
        executed_at,
        provider_metadata={"snapshot_name": snapshot_name, "before": before, "after": after},
    )


def _execute_qemu_restore(
    root: Path,
    row: dict[str, object],
    runtime: dict[str, object],
    executed_at: str,
    manifest_provider: str = "qemu_img",
) -> dict[str, object]:
    target = _qemu_image_target(root, runtime)
    restore_point = _safe_id(str(row.get("restore_point") or ""))
    if not restore_point:
        raise ValueError("restore_point is required")
    preserved = _preserve_qemu_image(root, target, str(row["resource_id"]), executed_at)
    before = _qemu_image_info(target)
    _run_qemu_img(("snapshot", "-a", restore_point, str(target)))
    after = _qemu_image_info(target)
    return _write_manifest(
        root,
        row,
        "restore",
        manifest_provider,
        target,
        target,
        executed_at,
        preserved=preserved,
        provider_metadata={"restore_point": restore_point, "before": before, "after": after},
    )


def _qemu_image_target(root: Path, runtime: dict[str, object]) -> Path:
    if runtime.get("adapter") != "qemu_img":
        raise ValueError("qemu_img execution requires a runtime record with adapter=qemu_img")
    if shutil.which("qemu-img") is None:
        raise ValueError("qemu-img is not available")
    hint = str(runtime.get("snapshot_hint") or "")
    if not hint.strip():
        raise ValueError("qemu_img execution requires a project-relative snapshot_hint qcow2 image")
    target = _project_relative_path(root, hint)
    allowed = (root / "local-secrets" / "virtual-runtime-targets").resolve()
    if target != allowed and allowed not in target.parents:
        raise ValueError("qemu_img target must stay under local-secrets/virtual-runtime-targets")
    if target.suffix != ".qcow2":
        raise ValueError("qemu_img target must be a .qcow2 image")
    if not target.exists():
        raise ValueError("qemu_img target does not exist")
    info = _qemu_image_info(target)
    if info.get("format") != "qcow2":
        raise ValueError("qemu_img target must report qcow2 format")
    return target


def _preserve_qemu_image(root: Path, target: Path, resource_id: str, executed_at: str) -> Path:
    preserved = root / "local-secrets" / "virtual-runtime-preserved" / _safe_id(resource_id) / f"{_safe_id(executed_at)}.qcow2"
    preserved.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(target, preserved)
    return preserved


def _qemu_image_info(target: Path) -> dict[str, object]:
    output = _run_qemu_img(("info", "--output=json", str(target)))
    try:
        data = json.loads(output)
    except json.JSONDecodeError as error:
        raise ValueError(f"qemu-img info returned invalid JSON: {error}") from error
    return {
        "format": data.get("format"),
        "virtual_size": data.get("virtual-size"),
        "actual_size": data.get("actual-size"),
        "snapshots": [
            {
                "id": item.get("id"),
                "name": item.get("name"),
                "vm_state_size": item.get("vm-state-size"),
            }
            for item in data.get("snapshots", [])
            if isinstance(item, dict)
        ],
    }


def _run_qemu_img(args: tuple[str, ...]) -> str:
    command = ("qemu-img", *args)
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=15.0)
    except subprocess.TimeoutExpired as error:
        raise ValueError(f"qemu-img timed out: {' '.join(command)}") from error
    except OSError as error:
        raise ValueError(f"qemu-img failed to start: {error}") from error
    if completed.returncode != 0:
        stderr = completed.stderr.strip() or completed.stdout.strip() or f"exit {completed.returncode}"
        raise ValueError(f"qemu-img {' '.join(args[:2])} failed: {stderr}")
    return completed.stdout.strip()


def _validate_lifecycle_runtime(root: Path, runtime: dict[str, object], provider: str) -> None:
    resource_id = str(runtime.get("resource_id") or "")
    notes = str(runtime.get("notes") or "").lower()
    if not resource_id:
        raise ValueError("virtual lifecycle requires a runtime resource_id")
    if "disposable" not in resource_id and "disposable" not in notes and not resource_id.startswith("vm."):
        raise ValueError("virtual lifecycle is limited to registered disposable targets")
    if provider not in {"docker", "podman", "libvirt", "qemu_process", "renode", "android_emulator", "gateway_proxy"}:
        raise ValueError(f"virtual lifecycle provider is not implemented: {provider}")
    hint = str(runtime.get("snapshot_hint") or "")
    if provider in {"qemu_process", "renode", "gateway_proxy"}:
        _project_relative_path(root, hint)
    if provider == "android_emulator" and not hint:
        raise ValueError("android_emulator lifecycle requires an AVD config snapshot_hint")


def _execute_lifecycle_provider(root: Path, runtime: dict[str, object], provider: str, action: str) -> dict[str, object]:
    if provider == "docker":
        return _docker_lifecycle(runtime, action)
    if provider == "podman":
        return _container_lifecycle(("podman",), runtime, action)
    if provider == "libvirt":
        return _libvirt_lifecycle(runtime, action)
    if provider == "qemu_process":
        return _qemu_process_lifecycle(root, runtime, action)
    if provider == "renode":
        return _scripted_process_lifecycle(root, runtime, action, "renode")
    if provider == "android_emulator":
        return _android_emulator_lifecycle(runtime, action)
    if provider == "gateway_proxy":
        return _scripted_process_lifecycle(root, runtime, action, "proxy")
    raise ValueError(f"virtual lifecycle provider is not implemented: {provider}")


def _docker_lifecycle(runtime: dict[str, object], action: str) -> dict[str, object]:
    try:
        return _container_lifecycle(("docker",), runtime, action)
    except ValueError as error:
        if "permission denied" not in str(error).lower() or shutil.which("sudo") is None:
            raise
    return _container_lifecycle(("sudo", "docker"), runtime, action)


def _container_lifecycle(base_command: tuple[str, ...], runtime: dict[str, object], action: str) -> dict[str, object]:
    name = str(runtime["resource_id"])
    if action == "start":
        output = _run_provider_command((*base_command, "start", name), timeout=20.0)
        state = _container_state(base_command, name)
        return _provider_result(state, output, "container started; inspect health and claim ownership before workload use")
    if action == "stop":
        output = _run_provider_command((*base_command, "stop", name), timeout=20.0)
        state = _container_state(base_command, name)
        return _provider_result(state, output, "container stopped; release claim or keep reserved for next lifecycle smoke")
    state = _container_state(base_command, name)
    return _provider_result(state, "", "container inspected; start only when a Dax claim owns the target")


def _container_state(base_command: tuple[str, ...], name: str) -> str:
    output = _run_provider_command((*base_command, "inspect", name, "--format", "{{.State.Status}}"), timeout=10.0)
    return _state_from_text(output.strip())


def _libvirt_lifecycle(runtime: dict[str, object], action: str) -> dict[str, object]:
    name = str(runtime["resource_id"])
    if action == "start":
        output = _run_provider_command(("virsh", "start", name), timeout=20.0)
        return _provider_result(_libvirt_state(name), output, "domain started without changing network definition; run health checks before use")
    if action == "stop":
        output = _run_provider_command(("virsh", "destroy", name), timeout=20.0)
        return _provider_result(_libvirt_state(name), output, "domain stopped; snapshot or release according to the active claim")
    return _provider_result(_libvirt_state(name), "", "domain inspected; start only under Dax claim control")


def _libvirt_state(name: str) -> str:
    output = _run_provider_command(("virsh", "domstate", name), timeout=10.0)
    text = output.strip().lower()
    if "running" in text:
        return "running"
    if "shut off" in text or "shut" in text:
        return "stopped"
    return _state_from_text(text)


def _qemu_process_lifecycle(root: Path, runtime: dict[str, object], action: str) -> dict[str, object]:
    resource_id = str(runtime["resource_id"])
    pidfile = root / "local-secrets" / "virtual-runtime-targets" / f"{_safe_id(resource_id)}.pid"
    script = root / "local-secrets" / "virtual-runtime-configs" / f"{_safe_id(resource_id)}-start.sh"
    if action == "start":
        if _pid_running(pidfile):
            return _provider_result("running", f"pid {pidfile.read_text(encoding='utf-8').strip()}", "qemu process already running; inspect before reuse")
        if not script.exists():
            raise ValueError("qemu_process lifecycle start script is missing")
        subprocess.Popen((str(script),), cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        return _provider_result("running" if _pid_running(pidfile) else "starting", _relative_or_name(root, pidfile), "qemu process launch requested with project-local pidfile")
    if action == "stop":
        stopped = _stop_pidfile(pidfile)
        return _provider_result("stopped", stopped, "qemu process stopped or already absent")
    return _provider_result("running" if _pid_running(pidfile) else "stopped", _relative_or_name(root, pidfile), "qemu process inspected; start only with -net none launch script")


def _scripted_process_lifecycle(root: Path, runtime: dict[str, object], action: str, suffix: str) -> dict[str, object]:
    resource_id = str(runtime["resource_id"])
    pidfile = root / "local-secrets" / "virtual-runtime-targets" / f"{_safe_id(resource_id)}.pid"
    if suffix == "proxy":
        pidfile = root / "local-secrets" / "virtual-runtime-targets" / "overseer-dax-disposable-proxy.pid"
    script = root / "local-secrets" / "virtual-runtime-configs" / f"{_safe_id(resource_id)}-start.sh"
    if suffix == "proxy":
        script = root / "local-secrets" / "virtual-runtime-configs" / "overseer-dax-disposable-proxy-start.sh"
    if action == "start":
        if _pid_running(pidfile):
            return _provider_result("running", f"pid {pidfile.read_text(encoding='utf-8').strip()}", f"{suffix} process already running")
        if not script.exists():
            raise ValueError(f"{suffix} lifecycle start script is missing")
        process = subprocess.Popen((str(script),), cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        pidfile.parent.mkdir(parents=True, exist_ok=True)
        pidfile.write_text(str(process.pid), encoding="utf-8")
        return _provider_result("running" if _pid_running(pidfile) else "starting", _relative_or_name(root, pidfile), f"{suffix} process launch requested")
    if action == "stop":
        stopped = _stop_pidfile(pidfile)
        return _provider_result("stopped", stopped, f"{suffix} process stopped or already absent")
    return _provider_result("running" if _pid_running(pidfile) else "stopped", _relative_or_name(root, pidfile), f"{suffix} process inspected")


def _android_emulator_lifecycle(runtime: dict[str, object], action: str) -> dict[str, object]:
    avd = str(runtime["resource_id"])
    emulator = _android_tool("emulator")
    adb = _android_tool("adb")
    if action == "start":
        if emulator is None:
            raise ValueError("Android emulator is not available")
        subprocess.Popen((emulator, "-avd", avd, "-no-window", "-no-audio", "-no-boot-anim"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        return _provider_result("starting", avd, "Android emulator launch requested; verify adb state before use")
    if action == "stop":
        if adb is None:
            raise ValueError("adb is not available")
        output = _run_provider_command((adb, "emu", "kill"), timeout=10.0, check=False)
        return _provider_result("stopped", output, "Android emulator stop requested; inspect adb devices")
    if emulator is None:
        raise ValueError("Android emulator is not available")
    output = _run_provider_command((emulator, "-list-avds"), timeout=10.0)
    return _provider_result("available" if avd in output.splitlines() else "missing", avd, "AVD inspected; start only under Dax claim control")


def _android_tool(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    home = Path.home() / "Android" / "Sdk"
    candidates = {
        "emulator": home / "emulator" / "emulator",
        "adb": home / "platform-tools" / "adb",
    }
    candidate = candidates.get(name)
    if candidate and candidate.exists():
        return str(candidate)
    return None


def _run_provider_command(command: tuple[str, ...], timeout: float = 15.0, check: bool = True) -> str:
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise ValueError(f"provider command timed out: {' '.join(command)}") from error
    except OSError as error:
        raise ValueError(f"provider command failed to start: {error}") from error
    if check and completed.returncode != 0:
        stderr = completed.stderr.strip() or completed.stdout.strip() or f"exit {completed.returncode}"
        raise ValueError(f"provider command failed: {command[0]} {command[1] if len(command) > 1 else ''}: {stderr}")
    return (completed.stdout.strip() or completed.stderr.strip()).strip()


def _provider_result(state: str, output: str, next_step: str) -> dict[str, object]:
    return {"state": state, "output": output[-500:], "next_step": next_step}


def _state_from_text(text: str) -> str:
    cleaned = text.strip().lower()
    if cleaned in {"created", "exited", "stopped", "shut off"}:
        return "stopped"
    if cleaned in {"running", "paused"}:
        return cleaned
    return cleaned or "observed"


def _pid_running(pidfile: Path) -> bool:
    try:
        pid = int(pidfile.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return False
    return Path(f"/proc/{pid}").exists()


def _stop_pidfile(pidfile: Path) -> str:
    try:
        pid = int(pidfile.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return "pidfile absent"
    try:
        Path(f"/proc/{pid}").exists()
        subprocess.run(("kill", str(pid)), check=False, capture_output=True, text=True, timeout=5.0)
    except OSError as error:
        raise ValueError(f"failed to stop pid {pid}: {error}") from error
    return f"stopped pid {pid}"


def _project_relative_path(root: Path, raw_path: str) -> Path:
    path = Path(raw_path)
    if path.is_absolute() or "~" in path.parts or ".." in path.parts:
        raise ValueError("virtual execution paths must be project-relative and cannot include parent traversal")
    target = (root / path).resolve()
    root_resolved = root.resolve()
    if target == root_resolved or root_resolved not in target.parents:
        raise ValueError("virtual execution path must stay inside the project root")
    return target


def _write_manifest(
    root: Path,
    row: dict[str, object],
    action: str,
    provider: str,
    source: Path,
    target: Path,
    executed_at: str,
    preserved: Path | None = None,
    provider_metadata: dict[str, object] | None = None,
) -> dict[str, object]:
    manifest_dir = root / "local-secrets" / "virtual-runtime-manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "request_id": row["id"],
        "resource_id": row["resource_id"],
        "action": action,
        "provider": provider,
        "executed_at": executed_at,
        "source": _relative_or_name(root, source),
        "target": _relative_or_name(root, target),
        "preserved": _relative_or_name(root, preserved) if preserved else "",
        "provider_metadata": provider_metadata or {},
        "entries": _manifest_entries(root, target),
    }
    manifest["entry_count"] = len(manifest["entries"])
    manifest_path = manifest_dir / f"{_safe_id(str(row['id']))}-{_safe_id(executed_at)}.json"
    manifest["manifest_path"] = _relative_or_name(root, manifest_path)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def _write_lifecycle_manifest(
    root: Path,
    runtime: dict[str, object],
    action: str,
    provider: str,
    result: dict[str, object],
    executed_at: str,
) -> dict[str, object]:
    manifest_dir = root / "local-secrets" / "virtual-runtime-manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "request_id": f"virtual-lifecycle.{runtime['resource_id']}.{action}",
        "resource_id": runtime["resource_id"],
        "action": f"lifecycle_{action}",
        "provider": provider,
        "executed_at": executed_at,
        "source": str(runtime.get("snapshot_hint") or ""),
        "target": str(runtime.get("resource_id") or ""),
        "preserved": "",
        "provider_metadata": {
            "state": result.get("state"),
            "next_step": result.get("next_step"),
            "output": result.get("output"),
        },
        "entries": [],
        "entry_count": 0,
    }
    manifest_path = manifest_dir / f"{_safe_id(str(manifest['request_id']))}-{_safe_id(executed_at)}.json"
    manifest["manifest_path"] = _relative_or_name(root, manifest_path)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def _manifest_entries(root: Path, target: Path) -> list[dict[str, object]]:
    paths = [target, *sorted(target.rglob("*"))] if target.is_dir() else [target]
    entries = []
    for path in paths:
        try:
            stat = path.stat()
        except OSError:
            continue
        entries.append(
            {
                "path": _relative_or_name(root, path),
                "kind": "directory" if path.is_dir() else "file",
                "bytes": 0 if path.is_dir() else stat.st_size,
            }
        )
    return entries


def _record_blocked_execution(
    root: Path,
    data: dict[str, list[dict[str, object]]],
    row: dict[str, object],
    action: str,
    request_id: str,
    executed_by: str,
    executed_at: str,
    error: str,
) -> dict[str, object]:
    row.update(
        {
            "status": "blocked",
            "executed_by": executed_by,
            "executed_at": executed_at,
            "updated_at": executed_at,
            "execution_error": error,
            "next_step": "declare a supported disposable runtime target or approved provider adapter before retrying",
        }
    )
    _append_execution(data, row, action, request_id, executed_by, executed_at, "blocked", "", error=error)
    _write_registry(root, data)
    return {
        f"{action}_request": row,
        "status": "blocked",
        "summary": error,
        "mutation_performed": True,
        "host_mutation_performed": False,
    }


def _record_failed_execution(
    root: Path,
    data: dict[str, list[dict[str, object]]],
    row: dict[str, object],
    action: str,
    request_id: str,
    executed_by: str,
    executed_at: str,
    error: str,
) -> dict[str, object]:
    row.update(
        {
            "status": "failed",
            "executed_by": executed_by,
            "executed_at": executed_at,
            "updated_at": executed_at,
            "execution_error": error,
            "next_step": "inspect partial virtual runtime state and retry only after Dax validates provider safety",
        }
    )
    _append_execution(data, row, action, request_id, executed_by, executed_at, "failed", "", error=error)
    _write_registry(root, data)
    return {
        f"{action}_request": row,
        "status": "failed",
        "summary": error,
        "mutation_performed": True,
        "host_mutation_performed": True,
    }


def _append_execution(
    data: dict[str, list[dict[str, object]]],
    row: dict[str, object],
    action: str,
    request_id: str,
    executed_by: str,
    executed_at: str,
    status: str,
    provider: str,
    manifest: dict[str, object] | None = None,
    error: str = "",
) -> None:
    data["execution_records"].append(
        {
            "id": f"virtual-execution.{_safe_id(request_id)}.{_safe_id(executed_at)}",
            "request_id": row.get("id") or request_id,
            "resource_id": row.get("resource_id"),
            "action": action,
            "status": status,
            "provider": provider,
            "executed_by": executed_by,
            "executed_at": executed_at,
            "manifest_path": (manifest or {}).get("manifest_path", ""),
            "error": error,
        }
    )


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


def _relative_or_name(root: Path, path: Path | None) -> str:
    if path is None:
        return ""
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
