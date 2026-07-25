"""Read-only virtual runtime and deconfliction evidence for Dax."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
from typing import Any

from .core import Claim, ClaimStatus, Resource, ResourceType
from .store import SQLiteStore
from .virtual_ops import virtual_operations_status


def virtual_evidence_status(store_path: str | Path) -> dict[str, object]:
    store_path = Path(store_path)
    project_root = store_path.parent.parent if store_path.parent.name == "state" else store_path.parent
    virtual_ops = virtual_operations_status(project_root)
    store = SQLiteStore(store_path)
    try:
        resources = [resource for resource in store.list_resources() if resource.type == ResourceType.VIRTUAL_ASSET]
        claims = store.list_claims()
    finally:
        store.close()
    rows = [_virtual_row(resource, claims) for resource in resources]
    port_rows = _port_pool_rows(resources, claims)
    return {
        "store": str(Path(store_path)),
        "runtime_assets": len(rows),
        "active_claims": sum(1 for row in rows for claim in row["claims"] if claim["active_like"]),
        "port_conflicts": sum(1 for row in port_rows if row["status"] == "conflict"),
        "snapshot_ready": sum(1 for row in rows if row["snapshot_status"] == "ready"),
        "items": rows,
        "runtime_records": virtual_ops["runtime_records"],
        "snapshot_requests": virtual_ops["snapshot_requests"],
        "restore_requests": virtual_ops["restore_requests"],
        "execution_records": virtual_ops["execution_records"],
        "runtime_adapters": _runtime_adapter_rows(),
        "runtime_inventory": _runtime_inventory_rows(),
        "port_pool": port_rows,
        "cleanup": _cleanup_rows(claims),
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def _virtual_row(resource: Resource, claims: tuple[Claim, ...]) -> dict[str, Any]:
    related_claims = [claim for claim in claims if claim.resource_id == resource.id]
    active_claims = [claim for claim in related_claims if claim.is_active_like()]
    return {
        "resource_id": resource.id,
        "name": resource.name,
        "kind": str(resource.identifiers.get("kind", "unknown")),
        "state": resource.state.value,
        "ports": sorted(resource.ports()),
        "networks": _values(resource.identifiers.get("networks")),
        "image": _short_value(resource.identifiers.get("image")),
        "snapshot_path": _redact_path(str(resource.identifiers.get("snapshot_path", ""))),
        "snapshot_status": "ready" if resource.identifiers.get("snapshot_path") else "not_configured",
        "active_claims": len(active_claims),
        "claims": [_claim_row(claim) for claim in related_claims],
        "ready_for_checkout": not active_claims and resource.state.value == "available",
        "next_step": "stage cleanup for stale claims" if any(claim.status in {ClaimStatus.EXPIRED, ClaimStatus.RELEASING} for claim in related_claims) else "continue deconfliction monitoring",
    }


def _port_pool_rows(resources: list[Resource], claims: tuple[Claim, ...]) -> list[dict[str, object]]:
    owners: dict[int, list[str]] = {}
    for resource in resources:
        for port in resource.ports():
            owners.setdefault(port, []).append(resource.id)
    for claim in claims:
        for port in claim.port_reservations:
            owners.setdefault(port, []).append(claim.id)
    return [
        {
            "port": port,
            "owners": sorted(set(owner_ids)),
            "owner_count": len(set(owner_ids)),
            "status": "conflict" if len(set(owner_ids)) > 1 else "reserved",
        }
        for port, owner_ids in sorted(owners.items())
    ]


def _cleanup_rows(claims: tuple[Claim, ...]) -> list[dict[str, object]]:
    return [
        {
            "claim_id": claim.id,
            "resource_id": claim.resource_id,
            "status": claim.status.value,
            "release_condition": claim.release_condition,
            "next_step": "request cleanup approval" if claim.status in {ClaimStatus.EXPIRED, ClaimStatus.RELEASING, ClaimStatus.BLOCKED} else "monitor",
        }
        for claim in claims
        if claim.status in {ClaimStatus.EXPIRED, ClaimStatus.RELEASING, ClaimStatus.BLOCKED, ClaimStatus.QUEUED}
    ]


def _runtime_adapter_rows() -> list[dict[str, object]]:
    adapters = ("docker", "podman", "virsh", "qemu-img", "qemu-system-x86_64", "qemu-system-aarch64", "VBoxManage", "emulator", "renode")
    return [
        {
            "adapter": adapter,
            "available": shutil.which(adapter) is not None,
            "status": "available_for_readonly_inventory" if shutil.which(adapter) else "missing",
            "mutation_boundary": "start, stop, snapshot, restore, and destroy require approval-gated live adapter execution",
        }
        for adapter in adapters
    ]


def _runtime_inventory_rows() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    rows.extend(_docker_inventory_rows())
    rows.extend(_virsh_inventory_rows())
    return rows


def _docker_inventory_rows() -> list[dict[str, object]]:
    if shutil.which("docker") is None:
        return []
    result = _run_inventory_command(("docker", "ps", "-a", "--format", "{{json .}}"))
    if result["exit_code"] != 0:
        return [
            {
                "provider": "docker",
                "resource_id": "docker.inventory",
                "kind": "container_inventory",
                "state": "unavailable",
                "image": "",
                "ports": "",
                "owner": "",
                "evidence": result["stderr"],
                "next_step": "verify Docker daemon access before container inventory can be trusted",
            }
        ]
    return parse_docker_ps_json_lines(str(result["stdout"]))


def parse_docker_ps_json_lines(output: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        container_id = str(item.get("ID") or item.get("ContainerID") or "").strip()
        name = str(item.get("Names") or item.get("Name") or container_id or "container").strip()
        state = str(item.get("State") or item.get("Status") or "unknown").strip()
        rows.append(
            {
                "provider": "docker",
                "resource_id": f"docker.{_safe_id(name or container_id)}",
                "kind": "container",
                "state": state,
                "image": _short_value(item.get("Image")),
                "ports": str(item.get("Ports") or ""),
                "owner": str(item.get("Labels") or ""),
                "evidence": f"id={container_id}",
                "next_step": "request Dax claim before changing container runtime state",
            }
        )
    return rows


def _virsh_inventory_rows() -> list[dict[str, object]]:
    if shutil.which("virsh") is None:
        return []
    names = _run_inventory_command(("virsh", "list", "--all", "--name"))
    if names["exit_code"] != 0:
        return [
            {
                "provider": "virsh",
                "resource_id": "virsh.inventory",
                "kind": "vm_inventory",
                "state": "unavailable",
                "image": "",
                "ports": "",
                "owner": "",
                "evidence": names["stderr"],
                "next_step": "verify libvirt access before VM inventory can be trusted",
            }
        ]
    rows = []
    for name in [line.strip() for line in str(names["stdout"]).splitlines() if line.strip()]:
        state = _run_inventory_command(("virsh", "domstate", name))
        rows.append(
            {
                "provider": "virsh",
                "resource_id": f"virsh.{_safe_id(name)}",
                "kind": "vm",
                "state": str(state["stdout"]).strip() if state["exit_code"] == 0 else "unknown",
                "image": "",
                "ports": "",
                "owner": "",
                "evidence": f"name={name}",
                "next_step": "request Dax claim before changing VM runtime state",
            }
        )
    return rows


def _run_inventory_command(command: tuple[str, ...]) -> dict[str, object]:
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=2.0)
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"exit_code": -1, "stdout": "", "stderr": str(error)}
    return {
        "exit_code": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }


def _claim_row(claim: Claim) -> dict[str, object]:
    return {
        "id": claim.id,
        "status": claim.status.value,
        "owner_thread": claim.owner_thread,
        "owner_role": claim.owner_role.value,
        "active_like": claim.is_active_like(),
        "ports": sorted(claim.port_reservations),
        "expires_at": claim.expires_at,
    }


def _values(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set, frozenset)):
        return sorted(str(item) for item in value)
    return []


def _short_value(value: object) -> str:
    if not value:
        return ""
    text = str(value)
    return text if len(text) <= 80 else f"{text[:77]}..."


def _redact_path(value: str) -> str:
    if not value:
        return ""
    if value.startswith("/"):
        return f".../{Path(value).name}"
    return value


def _safe_id(value: str) -> str:
    cleaned = "".join(character.lower() if character.isalnum() else "-" for character in value)
    return "-".join(part for part in cleaned.split("-") if part) or "item"
