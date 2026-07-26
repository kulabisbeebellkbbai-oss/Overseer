"""Read-only virtual runtime and deconfliction evidence for Dax."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
from typing import Any

from .core import Claim, ClaimStatus, Resource, ResourceType
from .image_scanning import image_scan_status
from .store import SQLiteStore
from .virtual_ops import virtual_operations_status


def virtual_evidence_status(store_path: str | Path) -> dict[str, object]:
    store_path = Path(store_path)
    project_root = store_path.parent.parent if store_path.parent.name == "state" else store_path.parent
    virtual_ops = virtual_operations_status(project_root)
    image_scans = image_scan_status(project_root)
    store = SQLiteStore(store_path)
    try:
        resources = [resource for resource in store.list_resources() if resource.type == ResourceType.VIRTUAL_ASSET]
        claims = store.list_claims()
    finally:
        store.close()
    rows = [_virtual_row(resource, claims) for resource in resources]
    port_rows = _port_pool_rows(resources, claims)
    runtime_records = list(virtual_ops["runtime_records"])
    runtime_inventory = _runtime_inventory_rows(project_root, runtime_records)
    return {
        "store": str(Path(store_path)),
        "runtime_assets": len(rows),
        "active_claims": sum(1 for row in rows for claim in row["claims"] if claim["active_like"]),
        "port_conflicts": sum(1 for row in port_rows if row["status"] == "conflict"),
        "snapshot_ready": sum(1 for row in rows if row["snapshot_status"] == "ready"),
        "items": rows,
        "runtime_records": runtime_records,
        "snapshot_requests": virtual_ops["snapshot_requests"],
        "restore_requests": virtual_ops["restore_requests"],
        "execution_records": virtual_ops["execution_records"],
        "runtime_adapters": _runtime_adapter_rows(),
        "runtime_inventory": runtime_inventory,
        "capacity_summary": _capacity_summary(resources, claims, runtime_records, runtime_inventory, port_rows),
        "image_provenance": _image_provenance_rows(runtime_inventory),
        "image_scanner_adapters": image_scans["scanner_adapters"],
        "image_scan_requests": image_scans["scan_requests"],
        "image_scan_results": image_scans["scan_results"],
        "provider_depth": _provider_depth_rows(runtime_records, runtime_inventory),
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
    adapters = ("docker", "podman", "virsh", "qemu-img", "qemu-system-x86_64", "qemu-system-aarch64", "emulator", "renode")
    return [
        {
            "adapter": adapter,
            "available": shutil.which(adapter) is not None,
            "status": "available_for_readonly_inventory" if shutil.which(adapter) else "missing",
            "mutation_boundary": "start, stop, snapshot, restore, and destroy require approval-gated live adapter execution",
        }
        for adapter in adapters
    ]


def _runtime_inventory_rows(project_root: Path, runtime_records: list[dict[str, object]]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    rows.extend(_docker_inventory_rows())
    rows.extend(_podman_inventory_rows())
    rows.extend(_virsh_inventory_rows())
    rows.extend(_qemu_image_inventory_rows(project_root))
    rows.extend(_registered_runtime_depth_rows(project_root, runtime_records))
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
                "cpu": "",
                "memory": "",
                "network": "",
                "evidence": result["stderr"],
                "next_step": "verify Docker daemon access before container inventory can be trusted",
            }
        ]
    return parse_docker_ps_json_lines(str(result["stdout"]), _docker_stats_map())


def parse_docker_ps_json_lines(output: str, stats_by_name: dict[str, dict[str, object]] | None = None) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    stats_by_name = stats_by_name or {}
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
        stats = stats_by_name.get(name) or stats_by_name.get(container_id) or {}
        rows.append(
            {
                "provider": "docker",
                "resource_id": f"docker.{_safe_id(name or container_id)}",
                "kind": "container",
                "state": state,
                "image": _short_value(item.get("Image")),
                "virtual_size": "",
                "actual_size": _short_value(stats.get("block_io")),
                "snapshots": "",
                "ports": str(item.get("Ports") or ""),
                "owner": str(item.get("Labels") or ""),
                "cpu": _short_value(stats.get("cpu")),
                "memory": _short_value(stats.get("memory")),
                "network": _short_value(stats.get("network")),
                "evidence": f"id={container_id}",
                "next_step": "request Dax claim before changing container runtime state",
            }
        )
    return rows


def _podman_inventory_rows() -> list[dict[str, object]]:
    if shutil.which("podman") is None:
        return []
    result = _run_inventory_command(("podman", "ps", "-a", "--format", "json"))
    if result["exit_code"] != 0:
        return [
            {
                "provider": "podman",
                "resource_id": "podman.inventory",
                "kind": "container_inventory",
                "state": "unavailable",
                "image": "",
                "virtual_size": "",
                "actual_size": "",
                "ports": "",
                "owner": "",
                "cpu": "",
                "memory": "",
                "network": "",
                "evidence": result["stderr"],
                "next_step": "verify Podman rootless runtime before container inventory can be trusted",
            }
        ]
    return parse_podman_ps_json(str(result["stdout"]), _podman_stats_map())


def parse_podman_ps_json(output: str, stats_by_name: dict[str, dict[str, object]] | None = None) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    stats_by_name = stats_by_name or {}
    try:
        items = json.loads(output) if output.strip() else []
    except json.JSONDecodeError:
        items = []
    if isinstance(items, dict):
        items = [items]
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        container_id = str(item.get("Id") or item.get("ID") or "").strip()
        names = item.get("Names") or item.get("Name") or container_id or "container"
        if isinstance(names, list):
            name = str(names[0] if names else container_id or "container")
        else:
            name = str(names)
        state = str(item.get("State") or item.get("Status") or "unknown").strip()
        ports = item.get("Ports") or item.get("PortMappings") or ""
        labels = item.get("Labels") or {}
        owner = labels.get("overseer.owner", "") if isinstance(labels, dict) else str(labels)
        stats = stats_by_name.get(name) or stats_by_name.get(container_id) or {}
        rows.append(
            {
                "provider": "podman",
                "resource_id": f"podman.{_safe_id(name or container_id)}",
                "kind": "container",
                "state": state,
                "image": _short_value(item.get("Image") or item.get("ImageName")),
                "virtual_size": "",
                "actual_size": item.get("Size") or "",
                "snapshots": "",
                "ports": _short_value(ports),
                "owner": owner,
                "cpu": _short_value(stats.get("cpu")),
                "memory": _short_value(stats.get("memory")),
                "network": _short_value(stats.get("network")),
                "evidence": f"id={container_id}",
                "next_step": "request Dax claim before changing container runtime state",
            }
        )
    return rows


def _docker_stats_map() -> dict[str, dict[str, object]]:
    result = _run_inventory_command(("docker", "stats", "--no-stream", "--format", "{{json .}}"), timeout_seconds=4.0)
    if result["exit_code"] != 0:
        return {}
    rows: dict[str, dict[str, object]] = {}
    for line in str(result["stdout"]).splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        names = [str(item.get("Name") or "").strip(), str(item.get("Container") or "").strip(), str(item.get("ID") or "").strip()]
        stats = {
            "cpu": item.get("CPUPerc") or item.get("CPU %") or "",
            "memory": item.get("MemUsage") or item.get("MemPerc") or item.get("Mem %") or "",
            "network": item.get("NetIO") or item.get("Net I/O") or "",
            "block_io": item.get("BlockIO") or item.get("Block I/O") or "",
        }
        for name in names:
            if name:
                rows[name] = stats
    return rows


def _podman_stats_map() -> dict[str, dict[str, object]]:
    result = _run_inventory_command(("podman", "stats", "--no-stream", "--format", "json"), timeout_seconds=4.0)
    if result["exit_code"] != 0:
        return {}
    try:
        items = json.loads(str(result["stdout"])) if str(result["stdout"]).strip() else []
    except json.JSONDecodeError:
        return {}
    if isinstance(items, dict):
        items = [items]
    rows: dict[str, dict[str, object]] = {}
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        names = [
            str(item.get("name") or item.get("Name") or "").strip(),
            str(item.get("id") or item.get("ID") or item.get("container_id") or "").strip(),
        ]
        stats = {
            "cpu": item.get("cpu_percent") or item.get("CPUPerc") or item.get("cpu") or "",
            "memory": item.get("mem_usage") or item.get("MemUsage") or item.get("mem_percent") or "",
            "network": item.get("net_input") or item.get("NetIO") or item.get("network") or "",
        }
        for name in names:
            if name:
                rows[name] = stats
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
                "cpu": "",
                "memory": "",
                "network": "",
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
                "cpu": "",
                "memory": "",
                "network": "",
                "evidence": f"name={name}",
                "next_step": "request Dax claim before changing VM runtime state",
            }
        )
    return rows


def _qemu_image_inventory_rows(project_root: Path) -> list[dict[str, object]]:
    if shutil.which("qemu-img") is None:
        return []
    targets_root = project_root / "local-secrets" / "virtual-runtime-targets"
    if not targets_root.exists():
        return []
    rows = []
    for image in sorted(targets_root.rglob("*.qcow2")):
        rows.append(_qemu_image_inventory_row(project_root, image))
    return rows


def _qemu_image_inventory_row(project_root: Path, image: Path) -> dict[str, object]:
    result = _run_inventory_command(("qemu-img", "info", "--output=json", str(image)), timeout_seconds=5.0)
    if result["exit_code"] != 0:
        return {
            "provider": "qemu_img",
            "resource_id": f"qemu-img.{_safe_id(_relative_or_name(project_root, image))}",
            "kind": "qcow2_image",
            "state": "unavailable",
            "image": _relative_or_name(project_root, image),
            "ports": "",
            "owner": "",
            "virtual_size": "",
            "actual_size": "",
            "snapshots": "",
            "evidence": result["stderr"],
            "cpu": "",
            "memory": "",
            "network": "",
            "next_step": "inspect qemu-img error before using this image as a Dax target",
        }
    try:
        info = json.loads(str(result["stdout"]))
    except json.JSONDecodeError:
        return {
            "provider": "qemu_img",
            "resource_id": f"qemu-img.{_safe_id(_relative_or_name(project_root, image))}",
            "kind": "qcow2_image",
            "state": "invalid_info",
            "image": _relative_or_name(project_root, image),
            "ports": "",
            "owner": "",
            "virtual_size": "",
            "actual_size": "",
            "snapshots": "",
            "evidence": "qemu-img info returned invalid JSON",
            "cpu": "",
            "memory": "",
            "network": "",
            "next_step": "inspect image metadata before using this image as a Dax target",
        }
    snapshots = [
        str(item.get("name") or item.get("id") or "")
        for item in info.get("snapshots", [])
        if isinstance(item, dict) and (item.get("name") or item.get("id"))
    ]
    return {
        "provider": "qemu_img",
        "resource_id": f"qemu-img.{_safe_id(_relative_or_name(project_root, image))}",
        "kind": "qcow2_image",
        "state": "ready" if info.get("format") == "qcow2" else "unsupported_format",
        "image": _relative_or_name(project_root, image),
        "ports": "",
        "owner": "",
        "virtual_size": info.get("virtual-size", ""),
        "actual_size": info.get("actual-size", ""),
        "snapshots": ", ".join(snapshots),
        "evidence": f"format={info.get('format', '')}",
        "cpu": "",
        "memory": "",
        "network": "offline image",
        "next_step": "request Dax claim before snapshot, restore, start, or image mutation",
    }


def _registered_runtime_depth_rows(project_root: Path, runtime_records: list[dict[str, object]]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for record in runtime_records:
        adapter = str(record.get("adapter") or "manual")
        if adapter in {"manual", "local_fixture", "qemu_img", "docker", "podman", "libvirt"}:
            continue
        rows.append(_registered_runtime_depth_row(project_root, record, adapter))
    return rows


def _registered_runtime_depth_row(project_root: Path, record: dict[str, object], adapter: str) -> dict[str, object]:
    resource_id = str(record.get("resource_id") or "runtime")
    hint = str(record.get("snapshot_hint") or "")
    target = _registered_target_path(project_root, record, adapter)
    target_exists = target.exists() if target else False
    state = str(record.get("state") or "observed")
    actual_size = _path_size(target) if target and target_exists else ""
    return {
        "provider": adapter,
        "resource_id": f"{adapter}.{_safe_id(resource_id)}",
        "kind": str(record.get("kind") or "runtime"),
        "state": state if target_exists or adapter == "android_emulator" else "target_missing",
        "image": _redact_path(hint) if hint else _relative_or_name(project_root, target) if target else "",
        "virtual_size": "",
        "actual_size": actual_size,
        "snapshots": "",
        "ports": ",".join(str(port) for port in record.get("ports") or []),
        "owner": _owner_from_notes(str(record.get("notes") or "")),
        "cpu": "running-state unknown" if state == "running" else "",
        "memory": "",
        "network": _network_from_runtime(record, adapter),
        "evidence": _runtime_depth_evidence(project_root, target, target_exists, adapter),
        "next_step": "request Dax claim before changing registered runtime state",
    }


def _registered_target_path(project_root: Path, record: dict[str, object], adapter: str) -> Path | None:
    resource_id = str(record.get("resource_id") or "")
    if adapter == "android_emulator":
        return Path.home() / ".android" / "avd" / f"{resource_id}.avd"
    hint = str(record.get("snapshot_hint") or "")
    if not hint or hint.startswith("/") or "~" in Path(hint).parts or ".." in Path(hint).parts:
        return None
    return project_root / hint


def _runtime_depth_evidence(project_root: Path, target: Path | None, target_exists: bool, adapter: str) -> str:
    if target is None:
        return "no safe project-relative snapshot_hint"
    if not target_exists:
        return "registered target path is missing"
    if adapter == "android_emulator":
        return f"avd={target.name}"
    return f"path={_relative_or_name(project_root, target)}"


def _path_size(path: Path) -> int:
    if path.is_file():
        try:
            return path.stat().st_size
        except OSError:
            return 0
    total = 0
    for child in path.rglob("*") if path.is_dir() else []:
        if not child.is_file():
            continue
        try:
            total += child.stat().st_size
        except OSError:
            continue
    return total


def _numeric_value(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    text = str(value or "").strip()
    return int(text) if text.isdigit() else 0


def _owner_from_notes(notes: str) -> str:
    lowered = notes.lower()
    if "dax" in lowered or "disposable" in lowered:
        return "dax"
    return ""


def _network_from_runtime(record: dict[str, object], adapter: str) -> str:
    ports = list(record.get("ports") or [])
    notes = str(record.get("notes") or "").lower()
    if adapter in {"qemu_process", "renode"} and ("-net none" in notes or "no network" in notes):
        return "none"
    if adapter == "gateway_proxy":
        return "loopback" if "loopback" in notes or ports else "unknown"
    if adapter == "android_emulator":
        return "emulator default"
    return "ports:" + ",".join(str(port) for port in ports) if ports else ""


def _capacity_summary(
    resources: list[Resource],
    claims: tuple[Claim, ...],
    runtime_records: list[dict[str, object]],
    runtime_inventory: list[dict[str, object]],
    port_rows: list[dict[str, object]],
) -> dict[str, object]:
    images = [_numeric_value(row.get("actual_size")) for row in runtime_inventory]
    return {
        "virtual_resources": len(resources),
        "registered_runtimes": len(runtime_records),
        "inventory_rows": len(runtime_inventory),
        "claimed_ports": len({port for claim in claims for port in claim.port_reservations}),
        "registered_ports": len({port for record in runtime_records for port in record.get("ports") or []}),
        "port_conflicts": sum(1 for row in port_rows if row["status"] == "conflict"),
        "image_actual_bytes": sum(images),
        "container_rows": sum(1 for row in runtime_inventory if row.get("kind") == "container"),
        "image_rows": sum(1 for row in runtime_inventory if row.get("kind") in {"qcow2_image", "vm"}),
        "next_step": "review conflicts, stale claims, and large images before scheduling new Dax work",
    }


def _image_provenance_rows(runtime_inventory: list[dict[str, object]]) -> list[dict[str, object]]:
    rows = []
    for item in runtime_inventory:
        image = str(item.get("image") or "")
        if not image:
            continue
        provider = str(item.get("provider") or "")
        risk = "local" if image.startswith("local-secrets") or image.endswith(".qcow2") else "external_or_registry"
        rows.append(
            {
                "provider": provider,
                "resource_id": item.get("resource_id", ""),
                "image": image,
                "state": item.get("state", ""),
                "provenance": risk,
                "evidence": item.get("evidence", ""),
                "next_step": "review image source and vulnerability scan before production use"
                if risk != "local"
                else "retain local manifest and snapshot evidence",
            }
        )
    return rows


def _provider_depth_rows(runtime_records: list[dict[str, object]], runtime_inventory: list[dict[str, object]]) -> list[dict[str, object]]:
    providers = ["docker", "podman", "libvirt", "qemu_process", "renode", "android_emulator", "gateway_proxy", "qemu_img"]
    inventory_by_provider: dict[str, int] = {}
    for row in runtime_inventory:
        provider = str(row.get("provider") or "")
        normalized = "libvirt" if provider == "virsh" else provider
        inventory_by_provider[normalized] = inventory_by_provider.get(normalized, 0) + 1
    records_by_provider: dict[str, int] = {}
    for record in runtime_records:
        provider = str(record.get("adapter") or "")
        records_by_provider[provider] = records_by_provider.get(provider, 0) + 1
    return [
        {
            "provider": provider,
            "registered_records": records_by_provider.get(provider, 0),
            "inventory_rows": inventory_by_provider.get(provider, 0),
            "snapshot_restore": "implemented" if provider in {"docker", "podman", "libvirt", "qemu_process", "renode", "android_emulator", "gateway_proxy", "qemu_img"} else "not_implemented",
            "mutation_boundary": "approved disposable targets only",
            "next_step": "add richer CPU, memory, disk, and network telemetry where provider exposes it read-only",
        }
        for provider in providers
    ]


def _run_inventory_command(command: tuple[str, ...], timeout_seconds: float = 2.0) -> dict[str, object]:
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout_seconds)
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"exit_code": -1, "stdout": "", "stderr": str(error)}
    return {
        "exit_code": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }


def _relative_or_name(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name


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
