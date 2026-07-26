"""Read-only service detail evidence for Julian's diagnostics workflows."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .core import Resource, ResourceType
from .health import HealthEvidence, HealthStatus, HealthTarget, ProbeType, summarize_health_targets
from .ops import record_operation_status
from .ops_records import OperationRecordStatus
from .store import SQLiteStore

SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)(token|secret|password|passwd|api[_-]?key|authorization)(\s*[:=]\s*)(\S+)"),
)


def service_evidence_status(
    store_path: str | Path,
    resource_id: str | None = None,
    log_tail_lines: int = 20,
) -> dict[str, object]:
    """Return service detail evidence without changing host state."""

    store = SQLiteStore(store_path)
    try:
        all_resources = store.list_resources()
        resources = [
            resource
            for resource in all_resources
            if resource.type in {ResourceType.SERVICE, ResourceType.MAINTENANCE_TARGET, ResourceType.USAGE_LIMITED_SERVICE}
            and (resource_id is None or resource.id == resource_id)
        ]
        targets = store.list_health_targets()
        evidence = store.list_health_evidence()
        plans = [plan for plan in store.list_admin_change_plans() if not plan.archived]
        executions = store.list_admin_executions()
    finally:
        store.close()

    health_by_resource = {
        summary.resource_id: summary
        for summary in summarize_health_targets(targets, evidence)
    }
    resources_by_id = {resource.id: resource for resource in all_resources}
    project_root = _project_root_for_store(store_path)
    return {
        "store": str(Path(store_path)),
        "resource_id": resource_id,
        "services": len(resources),
        "dependency_graph": _dependency_graph(resources, resources_by_id, health_by_resource),
        "items": [
            _service_detail(resource, targets, evidence, plans, executions, health_by_resource, resources_by_id, log_tail_lines)
            | {"system_journal_captures": _system_journal_capture_rows(project_root, resource.id)}
            for resource in resources
        ],
        "journal_access": _journal_access_status(resources),
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def stage_journal_access_request_status(
    store_path: str | Path,
    resource_id: str,
    unit: str = "",
    requested_by: str = "julian",
    reason: str = "system journal access needed for service diagnosis",
) -> dict[str, object]:
    """Stage a privileged journal review request without reading privileged logs."""

    safe_resource_id = _record_id_part(resource_id or unit or "service")
    unit = unit or resource_id
    return record_operation_status(
        store_path,
        record_id=f"ops.service.journal-access.{safe_resource_id}",
        kind="service_detail",
        owner_domain="julian",
        status="waiting_approval",
        subject=f"System journal access review: {resource_id or unit}",
        summary=f"Request read-only system journal evidence for {unit}. {reason}",
        severity="medium",
        resource_id=resource_id or None,
        next_step="human approval required before privileged or system journal contents are read",
        metadata={
            "requested_by": requested_by,
            "approval_required": True,
            "host_mutation_performed": False,
            "requested_access": "read-only system journal excerpt",
            "unit": unit,
            "planned_commands": [
                ["journalctl", "-u", unit, "-n", "50", "--no-pager"],
                ["journalctl", "-u", unit, "--since", "24 hours ago", "--no-pager"],
            ],
            "guardrails": [
                "redact secrets before storing excerpts",
                "bound line count and time window",
                "do not use sudo or privileged group changes without separate approval",
            ],
        },
    )


def execute_journal_access_request_status(
    store_path: str | Path,
    project_root: str | Path,
    record_id: str,
    executed_by: str = "julian",
    line_limit: int = 50,
    since: str = "24 hours ago",
    executed_at: str | None = None,
) -> dict[str, object]:
    """Execute an approved, bounded, read-only system journal capture."""

    if not executed_by.strip():
        raise ValueError("executed_by is required")
    now = executed_at or _now()
    root = Path(project_root)
    store = SQLiteStore(store_path)
    try:
        record = store.load_operation_record(record_id)
    finally:
        store.close()
    metadata = dict(record.metadata)
    unit = str(metadata.get("unit") or "")
    try:
        _validate_journal_capture_ready(record_id, record.status, metadata, unit)
        bounded_line_limit = min(max(1, int(line_limit)), 200)
        capture = _capture_system_journal(root, record_id, unit, bounded_line_limit, since, now)
    except (ValueError, OSError) as error:
        summary = _redact_text(str(error))
        result = _journal_capture_result(record_id, unit, now, "blocked", executed_by, line_limit, since, [], "", summary)
        _write_journal_capture(root, result)
        metadata.update(
            {
                "execution_status": "blocked",
                "execution_error": summary,
                "executed_by": executed_by,
                "executed_at": now,
                "journal_capture_result_id": result["id"],
                "journal_capture_path": result["capture_path"],
            }
        )
        updated = record_operation_status(
            store_path,
            record_id=record.id,
            kind=record.kind.value,
            owner_domain=record.owner_domain.value,
            status=OperationRecordStatus.BLOCKED.value,
            subject=record.subject,
            summary=record.summary,
            severity=record.severity.value,
            resource_id=record.resource_id,
            evidence_ids=(*record.evidence_ids, str(result["id"])),
            next_step="review blocked system journal capture and resolve access or request scope before retrying",
            metadata=metadata,
        )
        return {
            "record": updated["record"],
            "capture": result,
            "status": "blocked",
            "summary": summary,
            "mutation_performed": True,
            "host_mutation_performed": False,
        }

    metadata.update(
        {
            "execution_status": "completed",
            "executed_by": executed_by,
            "executed_at": now,
            "journal_capture_result_id": capture["id"],
            "journal_capture_path": capture["capture_path"],
            "captured_lines": capture["captured_lines"],
        }
    )
    updated = record_operation_status(
        store_path,
        record_id=record.id,
        kind=record.kind.value,
        owner_domain=record.owner_domain.value,
        status=OperationRecordStatus.VERIFIED.value,
        subject=record.subject,
        summary=record.summary,
        severity=record.severity.value,
        resource_id=record.resource_id,
        evidence_ids=(*record.evidence_ids, str(capture["id"])),
        next_step="system journal evidence captured; review redacted excerpt and continue service diagnosis",
        metadata=metadata,
    )
    return {
        "record": updated["record"],
        "capture": capture,
        "status": "completed",
        "mutation_performed": True,
        "host_mutation_performed": False,
    }


def _service_detail(
    resource: Resource,
    targets: Sequence[HealthTarget],
    evidence: Sequence[HealthEvidence],
    plans: Sequence[Any],
    executions: Sequence[Any],
    health_by_resource: Mapping[str, Any],
    resources_by_id: Mapping[str, Resource],
    log_tail_lines: int,
) -> dict[str, object]:
    unit = _systemd_unit_for(resource)
    health = health_by_resource.get(resource.id)
    resource_targets = [target for target in targets if target.resource_id == resource.id]
    resource_evidence = [item for item in evidence if item.resource_id == resource.id]
    service_plans = [plan for plan in plans if plan.target == resource.id or resource.id in plan.current_state]
    service_executions = [
        execution
        for execution in executions
        if any(plan.id == execution.plan_id for plan in service_plans)
    ]
    return {
        "resource_id": resource.id,
        "name": resource.name,
        "state": resource.state.value,
        "risk": resource.risk_level.value,
        "unit": unit or "",
        "journal_scope": _journal_scope(resource),
        "systemd": _systemd_show(unit) if unit else {"available": False, "reason": "no unit identifier"},
        "dependencies": sorted(resource.dependencies),
        "dependency_health": _dependency_health_rows(resource, resources_by_id, health_by_resource),
        "config_paths": _redacted_paths(resource.identifiers.get("config_paths", ())),
        "environment_paths": _redacted_paths(resource.identifiers.get("environment_paths", ())),
        "health": health.latest_status.value if health else HealthStatus.UNKNOWN.value,
        "health_error": _redact_text(health.error if health else "missing health target or evidence"),
        "health_targets": [_health_target_row(target) for target in resource_targets],
        "recent_evidence": [_health_evidence_row(item) for item in sorted(resource_evidence, key=lambda value: value.captured_at or value.id, reverse=True)[:10]],
        "log_evidence": _log_evidence(resource_targets, log_tail_lines),
        "journal_excerpt": _journal_excerpt(unit, log_tail_lines) if unit else {"available": False, "reason": "no unit identifier", "sample": []},
        "system_journal_request": _system_journal_request_row(resource, unit) if unit and _journal_scope(resource) == "system" else {},
        "admin_plans": [_admin_plan_row(plan) for plan in service_plans],
        "executions": len(service_executions),
        "validation_checklist": _validation_checklist(resource, health, service_plans),
        "next_step": _next_step(health, service_plans),
    }


def _dependency_graph(
    resources: Sequence[Resource],
    resources_by_id: Mapping[str, Resource],
    health_by_resource: Mapping[str, Any],
) -> dict[str, object]:
    node_ids = set()
    edges = []
    for resource in resources:
        node_ids.add(resource.id)
        for dependency_id in sorted(resource.dependencies):
            node_ids.add(dependency_id)
            dependency = resources_by_id.get(dependency_id)
            health = health_by_resource.get(dependency_id)
            edges.append(
                {
                    "from": resource.id,
                    "to": dependency_id,
                    "known": dependency is not None,
                    "owner_domain": dependency.owner_domain.value if dependency else "unknown",
                    "health": health.latest_status.value if health else HealthStatus.UNKNOWN.value,
                    "risk": dependency.risk_level.value if dependency else "unknown",
                }
            )
    return {
        "nodes": [_dependency_node(node_id, resources_by_id.get(node_id), health_by_resource.get(node_id)) for node_id in sorted(node_ids)],
        "edges": edges,
        "missing_dependencies": sorted(edge["to"] for edge in edges if not edge["known"]),
        "unhealthy_dependencies": sorted(
            edge["to"]
            for edge in edges
            if edge["health"] in {HealthStatus.DEGRADED.value, HealthStatus.FAILED.value, HealthStatus.UNKNOWN.value}
        ),
    }


def _dependency_node(resource_id: str, resource: Resource | None, health: Any | None) -> dict[str, object]:
    return {
        "resource_id": resource_id,
        "known": resource is not None,
        "name": resource.name if resource else "",
        "type": resource.type.value if resource else "unknown",
        "owner_domain": resource.owner_domain.value if resource else "unknown",
        "risk": resource.risk_level.value if resource else "unknown",
        "health": health.latest_status.value if health else HealthStatus.UNKNOWN.value,
    }


def _dependency_health_rows(
    resource: Resource,
    resources_by_id: Mapping[str, Resource],
    health_by_resource: Mapping[str, Any],
) -> list[dict[str, object]]:
    return [
        {
            "resource_id": dependency_id,
            "known": resources_by_id.get(dependency_id) is not None,
            "owner_domain": resources_by_id[dependency_id].owner_domain.value if dependency_id in resources_by_id else "unknown",
            "risk": resources_by_id[dependency_id].risk_level.value if dependency_id in resources_by_id else "unknown",
            "health": health_by_resource[dependency_id].latest_status.value if dependency_id in health_by_resource else HealthStatus.UNKNOWN.value,
            "next_step": _dependency_next_step(dependency_id, resources_by_id, health_by_resource),
        }
        for dependency_id in sorted(resource.dependencies)
    ]


def _dependency_next_step(
    dependency_id: str,
    resources_by_id: Mapping[str, Resource],
    health_by_resource: Mapping[str, Any],
) -> str:
    if dependency_id not in resources_by_id:
        return "register dependency resource before approving service changes"
    health = health_by_resource.get(dependency_id)
    if health is None or health.latest_status == HealthStatus.UNKNOWN:
        return "add or run dependency health probe before approving service changes"
    if health.latest_status in {HealthStatus.DEGRADED, HealthStatus.FAILED}:
        return "stage dependency recovery before dependent service changes"
    return "dependency ready for impact review"


def _systemd_unit_for(resource: Resource) -> str:
    identifiers = resource.identifiers
    for key in ("unit", "service", "systemd_unit"):
        value = identifiers.get(key)
        if isinstance(value, str) and value:
            return value
    prefix = "svc.systemd-user."
    if resource.id.startswith(prefix):
        unit = resource.id.removeprefix(prefix)
        return unit if unit.endswith(".service") else f"{unit}.service"
    return ""


def _journal_scope(resource: Resource) -> str:
    for key in ("journal_scope", "systemd_scope", "scope"):
        value = resource.identifiers.get(key)
        if isinstance(value, str) and value in {"user", "system"}:
            return value
    return "user" if resource.id.startswith("svc.systemd-user.") else "system"


def _journal_access_status(resources: Sequence[Resource]) -> dict[str, object]:
    journalctl_available = shutil.which("journalctl") is not None
    user_access = _journal_access_probe(("journalctl", "--user", "-n", "0", "--no-pager")) if journalctl_available else _missing_command_probe()
    system_access = _journal_access_probe(("journalctl", "-n", "0", "--no-pager")) if journalctl_available else _missing_command_probe()
    system_requests = []
    for resource in resources:
        unit = _systemd_unit_for(resource)
        if unit and _journal_scope(resource) == "system":
            system_requests.append(_system_journal_request_row(resource, unit))
    return {
        "journalctl_available": journalctl_available,
        "user_journal_access": user_access,
        "system_journal_access": system_access,
        "system_access_currently_available": system_access["available"],
        "system_review_requests": system_requests,
        "next_step": "stage journal access request for any system service needing privileged log evidence",
    }


def _journal_access_probe(command: tuple[str, ...]) -> dict[str, object]:
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=1.5)
    except subprocess.TimeoutExpired:
        return {"available": False, "exit_code": None, "reason": "journalctl timed out"}
    return {
        "available": completed.returncode == 0,
        "exit_code": completed.returncode,
        "reason": _redact_text(completed.stderr.strip()),
    }


def _missing_command_probe() -> dict[str, object]:
    return {"available": False, "exit_code": None, "reason": "journalctl not found"}


def _system_journal_request_row(resource: Resource, unit: str) -> dict[str, object]:
    return {
        "resource_id": resource.id,
        "unit": unit,
        "scope": _journal_scope(resource),
        "approval_required": True,
        "status": "needs_approval",
        "next_step": "stage read-only system journal access request",
    }


def _systemd_show(unit: str) -> dict[str, object]:
    command = (
        "systemctl",
        "--user",
        "show",
        unit,
        "--property=Id,LoadState,ActiveState,SubState,FragmentPath,DropInPaths,WantedBy,Names,NRestarts",
        "--no-pager",
    )
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=1.5)
    except FileNotFoundError:
        return {"available": False, "reason": "systemctl not found"}
    except subprocess.TimeoutExpired:
        return {"available": False, "reason": "systemctl timed out"}
    values: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = _redact_text(value)
    return {
        "available": completed.returncode == 0,
        "exit_code": completed.returncode,
        "unit": unit,
        "load_state": values.get("LoadState", ""),
        "active_state": values.get("ActiveState", ""),
        "sub_state": values.get("SubState", ""),
        "fragment": _redact_path(values.get("FragmentPath", "")),
        "drop_ins": _redact_path(values.get("DropInPaths", "")),
        "restart_count": values.get("NRestarts", ""),
    }


def _log_evidence(targets: Sequence[HealthTarget], log_tail_lines: int) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for target in targets:
        if target.probe_type != ProbeType.LOG:
            continue
        path = Path(target.target)
        row: dict[str, object] = {
            "target_id": target.id,
            "path": _redact_path(target.target),
            "readable": False,
            "lines": 0,
            "sample": [],
        }
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            row["error"] = _redact_text(str(exc))
        else:
            tail = [_redact_text(line) for line in lines[-max(0, log_tail_lines):]]
            row.update({"readable": True, "lines": len(lines), "sample": tail})
        rows.append(row)
    return rows


def _journal_excerpt(unit: str, log_tail_lines: int) -> dict[str, object]:
    command = ("journalctl", "--user", "-u", unit, "-n", str(max(1, log_tail_lines)), "--no-pager")
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=2.0)
    except FileNotFoundError:
        return {"available": False, "reason": "journalctl not found", "sample": []}
    except subprocess.TimeoutExpired:
        return {"available": False, "reason": "journalctl timed out", "sample": []}
    lines = [_redact_text(line) for line in completed.stdout.splitlines() if line.strip()]
    return {
        "available": completed.returncode == 0,
        "exit_code": completed.returncode,
        "unit": unit,
        "sample": lines[-max(1, log_tail_lines):],
        "error": _redact_text(completed.stderr.strip()),
    }


def _validate_journal_capture_ready(record_id: str, status: OperationRecordStatus, metadata: Mapping[str, object], unit: str) -> None:
    if not record_id.startswith("ops.service.journal-access."):
        raise ValueError("record is not a system journal access request")
    if metadata.get("requested_access") != "read-only system journal excerpt":
        raise ValueError("record does not carry a system journal access scope")
    if status not in {OperationRecordStatus.IN_PROGRESS, OperationRecordStatus.VERIFIED}:
        raise ValueError("system journal access request must be approved by transitioning it to in_progress before execution")
    if not unit.strip():
        raise ValueError("system journal unit is required")
    if not re.fullmatch(r"[A-Za-z0-9_.@:-]+\.service", unit.strip()):
        raise ValueError("system journal unit must be a systemd service unit name")


def _capture_system_journal(root: Path, record_id: str, unit: str, line_limit: int, since: str, captured_at: str) -> dict[str, object]:
    journalctl = shutil.which("journalctl")
    if journalctl is None:
        raise ValueError("journalctl not found")
    command = (
        journalctl,
        "-u",
        unit,
        "-n",
        str(line_limit),
        "--since",
        since,
        "--no-pager",
        "--output=short-iso",
    )
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=5.0)
    except subprocess.TimeoutExpired as error:
        raise ValueError("journalctl timed out") from error
    except OSError as error:
        raise ValueError(f"journalctl failed to start: {error}") from error
    if completed.returncode != 0:
        error_text = completed.stderr.strip() or completed.stdout.strip() or f"exit {completed.returncode}"
        raise ValueError(f"journalctl failed: {_redact_text(error_text[-500:])}")
    lines = [_redact_text(line) for line in completed.stdout.splitlines() if line.strip()]
    return _write_journal_capture(
        root,
        _journal_capture_result(record_id, unit, captured_at, "completed", "", line_limit, since, lines, "", ""),
    )


def _journal_capture_result(
    record_id: str,
    unit: str,
    captured_at: str,
    status: str,
    executed_by: str,
    line_limit: int,
    since: str,
    lines: Sequence[str],
    capture_path: str,
    error: str,
) -> dict[str, object]:
    bounded = list(lines)[-min(max(1, int(line_limit)), 200):]
    return {
        "id": f"journal-capture.{_record_id_part(record_id)}.{_record_id_part(captured_at)}",
        "record_id": record_id,
        "unit": unit,
        "status": status,
        "captured_at": captured_at,
        "executed_by": executed_by,
        "requested_lines": min(max(1, int(line_limit)), 200),
        "since": since,
        "captured_lines": len(bounded),
        "sample": bounded,
        "capture_path": capture_path,
        "execution_error": _redact_text(error),
        "next_step": "review redacted journal evidence" if status == "completed" else "resolve journal access before retrying",
    }


def _write_journal_capture(root: Path, result: dict[str, object]) -> dict[str, object]:
    capture_dir = root / "local-secrets" / "journal-captures"
    capture_dir.mkdir(parents=True, exist_ok=True)
    path = capture_dir / f"{_record_id_part(str(result['id']))}.json"
    result = dict(result)
    result["capture_path"] = _relative_or_name(root, path)
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def _system_journal_capture_rows(project_root: Path, resource_id: str) -> list[dict[str, object]]:
    safe_resource_id = _record_id_part(resource_id)
    capture_dir = project_root / "local-secrets" / "journal-captures"
    if not capture_dir.exists():
        return []
    rows = []
    for path in sorted(capture_dir.glob(f"journal-capture.ops.service.journal-access.{safe_resource_id}.*.json"))[-5:]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        rows.append(
            {
                "id": str(payload.get("id") or path.stem),
                "unit": str(payload.get("unit") or ""),
                "status": str(payload.get("status") or ""),
                "captured_at": str(payload.get("captured_at") or ""),
                "captured_lines": int(payload.get("captured_lines") or 0),
                "capture_path": str(payload.get("capture_path") or str(path)),
                "next_step": str(payload.get("next_step") or "review redacted journal evidence"),
            }
        )
    return rows


def _validation_checklist(resource: Resource, health: Any | None, plans: Sequence[Any]) -> list[dict[str, object]]:
    latest_plan = sorted(plans, key=lambda item: item.created_at or item.id)[-1] if plans else None
    return [
        {"step": "confirm service identity", "status": "ready" if _systemd_unit_for(resource) else "needs_unit_metadata"},
        {"step": "review latest health evidence", "status": "ready" if health and health.latest_status != HealthStatus.UNKNOWN else "needs_probe"},
        {"step": "review redacted logs", "status": "ready"},
        {"step": "verify dependency impact", "status": "ready" if resource.dependencies else "no_dependencies_recorded"},
        {"step": "confirm rollback path", "status": "ready" if latest_plan and latest_plan.rollback_steps else "needs_plan"},
        {"step": "run post-change validation", "status": "ready" if latest_plan and latest_plan.verification_steps else "needs_plan"},
    ]


def _next_step(health: Any | None, plans: Sequence[Any]) -> str:
    if not health or health.latest_status == HealthStatus.UNKNOWN:
        return "register or run a health probe before approving service work"
    if health.recovery_required and not plans:
        return "stage an approval-gated service recovery plan"
    if health.recovery_required:
        return "review staged service plan, rollback, and validation evidence"
    return "continue periodic health monitoring"


def _health_target_row(target: HealthTarget) -> dict[str, object]:
    return {
        "target_id": target.id,
        "probe_type": target.probe_type.value,
        "target": _redact_path(target.target),
        "expected_status": target.expected_status,
        "expected_content_type": target.expected_content_type,
        "latency_warn_ms": target.latency_warn_ms,
    }


def _health_evidence_row(evidence: HealthEvidence) -> dict[str, object]:
    return {
        "id": evidence.id,
        "target": _redact_path(evidence.target),
        "probe_type": evidence.probe_type.value,
        "status": evidence.observed_status.value,
        "recovery_required": evidence.recovery_required,
        "error": _redact_text(evidence.observed_error),
        "captured_at": evidence.captured_at,
    }


def _admin_plan_row(plan: Any) -> dict[str, object]:
    return {
        "id": plan.id,
        "kind": plan.kind.value,
        "approved": plan.approved,
        "canceled": plan.canceled,
        "rollback": "present" if plan.rollback_steps else "missing",
        "verification": "present" if plan.verification_steps else "missing",
    }


def _redacted_paths(value: object) -> list[str]:
    if isinstance(value, str):
        return [_redact_path(value)]
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_redact_path(str(item)) for item in value]
    return []


def _redact_path(value: str) -> str:
    if not value:
        return ""
    path = Path(value)
    if value.startswith("/"):
        return f".../{path.name}" if path.name else "local-path"
    return value


def _redact_text(value: str) -> str:
    redacted = value
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(lambda match: f"{match.group(1)}{match.group(2) if len(match.groups()) > 1 else ''}[redacted]", redacted)
    return redacted


def _record_id_part(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "-", value.strip()).strip("-")
    return cleaned or "service"


def _relative_or_name(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _project_root_for_store(store_path: str | Path) -> Path:
    path = Path(store_path)
    if path.parent.name == "state":
        return path.parent.parent
    return path.parent
