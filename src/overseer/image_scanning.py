"""Dax container image vulnerability scan planning and evidence."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path


def image_scan_status(project_root: str | Path) -> dict[str, object]:
    root = Path(project_root)
    data = _read_registry(root)
    return {
        "root": str(root),
        "scanner_adapters": _scanner_adapter_rows(),
        "scan_requests": data["scan_requests"],
        "scan_request_count": len(data["scan_requests"]),
        "scan_results": data["scan_results"],
        "scan_result_count": len(data["scan_results"]),
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def stage_image_scan_request_status(
    project_root: str | Path,
    image: str,
    provider: str = "docker",
    scanner: str = "trivy",
    requested_by: str = "dax",
    reason: str = "scan container image before production use",
) -> dict[str, object]:
    root = Path(project_root)
    data = _read_registry(root)
    now = _now()
    cleaned_image = _safe_image_ref(image)
    row = {
        "id": f"image-scan.{_safe_id(provider)}.{_safe_id(cleaned_image)}",
        "image": cleaned_image,
        "provider": _safe_id(provider),
        "scanner": _safe_id(scanner),
        "requested_by": requested_by,
        "reason": reason,
        "status": "waiting_approval",
        "approval_required": True,
        "created_at": now,
        "updated_at": now,
        "guardrails": [
            "scan only declared container image references",
            "do not pull, run, remove, or mutate containers during scan execution",
            "keep raw scanner JSON under local-secrets and expose only counts and finding summaries",
        ],
        "next_step": "Sisko approval required before invoking the image scanner",
    }
    _upsert(data["scan_requests"], row)
    _write_registry(root, data)
    return {"scan_request": row, "mutation_performed": True, "host_mutation_performed": False}


def approve_image_scan_request_status(
    project_root: str | Path,
    request_id: str,
    approved_by: str = "sisko",
    approved_at: str | None = None,
) -> dict[str, object]:
    if not approved_by.strip():
        raise ValueError("approved_by is required")
    root = Path(project_root)
    data = _read_registry(root)
    row = _find_request(data, request_id)
    if row.get("status") not in {"waiting_approval", "blocked"}:
        raise ValueError(f"image scan request is not approvable: {row.get('status')}")
    now = approved_at or _now()
    row.update(
        {
            "status": "approved",
            "approved_by": approved_by,
            "approved_at": now,
            "updated_at": now,
            "next_step": "execute approved read-only image scan",
        }
    )
    _write_registry(root, data)
    return {"scan_request": row, "mutation_performed": True, "host_mutation_performed": False}


def execute_image_scan_request_status(
    project_root: str | Path,
    request_id: str,
    executed_by: str = "dax",
    executed_at: str | None = None,
) -> dict[str, object]:
    if not executed_by.strip():
        raise ValueError("executed_by is required")
    root = Path(project_root)
    data = _read_registry(root)
    row = _find_request(data, request_id)
    now = executed_at or _now()
    try:
        _validate_request_ready(row)
        result = _execute_trivy_image_scan(root, row, now)
    except ValueError as error:
        row.update(
            {
                "status": "blocked",
                "executed_by": executed_by,
                "executed_at": now,
                "updated_at": now,
                "execution_error": str(error),
                "next_step": "install or configure the approved image scanner before retrying",
            }
        )
        result = _scan_result(row, now, "blocked", str(error), {}, "")
        _upsert(data["scan_results"], result)
        _write_registry(root, data)
        return {
            "scan_request": row,
            "scan_result": result,
            "status": "blocked",
            "summary": str(error),
            "mutation_performed": True,
            "host_mutation_performed": False,
        }
    row.update(
        {
            "status": "completed",
            "executed_by": executed_by,
            "executed_at": now,
            "updated_at": now,
            "result_id": result["id"],
            "next_step": result["next_step"],
        }
    )
    _upsert(data["scan_results"], result)
    _write_registry(root, data)
    return {
        "scan_request": row,
        "scan_result": result,
        "status": "completed",
        "mutation_performed": True,
        "host_mutation_performed": False,
    }


def parse_trivy_image_scan(output: str) -> dict[str, object]:
    try:
        payload = json.loads(output or "{}")
    except json.JSONDecodeError as error:
        raise ValueError(f"trivy returned invalid JSON: {error}") from error
    findings: list[dict[str, object]] = []
    for result in payload.get("Results") or []:
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target") or "")
        for vuln in result.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            findings.append(
                {
                    "target": target,
                    "vulnerability_id": str(vuln.get("VulnerabilityID") or ""),
                    "pkg_name": str(vuln.get("PkgName") or ""),
                    "installed_version": str(vuln.get("InstalledVersion") or ""),
                    "fixed_version": str(vuln.get("FixedVersion") or ""),
                    "severity": _severity(str(vuln.get("Severity") or "UNKNOWN")),
                    "title": _short(str(vuln.get("Title") or vuln.get("Description") or "")),
                    "primary_url": str(vuln.get("PrimaryURL") or ""),
                }
            )
    return {
        "finding_count": len(findings),
        "by_severity": _severity_counts(findings),
        "findings": sorted(findings, key=_finding_sort_key),
    }


def _execute_trivy_image_scan(root: Path, row: dict[str, object], executed_at: str) -> dict[str, object]:
    scanner = str(row.get("scanner") or "trivy")
    if scanner != "trivy":
        raise ValueError(f"image scanner is not implemented: {scanner}")
    trivy = shutil.which("trivy")
    if trivy is None:
        raise ValueError("trivy scanner is not installed")
    image = _safe_image_ref(str(row.get("image") or ""))
    command = (
        trivy,
        "image",
        "--format",
        "json",
        "--quiet",
        "--no-progress",
        "--scanners",
        "vuln",
        image,
    )
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=300.0)
    except subprocess.TimeoutExpired as error:
        raise ValueError("trivy image scan timed out") from error
    except OSError as error:
        raise ValueError(f"trivy failed to start: {error}") from error
    if completed.returncode not in {0, 1}:
        stderr = completed.stderr.strip() or completed.stdout.strip() or f"exit {completed.returncode}"
        raise ValueError(f"trivy image scan failed: {stderr[-500:]}")
    parsed = parse_trivy_image_scan(completed.stdout)
    raw_path = _write_raw_scan(root, row, completed.stdout, executed_at)
    return _scan_result(row, executed_at, "completed", "", parsed, raw_path)


def _scan_result(
    row: dict[str, object],
    scanned_at: str,
    status: str,
    error: str,
    parsed: dict[str, object],
    raw_path: str,
) -> dict[str, object]:
    counts = dict(parsed.get("by_severity") or {})
    finding_count = int(parsed.get("finding_count") or 0)
    return {
        "id": f"image-scan-result.{_safe_id(str(row.get('id') or 'request'))}.{_safe_id(scanned_at)}",
        "request_id": row.get("id", ""),
        "image": row.get("image", ""),
        "provider": row.get("provider", ""),
        "scanner": row.get("scanner", "trivy"),
        "status": status,
        "scanned_at": scanned_at,
        "finding_count": finding_count,
        "critical": int(counts.get("CRITICAL", 0)),
        "high": int(counts.get("HIGH", 0)),
        "medium": int(counts.get("MEDIUM", 0)),
        "low": int(counts.get("LOW", 0)),
        "unknown": int(counts.get("UNKNOWN", 0)),
        "findings": list(parsed.get("findings") or [])[:50],
        "raw_result_path": raw_path,
        "execution_error": error,
        "next_step": _scan_next_step(status, finding_count, counts, error),
    }


def _scan_next_step(status: str, finding_count: int, counts: dict[str, object], error: str) -> str:
    if status != "completed":
        return error or "resolve scanner setup before retrying"
    if int(counts.get("CRITICAL", 0)) or int(counts.get("HIGH", 0)):
        return "route critical or high image findings to Odo and O'Brien before production use"
    if finding_count:
        return "review image findings and schedule remediation before production use"
    return "image scan clean; retain evidence with Dax runtime record"


def _write_raw_scan(root: Path, row: dict[str, object], output: str, scanned_at: str) -> str:
    scan_dir = root / "local-secrets" / "image-scans"
    scan_dir.mkdir(parents=True, exist_ok=True)
    path = scan_dir / f"{_safe_id(str(row.get('id') or 'scan'))}-{_safe_id(scanned_at)}.json"
    path.write_text(output, encoding="utf-8")
    return _relative_or_name(root, path)


def _scanner_adapter_rows() -> list[dict[str, object]]:
    trivy = shutil.which("trivy")
    return [
        {
            "scanner": "trivy",
            "available": trivy is not None,
            "path": trivy or "",
            "status": "available_for_approved_image_scans" if trivy else "missing",
            "mutation_boundary": "read-only image scan execution requires approved image scan request",
            "next_step": "execute approved scan requests" if trivy else "stage approved Trivy installation via O'Brien",
        }
    ]


def _validate_request_ready(row: dict[str, object]) -> None:
    if row.get("status") != "approved":
        raise ValueError("image scan request must be approved before execution")
    if not row.get("approved_by"):
        raise ValueError("image scan request approval metadata is missing")


def _registry_path(root: Path) -> Path:
    return root / "state" / "image-scans.json"


def _read_registry(root: Path) -> dict[str, list[dict[str, object]]]:
    path = _registry_path(root)
    empty = {"scan_requests": [], "scan_results": []}
    if not path.exists():
        return empty
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return empty
    return {
        "scan_requests": list(data.get("scan_requests") or []),
        "scan_results": list(data.get("scan_results") or []),
    }


def _write_registry(root: Path, data: dict[str, object]) -> None:
    path = _registry_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _find_request(data: dict[str, list[dict[str, object]]], request_id: str) -> dict[str, object]:
    cleaned = _safe_id(request_id.removeprefix("image-scan."))
    candidates = {request_id, f"image-scan.{cleaned}"}
    for row in data["scan_requests"]:
        if row.get("id") in candidates:
            return row
    raise ValueError(f"image scan request does not exist: {request_id}")


def _upsert(rows: list[dict[str, object]], row: dict[str, object]) -> None:
    existing = next((index for index, item in enumerate(rows) if item["id"] == row["id"]), None)
    if existing is None:
        rows.append(row)
        return
    row["created_at"] = rows[existing].get("created_at") or row.get("created_at")
    rows[existing] = row


def _safe_image_ref(value: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("image is required")
    if any(part in cleaned for part in ("\x00", "\n", "\r", ";", "|", "&", "$", "`", "<", ">")):
        raise ValueError("image reference contains unsupported shell metacharacters")
    return cleaned


def _safe_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value).strip()).strip("-")
    return cleaned or "item"


def _severity(value: str) -> str:
    cleaned = value.upper()
    return cleaned if cleaned in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"} else "UNKNOWN"


def _severity_counts(findings: list[dict[str, object]]) -> dict[str, int]:
    counts = {severity: 0 for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")}
    for finding in findings:
        counts[_severity(str(finding.get("severity") or "UNKNOWN"))] += 1
    return counts


def _finding_sort_key(item: dict[str, object]) -> tuple[int, str, str]:
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    return (rank.get(str(item.get("severity") or "UNKNOWN"), 4), str(item.get("pkg_name") or ""), str(item.get("vulnerability_id") or ""))


def _short(value: str, limit: int = 220) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "..."


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _relative_or_name(root: Path, path: Path | None) -> str:
    if path is None:
        return ""
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name
