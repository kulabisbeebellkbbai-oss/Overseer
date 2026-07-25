"""Staged identity, SSH key, and secret rotation requests for Odo."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path


def identity_rotation_requests_status(project_root: str | Path) -> dict[str, object]:
    root = Path(project_root)
    data = _read_registry(root)
    return {
        "root": str(root),
        "requests": data["requests"],
        "request_count": len(data["requests"]),
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def stage_identity_rotation_request_status(
    project_root: str | Path,
    subject: str,
    subject_type: str = "secret",
    requested_by: str = "odo",
    reason: str = "stage identity or secret rotation review",
    urgency: str = "medium",
) -> dict[str, object]:
    root = Path(project_root)
    data = _read_registry(root)
    now = _now()
    request_id = f"identity-rotation.{_safe_id(subject_type)}.{_safe_id(subject)}"
    row = {
        "id": request_id,
        "subject": _redact_subject(subject),
        "subject_type": subject_type,
        "requested_by": requested_by,
        "reason": reason,
        "urgency": urgency,
        "status": "waiting_approval",
        "approval_required": True,
        "created_at": now,
        "updated_at": now,
        "guardrails": [
            "do not disclose, copy, print, or commit secret material",
            "verify dependent services and rollback before credential changes",
            "do not change users, groups, SSH keys, API keys, service accounts, or token files without explicit approval",
        ],
        "next_step": "human approval required before rotating credentials or changing account access",
    }
    _upsert(data["requests"], row)
    _write_registry(root, data)
    return {"request": row, "mutation_performed": True, "host_mutation_performed": False}


def _registry_path(root: Path) -> Path:
    return root / "state" / "identity-rotation-requests.json"


def _read_registry(root: Path) -> dict[str, list[dict[str, object]]]:
    path = _registry_path(root)
    if not path.exists():
        return {"requests": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"requests": []}
    return {"requests": list(data.get("requests") or [])}


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


def _safe_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value).strip()).strip("-")
    return cleaned or "item"


def _redact_subject(value: str) -> str:
    text = str(value).strip()
    if not text:
        return "unspecified"
    if "/" in text:
        path = Path(text)
        if text.startswith("/"):
            return f".../{path.name}" if path.name else "local-path"
    if len(text) > 80:
        return f"{text[:77]}..."
    return text


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
