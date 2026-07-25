"""Read-only compliance, policy, and local-secret guard evidence."""

from __future__ import annotations

from pathlib import Path
import json

from .audit import ApprovalStatus
from .store import SQLiteStore


def compliance_evidence_status(store_path: str | Path, project_root: str | Path | None = None) -> dict[str, object]:
    root = Path(project_root or Path.cwd())
    store = SQLiteStore(store_path)
    try:
        approvals = store.list_approvals()
        plans = store.list_admin_change_plans()
        audit_count = store.count_audit_events()
    finally:
        store.close()
    return {
        "store": str(Path(store_path)),
        "root": str(root),
        "policy_exceptions": [
            {
                "approval_id": approval.id,
                "subject_id": approval.subject_id,
                "status": approval.status.value,
                "level": approval.approval_level.value,
                "owner_domain": approval.owner_domain.value,
            }
            for approval in approvals
            if "policy.warning" in approval.subject_id or approval.status == ApprovalStatus.PENDING
        ],
        "desired_state": _desired_state_rows(root),
        "desired_state_drift": _desired_state_drift_rows(root),
        "local_secret_guards": _local_secret_guard_rows(root),
        "evidence_matrix": [
            {"area": "approvals", "records": len(approvals), "status": "attention" if any(item.status == ApprovalStatus.PENDING for item in approvals) else "ready"},
            {"area": "admin plans", "records": len(plans), "status": "ready"},
            {"area": "audit events", "records": audit_count, "status": "ready"},
        ],
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def _desired_state_rows(root: Path) -> list[dict[str, object]]:
    return [
        {"area": "policy profile", "path": "config/overseer-policy.json", "present": (root / "config" / "overseer-policy.json").exists(), "status": "baseline_or_default"},
        {"area": "git ignore", "path": ".gitignore", "present": (root / ".gitignore").exists(), "status": "review_local_only_patterns"},
        {"area": "runbooks", "path": "docs/operator-workflows.md", "present": (root / "docs" / "operator-workflows.md").exists(), "status": "required"},
    ]


def _local_secret_guard_rows(root: Path) -> list[dict[str, object]]:
    gitignore = root / ".gitignore"
    try:
        text = gitignore.read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = ""
    required = ("local-secrets/", "state/api-token", "*.sqlite3", "*.db")
    return [
        {
            "pattern": pattern,
            "present": pattern in text,
            "status": "ready" if pattern in text else "missing",
        }
        for pattern in required
    ]


def _desired_state_drift_rows(root: Path) -> list[dict[str, object]]:
    path = root / "config" / "desired-state.json"
    if not path.exists():
        return [{"area": "desired-state", "path": "config/desired-state.json", "status": "missing", "next_step": "create baseline before drift enforcement"}]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [{"area": "desired-state", "path": "config/desired-state.json", "status": "invalid", "next_step": "repair baseline JSON"}]
    checks = data.get("checks", [])
    if not isinstance(checks, list):
        checks = []
    rows = [_desired_state_check_row(root, check) for check in checks if isinstance(check, dict)]
    return rows or [{"area": "desired-state", "path": "config/desired-state.json", "status": "empty", "next_step": "add desired checks"}]


def _desired_state_check_row(root: Path, check: dict[str, object]) -> dict[str, object]:
    area = str(check.get("area") or "unknown")
    kind = str(check.get("kind") or "unknown")
    raw_path = str(check.get("path") or "")
    row: dict[str, object] = {
        "area": area,
        "kind": kind,
        "path": raw_path,
        "expected": check.get("expected", True),
    }
    target = _safe_project_path(root, raw_path)
    if target is None:
        return {
            **row,
            "actual": "blocked",
            "status": "invalid",
            "next_step": "use a relative project path inside the Overseer root",
        }
    if kind == "file_exists":
        actual = target.is_file()
        return {**row, "actual": actual, "status": _drift_status(actual is bool(check.get("expected", True))), "next_step": _drift_next_step(actual, "restore required file")}
    if kind == "directory_exists":
        actual = target.is_dir()
        return {**row, "actual": actual, "status": _drift_status(actual is bool(check.get("expected", True))), "next_step": _drift_next_step(actual, "restore required directory")}
    if kind == "gitignore_contains":
        pattern = str(check.get("pattern") or "")
        actual = _file_contains(target, pattern)
        return {**row, "pattern": pattern, "actual": actual, "status": _drift_status(actual), "next_step": _drift_next_step(actual, "add required gitignore guard")}
    if kind == "json_valid":
        actual = _json_file_valid(target)
        return {**row, "actual": actual, "status": _drift_status(actual), "next_step": _drift_next_step(actual, "repair JSON baseline")}
    return {**row, "actual": "unsupported", "status": "unsupported", "next_step": "use a supported desired-state check kind"}


def _safe_project_path(root: Path, raw_path: str) -> Path | None:
    if not raw_path or raw_path.startswith("~"):
        return None
    candidate = Path(raw_path)
    if candidate.is_absolute() or ".." in candidate.parts:
        return None
    resolved_root = root.resolve()
    resolved_candidate = (root / candidate).resolve()
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError:
        return None
    return resolved_candidate


def _file_contains(path: Path, pattern: str) -> bool:
    if not path.is_file() or not pattern:
        return False
    try:
        return pattern in path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False


def _json_file_valid(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return True


def _drift_status(ok: bool) -> str:
    return "ok" if ok else "drift"


def _drift_next_step(ok: bool, action: str) -> str:
    return "continue monitoring desired state" if ok else action
