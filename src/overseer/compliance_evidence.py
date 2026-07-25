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
        audits = store.list_audit_events()
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
            {"area": "audit events", "records": len(audits), "status": "ready"},
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
    return [
        {
            "area": str(check.get("area", "unknown")) if isinstance(check, dict) else "unknown",
            "expected": str(check.get("expected", "")) if isinstance(check, dict) else "",
            "status": "baseline_recorded",
            "next_step": "connect live read-only comparator",
        }
        for check in checks
    ] or [{"area": "desired-state", "path": "config/desired-state.json", "status": "empty", "next_step": "add desired checks"}]
