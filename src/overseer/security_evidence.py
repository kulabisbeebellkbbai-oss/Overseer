"""Read-only security evidence depth for Odo's review workflows."""

from __future__ import annotations

from pathlib import Path
import json

from .admin import AdminChangeKind
from .host import HostInspectionSnapshot, assess_host_security
from .source_review import SourceReviewDisposition
from .store import SQLiteStore


def security_evidence_status(store_path: str | Path) -> dict[str, object]:
    store = SQLiteStore(store_path)
    try:
        snapshot = store.load_latest_host_snapshot()
        plans = [plan for plan in store.list_admin_change_plans() if not plan.archived]
        reviews = store.list_host_security_source_reviews()
    finally:
        store.close()

    findings = tuple(assess_host_security(snapshot)) if snapshot else ()
    return {
        "store": str(Path(store_path)),
        "snapshot_id": snapshot.id if snapshot else None,
        "captured_at": snapshot.captured_at if snapshot else None,
        "firewall_provenance": _firewall_provenance(snapshot),
        "firewall_policy_diff": _firewall_policy_diff(Path(store_path).resolve().parent.parent if Path(store_path).resolve().parent.name == "state" else Path.cwd(), snapshot),
        "listener_exposure": [
            {
                "id": finding.id,
                "severity": finding.severity.value,
                "owner_domain": finding.owner_domain,
                "summary": finding.summary,
                "evidence": _redact_socket_evidence(finding.evidence),
                "recommended_action": finding.recommended_action,
            }
            for finding in findings
        ],
        "source_reviews": [
            {
                "id": review.id,
                "listener": review.listener,
                "remote_address": review.remote_address,
                "source_scope": review.source_scope,
                "disposition": review.disposition.value,
                "can_stage_block_plan": review.can_stage_block_plan(),
                "reviewed_by": review.reviewed_by,
                "reviewed_at": review.reviewed_at,
            }
            for review in reviews
        ],
        "protective_plan_provenance": [
            {
                "id": plan.id,
                "kind": plan.kind.value,
                "target": plan.target,
                "approved": plan.approved,
                "canceled": plan.canceled,
                "current_state": _redact_socket_evidence(plan.current_state),
                "rollback": "present" if plan.rollback_steps else "missing",
            }
            for plan in plans
            if plan.kind in {AdminChangeKind.FIREWALL_DENY_TCP, AdminChangeKind.FIREWALL_ALLOW_TCP, AdminChangeKind.BLOCK_IP}
        ],
        "baseline_checks": _baseline_checks(snapshot, findings, reviews),
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def _firewall_provenance(snapshot: HostInspectionSnapshot | None) -> list[dict[str, object]]:
    if snapshot is None:
        return [{"name": "host snapshot", "status": "missing", "summary": "run Inspect Host to capture firewall provenance"}]
    rows = []
    for name in ("firewalld-state", "firewalld-active-zones", "firewalld-public-zone"):
        try:
            observation = snapshot.observation(name)
        except KeyError:
            rows.append({"name": name, "status": "missing", "summary": "not captured"})
            continue
        rows.append(
            {
                "name": name,
                "status": "available" if observation.exit_code == 0 else "unavailable",
                "exit_code": observation.exit_code,
                "command": " ".join(observation.command),
                "summary": _summarize_lines(observation.stdout or observation.stderr),
            }
        )
    return rows


def _baseline_checks(snapshot: HostInspectionSnapshot | None, findings: tuple[object, ...], reviews: tuple[object, ...]) -> list[dict[str, object]]:
    hostile_reviews = [review for review in reviews if review.disposition == SourceReviewDisposition.HOSTILE]
    return [
        {"check": "host snapshot", "status": "present" if snapshot else "missing", "next_step": "run Inspect Host" if not snapshot else "continue periodic capture"},
        {"check": "listener exposure", "status": "attention" if findings else "quiet", "evidence": len(findings), "next_step": "review exposed listener queue"},
        {"check": "source reviews", "status": "attention" if hostile_reviews else "ready", "evidence": len(reviews), "next_step": "stage block plans for hostile external reviews"},
        {"check": "firewall provenance", "status": "present" if snapshot else "missing", "next_step": "review captured firewall observations before enforcement"},
    ]


def _firewall_policy_diff(root: Path, snapshot: HostInspectionSnapshot | None) -> list[dict[str, object]]:
    path = root / "config" / "desired-firewall.json"
    if not path.exists():
        return [{"rule": "desired firewall policy", "status": "missing", "next_step": "create config/desired-firewall.json before diff enforcement"}]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [{"rule": "desired firewall policy", "status": "invalid", "next_step": "repair desired firewall JSON"}]
    desired = data.get("rules", [])
    if not isinstance(desired, list):
        desired = []
    observed = ""
    if snapshot:
        for name in ("firewalld-public-zone", "firewalld-active-zones"):
            try:
                observed += "\n" + snapshot.observation(name).stdout
            except KeyError:
                pass
    rows = []
    for index, rule in enumerate(desired):
        rule_text = json.dumps(rule, sort_keys=True) if isinstance(rule, dict) else str(rule)
        action = str(rule.get("action") or "") if isinstance(rule, dict) else ""
        port = rule.get("port") if isinstance(rule, dict) else ""
        rows.append(
            {
                "index": index,
                "rule": rule_text,
                "action": action,
                "port": port,
                "status": "observed_fragment" if rule_text in observed else "needs_review",
                "next_step": "stage approval-gated firewall plan if required",
            }
        )
    return rows or [{"rule": "desired firewall policy", "status": "empty", "next_step": "add desired firewall rules"}]


def _summarize_lines(value: str) -> str:
    lines = [_redact_socket_evidence(line.strip()) for line in value.splitlines() if line.strip()]
    return "; ".join(lines[:5])


def _redact_socket_evidence(value: str) -> str:
    # Keep ports, states, and process labels useful while avoiding command noise.
    return " ".join(value.replace("\t", " ").split())
