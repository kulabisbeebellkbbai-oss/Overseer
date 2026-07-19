"""IDS/firewall advisory packages for approval-gated security changes."""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import replace
from enum import StrEnum
from pathlib import Path
import re
import shlex

from .admin import AdminChangeKind, AdminChangePlan
from .source_review import HostSecuritySourceReview, SourceReviewDisposition


INTRUSION_DETECTION_PROJECT_PATH = "/home/god/Documents/Codex Workspace/Intrusion Detection"
INTRUSION_DETECTION_ADVISOR = f"{INTRUSION_DETECTION_PROJECT_PATH}/ops/codex-advisor.sh"
INTRUSION_DETECTION_THREAD = "codex-intrusion-detection-019f09da"


class IDSReviewPackageStatus(StrEnum):
    PREPARED = "prepared"
    SUBMITTED = "submitted"
    ACCEPTED = "accepted"
    REVISION_REQUIRED = "revision_required"


@dataclass(frozen=True)
class HostSecurityIDSReviewPackage:
    id: str
    plan_id: str
    plan_kind: AdminChangeKind
    target: str
    requested_by: str
    status: IDSReviewPackageStatus
    advisory_project_path: str
    advisory_command: tuple[str, ...]
    interactive_thread: str
    current_state: str
    intended_traffic: str
    operational_reason: str
    sensitivity: str
    policy_gaps: str
    firewall_rule_drafts: tuple[str, ...]
    ids_rule_drafts: tuple[str, ...]
    logging_plan: str
    test_plan: str
    rollback_plan: str
    approval_boundary: str
    prompt: str
    source_review_id: str | None = None
    created_at: str | None = None
    submitted_by: str | None = None
    submitted_at: str | None = None
    prompt_path: str | None = None
    reviewed_by: str | None = None
    reviewed_at: str | None = None
    advisory_result: str | None = None
    dispatched_by: str | None = None
    dispatched_at: str | None = None
    dispatch_status: str | None = None
    dispatch_reason: str | None = None
    dispatch_thread: str | None = None
    dispatch_conversation_id: str | None = None
    dispatch_command: str | None = None
    dispatch_exit_code: int | None = None

    def satisfies_pre_execution_review_gate(self) -> bool:
        return self.status == IDSReviewPackageStatus.ACCEPTED and bool((self.advisory_result or "").strip())


_PROMPT_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def admin_plan_requires_ids_review(plan: AdminChangePlan) -> bool:
    return AdminChangeKind(plan.kind) in {
        AdminChangeKind.FIREWALL_ALLOW_TCP,
        AdminChangeKind.FIREWALL_DENY_TCP,
        AdminChangeKind.BLOCK_IP,
    }


def build_ids_review_package(
    plan: AdminChangePlan,
    source_review: HostSecuritySourceReview | None = None,
    package_id: str | None = None,
    requested_by: str = "odo",
    created_at: str | None = None,
) -> HostSecurityIDSReviewPackage:
    plan_kind = AdminChangeKind(plan.kind)
    if not admin_plan_requires_ids_review(plan):
        raise ValueError("admin plan does not require IDS/firewall review")
    if not requested_by.strip():
        raise ValueError("requested_by is required")
    if source_review is not None and source_review.remote_address != plan.target:
        raise ValueError("source review target does not match admin plan target")
    source_context = _source_context(source_review)
    firewall_rule_drafts = _firewall_rule_drafts(plan)
    ids_rule_drafts = _ids_rule_drafts(plan, source_review)
    logging_plan = _logging_plan(plan)
    test_plan = _test_plan(plan)
    rollback_plan = "; ".join(
        f"{step.title}: {shlex.join(step.command)} ({step.reason})" for step in plan.rollback_steps
    )
    approval_boundary = (
        "Prepared review package only. Do not apply firewall, IDS, IPS, route, VPN, NAT, service-bind, "
        "reload, restart, or alerting changes until explicit approval follows Intrusion Detection review."
    )
    prompt = _advisory_prompt(
        plan,
        source_context,
        firewall_rule_drafts,
        ids_rule_drafts,
        logging_plan,
        test_plan,
        rollback_plan,
        approval_boundary,
    )
    return HostSecurityIDSReviewPackage(
        id=package_id or f"ids-review.{plan.id}",
        plan_id=plan.id,
        plan_kind=plan_kind,
        target=plan.target,
        requested_by=requested_by,
        status=IDSReviewPackageStatus.PREPARED,
        advisory_project_path=INTRUSION_DETECTION_PROJECT_PATH,
        advisory_command=(INTRUSION_DETECTION_ADVISOR, "<prompt-file>"),
        interactive_thread=INTRUSION_DETECTION_THREAD,
        current_state=plan.current_state,
        intended_traffic=_intended_traffic(plan),
        operational_reason=plan.reason,
        sensitivity="local host security control plane; policy mistakes may block legitimate local or remote work",
        policy_gaps="requires Intrusion Detection review for mitigation, inspection, logging, alerting, and custom rules",
        firewall_rule_drafts=firewall_rule_drafts,
        ids_rule_drafts=ids_rule_drafts,
        logging_plan=logging_plan,
        test_plan=test_plan,
        rollback_plan=rollback_plan,
        approval_boundary=approval_boundary,
        prompt=prompt,
        source_review_id=source_review.id if source_review is not None else None,
        created_at=created_at,
    )


def mark_ids_review_package_submitted(
    package: HostSecurityIDSReviewPackage,
    submitted_by: str,
    submitted_at: str | None = None,
    prompt_path: str | None = None,
) -> HostSecurityIDSReviewPackage:
    if not submitted_by.strip():
        raise ValueError("submitted_by is required")
    if package.status == IDSReviewPackageStatus.ACCEPTED:
        raise ValueError("accepted IDS review packages cannot be resubmitted")
    return replace(
        package,
        status=IDSReviewPackageStatus.SUBMITTED,
        submitted_by=submitted_by,
        submitted_at=submitted_at,
        prompt_path=prompt_path,
    )


def record_ids_review_package_result(
    package: HostSecurityIDSReviewPackage,
    status: IDSReviewPackageStatus,
    advisory_result: str,
    reviewed_by: str,
    reviewed_at: str | None = None,
) -> HostSecurityIDSReviewPackage:
    selected_status = IDSReviewPackageStatus(status)
    if selected_status not in {IDSReviewPackageStatus.ACCEPTED, IDSReviewPackageStatus.REVISION_REQUIRED}:
        raise ValueError("IDS review result status must be accepted or revision_required")
    if not advisory_result.strip():
        raise ValueError("advisory_result is required")
    if not reviewed_by.strip():
        raise ValueError("reviewed_by is required")
    if package.status == IDSReviewPackageStatus.PREPARED:
        raise ValueError("IDS review package must be submitted before recording a result")
    return replace(
        package,
        status=selected_status,
        advisory_result=advisory_result,
        reviewed_by=reviewed_by,
        reviewed_at=reviewed_at,
    )


def write_ids_review_prompt_file(
    package: HostSecurityIDSReviewPackage,
    output_dir: str | Path,
    filename: str | None = None,
) -> tuple[HostSecurityIDSReviewPackage, Path]:
    output_path = Path(output_dir)
    if output_path.exists() and not output_path.is_dir():
        raise ValueError("output_dir must be a directory")
    selected_filename = filename or _default_prompt_filename(package)
    if Path(selected_filename).name != selected_filename:
        raise ValueError("filename must not include a directory")
    if not selected_filename.endswith(".md"):
        raise ValueError("filename must end with .md")
    output_path.mkdir(parents=True, exist_ok=True)
    prompt_path = output_path / selected_filename
    prompt_path.write_text(package.prompt + "\n", encoding="utf-8")
    prompt_path.chmod(0o600)
    return replace(package, prompt_path=str(prompt_path)), prompt_path


def _default_prompt_filename(package: HostSecurityIDSReviewPackage) -> str:
    safe_id = _PROMPT_FILENAME_RE.sub("-", package.id).strip(".-")
    if not safe_id:
        safe_id = "ids-review-package"
    return f"{safe_id}.prompt.md"


def _source_context(source_review: HostSecuritySourceReview | None) -> str:
    if source_review is None:
        return "No source review record was linked to this plan."
    return (
        f"source_review={source_review.id}; disposition={SourceReviewDisposition(source_review.disposition).value}; "
        f"listener={source_review.listener}; remote={source_review.remote_address}:{source_review.remote_port}; "
        f"scope={source_review.source_scope}; reviewer={source_review.reviewed_by}; "
        f"rationale={source_review.rationale}; evidence={source_review.evidence}"
    )


def _intended_traffic(plan: AdminChangePlan) -> str:
    plan_kind = AdminChangeKind(plan.kind)
    if plan_kind == AdminChangeKind.BLOCK_IP:
        return f"deny traffic from source {plan.target}; direction inbound or routed as interpreted by host firewall"
    if plan_kind == AdminChangeKind.FIREWALL_DENY_TCP:
        return f"deny inbound TCP service traffic for {plan.target}"
    return f"allow inbound TCP service traffic for {plan.target}"


def _firewall_rule_drafts(plan: AdminChangePlan) -> tuple[str, ...]:
    return tuple(f"{step.title}: {shlex.join(step.command)} ({step.reason})" for step in plan.steps)


def _ids_rule_drafts(
    plan: AdminChangePlan,
    source_review: HostSecuritySourceReview | None,
) -> tuple[str, ...]:
    if AdminChangeKind(plan.kind) == AdminChangeKind.BLOCK_IP and source_review is not None:
        return (
            f"Suricata/local rule draft: alert on repeated traffic from {source_review.remote_address} "
            f"to {source_review.listener} before firewall enforcement; classify as attempted-admin-policy-bypass.",
            "Review whether a custom deny/log firewall rule plus IDS alert is preferable to a broad host source block.",
        )
    return (
        "Review existing IDS/IPS policy coverage for the target service before firewall enforcement.",
        "Draft custom IDS signatures for scanning, brute force, malformed protocol traffic, and unusual volume if no existing rule fits.",
    )


def _logging_plan(plan: AdminChangePlan) -> str:
    return (
        f"Log filtered traffic for {plan.target} during validation; alert on repeated denied attempts, "
        "unexpected source networks, protocol anomalies, and authentication failures where service logs exist."
    )


def _test_plan(plan: AdminChangePlan) -> str:
    return (
        f"Before enforcement, confirm current reachability and policy state for {plan.target}. After approval, "
        "verify the exact rule exists, expected clients still work, denied traffic is logged, and rollback removes the rule."
    )


def _advisory_prompt(
    plan: AdminChangePlan,
    source_context: str,
    firewall_rule_drafts: tuple[str, ...],
    ids_rule_drafts: tuple[str, ...],
    logging_plan: str,
    test_plan: str,
    rollback_plan: str,
    approval_boundary: str,
) -> str:
    return "\n".join(
        (
            "Evaluate this proposed Overseer security change before enforcement.",
            "",
            f"Plan id: {plan.id}",
            f"Kind: {AdminChangeKind(plan.kind).value}",
            f"Target: {plan.target}",
            f"Reason: {plan.reason}",
            f"Current state: {plan.current_state}",
            f"Proposed state: {plan.proposed_state}",
            f"Source review context: {source_context}",
            "",
            "Please evaluate mitigation, inspection, logging, alerting, policy or rule gaps, rollback risk, "
            "and whether custom firewall or IDS rules are required.",
            "",
            "Firewall rule drafts:",
            *[f"- {item}" for item in firewall_rule_drafts],
            "",
            "IDS rule drafts:",
            *[f"- {item}" for item in ids_rule_drafts],
            "",
            f"Logging plan: {logging_plan}",
            f"Test plan: {test_plan}",
            f"Rollback plan: {rollback_plan}",
            f"Approval boundary: {approval_boundary}",
        )
    )
