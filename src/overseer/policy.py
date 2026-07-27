"""Policy evaluation for approval-gated Overseer actions."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Mapping

from .admin import AdminChangeKind, AdminChangePlan, AdminExecutionCapability, missing_admin_change_fields
from .core import ApprovalLevel, OwnerDomain, RiskLevel
from .ids_review import HostSecurityIDSReviewPackage, admin_plan_requires_ids_review


class PolicyCheckStatus(StrEnum):
    PASS = "pass"
    WARN = "warn"
    BLOCK = "block"


@dataclass(frozen=True)
class PolicyCheck:
    id: str
    status: PolicyCheckStatus
    owner_domain: OwnerDomain
    summary: str
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyDecision:
    subject_id: str
    subject_kind: str
    status: PolicyCheckStatus
    checks: tuple[PolicyCheck, ...]
    warnings_block_execution: bool = True

    def can_proceed(self) -> bool:
        return self.status == PolicyCheckStatus.PASS or (
            self.status == PolicyCheckStatus.WARN and not self.warnings_block_execution
        )


APPROVAL_RANK: dict[ApprovalLevel, int] = {
    ApprovalLevel.NONE: 0,
    ApprovalLevel.ROLE: 1,
    ApprovalLevel.SISKO: 2,
    ApprovalLevel.HUMAN: 3,
}


@dataclass(frozen=True)
class PolicyQuestion:
    id: str
    prompt: str
    profile_key: str
    default: object
    options: tuple[object, ...]
    rationale: str


@dataclass(frozen=True)
class PolicyProfile:
    name: str = "best-practice"
    description: str = "Conservative local-admin defaults for Overseer-controlled host changes."
    minimum_approval_by_risk: Mapping[RiskLevel, ApprovalLevel] = field(
        default_factory=lambda: {
            RiskLevel.LOW: ApprovalLevel.NONE,
            RiskLevel.MEDIUM: ApprovalLevel.SISKO,
            RiskLevel.HIGH: ApprovalLevel.SISKO,
            RiskLevel.CRITICAL: ApprovalLevel.HUMAN,
        }
    )
    require_live_adapter_enabled: bool = True
    require_rollback_steps: bool = True
    warn_on_apt_upgrade_rollback: bool = False
    require_verification_steps: bool = True
    require_ids_review_for_firewall: bool = True
    block_warnings_until_accepted: bool = True


BEST_PRACTICE_POLICY_PROFILE = PolicyProfile()


def evaluate_admin_change_policy(
    plan: AdminChangePlan,
    capability: AdminExecutionCapability,
    ids_review_packages: tuple[HostSecurityIDSReviewPackage, ...] = (),
    accepted_warning_check_ids: tuple[str, ...] = (),
    profile: PolicyProfile = BEST_PRACTICE_POLICY_PROFILE,
) -> PolicyDecision:
    checks = _apply_warning_acceptance(
        (
        _plan_state_check(plan),
        _plan_completeness_check(plan),
        _approval_check(plan),
        _adapter_check(plan, capability, profile),
        _ids_review_check(plan, ids_review_packages, profile),
        _residual_scan_findings_check(plan),
        _rollback_check(plan, profile),
        _verification_check(plan, profile),
        _risk_approval_check(plan, profile),
        ),
        frozenset(accepted_warning_check_ids),
    )
    return PolicyDecision(
        subject_id=plan.id,
        subject_kind=AdminChangeKind(plan.kind).value,
        status=_overall_status(checks),
        checks=checks,
        warnings_block_execution=profile.block_warnings_until_accepted,
    )


def _apply_warning_acceptance(
    checks: tuple[PolicyCheck, ...],
    accepted_warning_check_ids: frozenset[str],
) -> tuple[PolicyCheck, ...]:
    accepted: list[PolicyCheck] = []
    for check in checks:
        if check.status == PolicyCheckStatus.WARN and check.id in accepted_warning_check_ids:
            accepted.append(
                PolicyCheck(
                    check.id,
                    PolicyCheckStatus.PASS,
                    check.owner_domain,
                    f"accepted residual warning: {check.summary}",
                    check.evidence_ids,
                )
            )
        else:
            accepted.append(check)
    return tuple(accepted)


def _overall_status(checks: tuple[PolicyCheck, ...]) -> PolicyCheckStatus:
    if any(check.status == PolicyCheckStatus.BLOCK for check in checks):
        return PolicyCheckStatus.BLOCK
    if any(check.status == PolicyCheckStatus.WARN for check in checks):
        return PolicyCheckStatus.WARN
    return PolicyCheckStatus.PASS


def _plan_state_check(plan: AdminChangePlan) -> PolicyCheck:
    if plan.archived:
        return PolicyCheck(
            "admin.plan.state",
            PolicyCheckStatus.BLOCK,
            plan.owner_domain,
            "archived admin plans cannot execute",
            (plan.archive_record_id,) if plan.archive_record_id else (),
        )
    if plan.canceled:
        return PolicyCheck(
            "admin.plan.state",
            PolicyCheckStatus.BLOCK,
            plan.owner_domain,
            "canceled admin plans cannot execute",
        )
    return PolicyCheck("admin.plan.state", PolicyCheckStatus.PASS, plan.owner_domain, "admin plan is active")


def _plan_completeness_check(plan: AdminChangePlan) -> PolicyCheck:
    missing = missing_admin_change_fields(plan)
    if missing:
        return PolicyCheck(
            "admin.plan.completeness",
            PolicyCheckStatus.BLOCK,
            plan.owner_domain,
            f"admin plan is missing required fields: {', '.join(missing)}",
        )
    return PolicyCheck(
        "admin.plan.completeness",
        PolicyCheckStatus.PASS,
        plan.owner_domain,
        "admin plan includes commands, risks, rollback, and verification",
    )


def _approval_check(plan: AdminChangePlan) -> PolicyCheck:
    if plan.requires_explicit_approval() and not plan.approved:
        return PolicyCheck(
            "admin.plan.approval",
            PolicyCheckStatus.BLOCK,
            plan.owner_domain,
            f"{ApprovalLevel(plan.approval_level).value} approval is required before execution",
        )
    if plan.approved:
        return PolicyCheck(
            "admin.plan.approval",
            PolicyCheckStatus.PASS,
            plan.owner_domain,
            f"admin plan approved by {plan.approved_by or 'unknown approver'}",
        )
    return PolicyCheck("admin.plan.approval", PolicyCheckStatus.PASS, plan.owner_domain, "no explicit approval required")


def _adapter_check(plan: AdminChangePlan, capability: AdminExecutionCapability, profile: PolicyProfile) -> PolicyCheck:
    if not profile.require_live_adapter_enabled:
        return PolicyCheck(
            "admin.adapter.enabled",
            PolicyCheckStatus.WARN,
            plan.owner_domain,
            "policy profile does not block on live adapter status; executor capability still applies",
        )
    if not capability.can_execute_live():
        return PolicyCheck(
            "admin.adapter.enabled",
            PolicyCheckStatus.BLOCK,
            plan.owner_domain,
            f"live adapter is {capability.status.value}: {capability.summary}",
        )
    return PolicyCheck(
        "admin.adapter.enabled",
        PolicyCheckStatus.PASS,
        plan.owner_domain,
        f"live adapter is enabled: {capability.adapter_name}",
    )


def _ids_review_check(
    plan: AdminChangePlan,
    ids_review_packages: tuple[HostSecurityIDSReviewPackage, ...],
    profile: PolicyProfile,
) -> PolicyCheck:
    if not profile.require_ids_review_for_firewall:
        return PolicyCheck(
            "admin.ids.review",
            PolicyCheckStatus.WARN,
            OwnerDomain.ODO_IDS,
            "policy profile does not block firewall-affecting plans on IDS advisory review",
            tuple(package.id for package in ids_review_packages),
        )
    if not admin_plan_requires_ids_review(plan):
        return PolicyCheck("admin.ids.review", PolicyCheckStatus.PASS, OwnerDomain.ODO_IDS, "IDS review is not required")
    accepted = tuple(package for package in ids_review_packages if package.satisfies_pre_execution_review_gate())
    if not accepted:
        return PolicyCheck(
            "admin.ids.review",
            PolicyCheckStatus.BLOCK,
            OwnerDomain.ODO_IDS,
            "accepted IDS/firewall advisory is required before approval or execution",
            tuple(package.id for package in ids_review_packages),
        )
    return PolicyCheck(
        "admin.ids.review",
        PolicyCheckStatus.PASS,
        OwnerDomain.ODO_IDS,
        "accepted IDS/firewall advisory is present",
        tuple(package.id for package in accepted),
    )


def _residual_scan_findings_check(plan: AdminChangePlan) -> PolicyCheck:
    if not plan.residual_scan_findings:
        return PolicyCheck(
            "admin.scan.residual-findings",
            PolicyCheckStatus.PASS,
            OwnerDomain.ODO,
            "no residual critical/high image findings declared",
        )
    return PolicyCheck(
        "admin.scan.residual-findings",
        PolicyCheckStatus.WARN,
        OwnerDomain.ODO,
        "replacement images still have residual critical/high findings: " + "; ".join(plan.residual_scan_findings),
    )


def _rollback_check(plan: AdminChangePlan, profile: PolicyProfile) -> PolicyCheck:
    if not profile.require_rollback_steps:
        return PolicyCheck("admin.rollback", PolicyCheckStatus.WARN, plan.owner_domain, "policy profile allows missing rollback steps")
    if not plan.rollback_steps:
        return PolicyCheck("admin.rollback", PolicyCheckStatus.BLOCK, plan.owner_domain, "rollback steps are required")
    if profile.warn_on_apt_upgrade_rollback and AdminChangeKind(plan.kind) == AdminChangeKind.APT_UPGRADE:
        return PolicyCheck(
            "admin.rollback",
            PolicyCheckStatus.WARN,
            plan.owner_domain,
            "apt upgrades may require operator-selected rollback because package downgrades are not always available",
        )
    return PolicyCheck("admin.rollback", PolicyCheckStatus.PASS, plan.owner_domain, "rollback steps are recorded")


def _verification_check(plan: AdminChangePlan, profile: PolicyProfile) -> PolicyCheck:
    if not profile.require_verification_steps:
        return PolicyCheck("admin.verification", PolicyCheckStatus.WARN, OwnerDomain.JULIAN, "policy profile allows missing verification steps")
    if not plan.verification_steps:
        return PolicyCheck("admin.verification", PolicyCheckStatus.BLOCK, plan.owner_domain, "verification steps are required")
    return PolicyCheck("admin.verification", PolicyCheckStatus.PASS, OwnerDomain.JULIAN, "verification steps are recorded")


def _risk_approval_check(plan: AdminChangePlan, profile: PolicyProfile) -> PolicyCheck:
    risk_level = RiskLevel(plan.risk_level)
    approval_level = ApprovalLevel(plan.approval_level)
    minimum = ApprovalLevel(profile.minimum_approval_by_risk.get(risk_level, ApprovalLevel.HUMAN))
    if APPROVAL_RANK[approval_level] < APPROVAL_RANK[minimum]:
        return PolicyCheck(
            "admin.risk.approval-level",
            PolicyCheckStatus.BLOCK,
            OwnerDomain.SISKO,
            f"{risk_level.value}-risk admin changes require at least {minimum.value} approval",
        )
    return PolicyCheck(
        "admin.risk.approval-level",
        PolicyCheckStatus.PASS,
        OwnerDomain.SISKO,
        "risk level and approval level are compatible",
    )


def policy_profile_from_mapping(mapping: Mapping[str, object]) -> PolicyProfile:
    approvals = mapping.get("minimum_approval_by_risk", {})
    if not isinstance(approvals, Mapping):
        raise ValueError("minimum_approval_by_risk must be an object")
    return PolicyProfile(
        name=str(mapping.get("name", BEST_PRACTICE_POLICY_PROFILE.name)),
        description=str(mapping.get("description", BEST_PRACTICE_POLICY_PROFILE.description)),
        minimum_approval_by_risk={
            RiskLevel(risk): ApprovalLevel(level)
            for risk, level in ({
                risk.value: BEST_PRACTICE_POLICY_PROFILE.minimum_approval_by_risk[risk].value
                for risk in RiskLevel
            } | {str(risk): str(level) for risk, level in approvals.items()}).items()
        },
        require_live_adapter_enabled=_bool_setting(mapping, "require_live_adapter_enabled", True),
        require_rollback_steps=_bool_setting(mapping, "require_rollback_steps", True),
        warn_on_apt_upgrade_rollback=_bool_setting(
            mapping,
            "warn_on_apt_upgrade_rollback",
            BEST_PRACTICE_POLICY_PROFILE.warn_on_apt_upgrade_rollback,
        ),
        require_verification_steps=_bool_setting(mapping, "require_verification_steps", True),
        require_ids_review_for_firewall=_bool_setting(mapping, "require_ids_review_for_firewall", True),
        block_warnings_until_accepted=_bool_setting(mapping, "block_warnings_until_accepted", True),
    )


def _bool_setting(mapping: Mapping[str, object], key: str, default: bool) -> bool:
    value = mapping.get(key, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1", "on"}:
            return True
        if lowered in {"false", "no", "0", "off"}:
            return False
    raise ValueError(f"{key} must be a boolean")


def policy_profile_status(profile: PolicyProfile = BEST_PRACTICE_POLICY_PROFILE) -> dict[str, object]:
    return {
        "name": profile.name,
        "description": profile.description,
        "minimum_approval_by_risk": {
            risk.value: ApprovalLevel(profile.minimum_approval_by_risk[risk]).value
            for risk in RiskLevel
        },
        "require_live_adapter_enabled": profile.require_live_adapter_enabled,
        "require_rollback_steps": profile.require_rollback_steps,
        "warn_on_apt_upgrade_rollback": profile.warn_on_apt_upgrade_rollback,
        "require_verification_steps": profile.require_verification_steps,
        "require_ids_review_for_firewall": profile.require_ids_review_for_firewall,
        "block_warnings_until_accepted": profile.block_warnings_until_accepted,
    }


def policy_customization_questions() -> tuple[PolicyQuestion, ...]:
    return (
        PolicyQuestion(
            id="risk-low-approval",
            prompt="What minimum approval should low-risk admin changes require?",
            profile_key="minimum_approval_by_risk.low",
            default=ApprovalLevel.NONE.value,
            options=tuple(level.value for level in ApprovalLevel),
            rationale="Low-risk observation or localhost maintenance should not create unnecessary friction.",
        ),
        PolicyQuestion(
            id="risk-medium-approval",
            prompt="What minimum approval should medium-risk admin changes require?",
            profile_key="minimum_approval_by_risk.medium",
            default=ApprovalLevel.SISKO.value,
            options=tuple(level.value for level in ApprovalLevel),
            rationale="Medium-risk service or package work can interrupt local coordination.",
        ),
        PolicyQuestion(
            id="risk-high-approval",
            prompt="What minimum approval should high-risk admin changes require?",
            profile_key="minimum_approval_by_risk.high",
            default=ApprovalLevel.SISKO.value,
            options=tuple(level.value for level in ApprovalLevel),
            rationale="High-risk changes can affect network exposure, packages, or shared resources.",
        ),
        PolicyQuestion(
            id="risk-critical-approval",
            prompt="What minimum approval should critical admin changes require?",
            profile_key="minimum_approval_by_risk.critical",
            default=ApprovalLevel.HUMAN.value,
            options=tuple(level.value for level in ApprovalLevel),
            rationale="Critical changes should preserve a manual decision point.",
        ),
        PolicyQuestion(
            id="live-adapter-required",
            prompt="Should execution require an enabled live adapter for the exact change kind?",
            profile_key="require_live_adapter_enabled",
            default=True,
            options=(True, False),
            rationale="Typed adapters keep command boundaries auditable and prevent accidental shell execution.",
        ),
        PolicyQuestion(
            id="rollback-required",
            prompt="Should admin plans require rollback steps before execution?",
            profile_key="require_rollback_steps",
            default=True,
            options=(True, False),
            rationale="Rollback evidence is needed to recover from failed host changes.",
        ),
        PolicyQuestion(
            id="apt-upgrade-warning",
            prompt="Should package upgrades keep a residual rollback warning until explicitly accepted?",
            profile_key="warn_on_apt_upgrade_rollback",
            default=False,
            options=(True, False),
            rationale="Package downgrades are not always available or safe.",
        ),
        PolicyQuestion(
            id="verification-required",
            prompt="Should admin plans require post-change verification steps?",
            profile_key="require_verification_steps",
            default=True,
            options=(True, False),
            rationale="Verification confirms the requested state actually changed and the service is usable.",
        ),
        PolicyQuestion(
            id="ids-review-required",
            prompt="Should firewall-affecting plans require accepted Intrusion Detection advisory review?",
            profile_key="require_ids_review_for_firewall",
            default=True,
            options=(True, False),
            rationale="IDS review reduces the chance of weakening network defenses or blocking legitimate work.",
        ),
        PolicyQuestion(
            id="warnings-block",
            prompt="Should warning policy decisions block execution until explicitly accepted?",
            profile_key="block_warnings_until_accepted",
            default=True,
            options=(True, False),
            rationale="Warnings represent residual risk that should be acknowledged before execution.",
        ),
    )


def policy_customization_helper_status(profile: PolicyProfile = BEST_PRACTICE_POLICY_PROFILE) -> dict[str, object]:
    return {
        "profile": policy_profile_status(profile),
        "questions": [
            {
                "id": question.id,
                "prompt": question.prompt,
                "profile_key": question.profile_key,
                "default": question.default,
                "options": list(question.options),
                "rationale": question.rationale,
            }
            for question in policy_customization_questions()
        ],
        "next_step": "answer the questions, update the profile JSON fields, then pass the file with --policy-profile",
    }


def policy_profile_from_answers(
    answers: Mapping[str, object],
    base_profile: PolicyProfile = BEST_PRACTICE_POLICY_PROFILE,
) -> PolicyProfile:
    profile = policy_profile_status(base_profile)
    profile["name"] = str(answers.get("name", "custom"))
    profile["description"] = str(answers.get("description", "Customized Overseer policy profile."))
    question_by_id = {question.id: question for question in policy_customization_questions()}
    for answer_id, value in answers.items():
        if answer_id in {"name", "description"}:
            continue
        if answer_id not in question_by_id:
            raise ValueError(f"unsupported policy answer id: {answer_id}")
        question = question_by_id[answer_id]
        if value not in question.options:
            raise ValueError(f"unsupported value for {answer_id}: {value}")
        _set_profile_value(profile, question.profile_key, value)
    return policy_profile_from_mapping(profile)


def policy_profile_from_answers_status(answers: Mapping[str, object]) -> dict[str, object]:
    return {
        "profile": policy_profile_status(policy_profile_from_answers(answers)),
        "source": "policy_customization_answers",
    }


def _set_profile_value(profile: dict[str, object], dotted_key: str, value: object) -> None:
    if dotted_key.startswith("minimum_approval_by_risk."):
        risk = dotted_key.removeprefix("minimum_approval_by_risk.")
        approvals = profile["minimum_approval_by_risk"]
        if not isinstance(approvals, dict):
            raise ValueError("minimum_approval_by_risk must be an object")
        approvals[risk] = value
        return
    profile[dotted_key] = value
