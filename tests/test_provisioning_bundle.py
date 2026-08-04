"""Contract tests for the bounded typed provisioning bundle boundary."""
from __future__ import annotations

import hashlib
import math
from dataclasses import asdict, replace
from types import MappingProxyType

import pytest

from overseer.backup_provisioning import build_plan
from overseer.core import OwnerDomain
from overseer.provisioning_bundle import (
    PreflightCheck,
    ProvisioningBundleV1,
    ProvisioningIntentV1,
    ProvisioningPreflightReport,
    ProvisioningReviewOutboxEntry,
    bundle_digest,
    canonical_digest,
    parse_provisioning_intent,
)


def intent_payload(**changes: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "1",
        "request_id": "request.bundle-v20",
        "plan_id": "backup-provision.donuthole.v20.20260802",
        "kind": "donuthole_encrypted_backup_provisioning_v1",
        "project_id": "project.donuthole",
        "resource_id": "storage.donuthole",
        "root_id": "backup-root",
        "policy_revision": "1",
        "source_commit": "b" * 40,
        "requested_by": "roadex",
        "reason": "Review a bounded backup provisioning request.",
        "supersedes_plan_id": "",
    }
    payload.update(changes)
    return payload


def intent_fixture(**changes: object) -> ProvisioningIntentV1:
    return parse_provisioning_intent(intent_payload(**changes))


def plan_fixture(plan_id: str = "backup-provision.donuthole.v20.20260802"):
    return build_plan(
        plan_id,
        "sha256:" + "a" * 64,
        "b" * 40,
        "sha256:" + "d" * 64,
        "sha256:" + "c" * 64,
        {"sha256:" + "e" * 64: "root-auth.donuthole"},
        (
            {
                "project_id": "project.donuthole",
                "root_id": "backup-root",
                "policy_revision": "1",
                "host_path": "/disposable/donuthole",
                "alias": "donuthole-source",
                "max_bytes": 1073741824,
                "authorization_ref": "root-auth.donuthole",
            },
        ),
        "/run/user/1000/overseer-api-token",
        "/etc/codex-development-backups/keys/overseer.token",
        "/etc/codex-development-backups/keys/cursor.key",
        {
            "kira": "crew.kira.review-v20",
            "obrien": "crew.obrien.review-v20",
            "security": "crew.odo-ids.review-v20",
            "sisko": "crew.sisko.review-v20",
        },
    )


def report_fixture(plan_id: str = "backup-provision.donuthole.v20.20260802") -> ProvisioningPreflightReport:
    check = PreflightCheck(
        code="INTENT_VALID",
        status="passed",
        evidence_digest="sha256:" + "1" * 64,
        summary="The bounded intent satisfies the contract.",
    )
    return ProvisioningPreflightReport(
        report_id=f"preflight.{plan_id}",
        plan_id=plan_id,
        resolved_inputs={"source_commit": "b" * 40, "runtime_digest": "sha256:" + "d" * 64},
        checks=(check,),
        passed=True,
        report_digest=canonical_digest({"plan_id": plan_id, "check": check}),
    )


def outbox_fixture(
    *,
    plan_id: str = "backup-provision.donuthole.v20.20260802",
    outbox_state: str = "pending",
) -> tuple[ProvisioningReviewOutboxEntry, ...]:
    roles = (
        ("kira", OwnerDomain.KIRA),
        ("obrien", OwnerDomain.OBRIEN),
        ("security", OwnerDomain.ODO_IDS),
        ("sisko", OwnerDomain.SISKO),
    )
    return tuple(
        ProvisioningReviewOutboxEntry(
            id=f"outbox.{plan_id}.{role}",
            message_id=f"crew.{owner.value}.review-{plan_id}",
            plan_id=plan_id,
            bundle_digest="sha256:" + "0" * 64,
            role=role,
            owner_domain=owner,
            related_resource_id="storage.donuthole",
            subject="Review exact DonutHole provisioning bundle",
            message="Review the immutable plan and preflight evidence only.",
            acceptance_criteria=("Review the exact immutable evidence.",),
            evidence_ids=("sha256:" + "2" * 64,),
            state=outbox_state,
        )
        for role, owner in roles
    )


def bundle_fixture(*, outbox_state: str = "pending") -> ProvisioningBundleV1:
    intent = intent_fixture()
    return ProvisioningBundleV1(
        schema_version="1",
        intent=intent,
        plan=plan_fixture(intent.plan_id),
        preflight=report_fixture(intent.plan_id),
        outbox=outbox_fixture(plan_id=intent.plan_id, outbox_state=outbox_state),
        bundle_digest="sha256:" + "0" * 64,
        supersedes_plan_id=None,
        changed_immutable_inputs=(),
    )


def test_intent_accepts_only_bounded_exact_fields():
    intent = parse_provisioning_intent(intent_payload())

    assert intent.plan_id == "backup-provision.donuthole.v20.20260802"
    for forbidden in ("runtime_digest", "authorization_ref", "evidence_ids", "steps", "approval"):
        with pytest.raises(ValueError, match="exact typed provisioning intent"):
            parse_provisioning_intent({**intent_payload(), forbidden: "caller-controlled"})


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("source_commit", True),
        ("source_commit", "B" * 40),
        ("schema_version", 1),
        ("schema_version", "2"),
        ("kind", "other"),
        ("reason", ""),
        ("requested_by", " roadex"),
        ("supersedes_plan_id", 1),
    ),
)
def test_intent_rejects_inexact_types_empty_values_and_unsupported_enums(field, value):
    with pytest.raises(ValueError, match="exact typed provisioning intent"):
        parse_provisioning_intent(intent_payload(**{field: value}))


def test_contracts_reject_mutable_or_inexact_nested_values():
    with pytest.raises(ValueError, match="preflight check status"):
        PreflightCheck("INTENT_VALID", "unknown", "sha256:" + "1" * 64, "summary")
    with pytest.raises(ValueError, match="owner"):
        ProvisioningReviewOutboxEntry(
            "outbox.invalid", "crew.invalid", "plan.invalid", "sha256:" + "0" * 64,
            "kira", OwnerDomain.OBRIEN, "storage.donuthole", "subject", "message",
            ("criterion",), ("sha256:" + "2" * 64,),
        )
    with pytest.raises(ValueError, match="outbox state"):
        outbox_fixture(outbox_state="queued")
    with pytest.raises(ValueError, match="resolved inputs"):
        ProvisioningPreflightReport(
            "preflight.invalid", "plan.invalid", [], (), True, "sha256:" + "3" * 64
        )


def test_contracts_freeze_nested_values_and_bind_plan_relationships():
    report = report_fixture()
    with pytest.raises(TypeError):
        report.resolved_inputs["source_commit"] = "changed"  # type: ignore[index]

    bundle = bundle_fixture()
    with pytest.raises(ValueError, match="bundle plan ID"):
        ProvisioningBundleV1(
            "1", bundle.intent, bundle.plan, report_fixture("other-plan"), bundle.outbox,
            bundle.bundle_digest, None, (),
        )


def test_canonical_digest_is_stable_across_mapping_order_and_dataclass_values():
    check = PreflightCheck("INTENT_VALID", "passed", "sha256:" + "1" * 64, "summary")

    assert canonical_digest({"b": [check], "a": {"two": 2, "one": 1}}) == canonical_digest(
        {"a": {"one": 1, "two": 2}, "b": [check]}
    )


def test_bundle_digest_is_canonical_and_excludes_mutable_outbox_state():
    first = bundle_fixture(outbox_state="pending")
    second = bundle_fixture(outbox_state="dispatched")

    assert bundle_digest(first) == bundle_digest(second)
    assert bundle_digest(first) == "sha256:" + hashlib.sha256(
        __import__("overseer.provisioning_bundle", fromlist=["canonical_bundle_bytes"]).canonical_bundle_bytes(first)
    ).hexdigest()


def test_bundle_digest_binds_immutable_outbox_evidence_and_all_immutable_fields():
    first = bundle_fixture()
    changed = ProvisioningBundleV1(
        first.schema_version,
        first.intent,
        first.plan,
        first.preflight,
        tuple(
            entry if index else ProvisioningReviewOutboxEntry(
                entry.id, entry.message_id, entry.plan_id, entry.bundle_digest, entry.role,
                entry.owner_domain, entry.related_resource_id, entry.subject, entry.message,
                entry.acceptance_criteria, ("sha256:" + "f" * 64,), entry.state,
            )
            for index, entry in enumerate(first.outbox)
        ),
        first.bundle_digest,
        first.supersedes_plan_id,
        first.changed_immutable_inputs,
    )

    assert bundle_digest(first) != bundle_digest(changed)


def test_bundle_digest_converges_after_outbox_entries_receive_its_derived_value():
    provisional = bundle_fixture()
    digest = bundle_digest(provisional)
    bound_outbox = tuple(
        ProvisioningReviewOutboxEntry(
            entry.id, entry.message_id, entry.plan_id, digest, entry.role,
            entry.owner_domain, entry.related_resource_id, entry.subject, entry.message,
            entry.acceptance_criteria, entry.evidence_ids, entry.state,
        )
        for entry in provisional.outbox
    )
    bound = ProvisioningBundleV1(
        provisional.schema_version, provisional.intent, provisional.plan, provisional.preflight,
        bound_outbox, digest, provisional.supersedes_plan_id, provisional.changed_immutable_inputs,
    )

    assert bundle_digest(bound) == bound.bundle_digest


def test_bundle_snapshots_nested_plan_mappings_against_external_mutation():
    intent = intent_fixture()
    plan = plan_fixture(intent.plan_id)
    original_evidence = plan.evidence_ids
    original_arguments = plan.steps[0].arguments
    bundle = ProvisioningBundleV1(
        "1", intent, plan, report_fixture(intent.plan_id),
        outbox_fixture(plan_id=intent.plan_id), "sha256:" + "0" * 64, None, (),
    )
    original_digest = bundle_digest(bundle)

    original_evidence["kira"] = "crew.changed"
    original_arguments["commit"] = "f" * 40

    assert bundle.plan.evidence_ids["kira"] == "crew.kira.review-v20"
    assert bundle.plan.steps[0].arguments["commit"] == "b" * 40
    assert bundle_digest(bundle) == original_digest
    with pytest.raises(TypeError):
        bundle.plan.evidence_ids["kira"] = "crew.changed"  # type: ignore[index]
    with pytest.raises(TypeError):
        bundle.plan.steps[0].arguments["commit"] = "f" * 40  # type: ignore[index]
    assert asdict(bundle.plan)["evidence_ids"]["kira"] == "crew.kira.review-v20"


def test_bundle_seals_frozen_mapping_backing_attributes_against_reassignment_or_deletion():
    bundle = bundle_fixture()
    refs = bundle.plan.root_authorization_refs
    before = bundle_digest(bundle)

    with pytest.raises(AttributeError):
        refs._values = MappingProxyType({"sha256:" + "f" * 64: "root-auth.replaced"})  # type: ignore[attr-defined]
    with pytest.raises(AttributeError):
        del refs._values  # type: ignore[attr-defined]

    assert bundle_digest(bundle) == before


def test_bundle_snapshots_every_tuple_annotated_plan_field_against_caller_mutation():
    intent = intent_fixture()
    original_plan = plan_fixture(intent.plan_id)

    for field in ("root_registrations", "steps", "rollback_steps", "read_only_paths", "read_write_paths"):
        caller_values = list(getattr(original_plan, field))
        bundle = ProvisioningBundleV1(
            "1", intent, replace(original_plan, **{field: caller_values}), report_fixture(intent.plan_id),
            outbox_fixture(plan_id=intent.plan_id), "sha256:" + "0" * 64, None, (),
        )
        original_digest = bundle_digest(bundle)

        caller_values.append(caller_values[0])

        assert isinstance(getattr(bundle.plan, field), tuple)
        assert len(getattr(bundle.plan, field)) == len(getattr(original_plan, field))
        assert bundle_digest(bundle) == original_digest


def test_canonical_digest_rejects_non_string_mapping_keys_at_every_depth():
    with pytest.raises(ValueError, match="string keys"):
        canonical_digest({1: "one"})
    with pytest.raises(ValueError, match="string keys"):
        canonical_digest({"outer": [{"nested": {1: "one"}}]})


@pytest.mark.parametrize("value", (math.nan, math.inf, -math.inf), ids=("nan", "infinity", "negative-infinity"))
def test_canonical_contract_rejects_nonfinite_floats_before_freezing_or_hashing(value):
    with pytest.raises(ValueError, match="finite"):
        canonical_digest({"value": value})

    with pytest.raises(ValueError, match="finite"):
        ProvisioningPreflightReport(
            "preflight.nonfinite", "plan.nonfinite", {"nested": [{"value": value}]},
            (PreflightCheck("INTENT_VALID", "passed", "sha256:" + "1" * 64, "summary"),),
            True, "sha256:" + "3" * 64,
        )


def test_bundle_rejects_malformed_outbox_entry_with_value_error():
    bundle = bundle_fixture()

    with pytest.raises(ValueError, match="bundle requires four exact"):
        ProvisioningBundleV1(
            bundle.schema_version, bundle.intent, bundle.plan, bundle.preflight,
            (object(), *bundle.outbox[1:]), bundle.bundle_digest,
            bundle.supersedes_plan_id, bundle.changed_immutable_inputs,
        )
