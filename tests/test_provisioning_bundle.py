"""Contract tests for the bounded typed provisioning bundle boundary."""
from __future__ import annotations

import hashlib
import json
import math
import sqlite3
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType

import pytest

from overseer.backup_provisioning import build_plan
from overseer.backup_host_operations import capability_digest as reviewed_capability_digest
from overseer.core import OwnerDomain, RiskLevel
from overseer.crew import CrewMessage, CrewMessageStatus, CrewReviewStatus
from overseer.provisioning_bundle import (
    PreflightDependencies,
    PreflightCheck,
    ProvisioningBundleV1,
    ProvisioningBundleError,
    ProvisioningIntentV1,
    ProvisioningPreflightReport,
    ProvisioningReviewOutboxEntry,
    REQUIRED_PREFLIGHT_CODES,
    build_provisioning_bundle,
    bundle_digest,
    canonical_root_target_digest,
    canonical_digest,
    changed_immutable_inputs,
    parse_provisioning_intent,
    run_provisioning_preflight,
)
from overseer.storage_control import (
    approve_authorization,
    materialize_authorization,
    revoke_authorization,
    stage_authorization,
)
from overseer.store import SQLiteStore


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
    plan_digest: str = "sha256:" + "a" * 64,
    report_digest: str = "sha256:" + "b" * 64,
    bundle_digest: str = "sha256:" + "0" * 64,
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
            bundle_digest=bundle_digest,
            role=role,
            owner_domain=owner,
            related_resource_id="storage.donuthole",
            subject="Review exact DonutHole provisioning bundle",
            message="Review the immutable plan and preflight evidence only.",
            acceptance_criteria=("Review the exact immutable evidence.",),
            evidence_ids=(plan_digest, report_digest, bundle_digest),
            state=outbox_state,
        )
        for role, owner in roles
    )


def bundle_fixture(*, outbox_state: str = "pending") -> ProvisioningBundleV1:
    intent = intent_fixture()
    plan = plan_fixture(intent.plan_id)
    report = report_fixture(intent.plan_id)
    digest = "sha256:" + "0" * 64
    return ProvisioningBundleV1(
        schema_version="1",
        intent=intent,
        plan=plan,
        preflight=report,
        outbox=outbox_fixture(plan_id=intent.plan_id, plan_digest=plan.plan_digest, report_digest=report.report_digest, bundle_digest=digest, outbox_state=outbox_state),
        bundle_digest=digest,
        supersedes_plan_id=None,
        changed_immutable_inputs=(),
    )


def seeded_authority_store(tmp_path, *, root_identity: str = "sha256:" + "e" * 64) -> str:
    store_path = str(tmp_path / "state.sqlite3")
    now = datetime.now(UTC)
    with SQLiteStore(store_path) as store:
        store.save_crew_message(CrewMessage(
            "crew.kira.root-review", OwnerDomain.KIRA, "Root review", "Approved root",
            RiskLevel.HIGH, CrewMessageStatus.ACKNOWLEDGED,
            review_status=CrewReviewStatus.APPROVED, decided_by="kira", decided_at=now.isoformat(),
        ))
    payload = {
        "authorization_ref": "root-auth.current", "action": "root.register",
        "project_id": "project.donuthole", "root_id": "backup-root", "policy_revision": "1",
        "root_identity": root_identity, "alias": "donuthole-development", "status": "active",
        "max_bytes": 1073741824, "target_digest": canonical_root_target_digest(root_identity),
        "expires_at": (now + timedelta(days=1)).isoformat(),
    }
    stage_authorization(store_path, "root", payload, "crew.kira.root-review", "kira", now.isoformat())
    approve_authorization(store_path, "root-auth.current", "human", now.isoformat())
    materialize_authorization(store_path, "root-auth.current", now.isoformat())
    return store_path


def deterministic_dependencies(
    *, source_head: str = "b" * 40, root_identity: str = "sha256:" + "e" * 64,
    executable_available: bool = True, canonical_boundaries_valid: bool = True,
    rollback_prerequisites_valid: bool = True,
) -> PreflightDependencies:
    return PreflightDependencies(
        source_path="/home/god/Documents/Codex Workspace/TheUnderdark",
        source_head=lambda _path: source_head,
        runtime_digest=lambda _path, _commit: "sha256:" + "d" * 64,
        capability_digest=lambda commit, schemas: reviewed_capability_digest(commit, schemas, "1"),
        file_digest=lambda _path: "sha256:" + "a" * 64,
        executable_exists=lambda _path: executable_available,
        root_identity=lambda _path: root_identity,
        canonical_boundaries_valid=lambda: canonical_boundaries_valid,
        rollback_prerequisites_valid=lambda: rollback_prerequisites_valid,
    )


def test_canonical_root_target_digest_is_versioned_and_deterministic():
    identity = "sha256:" + "e" * 64

    assert canonical_root_target_digest(identity) == canonical_root_target_digest(identity)
    assert canonical_root_target_digest(identity) != canonical_root_target_digest("sha256:" + "f" * 64)


def test_preflight_resolves_authoritative_inputs_without_mutation(tmp_path):
    store_path = seeded_authority_store(tmp_path)
    before = Path(store_path).read_bytes()

    report = run_provisioning_preflight(store_path, intent_fixture(), deterministic_dependencies())

    assert report.passed is True
    assert [check.code for check in report.checks] == list(REQUIRED_PREFLIGHT_CODES)
    assert report.resolved_inputs["authorization_ref"] == "root-auth.current"
    assert Path(store_path).read_bytes() == before


def test_default_authority_resolution_is_read_only_for_absent_and_existing_stores(tmp_path):
    absent = tmp_path / "absent.sqlite3"
    absent_report = run_provisioning_preflight(str(absent), intent_fixture(), deterministic_dependencies())

    assert absent.exists() is False
    assert list(tmp_path.glob("absent.sqlite3*")) == []
    assert next(check for check in absent_report.checks if check.code == "ROOT_AUTHORIZATION_CURRENT").status == "failed"

    store_path = Path(seeded_authority_store(tmp_path))
    observed = lambda: sorted((path.name, path.read_bytes()) for path in tmp_path.glob("state.sqlite3*"))
    before = (store_path.stat().st_ino, store_path.stat().st_mode, store_path.stat().st_mtime_ns, store_path.stat().st_ctime_ns, store_path.read_bytes(), observed())
    report = run_provisioning_preflight(str(store_path), intent_fixture(), deterministic_dependencies())
    after = (store_path.stat().st_ino, store_path.stat().st_mode, store_path.stat().st_mtime_ns, store_path.stat().st_ctime_ns, store_path.read_bytes(), observed())

    assert report.passed is True
    assert after == before


def test_default_authority_resolution_rejects_checkpointed_revocation_without_mutation(tmp_path):
    store_path = Path(seeded_authority_store(tmp_path))
    revoke_authorization(str(store_path), "root-auth.current", "human", "crew.kira.root-review")
    observed = lambda: sorted(
        (path.name, path.stat().st_ino, path.stat().st_mode, path.stat().st_mtime_ns,
         path.stat().st_ctime_ns, path.read_bytes())
        for path in tmp_path.glob("state.sqlite3*")
    )
    before = observed()

    report = run_provisioning_preflight(str(store_path), intent_fixture(), deterministic_dependencies())

    assert next(check for check in report.checks if check.code == "ROOT_AUTHORIZATION_CURRENT").status == "failed"
    assert [check.code for check in report.checks] == list(REQUIRED_PREFLIGHT_CODES)
    assert "root-auth.current" not in repr(report)
    assert observed() == before


def test_default_authority_resolution_rejects_wal_only_revocation_without_mutation(tmp_path):
    store_path = Path(seeded_authority_store(tmp_path))
    writer = sqlite3.connect(store_path)
    try:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() == "wal"
        writer.execute(
            "INSERT INTO storage_authorization_revocations VALUES(?,?,?,?,?,?)",
            ("revoke.root-auth.current", "root", "root-auth.current", "human", datetime.now(UTC).isoformat(), "crew.kira.root-review"),
        )
        writer.commit()
        observed = lambda: sorted(
            (path.name, path.stat().st_ino, path.stat().st_mode, path.stat().st_mtime_ns,
             path.stat().st_ctime_ns, path.read_bytes())
            for path in tmp_path.glob("state.sqlite3*")
        )
        before = observed()

        report = run_provisioning_preflight(str(store_path), intent_fixture(), deterministic_dependencies())

        assert next(check for check in report.checks if check.code == "ROOT_AUTHORIZATION_CURRENT").status == "failed"
        assert [check.code for check in report.checks] == list(REQUIRED_PREFLIGHT_CODES)
        assert observed() == before
    finally:
        writer.close()


def test_default_authority_resolution_normalizes_same_instant_approval_times(tmp_path):
    store_path = seeded_authority_store(tmp_path)
    now = datetime.now(UTC).replace(microsecond=0)
    payload = {
        "authorization_ref": "root-auth.same-instant", "action": "root.register",
        "project_id": "project.donuthole", "root_id": "backup-root", "policy_revision": "1",
        "root_identity": "sha256:" + "e" * 64, "alias": "donuthole-development", "status": "active",
        "max_bytes": 1073741824, "target_digest": canonical_root_target_digest("sha256:" + "e" * 64),
        "expires_at": (now + timedelta(days=1)).isoformat(),
    }
    stage_authorization(store_path, "root", payload, "crew.kira.root-review", "kira", now.isoformat())
    approve_authorization(store_path, "root-auth.same-instant", "human", now.astimezone(timezone(timedelta(hours=1))).isoformat())
    materialize_authorization(store_path, "root-auth.same-instant", now.isoformat())
    connection = sqlite3.connect(store_path)
    try:
        approval = json.loads(connection.execute("SELECT payload FROM approvals WHERE id=?", ("approval.storage.root.root-auth.current",)).fetchone()[0])
        approval["decided_at"] = now.isoformat()
        connection.execute("UPDATE approvals SET payload=? WHERE id=?", (json.dumps(approval, sort_keys=True, separators=(",", ":")), "approval.storage.root.root-auth.current"))
        root = json.loads(connection.execute("SELECT payload FROM storage_root_authorizations WHERE id=?", ("root-auth.current",)).fetchone()[0])
        root["approved_at"] = now.isoformat()
        connection.execute("UPDATE storage_root_authorizations SET payload=? WHERE id=?", (json.dumps(root, sort_keys=True, separators=(",", ":")), "root-auth.current"))
        connection.commit()
    finally:
        connection.close()

    report = run_provisioning_preflight(store_path, intent_fixture(), deterministic_dependencies())

    assert next(check for check in report.checks if check.code == "ROOT_AUTHORIZATION_CURRENT").status == "failed"


def test_default_authority_resolution_rejects_incomplete_approval_payload_and_row_mismatch(tmp_path):
    store_path = seeded_authority_store(tmp_path)
    connection = sqlite3.connect(store_path)
    try:
        connection.execute(
            "UPDATE approvals SET subject_id=?, payload=? WHERE id=?",
            ("wrong-subject", json.dumps({"id": "approval.storage.root.root-auth.current", "subject_id": "root-auth.current", "status": "approved"}), "approval.storage.root.root-auth.current"),
        )
        connection.commit()
    finally:
        connection.close()
    before = Path(store_path).read_bytes()

    report = run_provisioning_preflight(store_path, intent_fixture(), deterministic_dependencies())

    assert next(check for check in report.checks if check.code == "ROOT_AUTHORIZATION_CURRENT").status == "failed"
    assert [check.code for check in report.checks] == list(REQUIRED_PREFLIGHT_CODES)
    assert "wrong-subject" not in repr(report)
    assert Path(store_path).read_bytes() == before


def test_preflight_fails_closed_on_changed_source_or_authority(tmp_path):
    dependencies = deterministic_dependencies(source_head="f" * 40)
    store_path = seeded_authority_store(tmp_path)
    before = Path(store_path).read_bytes()

    report = run_provisioning_preflight(store_path, intent_fixture(), dependencies)

    assert report.passed is False
    assert next(check for check in report.checks if check.status == "failed").code == "SOURCE_COMMIT_MATCH"
    assert "private" not in repr(report)
    assert Path(store_path).read_bytes() == before


def test_preflight_fails_closed_on_changed_root_authority_without_mutation(tmp_path):
    store_path = seeded_authority_store(tmp_path)
    before = Path(store_path).read_bytes()

    report = run_provisioning_preflight(
        store_path, intent_fixture(), deterministic_dependencies(root_identity="sha256:" + "f" * 64),
    )

    assert report.passed is False
    assert next(check for check in report.checks if check.status == "failed").code == "ROOT_AUTHORIZATION_CURRENT"
    assert Path(store_path).read_bytes() == before


def test_preflight_redacts_unavailable_dependency_exceptions(tmp_path):
    store_path = seeded_authority_store(tmp_path)
    before = Path(store_path).read_bytes()
    dependencies = replace(
        deterministic_dependencies(),
        file_digest=lambda _path: (_ for _ in ()).throw(RuntimeError("private token material")),
    )

    report = run_provisioning_preflight(store_path, intent_fixture(), dependencies)

    assert report.passed is False
    assert next(check for check in report.checks if check.code == "GPG_DIGEST_VALID").status == "failed"
    assert "private" not in repr(report)
    assert "token" not in repr(report)
    assert Path(store_path).read_bytes() == before


def test_preflight_redacts_sqlite_dependency_errors_and_returns_all_checks(tmp_path):
    dependencies = replace(
        deterministic_dependencies(),
        runtime_digest=lambda _path, _commit: (_ for _ in ()).throw(sqlite3.OperationalError("private sqlite failure")),
    )

    report = run_provisioning_preflight(str(tmp_path / "absent.sqlite3"), intent_fixture(), dependencies)

    assert [check.code for check in report.checks] == list(REQUIRED_PREFLIGHT_CODES)
    assert next(check for check in report.checks if check.code == "RUNTIME_DIGEST_VALID").status == "failed"
    assert "private sqlite failure" not in repr(report)


@pytest.mark.parametrize(
    ("dependencies", "code"),
    (
        (deterministic_dependencies(executable_available=False), "DEPENDENCIES_AVAILABLE"),
        (deterministic_dependencies(canonical_boundaries_valid=False), "CANONICAL_BOUNDARIES_VALID"),
        (deterministic_dependencies(rollback_prerequisites_valid=False), "ROLLBACK_PREREQUISITES_VALID"),
    ),
)
def test_preflight_returns_all_stable_checks_when_a_prerequisite_fails(tmp_path, dependencies, code):
    store_path = seeded_authority_store(tmp_path)
    before = Path(store_path).read_bytes()

    report = run_provisioning_preflight(store_path, intent_fixture(), dependencies)

    assert [check.code for check in report.checks] == list(REQUIRED_PREFLIGHT_CODES)
    assert next(check for check in report.checks if check.code == code).status == "failed"
    assert Path(store_path).read_bytes() == before


def test_preflight_requires_the_reviewed_capability_digest(tmp_path):
    store_path = seeded_authority_store(tmp_path)
    dependencies = replace(
        deterministic_dependencies(), capability_digest=lambda _commit, _schemas: "sha256:" + "f" * 64,
    )

    report = run_provisioning_preflight(store_path, intent_fixture(), dependencies)

    assert next(check for check in report.checks if check.code == "CAPABILITY_DIGEST_VALID").status == "failed"


def test_built_bundle_preflight_capability_digest_matches_its_plan(tmp_path):
    store_path = seeded_authority_store(tmp_path)
    expected = reviewed_capability_digest("b" * 40, __import__("overseer.backup_host_operations", fromlist=["EXPECTED_BACKUP_TOOL_SCHEMAS"]).EXPECTED_BACKUP_TOOL_SCHEMAS, "1")
    dependencies = replace(deterministic_dependencies(), capability_digest=lambda _commit, _schemas: expected)

    bundle = build_provisioning_bundle(store_path, intent_fixture(), dependencies)

    assert bundle.preflight.resolved_inputs["capability_digest"] == bundle.plan.capability_digest == expected


def test_authoritative_bundle_is_deterministic_and_does_not_mutate_store(tmp_path):
    store_path = seeded_authority_store(tmp_path)
    before = Path(store_path).read_bytes()

    first = build_provisioning_bundle(store_path, intent_fixture(), deterministic_dependencies())
    second = build_provisioning_bundle(store_path, intent_fixture(), deterministic_dependencies())

    assert first.bundle_digest == second.bundle_digest == bundle_digest(first)
    assert tuple(entry.role for entry in first.outbox) == ("kira", "obrien", "security", "sisko")
    assert all(entry.evidence_ids == (first.plan.plan_digest, first.preflight.report_digest, first.bundle_digest) for entry in first.outbox)
    assert Path(store_path).read_bytes() == before


def test_bundle_rejects_missing_non_tip_and_superseded_predecessors_without_mutation(tmp_path):
    store_path = seeded_authority_store(tmp_path)
    before = Path(store_path).read_bytes()
    predecessor = build_provisioning_bundle(store_path, intent_fixture(), deterministic_dependencies())
    successor = intent_fixture(
        plan_id="backup-provision.donuthole.v21.20260802",
        supersedes_plan_id=predecessor.plan.plan_id,
    )

    with pytest.raises(ProvisioningBundleError, match="PREDECESSOR_UNAVAILABLE"):
        build_provisioning_bundle(store_path, successor, deterministic_dependencies())
    with pytest.raises(ProvisioningBundleError, match="PREDECESSOR_NOT_CURRENT"):
        build_provisioning_bundle(
            store_path, successor,
            replace(deterministic_dependencies(), predecessor_lookup=lambda _id: predecessor, authoritative_chain_tip=lambda: "other-plan"),
        )
    superseded_predecessor = replace(
        predecessor,
        intent=replace(predecessor.intent, supersedes_plan_id=successor.plan_id),
        supersedes_plan_id=successor.plan_id,
    )
    with pytest.raises(ProvisioningBundleError, match="PREDECESSOR_INVALID"):
        build_provisioning_bundle(
            store_path, successor,
            replace(deterministic_dependencies(), predecessor_lookup=lambda _id: superseded_predecessor, authoritative_chain_tip=lambda: predecessor.plan.plan_id),
        )
    assert Path(store_path).read_bytes() == before


@pytest.mark.parametrize(
    "tamper",
    (
        lambda bundle: (object.__setattr__(bundle, "bundle_digest", "sha256:" + "f" * 64), bundle)[1],
        lambda bundle: (object.__setattr__(bundle.plan, "plan_digest", "sha256:" + "f" * 64), bundle)[1],
        lambda bundle: (object.__setattr__(bundle.preflight, "report_digest", "sha256:" + "f" * 64), bundle)[1],
        lambda bundle: (object.__setattr__(bundle.outbox[0], "evidence_ids", (bundle.plan.plan_digest, bundle.preflight.report_digest, "sha256:" + "f" * 64)), bundle)[1],
    ),
    ids=("bundle-digest", "plan-digest", "preflight-digest", "review-evidence"),
)
def test_successor_rejects_a_tampered_predecessor_contract(tmp_path, tamper):
    store_path = seeded_authority_store(tmp_path)
    predecessor = build_provisioning_bundle(store_path, intent_fixture(), deterministic_dependencies())
    successor = intent_fixture(plan_id="backup-provision.donuthole.v21.20260802", supersedes_plan_id=predecessor.plan.plan_id)

    with pytest.raises(ProvisioningBundleError, match="PREDECESSOR_INVALID"):
        build_provisioning_bundle(
            store_path,
            successor,
            replace(deterministic_dependencies(), predecessor_lookup=lambda _id: tamper(predecessor), authoritative_chain_tip=lambda: predecessor.plan.plan_id),
        )


def test_successor_rejects_coherently_redigested_predecessor_cross_binding_tampering(tmp_path):
    store_path = seeded_authority_store(tmp_path)
    predecessor = build_provisioning_bundle(store_path, intent_fixture(), deterministic_dependencies())
    resolved = {**predecessor.preflight.resolved_inputs, "authorization_ref": "root-auth.forged"}
    report_digest = canonical_digest({
        "report_id": predecessor.preflight.report_id, "plan_id": predecessor.preflight.plan_id,
        "resolved_inputs": resolved, "checks": [asdict(check) for check in predecessor.preflight.checks],
    })
    report = replace(predecessor.preflight, resolved_inputs=resolved, report_digest=report_digest)
    provisional = ProvisioningBundleV1(
        predecessor.schema_version, predecessor.intent, predecessor.plan, report,
        outbox_fixture(plan_id=predecessor.plan.plan_id, plan_digest=predecessor.plan.plan_digest, report_digest=report.report_digest, bundle_digest=predecessor.bundle_digest),
        predecessor.bundle_digest, predecessor.supersedes_plan_id, predecessor.changed_immutable_inputs,
    )
    digest = bundle_digest(provisional)
    forged = ProvisioningBundleV1(
        predecessor.schema_version, predecessor.intent, predecessor.plan, report,
        outbox_fixture(plan_id=predecessor.plan.plan_id, plan_digest=predecessor.plan.plan_digest, report_digest=report.report_digest, bundle_digest=digest),
        digest, predecessor.supersedes_plan_id, predecessor.changed_immutable_inputs,
    )
    successor = intent_fixture(plan_id="backup-provision.donuthole.v21.20260802", supersedes_plan_id=predecessor.plan.plan_id)

    with pytest.raises(ProvisioningBundleError, match="PREDECESSOR_INVALID"):
        build_provisioning_bundle(
            store_path, successor,
            replace(deterministic_dependencies(), predecessor_lookup=lambda _id: forged, authoritative_chain_tip=lambda: predecessor.plan.plan_id),
        )


def test_changed_immutable_inputs_are_sorted_and_limited_to_immutable_values(tmp_path):
    store_path = seeded_authority_store(tmp_path)
    previous = build_provisioning_bundle(store_path, intent_fixture(), deterministic_dependencies())
    changed_plan = replace(previous.plan, gpg_sha256="sha256:" + "f" * 64)
    changed_report = replace(
        previous.preflight,
        resolved_inputs={**previous.preflight.resolved_inputs, "authorization_ref": "root-auth.replaced"},
    )

    assert changed_immutable_inputs(previous, changed_plan, changed_report) == (
        "gpg_sha256", "resolved_preflight",
    )


def test_changed_immutable_inputs_ignore_derived_successor_plan_identity_but_detect_authority_changes(tmp_path):
    store_path = seeded_authority_store(tmp_path)
    previous = build_provisioning_bundle(store_path, intent_fixture(), deterministic_dependencies())
    successor = build_provisioning_bundle(
        store_path,
        intent_fixture(plan_id="backup-provision.donuthole.v21.20260802", supersedes_plan_id=previous.plan.plan_id),
        replace(deterministic_dependencies(), predecessor_lookup=lambda _id: previous, authoritative_chain_tip=lambda: previous.plan.plan_id),
    )

    assert successor.changed_immutable_inputs == ()
    changed_plan = replace(successor.plan, gpg_sha256="sha256:" + "f" * 64, runtime_digest="sha256:" + "e" * 64, capability_digest="sha256:" + "d" * 64)
    changed_report = replace(successor.preflight, resolved_inputs={**successor.preflight.resolved_inputs, "root_identity": "sha256:" + "f" * 64})

    assert changed_immutable_inputs(previous, changed_plan, changed_report) == (
        "capability_digest", "gpg_sha256", "resolved_preflight", "runtime_digest",
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
                    ("Review a different exact immutable evidence set.",), entry.evidence_ids, entry.state,
            )
            for index, entry in enumerate(first.outbox)
        ),
        first.bundle_digest,
        first.supersedes_plan_id,
        first.changed_immutable_inputs,
    )

    assert bundle_digest(first) != bundle_digest(changed)


@pytest.mark.parametrize(
    "evidence_ids",
    (
        lambda bundle: (bundle.plan.plan_digest, bundle.preflight.report_digest),
        lambda bundle: (bundle.plan.plan_digest, bundle.preflight.report_digest, bundle.bundle_digest, "sha256:" + "f" * 64),
        lambda bundle: (bundle.preflight.report_digest, bundle.plan.plan_digest, bundle.bundle_digest),
        lambda bundle: (bundle.plan.plan_digest, "sha256:" + "f" * 64, bundle.bundle_digest),
    ),
    ids=("missing", "extra", "reordered", "unrelated"),
)
def test_bundle_rejects_non_exact_outbox_evidence(evidence_ids):
    bundle = bundle_fixture()
    outbox = tuple(replace(entry, evidence_ids=evidence_ids(bundle)) for entry in bundle.outbox)

    with pytest.raises(ValueError, match="outbox evidence"):
        ProvisioningBundleV1(
            bundle.schema_version, bundle.intent, bundle.plan, bundle.preflight, outbox,
            bundle.bundle_digest, bundle.supersedes_plan_id, bundle.changed_immutable_inputs,
        )


def test_bundle_digest_converges_after_outbox_entries_receive_its_derived_value():
    provisional = bundle_fixture()
    digest = bundle_digest(provisional)
    bound_outbox = tuple(
        ProvisioningReviewOutboxEntry(
            entry.id, entry.message_id, entry.plan_id, digest, entry.role,
            entry.owner_domain, entry.related_resource_id, entry.subject, entry.message,
            entry.acceptance_criteria, (entry.evidence_ids[0], entry.evidence_ids[1], digest), entry.state,
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
    report = report_fixture(intent.plan_id)
    digest = "sha256:" + "0" * 64
    original_evidence = plan.evidence_ids
    original_arguments = plan.steps[0].arguments
    bundle = ProvisioningBundleV1(
        "1", intent, plan, report,
        outbox_fixture(plan_id=intent.plan_id, plan_digest=plan.plan_digest, report_digest=report.report_digest, bundle_digest=digest), digest, None, (),
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
        report = report_fixture(intent.plan_id)
        digest = "sha256:" + "0" * 64
        bundle = ProvisioningBundleV1(
            "1", intent, replace(original_plan, **{field: caller_values}), report,
            outbox_fixture(plan_id=intent.plan_id, plan_digest=original_plan.plan_digest, report_digest=report.report_digest, bundle_digest=digest), digest, None, (),
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
