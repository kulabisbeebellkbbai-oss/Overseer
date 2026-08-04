"""Contract tests for the bounded typed provisioning bundle boundary."""
from __future__ import annotations

import hashlib
import inspect
import json
import math
import os
import shutil
import sqlite3
import tempfile
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
    _PreflightDependencies as PreflightDependencies,
    _build_provisioning_bundle_with_dependencies as build_provisioning_bundle,
    _run_provisioning_preflight_with_dependencies as run_provisioning_preflight,
    PreflightCheck,
    ProvisioningBundleV1,
    ProvisioningBundleError,
    ProvisioningIntentV1,
    ProvisioningPreflightReport,
    ProvisioningReviewOutboxEntry,
    REQUIRED_PREFLIGHT_CODES,
    bundle_digest,
    canonical_root_target_digest,
    canonical_digest,
    changed_immutable_inputs,
    parse_provisioning_intent,
)
from overseer.storage_control import (
    approve_authorization,
    materialize_authorization,
    revoke_authorization,
    stage_authorization,
)
from overseer.store import SQLiteStore
from overseer import provisioning_bundle as provisioning_bundle_module


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
    authorization_ref = "root-auth.current"
    target_digest = canonical_root_target_digest(root_identity)
    staged_payload = {
        "authorization_ref": authorization_ref, "action": "root.register",
        "project_id": "project.donuthole", "root_id": "backup-root", "policy_revision": "1",
        "root_identity": root_identity, "alias": "donuthole-development", "status": "active",
        "max_bytes": 1073741824, "target_digest": target_digest,
        "expires_at": (now + timedelta(days=1)).isoformat(),
    }
    staged_digest = canonical_digest(staged_payload)
    with SQLiteStore(store_path) as store:
        store.save_crew_message(CrewMessage(
            "crew.kira.root-review", OwnerDomain.KIRA, "Root review", "Approved root",
            RiskLevel.HIGH, CrewMessageStatus.ACKNOWLEDGED,
            related_resource_id="backup-root", related_plan_id=authorization_ref,
            review_status=CrewReviewStatus.APPROVED,
            decision_reason=(f"Kira terminal approval for authorization {authorization_ref} "
                             f"staged authorization digest {staged_digest} root identity {root_identity} "
                             f"target digest {target_digest}"),
            decision_evidence_ids=(staged_digest, root_identity, target_digest),
            request_evidence_ids=(staged_digest, root_identity, target_digest),
            decided_by="kira", decided_at=now.isoformat(),
        ))
    stage_authorization(store_path, "root", staged_payload, "crew.kira.root-review", "kira", now.isoformat())
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


def authoritative_bundle_fixture(
    tmp_path, *, source_commit: str = "b" * 40,
) -> tuple[str, ProvisioningBundleV1]:
    """Build one valid bundle against a disposable authoritative root."""
    store_path = seeded_authority_store(tmp_path)
    intent = intent_fixture(source_commit=source_commit)
    bundle = build_provisioning_bundle(
        store_path,
        intent,
        deterministic_dependencies(source_head=source_commit),
    )
    return store_path, bundle


def expected_preview_digests(bundle: ProvisioningBundleV1):
    return provisioning_bundle_module.ProvisioningPreviewDigests(
        plan_digest=bundle.plan.plan_digest,
        preflight_digest=bundle.preflight.report_digest,
        bundle_digest=bundle.bundle_digest,
    )


def stage_expected_bundle(
    store_path: str,
    bundle: ProvisioningBundleV1,
    dependencies: PreflightDependencies | None = None,
):
    authoritative_dependencies = dependencies or deterministic_dependencies(
        source_head=bundle.intent.source_commit,
    )
    return provisioning_bundle_module._stage_authoritative_bundle_with_dependencies(
        store_path,
        bundle.intent,
        authoritative_dependencies,
        expected_preview_digests(bundle),
    )


def persisted_bundle_rows(store_path: str, plan_id: str) -> dict[str, int]:
    """Count only Task 3 records, excluding the prerequisite root evidence."""
    tables = {
        "plans": "backup_provisioning_plans",
        "bindings": "roadex_approval_bindings",
        "reports": "provisioning_preflight_reports",
        "bundles": "provisioning_bundles",
        "outbox": "provisioning_review_outbox",
    }
    with SQLiteStore(store_path) as store:
        available = {
            str(row["name"])
            for row in store._connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        counts = {}
        for name, table in tables.items():
            if table not in available:
                counts[name] = 0
            elif name == "plans":
                counts[name] = int(store._connection.execute(
                    "SELECT COUNT(*) AS count FROM backup_provisioning_plans WHERE id=?",
                    (plan_id,),
                ).fetchone()["count"])
            elif name == "bindings":
                counts[name] = int(store._connection.execute(
                    "SELECT COUNT(*) AS count FROM roadex_approval_bindings WHERE source_id=?",
                    (plan_id,),
                ).fetchone()["count"])
            else:
                counts[name] = int(store._connection.execute(
                    f"SELECT COUNT(*) AS count FROM {table} WHERE plan_id=?",
                    (plan_id,),
                ).fetchone()["count"])
        counts["crew"] = int(
            store._connection.execute(
                "SELECT COUNT(*) AS count FROM crew_messages WHERE payload LIKE ?",
                (f'%"related_plan_id":"{plan_id}"%',),
            ).fetchone()["count"]
        )
    return counts


def test_atomic_stage_rolls_back_every_source_binding_bundle_boundary(tmp_path, monkeypatch):
    """Every callback write must be protected by the one binding transaction."""
    store_path, bundle = authoritative_bundle_fixture(tmp_path)
    expected = {
        "plans": 0, "bindings": 0, "reports": 0,
        "bundles": 0, "outbox": 0, "crew": 0,
    }

    for method_name in (
        "save_backup_provisioning_plan_payload",
        "save_provisioning_preflight_report",
        "save_provisioning_bundle",
        "save_provisioning_review_outbox",
        "save_roadex_approval_binding",
    ):
        def fail_boundary(*_arguments, name=method_name, **_kwargs):
            raise RuntimeError(f"injected {name} failure")

        with monkeypatch.context() as scoped:
            scoped.setattr(SQLiteStore, method_name, fail_boundary, raising=False)
            with pytest.raises(RuntimeError, match=f"injected {method_name} failure"):
                stage_expected_bundle(store_path, bundle)
        assert persisted_bundle_rows(store_path, bundle.plan.plan_id) == expected


def test_correction_silently_omitted_fourth_outbox_rolls_back_every_record(tmp_path, monkeypatch):
    store_path, bundle = authoritative_bundle_fixture(tmp_path)
    original = SQLiteStore.save_provisioning_review_outbox
    calls = {"count": 0}

    def omit_fourth(self, *arguments, **kwargs):
        calls["count"] += 1
        if calls["count"] == 4:
            return None
        return original(self, *arguments, **kwargs)

    monkeypatch.setattr(SQLiteStore, "save_provisioning_review_outbox", omit_fourth)

    with pytest.raises(ValueError, match="outbox"):
        stage_expected_bundle(store_path, bundle)

    assert persisted_bundle_rows(store_path, bundle.plan.plan_id) == {
        "plans": 0, "bindings": 0, "reports": 0,
        "bundles": 0, "outbox": 0, "crew": 0,
    }


@pytest.mark.parametrize("replay", (False, True))
def test_correction_locked_root_recheck_rejects_revocation_after_outer_recheck(
    tmp_path, monkeypatch, replay,
):
    store_path, bundle = authoritative_bundle_fixture(tmp_path)
    if replay:
        stage_expected_bundle(store_path, bundle)
        before = persisted_bundle_rows(store_path, bundle.plan.plan_id)
    else:
        before = {
            "plans": 0, "bindings": 0, "reports": 0,
            "bundles": 0, "outbox": 0, "crew": 0,
        }
    original_init = SQLiteStore.__init__
    injected = {"done": False}

    def init_then_revoke(self, path):
        original_init(self, path)
        if not injected["done"] and str(self.path) == store_path:
            self._connection.execute(
                "INSERT INTO storage_authorization_revocations "
                "(id, kind, authorization_ref, revoked_by, revoked_at, evidence_id) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    "revoke.root-auth.current",
                    "root",
                    "root-auth.current",
                    "human",
                    datetime.now(UTC).isoformat(),
                    "crew.kira.root-review",
                ),
            )
            self._commit()
            injected["done"] = True

    monkeypatch.setattr(SQLiteStore, "__init__", init_then_revoke)

    with pytest.raises(ValueError, match="STALE_PREVIEW"):
        stage_expected_bundle(store_path, bundle)

    assert persisted_bundle_rows(store_path, bundle.plan.plan_id) == before


def test_correction_typed_stage_rebuilds_and_rejects_source_head_drift(tmp_path):
    store_path = seeded_authority_store(tmp_path)
    intent = intent_fixture()
    authoritative = {"source_head": intent.source_commit}
    dependencies = deterministic_dependencies()
    dependencies = replace(
        dependencies,
        source_head=lambda _path: authoritative["source_head"],
    )
    preview = build_provisioning_bundle(store_path, intent, dependencies)
    expected = expected_preview_digests(preview)

    first = provisioning_bundle_module._stage_authoritative_bundle_with_dependencies(
        store_path,
        intent,
        dependencies,
        expected,
    )
    before = persisted_bundle_rows(store_path, intent.plan_id)
    authoritative["source_head"] = "c" * 40

    with pytest.raises(ProvisioningBundleError, match="PREFLIGHT_FAILED"):
        provisioning_bundle_module._stage_authoritative_bundle_with_dependencies(
            store_path,
            intent,
            dependencies,
            expected,
        )

    assert first["mutation_performed"] is True
    assert persisted_bundle_rows(store_path, intent.plan_id) == before


def test_correction_typed_stage_rejects_invalid_preview_and_forbidden_caller_fields(tmp_path):
    store_path, preview = authoritative_bundle_fixture(tmp_path)
    dependencies = deterministic_dependencies(source_head=preview.intent.source_commit)
    expected = expected_preview_digests(preview)
    empty = {
        "plans": 0, "bindings": 0, "reports": 0,
        "bundles": 0, "outbox": 0, "crew": 0,
    }

    with pytest.raises(TypeError):
        provisioning_bundle_module.ProvisioningPreviewDigests(
            plan_digest=preview.plan.plan_digest,
            preflight_digest=preview.preflight.report_digest,
        )
    with pytest.raises(ValueError, match="preview digest"):
        provisioning_bundle_module.ProvisioningPreviewDigests(
            plan_digest="not-a-digest",
            preflight_digest=preview.preflight.report_digest,
            bundle_digest=preview.bundle_digest,
        )
    with pytest.raises(TypeError):
        provisioning_bundle_module._stage_authoritative_bundle_with_dependencies(
            store_path,
            preview.intent,
            dependencies,
        )
    with pytest.raises(ValueError, match="expected preview"):
        provisioning_bundle_module._stage_authoritative_bundle_with_dependencies(
            store_path,
            preview.intent,
            dependencies,
            {
                "plan_digest": preview.plan.plan_digest,
                "preflight_digest": preview.preflight.report_digest,
                "bundle_digest": preview.bundle_digest,
                "authorization_ref": "root-auth.current",
            },
        )
    with pytest.raises(ValueError, match="typed provisioning intent"):
        provisioning_bundle_module._stage_authoritative_bundle_with_dependencies(
            store_path,
            {**intent_payload(), "authorization_ref": "root-auth.current"},
            dependencies,
            expected,
        )
    with pytest.raises(ValueError, match="PREVIEW_MISMATCH"):
        provisioning_bundle_module._stage_authoritative_bundle_with_dependencies(
            store_path,
            preview.intent,
            dependencies,
            replace(expected, bundle_digest="sha256:" + "f" * 64),
        )

    assert persisted_bundle_rows(store_path, preview.plan.plan_id) == empty


def test_correction_typed_stage_rejects_extra_attributes_on_typed_inputs(tmp_path):
    store_path, preview = authoritative_bundle_fixture(tmp_path)
    dependencies = deterministic_dependencies(source_head=preview.intent.source_commit)
    expected = expected_preview_digests(preview)
    tainted_intent = replace(preview.intent)
    object.__setattr__(tainted_intent, "approval_ref", "root-auth.current")
    tainted_expected = replace(expected)
    object.__setattr__(tainted_expected, "evidence_ids", ("sha256:" + "a" * 64,))

    with pytest.raises(ValueError, match="typed provisioning intent"):
        provisioning_bundle_module._stage_authoritative_bundle_with_dependencies(
            store_path,
            tainted_intent,
            dependencies,
            expected,
        )
    with pytest.raises(ValueError, match="expected preview"):
        provisioning_bundle_module._stage_authoritative_bundle_with_dependencies(
            store_path,
            preview.intent,
            dependencies,
            tainted_expected,
        )

    assert persisted_bundle_rows(store_path, preview.plan.plan_id) == {
        "plans": 0, "bindings": 0, "reports": 0,
        "bundles": 0, "outbox": 0, "crew": 0,
    }


def test_trusted_boundary_public_stage_rejects_caller_dependencies_without_writes(tmp_path):
    store_path, preview = authoritative_bundle_fixture(tmp_path)
    callback_calls = {"count": 0}

    def forged_source_head(_path):
        callback_calls["count"] += 1
        return preview.intent.source_commit

    forged = replace(
        deterministic_dependencies(source_head=preview.intent.source_commit),
        source_head=forged_source_head,
    )

    with pytest.raises(TypeError):
        provisioning_bundle_module.stage_authoritative_bundle(
            store_path,
            preview.intent,
            forged,
            expected_preview_digests(preview),
        )

    assert callback_calls["count"] == 0
    assert persisted_bundle_rows(store_path, preview.plan.plan_id) == {
        "plans": 0, "bindings": 0, "reports": 0,
        "bundles": 0, "outbox": 0, "crew": 0,
    }


def test_trusted_boundary_public_signatures_and_exports_have_no_dependency_seam():
    assert tuple(inspect.signature(
        provisioning_bundle_module.stage_authoritative_bundle,
    ).parameters) == ("store_path", "intent", "expected_preview")
    assert tuple(inspect.signature(
        provisioning_bundle_module.build_provisioning_bundle,
    ).parameters) == ("store_path", "intent")
    assert tuple(inspect.signature(
        provisioning_bundle_module.run_provisioning_preflight,
    ).parameters) == ("store_path", "intent")
    assert "PreflightDependencies" not in provisioning_bundle_module.__all__
    assert "production_preflight_dependencies" not in provisioning_bundle_module.__all__
    assert all(not name.startswith("_stage_authoritative_bundle") for name in provisioning_bundle_module.__all__)


def test_trusted_boundary_factory_runs_on_initial_replay_and_source_drift(
    tmp_path, monkeypatch,
):
    store_path, preview = authoritative_bundle_fixture(tmp_path)
    authoritative = {"source_head": preview.intent.source_commit}
    calls = {"count": 0}

    def trusted_factory(_store_path):
        calls["count"] += 1
        return replace(
            deterministic_dependencies(),
            source_head=lambda _path: authoritative["source_head"],
        )

    monkeypatch.setattr(
        provisioning_bundle_module,
        "production_preflight_dependencies",
        trusted_factory,
        raising=False,
    )
    expected = expected_preview_digests(preview)

    first = provisioning_bundle_module.stage_authoritative_bundle(
        store_path, preview.intent, expected,
    )
    second = provisioning_bundle_module.stage_authoritative_bundle(
        store_path, preview.intent, expected,
    )
    before = persisted_bundle_rows(store_path, preview.plan.plan_id)
    authoritative["source_head"] = "c" * 40

    with pytest.raises(ProvisioningBundleError, match="PREFLIGHT_FAILED"):
        provisioning_bundle_module.stage_authoritative_bundle(
            store_path, preview.intent, expected,
        )

    assert calls["count"] == 3
    assert first["mutation_performed"] is True
    assert second["mutation_performed"] is False
    assert persisted_bundle_rows(store_path, preview.plan.plan_id) == before


def test_trusted_boundary_production_factory_uses_exact_persisted_chain_read_only(tmp_path):
    store_path, preview = authoritative_bundle_fixture(tmp_path)
    stage_expected_bundle(store_path, preview)
    observed = lambda: (
        Path(store_path).stat().st_mtime_ns,
        Path(store_path).stat().st_ctime_ns,
        Path(store_path).read_bytes(),
        tuple(sorted(path.name for path in tmp_path.glob("state.sqlite3*"))),
    )
    before = observed()

    dependencies = provisioning_bundle_module.production_preflight_dependencies(store_path)
    predecessor = dependencies.predecessor_lookup(preview.plan.plan_id)
    tip = dependencies.authoritative_chain_tip(preview.plan.plan_id)

    assert predecessor == preview
    assert tip == preview.plan.plan_id
    assert dependencies.source_path == "/home/god/Documents/Codex Workspace/TheUnderdark"
    assert dependencies.root_path == "/home/god/Documents/Codex Workspace/DonutHole"
    with pytest.raises(ValueError, match="source path"):
        dependencies.source_head("/caller/selected/source")
    with pytest.raises(ValueError, match="GPG path"):
        dependencies.file_digest("/caller/selected/gpg")
    assert dependencies.executable_exists("/caller/selected/gpg") is False
    assert dependencies.canonical_boundaries_valid() is True
    assert dependencies.rollback_prerequisites_valid() is True
    assert observed() == before

    repeated = provisioning_bundle_module.production_preflight_dependencies(store_path)
    assert repeated.predecessor_lookup(preview.plan.plan_id) == predecessor
    assert repeated.authoritative_chain_tip(preview.plan.plan_id) == tip
    assert observed() == before

    with sqlite3.connect(store_path) as connection:
        connection.execute(
            "UPDATE provisioning_bundles SET payload=? WHERE plan_id=?",
            ("{}", preview.plan.plan_id),
        )
    corrupted = observed()
    with pytest.raises(ValueError, match="persisted provisioning chain is unavailable"):
        provisioning_bundle_module.production_preflight_dependencies(store_path)
    assert observed() == corrupted


def test_atomic_stage_is_exactly_idempotent_and_does_not_reenter_source_callback(tmp_path, monkeypatch):
    store_path, bundle = authoritative_bundle_fixture(tmp_path)

    first = stage_expected_bundle(store_path, bundle)

    def fail_source_reentry(*_arguments, **_kwargs):
        pytest.fail("exact persisted replay must not re-enter source persistence")

    monkeypatch.setattr(
        SQLiteStore,
        "save_backup_provisioning_plan_payload",
        fail_source_reentry,
        raising=False,
    )
    second = stage_expected_bundle(store_path, bundle)

    assert first["mutation_performed"] is True
    assert second["mutation_performed"] is False
    assert persisted_bundle_rows(store_path, bundle.plan.plan_id) == {
        "plans": 1, "bindings": 1, "reports": 1,
        "bundles": 1, "outbox": 4, "crew": 0,
    }


def test_atomic_stage_rejects_changed_replay_without_mutating_bound_source(tmp_path):
    store_path, original = authoritative_bundle_fixture(tmp_path)
    stage_expected_bundle(store_path, original)
    changed = build_provisioning_bundle(
        store_path,
        intent_fixture(source_commit="c" * 40),
        deterministic_dependencies(source_head="c" * 40),
    )
    before = persisted_bundle_rows(store_path, original.plan.plan_id)
    with SQLiteStore(store_path) as store:
        source_before = store.load_registered_source_payload(
            "backup-provisioning-plan", original.plan.plan_id,
        )
        binding_before = store.load_roadex_approval_binding(
            f"approval.donuthole.{original.plan.plan_id}",
        )

    with pytest.raises(ValueError, match="immutable"):
        stage_expected_bundle(store_path, changed)

    with SQLiteStore(store_path) as store:
        assert store.load_registered_source_payload(
            "backup-provisioning-plan", original.plan.plan_id,
        ) == source_before
        assert store.load_roadex_approval_binding(
            f"approval.donuthole.{original.plan.plan_id}",
        ) == binding_before
    assert persisted_bundle_rows(store_path, original.plan.plan_id) == before


def test_atomic_stage_rejects_partial_replay_without_reconstruction(tmp_path):
    store_path, bundle = authoritative_bundle_fixture(tmp_path)
    stage_expected_bundle(store_path, bundle)
    with SQLiteStore(store_path) as store:
        store._connection.execute(
            "DELETE FROM provisioning_preflight_reports WHERE plan_id=?",
            (bundle.plan.plan_id,),
        )
        store._commit_agent_mutation()

    with pytest.raises(ValueError, match="immutable"):
        stage_expected_bundle(store_path, bundle)

    assert persisted_bundle_rows(store_path, bundle.plan.plan_id) == {
        "plans": 1, "bindings": 1, "reports": 0,
        "bundles": 1, "outbox": 4, "crew": 0,
    }


def test_atomic_stage_rechecks_current_root_and_rejects_drift_without_writes(tmp_path):
    store_path, bundle = authoritative_bundle_fixture(tmp_path)
    revoke_authorization(store_path, "root-auth.current", "human", "crew.kira.root-review")

    with pytest.raises(ProvisioningBundleError, match="PREFLIGHT_FAILED"):
        stage_expected_bundle(store_path, bundle)

    assert persisted_bundle_rows(store_path, bundle.plan.plan_id) == {
        "plans": 0, "bindings": 0, "reports": 0,
        "bundles": 0, "outbox": 0, "crew": 0,
    }


def test_persisted_bundle_load_requires_exact_serialized_bytes_and_digests(tmp_path):
    store_path, bundle = authoritative_bundle_fixture(tmp_path)
    stage_expected_bundle(store_path, bundle)

    with SQLiteStore(store_path) as store:
        loaded = provisioning_bundle_module.load_provisioning_bundle(
            store, bundle.plan.plan_id,
        )
        assert provisioning_bundle_module.dump_provisioning_bundle(loaded) == (
            provisioning_bundle_module.dump_provisioning_bundle(bundle)
        )
        store._connection.execute(
            "UPDATE provisioning_bundles SET payload=payload || ' ' WHERE plan_id=?",
            (bundle.plan.plan_id,),
        )
        store._commit_agent_mutation()
        with pytest.raises(ValueError, match="serialized"):
            provisioning_bundle_module.load_provisioning_bundle(store, bundle.plan.plan_id)


def test_persisted_bundle_rejects_tampered_indexed_digest_metadata(tmp_path):
    store_path, bundle = authoritative_bundle_fixture(tmp_path)
    stage_expected_bundle(store_path, bundle)
    with SQLiteStore(store_path) as store:
        store._connection.execute(
            "UPDATE provisioning_bundles SET bundle_digest=? WHERE plan_id=?",
            ("sha256:" + "f" * 64, bundle.plan.plan_id),
        )
        store._commit_agent_mutation()
        with pytest.raises(ValueError, match="digest"):
            provisioning_bundle_module.load_provisioning_bundle(store, bundle.plan.plan_id)


def test_atomic_stage_replay_rejects_tampered_preflight_digest_metadata(tmp_path):
    store_path, bundle = authoritative_bundle_fixture(tmp_path)
    stage_expected_bundle(store_path, bundle)
    with SQLiteStore(store_path) as store:
        store._connection.execute(
            "UPDATE provisioning_preflight_reports SET report_digest=? WHERE plan_id=?",
            ("sha256:" + "f" * 64, bundle.plan.plan_id),
        )
        store._commit_agent_mutation()

    with pytest.raises(ValueError, match="digest"):
        stage_expected_bundle(store_path, bundle)


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
    staged_digest = canonical_digest(payload)
    with SQLiteStore(store_path) as store:
        store.save_crew_message(CrewMessage(
            "crew.kira.same-instant", OwnerDomain.KIRA, "Root review", "Approved root",
            RiskLevel.HIGH, CrewMessageStatus.ACKNOWLEDGED,
            related_resource_id="backup-root", related_plan_id="root-auth.same-instant",
            review_status=CrewReviewStatus.APPROVED,
            decision_reason=(f"Kira terminal approval for authorization root-auth.same-instant "
                             f"staged authorization digest {staged_digest} root identity {'sha256:' + 'e' * 64} "
                             f"target digest {payload['target_digest']}"),
            decision_evidence_ids=(staged_digest, "sha256:" + "e" * 64, payload["target_digest"]),
            request_evidence_ids=(staged_digest, "sha256:" + "e" * 64, payload["target_digest"]),
            decided_by="kira", decided_at=now.isoformat(),
        ))
    stage_authorization(store_path, "root", payload, "crew.kira.same-instant", "kira", now.isoformat())
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


@pytest.mark.parametrize("mutation", ("crew-payload-duplicate", "crew-nonterminal", "crew-decision-time"))
def test_default_authority_resolution_requires_exact_terminal_kira_crew_evidence(tmp_path, mutation):
    store_path = seeded_authority_store(tmp_path)
    connection = sqlite3.connect(store_path)
    try:
        payload = connection.execute("SELECT payload FROM crew_messages WHERE id=?", ("crew.kira.root-review",)).fetchone()[0]
        if mutation == "crew-payload-duplicate":
            payload = payload[:-1] + ',"id":"crew.kira.root-review"}'
        else:
            decoded = json.loads(payload)
            decoded["review_status" if mutation == "crew-nonterminal" else "decided_at"] = "pending" if mutation == "crew-nonterminal" else "2026-08-02T12:00:00"
            payload = json.dumps(decoded, sort_keys=True, separators=(",", ":"))
        connection.execute("UPDATE crew_messages SET payload=? WHERE id=?", (payload, "crew.kira.root-review"))
        connection.commit()
    finally:
        connection.close()

    report = run_provisioning_preflight(store_path, intent_fixture(), deterministic_dependencies())

    assert next(check for check in report.checks if check.code == "ROOT_AUTHORIZATION_CURRENT").status == "failed"


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("related_resource_id", "other-root"),
        ("related_plan_id", "root-auth.substituted"),
        ("decision_evidence_ids", ("sha256:" + "f" * 64, "sha256:" + "e" * 64, "sha256:" + "d" * 64)),
        ("request_evidence_ids", ("sha256:" + "f" * 64, "sha256:" + "e" * 64, "sha256:" + "d" * 64)),
        ("decision_reason", "Kira approved generally"),
    ),
)
def test_default_authority_resolution_rejects_substituted_kira_root_bindings(tmp_path, field, value):
    store_path = seeded_authority_store(tmp_path)
    connection = sqlite3.connect(store_path)
    try:
        payload = json.loads(connection.execute("SELECT payload FROM crew_messages WHERE id=?", ("crew.kira.root-review",)).fetchone()[0])
        payload[field] = list(value) if isinstance(value, tuple) else value
        connection.execute("UPDATE crew_messages SET payload=? WHERE id=?", (json.dumps(payload, sort_keys=True, separators=(",", ":")), "crew.kira.root-review"))
        connection.commit()
    finally:
        connection.close()

    report = run_provisioning_preflight(store_path, intent_fixture(), deterministic_dependencies())

    assert next(check for check in report.checks if check.code == "ROOT_AUTHORIZATION_CURRENT").status == "failed"


@pytest.mark.parametrize("sidecar", ("-journal", "-wal", "-shm", "-mj hot-journal"))
def test_default_authority_resolution_rejects_sqlite_sidecars_without_mutation(tmp_path, sidecar):
    store_path = Path(seeded_authority_store(tmp_path))
    journal = store_path.with_name(store_path.name + sidecar)
    if sidecar == "-journal":
        writer = sqlite3.connect(store_path)
        try:
            assert writer.execute("PRAGMA journal_mode=DELETE").fetchone()[0].lower() == "delete"
            writer.execute("BEGIN IMMEDIATE")
            writer.execute("UPDATE approvals SET subject_id='journal-active' WHERE id='approval.storage.root.root-auth.current'")
            assert journal.exists()
            before = tuple((path.name, path.stat().st_mtime_ns, path.stat().st_ctime_ns, path.read_bytes()) for path in sorted(tmp_path.iterdir()))
            report = run_provisioning_preflight(str(store_path), intent_fixture(), deterministic_dependencies())
            assert next(check for check in report.checks if check.code == "ROOT_AUTHORIZATION_CURRENT").status == "failed"
            assert tuple((path.name, path.stat().st_mtime_ns, path.stat().st_ctime_ns, path.read_bytes()) for path in sorted(tmp_path.iterdir())) == before
        finally:
            writer.rollback()
            writer.close()
    else:
        journal.write_bytes(b"sidecar")
        before = journal.stat().st_mtime_ns, journal.stat().st_ctime_ns, journal.read_bytes()
        report = run_provisioning_preflight(str(store_path), intent_fixture(), deterministic_dependencies())
        assert next(check for check in report.checks if check.code == "ROOT_AUTHORIZATION_CURRENT").status == "failed"
        assert (journal.stat().st_mtime_ns, journal.stat().st_ctime_ns, journal.read_bytes()) == before


def test_default_authority_snapshot_closes_owned_descriptors_after_unexpected_sidecar_validation_failure(tmp_path, monkeypatch):
    import overseer.provisioning_bundle as bundle_module

    store_path = seeded_authority_store(tmp_path)
    real_open = os.open
    real_close = os.close
    close_attempts: list[int] = []
    owned_fds: set[int] = set()

    def recording_open(path, flags, *arguments, **keywords):
        fd = real_open(path, flags, *arguments, **keywords)
        if path == "state.sqlite3":
            owned_fds.update((fd, keywords["dir_fd"]))
        return fd

    def recording_close(fd):
        close_attempts.append(fd)
        return real_close(fd)

    def failing_sidecar_validation(*_arguments, **_keywords):
        raise AttributeError("private sidecar validation failure")

    before = len(os.listdir("/proc/self/fd"))
    monkeypatch.setattr(bundle_module.os, "open", recording_open)
    monkeypatch.setattr(bundle_module.os, "close", recording_close)
    monkeypatch.setattr(bundle_module, "_authority_sidecars_present", failing_sidecar_validation)
    try:
        report = run_provisioning_preflight(store_path, intent_fixture(), deterministic_dependencies())
        after = len(os.listdir("/proc/self/fd"))
    finally:
        for fd in owned_fds:
            try:
                real_close(fd)
            except OSError:
                pass

    assert next(check for check in report.checks if check.code == "ROOT_AUTHORIZATION_CURRENT").status == "failed"
    assert owned_fds.issubset(close_attempts)
    assert after == before
    assert "private sidecar validation failure" not in repr(report)


def test_default_authority_clock_failure_is_redacted_without_descriptor_leaks_and_fatal_clocks_propagate(tmp_path, monkeypatch):
    import overseer.provisioning_bundle as bundle_module

    store_path = seeded_authority_store(tmp_path)
    real_open = os.open
    real_close = os.close
    owned_fds: set[int] = set()

    class FailingClock:
        error: BaseException = AttributeError("private clock failure")

        @classmethod
        def now(cls, *_arguments):
            raise cls.error

    def recording_open(path, flags, *arguments, **keywords):
        fd = real_open(path, flags, *arguments, **keywords)
        if path == "state.sqlite3":
            owned_fds.update((fd, keywords["dir_fd"]))
        return fd

    def close_owned_fds():
        for fd in owned_fds:
            try:
                real_close(fd)
            except OSError:
                pass
        owned_fds.clear()

    monkeypatch.setattr(bundle_module.os, "open", recording_open)
    monkeypatch.setattr(bundle_module, "datetime", FailingClock)
    before = len(os.listdir("/proc/self/fd"))
    try:
        report = run_provisioning_preflight(store_path, intent_fixture(), deterministic_dependencies())
        after = len(os.listdir("/proc/self/fd"))
    finally:
        close_owned_fds()

    assert next(check for check in report.checks if check.code == "ROOT_AUTHORIZATION_CURRENT").status == "failed"
    assert after == before
    assert "private clock failure" not in repr(report)
    for error_type in (KeyboardInterrupt, SystemExit):
        FailingClock.error = error_type("private fatal clock failure")
        fatal_before = len(os.listdir("/proc/self/fd"))
        try:
            with pytest.raises(error_type):
                run_provisioning_preflight(store_path, intent_fixture(), deterministic_dependencies())
            fatal_after = len(os.listdir("/proc/self/fd"))
        finally:
            close_owned_fds()
        assert fatal_after == fatal_before


@pytest.mark.parametrize("failure", ("write", "fsync", "connect", "query", "close", "unlink"))
def test_default_authority_snapshot_cleans_up_each_partial_failure(tmp_path, monkeypatch, failure):
    import overseer.provisioning_bundle as bundle_module

    store_path = seeded_authority_store(tmp_path)
    real_mkstemp = tempfile.mkstemp
    real_unlink = os.unlink
    real_close = os.close
    closed_fds: list[int] = []
    unlink_attempted = []

    def fixed_mkstemp(*_arguments, **_keywords):
        return real_mkstemp(dir=tmp_path, prefix="private-authority-temp", suffix=".sqlite3")

    def recording_close(fd):
        closed_fds.append(fd)
        return real_close(fd)

    monkeypatch.setattr(bundle_module.tempfile, "mkstemp", fixed_mkstemp)
    monkeypatch.setattr(bundle_module.os, "close", recording_close)
    if failure == "write":
        monkeypatch.setattr(bundle_module, "_write_snapshot", lambda *_args: (_ for _ in ()).throw(OSError("private write")))
    elif failure == "fsync":
        monkeypatch.setattr(bundle_module.os, "fsync", lambda *_args: (_ for _ in ()).throw(OSError("private fsync")))
    elif failure == "connect":
        monkeypatch.setattr(bundle_module.sqlite3, "connect", lambda *_args, **_keywords: (_ for _ in ()).throw(sqlite3.Error("private connect")))
    elif failure == "query":
        monkeypatch.setattr(bundle_module, "_require_authority_schema", lambda *_args: (_ for _ in ()).throw(sqlite3.Error("private query")))
    elif failure == "close":
        real_connect = sqlite3.connect

        class ClosingFailure:
            def __init__(self, connection): self.connection = connection
            def execute(self, *args, **kwargs): return self.connection.execute(*args, **kwargs)
            def close(self):
                self.connection.close()
                raise sqlite3.Error("private close")

        monkeypatch.setattr(bundle_module.sqlite3, "connect", lambda *args, **kwargs: ClosingFailure(real_connect(*args, **kwargs)))
    else:
        def failing_unlink(path, *args, **kwargs):
            unlink_attempted.append(str(path))
            if "private-authority-temp" in str(path):
                raise OSError("private unlink")
            return real_unlink(path, *args, **kwargs)
        monkeypatch.setattr(bundle_module.os, "unlink", failing_unlink)

    report = run_provisioning_preflight(store_path, intent_fixture(), deterministic_dependencies())

    assert next(check for check in report.checks if check.code == "ROOT_AUTHORIZATION_CURRENT").status == "failed"
    assert closed_fds
    assert "private-authority-temp" not in repr(report)
    assert "private " not in repr(report)
    if failure == "unlink":
        assert any("private-authority-temp" in path for path in unlink_attempted)
        for path in tmp_path.glob("private-authority-temp*.sqlite3"):
            real_unlink(path)
    else:
        assert list(tmp_path.glob("private-authority-temp*.sqlite3")) == []


def test_default_authority_snapshot_fails_closed_after_unexpected_query_wrapper_exception(tmp_path, monkeypatch):
    import overseer.provisioning_bundle as bundle_module

    store_path = seeded_authority_store(tmp_path)
    real_connect = sqlite3.connect

    class QueryFailure:
        def __init__(self, connection):
            self.connection = connection

        def execute(self, *arguments, **keywords):
            if arguments[0] == "PRAGMA query_only=ON":
                raise AttributeError("unexpected query wrapper failure")
            return self.connection.execute(*arguments, **keywords)

        def close(self):
            self.connection.close()

    monkeypatch.setattr(
        bundle_module.sqlite3,
        "connect",
        lambda *arguments, **keywords: QueryFailure(real_connect(*arguments, **keywords)),
    )

    report = run_provisioning_preflight(store_path, intent_fixture(), deterministic_dependencies())

    assert next(check for check in report.checks if check.code == "ROOT_AUTHORIZATION_CURRENT").status == "failed"
    assert "unexpected query wrapper failure" not in repr(report)


def test_default_authority_snapshot_continues_cleanup_after_unexpected_connection_close_failure(tmp_path, monkeypatch):
    import overseer.provisioning_bundle as bundle_module

    store_path = seeded_authority_store(tmp_path)
    real_connect = sqlite3.connect
    real_unlink = os.unlink
    real_close = os.close
    cleanup_events: list[str] = []

    class ClosingFailure:
        def __init__(self, connection):
            self.connection = connection

        def execute(self, *arguments, **keywords):
            return self.connection.execute(*arguments, **keywords)

        def close(self):
            cleanup_events.append("connection-close")
            self.connection.close()
            raise AttributeError("unexpected connection close failure")

    def recording_unlink(path, *arguments, **keywords):
        cleanup_events.append("unlink")
        return real_unlink(path, *arguments, **keywords)

    def recording_close(fd):
        cleanup_events.append("descriptor-close")
        return real_close(fd)

    monkeypatch.setattr(
        bundle_module.sqlite3,
        "connect",
        lambda *arguments, **keywords: ClosingFailure(real_connect(*arguments, **keywords)),
    )
    monkeypatch.setattr(bundle_module.os, "unlink", recording_unlink)
    monkeypatch.setattr(bundle_module.os, "close", recording_close)

    report = run_provisioning_preflight(store_path, intent_fixture(), deterministic_dependencies())

    assert next(check for check in report.checks if check.code == "ROOT_AUTHORIZATION_CURRENT").status == "failed"
    close_index = cleanup_events.index("connection-close")
    assert "unlink" in cleanup_events[close_index + 1:]
    assert cleanup_events[close_index + 1:].count("descriptor-close") >= 2
    assert "unexpected connection close failure" not in repr(report)


def test_default_authority_resolution_rejects_blob_revocation_security_fields(tmp_path):
    store_path = seeded_authority_store(tmp_path)
    connection = sqlite3.connect(store_path)
    try:
        connection.execute(
            "INSERT INTO storage_authorization_revocations VALUES(?,?,?,?,?,?)",
            ("revoke.unrelated", "root", sqlite3.Binary(b"root-auth.current"), "human", datetime.now(UTC).isoformat(), "crew.kira.root-review"),
        )
        connection.commit()
    finally:
        connection.close()

    report = run_provisioning_preflight(store_path, intent_fixture(), deterministic_dependencies())

    assert next(check for check in report.checks if check.code == "ROOT_AUTHORIZATION_CURRENT").status == "failed"


def test_default_authority_snapshot_uses_noatime_and_rejects_symlinked_ancestor(tmp_path, monkeypatch):
    import overseer.provisioning_bundle as bundle_module

    real_open = os.open
    observed_flags = []

    def recording_open(path, flags, *arguments, **keywords):
        observed_flags.append((path, flags))
        return real_open(path, flags, *arguments, **keywords)

    monkeypatch.setattr(bundle_module.os, "open", recording_open)
    nested = tmp_path / "nested"
    nested.mkdir()
    store_path = Path(seeded_authority_store(nested))
    before_metadata = (store_path.stat().st_atime_ns, store_path.stat().st_mtime_ns, store_path.stat().st_ctime_ns)
    report = run_provisioning_preflight(str(store_path), intent_fixture(), deterministic_dependencies())
    assert report.passed is True
    assert (store_path.stat().st_atime_ns, store_path.stat().st_mtime_ns, store_path.stat().st_ctime_ns) == before_metadata
    assert any(flags & os.O_NOATIME for _path, flags in observed_flags)

    linked = tmp_path / "linked"
    linked.symlink_to(nested, target_is_directory=True)
    report = run_provisioning_preflight(str(linked / "state.sqlite3"), intent_fixture(), deterministic_dependencies())
    assert next(check for check in report.checks if check.code == "ROOT_AUTHORIZATION_CURRENT").status == "failed"


def test_default_authority_snapshot_closes_opened_child_after_unexpected_ancestor_close_failure(tmp_path, monkeypatch):
    import overseer.provisioning_bundle as bundle_module

    nested = tmp_path / "nested"
    nested.mkdir()
    store_path = seeded_authority_store(nested)
    real_open = os.open
    real_close = os.close
    opened_fds: list[int] = []
    close_attempts: list[int] = []
    root_fd: int | None = None
    failed_once = False

    def recording_open(path, flags, *arguments, **keywords):
        nonlocal root_fd
        fd = real_open(path, flags, *arguments, **keywords)
        opened_fds.append(fd)
        if path == "/":
            root_fd = fd
        return fd

    def fail_root_close_once(fd):
        nonlocal failed_once
        close_attempts.append(fd)
        if fd == root_fd and not failed_once:
            failed_once = True
            raise AttributeError("unexpected ancestor close failure")
        return real_close(fd)

    monkeypatch.setattr(bundle_module.os, "open", recording_open)
    monkeypatch.setattr(bundle_module.os, "close", fail_root_close_once)

    report = run_provisioning_preflight(store_path, intent_fixture(), deterministic_dependencies())

    assert failed_once is True
    assert next(check for check in report.checks if check.code == "ROOT_AUTHORIZATION_CURRENT").status == "failed"
    assert set(opened_fds).issubset(close_attempts)
    assert "unexpected ancestor close failure" not in repr(report)


def test_default_authority_snapshot_closes_descriptors_after_post_open_stat_failure(tmp_path, monkeypatch):
    import overseer.provisioning_bundle as bundle_module

    store_path = seeded_authority_store(tmp_path)
    real_stat = os.stat
    def failing_entry_stat(path, *arguments, **keywords):
        if path == "state.sqlite3" and keywords.get("dir_fd") is not None:
            raise OSError("simulated post-open stat failure")
        return real_stat(path, *arguments, **keywords)

    before = len(os.listdir("/proc/self/fd"))
    monkeypatch.setattr(bundle_module.os, "stat", failing_entry_stat)
    for _ in range(20):
        report = run_provisioning_preflight(store_path, intent_fixture(), deterministic_dependencies())
        assert next(check for check in report.checks if check.code == "ROOT_AUTHORIZATION_CURRENT").status == "failed"
    assert len(os.listdir("/proc/self/fd")) == before


def test_default_authority_resolution_rejects_wal_lifecycle_revocation_race(tmp_path, monkeypatch):
    store_path = Path(seeded_authority_store(tmp_path))
    real_connect = sqlite3.connect
    raced = False

    def connect_after_wal_lifecycle(*arguments, **keywords):
        nonlocal raced
        connection = real_connect(*arguments, **keywords)
        if not raced:
            raced = True
            writer = real_connect(store_path)
            try:
                assert writer.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() == "wal"
                writer.execute(
                    "INSERT INTO storage_authorization_revocations VALUES(?,?,?,?,?,?)",
                    ("revoke.root-auth.current", "root", "root-auth.current", "human", datetime.now(UTC).isoformat(), "crew.kira.root-review"),
                )
                writer.commit()
                writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                writer.close()
        return connection

    monkeypatch.setattr(sqlite3, "connect", connect_after_wal_lifecycle)
    report = run_provisioning_preflight(str(store_path), intent_fixture(), deterministic_dependencies())

    assert raced is True
    assert next(check for check in report.checks if check.code == "ROOT_AUTHORIZATION_CURRENT").status == "failed"


@pytest.mark.parametrize("swap", ("inode", "rename", "symlink"))
def test_default_authority_resolution_rejects_path_swaps_before_sqlite_snapshot(tmp_path, monkeypatch, swap):
    store_path = Path(seeded_authority_store(tmp_path))
    revoke_authorization(str(store_path), "root-auth.current", "human", "crew.kira.root-review")
    replacement = tmp_path / "replacement.sqlite3"
    shutil.copy2(store_path, replacement)
    connection = sqlite3.connect(replacement)
    try:
        connection.execute("DELETE FROM storage_authorization_revocations")
        connection.commit()
    finally:
        connection.close()
    original_connect = sqlite3.connect
    replaced = False

    def replace_before_connect(*arguments, **keywords):
        nonlocal replaced
        if not replaced:
            replaced = True
            if swap == "symlink":
                store_path.unlink()
                store_path.symlink_to(replacement)
            elif swap == "rename":
                os.rename(store_path, tmp_path / "revoked.sqlite3")
                os.rename(replacement, store_path)
            else:
                os.replace(replacement, store_path)
        return original_connect(*arguments, **keywords)

    monkeypatch.setattr(sqlite3, "connect", replace_before_connect)
    report = run_provisioning_preflight(str(store_path), intent_fixture(), deterministic_dependencies())

    assert replaced is True
    assert next(check for check in report.checks if check.code == "ROOT_AUTHORIZATION_CURRENT").status == "failed"


def test_default_authority_resolution_requires_exact_independent_staged_approval_binding(tmp_path):
    store_path = seeded_authority_store(tmp_path)
    connection = sqlite3.connect(store_path)
    try:
        approval = json.loads(connection.execute("SELECT payload FROM approvals WHERE id=?", ("approval.storage.root.root-auth.current",)).fetchone()[0])
        approval["decided_by"] = "kira"
        approval["reason"] = "arbitrary approval"
        approval["evidence_required"][1] = "sha256:" + "f" * 64
        connection.execute(
            "UPDATE approvals SET payload=? WHERE id=?",
            (json.dumps(approval, sort_keys=True, separators=(",", ":")), "approval.storage.root.root-auth.current"),
        )
        connection.commit()
    finally:
        connection.close()

    report = run_provisioning_preflight(store_path, intent_fixture(), deterministic_dependencies())

    assert next(check for check in report.checks if check.code == "ROOT_AUTHORIZATION_CURRENT").status == "failed"


@pytest.mark.parametrize(
    ("table", "columns"),
    (
        ("storage_root_authorizations", ("id", "project_id", "root_id", "status", "payload")),
        ("approvals", ("id", "subject_id", "payload")),
        ("crew_messages", ("id", "owner_domain", "payload")),
        ("storage_authorization_revocations", ("id", "kind", "authorization_ref", "revoked_by", "revoked_at", "evidence_id")),
    ),
)
def test_default_authority_resolution_rejects_constraint_free_lookalike_schema(tmp_path, table, columns):
    store_path = seeded_authority_store(tmp_path)
    canonical_table = f"{table}_canonical"
    column_list = ", ".join(columns)
    connection = sqlite3.connect(store_path)
    try:
        connection.execute(f"ALTER TABLE {table} RENAME TO {canonical_table}")
        connection.execute(f"CREATE TABLE {table} ({', '.join(f'{column} TEXT' for column in columns)})")
        connection.execute(f"INSERT INTO {table} ({column_list}) SELECT {column_list} FROM {canonical_table}")
        connection.execute(f"DROP TABLE {canonical_table}")
        connection.commit()
    finally:
        connection.close()

    report = run_provisioning_preflight(store_path, intent_fixture(), deterministic_dependencies())

    assert next(check for check in report.checks if check.code == "ROOT_AUTHORIZATION_CURRENT").status == "failed"


@pytest.mark.parametrize(
    "schema",
    (
        """CREATE TABLE approvals (
            id TEXT PRIMARY KEY,
            subject_id TEXT NOT NULL CHECK(length(subject_id)>0) /* private schema detail */,
            payload TEXT NOT NULL
        )""",
        """CREATE TABLE approvals (
            id TEXT PRIMARY KEY ON CONFLICT REPLACE /* private schema detail */,
            subject_id TEXT NOT NULL,
            payload TEXT NOT NULL
        )""",
        """CREATE TABLE approvals (
            id TEXT PRIMARY KEY,
            subject_id TEXT COLLATE NOCASE NOT NULL /* private schema detail */,
            payload TEXT NOT NULL
        )""",
    ),
    ids=("check-clause", "primary-key-conflict-policy", "column-collation"),
)
def test_default_authority_resolution_rejects_noncanonical_schema_clauses(tmp_path, schema):
    store_path = seeded_authority_store(tmp_path)
    connection = sqlite3.connect(store_path)
    try:
        connection.execute("ALTER TABLE approvals RENAME TO approvals_canonical")
        connection.execute(schema)
        connection.execute(
            "INSERT INTO approvals (id,subject_id,payload) "
            "SELECT id,subject_id,payload FROM approvals_canonical"
        )
        connection.execute("DROP TABLE approvals_canonical")
        connection.commit()
    finally:
        connection.close()

    report = run_provisioning_preflight(store_path, intent_fixture(), deterministic_dependencies())

    assert next(check for check in report.checks if check.code == "ROOT_AUTHORIZATION_CURRENT").status == "failed"
    assert "private schema detail" not in repr(report)
    assert "CHECK(length" not in repr(report)


@pytest.mark.parametrize(
    ("table", "trigger_target"),
    (
        ("storage_root_authorizations", "STORAGE_ROOT_AUTHORIZATIONS"),
        ("approvals", "ApPrOvAlS"),
        ("crew_messages", "CrEw_MeSsAgEs"),
        ("storage_authorization_revocations", "StOrAgE_AuThOrIzAtIoN_ReVoCaTiOnS"),
    ),
)
def test_default_authority_resolution_rejects_case_variant_authority_triggers(tmp_path, table, trigger_target):
    store_path = seeded_authority_store(tmp_path)
    trigger_name = f"private_schema_trigger_{table}"
    connection = sqlite3.connect(store_path)
    try:
        connection.execute(
            f"CREATE TRIGGER {trigger_name} AFTER INSERT ON {trigger_target} BEGIN SELECT 1; END"
        )
        stored_target = connection.execute(
            "SELECT tbl_name FROM sqlite_schema WHERE type='trigger' AND name=?",
            (trigger_name,),
        ).fetchone()[0]
        connection.commit()
    finally:
        connection.close()

    assert stored_target == trigger_target
    report = run_provisioning_preflight(store_path, intent_fixture(), deterministic_dependencies())

    assert next(check for check in report.checks if check.code == "ROOT_AUTHORIZATION_CURRENT").status == "failed"
    assert trigger_name not in repr(report)
    assert "CREATE TRIGGER" not in repr(report)


@pytest.mark.parametrize("payload_kind", ("blob", "duplicate-key"))
def test_default_authority_resolution_rejects_noncanonical_physical_payloads(tmp_path, payload_kind):
    store_path = seeded_authority_store(tmp_path)
    connection = sqlite3.connect(store_path)
    try:
        root_payload = connection.execute("SELECT payload FROM storage_root_authorizations WHERE id=?", ("root-auth.current",)).fetchone()[0]
        approval_payload = connection.execute("SELECT payload FROM approvals WHERE id=?", ("approval.storage.root.root-auth.current",)).fetchone()[0]
        if payload_kind == "blob":
            root_payload, approval_payload = sqlite3.Binary(root_payload.encode()), sqlite3.Binary(approval_payload.encode())
        else:
            root_payload = root_payload[:-1] + ',"authorization_ref":"root-auth.current"}'
        connection.execute("UPDATE storage_root_authorizations SET payload=? WHERE id=?", (root_payload, "root-auth.current"))
        connection.execute("UPDATE approvals SET payload=? WHERE id=?", (approval_payload, "approval.storage.root.root-auth.current"))
        connection.commit()
    finally:
        connection.close()

    report = run_provisioning_preflight(store_path, intent_fixture(), deterministic_dependencies())

    assert next(check for check in report.checks if check.code == "ROOT_AUTHORIZATION_CURRENT").status == "failed"


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


def test_preflight_redacts_unexpected_dependency_exceptions_without_masking_base_exceptions(tmp_path):
    store_path = seeded_authority_store(tmp_path)

    def raise_error(error):
        def callback(*_arguments):
            raise error
        return callback

    report = run_provisioning_preflight(
        store_path,
        intent_fixture(),
        replace(
            deterministic_dependencies(),
            source_head=raise_error(AttributeError("private unexpected dependency failure")),
        ),
    )

    assert report.passed is False
    assert next(check for check in report.checks if check.code == "SOURCE_COMMIT_MATCH").status == "failed"
    assert "private unexpected dependency failure" not in repr(report)
    for error_type in (KeyboardInterrupt, SystemExit):
        with pytest.raises(error_type):
            run_provisioning_preflight(
                store_path,
                intent_fixture(),
                replace(
                    deterministic_dependencies(),
                    source_head=raise_error(error_type("private fatal dependency failure")),
                ),
            )


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
            replace(deterministic_dependencies(), predecessor_lookup=lambda _id: predecessor, authoritative_chain_tip=lambda _id: "other-plan"),
        )
    superseded_predecessor = replace(
        predecessor,
        intent=replace(predecessor.intent, supersedes_plan_id=successor.plan_id),
        supersedes_plan_id=successor.plan_id,
    )
    with pytest.raises(ProvisioningBundleError, match="PREDECESSOR_INVALID"):
        build_provisioning_bundle(
            store_path, successor,
            replace(deterministic_dependencies(), predecessor_lookup=lambda _id: superseded_predecessor, authoritative_chain_tip=lambda _id: predecessor.plan.plan_id),
        )
    assert Path(store_path).read_bytes() == before


def test_bundle_redacts_unexpected_predecessor_callback_exception_as_unavailable(tmp_path):
    store_path = seeded_authority_store(tmp_path)
    predecessor = build_provisioning_bundle(store_path, intent_fixture(), deterministic_dependencies())
    successor = intent_fixture(
        plan_id="backup-provision.donuthole.v21.20260802",
        supersedes_plan_id=predecessor.plan.plan_id,
    )

    def failing_predecessor_lookup(_identifier):
        raise AttributeError("private predecessor callback failure")

    with pytest.raises(ProvisioningBundleError, match="^PREDECESSOR_UNAVAILABLE$") as error:
        build_provisioning_bundle(
            store_path,
            successor,
            replace(
                deterministic_dependencies(),
                predecessor_lookup=failing_predecessor_lookup,
                authoritative_chain_tip=lambda _id: predecessor.plan.plan_id,
            ),
        )

    assert "private predecessor callback failure" not in repr(error.value)


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
            replace(deterministic_dependencies(), predecessor_lookup=lambda _id: tamper(predecessor), authoritative_chain_tip=lambda _id: predecessor.plan.plan_id),
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
            replace(deterministic_dependencies(), predecessor_lookup=lambda _id: forged, authoritative_chain_tip=lambda _id: predecessor.plan.plan_id),
        )


def test_successor_rejects_coherently_redigested_predecessor_preflight_check_forgery(tmp_path):
    store_path = seeded_authority_store(tmp_path)
    predecessor = build_provisioning_bundle(store_path, intent_fixture(), deterministic_dependencies())
    forged_checks = tuple(
        replace(check, evidence_digest="sha256:" + "f" * 64, summary="Forged passing preflight check.") if check.code == "GPG_DIGEST_VALID" else check
        for check in predecessor.preflight.checks
    )
    report_digest = canonical_digest({
        "report_id": predecessor.preflight.report_id,
        "plan_id": predecessor.preflight.plan_id,
        "resolved_inputs": predecessor.preflight.resolved_inputs,
        "checks": [asdict(check) for check in forged_checks],
    })
    report = replace(predecessor.preflight, checks=forged_checks, report_digest=report_digest)
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
            replace(deterministic_dependencies(), predecessor_lookup=lambda _id: forged, authoritative_chain_tip=lambda _id: predecessor.plan.plan_id),
        )


def test_successor_rejects_predecessor_with_forged_unchanged_chain_delta(tmp_path):
    store_path = seeded_authority_store(tmp_path)
    root = build_provisioning_bundle(store_path, intent_fixture(), deterministic_dependencies())
    middle_intent = intent_fixture(plan_id="backup-provision.donuthole.v21.20260802", supersedes_plan_id=root.plan.plan_id)
    middle = build_provisioning_bundle(
        store_path, middle_intent,
        replace(deterministic_dependencies(), predecessor_lookup=lambda _id: root, authoritative_chain_tip=lambda _id: root.plan.plan_id),
    )
    changed = ("gpg_sha256",)
    provisional = ProvisioningBundleV1(
        middle.schema_version, middle.intent, middle.plan, middle.preflight,
        outbox_fixture(plan_id=middle.plan.plan_id, plan_digest=middle.plan.plan_digest, report_digest=middle.preflight.report_digest, bundle_digest=middle.bundle_digest),
        middle.bundle_digest, middle.supersedes_plan_id, changed,
    )
    forged_digest = bundle_digest(provisional)
    forged = ProvisioningBundleV1(
        middle.schema_version, middle.intent, middle.plan, middle.preflight,
        outbox_fixture(plan_id=middle.plan.plan_id, plan_digest=middle.plan.plan_digest, report_digest=middle.preflight.report_digest, bundle_digest=forged_digest),
        forged_digest, middle.supersedes_plan_id, changed,
    )
    successor = intent_fixture(plan_id="backup-provision.donuthole.v22.20260802", supersedes_plan_id=middle.plan.plan_id)

    with pytest.raises(ProvisioningBundleError, match="PREDECESSOR_INVALID"):
        build_provisioning_bundle(
            store_path, successor,
            replace(
                deterministic_dependencies(),
                predecessor_lookup=lambda identifier: root if identifier == root.plan.plan_id else forged,
                authoritative_chain_tip=lambda _id: middle.plan.plan_id,
            ),
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
        replace(deterministic_dependencies(), predecessor_lookup=lambda _id: previous, authoritative_chain_tip=lambda _id: previous.plan.plan_id),
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
