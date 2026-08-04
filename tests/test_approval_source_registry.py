from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from types import MappingProxyType

import pytest

from overseer.approval_source_registry import (
    ApprovalSourceAdapter,
    ProjectedDecision,
    build_approval_source_registry,
)
from overseer.admin import approve_admin_change_plan, cancel_admin_change_plan, plan_user_service_restart
from overseer.backup_provisioning import ProvisioningStatus
from overseer.roadex_approval_status import (
    RoadexApprovalBindingDraft,
    load_exact_bound_source,
    project_decision_version,
    project_decision,
    public_projection,
    roadex_approval_status,
    stage_bound_roadex_approval,
)
from overseer.store import SQLiteStore
from tests.test_backup_provisioning import seeded
from tests.test_roadex_approval_status import (
    _draft_for,
    _roadex_plan_with_status,
    _write_roadex_plan,
)


@dataclass(frozen=True)
class FixtureSource:
    id: str
    initial: bool
    digest: str
    decision: str
    updated_at: str


class FixtureStore:
    def __init__(self, payloads: dict[tuple[str, str], str] | None = None) -> None:
        self.payloads = payloads or {}
        self.bindings = {}

    def registered_source_exists(self, accessor: str, source_id: str) -> bool:
        return (accessor, source_id) in self.payloads

    def load_registered_source_payload(self, accessor: str, source_id: str) -> str:
        try:
            return self.payloads[(accessor, source_id)]
        except KeyError as error:
            raise KeyError(source_id) from error

    def agent_transaction(self):
        class Transaction:
            def __enter__(inner):
                return None

            def __exit__(inner, exc_type, exc, traceback):
                return False

        return Transaction()

    def load_roadex_approval_binding(self, approval_ref: str):
        return self.bindings[approval_ref]

    def save_roadex_approval_binding(self, binding):
        self.bindings[binding.approval_ref] = binding
        return binding


def _fixture_registry(*, decision: str = "pending"):
    def decode_exact(payload: str) -> FixtureSource:
        source_id, initial, digest, updated_at = payload.split("|")
        return FixtureSource(source_id, initial == "initial", digest, decision, updated_at)

    def require_initial(source: object) -> None:
        if not isinstance(source, FixtureSource) or not source.initial:
            raise ValueError("fixture source must be initial")

    def evidence_digest(source: object) -> str:
        assert isinstance(source, FixtureSource)
        return source.digest

    def project(_store: object, _binding: object, source: object) -> ProjectedDecision:
        assert isinstance(source, FixtureSource)
        return ProjectedDecision(source.decision, "fixture", source.updated_at)  # type: ignore[arg-type]

    adapter = ApprovalSourceAdapter(
        source_kind="fixture-source",
        accessor="fixture-accessor",
        decode_exact=decode_exact,
        require_initial=require_initial,
        evidence_digest=evidence_digest,
        project_decision=project,
    )
    return build_approval_source_registry((adapter,))


def _fixture_draft() -> RoadexApprovalBindingDraft:
    return RoadexApprovalBindingDraft(
        approval_ref="fixture.approval",
        source_kind="fixture-source",
        source_id="fixture.source",
        project_id="project.fixture",
        workspace_id="workspace.fixture",
        resource_ref="resource.fixture",
        authority_class="project-workflow",
        subject="Fixture approval",
    )


def test_registry_is_immutable_and_builtins_are_exactly_allowlisted() -> None:
    registry = build_approval_source_registry()

    assert isinstance(registry, MappingProxyType)
    assert set(registry) == {"admin-plan", "roadex-human-decision"}
    with pytest.raises(TypeError):
        registry["unreviewed"] = registry["admin-plan"]  # type: ignore[index]


def test_registry_rejects_duplicate_source_kinds() -> None:
    adapter = next(iter(_fixture_registry().values()))

    with pytest.raises(ValueError, match="duplicate"):
        build_approval_source_registry((adapter, adapter))


def test_unknown_kind_fails_before_source_callback_runs() -> None:
    store = FixtureStore()
    draft = _fixture_draft()
    invalid = RoadexApprovalBindingDraft(**{**draft.__dict__, "source_kind": "unknown"})
    called = False

    def save_source() -> None:
        nonlocal called
        called = True

    with pytest.raises(ValueError, match="unsupported source_kind"):
        stage_bound_roadex_approval(store, invalid, save_source, registry=_fixture_registry())
    assert called is False


def test_fixture_adapter_stages_and_projects_without_production_accessor() -> None:
    registry = _fixture_registry()
    store = FixtureStore()
    draft = _fixture_draft()
    payload = "fixture.source|initial|sha256:" + "a" * 64 + "|2026-08-03T00:00:00+00:00"

    def save_source() -> None:
        store.payloads[("fixture-accessor", draft.source_id)] = payload

    binding = stage_bound_roadex_approval(store, draft, save_source, registry=registry)
    source = load_exact_bound_source(store, binding, registry=registry)
    decision = project_decision(store, binding, source, registry=registry)

    assert binding.source_kind == "fixture-source"
    assert decision.decision == "pending"
    assert decision.source_status == "fixture"


def test_fixture_loader_identity_mismatch_fails_closed() -> None:
    registry = _fixture_registry()
    store = FixtureStore()
    draft = _fixture_draft()
    payload = "another.source|initial|sha256:" + "a" * 64 + "|2026-08-03T00:00:00+00:00"

    with pytest.raises(ValueError, match="identity"):
        stage_bound_roadex_approval(
            store,
            draft,
            lambda: store.payloads.__setitem__(("fixture-accessor", draft.source_id), payload),
            registry=registry,
        )


def test_fixture_digest_mismatch_fails_closed() -> None:
    registry = _fixture_registry()
    store = FixtureStore()
    draft = _fixture_draft()
    payload = "fixture.source|initial|sha256:" + "a" * 64 + "|2026-08-03T00:00:00+00:00"
    binding = stage_bound_roadex_approval(
        store,
        draft,
        lambda: store.payloads.__setitem__(("fixture-accessor", draft.source_id), payload),
        registry=registry,
    )
    tampered = FixtureSource("fixture.source", True, "sha256:" + "b" * 64, "pending", "2026-08-03T00:00:00+00:00")

    with pytest.raises(ValueError, match="digest"):
        project_decision(store, binding, tampered, registry=registry)


def test_fixture_adapter_rejects_unsupported_projected_decision() -> None:
    registry = _fixture_registry(decision="provider-failed")
    store = FixtureStore()
    draft = _fixture_draft()
    payload = "fixture.source|initial|sha256:" + "a" * 64 + "|2026-08-03T00:00:00+00:00"
    binding = stage_bound_roadex_approval(
        store,
        draft,
        lambda: store.payloads.__setitem__(("fixture-accessor", draft.source_id), payload),
        registry=registry,
    )

    with pytest.raises(ValueError, match="unsupported projected decision"):
        project_decision(store, binding, load_exact_bound_source(store, binding, registry=registry), registry=registry)


def test_backup_exact_load_rejects_tampered_immutable_payload_before_projection(tmp_path) -> None:
    path, plan = seeded(tmp_path / "backups")
    draft = _draft_for(
        "admin.roadex.human",
        source_kind="roadex-human-decision",
        source_id=plan.plan_id,
    )
    with SQLiteStore(path) as store:
        stage_bound_roadex_approval(store, draft, lambda: _write_roadex_plan(store, plan))
        _write_roadex_plan(store, replace(plan, gpg_sha256="sha256:" + "f" * 64))
        binding = store.load_roadex_approval_binding(draft.approval_ref)

        with pytest.raises(ValueError, match="plan digest"):
            load_exact_bound_source(store, binding)


def _registry_public_projection(store: SQLiteStore, approval_ref: str) -> dict[str, object]:
    binding = store.load_roadex_approval_binding(approval_ref)
    source = load_exact_bound_source(store, binding)
    projected = project_decision(store, binding, source)
    return {
        "provider": "overseer",
        **public_projection(
            binding,
            projected.decision,
            project_decision_version(
                binding,
                projected.source_status,
                projected.decision,
                projected.updated_at,
            ),
            projected.updated_at,
        ),
    }


@pytest.mark.parametrize("terminal", ("pending", "approved", "rejected"))
def test_admin_projection_fixtures_match_registry_public_contract(tmp_path, terminal: str) -> None:
    path = tmp_path / f"admin-{terminal}.sqlite3"
    approval_ref = f"admin.registry.{terminal}"
    plan = plan_user_service_restart(approval_ref, "roadex-test.service", "Registry parity fixture")
    with SQLiteStore(path) as store:
        stage_bound_roadex_approval(store, _draft_for(approval_ref), lambda: store.save_admin_change_plan(plan))
        now = datetime.now(UTC).isoformat()
        if terminal == "approved":
            store.save_admin_change_plan(approve_admin_change_plan(plan, "operator", now))
        elif terminal == "rejected":
            store.save_admin_change_plan(
                cancel_admin_change_plan(
                    approve_admin_change_plan(plan, "operator", now),
                    "operator",
                    "Denied request",
                    now,
                )
            )

    expected = {"provider": "overseer", **roadex_approval_status(str(path), approval_ref)}
    with SQLiteStore(path) as store:
        actual = _registry_public_projection(store, approval_ref)

    assert actual == expected
    assert set(actual) == {
        "provider", "approvalRef", "sourceKind", "projectId", "workspaceId", "resourceRef",
        "authorityClass", "subject", "scopeDigest", "decision", "decisionVersion", "updatedAt",
    }


@pytest.mark.parametrize(
    "status",
    (
        ProvisioningStatus.STAGED,
        ProvisioningStatus.DENIED,
        ProvisioningStatus.REVISION_REQUESTED,
        ProvisioningStatus.APPROVED,
        ProvisioningStatus.EXECUTED,
        ProvisioningStatus.FAILED,
        ProvisioningStatus.ROLLED_BACK,
    ),
)
def test_backup_projection_fixtures_match_registry_public_contract(tmp_path, status: ProvisioningStatus) -> None:
    path, plan = seeded(tmp_path / f"backups-{status.value}")
    draft = _draft_for(
        f"admin.registry.{status.value}",
        source_kind="roadex-human-decision",
        source_id=plan.plan_id,
    )
    with SQLiteStore(path) as store:
        stage_bound_roadex_approval(store, draft, lambda: _write_roadex_plan(store, plan))
        _write_roadex_plan(store, _roadex_plan_with_status(plan, status, datetime.now(UTC).isoformat()))

    expected = {"provider": "overseer", **roadex_approval_status(path, draft.approval_ref)}
    with SQLiteStore(path) as store:
        actual = _registry_public_projection(store, draft.approval_ref)

    assert actual == expected
    assert actual["decisionVersion"] == expected["decisionVersion"]
