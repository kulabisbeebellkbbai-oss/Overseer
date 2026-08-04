from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

import pytest

from overseer.approval_source_registry import (
    ApprovalSourceAdapter,
    ProjectedDecision,
    build_approval_source_registry,
)
from overseer.roadex_approval_status import (
    RoadexApprovalBindingDraft,
    load_exact_bound_source,
    project_decision,
    stage_bound_roadex_approval,
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
