"""Harmless, non-executing approval source used for Roadex conformance checks."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Literal, Mapping
from uuid import uuid4

from .roadex_approval_status import (
    RoadexApprovalBindingDraft,
    public_projection,
    roadex_approval_status,
    stage_bound_roadex_approval,
)
from .store import SQLiteStore


SOURCE_KIND = "roadex-approval-fixture"
AUTHORITY_CLASS = "project-workflow"
_STAGE_FIELDS = frozenset({"projectId", "workspaceId", "resourceRef", "subject"})
_APPROVE_FIELDS = frozenset({"approvalRef"})


@dataclass(frozen=True)
class RoadexApprovalFixture:
    id: str
    status: Literal["pending", "approved"]
    created_at: str
    approved_at: str | None = None
    approved_by: str | None = None


def stage_roadex_approval_fixture_api(
    store_path: str,
    payload: Mapping[str, object],
) -> Mapping[str, object]:
    _require_exact_request(payload, _STAGE_FIELDS)
    project_id = _require_bounded(payload["projectId"], "projectId")
    workspace_id = _require_bounded(payload["workspaceId"], "workspaceId")
    resource_ref = _require_bounded(payload["resourceRef"], "resourceRef")
    subject = _require_bounded(payload["subject"], "subject", maximum=256)
    approval_ref = f"roadex.fixture.{uuid4().hex}"
    source = RoadexApprovalFixture(
        id=approval_ref,
        status="pending",
        created_at=datetime.now(UTC).isoformat(),
    )
    draft = RoadexApprovalBindingDraft(
        approval_ref=approval_ref,
        source_kind=SOURCE_KIND,
        source_id=source.id,
        project_id=project_id,
        workspace_id=workspace_id,
        resource_ref=resource_ref,
        authority_class=AUTHORITY_CLASS,
        subject=subject,
    )
    with SQLiteStore(store_path) as store:
        binding = stage_bound_roadex_approval(
            store,
            draft,
            lambda: store.save_roadex_approval_fixture(source),
        )
    return {
        "provider": "overseer",
        "approvalRef": binding.approval_ref,
        "projectId": binding.project_id,
        "workspaceId": binding.workspace_id,
        "resourceRef": binding.resource_ref,
        "authorityClass": binding.authority_class,
        "scopeDigest": binding.scope_digest,
    }


def approve_roadex_approval_fixture_api(
    store_path: str,
    payload: Mapping[str, object],
    *,
    human_identity: str,
) -> Mapping[str, object]:
    _require_exact_request(payload, _APPROVE_FIELDS)
    approval_ref = _require_bounded(payload["approvalRef"], "approvalRef")
    approver = _require_bounded(human_identity, "human_identity")
    with SQLiteStore(store_path) as store:
        binding = store.load_roadex_approval_binding(approval_ref)
        if binding.source_kind != SOURCE_KIND or binding.authority_class != AUTHORITY_CLASS:
            raise ValueError("approval reference is not a project-workflow fixture")
        with store.agent_transaction():
            source = store.load_roadex_approval_fixture(binding.source_id)
            if source.status == "pending":
                source = replace(
                    source,
                    status="approved",
                    approved_at=datetime.now(UTC).isoformat(),
                    approved_by=approver,
                )
                store.approve_roadex_approval_fixture(source)
            elif source.status != "approved" or source.approved_by != approver:
                raise ValueError("approval fixture decision is immutable")
    return roadex_approval_status(store_path, approval_ref)


def fixture_source_evidence_digest_payload(source: RoadexApprovalFixture) -> Mapping[str, str]:
    """Only immutable source evidence contributes to the approval scope."""
    return {"id": source.id, "createdAt": source.created_at, "sourceKind": SOURCE_KIND}


def _require_exact_request(payload: Mapping[str, object], expected: frozenset[str]) -> None:
    if not isinstance(payload, Mapping) or set(payload) != expected:
        raise ValueError("request must contain exact fields")


def _require_bounded(value: object, field: str, *, maximum: int = 128) -> str:
    if not isinstance(value, str) or value != value.strip() or not value or len(value) > maximum:
        raise ValueError(f"{field} must be a bounded canonical string")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{field} must be a bounded canonical string")
    return value


__all__ = [
    "AUTHORITY_CLASS",
    "RoadexApprovalFixture",
    "SOURCE_KIND",
    "approve_roadex_approval_fixture_api",
    "fixture_source_evidence_digest_payload",
    "stage_roadex_approval_fixture_api",
]
