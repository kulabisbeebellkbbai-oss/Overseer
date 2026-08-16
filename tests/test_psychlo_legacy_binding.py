from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from overseer.audit import ApprovalRequest, ApprovalStatus
from overseer.core import ApprovalLevel, OwnerDomain
from overseer.admin import plan_psychlo_legacy_round_reconciliation
from overseer.psychlo_bridge import PsychloBridge, PsychloBridgeStore
from overseer.psychlo_legacy_binding import admin_plan_digest, approval_record_digest, attest_legacy_round_binding, attestation_manifest_digest
from overseer.psychlo_contracts import canonical_digest
from overseer.store import SQLiteStore


NOW = "2026-08-16T12:00:00+00:00"


class Dispatcher:
    def __init__(self, binding_path: Path, found: bool = False):
        self.bindings = json.loads(binding_path.read_text())
        self.found = found

    def __call__(self, *_args, **_kwargs):
        raise RuntimeError("legacy round must not be dispatched")

    def binding_provenance(self, _lead):
        return {"conversationId": "conversation-arcade", "sessionId": "session-arcade", "rolloutPathDigest": "a" * 64, "rolloutDev": 1, "rolloutIno": 2}

    def scan_rollout(self, _lead, _prompt):
        binding = self.binding_provenance(_lead)
        return {"found": self.found, **binding}


def _private_file(path: Path, content: bytes) -> dict:
    path.write_bytes(content); path.chmod(0o600)
    metadata = path.stat()
    return {"path": str(path), "digest": hashlib.sha256(content).hexdigest(), "dev": metadata.st_dev, "ino": metadata.st_ino, "size": metadata.st_size, "btime": 0, "mtime": metadata.st_mtime_ns, "ctime": metadata.st_ctime_ns}


def _fixture(tmp_path: Path, *, found: bool = False):
    binding_content = json.dumps({"member-hermione": {"conversationId": "conversation-arcade"}}, separators=(",", ":")).encode()
    binding_path = tmp_path / "bindings.json"
    binding = _private_file(binding_path, binding_content)
    unit = _private_file(tmp_path / "overseer-psychlo-usage.service", b"[Service]\nExecStart=/bin/true\n")
    dropin = _private_file(tmp_path / "override.conf", b"[Service]\nEnvironment=TEST=1\n")
    request = {"roundId": "round-arcade-legacy", "projectId": "arcade", "projectLeadId": "member-hermione", "planId": "arcade-plan", "planVersion": "v1", "correlationId": "corr-arcade-legacy", "idempotencyKey": "request-arcade-legacy", "snapshotId": "snapshot-arcade-legacy", "policyVersion": "2026-08-09", "expectedUsageCost": 1, "scope": "one bounded round", "selectionReason": "priority-selected", "priorityRationale": "manual-priority"}
    receipt = {**request, "sourceId": request["projectLeadId"], "provenanceId": "dispatch-legacy", "status": "accepted"}
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    store.record_round(request, receipt, "capability:legacy-arcade-1234567890")
    store.mark_dispatch_started(request["roundId"], NOW)
    primary = SQLiteStore(tmp_path / "primary.sqlite3")
    source_commit = "a" * 40
    plan = plan_psychlo_legacy_round_reconciliation("admin.psychlo.legacy-round.round-arcade-legacy", request["roundId"], "0" * 64, source_commit, "approve one immutable legacy Arcade binding attestation")
    approval = ApprovalRequest("approval.psychlo.legacy-round.round-arcade-legacy", plan.id, ApprovalLevel.HUMAN, "thread", OwnerDomain.SISKO, plan.reason, ApprovalStatus.APPROVED, ("legacy-attestation",), "human", NOW)
    manifest = {"schemaVersion": "psychlo.legacy-round-binding-attestation.v1", "attestationId": "attestation-legacy-arcade", "roundId": request["roundId"], "requestDigest": hashlib.sha256(json.dumps(request, separators=(",", ":")).encode()).hexdigest(), "startedAt": NOW, "bindingFile": {**binding, "leadToConversation": {"member-hermione": "conversation-arcade"}}, "systemd": {"unit": {**unit, "identity": "overseer-psychlo-usage.service"}, "dropIn": {**dropin, "identity": "overseer-psychlo-usage.service.d/override.conf"}}, "originalInvocation": {"startedAt": "2026-08-16T11:59:00+00:00", "endedAt": "2026-08-16T12:01:00+00:00"}, "approval": {"recordId": approval.id, "recordDigest": approval_record_digest(approval), "planId": plan.id, "planDigest": ""}, "sourceCommit": source_commit}
    manifest_digest = attestation_manifest_digest(manifest)
    plan = replace(plan, adapter_metadata={"legacy_round_reconciliation": {"manifestDigest": manifest_digest, "roundId": request["roundId"], "sourceCommit": source_commit}}, approved=True, approved_by="human", approved_at=NOW)
    manifest["approval"]["planDigest"] = admin_plan_digest(plan)
    # The final plan metadata and manifest digest are mutually bound once.
    manifest_path = tmp_path / "attestation.json"
    manifest_path.write_text(json.dumps(manifest, separators=(",", ":"))); manifest_path.chmod(0o600)
    primary.save_admin_change_plan(plan)
    primary.save_approval(approval)
    bridge = PsychloBridge(store=store, dispatcher=Dispatcher(binding_path, found), sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW, approval_store=primary, recover=False)
    return bridge, manifest_path, request, primary


def test_legacy_binding_attestation_persists_exact_binding_and_append_only_record(tmp_path: Path):
    bridge, manifest_path, request, _ = _fixture(tmp_path)
    result = attest_legacy_round_binding(bridge, request["roundId"], manifest_path)
    assert result["accepted"] is True
    assert bridge.store.round_binding(request["roundId"])["conversationId"] == "conversation-arcade"
    assert bridge.store.round_binding_attestation(request["roundId"])["manifestDigest"]


def test_legacy_binding_attestation_refuses_prompt_delivery_and_tampered_file(tmp_path: Path):
    bridge, manifest_path, request, _ = _fixture(tmp_path, found=True)
    with pytest.raises(ValueError, match="prompt delivery"):
        attest_legacy_round_binding(bridge, request["roundId"], manifest_path)
    assert bridge.store.round_binding(request["roundId"]) is None
