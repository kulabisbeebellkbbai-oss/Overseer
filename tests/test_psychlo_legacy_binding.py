from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import weakref

import pytest

from overseer.admin import approve_admin_change_plan, plan_psychlo_legacy_round_reconciliation
from overseer.psychlo_bridge import PsychloBridge, PsychloBridgeStore
from overseer.psychlo_legacy_binding import (
    admin_plan_digest,
    attest_legacy_round_binding,
    attestation_manifest_digest,
    _private_group_is_safe,
    _verify_source_lineage,
)
from overseer.psychlo_contracts import canonical_digest
from overseer.store import SQLiteStore


NOW = "2099-08-16T12:00:00+00:00"


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


def _fixture(tmp_path: Path, *, found: bool = False, approval_time: str | None = NOW):
    secure_root = Path("/home/god/.codex") / f"legacy-attest-{tmp_path.name}"
    secure_root.mkdir(mode=0o700, exist_ok=True)
    binding_content = json.dumps({"member-hermione": {"conversationId": "conversation-arcade"}}, separators=(",", ":")).encode()
    binding_path = secure_root / "bindings.json"
    binding = _private_file(binding_path, binding_content)
    unit = _private_file(secure_root / "overseer-api.service", b"[Service]\nExecStart=/home/god/.local/share/overseer/venvs/python -m overseer.cli serve-api\n")
    dropin_content = f"[Service]\nEnvironment=OVERSEER_PSYCHLO_PROJECT_BINDINGS_FILE={binding_path}\nEnvironment=OVERSEER_PSYCHLO_BRIDGE_DATABASE={tmp_path / 'bridge.sqlite3'}\n".encode()
    dropin = _private_file(secure_root / "override.conf", dropin_content)
    request = {"roundId": "round-arcade-legacy", "projectId": "arcade", "projectLeadId": "member-hermione", "planId": "arcade-plan", "planVersion": "v1", "correlationId": "corr-arcade-legacy", "idempotencyKey": "request-arcade-legacy", "snapshotId": "snapshot-arcade-legacy", "policyVersion": "2026-08-09", "expectedUsageCost": 1, "scope": "one bounded round", "selectionReason": "priority-selected", "priorityRationale": "manual-priority"}
    receipt = {**request, "sourceId": request["projectLeadId"], "provenanceId": "dispatch-legacy", "status": "accepted"}
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    store.record_round(request, receipt, "capability:legacy-arcade-1234567890")
    store.mark_dispatch_started(request["roundId"], NOW)
    primary = SQLiteStore(tmp_path / "primary.sqlite3")
    source_root = Path(__file__).resolve().parents[1]
    source_commit = subprocess.check_output(["/usr/bin/git", "-C", str(source_root), "rev-parse", "HEAD"], text=True).strip()
    source_tree = subprocess.check_output(["/usr/bin/git", "-C", str(source_root), "rev-parse", "HEAD^{tree}"], text=True).strip()
    plan = plan_psychlo_legacy_round_reconciliation("admin.psychlo.legacy-round.round-arcade-legacy", request["roundId"], "0" * 64, source_commit, "approve one immutable legacy Arcade binding attestation")
    invocation_id, boot_id = "invocation-legacy", "boot-legacy"
    def journal_record(cursor, realtime, monotonic, pid, message):
        return {"cursor": cursor, "realtime": realtime, "monotonic": monotonic, "pid": pid, "unit": "overseer-api.service", "messageDigest": hashlib.sha256(message.encode()).hexdigest(), "invocationId": invocation_id, "bootId": boot_id, "userUnit": "overseer-api.service"}
    journal_records = [journal_record("cursor-1", "2099-08-16T11:59:00+00:00", 100, 1234, "start"), journal_record("cursor-2", "2099-08-16T11:59:30+00:00", 150, 2222, "child"), journal_record("cursor-3", "2099-08-16T12:01:00+00:00", 200, 3333, "end")]
    journal_entries = {"started": journal_records[0], "ended": journal_records[-1]}
    journal_export = {"format": "psychlo.original-invocation-journal.v1", "invocationId": invocation_id, "bootId": boot_id, "userUnit": "overseer-api.service", "records": journal_records}
    journal_content = json.dumps(journal_export, separators=(",", ":")).encode()
    journal = _private_file(secure_root / "journal.json", journal_content)
    manifest = {"schemaVersion": "psychlo.legacy-round-binding-attestation.v1", "attestationId": "attestation-legacy-arcade", "roundId": request["roundId"], "requestDigest": hashlib.sha256(json.dumps(request, separators=(",", ":")).encode()).hexdigest(), "startedAt": NOW, "bindingFile": {**binding, "leadToConversation": {"member-hermione": "conversation-arcade"}}, "systemd": {"unit": {**unit, "identity": "overseer-api.service"}, "dropIn": {**dropin, "identity": "overseer-api.service.d/override.conf"}}, "invocationId": invocation_id, "bootId": boot_id, "journalEvidence": {**journal, "format": "psychlo.original-invocation-journal.v1", **journal_entries}, "approval": {"planId": plan.id, "planDigest": ""}, "attestationSourceCommit": source_commit, "sourceTreeDigest": source_tree}
    manifest_digest = attestation_manifest_digest(manifest)
    plan = replace(plan, adapter_metadata={"legacy_round_reconciliation": {"manifestDigest": manifest_digest, "roundId": request["roundId"], "sourceCommit": source_commit}})
    primary.save_admin_change_plan(plan)
    plan = approve_admin_change_plan(plan, "human", approval_time)
    primary.save_admin_change_plan(plan)
    manifest["approval"]["planDigest"] = admin_plan_digest(plan)
    # The final plan metadata and manifest digest are mutually bound once.
    manifest_path = secure_root / "attestation.json"
    manifest_path.write_text(json.dumps(manifest, separators=(",", ":"))); manifest_path.chmod(0o600)
    bridge = PsychloBridge(store=store, dispatcher=Dispatcher(binding_path, found), sender=lambda *_: {"accepted": True}, callback_origin="http://127.0.0.1:8766", clock=lambda: NOW, approval_store=primary, recover=False)
    bridge.journal_runner = lambda *_args: journal_export
    weakref.finalize(bridge, shutil.rmtree, secure_root, True)
    return bridge, manifest_path, request, primary


def test_legacy_binding_attestation_persists_exact_binding_and_append_only_record(tmp_path: Path):
    bridge, manifest_path, request, _ = _fixture(tmp_path)
    result = attest_legacy_round_binding(bridge, request["roundId"], manifest_path)
    assert result["accepted"] is True
    assert bridge.store.round_binding(request["roundId"])["conversationId"] == "conversation-arcade"
    assert bridge.store.round_binding_attestation(request["roundId"])["manifestDigest"]


def test_legacy_attestation_accepts_ui_style_server_stamped_approval(tmp_path: Path):
    bridge, manifest_path, request, _ = _fixture(tmp_path, approval_time=None)
    result = attest_legacy_round_binding(bridge, request["roundId"], manifest_path)
    assert result["accepted"] is True


def test_legacy_binding_attestation_refuses_prompt_delivery_and_tampered_file(tmp_path: Path):
    bridge, manifest_path, request, _ = _fixture(tmp_path, found=True)
    with pytest.raises(ValueError, match="prompt delivery"):
        attest_legacy_round_binding(bridge, request["roundId"], manifest_path)
    assert bridge.store.round_binding(request["roundId"]) is None


def test_legacy_attestation_rejects_fake_source_lineage(tmp_path: Path):
    with pytest.raises(ValueError, match="source"):
        _verify_source_lineage(tmp_path, "f" * 40, "0" * 64)


def test_legacy_attestation_rejects_dirty_source_tree(monkeypatch, tmp_path: Path):
    class Result:
        returncode = 0
        stdout = ""

    def fake_run(command, **_kwargs):
        result = Result()
        if "status" in command:
            result.stdout = " M src/overseer/psychlo_legacy_binding.py\n"
        elif "^{tree}" in command[-1]:
            result.stdout = "b" * 40 + "\n"
        else:
            result.stdout = "a" * 40 + "\n"
        return result

    monkeypatch.setattr("overseer.psychlo_legacy_binding.subprocess.run", fake_run)
    with pytest.raises(ValueError, match="dirty"):
        _verify_source_lineage(tmp_path, "a" * 40, "b" * 40)


def test_legacy_attestation_rejects_unsafe_shared_group(monkeypatch):
    monkeypatch.setattr("overseer.psychlo_legacy_binding.os.getgid", lambda: 1234)
    monkeypatch.setattr("overseer.psychlo_legacy_binding.os.getuid", lambda: 1000)
    monkeypatch.setattr("overseer.psychlo_legacy_binding.pwd.getpwuid", lambda _uid: type("P", (), {"pw_name": "owner"})())
    monkeypatch.setattr("overseer.psychlo_legacy_binding.pwd.getpwall", lambda: [type("P", (), {"pw_name": "owner", "pw_gid": 1234})(), type("P", (), {"pw_name": "other", "pw_gid": 1234})()])
    monkeypatch.setattr("overseer.psychlo_legacy_binding.grp.getgrgid", lambda _gid: type("G", (), {"gr_mem": ["owner", "other"]})())
    assert _private_group_is_safe(1234) is False


def test_legacy_attestation_rejects_tampered_generic_plan_approval(tmp_path: Path):
    bridge, manifest_path, request, primary = _fixture(tmp_path)
    manifest = json.loads(manifest_path.read_text())
    plan = primary.load_admin_change_plan(manifest["approval"]["planId"])
    primary.save_admin_change_plan(replace(plan, approved_by="different-human"))
    with pytest.raises(ValueError, match="approved|exact"):
        attest_legacy_round_binding(bridge, request["roundId"], manifest_path)


def test_legacy_attestation_replay_returns_exact_existing_record(tmp_path: Path):
    bridge, manifest_path, request, _ = _fixture(tmp_path)
    first = attest_legacy_round_binding(bridge, request["roundId"], manifest_path)
    second = attest_legacy_round_binding(bridge, request["roundId"], manifest_path)
    assert second == first


def test_legacy_attestation_rejects_newer_binding_metadata(tmp_path: Path):
    bridge, manifest_path, request, _ = _fixture(tmp_path)
    manifest = json.loads(manifest_path.read_text())
    os.utime(manifest["bindingFile"]["path"], ns=(manifest["bindingFile"]["mtime"] + 1_000_000_000, manifest["bindingFile"]["mtime"] + 1_000_000_000))
    with pytest.raises(ValueError, match="metadata|changed"):
        attest_legacy_round_binding(bridge, request["roundId"], manifest_path)


def test_legacy_attestation_rejects_unrelated_unit_content(tmp_path: Path):
    bridge, manifest_path, request, _ = _fixture(tmp_path)
    manifest = json.loads(manifest_path.read_text())
    Path(manifest["systemd"]["unit"]["path"]).write_text("[Service]\nExecStart=/bin/true\n")
    with pytest.raises(ValueError, match="digest|ExecStart|changed"):
        attest_legacy_round_binding(bridge, request["roundId"], manifest_path)


def test_legacy_attestation_rejects_fake_invocation_export(tmp_path: Path):
    bridge, manifest_path, request, _ = _fixture(tmp_path)
    manifest = json.loads(manifest_path.read_text())
    evidence = manifest["journalEvidence"]
    journal_path = Path(evidence["path"])
    journal_path.write_text(json.dumps({"format": "psychlo.original-invocation-journal.v1", "invocationId": "fake", "bootId": "fake", "entries": []}, separators=(",", ":")))
    with pytest.raises(ValueError, match="digest|journal"):
        attest_legacy_round_binding(bridge, request["roundId"], manifest_path)


def test_legacy_attestation_rejects_journal_export_not_from_direct_query(tmp_path: Path):
    bridge, manifest_path, request, _ = _fixture(tmp_path)
    bridge.journal_runner = lambda *_args: {"format": "psychlo.original-invocation-journal.v1", "invocationId": "fake", "bootId": "fake", "entries": []}
    with pytest.raises(ValueError, match="direct journal"):
        attest_legacy_round_binding(bridge, request["roundId"], manifest_path)


def test_manifest_digest_is_stable_across_later_human_decision_digests():
    manifest = {"approval": {"planId": "plan", "planDigest": "before"}, "roundId": "round"}
    finalized = {"approval": {"planId": "plan", "planDigest": "after"}, "roundId": "round"}
    assert attestation_manifest_digest(manifest) == attestation_manifest_digest(finalized)
