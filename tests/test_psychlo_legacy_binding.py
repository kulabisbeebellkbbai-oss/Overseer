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
    _require_binding_provenance,
    _verify_source_lineage,
    finalize_legacy_round_attestation,
    prepare_legacy_round_attestation,
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
        return {"found": False, "conversationId": "conversation-arcade", "sessionId": "session-arcade", "rolloutPathDigest": "a" * 64, "rolloutDev": 1, "rolloutIno": 2}

    def scan_rollout(self, _lead, _prompt):
        binding = {key: value for key, value in self.binding_provenance(_lead).items() if key != "found"}
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
    primary_path = secure_root / "primary.sqlite3"
    source_root = Path(__file__).resolve().parents[1]
    unit = _private_file(secure_root / "overseer-api.service", f"[Service]\nWorkingDirectory={source_root}\nEnvironment=PYTHONPATH=\"{source_root / 'src'}\"\nExecStart=/usr/bin/python3 -m overseer.cli serve-api --store {primary_path}\n".encode())
    dropin_content = f"[Service]\nEnvironment=OVERSEER_PSYCHLO_PROJECT_BINDINGS_FILE={binding_path}\nEnvironment=OVERSEER_PSYCHLO_BRIDGE_DATABASE={tmp_path / 'bridge.sqlite3'}\n".encode()
    dropin_dir = secure_root / "overseer-api.service.d"
    dropin_dir.mkdir(mode=0o700, exist_ok=True)
    dropin_dir.chmod(0o700)
    dropin = _private_file(dropin_dir / "override.conf", dropin_content)
    request = {"roundId": "round-arcade-legacy", "projectId": "arcade", "projectLeadId": "member-hermione", "planId": "arcade-plan", "planVersion": "v1", "correlationId": "corr-arcade-legacy", "idempotencyKey": "request-arcade-legacy", "snapshotId": "snapshot-arcade-legacy", "policyVersion": "2026-08-09", "expectedUsageCost": 1, "scope": "one bounded round", "selectionReason": "priority-selected", "priorityRationale": "manual-priority"}
    receipt = {**request, "sourceId": request["projectLeadId"], "provenanceId": "dispatch-legacy", "status": "accepted"}
    store = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    store.record_round(request, receipt, "capability:legacy-arcade-1234567890")
    store.mark_dispatch_started(request["roundId"], NOW)
    primary = SQLiteStore(primary_path)
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
    bridge.systemd_query = lambda _unit: {"fragmentPath": str(unit_path := (secure_root / "overseer-api.service")), "dropInPaths": [str(dropin_path := (secure_root / "overseer-api.service.d" / "override.conf"))], "execStart": ["/usr/bin/python3", "-m", "overseer.cli", "serve-api", "--store", str(primary_path)], "environment": {"PYTHONPATH": str(source_root / "src"), "OVERSEER_PSYCHLO_PROJECT_BINDINGS_FILE": str(binding_path), "OVERSEER_PSYCHLO_BRIDGE_DATABASE": str(tmp_path / "bridge.sqlite3")}, "workingDirectory": str(source_root)}
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


def test_rollout_provenance_accepts_only_explicit_negative_lookup():
    evidence = {"found": False, "conversationId": "conversation-arcade", "sessionId": "session-arcade", "rolloutPathDigest": "a" * 64, "rolloutDev": 1, "rolloutIno": 2}
    assert _require_binding_provenance(evidence, "conversation-arcade")["conversationId"] == "conversation-arcade"
    for invalid in (
        {key: value for key, value in evidence.items() if key != "found"},
        {**evidence, "found": True},
        {**evidence, "found": 0},
        {**evidence, "unexpected": "reject"},
    ):
        with pytest.raises(ValueError, match="provenance"):
            _require_binding_provenance(invalid, "conversation-arcade")


def _typed_prepare_fixture(tmp_path: Path, monkeypatch):
    bridge, old_manifest_path, request, primary = _fixture(tmp_path)
    old_manifest = json.loads(Path(old_manifest_path).read_text())
    export = json.loads(Path(old_manifest["journalEvidence"]["path"]).read_text())
    monkeypatch.setattr("overseer.psychlo_legacy_binding._direct_journal_query", lambda *_args: export)
    import overseer.psychlo_legacy_binding as module
    source_root = Path(__file__).resolve().parents[1]
    monkeypatch.setattr(module, "_effective_systemd_query", lambda *_args: {"fragmentPath": str(old_manifest["systemd"]["unit"]["path"]), "dropInPaths": [str(old_manifest["systemd"]["dropIn"]["path"])], "execStart": ["/usr/bin/python3", "-m", "overseer.cli", "serve-api", "--store", str(primary.path)], "environment": {"PYTHONPATH": str(source_root / "src"), "OVERSEER_PSYCHLO_PROJECT_BINDINGS_FILE": old_manifest["bindingFile"]["path"], "OVERSEER_PSYCHLO_BRIDGE_DATABASE": str(bridge.store.filename)}, "workingDirectory": str(source_root)})
    output_root = Path("/home/god/.codex") / f"legacy-prepare-{tmp_path.name}"
    output_root.mkdir(mode=0o700, exist_ok=True)
    env = {
        "OVERSEER_PSYCHLO_BRIDGE_DATABASE": str(bridge.store.filename),
        "OVERSEER_PSYCHLO_PROJECT_BINDINGS_FILE": old_manifest["bindingFile"]["path"],
        "OVERSEER_STORE_DATABASE": str(primary.path),
    }
    values = {
        "round_id": request["roundId"], "plan_id": "admin.test.typed-legacy", "manifest_path": output_root / "manifest.json",
        "journal_path": output_root / "journal.json", "invocation_id": old_manifest["invocationId"], "boot_id": old_manifest["bootId"],
        "unit_path": old_manifest["systemd"]["unit"]["path"], "drop_in_path": old_manifest["systemd"]["dropIn"]["path"],
        "source_root": Path(__file__).resolve().parents[1], "environment": env,
    }
    return bridge, primary, values, output_root


def test_typed_legacy_prepare_and_finalize_binds_only_approved_plan(tmp_path: Path, monkeypatch):
    bridge, primary, values, output_root = _typed_prepare_fixture(tmp_path, monkeypatch)
    try:
        prepared = prepare_legacy_round_attestation(**values)
        assert prepared["prepared"] is True
        manifest = json.loads(values["manifest_path"].read_text())
        plan = primary.load_admin_change_plan(values["plan_id"])
        assert plan.approved is False
        assert manifest["approval"]["planDigest"] == ""
        with pytest.raises(ValueError, match="approved"):
            finalize_legacy_round_attestation(values["plan_id"], values["manifest_path"], values["environment"])
        primary.save_admin_change_plan(approve_admin_change_plan(plan, "human", NOW))
        finalized = finalize_legacy_round_attestation(values["plan_id"], values["manifest_path"], values["environment"])
        assert finalized["finalized"] is True
        assert json.loads(values["manifest_path"].read_text())["approval"]["planDigest"]
    finally:
        bridge.close(); primary.close(); shutil.rmtree(output_root, ignore_errors=True)


def test_typed_legacy_prepare_finalize_and_attest_end_to_end(tmp_path: Path, monkeypatch):
    bridge, primary, values, output_root = _typed_prepare_fixture(tmp_path, monkeypatch)
    try:
        prepared = prepare_legacy_round_attestation(**values)
        assert prepared["prepared"] is True
        plan = primary.load_admin_change_plan(values["plan_id"])
        primary.save_admin_change_plan(approve_admin_change_plan(plan, "human", NOW))
        finalized = finalize_legacy_round_attestation(values["plan_id"], values["manifest_path"], values["environment"])
        assert finalized["finalized"] is True
        attested = attest_legacy_round_binding(bridge, values["round_id"], values["manifest_path"])
        assert attested["accepted"] is True
        assert bridge.store.round_binding_attestation(values["round_id"])["manifestDigest"]
    finally:
        bridge.close(); primary.close(); shutil.rmtree(output_root, ignore_errors=True)


def test_typed_legacy_prepare_rejects_wrong_store_and_preserves_existing_outputs(tmp_path: Path, monkeypatch):
    bridge, primary, values, output_root = _typed_prepare_fixture(tmp_path, monkeypatch)
    try:
        values["environment"] = {**values["environment"], "OVERSEER_STORE_DATABASE": values["environment"]["OVERSEER_PSYCHLO_BRIDGE_DATABASE"]}
        with pytest.raises(ValueError, match="primary store"):
            prepare_legacy_round_attestation(**values)
        values["environment"] = {**values["environment"], "OVERSEER_STORE_DATABASE": str(primary.path)}
        values["manifest_path"].write_text("pre-existing", encoding="utf-8"); values["manifest_path"].chmod(0o600)
        with pytest.raises(ValueError, match="already exists|exact replay"):
            prepare_legacy_round_attestation(**values)
        assert values["manifest_path"].read_text() == "pre-existing"
        assert not values["journal_path"].exists()
        values["manifest_path"].unlink()
        target = output_root / "outside.json"
        target.write_text("protected", encoding="utf-8"); target.chmod(0o600)
        values["manifest_path"].symlink_to(target)
        with pytest.raises(ValueError, match="already exists|safely"):
            prepare_legacy_round_attestation(**{**values, "plan_id": "admin.test.symlink"})
        assert values["manifest_path"].is_symlink() and target.read_text() == "protected"
        assert not values["journal_path"].exists()
    finally:
        bridge.close(); primary.close(); shutil.rmtree(output_root, ignore_errors=True)


def test_typed_legacy_finalize_rejects_manifest_tampering_and_wrong_invocation(tmp_path: Path, monkeypatch):
    bridge, primary, values, output_root = _typed_prepare_fixture(tmp_path, monkeypatch)
    try:
        original_query = __import__("overseer.psychlo_legacy_binding", fromlist=["_direct_journal_query"])._direct_journal_query
        bad = json.loads(values["journal_path"].read_text()) if values["journal_path"].exists() else None
        monkeypatch.setattr("overseer.psychlo_legacy_binding._direct_journal_query", lambda *_args: {"format": "psychlo.original-invocation-journal.v1", "invocationId": "wrong", "bootId": "wrong", "userUnit": "overseer-api.service", "records": []})
        with pytest.raises(ValueError, match="journal"):
            prepare_legacy_round_attestation(**{**values, "plan_id": "admin.test.wrong-invocation"})
        monkeypatch.setattr("overseer.psychlo_legacy_binding._direct_journal_query", original_query)
        prepare_legacy_round_attestation(**values)
        plan = primary.load_admin_change_plan(values["plan_id"])
        primary.save_admin_change_plan(approve_admin_change_plan(plan, "human", NOW))
        manifest = json.loads(values["manifest_path"].read_text()); manifest["requestDigest"] = "f" * 64
        values["manifest_path"].write_text(json.dumps(manifest, separators=(",", ":"))); values["manifest_path"].chmod(0o600)
        with pytest.raises(ValueError, match="bind|manifest"):
            finalize_legacy_round_attestation(values["plan_id"], values["manifest_path"], values["environment"])
    finally:
        bridge.close(); primary.close(); shutil.rmtree(output_root, ignore_errors=True)


def test_typed_legacy_finalize_short_write_and_retry_after_replace_are_safe(tmp_path: Path, monkeypatch):
    bridge, primary, values, output_root = _typed_prepare_fixture(tmp_path, monkeypatch)
    try:
        prepare_legacy_round_attestation(**values)
        plan = primary.load_admin_change_plan(values["plan_id"])
        primary.save_admin_change_plan(approve_admin_change_plan(plan, "human", NOW))
        import overseer.psychlo_legacy_binding as module
        original_write = module.os.write
        short_once = {"value": True}

        def short_write(fd, data):
            if short_once["value"] and len(data) > 2:
                short_once["value"] = False
                return original_write(fd, data[:2])
            return original_write(fd, data)

        monkeypatch.setattr(module.os, "write", short_write)
        first = finalize_legacy_round_attestation(values["plan_id"], values["manifest_path"], values["environment"])
        assert first["finalized"] is True
        replay = finalize_legacy_round_attestation(values["plan_id"], values["manifest_path"], values["environment"])
        assert replay["replay"] is True
    finally:
        bridge.close(); primary.close(); shutil.rmtree(output_root, ignore_errors=True)


def test_typed_legacy_finalize_recovers_after_replace_before_return(tmp_path: Path, monkeypatch):
    bridge, primary, values, output_root = _typed_prepare_fixture(tmp_path, monkeypatch)
    try:
        prepare_legacy_round_attestation(**values)
        plan = primary.load_admin_change_plan(values["plan_id"])
        primary.save_admin_change_plan(approve_admin_change_plan(plan, "human", NOW))
        import overseer.psychlo_legacy_binding as module
        original_replace = module.os.replace
        raised = {"value": False}

        def replace_then_crash(*args, **kwargs):
            original_replace(*args, **kwargs)
            if not raised["value"]:
                raised["value"] = True
                raise RuntimeError("injected crash after manifest replace")

        monkeypatch.setattr(module.os, "replace", replace_then_crash)
        with pytest.raises(RuntimeError, match="injected crash"):
            finalize_legacy_round_attestation(values["plan_id"], values["manifest_path"], values["environment"])
        monkeypatch.setattr(module.os, "replace", original_replace)
        replay = finalize_legacy_round_attestation(values["plan_id"], values["manifest_path"], values["environment"])
        assert replay["replay"] is True
    finally:
        bridge.close(); primary.close(); shutil.rmtree(output_root, ignore_errors=True)


@pytest.mark.parametrize("crash_point", ("journal", "manifest", "plan"))
def test_typed_legacy_prepare_resumes_after_each_durable_stage(tmp_path: Path, monkeypatch, crash_point: str):
    bridge, primary, values, output_root = _typed_prepare_fixture(tmp_path / crash_point, monkeypatch)
    import overseer.psychlo_legacy_binding as module
    try:
        if crash_point in {"journal", "manifest"}:
            original_create = module._atomic_create_private

            def create_then_crash(path, content):
                result = original_create(path, content)
                if path.name == f"{crash_point}.json" or (crash_point == "journal" and path == values["journal_path"]) or (crash_point == "manifest" and path == values["manifest_path"]):
                    raise RuntimeError(f"injected crash after {crash_point}")
                return result

            monkeypatch.setattr(module, "_atomic_create_private", create_then_crash)
        else:
            original_save = module.SQLiteStore.save_admin_change_plan

            def save_then_crash(store, plan):
                original_save(store, plan)
                raise RuntimeError("injected crash after plan")

            monkeypatch.setattr(module.SQLiteStore, "save_admin_change_plan", save_then_crash)
        with pytest.raises(RuntimeError, match="injected crash"):
            prepare_legacy_round_attestation(**values)
        monkeypatch.setattr(module, "_atomic_create_private", original_create if crash_point in {"journal", "manifest"} else module._atomic_create_private)
        if crash_point == "plan":
            monkeypatch.setattr(module.SQLiteStore, "save_admin_change_plan", original_save)
        resumed = prepare_legacy_round_attestation(**values)
        assert resumed["prepared"] is True
        assert primary.load_admin_change_plan(values["plan_id"]).approved is False
    finally:
        bridge.close(); primary.close(); shutil.rmtree(output_root, ignore_errors=True)


def test_typed_legacy_primary_store_trusted_symlink_uses_same_file_identity(tmp_path: Path, monkeypatch):
    bridge, primary, values, output_root = _typed_prepare_fixture(tmp_path, monkeypatch)
    link = output_root / "primary-link.sqlite3"
    link.symlink_to(primary.path)
    values["environment"] = {**values["environment"], "OVERSEER_STORE_DATABASE": str(link)}
    try:
        result = prepare_legacy_round_attestation(**values)
        assert result["prepared"] is True
    finally:
        bridge.close(); primary.close(); shutil.rmtree(output_root, ignore_errors=True)


def test_typed_legacy_primary_store_intermediate_live_style_symlink_resolves_safely(tmp_path: Path, monkeypatch):
    bridge, primary, values, output_root = _typed_prepare_fixture(tmp_path, monkeypatch)
    alias_root = output_root / "project-alias"
    alias_root.mkdir(mode=0o700)
    (alias_root / "project").symlink_to(primary.path.parent)
    declared = alias_root / "project" / primary.path.name
    values["environment"] = {**values["environment"], "OVERSEER_STORE_DATABASE": str(declared)}
    try:
        result = prepare_legacy_round_attestation(**values)
        assert result["prepared"] is True
    finally:
        bridge.close(); primary.close(); shutil.rmtree(output_root, ignore_errors=True)


def test_direct_journal_query_uses_user_unit_over_parent_system_unit(tmp_path: Path, monkeypatch):
    import overseer.psychlo_legacy_binding as module

    invocation_id = "invocation-live-shaped"
    boot_id = "boot-live-shaped"
    raw_records = []
    for cursor, realtime, monotonic, pid, message in (
        ("cursor-1", "1000000000000000", "100", "1234", "start"),
        ("cursor-2", "1000001000000000", "200", "1235", "end"),
    ):
        raw_records.append(json.dumps({
            "__CURSOR": cursor,
            "__REALTIME_TIMESTAMP": realtime,
            "__MONOTONIC_TIMESTAMP": monotonic,
            "_PID": pid,
            "MESSAGE": message,
            "_SYSTEMD_INVOCATION_ID": invocation_id,
            "_BOOT_ID": boot_id,
            "_SYSTEMD_UNIT": "user@1000.service",
            "_SYSTEMD_USER_UNIT": "overseer-api.service",
        }))

    class Completed:
        returncode = 0
        stdout = "\n".join(raw_records)

    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: Completed())
    export = module._direct_journal_query(invocation_id, boot_id, "overseer-api.service")
    assert [entry["unit"] for entry in export["records"]] == ["overseer-api.service", "overseer-api.service"]
    assert [entry["userUnit"] for entry in export["records"]] == ["overseer-api.service", "overseer-api.service"]


def test_effective_systemd_query_parses_user_loaded_configuration(tmp_path: Path, monkeypatch):
    import overseer.psychlo_legacy_binding as module

    class Completed:
        returncode = 0
        stdout = "\n".join((
            "FragmentPath=/srv/overseer/overseer-api.service",
            "DropInPaths=/srv/overseer/overseer-api.service.d/psychlo-bridge.conf",
            "ExecStart={ path=/srv/venv/bin/python ; argv[]=/srv/venv/bin/python -m overseer.cli serve-api --store /srv/state/overseer.sqlite3 ; ignore_errors=no ; pid=0 }",
            "Environment=PYTHONPATH=/srv/overseer/src OVERSEER_PSYCHO_MODE=reviewed",
            "WorkingDirectory=/srv/overseer",
        ))

    seen = {}
    def fake_run(*args, **kwargs):
        seen["env"] = kwargs["env"]
        return Completed()

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    result = module._effective_systemd_query()
    assert result["fragmentPath"] == "/srv/overseer/overseer-api.service"
    assert result["dropInPaths"] == ["/srv/overseer/overseer-api.service.d/psychlo-bridge.conf"]
    assert result["execStart"][:4] == ["/srv/venv/bin/python", "-m", "overseer.cli", "serve-api"]
    assert result["environment"]["PYTHONPATH"] == "/srv/overseer/src"
    assert result["workingDirectory"] == "/srv/overseer"
    assert seen["env"]["XDG_RUNTIME_DIR"].startswith("/run/user/")
    assert seen["env"]["DBUS_SESSION_BUS_ADDRESS"].startswith("unix:path=/run/user/")


def test_typed_legacy_rejects_conflicting_dropin_and_wrong_journal_unit(tmp_path: Path, monkeypatch):
    bridge, primary, values, output_root = _typed_prepare_fixture(tmp_path, monkeypatch)
    try:
        dropin_dir = Path(values["drop_in_path"]).parent
        conflicting = dropin_dir / "unreviewed.conf"
        conflicting.write_text("[Service]\nEnvironment=OVERSEER_PSYCHLO_BRIDGE_DATABASE=/tmp/wrong\n", encoding="utf-8")
        conflicting.chmod(0o600)
        with pytest.raises(ValueError, match="DropInPaths|override"):
            prepare_legacy_round_attestation(**values)
        conflicting.unlink()
        # Reuse the fixture's query result and alter only the closed unit field.
        import overseer.psychlo_legacy_binding as module
        monkeypatch.setattr(module, "_direct_journal_query", lambda *_args: {"format": "psychlo.original-invocation-journal.v1", "invocationId": values["invocation_id"], "bootId": values["boot_id"], "userUnit": "overseer-api.service", "records": [{"cursor": "1", "realtime": "2099-08-16T11:59:00+00:00", "monotonic": 1, "pid": 1, "unit": "wrong.service", "messageDigest": "a" * 64, "invocationId": values["invocation_id"], "bootId": values["boot_id"], "userUnit": "overseer-api.service"}, {"cursor": "2", "realtime": "2099-08-16T12:01:00+00:00", "monotonic": 2, "pid": 2, "unit": "wrong.service", "messageDigest": "b" * 64, "invocationId": values["invocation_id"], "bootId": values["boot_id"], "userUnit": "overseer-api.service"}]})
        with pytest.raises(ValueError, match="journal entry"):
            prepare_legacy_round_attestation(**{**values, "plan_id": "admin.test.wrong-unit"})
    finally:
        bridge.close(); primary.close(); shutil.rmtree(output_root, ignore_errors=True)


def test_typed_legacy_rejects_unreviewed_effective_environment(tmp_path: Path, monkeypatch):
    bridge, primary, values, output_root = _typed_prepare_fixture(tmp_path, monkeypatch)
    try:
        import overseer.psychlo_legacy_binding as module
        effective = module._effective_systemd_query()
        monkeypatch.setattr(module, "_effective_systemd_query", lambda *_args: {**effective, "environment": {**effective["environment"], "LD_PRELOAD": "/tmp/unreviewed.so"}})
        with pytest.raises(ValueError, match="effective systemd Environment"):
            prepare_legacy_round_attestation(**{**values, "plan_id": "admin.test.unreviewed-environment"})
    finally:
        bridge.close(); primary.close(); shutil.rmtree(output_root, ignore_errors=True)
