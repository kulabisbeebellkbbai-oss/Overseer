from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
import socket

import pytest

from overseer.admin import AdminChangeKind
from overseer.admin import approve_admin_change_plan, plan_psychlo_legacy_process_binding_attestation
from overseer.psychlo_contracts import canonical_digest
from overseer.psychlo_store import PsychloBridgeStore
from overseer.store import SQLiteStore
from overseer.psychlo_process_attestation import (
    AuthoritativeProcessEvidenceCollector,
    SCHEMA,
    ProcessAttestationError,
    attest_process_binding,
    finalize_process_attestation,
    manifest_digest,
    plan_psychlo_legacy_process_binding_attestation,
    stage_process_attestation,
    capture_process_identity,
    capture_direct_codex_child,
    capture_tmux_identity,
    capture_source_identity,
    collect_process_binding_evidence,
)


def test_process_attestation_plan_is_high_human_sisko_and_non_executable():
    plan = plan_psychlo_legacy_process_binding_attestation(
        "plan-arcade-process", "round-arcade", "a" * 64, "b" * 40, "c" * 64,
    )
    assert plan.kind == AdminChangeKind.PSYCHLO_LEGACY_PROCESS_BINDING_ATTESTATION
    assert plan.risk_level.value == "high"
    assert plan.approval_level.value == "human"
    assert plan.owner_domain.value == "sisko"
    assert plan.steps and all(step.command[0].startswith("__overseer_") for step in plan.steps)
    assert plan.can_execute() is False


def test_stage_rejects_symlink_and_never_creates_attestation(tmp_path: Path):
    manifest = tmp_path / "manifest.json"
    target = tmp_path / "target.json"
    target.write_text("{}")
    manifest.symlink_to(target)
    with pytest.raises(ProcessAttestationError, match="symlink|safe"):
        stage_process_attestation(
            round_id="round-arcade", plan_id="plan-arcade-process",
            manifest_path=manifest, evidence={"schemaVersion": SCHEMA},
        )
    assert not (tmp_path / "attestation.sqlite3").exists()


def test_attest_is_insert_only_and_does_not_touch_round_binding(tmp_path: Path):
    bridge = sqlite3.connect(tmp_path / "bridge.sqlite3")
    bridge.executescript(
        "CREATE TABLE rounds(round_id TEXT PRIMARY KEY, dispatch_state TEXT, result_json TEXT, codex_binding_json TEXT);"
        "INSERT INTO rounds VALUES('round-arcade','started',NULL,NULL);"
    )
    bridge.commit(); bridge.close()
    # The adapter must require an authoritative approved plan and an exact
    # process evidence snapshot before writing the separate table.
    with pytest.raises(ProcessAttestationError, match="approval|evidence"):
        attest_process_binding(tmp_path / "bridge.sqlite3", "round-arcade", "plan-arcade-process")
    check = sqlite3.connect(tmp_path / "bridge.sqlite3")
    assert check.execute("SELECT codex_binding_json FROM rounds").fetchone()[0] is None
    check.close()


def test_finalize_requires_exact_plan_digest_and_replays(tmp_path: Path):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"schemaVersion": SCHEMA, "roundId": "round-arcade", "approval": {"planId": "plan", "planDigest": ""}}))
    with pytest.raises(ProcessAttestationError, match="approved|exact"):
        finalize_process_attestation(path, approved_plan=None)


def _valid_evidence(round_id: str, plan_id: str) -> dict:
    return {
        "schemaVersion": SCHEMA, "attestationId": f"attestation-{round_id}", "roundId": round_id,
        "requestDigest": "1" * 64, "startedAt": "2099-01-01T00:00:00+00:00",
        "registry": {"pathDigest": "2" * 64, "rowDigest": "3" * 64, "conversationId": "conversation-arcade", "sessionId": "session-arcade", "workspaceDigest": "4" * 64, "commandDigest": "5" * 64, "launcherDigest": "6" * 64, "canonicalPathDigest": "7" * 64},
        "tmux": {"socket": {"dev": 1, "ino": 2, "mode": 0o700, "uid": os.getuid()}, "socketPathDigest": "6" * 64, "serverProcess": {"pid": 10, "startTicks": 1, "exeDigest": "7" * 64, "cgroupDigest": "8" * 64, "argvDigest": "9" * 64, "pidfdSupported": True}, "sessionId": "$33", "windowId": "@33", "paneId": "%33"},
        "process": {"pane": {"pid": 10, "startTicks": 1, "exeDigest": "a" * 64, "cgroupDigest": "b" * 64, "argvDigest": "c" * 64, "pidfdSupported": True}, "codexChild": {"pid": 11, "startTicks": 2, "exeDigest": "d" * 64, "cgroupDigest": "e" * 64, "argvDigest": "f" * 64, "pidfdSupported": True}},
        "rollout": {"negativeBefore": True, "negativeAfter": True, "bindingDigest": "0" * 64},
        "bridge": {"dispatchState": "started", "resultPresent": False, "deliveryPhase": "submitted", "recoveryPresent": False, "failurePresent": False, "cancelPresent": False, "requestDigest": "1" * 64, "capabilityHash": "2" * 64, "bindingDigest": "3" * 64, "promptDigest": "4" * 64},
        "approval": {"planId": plan_id, "planDigest": ""}, "source": {"commit": "a" * 40, "treeDigest": "b" * 40, "moduleDigest": "c" * 64},
    }


def test_manifest_rejects_sensitive_prompt_callback_capture_or_argv_fields(tmp_path: Path):
    evidence = _valid_evidence("round", "plan")
    evidence["process"]["argv"] = "must-not-persist"
    with pytest.raises(ProcessAttestationError, match="operator|Authoritative"):
        stage_process_attestation(round_id="round", plan_id="plan", manifest_path=tmp_path / "manifest.json", evidence=evidence)


def test_stage_requires_trusted_collector_and_does_not_accept_operator_evidence(tmp_path: Path):
    evidence = _valid_evidence("round", "plan")
    with pytest.raises(ProcessAttestationError, match="collector"):
        stage_process_attestation(round_id="round", plan_id="plan", manifest_path=tmp_path / "manifest.json", evidence=evidence)


def test_attest_rederives_evidence_before_insert(tmp_path: Path):
    # A collector returning changed evidence must fail before the store is
    # opened, so there is no possible partial attestation.
    with pytest.raises(ProcessAttestationError, match="collector|fresh"):
        attest_process_binding(tmp_path / "bridge.sqlite3", "round", "plan", manifest_path=tmp_path / "manifest.json", primary_store=None, evidence_provider=lambda *_: {})


def test_manifest_requires_submitted_resultless_bridge_state(tmp_path: Path):
    evidence = _valid_evidence("round", "plan")
    evidence["bridge"]["deliveryPhase"] = "confirmed"
    with pytest.raises(ProcessAttestationError, match="operator|Authoritative"):
        stage_process_attestation(round_id="round", plan_id="plan", manifest_path=tmp_path / "manifest.json", collector=lambda *_: evidence)


def test_process_attestation_insert_preserves_codex_binding_and_is_replay_exact(tmp_path: Path):
    round_id, plan_id = "round", "plan"
    secure = tmp_path / "secure"
    secure.mkdir(mode=0o700)
    bridge = PsychloBridgeStore(secure / "bridge.sqlite3")
    request = {"roundId": round_id, "projectId": "arcade", "projectLeadId": "hermione", "idempotencyKey": "idem"}
    receipt = {**request, "status": "accepted", "sourceId": "hermione", "provenanceId": "prov"}
    capability = "capability-1234567890"
    bridge.record_round(request, receipt, capability)
    bridge.mark_dispatch_started(round_id, "2099-01-01T00:00:00+00:00")
    binding = {"conversationId": "conversation-arcade", "sessionId": "session-arcade", "rolloutPathDigest": "1" * 64, "rolloutDev": 1, "rolloutIno": 2}
    bridge.connection.execute("UPDATE rounds SET codex_binding_json=? WHERE round_id=?", (json.dumps(binding, separators=(",", ":")), round_id))
    prompt_digest = "4" * 64
    bridge.record_round_prompt_delivery_phase(round_id, request, capability, binding, prompt_digest, "submitted", now="2099-01-01T00:00:00+00:00")
    before = bridge.connection.execute("SELECT codex_binding_json FROM rounds WHERE round_id=?", (round_id,)).fetchone()[0]
    manifest = _valid_evidence(round_id, plan_id)
    # Wire digests are the authoritative values used by the insert CAS.
    manifest["requestDigest"] = bridge._round_request_digest(request)
    manifest["bridge"]["requestDigest"] = manifest["requestDigest"]
    manifest["bridge"]["capabilityHash"] = __import__("hashlib").sha256(capability.encode()).hexdigest()
    manifest["bridge"]["bindingDigest"] = __import__("hashlib").sha256(json.dumps(binding, separators=(",", ":")).encode()).hexdigest()
    primary = SQLiteStore(secure / "primary.sqlite3")
    source = manifest["source"]
    plan = plan_psychlo_legacy_process_binding_attestation(plan_id, round_id, manifest_digest(manifest), source["commit"], source["treeDigest"], source["moduleDigest"])
    primary.save_admin_change_plan(approve_admin_change_plan(plan, "sisko", "2099-01-01T00:00:00+00:00"))
    path = secure / "manifest.json"
    class Dispatcher:
        def scan_rollout(self, _lead, _prompt):
            return False
        def binding_provenance(self, _lead):
            return {"found": False, **binding}
        def process_binding_provenance(self, _lead):
            workspace = secure / "arcade"
            workspace.mkdir(exist_ok=True)
            return {"conversationId": binding["conversationId"], "sessionId": binding["sessionId"], "workspace": str(workspace), "command": "codex", "launcher": "/bin/sh", "workspaceDev": "1", "workspaceIno": "2", "launcherDev": "1", "launcherIno": "3", "registryPath": str(secure / "codex-projects.csv")}
    class Bridge:
        def __init__(self): self.store = bridge; self.dispatcher = Dispatcher()
        def _round_prompt(self, _request, _capability): return "derived prompt"
    registry = secure / "registry.json"
    registry.write_text(json.dumps({"hermione": {"conversationId": binding["conversationId"]}}, separators=(",", ":")))
    registry.chmod(0o600)
    canonical_registry = secure / "codex-projects.csv"
    canonical_registry.write_text("conversation_id,project,command,launcher\nconversation-arcade,arcade,codex,/usr/bin/codex\n")
    canonical_registry.chmod(0o600)
    tmux_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    tmux_socket_path = secure / "tmux.sock"
    tmux_listener.bind(str(tmux_socket_path)); tmux_listener.listen(1); tmux_socket_path.chmod(0o700)
    identity = {"pid": 10, "startTicks": 1, "exeDigest": "a" * 64, "argvDigest": "b" * 64, "cgroupDigest": "c" * 64, "pidfdSupported": True}
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("overseer.psychlo_process_attestation.capture_tmux_identity", lambda *_args, **_kwargs: {"socket": {"dev": 1, "ino": 2, "mode": 448, "uid": os.getuid(), "pathDigest": "6" * 64}, "sessionId": "$1", "windowId": "@1", "paneId": "%1", "paneCommandDigest": "d" * 64, "serverProcess": {**identity, "pid": 9}, "paneProcess": {**identity, "pid": 10}, "serverEvidence": "list-sessions-and-list-panes-explicit-socket"})
    monkeypatch.setattr("overseer.psychlo_process_attestation.capture_direct_codex_child", lambda *_args, **_kwargs: {**identity, "pid": 11, "parentPid": 10})
    held_writes = []
    def fake_pidfd(_pid):
        read_fd, write_fd = os.pipe()
        held_writes.append(write_fd)
        return read_fd
    monkeypatch.setattr(os, "pidfd_open", fake_pidfd)
    monkeypatch.setattr("overseer.psychlo_process_attestation.capture_source_identity", lambda *_args: manifest["source"])
    authority = AuthoritativeProcessEvidenceCollector(Bridge(), str(registry), str(tmux_socket_path), "%1", str(secure))
    live = authority.collect(round_id, plan_id)
    plan = plan_psychlo_legacy_process_binding_attestation(plan_id, round_id, manifest_digest(live), source["commit"], source["treeDigest"], source["moduleDigest"])
    primary._connection.execute("DELETE FROM admin_change_plans")
    primary.save_admin_change_plan(approve_admin_change_plan(plan, "sisko", "2099-01-01T00:00:00+00:00"))
    path = secure / "manifest.json"
    stage_process_attestation(round_id=round_id, plan_id=plan_id, manifest_path=path, authority=authority, primary_store=primary)
    finalize_process_attestation(path, primary.load_admin_change_plan(plan_id))
    accepted = attest_process_binding(bridge, round_id, plan_id, manifest_path=path, primary_store=primary, authority=authority)
    replay = attest_process_binding(bridge, round_id, plan_id, manifest_path=path, primary_store=primary, authority=authority)
    monkeypatch.undo()
    assert accepted == replay
    assert bridge.connection.execute("SELECT codex_binding_json FROM rounds WHERE round_id=?", (round_id,)).fetchone()[0] == before
    assert bridge.process_binding_attestation(round_id)["manifestDigest"]
    primary.close(); bridge.close()
    tmux_listener.close()
    for write_fd in held_writes:
        os.close(write_fd)


def test_proc_identity_has_starttime_and_no_raw_argv(tmp_path: Path):
    identity = capture_process_identity(os.getpid())
    assert identity["pid"] == os.getpid()
    assert identity["startTicks"] > 0
    assert "argv" not in identity and "commandLine" not in identity


def test_tmux_collector_is_headless_and_never_uses_terminal_input(monkeypatch, tmp_path: Path):
    socket_path = tmp_path / "tmux.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    server.listen(1)
    socket_path.chmod(0o700)
    calls = []

    class Result:
        returncode = 0
        stderr = ""

        def __init__(self, stdout: str):
            self.stdout = stdout

    def fake_run(command, **_kwargs):
        calls.append(command)
        if command[3] == "list-sessions":
            return Result(f"$1|{os.getpid()}\n")
        return Result(f"$1|@1|%1|{os.getpid()}\n")

    monkeypatch.setattr("overseer.psychlo_process_attestation.subprocess.run", fake_run)
    result = capture_tmux_identity(str(socket_path), "%1")
    assert result["paneId"] == "%1"
    assert all(not any(token in command for token in ("info", "capture-pane", "send-keys", "kill-session")) for command in calls)
    assert all(command[0] == "/usr/bin/tmux" for command in calls)
    server.close()


def test_process_attestation_table_is_append_only(tmp_path: Path):
    bridge = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    bridge.connection.execute("INSERT INTO round_process_binding_attestations VALUES ('a','r','" + "a" * 64 + "','" + "b" * 64 + "','{}','now')")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        bridge.connection.execute("UPDATE round_process_binding_attestations SET manifest_json='{}'")
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        bridge.connection.execute("DELETE FROM round_process_binding_attestations")
    bridge.close()


def test_authoritative_collector_rejects_operator_evidence_and_insecure_source(tmp_path: Path):
    with pytest.raises(ProcessAttestationError, match="operator evidence"):
        collect_process_binding_evidence(round_id="round", evidence={"bridge": "claimed"})
    insecure = tmp_path / "source"
    insecure.mkdir(mode=0o755)
    with pytest.raises(ProcessAttestationError, match="private|trusted|verified|dirty"):
        capture_source_identity(insecure)


def test_tmux_query_rejects_changed_second_snapshot(monkeypatch, tmp_path: Path):
    socket_path = tmp_path / "tmux.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path)); server.listen(1); socket_path.chmod(0o700)
    class Result:
        returncode = 0
        stderr = ""
        def __init__(self, stdout: str): self.stdout = stdout
    counter = {"panes": 0}
    def fake_run(command, **_kwargs):
        if command[3] == "list-sessions": return Result("$1|10\n")
        counter["panes"] += 1
        return Result(f"$1|@1|%1|{os.getpid()}|codex-{counter['panes']}\n")
    monkeypatch.setattr("overseer.psychlo_process_attestation.subprocess.run", fake_run)
    with pytest.raises(ProcessAttestationError, match="changed"):
        capture_tmux_identity(str(socket_path), "%1")
    server.close()


def test_cli_attestation_bridge_is_request_scoped_and_never_runs_recovery(monkeypatch):
    from overseer import psychlo_bridge_cli
    calls = []
    class Template:
        def request_scoped(self):
            calls.append("request-scoped")
            return "scoped"
        def close(self):
            calls.append("template-close")
    monkeypatch.setattr(psychlo_bridge_cli, "create_bridge_from_environment", lambda *, recover=True, require_distinct_authority_store=False: (calls.append((recover, require_distinct_authority_store)) or Template()))
    assert psychlo_bridge_cli._create_process_attestation_bridge() == "scoped"
    assert calls == [(False, True), "request-scoped", "template-close"]


def test_process_bridge_rejects_missing_or_same_authority_store(tmp_path: Path):
    from overseer.psychlo_bridge import create_bridge_from_environment
    base = {"OVERSEER_PSYCHLO_BRIDGE_DATABASE": str(tmp_path / "bridge.sqlite3")}
    with pytest.raises(ValueError, match="OVERSEER_STORE_DATABASE"):
        create_bridge_from_environment(base, recover=False, require_distinct_authority_store=True)
    with pytest.raises(ValueError, match="distinct"):
        create_bridge_from_environment({**base, "OVERSEER_STORE_DATABASE": base["OVERSEER_PSYCHLO_BRIDGE_DATABASE"]}, recover=False, require_distinct_authority_store=True)


def test_attestation_rejects_collector_subclass_overrides(tmp_path: Path):
    class SpoofedCollector(AuthoritativeProcessEvidenceCollector):
        def collect(self, *_args):
            return {}
    with pytest.raises(ProcessAttestationError, match="AuthoritativeProcessEvidenceCollector"):
        stage_process_attestation(round_id="round", plan_id="plan", manifest_path=tmp_path / "manifest.json", authority=object.__new__(SpoofedCollector), primary_store=object())


def test_direct_shell_child_is_rejected_even_when_conversation_token_matches(monkeypatch, tmp_path: Path):
    workspace = tmp_path / "arcade"
    workspace.mkdir(mode=0o700)
    identity = {"pid": 22, "startTicks": 1, "exeDigest": "a" * 64, "argvDigest": "b" * 64, "cgroupDigest": "c" * 64, "pidfdSupported": True}
    monkeypatch.setattr("overseer.psychlo_process_attestation.capture_process_identity", lambda pid: {**identity, "pid": pid})
    monkeypatch.setattr("overseer.psychlo_process_attestation._read_proc_bytes", lambda path: b"123\n" if str(path).endswith("children") else b"resume\0conversation-arcade\0--cd\0" + str(workspace).encode() + b"\0")
    monkeypatch.setattr("overseer.psychlo_process_attestation.os.readlink", lambda path: "/bin/sh" if str(path).endswith("/exe") else str(workspace))
    with pytest.raises(ProcessAttestationError, match="trusted executable"):
        capture_direct_codex_child(22, expected_conversation_id="conversation-arcade", expected_exe_path="/usr/bin/codex", expected_workspace=str(workspace))
