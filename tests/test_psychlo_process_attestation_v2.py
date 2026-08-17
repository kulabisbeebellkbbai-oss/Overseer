from __future__ import annotations

import json
import os
import inspect
from types import SimpleNamespace

from overseer.admin import approve_admin_change_plan
from overseer.psychlo_process_attestation import (
    SCHEMA,
    attest_process_binding,
    manifest_digest,
    stage_process_attestation,
)
from overseer.psychlo_store import PsychloBridgeStore
from overseer.store import SQLiteStore


def _manifest(round_id: str = "round", plan_id: str = "plan") -> dict:
    identity = {"pid": 10, "startTicks": 1, "exeDigest": "a" * 64, "argvDigest": "b" * 64, "cgroupDigest": "c" * 64, "pidfdSupported": True}
    return {
        "schemaVersion": SCHEMA, "attestationId": f"attestation-{round_id}", "roundId": round_id,
        "requestDigest": "1" * 64, "startedAt": "2099-01-01T00:00:00+00:00",
        "registry": {"pathDigest": "2" * 64, "rowDigest": "3" * 64, "conversationId": "conversation-arcade", "sessionId": "session-arcade", "workspaceDigest": "4" * 64, "commandDigest": "5" * 64, "launcherDigest": "6" * 64, "canonicalPathDigest": "7" * 64},
        "tmux": {"socket": {"dev": 1, "ino": 2, "mode": 448, "uid": os.getuid(), "pathDigest": "8" * 64}, "sessionId": "$1", "windowId": "@1", "paneId": "%1", "paneCommandDigest": "9" * 64, "paneStartCommandDigest": "a" * 64, "serverProcess": {**identity, "pid": 9}, "paneProcess": identity, "paneParentPid": 9, "serverEvidence": "list-sessions-and-list-panes-explicit-socket"},
        "process": {"pane": identity, "codexChild": {**identity, "pid": 11, "parentPid": 10}},
        "rollout": {"found": False, "conversationId": "conversation-arcade", "sessionId": "session-arcade", "rolloutPathDigest": "b" * 64, "rolloutDev": 1, "rolloutIno": 2},
        "bridge": {"dispatchState": "started", "resultPresent": False, "deliveryPhase": "submitted", "recoveryPresent": False, "failurePresent": False, "cancelPresent": False, "requestDigest": "1" * 64, "capabilityHash": "2" * 64, "bindingDigest": "3" * 64, "promptDigest": "4" * 64},
        "approval": {"planId": plan_id, "planDigest": ""},
        "source": {"commit": "c" * 40, "treeDigest": "d" * 40, "moduleDigest": "e" * 64, "runtimeDependencies": {"overseer.psychlo_process_attestation": "e" * 64}, "interpreter": {"dev": 1, "ino": 3, "digest": "f" * 64}},
    }


def _runtime(tmp_path, monkeypatch):
    bridge = PsychloBridgeStore(tmp_path / "bridge.sqlite3")
    request = {"roundId": "round", "projectId": "arcade", "projectLeadId": "hermione", "idempotencyKey": "idem"}
    receipt = {**request, "status": "accepted", "sourceId": "hermione", "provenanceId": "prov"}
    capability = "capability-1234567890"
    bridge.record_round(request, receipt, capability)
    bridge.mark_dispatch_started("round", "2099-01-01T00:00:00+00:00")
    binding = {"conversationId": "conversation-arcade", "sessionId": "session-arcade", "rolloutPathDigest": "b" * 64, "rolloutDev": 1, "rolloutIno": 2}
    bridge.connection.execute("UPDATE rounds SET codex_binding_json=? WHERE round_id='round'", (json.dumps(binding, separators=(",", ":")),))
    bridge.record_round_prompt_delivery_phase("round", request, capability, binding, "4" * 64, "submitted", now="2099-01-01T00:00:00+00:00")
    primary = SQLiteStore(tmp_path / "primary.sqlite3")
    value = _manifest()
    value["requestDigest"] = bridge._round_request_digest(request)
    value["bridge"]["requestDigest"] = value["requestDigest"]
    value["bridge"]["capabilityHash"] = bridge.connection.execute("SELECT capability_hash FROM rounds WHERE round_id='round'").fetchone()[0]
    value["bridge"]["bindingDigest"] = __import__("hashlib").sha256(json.dumps(binding, separators=(",", ":")).encode()).hexdigest()

    class Collector:
        def collect(self, _round_id, _plan_id):
            return json.loads(json.dumps(value))
        def revalidate_held_identities(self):
            return None
        def release_held_identities(self):
            return None

    runtime = SimpleNamespace(
        bridge=SimpleNamespace(store=bridge, clock=lambda: "2099-01-01T00:00:00+00:00"),
        primary=primary, collector=Collector(), close=lambda: None,
    )
    monkeypatch.setattr("overseer.psychlo_process_attestation._open_runtime_authority", lambda _round_id: runtime)
    monkeypatch.setattr("overseer.psychlo_process_attestation._assert_runtime_source_integrity", lambda: None)
    return runtime, value


def test_primary_only_stage_approval_and_completed_lookup(tmp_path, monkeypatch):
    runtime, value = _runtime(tmp_path, monkeypatch)
    staged = stage_process_attestation(round_id="round", plan_id="plan")
    assert staged["manifestDigest"] == manifest_digest(value)
    assert runtime.primary._connection.execute("SELECT state FROM psychlo_process_binding_attestations").fetchone()[0] == "prepared"
    assert runtime.primary.process_binding_attestation("round") is None
    plan = runtime.primary.load_admin_change_plan("plan")
    runtime.primary.save_admin_change_plan(approve_admin_change_plan(plan, "sisko", "2099-01-01T00:00:00+00:00"))
    bridge_changes = runtime.bridge.store.connection.total_changes
    result = attest_process_binding(round_id="round", plan_id="plan")
    assert result["accepted"] is True
    assert runtime.primary.process_binding_attestation("round")["planId"] == "plan"
    assert runtime.bridge.store.connection.total_changes == bridge_changes
    assert runtime.bridge.store.connection.execute("SELECT name FROM sqlite_master WHERE name='round_process_binding_attestations'").fetchone() is None
    runtime.bridge.store.close(); runtime.primary.close()


def test_primary_attestation_transition_is_immutable(tmp_path):
    primary = SQLiteStore(tmp_path / "primary.sqlite3")
    primary._connection.execute("INSERT INTO psychlo_process_binding_attestations VALUES ('a','r','p','" + "a" * 64 + "','', 'prepared','{}','now',NULL)")
    try:
        primary._connection.execute("UPDATE psychlo_process_binding_attestations SET manifest_json='{" + "x" + "}' WHERE round_id='r'")
    except Exception as error:
        assert "immutable" in str(error)
    else:
        raise AssertionError("prepared attestation identity was mutable")
    primary._connection.execute("UPDATE psychlo_process_binding_attestations SET plan_digest='" + "b" * 64 + "',state='completed',completed_at='done' WHERE round_id='r'")
    assert primary.process_binding_attestation("r")["planDigest"] == "b" * 64
    primary.close()


def test_public_operations_have_no_caller_selected_authority_endpoints():
    assert set(inspect.signature(stage_process_attestation).parameters) == {"round_id", "plan_id"}
    assert set(inspect.signature(attest_process_binding).parameters) == {"round_id", "plan_id"}


def test_runtime_hardlink_database_is_rejected(tmp_path):
    from overseer.psychlo_process_attestation import _validate_runtime_path

    database = tmp_path / "primary.sqlite3"
    database.write_bytes(b"sqlite")
    hardlink = tmp_path / "alias.sqlite3"
    hardlink.hardlink_to(database)
    try:
        _validate_runtime_path(hardlink, label="primary authority database")
    except Exception as error:
        assert "unique" in str(error)
    else:
        raise AssertionError("hard-linked authority database was accepted")


def test_process_cli_rejects_endpoint_arguments():
    from overseer.psychlo_bridge_cli import build_parser

    try:
        build_parser().parse_args(("stage-process-attestation", "--round-id", "r", "--plan-id", "p", "--manifest-path", "/tmp/operator.json"))
    except SystemExit as error:
        assert error.code != 0
    else:
        raise AssertionError("caller-selected manifest endpoint was accepted")
