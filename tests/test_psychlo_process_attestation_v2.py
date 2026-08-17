from __future__ import annotations

import json
import os
import inspect
import hashlib
from types import SimpleNamespace
import pytest

from overseer.admin import approve_admin_change_plan
from overseer.psychlo_process_attestation import (
    SCHEMA,
    record_process_observation,
    manifest_digest,
    stage_process_observation,
)
from overseer.psychlo_store import PsychloBridgeStore
from overseer.store import SQLiteStore


def _manifest(round_id: str = "round", plan_id: str = "plan") -> dict:
    identity = {"pid": 10, "startTicks": 1, "exeDigest": "a" * 64, "argvDigest": "b" * 64, "cgroupDigest": "c" * 64, "pidfdSupported": True}
    return {
        "schemaVersion": SCHEMA, "observationId": f"observation-{round_id}", "roundId": round_id,
        "requestDigest": "1" * 64, "startedAt": "2099-01-01T00:00:00+00:00", "historical": True, "authoritative": False, "executable": False,
        "observedWindowStart": "2099-01-01T00:00:00+00:00", "observedWindowEnd": "2099-01-01T00:00:01+00:00",
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
        revalidate_calls = 0
        collect_calls = 0
        def collect(self, _round_id, _plan_id):
            self.collect_calls += 1
            return json.loads(json.dumps(value))
        def revalidate_exact(self, _round_id, _plan_id, _expected):
            self.revalidate_calls += 1
            self.revalidate_held_identities()
        def revalidate_held_identities(self):
            return None
        def release_held_identities(self):
            return None

    runtime = SimpleNamespace(
        bridge=SimpleNamespace(store=bridge, clock=lambda: "2099-01-01T00:00:00+00:00"),
        primary=primary, collector=Collector(), close=lambda: None,
    )
    primary.clock = lambda: runtime.bridge.clock()
    monkeypatch.setattr("overseer.psychlo_process_attestation._open_runtime_authority", lambda _round_id: runtime)
    monkeypatch.setattr(
        "overseer.psychlo_process_attestation._open_primary_observation_authority",
        lambda: SimpleNamespace(primary=primary, primary_identity=None, primary_fd=None, close=lambda: None),
    )
    monkeypatch.setattr("overseer.psychlo_process_attestation._assert_runtime_source_integrity", lambda: None)
    return runtime, value


def test_primary_only_stage_approval_and_completed_lookup(tmp_path, monkeypatch):
    runtime, value = _runtime(tmp_path, monkeypatch)
    staged = stage_process_observation(round_id="round", plan_id="plan")
    assert staged["observationDigest"] == manifest_digest(value)
    assert runtime.primary._connection.execute("SELECT state FROM psychlo_process_observations").fetchone()[0] == "prepared"
    assert runtime.primary.process_observation("round") is None
    plan = runtime.primary.load_admin_change_plan("plan")
    runtime.primary.save_admin_change_plan(approve_admin_change_plan(plan, "sisko", "2099-01-01T00:00:00+00:00"))
    bridge_changes = runtime.bridge.store.connection.total_changes
    result = record_process_observation(round_id="round", plan_id="plan")
    assert result["recorded"] is True
    assert runtime.primary.process_observation("round")["planId"] == "plan"
    assert runtime.collector.revalidate_calls == 0
    assert runtime.bridge.store.connection.total_changes == bridge_changes
    assert runtime.bridge.store.connection.execute("SELECT name FROM sqlite_master WHERE name='psychlo_process_observations'").fetchone() is None
    runtime.bridge.store.close(); runtime.primary.close()


def test_record_uses_immutable_prepared_snapshot_without_live_recollection(tmp_path, monkeypatch):
    runtime, value = _runtime(tmp_path, monkeypatch)
    clock_values = iter(("2099-01-01T00:00:02+00:00", "2099-01-01T00:00:03+00:00"))
    runtime.bridge.clock = lambda: next(clock_values)
    stage_process_observation(round_id="round", plan_id="plan")
    plan = runtime.primary.load_admin_change_plan("plan")
    runtime.primary.save_admin_change_plan(approve_admin_change_plan(plan, "sisko", "2099-01-01T00:00:02+00:00"))
    runtime.collector.collect = lambda *_args: (_ for _ in ()).throw(AssertionError("record must not recollect live state"))
    result = record_process_observation(round_id="round", plan_id="plan")
    assert result["recorded"] is True
    row = runtime.primary.process_observation("round")
    assert row["manifest"]["observedWindowStart"] == value["observedWindowStart"]
    assert row["manifest"]["observedWindowEnd"] == value["observedWindowEnd"]
    assert row["recordedAt"] == "2099-01-01T00:00:03+00:00"
    runtime.bridge.store.close(); runtime.primary.close()


def test_record_does_not_report_success_when_postcommit_primary_revalidation_fails(tmp_path, monkeypatch):
    runtime, _value = _runtime(tmp_path, monkeypatch)
    stage_process_observation(round_id="round", plan_id="plan")
    plan = runtime.primary.load_admin_change_plan("plan")
    runtime.primary.save_admin_change_plan(approve_admin_change_plan(plan, "sisko", "2099-01-01T00:00:02+00:00"))
    monkeypatch.setattr(
        "overseer.psychlo_process_attestation._revalidate_primary_database_after_commit",
        lambda _runtime, **_kwargs: (_ for _ in ()).throw(Exception("canonical primary path changed after commit")),
    )
    with pytest.raises(Exception, match="canonical primary path changed"):
        record_process_observation(round_id="round", plan_id="plan")
    # The historical row is committed on its bound inode; retry can reconcile
    # it once the canonical path is restored, but the failed call did not lie.
    assert runtime.primary.process_observation("round")["planId"] == "plan"
    monkeypatch.setattr("overseer.psychlo_process_attestation._revalidate_primary_database_after_commit", lambda _runtime, **_kwargs: None)
    replay = record_process_observation(round_id="round", plan_id="plan")
    assert replay["recorded"] is True and replay["recordedAt"] == "2099-01-01T00:00:00+00:00"
    runtime.bridge.store.close(); runtime.primary.close()


def test_stage_does_not_report_success_when_postcommit_primary_revalidation_fails(tmp_path, monkeypatch):
    runtime, _value = _runtime(tmp_path, monkeypatch)
    monkeypatch.setattr(
        "overseer.psychlo_process_attestation._revalidate_primary_database_after_commit",
        lambda _runtime, **_kwargs: (_ for _ in ()).throw(Exception("canonical primary path changed after stage commit")),
    )
    with pytest.raises(Exception, match="canonical primary path changed after stage commit"):
        stage_process_observation(round_id="round", plan_id="plan")
    assert runtime.primary._connection.execute("SELECT state FROM psychlo_process_observations").fetchone()[0] == "prepared"
    runtime.bridge.store.close(); runtime.primary.close()


def test_postcommit_revalidation_rejects_canonical_primary_swap_after_connection_check(tmp_path, monkeypatch):
    import overseer.psychlo_process_attestation as module

    canonical = tmp_path / "primary.sqlite3"
    decoy = tmp_path / "decoy.sqlite3"
    store = SQLiteStore(canonical)
    SQLiteStore(decoy).close()
    fd = os.open(canonical, os.O_RDWR | os.O_NOFOLLOW)
    metadata = os.fstat(fd)
    runtime = SimpleNamespace(primary=store, primary_fd=fd,
                              primary_identity=(metadata.st_dev, metadata.st_ino, metadata.st_nlink))
    module._register_verified_connection(store._connection, fd)
    monkeypatch.setattr(module, "CANONICAL_PRIMARY_DATABASE", canonical)
    original = module._revalidate_sqlite_database
    def swap_after_connection_check(*args, **kwargs):
        original(*args, **kwargs)
        os.replace(canonical, tmp_path / "bound.sqlite3")
        os.replace(decoy, canonical)
    monkeypatch.setattr(module, "_revalidate_sqlite_database", swap_after_connection_check)
    try:
        with pytest.raises(module.ProcessAttestationError, match="canonical primary path changed"):
            module._revalidate_primary_database_after_commit(runtime)
    finally:
        module._forget_verified_connection(store._connection)
        os.close(fd)
        store._connection.close()


def test_primary_attestation_transition_is_immutable(tmp_path):
    primary = SQLiteStore(tmp_path / "primary.sqlite3")
    primary._connection.execute("INSERT INTO psychlo_process_observations VALUES ('a','r','p','" + "a" * 64 + "','', 'prepared','{}','now',NULL)")
    try:
        primary._connection.execute("UPDATE psychlo_process_observations SET manifest_json='{" + "x" + "}' WHERE round_id='r'")
    except Exception as error:
        assert "immutable" in str(error)
    else:
        raise AssertionError("prepared attestation identity was mutable")
    primary._connection.execute("UPDATE psychlo_process_observations SET plan_digest='" + "b" * 64 + "',state='recorded',recorded_at='done' WHERE round_id='r'")
    assert primary.process_observation("r")["planDigest"] == "b" * 64
    primary.close()


def test_public_operations_have_no_caller_selected_authority_endpoints():
    assert set(inspect.signature(stage_process_observation).parameters) == {"round_id", "plan_id"}
    assert set(inspect.signature(record_process_observation).parameters) == {"round_id", "plan_id"}


def test_observation_window_is_collection_window_and_recorded_at_is_store_envelope():
    import overseer.psychlo_process_attestation as module

    value = _manifest()
    value["observedWindowStart"] = "2099-01-01T00:00:00.500000+00:00"
    value["observedWindowEnd"] = "2099-01-01T00:00:01+00:00"
    checked = module._manifest(value, "round")
    assert checked["observedWindowStart"] != checked["startedAt"]
    assert "recordedAt" not in checked


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


def test_sqlite_binding_rejects_decoy_connection_after_canonical_path_restore(tmp_path):
    import overseer.psychlo_process_attestation as module

    canonical = tmp_path / "canonical.sqlite3"
    decoy = tmp_path / "decoy.sqlite3"
    original = SQLiteStore(canonical)
    original.close()
    decoy_store_init = SQLiteStore(decoy)
    decoy_store_init.close()
    expected = canonical.stat()
    os.replace(canonical, tmp_path / "original.sqlite3")
    os.replace(decoy, canonical)
    decoy_store = SQLiteStore(canonical)
    os.unlink(canonical)
    os.replace(tmp_path / "original.sqlite3", canonical)
    try:
        with pytest.raises(module.ProcessAttestationError, match="backing|canonical inode"):
            module._bind_sqlite_database(decoy_store._connection, canonical, (expected.st_dev, expected.st_ino), "primary")
    finally:
        try:
            decoy_store.close()
        except ValueError:
            decoy_store._connection.close()


def test_sqlite_binding_rejects_cover_fd_not_bound_to_connection(tmp_path):
    """A canonical cover descriptor must not bless a decoy SQLite connection."""
    import overseer.psychlo_process_attestation as module

    canonical = tmp_path / "canonical.sqlite3"
    decoy = tmp_path / "decoy.sqlite3"
    canonical_store = SQLiteStore(canonical)
    canonical_store.close()
    decoy_store = SQLiteStore(decoy)
    decoy_store.close()
    expected = canonical.stat()
    os.replace(canonical, tmp_path / "original.sqlite3")
    os.replace(decoy, canonical)
    decoy_connection = SQLiteStore(canonical)
    os.unlink(canonical)
    os.replace(tmp_path / "original.sqlite3", canonical)
    cover_fd = os.open(canonical, os.O_RDWR | os.O_NOFOLLOW)
    try:
        with pytest.raises(module.ProcessAttestationError, match="connection was not opened"):
            module._bind_sqlite_database(
                decoy_connection._connection, canonical,
                (expected.st_dev, expected.st_ino), "primary", bound_fd=cover_fd,
            )
    finally:
        os.close(cover_fd)
        module._forget_verified_connection(decoy_connection._connection)
        try:
            decoy_connection.close()
        except ValueError:
            decoy_connection._connection.close()


def test_historical_observation_contract_has_no_action_consumer():
    import pathlib
    import overseer.psychlo_process_attestation as module

    value = _manifest()
    assert module._manifest(value, "round")["historical"] is True
    assert module._manifest(value, "round")["authoritative"] is False
    assert module._manifest(value, "round")["executable"] is False
    source = pathlib.Path(module.__file__).read_text()
    for forbidden in ("tmux send-keys", "kill-session", "os.kill(", "send_keys("):
        assert forbidden not in source
    assert "fresh-live" in source


def test_live_wrapper_binding_uses_actual_documents_path():
    import overseer.psychlo_process_attestation as module

    assert module.CANONICAL_CODEX_MEMORY_SESSION_SCRIPT == __import__("pathlib").Path(
        "/home/god/Documents/Private AI Memory Storage System/scripts/codex-session-with-memory.sh"
    )


def _two_hop_chain_fixture(tmp_path):
    import overseer.psychlo_process_attestation as module

    docs = tmp_path / "memory"; scripts = docs / "scripts"; scripts.mkdir(parents=True)
    wrapper = scripts / "codex-session-with-memory.sh"
    wrapper.write_text("#!/usr/bin/env bash\nexec /usr/bin/codex \"$@\"\n")
    wrapper.chmod(0o775)
    trampoline = tmp_path / "skill-trampoline.sh"
    trampoline.write_text(
        "#!/usr/bin/env bash\nset -euo pipefail\n\n"
        f'project_root="${{MEMORY_VAULT_PROJECT:-{docs}}}"\n'
        'exec "${project_root}/scripts/codex-session-with-memory.sh" "$@"\n'
    )
    trampoline.chmod(0o775)
    memory_session = tmp_path / "codex-memory-session"
    memory_session.symlink_to(trampoline)
    launcher = tmp_path / "codex-arcade"
    launcher.write_text(f"#!/usr/bin/env bash\nexec {memory_session} resume conversation --cd '{docs}'\n")
    launcher.chmod(0o755)
    process_binding = {
        "launcher": str(launcher),
        "launcherDigest": hashlib.sha256(launcher.read_bytes()).hexdigest(),
        "conversationId": "conversation",
        "workspace": str(docs),
    }
    return module, docs, wrapper, trampoline, memory_session, launcher, process_binding


def test_live_two_hop_trampoline_chain_is_hashed_and_bound_to_pane_argv(tmp_path, monkeypatch):
    module, docs, wrapper, trampoline, memory_session, launcher, binding = _two_hop_chain_fixture(tmp_path)
    monkeypatch.setattr(module, "CANONICAL_CODEX_MEMORY_SESSION", str(memory_session))
    monkeypatch.setattr(module, "CANONICAL_CODEX_MEMORY_SESSION_TRAMPOLINE", trampoline)
    monkeypatch.setattr(module, "CANONICAL_CODEX_MEMORY_SESSION_SCRIPT", wrapper)
    monkeypatch.setattr(module, "_read_proc_bytes", lambda path: (
        b"bash\0" + str(wrapper).encode() + b"\0resume\0conversation\0--cd\0" + str(docs).encode() + b"\0"
        if str(path).endswith("/cmdline") else b"MEMORY_VAULT_PROJECT=" + str(docs).encode() + b"\0"
    ))
    chain = module._capture_launcher_chain(77, binding)
    assert chain["launcher"]["digest"] == binding["launcherDigest"]
    assert chain["memorySession"]["target"] == str(trampoline)
    assert chain["trampoline"]["digest"] == hashlib.sha256(trampoline.read_bytes()).hexdigest()
    assert chain["wrapper"]["path"] == str(wrapper)


def test_live_trampoline_rejects_replace_target_and_environment_override(tmp_path, monkeypatch):
    module, docs, wrapper, trampoline, memory_session, _launcher, binding = _two_hop_chain_fixture(tmp_path)
    monkeypatch.setattr(module, "CANONICAL_CODEX_MEMORY_SESSION", str(memory_session))
    monkeypatch.setattr(module, "CANONICAL_CODEX_MEMORY_SESSION_TRAMPOLINE", trampoline)
    monkeypatch.setattr(module, "CANONICAL_CODEX_MEMORY_SESSION_SCRIPT", wrapper)
    monkeypatch.setattr(module, "_read_proc_bytes", lambda path: (
        b"bash\0" + str(wrapper).encode() + b"\0resume\0conversation\0--cd\0" + str(docs).encode() + b"\0"
        if str(path).endswith("/cmdline") else b"MEMORY_VAULT_PROJECT=/tmp\0"
    ))
    with pytest.raises(module.ProcessAttestationError, match="environment override"):
        module._capture_launcher_chain(77, binding)
    trampoline.write_text(trampoline.read_text().replace(str(docs), "/tmp"))
    monkeypatch.setattr(module, "_read_proc_bytes", lambda path: (
        b"bash\0" + str(wrapper).encode() + b"\0resume\0conversation\0--cd\0" + str(docs).encode() + b"\0"
        if str(path).endswith("/cmdline") else b"MEMORY_VAULT_PROJECT=" + str(docs).encode() + b"\0"
    ))
    with pytest.raises(module.ProcessAttestationError, match="trampoline"):
        module._capture_launcher_chain(77, binding)


def test_process_cli_rejects_endpoint_arguments():
    from overseer.psychlo_bridge_cli import build_parser

    try:
        build_parser().parse_args(("stage-process-attestation", "--round-id", "r", "--plan-id", "p", "--manifest-path", "/tmp/operator.json"))
    except SystemExit as error:
        assert error.code != 0
    else:
        raise AssertionError("caller-selected manifest endpoint was accepted")


def test_release_selection_binds_the_actual_child_when_many_releases_exist(tmp_path, monkeypatch):
    import overseer.psychlo_process_attestation as module

    releases = tmp_path / "releases"
    first = releases / "one" / "bin"; second = releases / "two" / "bin"
    first.mkdir(parents=True); second.mkdir(parents=True)
    (first / "codex").write_bytes(b"first"); (second / "codex").write_bytes(b"second")
    (first / "codex").chmod(0o755); (second / "codex").chmod(0o755)
    monkeypatch.setattr(module, "CANONICAL_CODEX_RELEASES", releases)
    monkeypatch.setattr(module.os, "readlink", lambda path: str(second / "codex") if str(path) == "/proc/77/exe" else (_ for _ in ()).throw(OSError("unexpected read")))
    path, dev, ino, digest = module._trusted_codex_executable(77)
    assert path == str(second / "codex")
    assert (dev, ino) == ((second / "codex").stat().st_dev, (second / "codex").stat().st_ino)
    assert digest


def test_release_selection_rejects_symlinked_child_path(tmp_path, monkeypatch):
    import overseer.psychlo_process_attestation as module

    releases = tmp_path / "releases"; real = tmp_path / "real"
    (releases / "one" / "bin").mkdir(parents=True); real.write_bytes(b"codex"); real.chmod(0o755)
    (releases / "one" / "bin" / "codex").symlink_to(real)
    monkeypatch.setattr(module, "CANONICAL_CODEX_RELEASES", releases)
    monkeypatch.setattr(module.os, "readlink", lambda path: str(releases / "one" / "bin" / "codex"))
    with pytest.raises(module.ProcessAttestationError, match="symlink"):
        module._trusted_codex_executable(77)


def test_canonical_source_symlink_must_resolve_to_reviewed_checkout(tmp_path, monkeypatch):
    import overseer.psychlo_process_attestation as module

    expected = tmp_path / "reviewed"; expected.mkdir()
    link = tmp_path / "source"; link.symlink_to(expected, target_is_directory=True)
    monkeypatch.setattr(module, "CANONICAL_SOURCE_ROOT", link)
    monkeypatch.setattr(module, "CANONICAL_SOURCE_REAL_ROOT", expected)
    assert module._resolve_canonical_source_root() == expected
    other = tmp_path / "other"; other.mkdir()
    monkeypatch.setattr(module, "CANONICAL_SOURCE_REAL_ROOT", other)
    with pytest.raises(module.ProcessAttestationError, match="reviewed checkout"):
        module._resolve_canonical_source_root()


def test_workspace_private_primary_group_policy_allows_0775_only_for_private_group(tmp_path, monkeypatch):
    import overseer.psychlo_process_attestation as module

    workspace = tmp_path / "arcade"; workspace.mkdir(mode=0o775)
    metadata = workspace.stat()
    monkeypatch.setattr(module, "_private_group_is_safe", lambda gid: gid == metadata.st_gid)
    assert module._private_workspace_mode(metadata) is True
    monkeypatch.setattr(module, "_private_group_is_safe", lambda _gid: False)
    assert module._private_workspace_mode(metadata) is False


def test_tmux_scan_binds_pane_by_start_chain_not_launcher_name(monkeypatch, tmp_path):
    import overseer.psychlo_process_attestation as module

    socket_path = tmp_path / "tmux.sock"
    expected = "/home/god/.local/bin/codex-memory-session resume conversation-arcade --cd '/home/god/Documents/Codex Workspace/Arcade'"
    rows = "$1|@1|%1|101|bash|/home/god/.local/bin/codex-memory-session resume conversation-other --cd '/tmp/Other'\n$2|@2|%2|102|bash|/home/god/.local/bin/codex-memory-session resume conversation-arcade --cd \"/home/god/Documents/Codex Workspace/Arcade\"\n"
    class Result:
        returncode = 0
        def __init__(self, stdout): self.stdout = stdout
    monkeypatch.setattr(module, "capture_socket_identity", lambda _path: {"dev": 1, "ino": 2, "mode": 0o770, "uid": os.getuid()})
    monkeypatch.setattr(module.subprocess, "run", lambda command, **_kwargs: Result("$1|11\n$2|12\n") if "list-sessions" in command else Result(rows))
    identity = {"pid": 12, "startTicks": 1, "exeDigest": "a" * 64, "argvDigest": "b" * 64, "cgroupDigest": "c" * 64, "pidfdSupported": True}
    monkeypatch.setattr(module, "capture_process_identity", lambda pid: {**identity, "pid": pid})
    monkeypatch.setattr(module, "_proc_parent_pid", lambda _pid: 11)
    result = module.capture_tmux_identity(str(socket_path), "", expected_start_command=expected)
    assert (result["sessionId"], result["paneId"]) == ("$2", "%2")


def test_corrupt_completed_replay_is_rejected_before_live_collection(tmp_path, monkeypatch):
    import overseer.psychlo_process_attestation as module

    primary_path = tmp_path / "primary.sqlite3"
    primary = SQLiteStore(primary_path)
    primary._connection.execute("INSERT INTO psychlo_process_observations VALUES ('a','round','plan','" + "b" * 64 + "','" + "c" * 64 + "','recorded','{}','inserted','completed')")
    primary._connection.commit()
    primary.close()
    monkeypatch.setattr(module, "CANONICAL_PRIMARY_DATABASE", primary_path)
    monkeypatch.setattr(module, "_assert_runtime_source_integrity", lambda: None)
    monkeypatch.setattr(module, "capture_process_identity", lambda _pid: (_ for _ in ()).throw(AssertionError("exited process must not be recollected")))
    monkeypatch.setattr(module, "_open_runtime_authority", lambda _round: (_ for _ in ()).throw(AssertionError("runtime must not open on completed replay")))
    with pytest.raises(module.ProcessAttestationError, match="manifest|timestamp|plan"):
        module.record_process_observation(round_id="round", plan_id="plan")


def test_record_uses_primary_only_when_live_runtime_has_vanished(tmp_path, monkeypatch):
    module = __import__("overseer.psychlo_process_attestation", fromlist=["module"])
    runtime, _value = _runtime(tmp_path, monkeypatch)
    stage_process_observation(round_id="round", plan_id="plan")
    plan = runtime.primary.load_admin_change_plan("plan")
    runtime.primary.save_admin_change_plan(approve_admin_change_plan(plan, "sisko", "2099-01-01T00:00:02+00:00"))
    monkeypatch.setattr(module, "_open_runtime_authority", lambda _round: (_ for _ in ()).throw(AssertionError("vanished runtime must not open")))
    monkeypatch.setattr(module, "_assert_runtime_source_integrity", lambda: (_ for _ in ()).throw(AssertionError("record must not read source")))
    result = record_process_observation(round_id="round", plan_id="plan")
    assert result["recorded"] is True and result["authoritative"] is False


def test_stage_reconciles_prepared_snapshot_before_runtime_or_clock(tmp_path, monkeypatch):
    import overseer.psychlo_process_attestation as module

    runtime, _value = _runtime(tmp_path, monkeypatch)
    first = stage_process_observation(round_id="round", plan_id="plan")
    collect_calls = runtime.collector.collect_calls
    monkeypatch.setattr(module, "_open_runtime_authority", lambda _round: (_ for _ in ()).throw(AssertionError("stage replay must not open runtime")))
    monkeypatch.setattr(module, "_assert_runtime_source_integrity", lambda: (_ for _ in ()).throw(AssertionError("stage replay must not read source")))
    replay = stage_process_observation(round_id="round", plan_id="plan")
    assert replay["replayed"] is True
    assert replay["observationDigest"] == first["observationDigest"]
    assert runtime.collector.collect_calls == collect_calls


def test_finalize_reports_approved_prepared_without_claiming_recorded(tmp_path, monkeypatch):
    from overseer.psychlo_process_attestation import finalize_process_observation

    runtime, _value = _runtime(tmp_path, monkeypatch)
    stage_process_observation(round_id="round", plan_id="plan")
    plan = runtime.primary.load_admin_change_plan("plan")
    runtime.primary.save_admin_change_plan(approve_admin_change_plan(plan, "sisko", "2099-01-01T00:00:02+00:00"))
    result = finalize_process_observation(plan_id="plan")
    assert result["approved"] is True and result["prepared"] is True
    assert result["recorded"] is False and result["finalized"] is False
    assert result["status"] == "approved-prepared"


def test_postcommit_missing_wal_shm_requires_exact_readonly_visibility(tmp_path, monkeypatch):
    import overseer.psychlo_process_attestation as module

    primary_path = tmp_path / "primary.sqlite3"
    primary = SQLiteStore(primary_path)
    value = _manifest()
    plan = module.plan_psychlo_legacy_process_observation(
        "plan", "round", module.manifest_digest(value), value["source"]["commit"],
        value["source"]["treeDigest"], value["source"]["moduleDigest"],
    )
    from overseer.store import _dump
    primary._connection.execute("INSERT INTO admin_change_plans(id,payload) VALUES (?,?)", ("plan", _dump(plan)))
    primary._connection.execute("INSERT INTO psychlo_process_observations VALUES ('a','round','plan',?,?, 'prepared',?,?,NULL)", (module.manifest_digest(value), "", json.dumps(value, sort_keys=True, separators=(",", ":")), "2099-01-01T00:00:01+00:00"))
    primary._connection.commit()
    primary._connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    fd = os.open(primary_path, os.O_RDWR | os.O_NOFOLLOW)
    metadata = os.fstat(fd)
    sidecar_wal = tmp_path / "primary.sqlite3-wal"
    sidecar_shm = tmp_path / "primary.sqlite3-shm"
    sidecar_wal.write_bytes(b"wal")
    sidecar_shm.write_bytes(b"shm")
    runtime = SimpleNamespace(
        primary=primary, primary_fd=fd,
        primary_identity=(metadata.st_dev, metadata.st_ino),
    )
    module._register_verified_connection(primary._connection, fd)
    monkeypatch.setattr(module, "CANONICAL_PRIMARY_DATABASE", primary_path)
    runtime.primary._sidecar_identities = {
        "-wal": (sidecar_wal.stat().st_dev, sidecar_wal.stat().st_ino),
        "-shm": (sidecar_shm.stat().st_dev, sidecar_shm.stat().st_ino),
    }
    sidecar_wal.unlink(); sidecar_shm.unlink()
    try:
        module._revalidate_primary_database_after_commit(
            runtime, round_id="round", plan_id="plan", state="prepared",
            observation_digest=module.manifest_digest(value), plan_digest="",
        )
    finally:
        module._forget_verified_connection(primary._connection)
        os.close(fd)
        primary._connection.close()


def test_postcommit_missing_wal_shm_fails_when_exact_row_is_not_visible(tmp_path, monkeypatch):
    import overseer.psychlo_process_attestation as module

    primary_path = tmp_path / "primary.sqlite3"
    primary = SQLiteStore(primary_path)
    fd = os.open(primary_path, os.O_RDWR | os.O_NOFOLLOW)
    metadata = os.fstat(fd)
    runtime = SimpleNamespace(primary=primary, primary_fd=fd, primary_identity=(metadata.st_dev, metadata.st_ino), primary_sidecars={})
    module._register_verified_connection(primary._connection, fd)
    monkeypatch.setattr(module, "CANONICAL_PRIMARY_DATABASE", primary_path)
    try:
        with pytest.raises(module.ProcessAttestationError, match="not visible"):
            module._revalidate_primary_database_after_commit(
                runtime, round_id="round", plan_id="plan", state="prepared",
                observation_digest="b" * 64, plan_digest="",
            )
    finally:
        module._forget_verified_connection(primary._connection)
        os.close(fd)
        primary._connection.close()


def test_strict_replay_validator_rejects_full_row_manifest_mismatch(tmp_path, monkeypatch):
    import overseer.psychlo_process_attestation as module

    runtime, _value = _runtime(tmp_path, monkeypatch)
    stage_process_observation(round_id="round", plan_id="plan")
    row = runtime.primary._connection.execute(
        "SELECT observation_id,round_id,plan_id,observation_digest,plan_digest,state,manifest_json,inserted_at,recorded_at "
        "FROM psychlo_process_observations WHERE round_id='round'"
    ).fetchone()
    corrupted = list(row)
    corrupted[6] = json.dumps({})
    with pytest.raises(module.ProcessAttestationError, match="manifest"):
        module._validate_process_observation_row(
            runtime.primary, tuple(corrupted), round_id="round", plan_id="plan",
        )
    corrupted = list(row)
    corrupted[4] = "d" * 64
    with pytest.raises(module.ProcessAttestationError, match="prepared process observation recording fields"):
        module._validate_process_observation_row(
            runtime.primary, tuple(corrupted), round_id="round", plan_id="plan",
        )
    runtime.bridge.store.close(); runtime.primary.close()


def test_readonly_connection_rejects_close_reuse_decoy_fd(tmp_path, monkeypatch):
    import overseer.psychlo_process_attestation as module

    canonical = tmp_path / "canonical.sqlite3"
    decoy = tmp_path / "decoy.sqlite3"
    canonical_store = SQLiteStore(canonical)
    canonical_store.close()
    decoy_store = SQLiteStore(decoy)
    decoy_store.close()
    expected = canonical.stat()
    original_bind = module._bind_sqlite_database

    def close_and_reuse(connection, path, identity, label, *, bound_fd=None):
        if bound_fd is not None:
            os.close(bound_fd)
            replacement = os.open(decoy, os.O_RDONLY | os.O_NOFOLLOW)
            assert replacement == bound_fd
        return original_bind(connection, path, identity, label, bound_fd=bound_fd)

    monkeypatch.setattr(module, "_bind_sqlite_database", close_and_reuse)
    with pytest.raises(module.ProcessAttestationError, match="bound database handle changed|bad file descriptor|canonical inode"):
        module._open_verified_readonly_connection(
            canonical, (expected.st_dev, expected.st_ino, expected.st_nlink),
        )
