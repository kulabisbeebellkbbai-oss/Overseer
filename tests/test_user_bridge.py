from __future__ import annotations

import json
import os
import sqlite3
import socket
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from overseer.user_bridge import (
    BRIDGE_PROTOCOL,
    DEFAULT_OVERSEER_UID,
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    UserBridgeClient,
    UserBridgePeerError,
    UserBridgeResponseError,
    UserBridgeTimeoutError,
    UserBridgeUnavailableError,
    UserBridge,
    UserBridgeProtocolError,
    client_from_environment,
    create_default_bridge,
    main,
    peer_credentials,
)
from overseer.user_bridge_providers import (
    DEFAULT_CODEX_REGISTRY_PATH,
    DEFAULT_CODEX_USAGE_DB_PATH,
    MAX_SOURCE_BYTES,
    CodexSessionProjectionProvider,
    CodexUsageProjectionProvider,
    OverseerGitStatusProjectionProvider,
    UserServiceFreshnessProjectionProvider,
)


def request(request_id: str, method: str, params: dict | None = None) -> bytes:
    return json.dumps(
        {
            "protocol": BRIDGE_PROTOCOL,
            "request_id": request_id,
            "method": method,
            "params": {} if params is None else params,
        },
        separators=(",", ":"),
    ).encode("utf-8")


def decode(response: bytes) -> dict:
    return json.loads(response)


def test_valid_session_projection_is_allowlisted_and_bounded() -> None:
    calls = 0

    def sessions() -> dict:
        nonlocal calls
        calls += 1
        return {
            "state": "available",
            "observed_at": "2026-08-26T12:00:00+00:00",
            "sessions": [
                {
                    "session_id": "session-1",
                    "project_id": "overseer",
                    "status": "active",
                    "last_seen_at": "2026-08-26T11:59:00+00:00",
                    "path": "/home/god/private-project",
                    "prompt": "do not disclose this",
                    "environment": {"TOKEN": "secret"},
                    "tmux_target": "overseer:0",
                }
            ],
        }

    bridge = UserBridge(allowed_peer_uid=4242, sessions_provider=sessions)
    response = decode(bridge.handle_bytes(request("req-1", "codex.sessions.list.v1"), peer_uid=4242))

    assert response["status"] == "ok"
    assert response["method"] == "codex.sessions.list.v1"
    assert response["projection"] == {
        "state": "available",
        "observed_at": "2026-08-26T12:00:00+00:00",
        "sessions": [
            {
                "session_id": "session-1",
                "project_id": "overseer",
                "status": "active",
                "last_seen_at": "2026-08-26T11:59:00+00:00",
            }
        ],
    }
    assert calls == 1
    assert len(json.dumps(response).encode()) <= MAX_RESPONSE_BYTES


def test_valid_usage_projection_is_allowlisted() -> None:
    bridge = UserBridge(
        allowed_peer_uid=4242,
        usage_provider=lambda: {
            "state": "available",
            "observed_at": "2026-08-26T12:00:00+00:00",
            "windows": [
                {
                    "name": "weekly",
                    "used": 12,
                    "remaining": 88,
                    "reset_at": "2026-09-01T00:00:00+00:00",
                    "account_token": "must-not-cross-boundary",
                }
            ],
            "account": "private@example.invalid",
        },
    )

    response = decode(bridge.handle_bytes(request("req-usage", "codex.usage.snapshot.v1"), peer_uid=4242))

    assert response["projection"] == {
        "state": "available",
        "observed_at": "2026-08-26T12:00:00+00:00",
        "windows": [
            {
                "name": "weekly",
                "used": 12,
                "remaining": 88,
                "reset_at": "2026-09-01T00:00:00+00:00",
            }
        ],
    }


def test_fixed_collection_projections_are_allowlisted_and_redacted() -> None:
    bridge = UserBridge(
        allowed_peer_uid=4242,
        freshness_provider=lambda: {
            "state": "available",
            "observed_at": "2026-09-06T12:00:00+00:00",
            "services": [
                {
                    "job_id": "collection.freshness.psychlo-usage",
                    "outcome": "succeeded",
                    "evidence_id": "freshness.psychlo-usage",
                    "unit": "private.service",
                    "argv": ["systemctl", "restart"],
                },
                {
                    "job_id": "collection.freshness.quark-scheduler",
                    "outcome": "failed",
                    "failure_category": "stale",
                    "private_error": "/home/god/private",
                },
            ],
        },
        git_provider=lambda: {
            "state": "available",
            "observed_at": "2026-09-06T12:00:00+00:00",
            "git": {
                "repository": "overseer",
                "branch": "feature/maintenance-window-v1-1-6",
                "head": "a" * 40,
                "short_head": "a" * 7,
                "upstream": "origin/feature/maintenance-window-v1-1-6",
                "ahead": 1,
                "behind": 0,
                "dirty": True,
                "changed": 1,
                "staged": 0,
                "unstaged": 1,
                "untracked": 0,
                "conflicted": 0,
                "remote_owner": "example",
                "remote_repo": "overseer",
                "repo_path": "/home/god/Documents/Codex Workspace/Overseer",
                "remote_url": "https://token@example.invalid/private.git",
                "status_lines": ["private-file"],
            },
        },
    )

    freshness = decode(
        bridge.handle_bytes(
            request("req-freshness", "overseer.scheduler.freshness.v1"),
            peer_uid=4242,
        )
    )["projection"]
    git = decode(
        bridge.handle_bytes(
            request("req-git", "overseer.git.status.v1"),
            peer_uid=4242,
        )
    )["projection"]

    assert freshness == {
        "state": "available",
        "observed_at": "2026-09-06T12:00:00+00:00",
        "services": [
            {
                "job_id": "collection.freshness.psychlo-usage",
                "outcome": "succeeded",
                "evidence_id": "freshness.psychlo-usage",
            },
            {
                "job_id": "collection.freshness.quark-scheduler",
                "outcome": "failed",
                "failure_category": "stale",
            },
        ],
    }
    assert git["git"] == {
        "repository": "overseer",
        "branch": "feature/maintenance-window-v1-1-6",
        "head": "a" * 40,
        "short_head": "a" * 7,
        "upstream": "origin/feature/maintenance-window-v1-1-6",
        "ahead": 1,
        "behind": 0,
        "dirty": True,
        "changed": 1,
        "staged": 0,
        "unstaged": 1,
        "untracked": 0,
        "conflicted": 0,
        "remote_owner": "example",
        "remote_repo": "overseer",
    }
    assert "/home/god" not in json.dumps([freshness, git])
    assert "token" not in json.dumps(git)


def test_bridge_client_separates_socket_owner_from_connected_server_uid(
    tmp_path: Path,
) -> None:
    path = tmp_path / "bridge.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(path))
        path.chmod(0o600)
        client = UserBridgeClient(
            path,
            expected_server_uid=os.getuid() + 10000,
            expected_socket_uid=os.getuid(),
        )
        metadata = client._socket_metadata()
        client._verify_socket_metadata(metadata)
    finally:
        listener.close()


def test_collection_projection_providers_use_only_fixed_inputs(tmp_path: Path) -> None:
    calls: list[tuple[tuple[str, ...], float]] = []

    def systemd_runner(command: tuple[str, ...], timeout: float):
        calls.append((command, timeout))
        if command[-1].endswith(".timer"):
            stdout = (
                "ActiveState=active\nSubState=waiting\nResult=success\n"
                "LastTriggerUSec=2026-09-06 12:00:00 UTC\n"
                "NextElapseUSecMonotonic=1min\n"
            )
        else:
            stdout = "ActiveState=inactive\nSubState=dead\nResult=success\n"
        return subprocess.CompletedProcess(command, 0, stdout, "")

    freshness = UserServiceFreshnessProjectionProvider(
        runner=systemd_runner,
        clock=lambda: datetime(2026, 9, 6, 12, 1, tzinfo=UTC),
    ).snapshot()

    git = OverseerGitStatusProjectionProvider(
        repo_path=tmp_path,
        status_reader=lambda path, **kwargs: {
            "repo_path": str(path),
            "branch": "main",
            "head": "b" * 40,
            "short_head": "b" * 7,
            "upstream": "origin/main",
            "ahead": 0,
            "behind": 0,
            "dirty": False,
            "changed": 0,
            "staged": 0,
            "unstaged": 0,
            "untracked": 0,
            "conflicted": 0,
            "remote": {"owner": "example", "repo": "overseer", "url": "private"},
        },
        clock=lambda: datetime(2026, 9, 6, 12, 1, tzinfo=UTC),
    ).snapshot()

    assert freshness["state"] == "available"
    assert [item["outcome"] for item in freshness["services"]] == [
        "succeeded",
        "succeeded",
    ]
    assert len(calls) == 4
    assert all(command[0] == "/usr/bin/systemctl" for command, _timeout in calls)
    assert git == {
        "state": "available",
        "observed_at": "2026-09-06T12:01:00+00:00",
        "git": {
            "repository": "overseer",
            "branch": "main",
            "head": "b" * 40,
            "short_head": "b" * 7,
            "upstream": "origin/main",
            "ahead": 0,
            "behind": 0,
            "dirty": False,
            "changed": 0,
            "staged": 0,
            "unstaged": 0,
            "untracked": 0,
            "conflicted": 0,
            "remote_owner": "example",
            "remote_repo": "overseer",
        },
    }


def test_bridge_git_runner_seals_config_environment_and_optional_locks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import overseer.git as git_module

    calls: list[dict[str, object]] = []

    def run(command: tuple[str, ...], **kwargs: object):
        calls.append({"command": command, **kwargs})
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(git_module, "run_bounded", run)

    git_module._bridge_git(tmp_path, "status", "--porcelain=v1", timeout=0.5)

    assert len(calls) == 1
    call = calls[0]
    assert call["command"] == (
        "/usr/bin/git",
        "--no-optional-locks",
        "status",
        "--porcelain=v1",
    )
    assert call["cwd"] == tmp_path
    assert call["max_output_bytes"] == 256 * 1024
    environment = call["env"]
    assert isinstance(environment, dict)
    assert environment == {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_COUNT": "4",
        "GIT_CONFIG_KEY_0": "core.fsmonitor",
        "GIT_CONFIG_VALUE_0": "false",
        "GIT_CONFIG_KEY_1": "core.hooksPath",
        "GIT_CONFIG_VALUE_1": "/dev/null",
        "GIT_CONFIG_KEY_2": "diff.external",
        "GIT_CONFIG_VALUE_2": "",
        "GIT_CONFIG_KEY_3": "credential.helper",
        "GIT_CONFIG_VALUE_3": "",
        "GIT_EXTERNAL_DIFF": "/usr/bin/false",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
    }


def test_default_git_projection_provider_uses_the_sealed_reader(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import overseer.git as git_module

    observed: list[tuple[Path, float]] = []

    def read(path: Path, *, command_timeout_seconds: float) -> dict[str, object]:
        observed.append((path, command_timeout_seconds))
        return {
            "branch": "main",
            "head": "b" * 40,
            "short_head": "b" * 7,
            "upstream": None,
            "ahead": None,
            "behind": None,
            "dirty": False,
            "changed": 0,
            "staged": 0,
            "unstaged": 0,
            "untracked": 0,
            "conflicted": 0,
            "remote": {},
        }

    monkeypatch.setattr(git_module, "bridge_git_status_status", read, raising=False)

    result = OverseerGitStatusProjectionProvider(repo_path=tmp_path).snapshot()

    assert result["state"] == "available"
    assert observed == [(tmp_path, 0.75)]


def test_wrong_peer_is_rejected_before_provider_execution() -> None:
    calls = 0

    def provider() -> dict:
        nonlocal calls
        calls += 1
        return {"state": "available", "sessions": []}

    bridge = UserBridge(allowed_peer_uid=4242, sessions_provider=provider)
    response = decode(bridge.handle_bytes(request("req-peer", "codex.sessions.list.v1"), peer_uid=4243))

    assert response["status"] == "error"
    assert response["error"]["code"] == "peer_not_allowed"
    assert calls == 0


@pytest.mark.parametrize(
    "payload, code",
    [
        (
            {"protocol": BRIDGE_PROTOCOL, "request_id": "req-extra", "method": "codex.sessions.list.v1", "params": {}, "extra": True},
            "unknown_field",
        ),
        (
            {"protocol": BRIDGE_PROTOCOL, "request_id": "req-param", "method": "codex.sessions.list.v1", "params": {"path": "/home/god"}},
            "unknown_field",
        ),
        (
            {"protocol": BRIDGE_PROTOCOL, "request_id": "req-method", "method": "system.restart.v1", "params": {}},
            "unsupported_method",
        ),
        (
            {"protocol": BRIDGE_PROTOCOL, "request_id": "req-mutation", "method": "codex.sessions.list.v1", "params": {"prompt": "run tmux and systemctl"}},
            "unknown_field",
        ),
    ],
)
def test_closed_request_contract_rejects_unknown_fields_and_mutations(payload: dict, code: str) -> None:
    bridge = UserBridge(allowed_peer_uid=4242)

    response = decode(bridge.handle_bytes(json.dumps(payload).encode(), peer_uid=4242))

    assert response["status"] == "error"
    assert response["error"]["code"] == code


def test_oversized_request_is_rejected() -> None:
    bridge = UserBridge(allowed_peer_uid=4242)
    oversized = b"{" + (b"x" * MAX_REQUEST_BYTES) + b"}"

    response = decode(bridge.handle_bytes(oversized, peer_uid=4242))

    assert response["status"] == "error"
    assert response["error"]["code"] == "request_too_large"


def test_request_id_replay_is_idempotent_and_conflicts_are_rejected() -> None:
    calls = 0

    def provider() -> dict:
        nonlocal calls
        calls += 1
        return {"state": "available", "sessions": [{"session_id": f"session-{calls}"}]}

    bridge = UserBridge(allowed_peer_uid=4242, sessions_provider=provider)
    first = request("same-id", "codex.sessions.list.v1")
    first_response = bridge.handle_bytes(first, peer_uid=4242)
    replay_response = bridge.handle_bytes(first, peer_uid=4242)
    conflict = decode(
        bridge.handle_bytes(
            request("same-id", "codex.sessions.list.v1", {"unexpected": "different"}),
            peer_uid=4242,
        )
    )

    assert replay_response == first_response
    assert calls == 1
    assert conflict["status"] == "error"
    assert conflict["error"]["code"] == "request_id_reuse"


@pytest.mark.parametrize(
    "state, extra",
    [
        ("unavailable", {"reason": "provider_disabled"}),
        ("stale", {"stale_at": "2026-08-26T11:00:00+00:00", "sessions": []}),
        ("error", {"error_code": "provider_error"}),
    ],
)
def test_provider_states_are_explicit_and_preserved(state: str, extra: dict) -> None:
    bridge = UserBridge(
        allowed_peer_uid=4242,
        sessions_provider=lambda: {"state": state, **extra},
    )

    response = decode(bridge.handle_bytes(request(f"state-{state}", "codex.sessions.list.v1"), peer_uid=4242))

    assert response["status"] == "ok"
    assert response["projection"]["state"] == state
    for key, value in extra.items():
        assert response["projection"][key] == value


def test_provider_exception_becomes_redacted_error_state() -> None:
    def broken_provider() -> dict:
        raise RuntimeError("secret path /home/god/private and token=abc")

    bridge = UserBridge(allowed_peer_uid=4242, sessions_provider=broken_provider)
    response = decode(bridge.handle_bytes(request("provider-error", "codex.sessions.list.v1"), peer_uid=4242))

    assert response["status"] == "ok"
    assert response["projection"] == {"state": "error", "error_code": "provider_error"}
    assert "/home/god" not in json.dumps(response)
    assert "token" not in json.dumps(response)


def test_slow_provider_times_out_without_leaking_error_details() -> None:
    def slow_provider() -> dict:
        time.sleep(0.2)
        return {"state": "available", "sessions": []}

    bridge = UserBridge(allowed_peer_uid=4242, provider_timeout=0.01, sessions_provider=slow_provider)
    response = decode(bridge.handle_bytes(request("provider-timeout", "codex.sessions.list.v1"), peer_uid=4242))

    assert response["status"] == "ok"
    assert response["projection"] == {"state": "error", "error_code": "provider_timeout"}


def test_projection_lists_are_bounded_and_response_has_a_hard_limit() -> None:
    bridge = UserBridge(
        allowed_peer_uid=4242,
        sessions_provider=lambda: {
            "state": "available",
            "sessions": [
                {
                    "session_id": f"session-{index}",
                    "project_id": "project",
                    "status": "idle",
                    "last_seen_at": "2026-08-26T12:00:00+00:00",
                    "path": "/home/god/should-be-redacted",
                    "secret": "x" * 10000,
                }
                for index in range(200)
            ],
        },
        usage_provider=lambda: {
            "state": "available",
            "windows": [
                {
                    "name": f"window-{index}",
                    "used": index,
                    "remaining": 100,
                    "reset_at": "2026-09-01T00:00:00+00:00",
                    "path": "/home/god/should-be-redacted",
                }
                for index in range(200)
            ],
        },
    )

    session_response = bridge.handle_bytes(request("bounded-sessions", "codex.sessions.list.v1"), peer_uid=4242)
    usage_response = bridge.handle_bytes(request("bounded-usage", "codex.usage.snapshot.v1"), peer_uid=4242)
    sessions = decode(session_response)["projection"]["sessions"]
    windows = decode(usage_response)["projection"]["windows"]

    assert len(sessions) == 64
    assert len(windows) == 8
    assert all(set(item) <= {"session_id", "project_id", "status", "last_seen_at"} for item in sessions)
    assert all(set(item) <= {"name", "used", "remaining", "reset_at"} for item in windows)
    assert len(session_response) <= MAX_RESPONSE_BYTES
    assert len(usage_response) <= MAX_RESPONSE_BYTES
    assert b"/home/god" not in session_response + usage_response


def test_peer_credentials_reads_linux_socket_peer_uid() -> None:
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        credentials = peer_credentials(left)
    finally:
        left.close()
        right.close()

    assert credentials.uid == DEFAULT_OVERSEER_UID or credentials.uid >= 0
    assert credentials.pid > 0
    assert credentials.gid >= 0


def test_invalid_peer_uid_configuration_is_rejected() -> None:
    with pytest.raises(UserBridgeProtocolError, match="peer uid"):
        UserBridge(allowed_peer_uid=-1)


def test_bridge_templates_are_root_socket_activated_and_network_denied() -> None:
    root = Path(__file__).parents[1]
    socket_unit = (root / "systemd/overseer-codex-user-bridge.socket").read_text()
    service_unit = (root / "systemd/overseer-codex-user-bridge.service").read_text()

    assert "ListenStream=/run/overseer/codex-user-bridge.sock" in socket_unit
    assert "SocketUser=@OVERSEER_UID@" in socket_unit
    assert "SocketGroup=0" in socket_unit
    assert "SocketMode=0600" in socket_unit
    assert "User=@GOD_UID@" in service_unit
    assert "Group=@GOD_GID@" in service_unit
    assert (
        "Environment=PYTHONPATH=@OVERSEER_RELEASE@/app/src:"
        "@OVERSEER_RELEASE@/site-packages"
    ) in service_unit
    assert "Environment=PYTHONHOME=@OVERSEER_RELEASE@/runtime" in service_unit
    assert "Environment=LD_LIBRARY_PATH=@OVERSEER_RELEASE@/lib" in service_unit
    assert "Environment=PYTHONNOUSERSITE=1" in service_unit
    assert "Environment=PYTHONSAFEPATH=1" in service_unit
    assert "@OVERSEER_PYTHON@ -s -P -m overseer.user_bridge" in service_unit
    assert "--socket-fd=3" in service_unit
    assert "--peer-uid=@OVERSEER_UID@" in service_unit
    assert "RestrictAddressFamilies=AF_UNIX" in service_unit
    assert "IPAddressDeny=any" in service_unit
    assert "PrivateNetwork=yes" in service_unit
    assert "ProtectHome=tmpfs" in service_unit
    assert "BindReadOnlyPaths=/home/god/.codex/codex-projects.csv" in service_unit
    assert "BindReadOnlyPaths=/home/god/.local/share/overseer/codex-usage-mcp" in service_unit
    assert "systemctl" not in service_unit
    assert "/home/god/.codex/auth.json" not in service_unit
    assert "/home/god/.codex/sessions" not in service_unit


def test_bridge_templates_pass_disposable_systemd_verify(tmp_path: Path) -> None:
    root = Path(__file__).parents[1]
    release = tmp_path / "release"
    (release / "src").mkdir(parents=True)
    replacements = {
        "@OVERSEER_RELEASE@": str(release),
        "@OVERSEER_PYTHON@": sys.executable,
        "@GOD_UID@": "4243",
        "@GOD_GID@": "4244",
        "@OVERSEER_UID@": "4242",
    }
    rendered: list[Path] = []
    for name in ("overseer-codex-user-bridge.socket", "overseer-codex-user-bridge.service"):
        content = (root / "systemd" / name).read_text()
        for placeholder, value in replacements.items():
            content = content.replace(placeholder, value)
        path = tmp_path / name
        path.write_text(content)
        rendered.append(path)

    result = subprocess.run(
        ["systemd-analyze", "verify", *(str(path) for path in rendered)],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr


def _start_one_shot_socket(path: Path, response: bytes, *, delay: float = 0.0) -> tuple[threading.Thread, socket.socket]:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    os.chmod(path, 0o660)
    listener.listen(1)

    def serve() -> None:
        try:
            connection, _ = listener.accept()
            try:
                connection.recv(MAX_REQUEST_BYTES + 1)
                if delay:
                    time.sleep(delay)
                try:
                    connection.sendall(response)
                except OSError:
                    pass
            finally:
                connection.close()
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread, listener


def _start_bridge_socket(path: Path, bridge: UserBridge) -> threading.Thread:
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    os.chmod(path, 0o660)
    listener.listen(1)

    def serve() -> None:
        try:
            connection, _ = listener.accept()
            bridge._serve_connection(connection)
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread


def test_client_validates_socket_metadata_and_peer_credentials_bidirectionally(tmp_path: Path) -> None:
    path = tmp_path / "bridge.sock"
    bridge = UserBridge(
        allowed_peer_uid=os.getuid(),
        sessions_provider=lambda: {"state": "available", "sessions": [{"session_id": "s-1"}]},
    )
    thread = _start_bridge_socket(path, bridge)
    client = UserBridgeClient(path, expected_server_uid=os.getuid(), timeout=1.0)

    response = client.call("codex.sessions.list.v1", "client-valid-1")
    thread.join(timeout=1.0)

    assert response["status"] == "ok"
    assert response["projection"]["state"] == "available"
    assert not thread.is_alive()


def test_client_rejects_wrong_server_uid(tmp_path: Path) -> None:
    path = tmp_path / "bridge.sock"
    thread, _listener = _start_one_shot_socket(path, b"{}\n")
    wrong_uid = os.getuid() + 1
    client = UserBridgeClient(path, expected_server_uid=wrong_uid)
    client._socket_metadata = lambda: (os.stat(path).st_dev, os.stat(path).st_ino)

    with pytest.raises(UserBridgePeerError):
        client.call("codex.sessions.list.v1", "wrong-server")

    thread.join(timeout=1.0)


@pytest.mark.parametrize("response", [b"not-json\n", b"{" + (b"x" * (MAX_RESPONSE_BYTES + 1)) + b"}\n"])
def test_client_rejects_malformed_or_oversized_response(tmp_path: Path, response: bytes) -> None:
    path = tmp_path / "bridge.sock"
    thread, _listener = _start_one_shot_socket(path, response)

    with pytest.raises(UserBridgeResponseError):
        UserBridgeClient(path, expected_server_uid=os.getuid()).call("codex.sessions.list.v1", "bad-response")

    thread.join(timeout=1.0)


def test_client_reports_unavailable_and_timeout(tmp_path: Path) -> None:
    with pytest.raises(UserBridgeUnavailableError):
        UserBridgeClient(tmp_path / "missing.sock", expected_server_uid=os.getuid(), timeout=0.05).call(
            "codex.sessions.list.v1", "missing"
        )

    path = tmp_path / "slow.sock"
    thread, _listener = _start_one_shot_socket(path, b"{}\n", delay=0.2)
    with pytest.raises(UserBridgeTimeoutError):
        UserBridgeClient(path, expected_server_uid=os.getuid(), timeout=0.01).call(
            "codex.sessions.list.v1", "slow"
        )
    thread.join(timeout=1.0)


def test_default_provider_paths_are_fixed_server_side_paths() -> None:
    assert MAX_SOURCE_BYTES == 2 * 1024 * 1024
    assert DEFAULT_CODEX_REGISTRY_PATH == Path("/home/god/.codex/codex-projects.csv")
    assert DEFAULT_CODEX_USAGE_DB_PATH == Path("/home/god/.local/share/overseer/codex-usage-mcp/state.sqlite3")
    assert DEFAULT_CODEX_REGISTRY_PATH.is_absolute()
    assert DEFAULT_CODEX_USAGE_DB_PATH.is_absolute()


def test_cli_serve_wires_fixed_default_providers(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_serve(self: UserBridge, listener: socket.socket) -> None:
        captured["bridge"] = self
        listener.close()

    monkeypatch.setattr(UserBridge, "serve_forever", fake_serve)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        main(["serve", "--socket-fd", str(listener.fileno()), "--peer-uid", str(os.getuid())])
    finally:
        listener.close()

    bridge = captured["bridge"]
    assert isinstance(bridge.sessions_provider, CodexSessionProjectionProvider)
    assert isinstance(bridge.usage_provider, CodexUsageProjectionProvider)
    assert bridge.sessions_provider.registry_path == DEFAULT_CODEX_REGISTRY_PATH
    assert bridge.usage_provider.db_path == DEFAULT_CODEX_USAGE_DB_PATH
    assert isinstance(create_default_bridge(allowed_peer_uid=os.getuid()).sessions_provider, CodexSessionProjectionProvider)


def test_session_provider_hashes_ids_and_never_emits_registry_secrets(tmp_path: Path) -> None:
    registry = tmp_path / "codex-projects.csv"
    registry.write_text(
        "conversation_id,project,command,launcher\n"
        "conversation-secret,/home/god/private-project,codex --danger,launcher-secret\n",
        encoding="utf-8",
    )
    before = registry.stat()

    projection = CodexSessionProjectionProvider(registry_path=registry).snapshot()
    encoded = json.dumps(projection)

    assert projection["state"] == "available"
    assert len(projection["sessions"]) == 1
    assert projection["sessions"][0]["session_id"].startswith("session-")
    assert projection["sessions"][0]["project_id"].startswith("project-")
    assert "conversation-secret" not in encoded
    assert "/home/god/private-project" not in encoded
    assert "danger" not in encoded
    assert "launcher-secret" not in encoded
    assert registry.stat() == before


def test_session_provider_accepts_currently_sized_registry_but_stays_bounded(tmp_path: Path) -> None:
    registry = tmp_path / "large-codex-projects.csv"
    registry.write_text(
        "conversation_id,project,command,launcher\n"
        + "conversation-large,/home/god/project,"
        + ("ignored-command-data" * 30_000)
        + ",launcher\n",
        encoding="utf-8",
    )
    assert registry.stat().st_size > 512 * 1024

    projection = CodexSessionProjectionProvider(registry_path=registry).snapshot()

    assert projection["state"] == "available"
    assert len(projection["sessions"]) == 1
    assert len(json.dumps(projection).encode()) <= MAX_RESPONSE_BYTES


@pytest.mark.parametrize("mode", [0o666, 0o777])
def test_session_provider_rejects_world_writable_source(tmp_path: Path, mode: int) -> None:
    registry = tmp_path / "world-writable.csv"
    registry.write_text("conversation_id,project\nconversation-1,project-1\n", encoding="utf-8")
    registry.chmod(mode)

    assert CodexSessionProjectionProvider(registry_path=registry).snapshot() == {
        "state": "unavailable",
        "reason": "source_unavailable",
    }


def test_session_provider_rejects_hardlink_aliases_and_symlinks(tmp_path: Path) -> None:
    registry = tmp_path / "registry.csv"
    registry.write_text("conversation_id,project\nconversation-1,project-1\n", encoding="utf-8")
    alias = tmp_path / "registry-alias.csv"
    alias.hardlink_to(registry)
    symlink = tmp_path / "registry-symlink.csv"
    symlink.symlink_to(registry)

    assert CodexSessionProjectionProvider(registry_path=registry).snapshot() == {
        "state": "unavailable",
        "reason": "source_unavailable",
    }
    assert CodexSessionProjectionProvider(registry_path=symlink).snapshot() == {
        "state": "unavailable",
        "reason": "source_unavailable",
    }


def _create_usage_fixture(path: Path, payload: dict, observed_at: str) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE codex_usage_snapshots (id INTEGER PRIMARY KEY, observed_at TEXT NOT NULL, source TEXT NOT NULL, payload TEXT NOT NULL)")
        connection.execute(
            "INSERT INTO codex_usage_snapshots (id, observed_at, source, payload) VALUES (1, ?, ?, ?)",
            (observed_at, "codex_app_server", json.dumps(payload)),
        )


def test_usage_provider_is_read_only_bounded_and_redacted(tmp_path: Path) -> None:
    database = tmp_path / "usage.sqlite3"
    _create_usage_fixture(
        database,
        {
            "rate_limits": [
                {
                    "limit_id": "private-account@example.invalid",
                    "windows": [
                        {"name": "primary", "used_percent": 12, "remaining_percent": 88, "resets_at": "2026-09-01T00:00:00+00:00"}
                    ],
                }
            ],
            "account_usage": {"token": "secret"},
        },
        "2026-08-26T12:00:00+00:00",
    )
    before = database.stat()

    projection = CodexUsageProjectionProvider(
        db_path=database,
        clock=lambda: datetime(2026, 8, 26, 12, 5, tzinfo=UTC),
    ).snapshot()
    encoded = json.dumps(projection)

    assert projection["state"] == "available"
    assert len(projection["windows"]) == 1
    assert projection["windows"][0]["used"] == 12
    assert projection["windows"][0]["remaining"] == 88
    assert "private-account@example.invalid" not in encoded
    assert "secret" not in encoded
    assert database.stat() == before


def test_usage_provider_reports_stale_unavailable_and_error(tmp_path: Path) -> None:
    stale_db = tmp_path / "stale.sqlite3"
    _create_usage_fixture(stale_db, {"rate_limits": []}, "2020-01-01T00:00:00+00:00")
    stale = CodexUsageProjectionProvider(
        db_path=stale_db,
        clock=lambda: datetime(2026, 8, 26, tzinfo=UTC),
        stale_after_seconds=1,
    ).snapshot()
    missing = CodexUsageProjectionProvider(db_path=tmp_path / "missing.sqlite3").snapshot()
    invalid_db = tmp_path / "invalid.sqlite3"
    invalid_db.write_bytes(b"not sqlite")
    error = CodexUsageProjectionProvider(db_path=invalid_db).snapshot()

    assert stale["state"] == "stale"
    assert missing == {"state": "unavailable", "reason": "source_missing"}
    assert error == {"state": "error", "error_code": "source_invalid"}


def test_usage_provider_queries_the_validated_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import overseer.user_bridge_providers as providers_module

    database = tmp_path / "usage.sqlite3"
    _create_usage_fixture(
        database,
        {"rate_limits": []},
        "2026-08-26T12:00:00+00:00",
    )
    observed_uris: list[str] = []
    connect = sqlite3.connect

    def connect_observed(database_uri: str, *args: object, **kwargs: object):
        observed_uris.append(database_uri)
        return connect(database_uri, *args, **kwargs)

    monkeypatch.setattr(providers_module.sqlite3, "connect", connect_observed)

    result = CodexUsageProjectionProvider(db_path=database).snapshot()

    assert result["state"] in {"available", "stale"}
    assert len(observed_uris) == 1
    assert observed_uris[0].startswith("file:/proc/self/fd/")
    assert observed_uris[0].endswith("?mode=ro")


def test_provider_slot_remains_occupied_after_timeout_until_worker_exits() -> None:
    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    calls = 0

    def blocked_provider() -> dict:
        nonlocal calls
        calls += 1
        started.set()
        try:
            release.wait(1.0)
            return {"state": "available", "sessions": []}
        finally:
            finished.set()

    bridge = UserBridge(
        allowed_peer_uid=4242,
        provider_timeout=0.01,
        max_provider_workers=1,
        sessions_provider=blocked_provider,
        usage_provider=lambda: {"state": "available", "windows": []},
    )
    first_result: list[dict] = []
    first_thread = threading.Thread(
        target=lambda: first_result.append(
            decode(bridge.handle_bytes(request("worker-first", "codex.sessions.list.v1"), peer_uid=4242))
        ),
        daemon=True,
    )
    first_thread.start()
    assert started.wait(1.0)
    first_thread.join(timeout=1.0)

    saturated = decode(bridge.handle_bytes(request("worker-second", "codex.sessions.list.v1"), peer_uid=4242))
    unrelated = decode(
        bridge.handle_bytes(
            request("worker-usage", "codex.usage.snapshot.v1"),
            peer_uid=4242,
        )
    )

    assert first_result[0]["projection"] == {"state": "error", "error_code": "provider_timeout"}
    assert saturated["projection"] == {"state": "error", "error_code": "busy"}
    assert unrelated["projection"] == {"state": "available", "windows": []}
    assert calls == 1

    release.set()
    assert finished.wait(1.0)
    recovered = decode(bridge.handle_bytes(request("worker-third", "codex.sessions.list.v1"), peer_uid=4242))
    assert recovered["projection"] == {"state": "available", "sessions": []}
    assert calls == 2


def test_slow_provider_does_not_block_an_unrelated_projection() -> None:
    slow_started = threading.Event()
    release_slow = threading.Event()
    fast_finished = threading.Event()
    fast_result: list[dict] = []

    def slow_provider() -> dict:
        slow_started.set()
        release_slow.wait(1.0)
        return {"state": "available", "sessions": []}

    bridge = UserBridge(
        allowed_peer_uid=4242,
        provider_timeout=0.5,
        max_provider_workers=2,
        sessions_provider=slow_provider,
        usage_provider=lambda: {"state": "available", "windows": []},
    )
    slow_thread = threading.Thread(
        target=lambda: bridge.handle_bytes(
            request("slow-projection", "codex.sessions.list.v1"),
            peer_uid=4242,
        ),
        daemon=True,
    )
    slow_thread.start()
    assert slow_started.wait(1.0)

    def read_fast() -> None:
        fast_result.append(
            decode(
                bridge.handle_bytes(
                    request("fast-projection", "codex.usage.snapshot.v1"),
                    peer_uid=4242,
                )
            )
        )
        fast_finished.set()

    fast_thread = threading.Thread(target=read_fast, daemon=True)
    fast_thread.start()
    assert fast_finished.wait(0.2)
    assert fast_result[0]["projection"] == {
        "state": "available",
        "windows": [],
    }
    release_slow.set()
    slow_thread.join(timeout=1.0)
    fast_thread.join(timeout=1.0)


def test_connection_saturation_returns_redacted_busy_response() -> None:
    bridge = UserBridge(allowed_peer_uid=4242, max_active_connections=1)
    assert bridge._connection_slots.acquire(blocking=False)
    client_side, accepted_side = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        bridge._dispatch_connection(accepted_side)
        response = decode(client_side.recv(MAX_RESPONSE_BYTES + 1).rstrip(b"\n"))
    finally:
        client_side.close()
        bridge._connection_slots.release()

    assert response == {
        "error": {"code": "busy", "message": "busy"},
        "protocol": BRIDGE_PROTOCOL,
        "request_id": None,
        "status": "error",
    }
