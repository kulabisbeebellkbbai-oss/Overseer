from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SYSTEMD = ROOT / "systemd"
API_UNIT = SYSTEMD / "overseer-api-system.service"
CANARY_UNIT = SYSTEMD / "overseer-api-canary.service"
RUNTIME_UNIT = SYSTEMD / "overseer-runtime-system.service"
SOCKET_UNIT = SYSTEMD / "overseer-admin-executor.socket"
EXECUTOR_UNIT = SYSTEMD / "overseer-admin-executor@.service"
ALLOWLIST = ROOT / "config" / "admin-executor-allowlist.json"
TMPFILES = SYSTEMD / "overseer-tmpfiles.conf"


COMMON_HARDENING = (
    "NoNewPrivileges=yes",
    "ProtectSystem=strict",
    "ProtectHome=true",
    "PrivateTmp=yes",
    "PrivateDevices=yes",
    "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes",
    "ProtectControlGroups=yes",
    "ProtectClock=yes",
    "RestrictSUIDSGID=yes",
    "LockPersonality=yes",
    "MemoryDenyWriteExecute=yes",
    "UMask=0077",
)


def _read(path: Path) -> str:
    assert path.is_file(), f"missing required new file: {path.relative_to(ROOT)}"
    return path.read_text(encoding="utf-8")


def _lines(text: str, key: str) -> list[str]:
    prefix = f"{key}="
    return [line.removeprefix(prefix) for line in text.splitlines() if line.startswith(prefix)]


def _one(text: str, key: str) -> str:
    values = _lines(text, key)
    assert len(values) == 1, f"expected one {key}= setting, got {values!r}"
    return values[0]


def _render_units(tmp_path: Path) -> list[Path]:
    release = tmp_path / "release"
    release.mkdir()
    python_path = tmp_path / "python"
    python_path.symlink_to(sys.executable)
    rendered: list[Path] = []
    replacements = {
        "@OVERSEER_RELEASE@": str(release),
        "@OVERSEER_PYTHON@": str(python_path),
        "@GOD_UID@": "1000",
        "@GOD_GID@": "1000",
        "@OVERSEER_UID@": "984",
    }
    for source in (
        API_UNIT,
        CANARY_UNIT,
        RUNTIME_UNIT,
        SOCKET_UNIT,
        EXECUTOR_UNIT,
    ):
        target = tmp_path / source.name
        content = _read(source)
        for placeholder, value in replacements.items():
            content = content.replace(placeholder, value)
        target.write_text(content, encoding="utf-8")
        rendered.append(target)
    return rendered


def test_api_and_runtime_use_the_dedicated_system_principal_and_immutable_release() -> None:
    for path in (API_UNIT, RUNTIME_UNIT):
        unit = _read(path)
        assert "[Service]" in unit
        assert "[Install]" in unit
        assert _one(unit, "User") == "@OVERSEER_UID@"
        assert _one(unit, "Group") == "@OVERSEER_UID@"
        assert _one(unit, "WorkingDirectory") == "@OVERSEER_RELEASE@"
        assert (
            "Environment=PYTHONPATH=@OVERSEER_RELEASE@/app/src:"
            "@OVERSEER_RELEASE@/site-packages"
        ) in unit
        assert "Environment=PYTHONHOME=@OVERSEER_RELEASE@/runtime" in unit
        assert "Environment=LD_LIBRARY_PATH=@OVERSEER_RELEASE@/lib" in unit
        assert "Environment=PYTHONNOUSERSITE=1" in unit
        assert "Environment=PYTHONSAFEPATH=1" in unit
        assert _one(unit, "StateDirectory") == "overseer"
        assert _one(unit, "StateDirectoryMode") == "0700"
        assert "/etc/overseer" in unit
        assert "/var/lib/overseer/overseer.sqlite3" in unit
        assert "Environment=OVERSEER_DEDICATED_PRINCIPAL=1" in unit
        assert "ReadOnlyPaths=@OVERSEER_RELEASE@" in unit
        assert "ReadWritePaths=/var/lib/overseer" in unit
        assert "WantedBy=multi-user.target" in unit

        for setting in COMMON_HARDENING:
            assert setting in unit
        assert _one(unit, "RestrictAddressFamilies") == "AF_UNIX AF_INET AF_INET6"
        assert _one(unit, "IPAddressDeny") == "any"
        assert _one(unit, "IPAddressAllow") == "localhost"
        assert _one(unit, "CapabilityBoundingSet") == ""
        assert _one(unit, "AmbientCapabilities") == ""

        forbidden = (
            r"%h",
            r"/home(?:/|$)",
            r"systemctl\s+--user",
            r"\bsudo\b",
            r"/(?:usr/)?bin/(?:ba)?sh\b",
            r"/usr/bin/env\b",
            r"^EnvironmentFile=",
            r"\$\{[^}]+\}",
        )
        for pattern in forbidden:
            assert not re.search(pattern, unit, flags=re.MULTILINE), pattern

        exec_start = _one(unit, "ExecStart")
        assert "@OVERSEER_PYTHON@" in exec_start
        assert " -s -P -m " in exec_start
        assert "$" not in exec_start
        assert "%i" not in exec_start and "%I" not in exec_start


def test_api_uses_independent_credentials_verifiers_and_loopback_peer_channels() -> None:
    api = _read(API_UNIT)
    assert "LoadCredential=api-token:/etc/overseer/api-token" in api
    assert "--auth-token-file %d/api-token" in _one(api, "ExecStart")
    assert "LoadCredential=psychlo-peer-secret:/etc/overseer/psychlo-peer-secret" in api
    assert "LoadCredential=roadex-peer-secret:/etc/overseer/roadex-project-human-thread-secret" in api
    assert "OVERSEER_PSYCHLO_PEER_SECRET_FILE=%d/psychlo-peer-secret" in api
    assert "OVERSEER_ROADEX_PROJECT_HUMAN_THREAD_SECRET_FILE=%d/roadex-peer-secret" in api
    assert "OVERSEER_PSYCHLO_BRIDGE_DATABASE=/var/lib/overseer/psychlo-bridge.sqlite3" in api
    assert "OVERSEER_PSYCHLO_PROJECT_BINDINGS_FILE=/etc/overseer/psychlo-project-bindings.json" in api
    assert "OVERSEER_ROADEX_PROJECT_HUMAN_THREAD_DATABASE=/var/lib/overseer/roadex-relay.sqlite3" in api
    assert "OVERSEER_PSYCHLO_ENDPOINT=http://127.0.0.1:8798" in api
    assert (
        "Environment=OVERSEER_ROADEX_PROJECT_HUMAN_THREAD_QUESTION_ENDPOINT="
        "http://127.0.0.1:8780/api/internal/overseer/project-human-thread/questions"
        in api
    )
    assert "Environment=OVERSEER_ADMIN_TICKET_PRIVATE_KEY=/etc/overseer/admin-ticket-private-key" in api
    assert "Environment=OVERSEER_ADMIN_EXECUTOR_SOCKET=/run/overseer/admin-executor.sock" in api
    assert "Environment=OVERSEER_USER_BRIDGE_SOCKET=/run/overseer/codex-user-bridge.sock" in api
    assert "Environment=OVERSEER_USER_BRIDGE_SERVER_UID=@GOD_UID@" in api
    assert "Wants=overseer-codex-user-bridge.socket" in api

    command = _one(api, "ExecStart")
    assert "--admin-approval-verifier-file /etc/overseer/admin-approval-verifier.json" in command
    assert "--roadex-fixture-approval-verifier-file /etc/overseer/roadex-fixture-approval-verifier.json" in command
    assert "--human-approval-token-file" not in command
    assert "api-token:/etc/overseer/admin-approval-verifier.json" not in api
    assert "api-token:/etc/overseer/roadex-fixture-approval-verifier.json" not in api


def test_disposable_api_canary_is_separate_bounded_and_principal_owned() -> None:
    canary = _read(CANARY_UNIT)
    command = _one(canary, "ExecStart")
    assert _one(canary, "User") == "@OVERSEER_UID@"
    assert _one(canary, "Group") == "@OVERSEER_UID@"
    assert "--store @OVERSEER_CANARY_STATE@/overseer.sqlite3" in command
    assert "--socket-fd" not in command
    assert "--socket-path /run/overseer-canary/api.sock" in command
    assert "--socket-peer-uid 0" in command
    assert "--socket-owner-uid 984 --socket-owner-gid 984" in command
    assert "--host" not in command and "--port" not in command
    assert "overseer-api-canary.socket" not in canary
    assert (
        "OVERSEER_PSYCHLO_BRIDGE_DATABASE="
        "@OVERSEER_CANARY_STATE@/psychlo-bridge.sqlite3"
    ) in canary
    assert (
        "OVERSEER_ROADEX_PROJECT_HUMAN_THREAD_DATABASE="
        "@OVERSEER_CANARY_STATE@/roadex-relay.sqlite3"
    ) in canary
    assert _one(canary, "ReadWritePaths") == "@OVERSEER_CANARY_STATE@"
    assert (
        "Environment=OVERSEER_ROADEX_PROJECT_HUMAN_THREAD_QUESTION_ENDPOINT="
        "http://127.0.0.1:8780/api/internal/overseer/project-human-thread/questions"
        in canary
    )
    assert _one(canary, "RuntimeMaxSec") == "10min"
    assert _one(canary, "TimeoutStopSec") == "10s"
    assert _one(canary, "RuntimeDirectory") == "overseer-canary"
    assert _one(canary, "RuntimeDirectoryMode") == "0700"
    assert "StateDirectory=" not in canary
    assert "StateDirectoryMode=" not in canary
    assert _one(canary, "RestrictAddressFamilies") == "AF_UNIX"
    assert "[Install]" not in canary
    for setting in COMMON_HARDENING:
        assert setting in canary
def test_executor_socket_and_root_instance_have_narrow_privileged_boundary() -> None:
    socket = _read(SOCKET_UNIT)
    assert "Accept=yes" in socket
    assert _one(socket, "ListenStream") == "/run/overseer/admin-executor.sock"
    assert _one(socket, "SocketMode") == "0600"
    assert _one(socket, "SocketUser") == "@OVERSEER_UID@"
    assert _one(socket, "SocketGroup") == "0"
    assert "WantedBy=sockets.target" in socket

    executor = _read(EXECUTOR_UNIT)
    assert _one(executor, "User") == "root"
    assert _one(executor, "Group") == "root"
    assert _one(executor, "StateDirectory") == "overseer-executor"
    assert _one(executor, "StateDirectoryMode") == "0700"
    assert "StandardInput=socket" in executor
    assert "StandardOutput=socket" in executor
    assert _one(executor, "RuntimeMaxSec") == "30s"
    assert _one(executor, "TimeoutStopSec") == "5s"
    assert _one(executor, "RestrictAddressFamilies") == "AF_UNIX"
    assert "PrivateNetwork=yes" in executor
    assert "ProtectProc=invisible" in executor
    assert "ProcSubset=pid" in executor
    assert "RestrictNamespaces=yes" in executor
    assert "SystemCallArchitectures=native" in executor
    assert "SystemCallFilter=@system-service" in executor
    assert "SystemCallErrorNumber=EPERM" in executor
    assert "ReadOnlyPaths=/etc/overseer" in executor
    assert "ReadWritePaths=/var/lib/overseer-executor" in executor
    assert _one(executor, "CapabilityBoundingSet") == ""
    assert _one(executor, "AmbientCapabilities") == ""
    assert "Environment=LD_LIBRARY_PATH=@OVERSEER_RELEASE@/lib" in executor
    for setting in COMMON_HARDENING:
        assert setting in executor

    command = _one(executor, "ExecStart")
    assert re.search(
        r"@OVERSEER_PYTHON@ -s -P -m overseer\.admin_executor serve-one(?: |$)",
        command,
    )
    assert "--allowlist-file /etc/overseer/admin-executor-allowlist.json" in command
    assert "--public-key-file /etc/overseer/admin-executor-public-key" in command
    assert "--ledger /var/lib/overseer-executor/ledger.sqlite3" in command
    assert "systemctl --user" not in executor
    assert "sudo" not in executor
    assert "/bin/sh" not in executor and "/bin/bash" not in executor


def test_shared_runtime_socket_directory_is_root_created_for_only_overseer_group() -> None:
    assert _read(TMPFILES).strip() == "d /run/overseer 0710 0 @OVERSEER_UID@ -"


def test_sample_allowlist_contains_only_the_approval_smoke_restart_rule() -> None:
    parsed = json.loads(_read(ALLOWLIST))
    assert parsed == {
        "schemaVersion": "overseer.admin-executor-allowlist.v1",
        "allowed": [
            {
                "operation": "restart-system-unit",
                "unit": "overseer-approval-smoke.service",
            }
        ]
    }
    encoded = json.dumps(parsed)
    assert "overseer.service" not in encoded


def test_rendered_units_pass_systemd_analyze_verify_without_installing(tmp_path: Path) -> None:
    rendered = _render_units(tmp_path)
    result = subprocess.run(
        ["systemd-analyze", "verify", *(str(path) for path in rendered)],
        cwd=ROOT,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
