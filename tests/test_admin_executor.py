from __future__ import annotations

import json
import os
import socket
import sqlite3
import stat
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from overseer.admin_executor import (
    ALLOWLIST_SCHEMA_VERSION,
    RECEIPT_SCHEMA_VERSION,
    AdminExecutorError,
    execute_ticket,
    load_allowlist,
    send_ticket,
    serve_one,
)
from overseer.admin_tickets import create_ticket


PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
NOW = "2026-08-26T12:01:00Z"
TARGET = "overseer-approval-smoke.service"


def _ticket(*, ticket_id: str = "ticket-1", nonce: str = "nonce-1", target: str = TARGET) -> bytes:
    return create_ticket(
        {"planId": "plan-1", "planDigest": "a" * 64},
        PRIVATE_KEY,
        ticket_id=ticket_id,
        issued_at="2026-08-26T12:00:00Z",
        expires_at="2026-08-26T12:05:00Z",
        nonce=nonce,
        target=target,
    )


def _allowlist(path: Path, *, raw: bytes | None = None) -> None:
    if raw is None:
        raw = json.dumps(
            {
                "schemaVersion": ALLOWLIST_SCHEMA_VERSION,
                "allowed": [{"operation": "restart-system-unit", "unit": TARGET}],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    path.write_bytes(raw)
    os.chmod(path, 0o644)


def _executor_files(tmp_path: Path) -> tuple[Path, Path, Path]:
    allowlist = tmp_path / "allowlist.json"
    key = tmp_path / "public.key"
    ledger_dir = tmp_path / "ledger-dir"
    ledger_dir.mkdir()
    os.chmod(ledger_dir, 0o700)
    _allowlist(allowlist)
    key.write_bytes(PRIVATE_KEY.public_key().public_bytes_raw())
    os.chmod(key, 0o644)
    return allowlist, key, ledger_dir / "ledger.sqlite3"


def _runner(calls: list[tuple[str, ...]], *, restart: int = 0, verify: int = 0):
    def run(argv: tuple[str, ...]):
        calls.append(tuple(argv))
        result = restart if len(calls) == 1 else verify
        return result, b"ok\n", b""

    return run


def test_allowlist_is_exact_bounded_canonical_root_owned_data(tmp_path: Path) -> None:
    path = tmp_path / "allowlist.json"
    _allowlist(path)

    assert load_allowlist(path, expected_owner_uid=os.getuid()) == {
        ("restart-system-unit", TARGET)
    }

    duplicate = b'{"allowed":[],"allowed":[],"schemaVersion":"' + ALLOWLIST_SCHEMA_VERSION.encode() + b'"}'
    _allowlist(path, raw=duplicate)
    with pytest.raises(AdminExecutorError, match="duplicate"):
        load_allowlist(path, expected_owner_uid=os.getuid())


def test_repository_allowlist_format_is_accepted(tmp_path: Path) -> None:
    path = tmp_path / "allowlist.json"
    path.write_text(
        '{\n  "schemaVersion": "overseer.admin-executor-allowlist.v1",\n'
        '  "allowed": [\n    {"operation": "restart-system-unit", "unit": "overseer-approval-smoke.service"}\n  ]\n}\n',
        encoding="utf-8",
    )
    os.chmod(path, 0o644)
    assert load_allowlist(path, expected_owner_uid=os.getuid()) == {
        ("restart-system-unit", TARGET)
    }


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: {**value, "extra": True},
        lambda value: {**value, "allowed": [{"operation": "restart-system-unit", "unit": "x.socket"}]},
        lambda value: {**value, "allowed": [{"operation": "restart-system-unit", "unit": TARGET}, {"operation": "restart-system-unit", "unit": TARGET}]},
    ],
)
def test_allowlist_rejects_schema_or_entry_variants(tmp_path: Path, mutate) -> None:
    path = tmp_path / "allowlist.json"
    value = {"schemaVersion": ALLOWLIST_SCHEMA_VERSION, "allowed": [{"operation": "restart-system-unit", "unit": TARGET}]}
    _allowlist(path, raw=json.dumps(mutate(value), separators=(",", ":")).encode())
    with pytest.raises(AdminExecutorError):
        load_allowlist(path, expected_owner_uid=os.getuid())


def test_executor_claims_before_fixed_commands_and_persists_receipt(tmp_path: Path) -> None:
    allowlist, key, ledger = _executor_files(tmp_path)
    calls: list[tuple[str, ...]] = []
    receipt = execute_ticket(
        _ticket(),
        allowlist_file=allowlist,
        public_key_file=key,
        ledger=ledger,
        expected_owner_uid=os.getuid(),
        now=NOW,
        runner=_runner(calls),
    )

    assert receipt == {
        "schemaVersion": RECEIPT_SCHEMA_VERSION,
        "ticketId": "ticket-1",
        "planId": "plan-1",
        "planDigest": "a" * 64,
        "operation": "restart-system-unit",
        "target": TARGET,
        "status": "completed",
        "restartExitCode": 0,
        "verifyExitCode": 0,
        "stdout": "ok\nok\n",
        "stderr": "",
        "replayed": False,
    }
    assert calls == [
        ("/usr/bin/systemctl", "restart", "--", TARGET),
        ("/usr/bin/systemctl", "is-active", "--quiet", "--", TARGET),
    ]
    with sqlite3.connect(ledger) as db:
        row = db.execute("SELECT state, terminal_receipt FROM admin_executions WHERE ticket_id=?", ("ticket-1",)).fetchone()
    assert row[0] == "completed"
    assert json.loads(row[1])["replayed"] is False
    assert stat.S_IMODE(os.stat(ledger).st_mode) == 0o600


def test_terminal_replay_returns_receipt_without_running_commands(tmp_path: Path) -> None:
    allowlist, key, ledger = _executor_files(tmp_path)
    calls: list[tuple[str, ...]] = []
    first = execute_ticket(_ticket(), allowlist_file=allowlist, public_key_file=key, ledger=ledger, expected_owner_uid=os.getuid(), now=NOW, runner=_runner(calls))
    replay = execute_ticket(_ticket(), allowlist_file=allowlist, public_key_file=key, ledger=ledger, expected_owner_uid=os.getuid(), now=NOW, runner=lambda _: pytest.fail("replay ran a command"))

    assert first["replayed"] is False
    assert replay == {**first, "replayed": True}
    assert len(calls) == 2


def test_claimed_ticket_and_reused_nonce_fail_closed_and_runner_exception_stays_claimed(tmp_path: Path) -> None:
    allowlist, key, ledger = _executor_files(tmp_path)
    calls: list[tuple[str, ...]] = []

    def broken(argv):
        calls.append(argv)
        raise RuntimeError("runner unavailable")

    with pytest.raises(RuntimeError):
        execute_ticket(_ticket(), allowlist_file=allowlist, public_key_file=key, ledger=ledger, expected_owner_uid=os.getuid(), now=NOW, runner=broken)
    with pytest.raises(AdminExecutorError, match="reconciliation"):
        execute_ticket(_ticket(), allowlist_file=allowlist, public_key_file=key, ledger=ledger, expected_owner_uid=os.getuid(), now=NOW, runner=_runner([]))
    with pytest.raises(AdminExecutorError, match="nonce"):
        execute_ticket(_ticket(ticket_id="ticket-2"), allowlist_file=allowlist, public_key_file=key, ledger=ledger, expected_owner_uid=os.getuid(), now=NOW, runner=_runner([]))


def test_failed_commands_produce_bounded_failed_receipt(tmp_path: Path) -> None:
    allowlist, key, ledger = _executor_files(tmp_path)
    receipt = execute_ticket(_ticket(), allowlist_file=allowlist, public_key_file=key, ledger=ledger, expected_owner_uid=os.getuid(), now=NOW, runner=_runner([], restart=7, verify=3))
    assert receipt["status"] == "failed"
    assert receipt["restartExitCode"] == 7
    assert receipt["verifyExitCode"] == 3


def test_socket_client_and_serve_one_require_peer_and_return_canonical_receipt(tmp_path: Path) -> None:
    allowlist, key, ledger = _executor_files(tmp_path)
    server, client = socket.socketpair()
    errors: list[BaseException] = []

    def serve() -> None:
        try:
            serve_one(server, allowlist_file=allowlist, public_key_file=key, ledger=ledger, authority_uid=os.getuid(), expected_owner_uid=os.getuid(), now=NOW, runner=_runner([]))
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=serve)
    thread.start()
    received = send_ticket(client, _ticket())
    thread.join(timeout=3)
    client.close()
    server.close()
    assert not errors
    parsed = json.loads(received)
    assert parsed["status"] == "completed"
    assert received == json.dumps(parsed, sort_keys=True, separators=(",", ":")).encode()


def test_unsafe_ledger_parent_is_rejected_before_database_creation(tmp_path: Path) -> None:
    allowlist, key, ledger = _executor_files(tmp_path)
    os.chmod(ledger.parent, 0o755)
    with pytest.raises(AdminExecutorError, match="0700"):
        execute_ticket(_ticket(), allowlist_file=allowlist, public_key_file=key, ledger=ledger, expected_owner_uid=os.getuid(), now=NOW, runner=_runner([]))
    assert not ledger.exists()
