from __future__ import annotations

import json
import os
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pytest

import overseer.cli as cli_module
from overseer.admin import (
    AdminChangeKind,
    AdminCommandStep,
    AdminExecutionResult,
    AdminExecutionStatus,
    approve_admin_change_plan,
)
from overseer.admin_executor import RECEIPT_SCHEMA_VERSION
from overseer.admin_tickets import parse_ticket
from overseer.admin_ticket_execution import (
    execute_system_service_restart_ticket,
    preflight_system_service_ticket_execution,
)
from overseer.cli import execute_admin_change_status, plan_admin_change_status
from overseer.store import SQLiteStore


TARGET = "overseer-approval-smoke.service"
PLAN_DIGEST = "a" * 64
MARKER = "__overseer_ticketed_system_service_restart_v1"
NOW = datetime(2026, 8, 26, 12, 0, 0, 400000, tzinfo=timezone.utc)


@dataclass(frozen=True)
class _ExecutablePlan:
    id: str = "admin.restart-system.smoke"
    kind: AdminChangeKind = AdminChangeKind.SYSTEM_SERVICE_RESTART
    target: str = TARGET
    approved: bool = True
    steps: tuple[AdminCommandStep, ...] = (
        AdminCommandStep("Restart system service", (MARKER, TARGET), "approved ticket marker"),
    )
    rollback_steps: tuple[AdminCommandStep, ...] = ()
    verification_steps: tuple[AdminCommandStep, ...] = ()

    def can_execute(self) -> bool:
        return self.approved


def _private_key_file(tmp_path: Path) -> Path:
    path = tmp_path / "authority.ed25519"
    path.write_bytes(bytes(range(32)))
    os.chmod(path, 0o600)
    return path


def _receipt(raw_ticket: bytes, *, status: str = "completed", restart: int = 0, verify: int = 0) -> bytes:
    ticket = parse_ticket(raw_ticket).to_dict()
    value = {
        "schemaVersion": RECEIPT_SCHEMA_VERSION,
        "ticketId": ticket["ticketId"],
        "planId": ticket["planId"],
        "planDigest": ticket["planDigest"],
        "operation": ticket["operation"],
        "target": ticket["target"],
        "status": status,
        "restartExitCode": restart,
        "verifyExitCode": verify,
        "stdout": "restart output",
        "stderr": "verify output" if status == "failed" else "",
        "replayed": False,
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def test_issues_exactly_bound_ticket_and_sends_only_ticket_bytes(tmp_path: Path) -> None:
    calls: list[tuple[object, bytes]] = []

    def sender(socket_address: object, raw_ticket: bytes) -> bytes:
        calls.append((socket_address, raw_ticket))
        return _receipt(raw_ticket)

    result = execute_system_service_restart_ticket(
        _ExecutablePlan(),
        PLAN_DIGEST,
        private_key_file=_private_key_file(tmp_path),
        executor_socket="/run/overseer/admin-executor.sock",
        expected_key_owner_uid=os.getuid(),
        clock=lambda: NOW,
        ticket_id_factory=lambda: "ticket.restart.1",
        nonce_factory=lambda: "nonce.restart.1",
        sender=sender,
    )

    assert result.status is AdminExecutionStatus.COMPLETED
    assert len(calls) == 1
    assert calls[0][0] == "/run/overseer/admin-executor.sock"
    ticket = parse_ticket(calls[0][1]).to_dict()
    assert ticket["ticketId"] == "ticket.restart.1"
    assert ticket["planId"] == "admin.restart-system.smoke"
    assert ticket["planDigest"] == PLAN_DIGEST
    assert ticket["operation"] == "restart-system-unit"
    assert ticket["target"] == TARGET
    assert ticket["issuedAt"] == "2026-08-26T12:00:00Z"
    assert ticket["expiresAt"] == "2026-08-26T12:01:00Z"
    assert ticket["nonce"] == "nonce.restart.1"
    assert MARKER.encode() not in calls[0][1]
    assert bytes(range(32)) not in calls[0][1]


def test_rejects_a_tampered_or_generic_executor_receipt(tmp_path: Path) -> None:
    def sender(_socket_address: object, raw_ticket: bytes) -> bytes:
        value = json.loads(_receipt(raw_ticket))
        value["planDigest"] = "b" * 64
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")

    with pytest.raises(ValueError, match="receipt.*planDigest"):
        execute_system_service_restart_ticket(
            _ExecutablePlan(),
            PLAN_DIGEST,
            private_key_file=_private_key_file(tmp_path),
            executor_socket="executor.sock",
            clock=lambda: NOW,
            ticket_id_factory=lambda: "ticket.restart.1",
            nonce_factory=lambda: "nonce.restart.1",
            sender=sender,
        )


def test_maps_failed_receipt_to_one_marker_command_result(tmp_path: Path) -> None:
    def sender(_socket_address: object, raw_ticket: bytes) -> bytes:
        return _receipt(raw_ticket, status="failed", restart=0, verify=7)

    result = execute_system_service_restart_ticket(
        _ExecutablePlan(),
        PLAN_DIGEST,
        private_key_file=_private_key_file(tmp_path),
        executor_socket="executor.sock",
        clock=lambda: NOW,
        ticket_id_factory=lambda: "ticket.restart.1",
        nonce_factory=lambda: "nonce.restart.1",
        sender=sender,
    )

    assert result.status is AdminExecutionStatus.FAILED
    assert result.plan_digest == PLAN_DIGEST
    assert len(result.command_results) == 1
    command = result.command_results[0]
    assert command.command == (MARKER, TARGET)
    assert command.exit_code == 7
    assert command.stdout == "restart output"
    assert command.stderr == "verify output"


def test_sender_exception_propagates_without_retry(tmp_path: Path) -> None:
    calls = 0

    def sender(_socket_address: object, _raw_ticket: bytes) -> bytes:
        nonlocal calls
        calls += 1
        raise RuntimeError("executor socket crashed")

    with pytest.raises(RuntimeError, match="executor socket crashed"):
        execute_system_service_restart_ticket(
            _ExecutablePlan(),
            PLAN_DIGEST,
            private_key_file=_private_key_file(tmp_path),
            executor_socket="executor.sock",
            clock=lambda: NOW,
            ticket_id_factory=lambda: "ticket.restart.1",
            nonce_factory=lambda: "nonce.restart.1",
            sender=sender,
        )

    assert calls == 1


def test_preflight_requires_an_owned_private_key_and_unix_socket(tmp_path: Path) -> None:
    key = _private_key_file(tmp_path)
    socket_path = tmp_path / "executor.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(socket_path))
        os.chmod(socket_path, 0o600)

        config = preflight_system_service_ticket_execution(
            {
                "OVERSEER_ADMIN_TICKET_PRIVATE_KEY": str(key),
                "OVERSEER_ADMIN_EXECUTOR_SOCKET": str(socket_path),
            },
            expected_owner_uid=os.geteuid(),
        )
    finally:
        listener.close()

    assert config.private_key_file == str(key)
    assert config.executor_socket == str(socket_path)


@pytest.mark.parametrize(
    "environment",
    [
        {},
        {"OVERSEER_ADMIN_TICKET_PRIVATE_KEY": "/missing/key"},
        {"OVERSEER_ADMIN_EXECUTOR_SOCKET": "/missing/socket"},
    ],
)
def test_preflight_rejects_missing_ticket_authority_configuration(environment) -> None:
    with pytest.raises(ValueError, match="OVERSEER_ADMIN"):
        preflight_system_service_ticket_execution(environment)


def _stage_approved_system_restart(store_path: Path) -> None:
    plan_admin_change_status(
        store_path,
        "admin.restart-system.smoke",
        "system_service_restart",
        TARGET,
        "exercise the signed executor boundary",
        "inactive",
    )
    with SQLiteStore(store_path) as store:
        store.save_admin_change_plan(
            approve_admin_change_plan(
                store.load_admin_change_plan("admin.restart-system.smoke"),
                "sisko",
                "2026-08-26T12:00:00+00:00",
            )
        )


def test_status_execution_preflights_ticket_authority_before_durable_claim(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    _stage_approved_system_restart(store_path)
    monkeypatch.delenv("OVERSEER_ADMIN_TICKET_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("OVERSEER_ADMIN_EXECUTOR_SOCKET", raising=False)

    with pytest.raises(ValueError, match="OVERSEER_ADMIN_TICKET_PRIVATE_KEY"):
        execute_admin_change_status(store_path, "admin.restart-system.smoke")

    with SQLiteStore(store_path) as store:
        assert store.load_admin_execution_claim_for_plan("admin.restart-system.smoke") is None


def test_status_execution_uses_ticket_adapter_once_and_replays_persisted_result(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    _stage_approved_system_restart(store_path)
    key = _private_key_file(tmp_path)
    socket_path = tmp_path / "executor.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    os.chmod(socket_path, 0o600)
    monkeypatch.setenv("OVERSEER_ADMIN_TICKET_PRIVATE_KEY", str(key))
    monkeypatch.setenv("OVERSEER_ADMIN_EXECUTOR_SOCKET", str(socket_path))
    calls: list[tuple[object, ...]] = []

    def execute_ticket(plan, plan_digest, **kwargs):
        calls.append((plan, plan_digest, kwargs))
        return AdminExecutionResult(
            id=f"admin.exec.{plan.id}.completed",
            plan_id=plan.id,
            status=AdminExecutionStatus.COMPLETED,
            summary="approved system-service restart ticket completed",
            command_results=(),
            plan_digest=plan_digest,
        )

    monkeypatch.setattr(
        cli_module,
        "execute_system_service_restart_ticket",
        execute_ticket,
        raising=False,
    )
    try:
        original = execute_admin_change_status(store_path, "admin.restart-system.smoke")
        replay = execute_admin_change_status(store_path, "admin.restart-system.smoke")
    finally:
        listener.close()

    assert original["status"] == "completed"
    assert original["mutation_performed"] is True
    assert replay["replayed"] is True
    assert replay["mutation_performed"] is False
    assert len(calls) == 1
    plan, digest, kwargs = calls[0]
    assert plan.id == "admin.restart-system.smoke"
    assert digest == original["plan_digest"]
    assert kwargs["private_key_file"] == str(key)
    assert kwargs["executor_socket"] == str(socket_path)
    assert kwargs["expected_key_owner_uid"] == os.geteuid()
