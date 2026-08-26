"""Authority-side execution adapter for approved system-service tickets."""

from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from . import admin_executor, admin_tickets
from .admin import (
    AdminChangeKind,
    AdminCommandResult,
    AdminExecutionResult,
    AdminExecutionStatus,
)


MARKER_COMMAND = "__overseer_ticketed_system_service_restart_v1"
SHORT_TICKET_LIFETIME = timedelta(seconds=60)
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TARGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@%_.:-]{0,190}\.service$")
_RECEIPT_FIELDS = frozenset(
    {
        "schemaVersion",
        "ticketId",
        "planId",
        "planDigest",
        "operation",
        "target",
        "status",
        "restartExitCode",
        "verifyExitCode",
        "stdout",
        "stderr",
        "replayed",
    }
)
_RECEIPT_STRING_FIELDS = frozenset(
    {
        "schemaVersion",
        "ticketId",
        "planId",
        "planDigest",
        "operation",
        "target",
        "status",
        "stdout",
        "stderr",
    }
)


class AdminTicketExecutionError(ValueError):
    """Raised when a plan, ticket, or executor receipt is outside the contract."""


@dataclass(frozen=True)
class SystemServiceTicketExecutionConfig:
    private_key_file: str
    executor_socket: str


def preflight_system_service_ticket_execution(
    environment: Mapping[str, str] | None = None,
    *,
    expected_owner_uid: int | None = None,
) -> SystemServiceTicketExecutionConfig:
    """Validate ticket authority inputs before a durable execution claim."""

    values = os.environ if environment is None else environment
    key_value = values.get("OVERSEER_ADMIN_TICKET_PRIVATE_KEY")
    socket_value = values.get("OVERSEER_ADMIN_EXECUTOR_SOCKET")
    if type(key_value) is not str or not key_value or not os.path.isabs(key_value):
        raise AdminTicketExecutionError(
            "OVERSEER_ADMIN_TICKET_PRIVATE_KEY must name an absolute private-key path"
        )
    if type(socket_value) is not str or not socket_value or not os.path.isabs(socket_value):
        raise AdminTicketExecutionError(
            "OVERSEER_ADMIN_EXECUTOR_SOCKET must name an absolute Unix-socket path"
        )

    owner_uid = os.geteuid() if expected_owner_uid is None else expected_owner_uid
    if type(owner_uid) is not int or owner_uid < 0:
        raise AdminTicketExecutionError("expected ticket authority UID is invalid")
    admin_tickets.load_private_key(key_value, expected_owner_uid=owner_uid)
    try:
        metadata = os.lstat(socket_value)
    except OSError as error:
        raise AdminTicketExecutionError(
            "OVERSEER_ADMIN_EXECUTOR_SOCKET could not be inspected"
        ) from error
    if not stat.S_ISSOCK(metadata.st_mode):
        raise AdminTicketExecutionError("OVERSEER_ADMIN_EXECUTOR_SOCKET is not a Unix socket")
    if metadata.st_uid != owner_uid:
        raise AdminTicketExecutionError("OVERSEER_ADMIN_EXECUTOR_SOCKET has an unexpected owner")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise AdminTicketExecutionError("OVERSEER_ADMIN_EXECUTOR_SOCKET must have mode 0600")
    if metadata.st_nlink != 1:
        raise AdminTicketExecutionError("OVERSEER_ADMIN_EXECUTOR_SOCKET must be single-link")
    return SystemServiceTicketExecutionConfig(key_value, socket_value)


def _duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AdminTicketExecutionError(f"receipt contains duplicate key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise AdminTicketExecutionError(f"receipt contains non-finite number: {value}")


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            dict(value),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as error:
        raise AdminTicketExecutionError("receipt is not canonical JSON") from error


def _parse_receipt(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or len(raw) > admin_executor.MAX_RECEIPT_BYTES:
        raise AdminTicketExecutionError("receipt exceeds the maximum size")
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except AdminTicketExecutionError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdminTicketExecutionError("receipt must be bounded UTF-8 JSON") from error
    if type(document) is not dict or set(document) != _RECEIPT_FIELDS:
        raise AdminTicketExecutionError("receipt schema is invalid")
    if _canonical_json(document) != raw:
        raise AdminTicketExecutionError("receipt JSON is not canonical")
    if document["schemaVersion"] != admin_executor.RECEIPT_SCHEMA_VERSION:
        raise AdminTicketExecutionError("receipt schema version is unsupported")
    if any(type(document[field]) is not str for field in _RECEIPT_STRING_FIELDS):
        raise AdminTicketExecutionError("receipt string fields have invalid types")
    if document["status"] not in {"completed", "failed"}:
        raise AdminTicketExecutionError("receipt status is invalid")
    if type(document["restartExitCode"]) is not int or type(document["verifyExitCode"]) is not int:
        raise AdminTicketExecutionError("receipt exit codes have invalid types")
    if type(document["replayed"]) is not bool:
        raise AdminTicketExecutionError("receipt replay flag has an invalid type")
    for field in ("stdout", "stderr"):
        try:
            output_bytes = document[field].encode("utf-8")
        except UnicodeEncodeError as error:
            raise AdminTicketExecutionError(f"receipt {field} is not valid UTF-8 text") from error
        if len(output_bytes) > admin_executor.MAX_OUTPUT_BYTES:
            raise AdminTicketExecutionError(f"receipt {field} exceeds the maximum size")
    if document["status"] == "completed" and (
        document["restartExitCode"] != 0 or document["verifyExitCode"] != 0
    ):
        raise AdminTicketExecutionError("completed receipt has a failed command")
    if document["status"] == "failed" and (
        document["restartExitCode"] == 0 and document["verifyExitCode"] == 0
    ):
        raise AdminTicketExecutionError("failed receipt has no failed command")
    return document


def _canonical_utc_second(value: object) -> datetime:
    if type(value) is str:
        try:
            return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except ValueError as error:
            raise AdminTicketExecutionError("clock must return a canonical UTC whole-second timestamp") from error
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise AdminTicketExecutionError("clock must return an aware datetime")
    return value.astimezone(timezone.utc).replace(microsecond=0)


def _validate_plan(plan: object, plan_digest: object) -> tuple[str, str, tuple[str, str]]:
    try:
        kind = AdminChangeKind(getattr(plan, "kind"))
    except (AttributeError, TypeError, ValueError) as error:
        raise AdminTicketExecutionError("plan kind is not SYSTEM_SERVICE_RESTART") from error
    if kind is not AdminChangeKind.SYSTEM_SERVICE_RESTART:
        raise AdminTicketExecutionError("plan kind is not SYSTEM_SERVICE_RESTART")
    if getattr(plan, "approved", None) is not True:
        raise AdminTicketExecutionError("plan is not approved")
    can_execute = getattr(plan, "can_execute", None)
    if not callable(can_execute) or can_execute() is not True:
        raise AdminTicketExecutionError("plan cannot execute")
    if type(plan_digest) is not str or _DIGEST.fullmatch(plan_digest) is None:
        raise AdminTicketExecutionError("plan digest must be 64 lowercase hexadecimal characters")

    plan_id = getattr(plan, "id", None)
    target = getattr(plan, "target", None)
    if type(plan_id) is not str:
        raise AdminTicketExecutionError("plan id is invalid")
    if type(target) is not str or _TARGET.fullmatch(target) is None or ".." in target or "/" in target:
        raise AdminTicketExecutionError("target is not a safe canonical .service unit")

    steps = getattr(plan, "steps", None)
    if not isinstance(steps, (tuple, list)) or len(steps) != 1:
        raise AdminTicketExecutionError("plan must contain exactly one ticket marker step")
    command = getattr(steps[0], "command", None)
    expected_command = (MARKER_COMMAND, target)
    if command != expected_command:
        raise AdminTicketExecutionError("plan command is not the exact ticket marker")
    if getattr(plan, "rollback_steps", None) != ():
        raise AdminTicketExecutionError("system-service ticket plan must not contain rollback steps")
    if getattr(plan, "verification_steps", None) != ():
        raise AdminTicketExecutionError("system-service ticket plan must not contain verification steps")
    return plan_id, target, expected_command


def _check_receipt_binding(
    receipt: Mapping[str, Any],
    ticket: admin_tickets.AdminExecutionTicket,
    plan_id: str,
    plan_digest: str,
    target: str,
) -> None:
    expected = {
        "ticketId": ticket.ticket_id,
        "planId": plan_id,
        "planDigest": plan_digest,
        "operation": admin_tickets.OPERATION_RESTART_SYSTEM_UNIT,
        "target": target,
    }
    for field, value in expected.items():
        if receipt[field] != value:
            raise AdminTicketExecutionError(f"receipt {field} does not match the ticket and plan")
    if receipt["replayed"] is not False:
        raise AdminTicketExecutionError("fresh authority execution received a replayed receipt")


def execute_system_service_restart_ticket(
    plan: object,
    plan_digest: str,
    *,
    private_key_file: str,
    executor_socket: object,
    expected_key_owner_uid: int | None = None,
    clock: Callable[[], object],
    ticket_id_factory: Callable[[], object],
    nonce_factory: Callable[[], object],
    sender: Callable[[object, bytes], bytes] | None = None,
) -> AdminExecutionResult:
    """Execute one approved restart plan through the signed ticket socket."""

    plan_id, target, command = _validate_plan(plan, plan_digest)
    issued_at = _canonical_utc_second(clock())
    expires_at = issued_at + SHORT_TICKET_LIFETIME
    private_key = admin_tickets.load_private_key(
        private_key_file,
        expected_owner_uid=expected_key_owner_uid,
    )
    raw_ticket = admin_tickets.create_ticket(
        {"planId": plan_id, "planDigest": plan_digest},
        private_key,
        ticket_id=ticket_id_factory(),
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=nonce_factory(),
        target=target,
        operation=admin_tickets.OPERATION_RESTART_SYSTEM_UNIT,
    )
    ticket = admin_tickets.parse_ticket(raw_ticket)
    actual_sender = sender or (
        lambda socket_address, payload: admin_executor.send_ticket(
            socket_address,
            payload,
            expected_peer_uid=0,
        )
    )
    raw_receipt = actual_sender(executor_socket, raw_ticket)
    receipt = _parse_receipt(raw_receipt)
    _check_receipt_binding(receipt, ticket, plan_id, plan_digest, target)

    status = AdminExecutionStatus(receipt["status"])
    exit_code = 0 if status is AdminExecutionStatus.COMPLETED else (
        receipt["restartExitCode"] or receipt["verifyExitCode"]
    )
    command_result = AdminCommandResult(
        title="Execute signed system-service restart ticket",
        command=command,
        exit_code=exit_code,
        stdout=receipt["stdout"],
        stderr=receipt["stderr"],
    )
    return AdminExecutionResult(
        id=f"admin.exec.{plan_id}.{status.value}",
        plan_id=plan_id,
        status=status,
        summary=f"approved system-service restart ticket {status.value}",
        command_results=(command_result,),
        plan_digest=plan_digest,
    )


__all__ = [
    "AdminTicketExecutionError",
    "MARKER_COMMAND",
    "SHORT_TICKET_LIFETIME",
    "SystemServiceTicketExecutionConfig",
    "execute_system_service_restart_ticket",
    "preflight_system_service_ticket_execution",
]
