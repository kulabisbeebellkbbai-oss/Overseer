"""Fail-closed one-shot executor for signed, allowlisted system-unit tickets."""

from __future__ import annotations

import argparse
import json
import os
import pwd
import socket
import sqlite3
import stat
import struct
import subprocess
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import admin_tickets


ALLOWLIST_SCHEMA_VERSION = "overseer.admin-executor-allowlist.v1"
RECEIPT_SCHEMA_VERSION = "overseer.admin-execution-receipt.v1"
ERROR_SCHEMA_VERSION = "overseer.admin-executor-error.v1"
MAX_ALLOWLIST_BYTES = 4096
MAX_RECEIPT_BYTES = 8192
MAX_SOCKET_BYTES = 4096
MAX_OUTPUT_BYTES = 2048
_UNIT_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@%_.:-")


class AdminExecutorError(ValueError):
    """Raised for a rejected request or an unsafe executor state."""


def _duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AdminExecutorError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise AdminExecutorError(f"non-finite JSON number: {value}")


def _canonical_json(value: Mapping[str, Any], *, label: str) -> bytes:
    try:
        return json.dumps(
            dict(value), ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as error:
        raise AdminExecutorError(f"{label} is not canonical JSON") from error


def _parse_canonical(
    raw: bytes, *, limit: int, label: str, require_canonical: bool = True
) -> dict[str, Any]:
    if type(raw) is not bytes or len(raw) > limit:
        raise AdminExecutorError(f"{label} exceeds the maximum size")
    try:
        document = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_duplicate_keys, parse_constant=_reject_constant
        )
    except AdminExecutorError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdminExecutorError(f"{label} must be bounded UTF-8 JSON") from error
    if type(document) is not dict:
        raise AdminExecutorError(f"{label} must be a JSON object")
    if require_canonical and _canonical_json(document, label=label) != raw:
        raise AdminExecutorError(f"{label} JSON is not canonical")
    return document


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _same_read_state(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        _same_inode(left, right)
        and left.st_uid == right.st_uid
        and left.st_mode == right.st_mode
        and left.st_nlink == right.st_nlink
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
        and left.st_ctime_ns == right.st_ctime_ns
    )


def _check_file_metadata(metadata: os.stat_result, *, owner_uid: int, mode: int, label: str) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise AdminExecutorError(f"{label} is not a regular file")
    if metadata.st_nlink != 1:
        raise AdminExecutorError(f"{label} must be a single-link file")
    if metadata.st_uid != owner_uid:
        raise AdminExecutorError(f"{label} has an unexpected owner")
    if stat.S_IMODE(metadata.st_mode) != mode:
        raise AdminExecutorError(f"{label} must have mode {mode:04o}")


def _stable_read(path: str | os.PathLike[str], *, owner_uid: int, mode: int, limit: int, label: str) -> bytes:
    try:
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode):
            raise AdminExecutorError(f"{label} must not be a symlink")
        _check_file_metadata(before, owner_uid=owner_uid, mode=mode, label=label)
        if before.st_size > limit:
            raise AdminExecutorError(f"{label} exceeds the maximum size")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            _check_file_metadata(opened, owner_uid=owner_uid, mode=mode, label=label)
            if not _same_read_state(before, opened):
                raise AdminExecutorError(f"{label} changed while opening")
            data = bytearray()
            while len(data) <= limit:
                chunk = os.read(descriptor, min(4096, limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            after = os.fstat(descriptor)
            lexical_after = os.lstat(path)
            _check_file_metadata(after, owner_uid=owner_uid, mode=mode, label=label)
            _check_file_metadata(lexical_after, owner_uid=owner_uid, mode=mode, label=label)
            if not _same_read_state(opened, after) or not _same_read_state(before, lexical_after):
                raise AdminExecutorError(f"{label} changed while reading")
            if len(data) > limit:
                raise AdminExecutorError(f"{label} exceeds the maximum size")
            return bytes(data)
        finally:
            os.close(descriptor)
    except AdminExecutorError:
        raise
    except OSError as error:
        raise AdminExecutorError(f"could not safely read {label}") from error


def _safe_unit(value: object) -> bool:
    if type(value) is not str or not value.endswith(".service") or len(value) > 192:
        return False
    stem = value[:-8]
    return (
        bool(stem)
        and value[0].isalnum()
        and ".." not in value
        and "/" not in value
        and all(char in _UNIT_CHARS for char in value)
    )


def load_allowlist(path: str | os.PathLike[str], *, expected_owner_uid: int = 0) -> set[tuple[str, str]]:
    """Load the exact root-owned allowlist schema."""

    raw = _stable_read(path, owner_uid=expected_owner_uid, mode=0o644, limit=MAX_ALLOWLIST_BYTES, label="allowlist")
    document = _parse_canonical(raw, limit=MAX_ALLOWLIST_BYTES, label="allowlist", require_canonical=False)
    if set(document) != {"schemaVersion", "allowed"} or document["schemaVersion"] != ALLOWLIST_SCHEMA_VERSION:
        raise AdminExecutorError("allowlist schema is unsupported")
    allowed = document["allowed"]
    if type(allowed) is not list:
        raise AdminExecutorError("allowlist allowed must be an array")
    result: set[tuple[str, str]] = set()
    for entry in allowed:
        if type(entry) is not dict or set(entry) != {"operation", "unit"}:
            raise AdminExecutorError("allowlist entry schema is invalid")
        operation, unit = entry["operation"], entry["unit"]
        if operation != admin_tickets.OPERATION_RESTART_SYSTEM_UNIT or not _safe_unit(unit):
            raise AdminExecutorError("allowlist entry is unsafe")
        pair = (operation, unit)
        if pair in result:
            raise AdminExecutorError("allowlist contains duplicate entries")
        result.add(pair)
    return result


def _owner_uid(value: int | None, default: int) -> int:
    result = default if value is None else value
    if type(result) is not int or result < 0:
        raise AdminExecutorError("owner UID is invalid")
    return result


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _bounded_text(value: object, *, limit: int = MAX_OUTPUT_BYTES) -> str:
    if isinstance(value, str):
        encoded = value.encode("utf-8", errors="replace")
    elif isinstance(value, bytes):
        encoded = value
    else:
        encoded = b"" if value is None else str(value).encode("utf-8", errors="replace")
    return encoded[:limit].decode("utf-8", errors="replace")


def _result(result: object) -> tuple[int, object, object]:
    if isinstance(result, subprocess.CompletedProcess):
        return int(result.returncode), result.stdout, result.stderr
    if isinstance(result, Mapping):
        return int(result["returncode"]), result.get("stdout", b""), result.get("stderr", b"")
    if isinstance(result, tuple) and len(result) == 3:
        return int(result[0]), result[1], result[2]
    raise AdminExecutorError("systemctl runner returned an invalid result")


def _default_runner(argv: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        list(argv),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        shell=False,
        timeout=30,
    )


def _validate_receipt(document: Mapping[str, Any]) -> None:
    fields = {
        "schemaVersion", "ticketId", "planId", "planDigest", "operation", "target", "status",
        "restartExitCode", "verifyExitCode", "stdout", "stderr", "replayed",
    }
    if set(document) != fields or document.get("schemaVersion") != RECEIPT_SCHEMA_VERSION:
        raise AdminExecutorError("stored receipt schema is invalid")
    if document.get("status") not in {"completed", "failed"} or type(document.get("replayed")) is not bool:
        raise AdminExecutorError("stored receipt status is invalid")
    if type(document.get("restartExitCode")) is not int or type(document.get("verifyExitCode")) is not int:
        raise AdminExecutorError("stored receipt exit codes are invalid")
    if type(document.get("stdout")) is not str or type(document.get("stderr")) is not str:
        raise AdminExecutorError("stored receipt output is invalid")


class _Ledger:
    def __init__(self, path: str | os.PathLike[str], *, owner_uid: int) -> None:
        self.path = Path(path)
        self._check_parent(owner_uid)
        self._ensure_database(owner_uid)
        try:
            self.db = sqlite3.connect(str(self.path), timeout=0, isolation_level=None)
            self.db.execute("PRAGMA busy_timeout=0")
            self.db.execute("PRAGMA journal_mode=DELETE")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute(
                "CREATE TABLE IF NOT EXISTS admin_executions ("
                "ticket_id TEXT PRIMARY KEY, nonce TEXT NOT NULL UNIQUE, plan_id TEXT NOT NULL, "
                "plan_digest TEXT NOT NULL, target TEXT NOT NULL, state TEXT NOT NULL, "
                "claimed_at TEXT NOT NULL, terminal_receipt TEXT)"
            )
        except sqlite3.Error as error:
            raise AdminExecutorError("ledger is unavailable") from error

    def _check_parent(self, owner_uid: int) -> None:
        try:
            metadata = os.lstat(self.path.parent)
        except OSError as error:
            raise AdminExecutorError("ledger parent is unavailable") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise AdminExecutorError("ledger parent must be a regular non-symlink directory")
        if metadata.st_uid != owner_uid:
            raise AdminExecutorError("ledger parent has an unexpected owner")
        if stat.S_IMODE(metadata.st_mode) != 0o700:
            raise AdminExecutorError("ledger parent must have mode 0700")

    def _ensure_database(self, owner_uid: int) -> None:
        try:
            if self.path.exists() or self.path.is_symlink():
                metadata = os.lstat(self.path)
                if stat.S_ISLNK(metadata.st_mode):
                    raise AdminExecutorError("ledger must not be a symlink")
                _check_file_metadata(metadata, owner_uid=owner_uid, mode=0o600, label="ledger")
            else:
                flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(self.path, flags, 0o600)
                os.close(descriptor)
            metadata = os.lstat(self.path)
            _check_file_metadata(metadata, owner_uid=owner_uid, mode=0o600, label="ledger")
        except AdminExecutorError:
            raise
        except OSError as error:
            raise AdminExecutorError("ledger is not a safe owner-only database") from error

    def claim(self, ticket: admin_tickets.AdminExecutionTicket, claimed_at: str) -> tuple[str, dict[str, Any] | None]:
        try:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT ticket_id, nonce, plan_id, plan_digest, target, state, terminal_receipt "
                "FROM admin_executions WHERE ticket_id=? OR nonce=?", (ticket.ticket_id, ticket.nonce)
            ).fetchall()
            if row:
                if len(row) != 1:
                    raise AdminExecutorError("ledger conflict requires reconciliation")
                existing = row[0]
                if existing[0] != ticket.ticket_id:
                    raise AdminExecutorError("nonce is already used by another ticket")
                if existing[1:5] != (ticket.nonce, ticket.plan_id, ticket.plan_digest, ticket.target):
                    raise AdminExecutorError("ticket identity conflicts and requires reconciliation")
                if existing[5] in {"completed", "failed"}:
                    if not existing[6]:
                        raise AdminExecutorError("terminal ledger receipt is missing")
                    stored = _parse_canonical(existing[6].encode("utf-8"), limit=MAX_RECEIPT_BYTES, label="receipt")
                    _validate_receipt(stored)
                    self.db.execute("COMMIT")
                    return "replay", stored
                raise AdminExecutorError("ticket is claimed and requires reconciliation")
            self.db.execute(
                "INSERT INTO admin_executions(ticket_id, nonce, plan_id, plan_digest, target, state, claimed_at, terminal_receipt) "
                "VALUES (?, ?, ?, ?, ?, 'claimed', ?, NULL)",
                (ticket.ticket_id, ticket.nonce, ticket.plan_id, ticket.plan_digest, ticket.target, claimed_at),
            )
            self.db.execute("COMMIT")
            return "claimed", None
        except AdminExecutorError:
            self.db.execute("ROLLBACK")
            raise
        except sqlite3.IntegrityError as error:
            self.db.execute("ROLLBACK")
            raise AdminExecutorError("ledger conflict requires reconciliation") from error
        except sqlite3.Error as error:
            self.db.execute("ROLLBACK")
            raise AdminExecutorError("ledger claim failed") from error

    def settle(self, ticket_id: str, receipt: bytes, status: str) -> None:
        try:
            self.db.execute("BEGIN IMMEDIATE")
            updated = self.db.execute(
                "UPDATE admin_executions SET state=?, terminal_receipt=? WHERE ticket_id=? AND state='claimed'",
                (status, receipt.decode("utf-8"), ticket_id),
            ).rowcount
            if updated != 1:
                raise AdminExecutorError("ledger settlement requires reconciliation")
            self.db.execute("COMMIT")
        except AdminExecutorError:
            self.db.execute("ROLLBACK")
            raise
        except sqlite3.Error as error:
            self.db.execute("ROLLBACK")
            raise AdminExecutorError("ledger settlement failed") from error

    def close(self) -> None:
        self.db.close()


class AdminExecutor:
    def __init__(
        self,
        *,
        allowlist_file: str | os.PathLike[str],
        public_key_file: str | os.PathLike[str],
        ledger: str | os.PathLike[str],
        expected_owner_uid: int = 0,
        runner: Callable[[Sequence[str]], object] | None = None,
        clock: Callable[[], str] = _utc_now,
    ) -> None:
        self.allowed = load_allowlist(allowlist_file, expected_owner_uid=expected_owner_uid)
        try:
            self.public_key = admin_tickets.load_public_key(
                public_key_file, expected_owner_uid=expected_owner_uid
            )
        except admin_tickets.AdminTicketError as error:
            raise AdminExecutorError("public key is unsafe") from error
        self.ledger = _Ledger(ledger, owner_uid=expected_owner_uid)
        self.runner = runner or _default_runner
        self.clock = clock

    def close(self) -> None:
        self.ledger.close()

    def execute(self, raw_ticket: bytes, *, now: object | None = None) -> dict[str, Any]:
        try:
            ticket = admin_tickets.verify_ticket(raw_ticket, self.public_key, now=self.clock() if now is None else now)
        except admin_tickets.AdminTicketError as error:
            raise AdminExecutorError("ticket verification failed") from error
        if (ticket.operation, ticket.target) not in self.allowed:
            raise AdminExecutorError("ticket operation and target are not allowlisted")
        mode, stored = self.ledger.claim(ticket, self.clock())
        if mode == "replay":
            assert stored is not None
            return {**stored, "replayed": True}

        restart = ("/usr/bin/systemctl", "restart", "--", ticket.target)
        verify = ("/usr/bin/systemctl", "is-active", "--quiet", "--", ticket.target)
        restart_code, restart_out, restart_err = _result(self.runner(list(restart)))
        verify_code, verify_out, verify_err = _result(self.runner(list(verify)))
        receipt: dict[str, Any] = {
            "schemaVersion": RECEIPT_SCHEMA_VERSION,
            "ticketId": ticket.ticket_id,
            "planId": ticket.plan_id,
            "planDigest": ticket.plan_digest,
            "operation": ticket.operation,
            "target": ticket.target,
            "status": "completed" if restart_code == 0 and verify_code == 0 else "failed",
            "restartExitCode": restart_code,
            "verifyExitCode": verify_code,
            "stdout": _bounded_text(restart_out) + _bounded_text(verify_out),
            "stderr": _bounded_text(restart_err) + _bounded_text(verify_err),
            "replayed": False,
        }
        _validate_receipt(receipt)
        encoded = _canonical_json(receipt, label="receipt")
        if len(encoded) > MAX_RECEIPT_BYTES:
            raise AdminExecutorError("receipt exceeds the maximum size")
        self.ledger.settle(ticket.ticket_id, encoded, receipt["status"])
        return receipt


def execute_ticket(
    raw_ticket: bytes,
    *,
    allowlist_file: str | os.PathLike[str],
    public_key_file: str | os.PathLike[str],
    ledger: str | os.PathLike[str],
    expected_owner_uid: int = 0,
    runner: Callable[[Sequence[str]], object] | None = None,
    now: object | None = None,
) -> dict[str, Any]:
    executor = AdminExecutor(
        allowlist_file=allowlist_file,
        public_key_file=public_key_file,
        ledger=ledger,
        expected_owner_uid=expected_owner_uid,
        runner=runner,
        clock=_utc_now,
    )
    try:
        return executor.execute(raw_ticket, now=now)
    finally:
        executor.close()


def _read_socket(sock: socket.socket, limit: int) -> bytes:
    data = bytearray()
    while len(data) <= limit:
        chunk = sock.recv(min(4096, limit + 1 - len(data)))
        if not chunk:
            return bytes(data)
        data.extend(chunk)
    raise AdminExecutorError("socket request exceeds the maximum size")


def _error_bytes() -> bytes:
    return _canonical_json({"schemaVersion": ERROR_SCHEMA_VERSION, "error": "request rejected"}, label="error")


def send_ticket(socket_address: str | os.PathLike[str] | socket.socket, raw_ticket: bytes) -> bytes:
    """Send canonical ticket bytes and read one bounded canonical response."""

    try:
        ticket = admin_tickets.parse_ticket(raw_ticket)
        payload = ticket.to_bytes()
    except admin_tickets.AdminTicketError as error:
        raise AdminExecutorError("ticket is not canonical") from error
    if len(payload) > MAX_SOCKET_BYTES:
        raise AdminExecutorError("ticket exceeds the socket limit")
    owned = isinstance(socket_address, (str, os.PathLike))
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) if owned else socket_address
    try:
        if owned:
            sock.connect(os.fspath(socket_address))
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
        response = _read_socket(sock, MAX_RECEIPT_BYTES)
        _parse_canonical(response, limit=MAX_RECEIPT_BYTES, label="receipt")
        return response
    finally:
        if owned:
            sock.close()


def serve_one(
    socket_fd: int | socket.socket = 0,
    *,
    allowlist_file: str | os.PathLike[str],
    public_key_file: str | os.PathLike[str],
    ledger: str | os.PathLike[str],
    authority_uid: int,
    expected_owner_uid: int = 0,
    runner: Callable[[Sequence[str]], object] | None = None,
    now: object | None = None,
) -> int:
    """Serve exactly one systemd Accept=yes connection without traceback output."""

    owned = isinstance(socket_fd, int)
    sock = socket.socket(fileno=os.dup(socket_fd)) if owned else socket_fd
    try:
        _pid, peer_uid, _gid = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if peer_uid != authority_uid:
            raise AdminExecutorError("socket peer is not the authority")
        raw = _read_socket(sock, MAX_SOCKET_BYTES)
        response = execute_ticket(
            raw,
            allowlist_file=allowlist_file,
            public_key_file=public_key_file,
            ledger=ledger,
            expected_owner_uid=expected_owner_uid,
            runner=runner,
            now=now,
        )
        encoded = _canonical_json(response, label="receipt")
    except Exception:
        encoded = _error_bytes()
    try:
        sock.sendall(encoded[:MAX_RECEIPT_BYTES])
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
    finally:
        if owned:
            sock.close()
    return 0


def _cli(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m overseer.admin_executor")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve-one")
    serve.add_argument("--allowlist-file", required=True)
    serve.add_argument("--public-key-file", required=True)
    serve.add_argument("--ledger", required=True)
    serve.add_argument("--authority-user", default="overseer")
    args = parser.parse_args(argv)
    if args.command != "serve-one":
        return 2
    try:
        authority_uid = pwd.getpwnam(args.authority_user).pw_uid
    except KeyError:
        return 2
    return serve_one(
        0,
        allowlist_file=args.allowlist_file,
        public_key_file=args.public_key_file,
        ledger=args.ledger,
        authority_uid=authority_uid,
        expected_owner_uid=0,
    )


def main(argv: Sequence[str] | None = None) -> int:
    return _cli(argv)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ALLOWLIST_SCHEMA_VERSION",
    "AdminExecutor",
    "AdminExecutorError",
    "MAX_ALLOWLIST_BYTES",
    "MAX_OUTPUT_BYTES",
    "MAX_RECEIPT_BYTES",
    "RECEIPT_SCHEMA_VERSION",
    "execute_ticket",
    "load_allowlist",
    "main",
    "send_ticket",
    "serve_one",
]
