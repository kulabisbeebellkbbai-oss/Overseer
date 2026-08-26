"""Bounded, signed tickets for a future root-owned admin executor.

This module only creates and verifies inert data.  It does not execute an
operation, inspect systemd, create users, or write key/ticket files.
"""

from __future__ import annotations

import base64
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


SCHEMA_VERSION = "overseer.admin-execution-ticket.v1"
OPERATION_RESTART_SYSTEM_UNIT = "restart-system-unit"
MAX_TICKET_BYTES = 4096
ED25519_RAW_KEY_BYTES = 32
ED25519_SIGNATURE_BYTES = 64
MAX_IDENTIFIER_LENGTH = 128
MAX_TARGET_LENGTH = 192
MAX_NONCE_LENGTH = 128
CLOCK_SKEW = timedelta(seconds=5)
MAX_TICKET_LIFETIME = timedelta(minutes=5)

_FIELDS = frozenset(
    {
        "schemaVersion",
        "ticketId",
        "planId",
        "planDigest",
        "operation",
        "target",
        "issuedAt",
        "expiresAt",
        "nonce",
        "signature",
    }
)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_NONCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~:-]{0,127}$")
_UNIT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@%_.:-]{0,190}\.service$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class AdminTicketError(ValueError):
    """Raised when a ticket or key violates its strict contract."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AdminTicketError(f"duplicate ticket key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise AdminTicketError(f"non-finite JSON number: {value}")


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            dict(value),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise AdminTicketError("ticket cannot be canonically encoded") from error


def _decode_canonical_base64(value: object, field: str, expected_length: int) -> bytes:
    if type(value) is not str:
        raise AdminTicketError(f"{field} must be a base64 string")
    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, ValueError):
        raise AdminTicketError(f"{field} is not canonical base64") from None
    if base64.b64encode(decoded) != encoded:
        raise AdminTicketError(f"{field} is not canonical base64")
    if len(decoded) != expected_length:
        raise AdminTicketError(f"{field} has an invalid length")
    return decoded


def _validate_identifier(value: object, field: str) -> str:
    if type(value) is not str or len(value) > MAX_IDENTIFIER_LENGTH or not _IDENTIFIER.fullmatch(value):
        raise AdminTicketError(f"{field} is malformed")
    return value


def _validate_nonce(value: object) -> str:
    if type(value) is not str or len(value) > MAX_NONCE_LENGTH or not _NONCE.fullmatch(value):
        raise AdminTicketError("nonce is malformed")
    return value


def _validate_timestamp(value: object, field: str) -> datetime:
    if type(value) is not str or not _TIMESTAMP.fullmatch(value):
        raise AdminTicketError(f"{field} is not a canonical UTC timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise AdminTicketError(f"{field} is not a valid UTC timestamp") from error
    return parsed.replace(tzinfo=timezone.utc)


def _timestamp_input(value: object, field: str) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None or value.microsecond:
            raise AdminTicketError(f"{field} must be an aware, whole-second timestamp")
        utc_value = value.astimezone(timezone.utc)
        result = utc_value.strftime("%Y-%m-%dT%H:%M:%SZ")
        _validate_timestamp(result, field)
        return result
    if type(value) is str:
        _validate_timestamp(value, field)
        return value
    raise AdminTicketError(f"{field} must be a UTC timestamp string")


def _validate_target(value: object) -> str:
    if (
        type(value) is not str
        or len(value) > MAX_TARGET_LENGTH
        or not _UNIT.fullmatch(value)
        or ".." in value
        or "/" in value
    ):
        raise AdminTicketError("target is not a safe canonical .service unit")
    return value


def _validate_document(document: Mapping[str, Any]) -> None:
    if set(document) != _FIELDS:
        raise AdminTicketError("ticket has unsupported or missing keys")
    if any(type(value) is not str for value in document.values()):
        raise AdminTicketError("ticket fields must all be strings")
    if document["schemaVersion"] != SCHEMA_VERSION:
        raise AdminTicketError("unsupported ticket schema version")
    _validate_identifier(document["ticketId"], "ticketId")
    _validate_identifier(document["planId"], "planId")
    if not _HEX_DIGEST.fullmatch(document["planDigest"]):
        raise AdminTicketError("planDigest must be 64 lowercase hexadecimal characters")
    if document["operation"] != OPERATION_RESTART_SYSTEM_UNIT:
        raise AdminTicketError("unsupported ticket operation")
    _validate_target(document["target"])
    issued = _validate_timestamp(document["issuedAt"], "issuedAt")
    expires = _validate_timestamp(document["expiresAt"], "expiresAt")
    if expires <= issued:
        raise AdminTicketError("expiresAt must be after issuedAt")
    if expires - issued > MAX_TICKET_LIFETIME:
        raise AdminTicketError("ticket lifetime exceeds the maximum")
    _validate_nonce(document["nonce"])
    _decode_canonical_base64(document["signature"], "signature", ED25519_SIGNATURE_BYTES)


def _document_from_bytes(raw: bytes) -> dict[str, str]:
    if type(raw) is not bytes:
        raise AdminTicketError("ticket must be UTF-8 JSON bytes")
    if len(raw) > MAX_TICKET_BYTES:
        raise AdminTicketError("ticket exceeds the maximum size")
    try:
        text = raw.decode("utf-8")
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except AdminTicketError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdminTicketError("ticket must be valid UTF-8 JSON") from error
    if type(document) is not dict:
        raise AdminTicketError("ticket must be a JSON object")
    _validate_document(document)
    if _canonical_json(document) != raw:
        raise AdminTicketError("ticket JSON is not canonical")
    return document


def _private_key(value: object) -> Ed25519PrivateKey:
    if isinstance(value, Ed25519PrivateKey):
        return value
    if type(value) is bytes and len(value) == ED25519_RAW_KEY_BYTES:
        try:
            return Ed25519PrivateKey.from_private_bytes(value)
        except ValueError as error:
            raise AdminTicketError("invalid Ed25519 private key") from error
    raise AdminTicketError("Ed25519 private key must be a raw 32-byte key")


def _public_key(value: object) -> Ed25519PublicKey:
    if isinstance(value, Ed25519PublicKey):
        return value
    if type(value) is bytes and len(value) == ED25519_RAW_KEY_BYTES:
        try:
            return Ed25519PublicKey.from_public_bytes(value)
        except ValueError as error:
            raise AdminTicketError("invalid Ed25519 public key") from error
    raise AdminTicketError("Ed25519 public key must be a raw 32-byte key")


def _plan_value(plan: Mapping[str, object] | object, *names: str) -> object:
    if isinstance(plan, Mapping):
        for name in names:
            if name in plan:
                return plan[name]
    else:
        for name in names:
            if hasattr(plan, name):
                return getattr(plan, name)
    raise AdminTicketError(f"plan metadata is missing {names[0]}")


def _ticket_document(
    plan: Mapping[str, object] | object,
    private_key: object,
    *,
    ticket_id: object,
    issued_at: object,
    expires_at: object,
    nonce: object,
    target: object,
    operation: object = OPERATION_RESTART_SYSTEM_UNIT,
) -> dict[str, str]:
    unsigned = {
        "schemaVersion": SCHEMA_VERSION,
        "ticketId": _validate_identifier(ticket_id, "ticketId"),
        "planId": _validate_identifier(_plan_value(plan, "planId", "plan_id", "id"), "planId"),
        "planDigest": str(_plan_value(plan, "planDigest", "plan_digest", "digest")),
        "operation": operation,
        "target": _validate_target(target),
        "issuedAt": _timestamp_input(issued_at, "issuedAt"),
        "expiresAt": _timestamp_input(expires_at, "expiresAt"),
        "nonce": _validate_nonce(nonce),
    }
    if type(operation) is not str or operation != OPERATION_RESTART_SYSTEM_UNIT:
        raise AdminTicketError("unsupported ticket operation")
    if not _HEX_DIGEST.fullmatch(unsigned["planDigest"]):
        raise AdminTicketError("planDigest must be 64 lowercase hexadecimal characters")
    issued = _validate_timestamp(unsigned["issuedAt"], "issuedAt")
    expires = _validate_timestamp(unsigned["expiresAt"], "expiresAt")
    if expires <= issued:
        raise AdminTicketError("expiresAt must be after issuedAt")
    if expires - issued > MAX_TICKET_LIFETIME:
        raise AdminTicketError("ticket lifetime exceeds the maximum")
    signature = _private_key(private_key).sign(_canonical_json(unsigned))
    document = {**unsigned, "signature": base64.b64encode(signature).decode("ascii")}
    _validate_document(document)
    return document


@dataclass(frozen=True, slots=True)
class AdminExecutionTicket:
    """Immutable parsed ticket whose signature has been checked by the caller."""

    schema_version: str
    ticket_id: str
    plan_id: str
    plan_digest: str
    operation: str
    target: str
    issued_at: str
    expires_at: str
    nonce: str
    signature: str

    def __post_init__(self) -> None:
        _validate_document(self.to_dict())

    def to_dict(self) -> dict[str, str]:
        return {
            "schemaVersion": self.schema_version,
            "ticketId": self.ticket_id,
            "planId": self.plan_id,
            "planDigest": self.plan_digest,
            "operation": self.operation,
            "target": self.target,
            "issuedAt": self.issued_at,
            "expiresAt": self.expires_at,
            "nonce": self.nonce,
            "signature": self.signature,
        }

    @property
    def canonical_payload(self) -> bytes:
        document = self.to_dict()
        document.pop("signature")
        return _canonical_json(document)

    def to_bytes(self) -> bytes:
        return _canonical_json(self.to_dict())


def _ticket_from_document(document: Mapping[str, str]) -> AdminExecutionTicket:
    return AdminExecutionTicket(
        schema_version=document["schemaVersion"],
        ticket_id=document["ticketId"],
        plan_id=document["planId"],
        plan_digest=document["planDigest"],
        operation=document["operation"],
        target=document["target"],
        issued_at=document["issuedAt"],
        expires_at=document["expiresAt"],
        nonce=document["nonce"],
        signature=document["signature"],
    )


def create_ticket(
    plan: Mapping[str, object] | object,
    private_key: object,
    *,
    ticket_id: object,
    issued_at: object,
    expires_at: object,
    nonce: object,
    target: object,
    operation: object = OPERATION_RESTART_SYSTEM_UNIT,
) -> bytes:
    """Create canonical ticket bytes from plan metadata and an Ed25519 key."""

    return _canonical_json(
        _ticket_document(
            plan,
            private_key,
            ticket_id=ticket_id,
            issued_at=issued_at,
            expires_at=expires_at,
            nonce=nonce,
            target=target,
            operation=operation,
        )
    )


issue_ticket = create_ticket


def parse_ticket(raw: bytes) -> AdminExecutionTicket:
    """Parse and structurally validate one canonical bounded ticket."""

    return _ticket_from_document(_document_from_bytes(raw))


def verify_ticket(
    raw: bytes,
    public_key: object,
    *,
    now: object | None = None,
) -> AdminExecutionTicket:
    """Parse, verify the signature, and enforce the bounded validity window."""

    ticket = parse_ticket(raw)
    key = _public_key(public_key)
    try:
        key.verify(_decode_canonical_base64(ticket.signature, "signature", ED25519_SIGNATURE_BYTES), ticket.canonical_payload)
    except InvalidSignature as error:
        raise AdminTicketError("ticket signature is invalid") from error
    current = _timestamp_input(
        datetime.now(timezone.utc).replace(microsecond=0) if now is None else now,
        "now",
    )
    current_time = _validate_timestamp(current, "now")
    issued = _validate_timestamp(ticket.issued_at, "issuedAt")
    expires = _validate_timestamp(ticket.expires_at, "expiresAt")
    if current_time < issued - CLOCK_SKEW:
        raise AdminTicketError("ticket is not yet valid")
    if current_time > expires + CLOCK_SKEW:
        raise AdminTicketError("ticket has expired")
    return ticket


parse_and_verify_ticket = verify_ticket


def _validate_key_metadata(metadata: os.stat_result, expected_owner_uid: int, expected_mode: int, label: str) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise AdminTicketError(f"{label} is not a regular file")
    if metadata.st_nlink != 1:
        raise AdminTicketError(f"{label} must be a single-link file")
    if metadata.st_uid != expected_owner_uid:
        raise AdminTicketError(f"{label} has an unexpected owner")
    if stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise AdminTicketError(f"{label} must have mode {expected_mode:04o}")


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _read_raw_key(path: str | os.PathLike[str], *, owner_uid: int, mode: int, label: str) -> bytes:
    try:
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode):
            raise AdminTicketError(f"{label} must not be a symlink")
        _validate_key_metadata(before, owner_uid, mode, label)
        if before.st_size != ED25519_RAW_KEY_BYTES:
            raise AdminTicketError(f"{label} must contain exactly 32 raw bytes")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            _validate_key_metadata(opened, owner_uid, mode, label)
            if not _same_inode(before, opened):
                raise AdminTicketError(f"{label} changed while opening")
            data = os.read(descriptor, ED25519_RAW_KEY_BYTES + 1)
            if len(data) != ED25519_RAW_KEY_BYTES:
                raise AdminTicketError(f"{label} must contain exactly 32 raw bytes")
            after = os.fstat(descriptor)
            lexical_after = os.lstat(path)
            _validate_key_metadata(after, owner_uid, mode, label)
            _validate_key_metadata(lexical_after, owner_uid, mode, label)
            if not _same_inode(opened, after) or not _same_inode(before, lexical_after):
                raise AdminTicketError(f"{label} changed while reading")
            if after.st_size != ED25519_RAW_KEY_BYTES or lexical_after.st_size != ED25519_RAW_KEY_BYTES:
                raise AdminTicketError(f"{label} must contain exactly 32 raw bytes")
            return data
        finally:
            os.close(descriptor)
    except AdminTicketError:
        raise
    except OSError as error:
        raise AdminTicketError(f"could not safely read {label}") from error


def _owner_uid(value: object, default: int) -> int:
    result = default if value is None else value
    if type(result) is not int or result < 0:
        raise AdminTicketError("expected owner UID is invalid")
    return result


def load_private_key_bytes(path: str | Path, *, expected_owner_uid: int | None = None) -> bytes:
    """Load exactly one raw Ed25519 private key from an owned 0600 file."""

    return _read_raw_key(
        path,
        owner_uid=_owner_uid(expected_owner_uid, os.geteuid()),
        mode=0o600,
        label="private key",
    )


def load_public_key_bytes(path: str | Path, *, expected_owner_uid: int | None = 0) -> bytes:
    """Load exactly one raw Ed25519 public key from an owned root-mode 0644 file."""

    return _read_raw_key(
        path,
        owner_uid=_owner_uid(expected_owner_uid, 0),
        mode=0o644,
        label="public key",
    )


def load_private_key(path: str | Path, *, expected_owner_uid: int | None = None) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(load_private_key_bytes(path, expected_owner_uid=expected_owner_uid))


def load_public_key(path: str | Path, *, expected_owner_uid: int | None = 0) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(load_public_key_bytes(path, expected_owner_uid=expected_owner_uid))


__all__ = [
    "AdminExecutionTicket",
    "AdminTicketError",
    "CLOCK_SKEW",
    "ED25519_RAW_KEY_BYTES",
    "ED25519_SIGNATURE_BYTES",
    "MAX_TICKET_BYTES",
    "MAX_TICKET_LIFETIME",
    "OPERATION_RESTART_SYSTEM_UNIT",
    "SCHEMA_VERSION",
    "create_ticket",
    "issue_ticket",
    "load_private_key",
    "load_private_key_bytes",
    "load_public_key",
    "load_public_key_bytes",
    "parse_and_verify_ticket",
    "parse_ticket",
    "verify_ticket",
]
