from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from overseer.admin_tickets import (
    CLOCK_SKEW,
    AdminExecutionTicket,
    AdminTicketError,
    create_ticket,
    load_private_key,
    load_private_key_bytes,
    load_public_key,
    load_public_key_bytes,
    parse_ticket,
    verify_ticket,
)


PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


def _ticket_bytes(**overrides: object) -> bytes:
    values: dict[str, object] = {
        "planId": "plan.restart.1",
        "planDigest": "a" * 64,
    }
    values.update(overrides.pop("plan", {}))  # type: ignore[arg-type]
    return create_ticket(
        values,
        PRIVATE_KEY,
        ticket_id=overrides.pop("ticket_id", "ticket.restart.1"),
        issued_at=overrides.pop("issued_at", "2026-08-26T12:00:00Z"),
        expires_at=overrides.pop("expires_at", "2026-08-26T12:05:00Z"),
        nonce=overrides.pop("nonce", "nonce-1"),
        target=overrides.pop("target", "overseer.service"),
        operation=overrides.pop("operation", "restart-system-unit"),
    )


def _document(raw: bytes) -> dict[str, object]:
    return json.loads(raw)


def test_authority_creates_a_verifiable_restart_ticket() -> None:
    ticket = _ticket_bytes()

    verified = verify_ticket(ticket, PRIVATE_KEY.public_key(), now="2026-08-26T12:01:00Z")

    assert verified.to_dict() == {
        "expiresAt": "2026-08-26T12:05:00Z",
        "issuedAt": "2026-08-26T12:00:00Z",
        "nonce": "nonce-1",
        "operation": "restart-system-unit",
        "planDigest": "a" * 64,
        "planId": "plan.restart.1",
        "schemaVersion": "overseer.admin-execution-ticket.v1",
        "signature": verified.signature,
        "target": "overseer.service",
        "ticketId": "ticket.restart.1",
    }


def test_authority_rejects_a_ticket_lifetime_longer_than_five_minutes() -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))

    with pytest.raises(ValueError, match="lifetime"):
        create_ticket(
            {"planId": "plan.restart.long", "planDigest": "a" * 64},
            private_key,
            ticket_id="ticket.restart.long",
            issued_at="2026-08-26T12:00:00Z",
            expires_at="2026-08-26T12:05:01Z",
            nonce="nonce-long",
            target="overseer-approval-smoke.service",
        )


def test_ticket_schema_and_signing_payload_are_exact_canonical_json() -> None:
    raw = _ticket_bytes()
    document = _document(raw)
    assert set(document) == {
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
    assert list(document) == sorted(document)
    assert raw == json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")

    parsed = parse_ticket(raw)
    unsigned = dict(document)
    unsigned.pop("signature")
    assert parsed.canonical_payload == json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("ascii")
    assert isinstance(parsed, AdminExecutionTicket)
    with pytest.raises(AttributeError):
        parsed.ticket_id = "changed"  # type: ignore[misc]


@pytest.mark.parametrize("field", ["ticketId", "planId", "planDigest", "target", "issuedAt", "expiresAt", "nonce"])
def test_signed_fields_cannot_be_tampered(field: str) -> None:
    document = _document(_ticket_bytes())
    document[field] = {
        "ticketId": "ticket.other",
        "planId": "plan.other",
        "planDigest": "b" * 64,
        "target": "other.service",
        "issuedAt": "2026-08-26T12:00:01Z",
        "expiresAt": "2026-08-26T12:04:59Z",
        "nonce": "nonce-2",
    }[field]
    tampered = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
    with pytest.raises(AdminTicketError, match="signature"):
        verify_ticket(tampered, PRIVATE_KEY.public_key(), now="2026-08-26T12:01:00Z")


def test_signature_tamper_and_wrong_public_key_are_rejected() -> None:
    document = _document(_ticket_bytes())
    signature = bytearray(base64.b64decode(document["signature"], validate=True))
    signature[-1] ^= 1
    document["signature"] = base64.b64encode(signature).decode("ascii")
    tampered = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("ascii")
    with pytest.raises(AdminTicketError, match="signature"):
        verify_ticket(tampered, PRIVATE_KEY.public_key(), now="2026-08-26T12:01:00Z")

    with pytest.raises(AdminTicketError, match="signature"):
        verify_ticket(_ticket_bytes(), Ed25519PrivateKey.generate().public_key(), now="2026-08-26T12:01:00Z")


@pytest.mark.parametrize(
    "raw_factory",
    [
        lambda raw: raw.replace(b'"nonce":"nonce-1"', b'"nonce":"nonce-1","nonce":"nonce-1"'),
        lambda raw: raw.replace(b'"target":"overseer.service"', b'"target":"overseer.service","extra":"reject"'),
        lambda raw: raw.replace(b'"nonce":"nonce-1",', b""),
        lambda raw: raw.replace(b"{\"expiresAt\"", b"{ \"expiresAt\""),
    ],
)
def test_parser_rejects_duplicate_extra_missing_and_noncanonical_json(raw_factory) -> None:
    with pytest.raises(AdminTicketError):
        parse_ticket(raw_factory(_ticket_bytes()))


@pytest.mark.parametrize(
    "field,value",
    [
        ("planId", 7),
        ("planDigest", "A" * 64),
        ("planDigest", "0" * 63),
        ("operation", "start-system-unit"),
        ("target", "../../etc/shadow.service"),
        ("target", "overseer.socket"),
        ("target", "overseer.service/extra"),
        ("ticketId", "ticket with spaces"),
        ("nonce", "nonce with spaces"),
        ("issuedAt", "2026-08-26T12:00:00.000Z"),
        ("expiresAt", "2026-08-26T11:59:00Z"),
        ("signature", "not-base64"),
    ],
)
def test_parser_rejects_noncanonical_field_values(field: str, value: object) -> None:
    document = _document(_ticket_bytes())
    document[field] = value
    raw = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    with pytest.raises(AdminTicketError):
        parse_ticket(raw)


def test_parser_rejects_invalid_utf8_and_oversized_json() -> None:
    with pytest.raises(AdminTicketError):
        parse_ticket(b"{\xff")
    with pytest.raises(AdminTicketError, match="size"):
        parse_ticket(b" " * 4097)


def test_expiration_and_not_yet_validity_allow_only_fixed_skew() -> None:
    with pytest.raises(AdminTicketError, match="expired"):
        verify_ticket(_ticket_bytes(), PRIVATE_KEY.public_key(), now="2026-08-26T12:05:06Z")
    with pytest.raises(AdminTicketError, match="not yet"):
        verify_ticket(_ticket_bytes(), PRIVATE_KEY.public_key(), now="2026-08-26T11:59:54Z")

    skewed = verify_ticket(_ticket_bytes(), PRIVATE_KEY.public_key(), now="2026-08-26T12:05:05Z")
    assert skewed.ticket_id == "ticket.restart.1"
    assert CLOCK_SKEW.total_seconds() == 5


@pytest.mark.parametrize("operation", ["restart-system-unit", "restart-system-unit ", "stop-system-unit"])
def test_authority_allows_only_the_single_supported_operation(operation: str) -> None:
    if operation == "restart-system-unit":
        assert parse_ticket(_ticket_bytes(operation=operation)).operation == operation
    else:
        with pytest.raises(AdminTicketError):
            _ticket_bytes(operation=operation)


def test_key_loaders_require_raw_lengths_owner_mode_regular_single_link_and_no_symlink(tmp_path: Path) -> None:
    owner = os.getuid()
    private_path = tmp_path / "private.key"
    public_path = tmp_path / "public.key"
    private_path.write_bytes(bytes(range(32)))
    public_path.write_bytes(PRIVATE_KEY.public_key().public_bytes_raw())
    os.chmod(private_path, 0o600)
    os.chmod(public_path, 0o644)

    assert load_private_key_bytes(private_path, expected_owner_uid=owner) == bytes(range(32))
    assert load_public_key_bytes(public_path, expected_owner_uid=owner) == PRIVATE_KEY.public_key().public_bytes_raw()
    assert load_private_key(private_path, expected_owner_uid=owner).public_key().public_bytes_raw() == public_path.read_bytes()
    assert load_public_key(public_path, expected_owner_uid=owner).public_bytes_raw() == public_path.read_bytes()

    os.chmod(private_path, 0o640)
    with pytest.raises(AdminTicketError, match="0600"):
        load_private_key_bytes(private_path, expected_owner_uid=owner)
    os.chmod(private_path, 0o600)
    os.chmod(public_path, 0o644)
    with pytest.raises(AdminTicketError, match="owner"):
        load_public_key_bytes(public_path, expected_owner_uid=owner + 1)

    hardlink = tmp_path / "private-hardlink.key"
    hardlink.hardlink_to(private_path)
    with pytest.raises(AdminTicketError, match="single-link"):
        load_private_key_bytes(private_path, expected_owner_uid=owner)

    symlink = tmp_path / "public-symlink.key"
    symlink.symlink_to(public_path)
    with pytest.raises(AdminTicketError, match="symlink"):
        load_public_key_bytes(symlink, expected_owner_uid=owner)


@pytest.mark.parametrize("length", [0, 31, 33])
def test_key_loaders_reject_non_exact_raw_lengths(tmp_path: Path, length: int) -> None:
    path = tmp_path / "key"
    path.write_bytes(b"x" * length)
    os.chmod(path, 0o600)
    with pytest.raises(AdminTicketError, match="exactly 32"):
        load_private_key_bytes(path, expected_owner_uid=os.getuid())
