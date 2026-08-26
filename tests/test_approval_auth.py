from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

import overseer.approval_auth as approval_auth
from overseer.approval_auth import (
    MAX_APPROVAL_DOCUMENT_BYTES,
    MAX_BEARER_SECRET_BYTES,
    MIN_BEARER_SECRET_BYTES,
    ApprovalVerifier,
    authenticate_bearer_secret,
    create_approval_document,
    load_approval_verifier,
)


def _write_document(path: Path, document: dict[str, object], *, mode: int = 0o600) -> None:
    path.write_bytes(json.dumps(document, separators=(",", ":")).encode("utf-8"))
    os.chmod(path, mode)


def _document(secret: str = "correct-horse-battery-staple", scope: str = "admin-plan-approval"):
    return create_approval_document(secret, scope)


def test_valid_document_round_trips_without_storing_plaintext(tmp_path: Path) -> None:
    document = _document()
    assert list(tmp_path.iterdir()) == []
    assert set(document) == {"version", "scope", "identity", "kdf", "salt", "digest"}
    assert document["version"] == 1
    assert document["scope"] == "admin-plan-approval"
    assert document["identity"] == "sisko"
    assert document["kdf"] == "scrypt"
    assert len(base64.b64decode(document["salt"], validate=True)) == 16
    assert len(base64.b64decode(document["digest"], validate=True)) == 32
    assert "correct-horse-battery-staple" not in json.dumps(document)

    path = tmp_path / "approval.json"
    _write_document(path, document)
    verifier = load_approval_verifier(path)

    assert isinstance(verifier, ApprovalVerifier)
    assert verifier.version == 1
    assert verifier.scope == "admin-plan-approval"
    assert verifier.identity == "sisko"
    assert verifier.kdf == "scrypt"
    assert len(verifier.salt) == 16
    assert len(verifier.digest) == 32
    assert verifier.authenticate("wrong-secret") is None
    assert verifier.verify("wrong-secret") is False
    assert verifier.authenticate("correct-horse-battery-staple") == "sisko"
    assert verifier.verify("correct-horse-battery-staple") is True
    assert verifier.authenticate_bearer_header("Bearer correct-horse-battery-staple") == "sisko"
    assert verifier.authenticate_bearer_header("bearer correct-horse-battery-staple") is None
    assert authenticate_bearer_secret(verifier, "correct-horse-battery-staple") == "sisko"

    with pytest.raises(AttributeError):
        verifier.identity = "obrien"  # type: ignore[misc]


def test_supported_scopes_bind_server_owned_identities(tmp_path: Path) -> None:
    expected = {
        "admin-plan-approval": "sisko",
        "roadex-fixture-approval": "roadex-fixture-approver",
    }
    for scope, identity in expected.items():
        path = tmp_path / f"{scope}.json"
        _write_document(path, _document(scope=scope))
        verifier = load_approval_verifier(path)
        assert verifier.identity == identity
        assert verifier.authenticate("correct-horse-battery-staple") == identity


@pytest.mark.parametrize("scope", ["", "admin", "admin-plan-approval ", "roadex-fixture-approval\n"])
def test_creation_rejects_unsupported_scopes(scope: str) -> None:
    with pytest.raises(ValueError):
        create_approval_document("secret", scope)


@pytest.mark.parametrize("secret", ["", " leading", "trailing ", "line\nbreak", "\tcontrol"])
def test_creation_rejects_noncanonical_bearer_secrets(secret: str) -> None:
    with pytest.raises(ValueError):
        create_approval_document(secret, "admin-plan-approval")


def test_bearer_secret_is_bounded_and_type_strict() -> None:
    with pytest.raises(ValueError, match="minimum"):
        create_approval_document("x" * (MIN_BEARER_SECRET_BYTES - 1), "admin-plan-approval")
    with pytest.raises(ValueError):
        create_approval_document("x" * (MAX_BEARER_SECRET_BYTES + 1), "admin-plan-approval")
    with pytest.raises(ValueError):
        create_approval_document(b"secret", "admin-plan-approval")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda d: d.pop("digest"),
        lambda d: d.__setitem__("extra", "rejected"),
        lambda d: d.__setitem__("version", 2),
        lambda d: d.__setitem__("scope", "roadex-fixture-approval"),
        lambda d: d.__setitem__("identity", "obrien"),
        lambda d: d.__setitem__("kdf", "pbkdf2"),
        lambda d: d.__setitem__("salt", "not-base64"),
        lambda d: d.__setitem__("digest", base64.b64encode(b"short").decode("ascii")),
        lambda d: d.__setitem__("salt", base64.b64encode(b"\x00" * 16).decode("ascii").rstrip("=")),
        lambda d: d.__setitem__("digest", "correct horse battery staple"),
    ],
)
def test_loader_rejects_invalid_document_properties(
    tmp_path: Path, mutation,
) -> None:
    document = _document()
    mutation(document)
    path = tmp_path / "approval.json"
    _write_document(path, document)
    with pytest.raises(ValueError):
        load_approval_verifier(path)


def test_loader_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    document = _document()
    encoded = json.dumps(document, separators=(",", ":"))
    encoded = encoded.replace('"scope":"admin-plan-approval"', '"scope":"admin-plan-approval","scope":"admin-plan-approval"')
    path = tmp_path / "approval.json"
    path.write_bytes(encoded.encode("utf-8"))
    os.chmod(path, 0o600)
    with pytest.raises(ValueError, match="duplicate"):
        load_approval_verifier(path)


def test_loader_rejects_invalid_utf8_and_oversized_files(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_bytes(b"{\xff")
    os.chmod(invalid, 0o600)
    with pytest.raises(ValueError):
        load_approval_verifier(invalid)

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (MAX_APPROVAL_DOCUMENT_BYTES + 1))
    os.chmod(oversized, 0o600)
    with pytest.raises(ValueError, match="size"):
        load_approval_verifier(oversized)


def test_loader_rejects_symlink_nonregular_hardlink_wrong_mode_and_owner(tmp_path: Path) -> None:
    source = tmp_path / "source.json"
    _write_document(source, _document())

    symlink = tmp_path / "symlink.json"
    symlink.symlink_to(source)
    with pytest.raises(ValueError):
        load_approval_verifier(symlink)

    directory = tmp_path / "directory.json"
    directory.mkdir()
    with pytest.raises(ValueError):
        load_approval_verifier(directory)

    hardlink = tmp_path / "hardlink.json"
    hardlink.hardlink_to(source)
    with pytest.raises(ValueError, match="hardlink"):
        load_approval_verifier(hardlink)
    hardlink.unlink()

    os.chmod(source, 0o640)
    with pytest.raises(ValueError, match="0600"):
        load_approval_verifier(source)
    os.chmod(source, 0o600)

    with pytest.raises(ValueError, match="owner"):
        load_approval_verifier(source, expected_owner_uid=os.getuid() + 1)


def test_loader_rechecks_open_descriptor_identity(tmp_path: Path) -> None:
    path = tmp_path / "approval.json"
    _write_document(path, _document())
    real_fstat = approval_auth.os.fstat
    calls = 0

    def fstat_with_changed_identity(fd: int):
        nonlocal calls
        result = real_fstat(fd)
        calls += 1
        if calls == 2:
            values = list(result)
            values[1] += 1
            return os.stat_result(values)
        return result

    with patch.object(approval_auth.os, "fstat", side_effect=fstat_with_changed_identity):
        with pytest.raises(ValueError, match="changed"):
            load_approval_verifier(path)


def test_no_plaintext_or_client_identity_fallback() -> None:
    verifier = ApprovalVerifier(
        version=1,
        scope="admin-plan-approval",
        identity="sisko",
        kdf="scrypt",
        salt=b"\x00" * 16,
        digest=b"\x00" * 32,
    )
    assert verifier.authenticate("\x00" * 32) is None
