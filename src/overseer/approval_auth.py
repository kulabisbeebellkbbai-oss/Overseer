"""Strict, file-backed authentication for narrowly scoped human approvals.

The on-disk document contains only the scope, its server-owned identity, and
the parameters needed to verify a scrypt digest.  It never contains the
bearer secret or a plaintext-token fallback.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path


APPROVAL_DOCUMENT_VERSION = 1
APPROVAL_KDF = "scrypt"
SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
APPROVAL_SALT_BYTES = 16
MAX_APPROVAL_DOCUMENT_BYTES = 2048
MAX_BEARER_SECRET_BYTES = 256
_APPROVAL_FIELDS = frozenset({"version", "scope", "identity", "kdf", "salt", "digest"})
_SCOPED_IDENTITIES = {
    "admin-plan-approval": "sisko",
    "roadex-fixture-approval": "roadex-fixture-approver",
}


class ApprovalDocumentError(ValueError):
    """Raised when an approval document or secret violates its contract."""


def _scope_identity(scope: object) -> str:
    if type(scope) is not str or scope not in _SCOPED_IDENTITIES:
        raise ApprovalDocumentError("unsupported approval scope")
    return _SCOPED_IDENTITIES[scope]


def _secret_bytes(secret: object) -> bytes:
    if type(secret) is not str or not secret:
        raise ApprovalDocumentError("bearer secret must be a non-empty string")
    if any(character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F for character in secret):
        raise ApprovalDocumentError("bearer secret is not canonical")
    try:
        encoded = secret.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ApprovalDocumentError("bearer secret must be valid UTF-8") from error
    if len(encoded) > MAX_BEARER_SECRET_BYTES:
        raise ApprovalDocumentError("bearer secret exceeds its maximum size")
    return encoded


def _scrypt_digest(secret: bytes, salt: bytes) -> bytes:
    return hashlib.scrypt(
        secret,
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
    )


@dataclass(frozen=True, slots=True)
class ApprovalVerifier:
    """Immutable verifier for one supported approval scope."""

    version: int
    scope: str
    identity: str
    kdf: str
    salt: bytes
    digest: bytes

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != APPROVAL_DOCUMENT_VERSION:
            raise ApprovalDocumentError("unsupported approval document version")
        if _scope_identity(self.scope) != self.identity:
            raise ApprovalDocumentError("approval identity does not match scope")
        if self.kdf != APPROVAL_KDF:
            raise ApprovalDocumentError("unsupported approval key derivation function")
        if type(self.salt) is not bytes or len(self.salt) != APPROVAL_SALT_BYTES:
            raise ApprovalDocumentError("approval salt has an invalid length")
        if type(self.digest) is not bytes or len(self.digest) != SCRYPT_DKLEN:
            raise ApprovalDocumentError("approval digest has an invalid length")

    def authenticate(self, bearer_secret: object) -> str | None:
        """Return the server-owned identity only when the secret verifies."""

        try:
            secret = _secret_bytes(bearer_secret)
        except ApprovalDocumentError:
            return None
        candidate = _scrypt_digest(secret, self.salt)
        if secrets.compare_digest(candidate, self.digest):
            return self.identity
        return None

    def verify(self, bearer_secret: object) -> bool:
        """Return whether a canonical bearer secret authenticates."""

        return self.authenticate(bearer_secret) is not None

    def authenticate_bearer_header(self, authorization: object) -> str | None:
        """Authenticate an exact ``Bearer <secret>`` authorization value."""

        if type(authorization) is not str or not authorization.startswith("Bearer "):
            return None
        return self.authenticate(authorization[len("Bearer "):])


def create_approval_document(secret: str, scope: str) -> dict[str, object]:
    """Create an in-memory approval document; this helper never writes files."""

    identity = _scope_identity(scope)
    secret_bytes = _secret_bytes(secret)
    salt = secrets.token_bytes(APPROVAL_SALT_BYTES)
    digest = _scrypt_digest(secret_bytes, salt)
    return {
        "version": APPROVAL_DOCUMENT_VERSION,
        "scope": scope,
        "identity": identity,
        "kdf": APPROVAL_KDF,
        "salt": base64.b64encode(salt).decode("ascii"),
        "digest": base64.b64encode(digest).decode("ascii"),
    }


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ApprovalDocumentError(f"duplicate approval document key: {key}")
        result[key] = value
    return result


def _decode_canonical_base64(value: object, field: str, expected_length: int) -> bytes:
    if type(value) is not str:
        raise ApprovalDocumentError(f"{field} must be a base64 string")
    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, ValueError):
        raise ApprovalDocumentError(f"{field} is not canonical base64") from None
    if base64.b64encode(decoded) != encoded:
        raise ApprovalDocumentError(f"{field} is not canonical base64")
    if len(decoded) != expected_length:
        raise ApprovalDocumentError(f"{field} has an invalid length")
    return decoded


def _document_to_verifier(raw: bytes) -> ApprovalVerifier:
    try:
        text = raw.decode("utf-8")
        document = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ApprovalDocumentError("approval document must be valid UTF-8 JSON") from error
    if type(document) is not dict:
        raise ApprovalDocumentError("approval document must be a JSON object")
    if set(document) != _APPROVAL_FIELDS:
        raise ApprovalDocumentError("approval document has unsupported or missing keys")
    if type(document["version"]) is not int or document["version"] != APPROVAL_DOCUMENT_VERSION:
        raise ApprovalDocumentError("unsupported approval document version")
    scope = document["scope"]
    identity = document["identity"]
    if type(scope) is not str or _scope_identity(scope) != identity:
        raise ApprovalDocumentError("approval identity does not match scope")
    if document["kdf"] != APPROVAL_KDF:
        raise ApprovalDocumentError("unsupported approval key derivation function")
    salt = _decode_canonical_base64(document["salt"], "salt", APPROVAL_SALT_BYTES)
    digest = _decode_canonical_base64(document["digest"], "digest", SCRYPT_DKLEN)
    return ApprovalVerifier(
        version=APPROVAL_DOCUMENT_VERSION,
        scope=scope,
        identity=identity,
        kdf=APPROVAL_KDF,
        salt=salt,
        digest=digest,
    )


def _metadata_error(message: str) -> ApprovalDocumentError:
    return ApprovalDocumentError(f"approval document {message}")


def _validate_metadata(metadata: os.stat_result, expected_owner_uid: int) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise _metadata_error("is not a regular file")
    if metadata.st_nlink != 1:
        raise _metadata_error("is a hardlink")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise _metadata_error("must have mode 0600")
    if metadata.st_uid != expected_owner_uid:
        raise _metadata_error("has an unexpected owner")


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _read_bounded_document(path: str | os.PathLike[str], expected_owner_uid: int) -> bytes:
    try:
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode):
            raise _metadata_error("must not be a symlink")
        _validate_metadata(before, expected_owner_uid)
        if before.st_size > MAX_APPROVAL_DOCUMENT_BYTES:
            raise _metadata_error("exceeds the maximum size")

        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            _validate_metadata(opened, expected_owner_uid)
            if not _same_file(before, opened):
                raise _metadata_error("identity changed while opening")

            chunks: list[bytes] = []
            remaining = MAX_APPROVAL_DOCUMENT_BYTES + 1
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)

            after = os.fstat(descriptor)
            _validate_metadata(after, expected_owner_uid)
            if not _same_file(opened, after) or after.st_size != before.st_size:
                raise _metadata_error("identity changed while reading")
            lexical_after = os.lstat(path)
            _validate_metadata(lexical_after, expected_owner_uid)
            if not _same_file(before, lexical_after):
                raise _metadata_error("identity changed while reading")
            if len(raw) > MAX_APPROVAL_DOCUMENT_BYTES:
                raise _metadata_error("exceeds the maximum size")
            return raw
        finally:
            os.close(descriptor)
    except ApprovalDocumentError:
        raise
    except OSError as error:
        raise ApprovalDocumentError("could not be safely read") from error


def load_approval_verifier(
    path: str | Path,
    *,
    expected_owner_uid: int | None = None,
) -> ApprovalVerifier:
    """Safely load one strict approval document owned by the expected UID."""

    if expected_owner_uid is None:
        expected_owner_uid = os.geteuid()
    if type(expected_owner_uid) is not int or expected_owner_uid < 0:
        raise ApprovalDocumentError("expected owner UID is invalid")
    return _document_to_verifier(_read_bounded_document(path, expected_owner_uid))


def authenticate_bearer_secret(verifier: ApprovalVerifier, bearer_secret: object) -> str | None:
    """Return the verifier's identity only after successful authentication."""

    if not isinstance(verifier, ApprovalVerifier):
        raise TypeError("verifier must be an ApprovalVerifier")
    return verifier.authenticate(bearer_secret)
