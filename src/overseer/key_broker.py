"""Local key broker records and scoped token issuance.

The broker keeps secret custody out of Overseer core state. SQLite stores only
metadata and hashes; raw issued tokens are written under local-secrets.
"""

from __future__ import annotations

import hashlib
import base64
import json
import re
import secrets
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from pathlib import Path

from .audit import AuditEvent, AuditEventType
from .core import OwnerDomain, RiskLevel


DEFAULT_BROKER_ROOT = "local-secrets/key-broker"
MAX_TOKEN_TTL_MINUTES = 60


class KeyProviderKind(str, Enum):
    STATIC_TOKEN = "static_token"
    GITHUB_APP = "github_app"
    BREAK_GLASS = "break_glass"


class KeyBrokerRequestStatus(str, Enum):
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    ISSUED = "issued"
    DENIED = "denied"
    CANCELED = "canceled"


class KeyBrokerGrantStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass(frozen=True)
class KeyProviderRecord:
    id: str
    display_name: str
    provider_kind: KeyProviderKind
    owner_domain: OwnerDomain = OwnerDomain.ODO
    enabled: bool = True
    secret_ref: str = ""
    allowed_subjects: tuple[str, ...] = ("*",)
    allowed_scopes: tuple[str, ...] = ()
    metadata: dict[str, object] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""


@dataclass(frozen=True)
class KeyBrokerTokenRequest:
    id: str
    provider_id: str
    subject: str
    requested_scopes: tuple[str, ...]
    requested_by: str
    justification: str
    ttl_minutes: int
    status: KeyBrokerRequestStatus = KeyBrokerRequestStatus.PENDING_APPROVAL
    risk_level: RiskLevel = RiskLevel.MEDIUM
    approval_id: str | None = None
    approved_by: str | None = None
    approved_at: str | None = None
    denial_reason: str | None = None
    created_at: str = ""
    updated_at: str = ""


@dataclass(frozen=True)
class KeyBrokerTokenGrant:
    id: str
    request_id: str
    provider_id: str
    subject: str
    scopes: tuple[str, ...]
    token_hash: str
    token_path: str
    status: KeyBrokerGrantStatus
    issued_by: str
    issued_at: str
    expires_at: str
    revoked_by: str | None = None
    revoked_at: str | None = None
    revoke_reason: str | None = None


def key_broker_status(store, project_root: str | Path = ".") -> dict[str, object]:
    providers = store.list_key_providers()
    requests = store.list_key_broker_token_requests()
    grants = tuple(_refresh_grant_status(grant) for grant in store.list_key_broker_token_grants())
    return {
        "project_root": str(Path(project_root)),
        "broker_root": str(_broker_root(project_root)),
        "providers": [_provider_status(provider) for provider in providers],
        "requests": [_request_status(request) for request in requests],
        "grants": [_grant_status(grant) for grant in grants],
        "summary": {
            "providers": len(providers),
            "enabled_providers": sum(1 for provider in providers if provider.enabled),
            "pending_approval": sum(1 for request in requests if request.status == KeyBrokerRequestStatus.PENDING_APPROVAL),
            "active_grants": sum(1 for grant in grants if grant.status == KeyBrokerGrantStatus.ACTIVE),
        },
        "secret_policy": "raw provider secrets and issued tokens are not stored in SQLite or returned by status APIs",
        "host_mutation_performed": False,
    }


def record_key_provider_status(
    store,
    provider_id: str,
    display_name: str,
    provider_kind: str,
    secret_ref: str,
    allowed_subjects: tuple[str, ...] | list[str],
    allowed_scopes: tuple[str, ...] | list[str],
    enabled: bool = True,
    metadata: dict[str, object] | None = None,
) -> dict[str, object]:
    now = _now()
    try:
        existing = store.load_key_provider(provider_id)
        created_at = existing.created_at
    except KeyError:
        created_at = now
    provider = KeyProviderRecord(
        id=_safe_id(provider_id, "provider_id"),
        display_name=display_name,
        provider_kind=KeyProviderKind(provider_kind),
        enabled=bool(enabled),
        secret_ref=secret_ref,
        allowed_subjects=_normalized_values(allowed_subjects, allow_wildcard=True),
        allowed_scopes=_normalized_values(allowed_scopes, allow_wildcard=True),
        metadata=_redact_mapping(metadata or {}),
        created_at=created_at,
        updated_at=now,
    )
    store.save_key_provider(provider)
    event = _audit_event("key_provider_recorded", provider.id, f"Key provider {provider.id} recorded")
    store.save_audit_event(event)
    return {
        "provider": _provider_status(provider),
        "audit_event": event.id,
        "mutation_performed": True,
        "host_mutation_performed": False,
    }


def request_key_broker_token_status(
    store,
    provider_id: str,
    subject: str,
    requested_scopes: tuple[str, ...] | list[str],
    requested_by: str,
    justification: str,
    ttl_minutes: int = 15,
) -> dict[str, object]:
    provider = store.load_key_provider(provider_id)
    if not provider.enabled:
        raise ValueError("key provider is disabled")
    subject = _safe_subject(subject)
    scopes = _normalized_values(requested_scopes, allow_wildcard=False)
    _assert_allowed(subject, provider.allowed_subjects, "subject")
    for scope in scopes:
        _assert_allowed(scope, provider.allowed_scopes, "scope")
    risk = _request_risk(provider, scopes)
    status = KeyBrokerRequestStatus.PENDING_APPROVAL if risk != RiskLevel.LOW else KeyBrokerRequestStatus.APPROVED
    now = _now()
    request = KeyBrokerTokenRequest(
        id=f"kbr.{_safe_id(provider_id, 'provider_id')}.{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.{secrets.token_hex(4)}",
        provider_id=provider.id,
        subject=subject,
        requested_scopes=scopes,
        requested_by=requested_by,
        justification=justification,
        ttl_minutes=max(1, min(int(ttl_minutes), MAX_TOKEN_TTL_MINUTES)),
        status=status,
        risk_level=risk,
        created_at=now,
        updated_at=now,
    )
    store.save_key_broker_token_request(request)
    event = _audit_event("key_token_requested", request.id, f"Key token request {request.id} created")
    store.save_audit_event(event)
    return {
        "request": _request_status(request),
        "audit_event": event.id,
        "next_step": "approve request before issuance" if status == KeyBrokerRequestStatus.PENDING_APPROVAL else "issue scoped token",
        "mutation_performed": True,
        "host_mutation_performed": False,
    }


def approve_key_broker_token_request_status(
    store,
    request_id: str,
    approved_by: str,
    approval_id: str,
    approved_at: str | None = None,
) -> dict[str, object]:
    request = store.load_key_broker_token_request(request_id)
    if request.status not in {KeyBrokerRequestStatus.PENDING_APPROVAL, KeyBrokerRequestStatus.APPROVED}:
        raise ValueError("request is not approvable")
    approved = KeyBrokerTokenRequest(
        **{
            **request.__dict__,
            "status": KeyBrokerRequestStatus.APPROVED,
            "approval_id": approval_id,
            "approved_by": approved_by,
            "approved_at": approved_at or _now(),
            "updated_at": _now(),
        }
    )
    store.save_key_broker_token_request(approved)
    event = _audit_event("key_token_approved", approved.id, f"Key token request {approved.id} approved")
    store.save_audit_event(event)
    return {"request": _request_status(approved), "audit_event": event.id, "mutation_performed": True}


def issue_key_broker_token_status(
    store,
    project_root: str | Path,
    request_id: str,
    issued_by: str,
) -> dict[str, object]:
    request = store.load_key_broker_token_request(request_id)
    if request.status != KeyBrokerRequestStatus.APPROVED:
        raise ValueError("request must be approved before issuance")
    provider = store.load_key_provider(request.provider_id)
    if not provider.enabled:
        raise ValueError("key provider is disabled")
    raw_token = _mint_broker_token(provider, request)
    token_hash = _hash_token(raw_token)
    now = datetime.now(UTC)
    expires_at = now + timedelta(minutes=request.ttl_minutes)
    grant_id = f"kbg.{_safe_id(provider.id, 'provider_id')}.{now.strftime('%Y%m%dT%H%M%SZ')}.{secrets.token_hex(4)}"
    token_path = _write_token_file(project_root, grant_id, raw_token)
    grant = KeyBrokerTokenGrant(
        id=grant_id,
        request_id=request.id,
        provider_id=provider.id,
        subject=request.subject,
        scopes=request.requested_scopes,
        token_hash=token_hash,
        token_path=str(token_path),
        status=KeyBrokerGrantStatus.ACTIVE,
        issued_by=issued_by,
        issued_at=now.isoformat(),
        expires_at=expires_at.isoformat(),
    )
    issued_request = KeyBrokerTokenRequest(**{**request.__dict__, "status": KeyBrokerRequestStatus.ISSUED, "updated_at": _now()})
    store.save_key_broker_token_grant(grant)
    store.save_key_broker_token_request(issued_request)
    event = _audit_event("key_token_issued", grant.id, f"Scoped key token {grant.id} issued")
    store.save_audit_event(event)
    return {
        "grant": _grant_status(grant),
        "request": _request_status(issued_request),
        "token_source": f"key-broker-token:{grant.id}",
        "audit_event": event.id,
        "raw_token_returned": False,
        "mutation_performed": True,
        "host_mutation_performed": False,
    }


def revoke_key_broker_token_status(
    store,
    grant_id: str,
    revoked_by: str,
    reason: str = "work complete",
) -> dict[str, object]:
    grant = store.load_key_broker_token_grant(grant_id)
    revoked = KeyBrokerTokenGrant(
        **{
            **grant.__dict__,
            "status": KeyBrokerGrantStatus.REVOKED,
            "revoked_by": revoked_by,
            "revoked_at": _now(),
            "revoke_reason": reason,
        }
    )
    store.save_key_broker_token_grant(revoked)
    path = Path(revoked.token_path)
    if path.exists() and path.name.endswith(".token") and path.parent.name == "tokens" and path.parent.parent.name == "key-broker":
        path.write_text("", encoding="utf-8")
    event = _audit_event("key_token_revoked", revoked.id, f"Scoped key token {revoked.id} revoked")
    store.save_audit_event(event)
    return {"grant": _grant_status(revoked), "audit_event": event.id, "mutation_performed": True}


def _mint_broker_token(provider: KeyProviderRecord, request: KeyBrokerTokenRequest) -> str:
    if provider.provider_kind == KeyProviderKind.GITHUB_APP:
        return _mint_github_app_installation_token(provider, request)
    if provider.provider_kind == KeyProviderKind.BREAK_GLASS:
        prefix = "obb_"
    else:
        prefix = "obs_"
    return f"{prefix}{secrets.token_urlsafe(32)}"


def _mint_github_app_installation_token(provider: KeyProviderRecord, request: KeyBrokerTokenRequest) -> str:
    config = _github_app_config(provider)
    jwt_token = _github_app_jwt(config["app_id"], Path(config["private_key_path"]))
    payload = {
        "permissions": _github_permissions_for_scopes(request.requested_scopes),
    }
    repository = config.get("repository")
    if repository and request.subject == "project:Overseer":
        payload["repositories"] = [repository]
    body = json.dumps(payload).encode("utf-8")
    http_request = urllib.request.Request(
        f"https://api.github.com/app/installations/{config['installation_id']}/access_tokens",
        data=body,
        method="POST",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {jwt_token}",
            "Content-Type": "application/json",
            "User-Agent": "Overseer-Key-Broker",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(http_request, timeout=20) as response:
            response_body = response.read()
    except urllib.error.HTTPError as exc:
        raise ValueError(f"github app token exchange failed with HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise ValueError("github app token exchange failed") from exc
    parsed = json.loads(response_body.decode("utf-8"))
    token = parsed.get("token")
    if not isinstance(token, str) or not token:
        raise ValueError("github app token exchange returned no token")
    return token


def _github_app_config(provider: KeyProviderRecord) -> dict[str, str]:
    private_key_path = Path(provider.secret_ref).expanduser()
    if not private_key_path.exists():
        raise ValueError("github app private key file is missing")
    env_path = private_key_path.parent / "overseer-github-app.env"
    values = _read_env_file(env_path)
    app_id = values.get("GITHUB_APP_ID")
    installation_id = values.get("GITHUB_APP_INSTALLATION_ID")
    if not app_id or not installation_id:
        raise ValueError("github app id and installation id are required")
    return {
        "app_id": app_id,
        "installation_id": installation_id,
        "private_key_path": str(private_key_path),
        "owner": values.get("GITHUB_APP_OWNER", ""),
        "repository": values.get("GITHUB_APP_REPOSITORY", ""),
    }


def _read_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        raise ValueError("github app environment file is missing")
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def _github_app_jwt(app_id: str, private_key_path: Path) -> str:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    now = int(datetime.now(UTC).timestamp())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"iat": now - 60, "exp": now + 540, "iss": str(app_id)}
    signing_input = ".".join(
        (
            _base64url_json(header),
            _base64url_json(payload),
        )
    ).encode("ascii")
    key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return signing_input.decode("ascii") + "." + _base64url(signature)


def _base64url_json(value: dict[str, object]) -> str:
    return _base64url(json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _github_permissions_for_scopes(scopes: tuple[str, ...]) -> dict[str, str]:
    permissions: dict[str, str] = {}
    for scope in scopes:
        if ":" not in scope:
            raise ValueError(f"invalid github scope {scope}")
        permission, level = scope.split(":", 1)
        if level not in {"read", "write"}:
            raise ValueError(f"invalid github permission level {level}")
        current = permissions.get(permission)
        if current == "write":
            continue
        permissions[permission] = level
    if "metadata" not in permissions:
        permissions["metadata"] = "read"
    return permissions


def _provider_status(provider: KeyProviderRecord) -> dict[str, object]:
    return {
        "id": provider.id,
        "display_name": provider.display_name,
        "provider_kind": provider.provider_kind.value,
        "owner_domain": provider.owner_domain.value,
        "enabled": provider.enabled,
        "secret_ref": _redact_secret_ref(provider.secret_ref),
        "allowed_subjects": list(provider.allowed_subjects),
        "allowed_scopes": list(provider.allowed_scopes),
        "metadata": provider.metadata,
        "created_at": provider.created_at,
        "updated_at": provider.updated_at,
    }


def _request_status(request: KeyBrokerTokenRequest) -> dict[str, object]:
    return {
        "id": request.id,
        "provider_id": request.provider_id,
        "subject": request.subject,
        "requested_scopes": list(request.requested_scopes),
        "requested_by": request.requested_by,
        "justification": request.justification,
        "ttl_minutes": request.ttl_minutes,
        "status": request.status.value,
        "risk_level": request.risk_level.value,
        "approval_id": request.approval_id,
        "approved_by": request.approved_by,
        "approved_at": request.approved_at,
        "created_at": request.created_at,
        "updated_at": request.updated_at,
    }


def _grant_status(grant: KeyBrokerTokenGrant) -> dict[str, object]:
    refreshed = _refresh_grant_status(grant)
    return {
        "id": refreshed.id,
        "request_id": refreshed.request_id,
        "provider_id": refreshed.provider_id,
        "subject": refreshed.subject,
        "scopes": list(refreshed.scopes),
        "token_hash_prefix": refreshed.token_hash[:19],
        "token_path": refreshed.token_path,
        "status": refreshed.status.value,
        "issued_by": refreshed.issued_by,
        "issued_at": refreshed.issued_at,
        "expires_at": refreshed.expires_at,
        "revoked_by": refreshed.revoked_by,
        "revoked_at": refreshed.revoked_at,
        "revoke_reason": refreshed.revoke_reason,
    }


def _refresh_grant_status(grant: KeyBrokerTokenGrant) -> KeyBrokerTokenGrant:
    if grant.status != KeyBrokerGrantStatus.ACTIVE:
        return grant
    if datetime.fromisoformat(grant.expires_at) <= datetime.now(UTC):
        return KeyBrokerTokenGrant(**{**grant.__dict__, "status": KeyBrokerGrantStatus.EXPIRED})
    return grant


def _request_risk(provider: KeyProviderRecord, scopes: tuple[str, ...]) -> RiskLevel:
    if provider.provider_kind == KeyProviderKind.BREAK_GLASS or "*" in scopes:
        return RiskLevel.CRITICAL
    if provider.provider_kind == KeyProviderKind.GITHUB_APP:
        return RiskLevel.HIGH
    return RiskLevel.LOW


def _write_token_file(project_root: str | Path, token_id: str, token: str) -> Path:
    root = _broker_root(project_root) / "tokens"
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{_safe_id(token_id, 'token_id')}.token"
    path.write_text(token, encoding="utf-8")
    path.chmod(0o600)
    return path


def _broker_root(project_root: str | Path) -> Path:
    return Path(project_root) / DEFAULT_BROKER_ROOT


def _hash_token(token: str) -> str:
    return "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _safe_id(value: str, field: str) -> str:
    cleaned = str(value).strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", cleaned):
        raise ValueError(f"{field} must contain only letters, numbers, underscore, dash, dot, or colon")
    return cleaned


def _safe_subject(value: str) -> str:
    cleaned = str(value).strip()
    if not cleaned or any(part in cleaned.lower() for part in ("token", "secret", "password")):
        raise ValueError("invalid subject")
    return cleaned


def _normalized_values(values: tuple[str, ...] | list[str], allow_wildcard: bool) -> tuple[str, ...]:
    normalized = []
    for value in values:
        item = str(value).strip()
        if not item:
            continue
        if item == "*" and not allow_wildcard:
            raise ValueError("wildcard is not allowed here")
        normalized.append(item)
    if not normalized:
        raise ValueError("at least one value is required")
    return tuple(dict.fromkeys(normalized))


def _assert_allowed(value: str, allowed: tuple[str, ...], label: str) -> None:
    if "*" in allowed or value in allowed:
        return
    raise ValueError(f"{label} is outside provider allowlist")


def _redact_mapping(value: dict[str, object]) -> dict[str, object]:
    redacted = {}
    for key, item in value.items():
        if any(part in key.lower() for part in ("token", "secret", "password", "key")):
            redacted[key] = "[redacted]"
        else:
            redacted[key] = item
    return redacted


def _redact_secret_ref(secret_ref: str) -> str:
    if not secret_ref:
        return ""
    return str(Path(secret_ref).name)


def _audit_event(event_type: str, subject_id: str, summary: str) -> AuditEvent:
    return AuditEvent(
        id=f"audit.key-broker.{_safe_id(subject_id, 'subject_id')}.{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}",
        subject_id=subject_id,
        event_type=AuditEventType.REQUESTED if "requested" in event_type or "recorded" in event_type else AuditEventType.EXECUTED,
        owner_domain=OwnerDomain.ODO,
        risk_level=RiskLevel.HIGH,
        summary=summary,
        occurred_at=_now(),
    )


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False
