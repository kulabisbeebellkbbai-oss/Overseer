"""One-shot, authority-signed provider percentage accounting producer."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
import re
import secrets
import stat
from typing import Any, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .psychlo_contracts import canonical_digest


_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")


def _identity(value: object, name: str) -> str:
    if not isinstance(value, str) or not _IDENTITY.fullmatch(value):
        raise ValueError(f"{name} is invalid")
    return value


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(dict(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _timestamp(value: object, name: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{name} timestamp is invalid")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{name} timestamp is invalid") from error
    if result.tzinfo is None:
        raise ValueError(f"{name} timestamp requires an offset")
    return result.astimezone(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def derive_provider_window(provider_next_reset_at: str, window_duration_mins: int) -> tuple[str, str]:
    if isinstance(window_duration_mins, bool) or not isinstance(window_duration_mins, int) or window_duration_mins <= 0 or window_duration_mins > 60 * 24 * 366:
        raise ValueError("window duration must be a positive integer number of minutes")
    end = _timestamp(provider_next_reset_at, "provider next reset")
    return _iso(end - timedelta(minutes=window_duration_mins)), _iso(end)


@dataclass(frozen=True)
class MeterAuthority:
    authority_id: str
    authority_binding_id: str
    authority_binding_digest: str
    account_id: str
    public_key: bytes

    def __post_init__(self) -> None:
        _identity(self.authority_id, "authority identity")
        _identity(self.authority_binding_id, "authority binding identity")
        _identity(self.account_id, "account identity")
        if not isinstance(self.authority_binding_digest, str) or len(self.authority_binding_digest) != 64 or any(char not in "0123456789abcdef" for char in self.authority_binding_digest):
            raise ValueError("authority binding digest is invalid")
        if not isinstance(self.public_key, bytes) or len(self.public_key) != 32:
            raise ValueError("authority public key is invalid")

    @classmethod
    def from_json(cls, value: Mapping[str, Any]) -> "MeterAuthority":
        expected = {"authorityId", "authorityBindingId", "authorityBindingDigest", "accountId", "publicKey"}
        if not isinstance(value, Mapping) or set(value) != expected or any(not isinstance(value[key], str) for key in expected):
            raise ValueError("authority configuration is invalid")
        try:
            key = base64.b64decode(value["publicKey"], validate=True)
        except (ValueError, TypeError) as error:
            raise ValueError("authority public key encoding is invalid") from error
        return cls(value["authorityId"], value["authorityBindingId"], value["authorityBindingDigest"], value["accountId"], key)


@dataclass(frozen=True)
class ProviderPercentageMeterConfig:
    provider_id: str
    limit_id: str
    window_name: str
    decision_version: str

    def __post_init__(self) -> None:
        _identity(self.provider_id, "provider identity")
        if self.provider_id != "codex":
            raise ValueError("meter provider must match the fixed Codex app-server source")
        _identity(self.limit_id, "limit identity")
        _identity(self.decision_version, "decision version")
        if self.window_name not in {"primary", "secondary"}:
            raise ValueError("meter window must be primary or secondary")

    @classmethod
    def from_json(cls, value: Mapping[str, Any]) -> "ProviderPercentageMeterConfig":
        expected = {"providerId", "limitId", "windowName", "decisionVersion"}
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ValueError("meter configuration is invalid")
        return cls(value["providerId"], value["limitId"], value["windowName"], value["decisionVersion"])


def _raw_limits(raw: Mapping[str, Any]) -> Mapping[str, Any]:
    value = raw.get("rate_limits", raw)
    if not isinstance(value, Mapping):
        raise ValueError("provider rate limits are invalid")
    by_id = value.get("rateLimitsByLimitId", value.get("rate_limits_by_limit_id"))
    legacy = value.get("rateLimits", value.get("rate_limits"))
    if not by_id and isinstance(legacy, Mapping):
        by_id = {str(legacy.get("limitId", legacy.get("limit_id", "codex"))): legacy}
    if not isinstance(by_id, Mapping):
        raise ValueError("provider rate limits are invalid")
    return by_id


def _select_window(raw: Mapping[str, Any], config: ProviderPercentageMeterConfig) -> Mapping[str, Any]:
    by_id = _raw_limits(raw)
    value = by_id.get(config.limit_id)
    if not isinstance(value, Mapping):
        raise ValueError("configured provider limit is missing")
    disclosed_limit = value.get("limitId", value.get("limit_id"))
    if disclosed_limit is not None and disclosed_limit != config.limit_id:
        raise ValueError("configured provider limit identity is inconsistent")
    window = value.get(config.window_name)
    if not isinstance(window, Mapping):
        raise ValueError("configured provider window is missing")
    return window


class ProviderPercentageMeter:
    def __init__(self, authority: MeterAuthority, config: ProviderPercentageMeterConfig, private_key: Ed25519PrivateKey):
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("Ed25519 private key is required")
        derived = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if derived != authority.public_key:
            raise ValueError("private key public key does not match authority public key")
        self.authority, self.config, self.private_key = authority, config, private_key

    @classmethod
    def from_pem(cls, authority: MeterAuthority, config: ProviderPercentageMeterConfig, pem: bytes) -> "ProviderPercentageMeter":
        try:
            key = serialization.load_pem_private_key(pem, password=None)
        except (TypeError, ValueError) as error:
            raise ValueError("Ed25519 private key PEM is invalid") from error
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("Ed25519 private key is required")
        return cls(authority, config, key)

    def observe(self, raw: Mapping[str, Any], *, observed_at: str | None = None) -> dict[str, Any]:
        observed = _timestamp(observed_at or datetime.now(UTC).isoformat(), "observed")
        window = _select_window(raw, self.config)
        used = window.get("usedPercent", window.get("used_percent"))
        duration = window.get("windowDurationMins", window.get("window_minutes"))
        reset = window.get("resetsAt", window.get("resets_at"))
        if isinstance(used, bool) or not isinstance(used, int) or not 0 <= used <= 100:
            raise ValueError("used percentage must be an integral value on the 0..100 scale")
        if isinstance(reset, int) and not isinstance(reset, bool):
            try:
                reset_value = _iso(datetime.fromtimestamp(reset, UTC))
            except (OSError, OverflowError, ValueError) as error:
                raise ValueError("provider reset must be an exact timestamp") from error
        elif isinstance(reset, str):
            reset_value = str(reset)
        else:
            raise ValueError("provider reset must be an exact timestamp")
        interval_start, next_reset = derive_provider_window(reset_value, duration)
        if _timestamp(next_reset, "provider next reset") <= observed:
            raise ValueError("provider reset must be after observation")
        if _timestamp(interval_start, "provider window start") >= observed:
            raise ValueError("observation must fall inside the current provider window")
        body = {
            "observationId": "provider-percentage-" + canonical_digest({"providerId": self.config.provider_id, "limitId": self.config.limit_id, "windowName": self.config.window_name, "observedAt": _iso(observed), "providerNextResetAt": next_reset})[:24],
            "authorityId": self.authority.authority_id,
            "authorityBindingId": self.authority.authority_binding_id,
            "authorityBindingDigest": self.authority.authority_binding_digest,
            "measurementScope": "provider-global-percentage-window",
            "accountId": self.authority.account_id,
            "providerId": self.config.provider_id,
            "limitId": self.config.limit_id,
            "windowName": self.config.window_name,
            "usageUnit": "provider-percentage-points",
            "providerResetAt": interval_start,
            "providerNextResetAt": next_reset,
            "windowDurationMins": duration,
            "intervalStart": interval_start,
            "intervalEnd": _iso(observed),
            "totalConsumed": used,
            "weeklyQuota": 100,
            "weeklyRemainingCapacity": 100 - used,
            "unusedPriorDayWeeklyCapacity": 0,
            "decisionVersion": self.config.decision_version,
            "correlationId": "provider-percentage-correlation-" + self.config.provider_id,
            "idempotencyKey": "provider-percentage-idempotency-" + canonical_digest({"providerId": self.config.provider_id, "limitId": self.config.limit_id, "windowName": self.config.window_name, "observedAt": _iso(observed), "providerNextResetAt": next_reset})[:24],
            "occurredAt": _iso(observed),
        }
        body["digest"] = canonical_digest(body)
        body["signature"] = base64.b64encode(self.private_key.sign(_canonical_bytes({key: value for key, value in body.items() if key != "digest"}))).decode("ascii")
        return body


def atomic_publish_observation(path: Path | str, observation: Mapping[str, Any]) -> Path:
    """Publish a sealed observation with private, no-follow replacement semantics."""
    target = Path(path).expanduser()
    parent = target.parent
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        directory = os.open(parent, directory_flags)
    except OSError as error:
        raise ValueError("observation directory must already exist and must not be a symlink") from error
    parent_stat = os.fstat(directory)
    if not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid != os.getuid() or parent_stat.st_mode & 0o077:
        os.close(directory)
        raise ValueError("observation directory must be private")
    try:
        target_stat = os.stat(target.name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        target_stat = None
    if target_stat is not None and (stat.S_ISLNK(target_stat.st_mode) or not stat.S_ISREG(target_stat.st_mode) or target_stat.st_uid != os.getuid() or target_stat.st_mode & 0o077):
        os.close(directory)
        raise ValueError("observation target must be a private regular file, not a symlink")
    encoded = json.dumps(dict(observation), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    temporary = f".{target.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(temporary, flags, 0o600, dir_fd=directory)
    try:
        remaining = memoryview(encoded)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("observation write made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, target.name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    except Exception:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(directory)
    return target
