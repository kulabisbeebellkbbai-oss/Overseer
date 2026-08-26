"""Bounded, read-only providers for the v1 user bridge.

Runtime instances use fixed server-side source paths.  The optional path
arguments exist so tests can inject disposable fixtures; no bridge request can
provide or alter either path.
"""

from __future__ import annotations

import csv
from datetime import UTC, datetime
import hashlib
import io
import json
import math
import os
from pathlib import Path
import sqlite3
import stat
from typing import Any, Callable


DEFAULT_CODEX_REGISTRY_PATH = Path("/home/god/.codex/codex-projects.csv")
DEFAULT_CODEX_USAGE_DB_PATH = Path("/home/god/.local/share/overseer/codex-usage-mcp/state.sqlite3")
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_SESSION_ROWS = 64
MAX_USAGE_WINDOWS = 8
DEFAULT_STALE_AFTER_SECONDS = 60 * 60

Clock = Callable[[], datetime]


def _now() -> datetime:
    return datetime.now(UTC)


def _validate_source_path(path: str | Path) -> Path:
    selected = Path(path)
    if not selected.is_absolute():
        raise ValueError("provider source path must be absolute")
    return selected


def _read_fixed_file(path: Path) -> tuple[bytes, os.stat_result]:
    descriptor, metadata = _open_fixed_descriptor(path)
    try:
        chunks: list[bytes] = []
        size = 0
        while size <= MAX_SOURCE_BYTES:
            chunk = os.read(descriptor, min(16 * 1024, MAX_SOURCE_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if size > MAX_SOURCE_BYTES:
            raise OverflowError("provider source is too large")
        final = os.fstat(descriptor)
        if not _acceptable_metadata(final) or _identity_and_size(final) != _identity_and_size(metadata):
            raise OSError("provider source metadata changed")
        return b"".join(chunks), metadata
    finally:
        os.close(descriptor)


def _open_fixed_descriptor(path: Path) -> tuple[int, os.stat_result]:
    try:
        initial = os.lstat(path)
    except FileNotFoundError:
        raise
    if not _acceptable_metadata(initial):
        raise OSError("provider source is not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    metadata = os.fstat(descriptor)
    if not _acceptable_metadata(metadata) or _identity_and_size(metadata) != _identity_and_size(initial):
        os.close(descriptor)
        raise OSError("provider source metadata changed")
    return descriptor, metadata


def _acceptable_metadata(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.geteuid()
        and metadata.st_nlink == 1
        and not (metadata.st_mode & stat.S_IWOTH)
    )


def _identity_and_size(metadata: os.stat_result) -> tuple[int, int, int]:
    return metadata.st_dev, metadata.st_ino, metadata.st_size


def _observed_at(metadata: os.stat_result) -> str:
    return datetime.fromtimestamp(metadata.st_mtime, UTC).isoformat()


def _state_for_timestamp(observed_at: str, clock: Clock, stale_after_seconds: float) -> str:
    observed = datetime.fromisoformat(observed_at)
    current = clock()
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    age = (current - observed).total_seconds()
    return "stale" if age > stale_after_seconds else "available"


def _digest(prefix: str, value: str) -> str:
    return f"{prefix}-{hashlib.sha256((prefix + ':' + value).encode('utf-8')).hexdigest()[:24]}"


def _safe_timestamp(value: Any) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 256:
        return None
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value) or "/" in value or "\\" in value:
        return None
    return value


def _percent(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        return None
    return max(0, min(100, int(round(float(value)))))


class CodexSessionProjectionProvider:
    """Read the fixed Codex registry without exposing its raw values."""

    def __init__(
        self,
        registry_path: str | Path = DEFAULT_CODEX_REGISTRY_PATH,
        *,
        clock: Clock | None = None,
        stale_after_seconds: float = DEFAULT_STALE_AFTER_SECONDS,
    ) -> None:
        self.registry_path = _validate_source_path(registry_path)
        self.clock = clock or _now
        if not isinstance(stale_after_seconds, (int, float)) or isinstance(stale_after_seconds, bool) or not math.isfinite(stale_after_seconds) or stale_after_seconds <= 0:
            raise ValueError("stale threshold must be positive")
        self.stale_after_seconds = float(stale_after_seconds)

    def __call__(self) -> dict[str, Any]:
        return self.snapshot()

    def snapshot(self) -> dict[str, Any]:
        try:
            raw, metadata = _read_fixed_file(self.registry_path)
        except FileNotFoundError:
            return {"state": "unavailable", "reason": "source_missing"}
        except OverflowError:
            return {"state": "error", "error_code": "source_too_large"}
        except OSError:
            return {"state": "unavailable", "reason": "source_unavailable"}
        previous_csv_field_limit = csv.field_size_limit(MAX_SOURCE_BYTES)
        try:
            text = raw.decode("utf-8")
            reader = csv.DictReader(io.StringIO(text), strict=True)
            required = {"conversation_id", "project"}
            if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
                return {"state": "error", "error_code": "source_invalid"}
            sessions: list[dict[str, str]] = []
            for row in reader:
                conversation_id = str(row.get("conversation_id") or "").strip()
                project = str(row.get("project") or "").strip()
                if not conversation_id or not project:
                    continue
                sessions.append(
                    {
                        "session_id": _digest("session", conversation_id),
                        "project_id": _digest("project", project),
                        "status": "discovered",
                    }
                )
                if len(sessions) >= MAX_SESSION_ROWS:
                    break
            observed_at = _observed_at(metadata)
            state = _state_for_timestamp(observed_at, self.clock, self.stale_after_seconds)
            projection: dict[str, Any] = {"state": state, "observed_at": observed_at, "sessions": sessions}
            if state == "stale":
                projection["stale_at"] = observed_at
            return projection
        except (UnicodeDecodeError, csv.Error, OSError, ValueError):
            return {"state": "error", "error_code": "source_invalid"}
        finally:
            csv.field_size_limit(previous_csv_field_limit)


class CodexUsageProjectionProvider:
    """Read the fixed usage SQLite database with SQLite's read-only URI mode."""

    def __init__(
        self,
        db_path: str | Path = DEFAULT_CODEX_USAGE_DB_PATH,
        *,
        clock: Clock | None = None,
        stale_after_seconds: float = DEFAULT_STALE_AFTER_SECONDS,
    ) -> None:
        self.db_path = _validate_source_path(db_path)
        self.clock = clock or _now
        if not isinstance(stale_after_seconds, (int, float)) or isinstance(stale_after_seconds, bool) or not math.isfinite(stale_after_seconds) or stale_after_seconds <= 0:
            raise ValueError("stale threshold must be positive")
        self.stale_after_seconds = float(stale_after_seconds)

    def __call__(self) -> dict[str, Any]:
        return self.snapshot()

    def snapshot(self) -> dict[str, Any]:
        descriptor: int | None = None
        try:
            descriptor, metadata = _open_fixed_descriptor(self.db_path)
            uri = f"file:{self.db_path.as_posix()}?mode=ro"
            with sqlite3.connect(uri, uri=True, timeout=0.5) as connection:
                row = connection.execute(
                    "SELECT observed_at, payload FROM codex_usage_snapshots ORDER BY id DESC LIMIT 1"
                ).fetchone()
            final_descriptor = os.fstat(descriptor)
            final_path = os.lstat(self.db_path)
            if (
                not _acceptable_metadata(final_descriptor)
                or not _acceptable_metadata(final_path)
                or _identity_and_size(final_descriptor) != _identity_and_size(metadata)
                or _identity_and_size(final_path) != _identity_and_size(metadata)
            ):
                return {"state": "unavailable", "reason": "source_unavailable"}
        except FileNotFoundError:
            return {"state": "unavailable", "reason": "source_missing"}
        except (OSError, sqlite3.OperationalError):
            return {"state": "unavailable", "reason": "source_unavailable"}
        except sqlite3.Error:
            return {"state": "error", "error_code": "source_invalid"}
        finally:
            if descriptor is not None:
                os.close(descriptor)
        if row is None:
            return {"state": "unavailable", "reason": "source_empty"}
        try:
            observed_at = _safe_timestamp(row[0])
            payload = json.loads(row[1])
            if observed_at is None or not isinstance(payload, dict):
                raise ValueError("invalid usage snapshot")
            windows = self._windows(payload)
            state = _state_for_timestamp(observed_at, self.clock, self.stale_after_seconds)
            projection: dict[str, Any] = {"state": state, "observed_at": observed_at, "windows": windows}
            if state == "stale":
                projection["stale_at"] = observed_at
            return projection
        except (TypeError, ValueError, KeyError, json.JSONDecodeError):
            return {"state": "error", "error_code": "source_invalid"}

    @staticmethod
    def _windows(payload: dict[str, Any]) -> list[dict[str, Any]]:
        limits = payload.get("rate_limits")
        if not isinstance(limits, list):
            raise ValueError("rate limits are invalid")
        windows: list[dict[str, Any]] = []
        for limit in limits:
            if not isinstance(limit, dict):
                continue
            limit_id = str(limit.get("limit_id") or "codex")
            source_windows = limit.get("windows")
            if not isinstance(source_windows, list):
                continue
            limit_digest = hashlib.sha256(limit_id.encode("utf-8")).hexdigest()[:16]
            for window in source_windows:
                if len(windows) >= MAX_USAGE_WINDOWS:
                    return windows
                if not isinstance(window, dict):
                    continue
                raw_name = window.get("name")
                name = raw_name if raw_name in {"primary", "secondary"} else "window"
                item: dict[str, Any] = {"name": f"window-{limit_digest}-{name}"}
                used = _percent(window.get("used_percent"))
                remaining = _percent(window.get("remaining_percent"))
                reset_at = _safe_timestamp(window.get("resets_at"))
                if used is not None:
                    item["used"] = used
                if remaining is not None:
                    item["remaining"] = remaining
                if reset_at is not None:
                    item["reset_at"] = reset_at
                windows.append(item)
        return windows
