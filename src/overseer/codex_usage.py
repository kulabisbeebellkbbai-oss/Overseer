"""Read-only Codex usage collection, snapshot history, and heuristics."""

from __future__ import annotations

import json
import os
import select
import sqlite3
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


DEFAULT_DB_PATH = Path("state/codex-usage.sqlite3")


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _iso_epoch(value: Any) -> str | None:
    if not isinstance(value, (int, float)):
        return None
    return datetime.fromtimestamp(value, UTC).isoformat()


def _pick(mapping: dict[str, Any], camel: str, snake: str) -> Any:
    return mapping.get(camel, mapping.get(snake))


class CodexAppServerClient:
    """Small JSON-RPC client for the local, authenticated Codex app server."""

    def __init__(self, command: tuple[str, ...] = ("codex", "app-server", "--stdio"), timeout: float = 15.0):
        self.command = command
        self.timeout = timeout

    def read_usage(self) -> dict[str, Any]:
        process = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        try:
            self._send(
                process,
                1,
                "initialize",
                {"clientInfo": {"name": "overseer-codex-usage", "version": "0.1.0"}, "capabilities": {}},
            )
            self._receive(process, 1)
            self._send(process, 2, "account/rateLimits/read", {})
            rate_limits = self._receive(process, 2)
            self._send(process, 3, "account/usage/read", {})
            usage = self._receive(process, 3)
            return {"rate_limits": rate_limits, "usage": usage}
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()

    @staticmethod
    def _send(process: subprocess.Popen[str], request_id: int, method: str, params: dict[str, Any]) -> None:
        if process.stdin is None:
            raise RuntimeError("codex_app_server_stdin_unavailable")
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}) + "\n")
        process.stdin.flush()

    def _receive(self, process: subprocess.Popen[str], request_id: int) -> dict[str, Any]:
        if process.stdout is None:
            raise RuntimeError("codex_app_server_stdout_unavailable")
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            ready, _, _ = select.select([process.stdout], [], [], max(0.0, deadline - time.monotonic()))
            if not ready:
                break
            line = process.stdout.readline()
            if not line:
                break
            message = json.loads(line)
            if message.get("id") != request_id:
                continue
            if "error" in message:
                error = message["error"]
                raise RuntimeError(f"codex_app_server_error:{error.get('code')}:{error.get('message')}")
            result = message.get("result")
            if not isinstance(result, dict):
                raise RuntimeError("codex_app_server_invalid_result")
            return result
        raise TimeoutError(f"codex_app_server_timeout:{request_id}")


class CodexUsageTracker:
    def __init__(self, db_path: Path | str | None = None, client: CodexAppServerClient | None = None):
        selected = db_path or os.environ.get("OVERSEER_CODEX_USAGE_DB") or DEFAULT_DB_PATH
        self.db_path = Path(selected).expanduser()
        self.client = client or CodexAppServerClient()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS codex_usage_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    observed_at TEXT NOT NULL,
                    source TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )

    def refresh(self) -> dict[str, Any]:
        observed_at = _now()
        raw = self.client.read_usage()
        snapshot = self._normalize(raw, observed_at)
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO codex_usage_snapshots (observed_at, source, payload) VALUES (?, ?, ?)",
                (observed_at, "codex_app_server", json.dumps(snapshot, sort_keys=True)),
            )
        return snapshot

    def latest(self, refresh: bool = True) -> dict[str, Any]:
        if refresh:
            return self.refresh()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM codex_usage_snapshots ORDER BY id DESC LIMIT 1"
            ).fetchone()
        if row is None:
            return self.refresh()
        return json.loads(row["payload"])

    def history(self, limit: int = 100) -> list[dict[str, Any]]:
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM codex_usage_snapshots ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def source_status(self) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count, MAX(observed_at) AS latest FROM codex_usage_snapshots"
            ).fetchone()
        return {
            "source": "codex_app_server",
            "command": "codex app-server --stdio",
            "authoritative": True,
            "read_only_provider_access": True,
            "snapshots": row["count"],
            "last_observed_at": row["latest"],
            "database": str(self.db_path),
            "absolute_quota_caveat": (
                "Most Codex rate windows expose percentages, not absolute units. "
                "Absolute amounts are reported only when individual-limit or credit data is available."
            ),
        }

    def heuristics(self, refresh: bool = False) -> dict[str, Any]:
        current = self.latest(refresh=refresh)
        history = self.history(200)
        windows = current["rate_limits"]
        remaining = [
            window["remaining_percent"]
            for limit in windows
            for window in limit["windows"]
            if window["remaining_percent"] is not None
        ]
        minimum = min(remaining) if remaining else None
        if minimum is None:
            posture, recommendation = "unknown", "Refresh usage or inspect source status before capacity-sensitive work."
        elif minimum <= 10:
            posture, recommendation = "critical", "Defer nonessential high-usage work until the limiting window resets."
        elif minimum <= 25:
            posture, recommendation = "conserve", "Prefer focused work and avoid speculative high-token parallel runs."
        elif minimum <= 50:
            posture, recommendation = "moderate", "Normal work is reasonable; reserve capacity for verification and fixes."
        else:
            posture, recommendation = "healthy", "Capacity is healthy for normal work."

        daily = current.get("account_usage", {}).get("daily_usage_buckets") or []
        tokens = [item["tokens"] for item in daily if isinstance(item.get("tokens"), (int, float))]
        recent = tokens[-7:]
        previous = tokens[-14:-7]
        recent_avg = sum(recent) / len(recent) if recent else None
        previous_avg = sum(previous) / len(previous) if previous else None
        trend_percent = None
        if recent_avg is not None and previous_avg not in (None, 0):
            trend_percent = round(((recent_avg - previous_avg) / previous_avg) * 100, 2)

        forecasts = self._window_forecasts(history)
        return {
            "observed_at": current["observed_at"],
            "posture": posture,
            "minimum_remaining_percent": minimum,
            "recommendation": recommendation,
            "daily_token_heuristics": {
                "samples": len(tokens),
                "recent_7_sample_average": round(recent_avg, 2) if recent_avg is not None else None,
                "previous_7_sample_average": round(previous_avg, 2) if previous_avg is not None else None,
                "trend_percent": trend_percent,
                "peak_daily_tokens": current.get("account_usage", {}).get("peak_daily_tokens"),
            },
            "window_forecasts": forecasts,
            "confidence": "medium" if len(history) >= 2 else "low",
            "warnings": [
                "Token counts and quota percentages are separate measures and are not converted into each other.",
                "Forecasts are estimates based only on locally captured snapshots.",
            ],
        }

    @staticmethod
    def _window_forecasts(history: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if len(history) < 2:
            return []
        newest, oldest = history[0], history[-1]
        start = datetime.fromisoformat(oldest["observed_at"])
        end = datetime.fromisoformat(newest["observed_at"])
        hours = (end - start).total_seconds() / 3600
        if hours <= 0:
            return []
        old_windows = {
            (item["limit_id"], window["name"], window["resets_at"]): window
            for item in oldest["rate_limits"]
            for window in item["windows"]
        }
        forecasts: list[dict[str, Any]] = []
        for item in newest["rate_limits"]:
            for window in item["windows"]:
                key = (item["limit_id"], window["name"], window["resets_at"])
                old = old_windows.get(key)
                if not old:
                    continue
                before, now = old.get("used_percent"), window.get("used_percent")
                if not isinstance(before, (int, float)) or not isinstance(now, (int, float)) or now <= before:
                    continue
                burn = (now - before) / hours
                hours_to_exhaustion = (100 - now) / burn if burn > 0 else None
                forecasts.append(
                    {
                        "limit_id": item["limit_id"],
                        "window": window["name"],
                        "samples_span_hours": round(hours, 2),
                        "burn_percent_per_hour": round(burn, 3),
                        "estimated_hours_to_exhaustion": round(hours_to_exhaustion, 2) if hours_to_exhaustion else None,
                        "resets_at": window["resets_at"],
                    }
                )
        return forecasts

    @classmethod
    def _normalize(cls, raw: dict[str, Any], observed_at: str) -> dict[str, Any]:
        rate_result = raw.get("rate_limits", {})
        by_id = _pick(rate_result, "rateLimitsByLimitId", "rate_limits_by_limit_id") or {}
        legacy = _pick(rate_result, "rateLimits", "rate_limits")
        if not by_id and isinstance(legacy, dict):
            by_id = {str(_pick(legacy, "limitId", "limit_id") or "codex"): legacy}

        normalized_limits = []
        for limit_id, value in sorted(by_id.items()):
            if not isinstance(value, dict):
                continue
            windows = []
            for name in ("primary", "secondary"):
                window = value.get(name)
                if not isinstance(window, dict):
                    continue
                used = _pick(window, "usedPercent", "used_percent")
                windows.append(
                    {
                        "name": name,
                        "used_percent": used,
                        "remaining_percent": round(max(0.0, 100.0 - float(used)), 4)
                        if isinstance(used, (int, float))
                        else None,
                        "window_minutes": _pick(window, "windowDurationMins", "window_minutes"),
                        "resets_at": _iso_epoch(_pick(window, "resetsAt", "resets_at")),
                    }
                )
            credits = value.get("credits") if isinstance(value.get("credits"), dict) else {}
            individual = _pick(value, "individualLimit", "individual_limit")
            normalized_limits.append(
                {
                    "limit_id": str(_pick(value, "limitId", "limit_id") or limit_id),
                    "limit_name": _pick(value, "limitName", "limit_name"),
                    "plan_type": _pick(value, "planType", "plan_type"),
                    "rate_limit_reached_type": _pick(value, "rateLimitReachedType", "rate_limit_reached_type"),
                    "spend_control_reached": _pick(value, "spendControlReached", "spend_control_reached"),
                    "windows": windows,
                    "credits": {
                        "has_credits": _pick(credits, "hasCredits", "has_credits"),
                        "unlimited": credits.get("unlimited"),
                        "balance": credits.get("balance"),
                    },
                    "individual_limit": individual,
                }
            )

        usage_result = raw.get("usage", {})
        usage = usage_result.get("summary") or usage_result.get("usage") or usage_result
        daily = (
            _pick(usage_result, "dailyUsageBuckets", "daily_usage_buckets")
            or _pick(usage, "dailyUsageBuckets", "daily_usage_buckets")
            or []
        )
        return {
            "observed_at": observed_at,
            "source": "codex_app_server",
            "rate_limits": normalized_limits,
            "reset_credits": _pick(rate_result, "rateLimitResetCredits", "rate_limit_reset_credits"),
            "account_usage": {
                "lifetime_tokens": _pick(usage, "lifetimeTokens", "lifetime_tokens"),
                "peak_daily_tokens": _pick(usage, "peakDailyTokens", "peak_daily_tokens"),
                "longest_running_turn_seconds": _pick(usage, "longestRunningTurnSec", "longest_running_turn_sec"),
                "current_streak_days": _pick(usage, "currentStreakDays", "current_streak_days"),
                "longest_streak_days": _pick(usage, "longestStreakDays", "longest_streak_days"),
                "daily_usage_buckets": [
                    {
                        "start_date": _pick(item, "startDate", "start_date"),
                        "tokens": item.get("tokens"),
                    }
                    for item in daily
                    if isinstance(item, dict)
                ],
            },
        }
