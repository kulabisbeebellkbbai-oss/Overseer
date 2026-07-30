from __future__ import annotations

from pathlib import Path

import pytest

from overseer.api import codex_usage_health_status
from overseer.codex_usage import CodexUsageTracker
from overseer.ui import OPERATOR_CONSOLE_HTML


class FakeClient:
    def __init__(self, used: float = 25.0):
        self.used = used

    def read_usage(self):
        return {
            "rate_limits": {
                "rateLimitsByLimitId": {
                    "codex": {
                        "limitId": "codex",
                        "planType": "pro",
                        "primary": {"usedPercent": self.used, "windowDurationMins": 300, "resetsAt": 1786000000},
                        "secondary": None,
                        "credits": {"hasCredits": True, "unlimited": False, "balance": "7.5"},
                        "individualLimit": {"limit": 20, "used": 3, "remainingPercent": 85},
                    }
                }
            },
            "usage": {
                "summary": {
                    "lifetimeTokens": 1000,
                    "peakDailyTokens": 400,
                },
                "dailyUsageBuckets": [
                    {"startDate": "2026-07-27", "tokens": 100},
                    {"startDate": "2026-07-28", "tokens": 200},
                ],
            },
        }


def test_refresh_tracks_all_disclosed_usage(tmp_path: Path):
    tracker = CodexUsageTracker(tmp_path / "usage.sqlite3", client=FakeClient())
    result = tracker.refresh()
    limit = result["rate_limits"][0]
    assert limit["windows"][0]["used_percent"] == 25.0
    assert limit["windows"][0]["remaining_percent"] == 75.0
    assert limit["windows"][0]["resets_at"].endswith("+00:00")
    assert limit["credits"]["balance"] == "7.5"
    assert limit["individual_limit"]["remainingPercent"] == 85
    assert result["account_usage"]["lifetime_tokens"] == 1000
    assert len(tracker.history()) == 1


def test_heuristic_posture_uses_most_constrained_window(tmp_path: Path):
    tracker = CodexUsageTracker(tmp_path / "usage.sqlite3", client=FakeClient(used=92))
    tracker.refresh()
    heuristic = tracker.heuristics()
    assert heuristic["posture"] == "critical"
    assert heuristic["minimum_remaining_percent"] == 8


def test_history_limit_is_validated(tmp_path: Path):
    tracker = CodexUsageTracker(tmp_path / "usage.sqlite3", client=FakeClient())
    with pytest.raises(ValueError, match="between 1 and 1000"):
        tracker.history(0)


def test_normalization_handles_legacy_single_limit():
    normalized = CodexUsageTracker._normalize(
        {
            "rate_limits": {
                "rateLimits": {
                    "limitId": "codex",
                    "primary": {"usedPercent": 40, "windowDurationMins": 60, "resetsAt": 1786000000},
                }
            },
            "usage": {},
        },
        "2026-07-29T00:00:00+00:00",
    )
    assert normalized["rate_limits"][0]["windows"][0]["remaining_percent"] == 60


def test_julian_codex_usage_health_surface_uses_latest_snapshot(tmp_path: Path):
    db_path = tmp_path / "usage.sqlite3"
    tracker = CodexUsageTracker(db_path, client=FakeClient())
    tracker.refresh()

    status = codex_usage_health_status(db_path)

    assert status["available"] is True
    assert status["observed_at"]
    assert status["posture"] == "healthy"
    assert status["minimum_remaining_percent"] == 75
    assert status["rate_limits"][0]["windows"][0]["resets_at"]
    assert status["account_usage"]["lifetime_tokens"] == 1000


def test_julian_codex_usage_health_surface_fails_closed_without_snapshot(tmp_path: Path):
    status = codex_usage_health_status(tmp_path / "missing" / "usage.sqlite3")

    assert status["available"] is False
    assert status["rate_limits"] == []
    assert status["next_step"]


def test_julian_health_page_renders_codex_usage_panels():
    assert 'codexUsage: "/health/codex-usage"' in OPERATOR_CONSOLE_HTML
    assert "Codex Capacity" in OPERATOR_CONSOLE_HTML
    assert "Codex Usage Windows" in OPERATOR_CONSOLE_HTML
    assert "Codex Account Usage" in OPERATOR_CONSOLE_HTML
    assert "Codex Usage" in OPERATOR_CONSOLE_HTML
    assert "providerNativeUsage" in OPERATOR_CONSOLE_HTML
    assert "usage_unit" in OPERATOR_CONSOLE_HTML
