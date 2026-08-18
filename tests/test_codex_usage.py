from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from overseer.api import codex_usage_health_status
from overseer.codex_usage import CodexUsageTracker
from overseer.codex_usage import CodexAppServerClient, CodexAppServerMethodNotFound
from overseer.ui import OPERATOR_CONSOLE_HTML


class _FinishedProcess:
    def poll(self):
        return 0


class _ScriptedAppServerClient(CodexAppServerClient):
    def __init__(self, terminal_error: BaseException):
        super().__init__()
        self.terminal_error = terminal_error

    @staticmethod
    def _send(process, request_id, method, params):
        return None

    def _receive(self, process, request_id):
        if request_id == 1:
            return {}
        if request_id == 2:
            return {"rateLimitsByLimitId": {"codex": {"limitId": "codex", "primary": {"usedPercent": 12, "windowDurationMins": 60, "resetsAt": 1786000000}}}}
        raise self.terminal_error


class _StructuredDispatchClient(CodexAppServerClient):
    def __init__(self, responses):
        super().__init__()
        self.responses = responses
        self.sent = []

    def _send(self, process, request_id, method, params):
        self.sent.append((request_id, method, params))

    def _receive(self, process, request_id):
        return self.responses[request_id]


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


class RemovedUsageClient:
    def read_usage(self):
        raise AssertionError("tracker should use the rate-limit-only compatibility path")

    def read_rate_limits(self):
        return {"rateLimitsByLimitId": {"codex": {"limitId": "codex", "primary": {"usedPercent": 12, "windowDurationMins": 60, "resetsAt": 1786000000}}}}


def test_rate_limit_only_read_is_available_when_account_usage_method_was_removed(tmp_path: Path):
    tracker = CodexUsageTracker(tmp_path / "usage.sqlite3", client=RemovedUsageClient())
    result = tracker.refresh_rate_limits()
    assert result["rate_limits"][0]["windows"][0]["used_percent"] == 12


def test_method_not_found_compatibility_is_narrow():
    assert CodexAppServerClient.is_removed_account_usage_error(CodexAppServerMethodNotFound("-32601", "Method not found: account/usage/read")) is True
    assert CodexAppServerClient.is_removed_account_usage_error(RuntimeError("codex_app_server_error:-32601:Method not found: other")) is False
    assert CodexAppServerClient.is_removed_account_usage_error(TimeoutError("timed out")) is False


def test_read_usage_preserves_limits_only_for_removed_usage_rpc(monkeypatch):
    monkeypatch.setattr("overseer.codex_usage.subprocess.Popen", lambda *args, **kwargs: _FinishedProcess())
    result = _ScriptedAppServerClient(CodexAppServerMethodNotFound(-32601, "Method not found: account/usage/read")).read_usage()
    assert result["rate_limits"]["rateLimitsByLimitId"]["codex"]["primary"]["usedPercent"] == 12
    assert result["usage"] == {}


def test_read_usage_does_not_hide_other_provider_failures(monkeypatch):
    monkeypatch.setattr("overseer.codex_usage.subprocess.Popen", lambda *args, **kwargs: _FinishedProcess())
    with pytest.raises(TimeoutError, match="provider timeout"):
        _ScriptedAppServerClient(TimeoutError("provider timeout")).read_usage()


def test_structured_turn_submission_is_bound_and_confirmed_before_ack(monkeypatch):
    thread_id = "01a01569-7874-7f72-bca9-9c91bb869846"
    client_message_id = "legacy.dispatch.round-arcade-v5"
    prompt = "Execute exactly one approved Arcade round."
    idle = {
        "thread": {
            "id": thread_id,
            "status": {"type": "notLoaded"},
            "turns": [
                {
                    "id": "turn.ready",
                    "status": "completed",
                    "items": [
                        {
                            "id": "item.ready",
                            "type": "userMessage",
                            "clientId": None,
                            "content": [{"type": "text", "text": "Identity initialization only."}],
                        }
                    ],
                }
            ],
        }
    }
    confirmed = {
        "thread": {
            "id": thread_id,
            "status": {"type": "active"},
            "turns": [
                *idle["thread"]["turns"],
                {
                    "id": "turn.arcade",
                    "status": "inProgress",
                    "items": [
                        {
                            "id": "item.arcade",
                            "type": "userMessage",
                            "clientId": client_message_id,
                            "content": [{"type": "text", "text": prompt}],
                        }
                    ],
                },
            ],
        }
    }
    client = _StructuredDispatchClient(
        {
            1: {},
            2: idle,
            3: idle,
            4: idle,
            5: {"turn": {"id": "turn.arcade", "status": "inProgress", "items": []}},
            6: confirmed,
        }
    )
    phases = []
    spawned = []
    monkeypatch.setenv("OVERSEER_PSYCHLO_PEER_SECRET", "must-not-reach-codex")
    monkeypatch.setattr(
        "overseer.codex_usage.subprocess.Popen",
        lambda *args, **kwargs: spawned.append(kwargs) or _FinishedProcess(),
    )

    evidence = client.submit_bound_turn(
        thread_id=thread_id,
        prompt=prompt,
        client_message_id=client_message_id,
        cwd="/workspace/Arcade",
        phase_callback=phases.append,
    )

    assert evidence == {
        "thread_id": thread_id,
        "turn_id": "turn.arcade",
        "client_message_id": client_message_id,
        "prompt_digest": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        "delivery_proof": "app-server-user-message",
    }
    assert phases == ["prepared", "paste-intent", "submit-intent", "submitted"]
    assert [method for _, method, _ in client.sent] == [
        "initialize",
        "thread/read",
        "thread/resume",
        "thread/read",
        "turn/start",
        "thread/read",
    ]
    assert client.sent[4][2] == {
        "threadId": thread_id,
        "input": [{"type": "text", "text": prompt}],
        "clientUserMessageId": client_message_id,
        "cwd": "/workspace/Arcade",
    }
    assert "OVERSEER_PSYCHLO_PEER_SECRET" not in spawned[0]["env"]
    assert set(spawned[0]["env"]) <= {
        "CODEX_HOME",
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "TMPDIR",
    }


def test_structured_thread_validation_rejects_non_list_items():
    with pytest.raises(ValueError, match="turn history is invalid"):
        CodexAppServerClient._require_idle_thread(
            {
                "thread": {
                    "id": "thread-1",
                    "turns": [{"id": "turn-1", "status": "completed", "items": {}}],
                }
            },
            "thread-1",
            "client-message-1",
        )


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
