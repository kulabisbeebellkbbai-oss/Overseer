from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from overseer.admin import AdminChangeKind, ApprovalLevel, OwnerDomain, RiskLevel
from overseer.codex_dispatch_activation import (
    CODEX_DISPATCH_ACTIVATION_SCHEMA,
    CodexDispatchActivationSpec,
    execute_codex_dispatch_activation_marker,
    plan_codex_dispatch_activation,
    validate_codex_dispatch_activation_plan,
)


def _spec(tmp_path: Path) -> CodexDispatchActivationSpec:
    source = tmp_path / "source"
    (source / "src" / "overseer").mkdir(parents=True)
    for name, content in {
        "codex_usage.py": b"usage",
        "agent_adapters/codex.py": b"driver",
        "psychlo_bridge.py": b"bridge",
    }.items():
        path = source / "src" / "overseer" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return CodexDispatchActivationSpec(
        schema_version=CODEX_DISPATCH_ACTIVATION_SCHEMA,
        source_root=source,
        source_commit="a" * 40,
        source_tree_digest="b" * 40,
        source_module_digest="c" * 64,
        review_digest="d" * 64,
        service_name="overseer-api.service",
        drop_in_relative_path=".config/systemd/user/overseer-api.service.d/10-overseer-codex-dispatch.conf",
        daemon_socket=".codex/run/app-server.sock",
        health_url="http://127.0.0.1:8766/health",
        source_files=(
            "src/overseer/agent_adapters/codex.py",
            "src/overseer/codex_usage.py",
            "src/overseer/psychlo_bridge.py",
        ),
    )


def _context(plan):
    marker = plan.steps[0].command
    return marker


def test_plan_is_exact_high_human_sisko_and_staged_only(tmp_path: Path):
    spec = _spec(tmp_path)
    plan = plan_codex_dispatch_activation("admin.codex-dispatch.activate", spec, "activate reviewed dispatch", "disabled")

    assert plan.kind == AdminChangeKind.CODEX_APP_SERVER_DISPATCH_ACTIVATION
    assert plan.owner_domain == OwnerDomain.SISKO
    assert plan.risk_level == RiskLevel.HIGH
    assert plan.approval_level == ApprovalLevel.HUMAN
    assert plan.approved is False
    assert plan.adapter_metadata["specDigest"]
    assert all(step.command[0].startswith("__overseer_codex_dispatch_") for step in plan.steps + plan.rollback_steps + plan.verification_steps)
    assert "--remote-control" not in sum((list(step.command) for step in plan.steps), [])
    assert not (Path.home() / ".config/systemd/user/overseer-api.service.d/10-overseer-codex-dispatch.conf").exists()


def test_plan_rejects_metadata_or_source_binding_drift(tmp_path: Path):
    spec = _spec(tmp_path)
    plan = plan_codex_dispatch_activation("admin.codex-dispatch.drift", spec, "activate", "disabled")
    validate_codex_dispatch_activation_plan(plan)

    with pytest.raises(ValueError, match="canonical|digest"):
        validate_codex_dispatch_activation_plan(replace(plan, target="other.service"))
    with pytest.raises(ValueError, match="digest"):
        validate_codex_dispatch_activation_plan(
            replace(plan, adapter_metadata={**plan.adapter_metadata, "specDigest": "e" * 64})
        )


def test_marker_context_is_closed_and_rollback_is_exact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    spec = _spec(tmp_path)
    plan = plan_codex_dispatch_activation("admin.codex-dispatch.marker", spec, "activate", "disabled")
    marker = _context(plan)

    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        "overseer.codex_dispatch_activation._run_checked",
        lambda command, **_kwargs: calls.append(tuple(command)) or "ok",
    )
    code, out, err = execute_codex_dispatch_activation_marker(marker, home=tmp_path)
    assert code == 0, err
    assert out == "daemon bootstrap staged"
    assert calls == [("codex", "app-server", "daemon", "bootstrap"), ("codex", "app-server", "daemon", "disable-remote-control")]
    assert "secret" not in out.lower()


def test_marker_rejects_unknown_or_tampered_context(tmp_path: Path):
    spec = _spec(tmp_path)
    plan = plan_codex_dispatch_activation("admin.codex-dispatch.closed", spec, "activate", "disabled")
    marker = list(_context(plan))
    marker[-1] = json.dumps({"schemaVersion": "wrong"})
    code, out, err = execute_codex_dispatch_activation_marker(tuple(marker), home=tmp_path)
    assert code == 1
    assert not out
    assert any(token in err for token in ("schema", "context", "exact keys"))
