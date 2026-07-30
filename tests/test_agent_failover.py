from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from overseer.agent_contracts import (
    ActiveAgentRisk,
    ActiveAgentRiskLevel,
    AgentCapabilities,
    AgentCheckpoint,
    AgentOperationState,
    DriverEpoch,
    FailoverPolicy,
    FailoverExecution,
    FailoverExecutionState,
    FAILOVER_RECOVERY_BLOCKERS,
    RECOVERABLE_FAILOVER_EXECUTION_STATES,
    ProviderHealthObservation,
    ProviderHealthState,
)
from overseer.agent_handoff import evaluate_failover_evidence
from overseer.cli import agent_failover_executions_status
from overseer.store import OverseerStore


NOW = datetime(2026, 7, 29, 16, tzinfo=timezone.utc)


def _policy(**changes) -> FailoverPolicy:
    values = dict(
        id="policy.failover",
        instance_id="overseer.default",
        approved=True,
        approval_ref="approval.failover",
        approved_at=(NOW - timedelta(hours=1)).isoformat(),
        failure_threshold=2,
        checkpoint_max_age_seconds=300,
        approved_fallback_provider_ids=("claude", "qwen-code"),
        decision_lifetime_seconds=30,
    )
    values.update(changes)
    return FailoverPolicy(**values)


def _evaluate(**changes):
    epoch = DriverEpoch(
        id="epoch.codex.1",
        instance_id="overseer.default",
        session_id="session.codex",
        provider_id="codex",
        ordinal=1,
        state=AgentOperationState.RUNNING,
    )
    health = (
        ProviderHealthObservation(
            id="health.codex.1",
            instance_id=epoch.instance_id,
            provider_id="codex",
            state=ProviderHealthState.TRANSPORT_FAILURE,
            observed_at=(NOW - timedelta(minutes=2)).isoformat(),
            reason_category="transport_error",
        ),
        ProviderHealthObservation(
            id="health.codex.2",
            instance_id=epoch.instance_id,
            provider_id="codex",
            state=ProviderHealthState.FAILED,
            observed_at=(NOW - timedelta(minutes=1)).isoformat(),
            reason_category="provider_unavailable",
        ),
        ProviderHealthObservation(
            id="health.claude.1",
            instance_id=epoch.instance_id,
            provider_id="claude",
            state=ProviderHealthState.HEALTHY,
            observed_at=NOW.isoformat(),
            reason_category="probe_ok",
        ),
    )
    checkpoint = AgentCheckpoint(
        id="checkpoint.1",
        instance_id=epoch.instance_id,
        session_id=epoch.session_id,
        driver_epoch_id=epoch.id,
        evidence={"status": "ready"},
        created_at=(NOW - timedelta(seconds=10)).isoformat(),
        expires_at=(NOW + timedelta(minutes=1)).isoformat(),
    )
    values = dict(
        decision_id="decision.1",
        instance_id=epoch.instance_id,
        outgoing_epoch=epoch,
        operation_generation=3,
        policy=_policy(),
        health=health,
        checkpoint=checkpoint,
        risks=(),
        candidate_capabilities={
            "claude": AgentCapabilities(handoff_import=True),
            "qwen-code": AgentCapabilities(handoff_import=True),
        },
        healthy_candidates=frozenset({"claude"}),
        candidate_readiness={"claude": "readiness.claude.cli"},
        required_capabilities=AgentCapabilities(handoff_import=True),
        evaluated_at=NOW.isoformat(),
    )
    values.update(changes)
    if values["policy"] is None and "health" not in changes:
        values["health"] = tuple(
            item for item in health if item.provider_id == epoch.provider_id
        )
    return evaluate_failover_evidence(**values)


def test_failover_selects_first_healthy_approved_compatible_provider() -> None:
    decision = _evaluate()
    assert decision.allowed
    assert decision.incoming_provider_id == "claude"
    assert decision.blockers == ()


@pytest.mark.parametrize(
    ("changes", "blocker"),
    (
        ({"policy": None}, "failover policy missing or not approved"),
        ({"policy": _policy(approved_at=NOW.isoformat())}, "policy approval does not predate failure sequence"),
        ({"policy": _policy(failure_threshold=3)}, "failure threshold not reached"),
        ({"checkpoint": None}, "checkpoint missing, stale, expired, or incorrectly bound"),
        ({"healthy_candidates": frozenset()}, "no healthy approved fallback"),
        ({"transition_changed": True}, "transition, reservation, or epoch already changed"),
    ),
)
def test_failover_blocker_matrix(changes, blocker) -> None:
    decision = _evaluate(**changes)
    assert not decision.allowed
    assert blocker in decision.blockers


def test_slow_only_is_never_a_failover_trigger() -> None:
    decision = _evaluate(
        health=(
            ProviderHealthObservation(
                id="health.slow",
                instance_id="overseer.default",
                provider_id="codex",
                state=ProviderHealthState.SLOW,
                observed_at=NOW.isoformat(),
                reason_category="latency",
            ),
        )
    )
    assert "slow response is not a failover trigger" in decision.blockers


def test_unresolved_high_risk_and_non_transferable_state_block() -> None:
    decision = _evaluate(
        risks=(
            ActiveAgentRisk(
                id="risk.1",
                instance_id="overseer.default",
                risk_level=ActiveAgentRiskLevel.HIGH,
                resolved=False,
                transferable=False,
                evidence_ref="evidence.risk.1",
            ),
        )
    )
    assert decision.blockers[0] == "unresolved high-risk action"
    assert "non-transferable active operation or checkpoint state" in decision.blockers


def test_capability_mismatch_does_not_skip_to_unhealthy_provider() -> None:
    decision = _evaluate(
        candidate_capabilities={
            "claude": AgentCapabilities(),
            "qwen-code": AgentCapabilities(handoff_import=True),
        },
        healthy_candidates=frozenset({"claude"}),
    )
    assert decision.incoming_provider_id is None
    assert "fallback capability mismatch or missing handoff_import" in decision.blockers


def test_foreign_persisted_evidence_is_rejected() -> None:
    foreign = ProviderHealthObservation(
        id="health.foreign",
        instance_id="another.instance",
        provider_id="codex",
        state=ProviderHealthState.FAILED,
        observed_at=NOW.isoformat(),
        reason_category="transport_error",
    )
    with pytest.raises(ValueError, match="foreign health"):
        _evaluate(health=(foreign,))


def test_timestamp_order_uses_instants_not_lexical_offsets() -> None:
    earlier = ProviderHealthObservation(
        id="health.offset.earlier",
        instance_id="overseer.default",
        provider_id="codex",
        state=ProviderHealthState.FAILED,
        observed_at="2026-07-29T12:30:00-04:00",
        reason_category="transport_error",
    )
    later = replace(
        earlier,
        id="health.offset.later",
        observed_at="2026-07-29T17:00:00+00:00",
    )
    decision = _evaluate(health=(later, earlier))
    assert decision.health_evidence_ids == (later.id, earlier.id)


def test_failover_contracts_reject_loose_types_and_duplicate_order() -> None:
    with pytest.raises(TypeError, match="boolean"):
        _policy(approved=1)
    with pytest.raises(ValueError, match="unique"):
        _policy(approved_fallback_provider_ids=("claude", "claude"))
    with pytest.raises(TypeError, match="health state"):
        ProviderHealthObservation(
            id="health.bad",
            instance_id="overseer.default",
            provider_id="codex",
            state="failed",  # type: ignore[arg-type]
            observed_at=NOW.isoformat(),
            reason_category="transport_error",
        )


def test_failover_blocked_evaluation_is_not_persisted_implicitly(tmp_path) -> None:
    with OverseerStore(tmp_path / "state.sqlite3") as store:
        blocked = _evaluate(policy=None)
        with pytest.raises(KeyError):
            store.load_failover_decision(blocked.id)


def test_failover_decision_is_immutable_and_consumed_once(tmp_path) -> None:
    with OverseerStore(tmp_path / "state.sqlite3") as store:
        decision = _evaluate()
        store.save_failover_decision(decision)
        with pytest.raises(ValueError, match="immutable"):
            store.save_failover_decision(replace(decision, incoming_provider_id="qwen-code"))
        consumed = store.consume_failover_decision(
            decision.id,
            expected_generation=decision.operation_generation,
            consumed_at=(NOW + timedelta(seconds=1)).isoformat(),
        )
        assert consumed.consumed_at
        with pytest.raises(ValueError, match="already consumed"):
            store.consume_failover_decision(
                decision.id,
                expected_generation=decision.operation_generation,
                consumed_at=(NOW + timedelta(seconds=2)).isoformat(),
            )


@pytest.mark.parametrize(
    "state",
    (
        FailoverExecutionState.RESERVED,
        FailoverExecutionState.DRAINING,
        FailoverExecutionState.BLOCKED_PREIMPORT,
        FailoverExecutionState.RECOVERING,
    ),
)
def test_every_nonterminal_failover_state_has_private_recovery_status(
    tmp_path, state
) -> None:
    path = tmp_path / "state.sqlite3"
    now = NOW.isoformat()
    with OverseerStore(path) as store:
        store.save_failover_execution(
            FailoverExecution(
                id=f"execution.{state.value}",
                decision_id="decision.1",
                instance_id="overseer.default",
                outgoing_epoch_id="epoch.1",
                outgoing_session_id="session.secret.internal",
                outgoing_provider_id="codex",
                checkpoint_id="checkpoint.1",
                operation_generation=7,
                operation_owner_ref="owner.must-not-leak",
                state=state,
                created_at=now,
                updated_at=now,
            )
        )
    status = agent_failover_executions_status(path)
    item = status["executions"][0]
    assert status["recovery_required"] is True
    assert item["recovery_state"] == state.value
    assert item["blocker"]
    assert item["next_action"].startswith("POST /agent-failover/recover")
    serialized = repr(status)
    assert "owner.must-not-leak" not in serialized
    assert "session.secret.internal" not in serialized


def test_failover_recovery_state_and_blocker_contract_cannot_drift() -> None:
    assert set(FAILOVER_RECOVERY_BLOCKERS) == set(
        RECOVERABLE_FAILOVER_EXECUTION_STATES
    )
