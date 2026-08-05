"""Contract-first tests for append-only backup execution persistence."""

from __future__ import annotations

import dataclasses
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from threading import Barrier, Thread

import pytest

from overseer.backup_execution import (
    BehaviorAcceptance,
    CheckpointEvent,
    ExecutionOperationIdentity,
    ExecutionPhase,
    ExecutionPhaseSpec,
    ExecutionStepIdentity,
    ProvisioningCheckpoint,
    ProvisioningExecutionHeader,
    ProvisioningExecutionView,
    ProvisioningStepEvidence,
    RuntimeAttestation,
    StepDisposition,
    build_checkpoint,
    build_execution_header,
    canonical_arguments_digest,
    canonical_json,
    canonical_step_digest,
    checkpoint_from_payload,
    checkpoint_payload,
    derive_backup_execution_view,
    execution_header_digest,
    header_from_payload,
    header_payload,
    provisioning_checkpoint_digest,
    verify_backup_execution_chain,
)
from overseer.store import CURRENT_SCHEMA_VERSION, OverseerStore


PLAN_DIGEST = "sha256:" + "1" * 64
APPROVAL_DIGEST = "sha256:" + "2" * 64
BUNDLE_DIGEST = "sha256:" + "3" * 64
CONTRACT_DIGEST = "sha256:" + "4" * 64
APPROVED_RUNTIME_DIGEST = "sha256:" + "5" * 64
APPROVED_CONFIG_DIGEST = "sha256:" + "6" * 64


def _header() -> ProvisioningExecutionHeader:
    steps = tuple(
        ExecutionStepIdentity(
            ordinal,
            ExecutionOperationIdentity(
                "duplicate-operation",
                canonical_arguments_digest({"ordinal": ordinal}),
                canonical_step_digest(PLAN_DIGEST, "forward", ordinal, "duplicate-operation", {"ordinal": ordinal}),
            ),
        )
        for ordinal in range(6)
    )
    phases = tuple(ExecutionPhaseSpec(i, phase, (steps[i],)) for i, phase in enumerate(ExecutionPhase))
    return build_execution_header(
        execution_id="execution." + PLAN_DIGEST.removeprefix("sha256:"),
        plan_id="plan.backup.1",
        plan_digest=PLAN_DIGEST,
        bundle_id="bundle.backup.1",
        bundle_digest=BUNDLE_DIGEST,
        approval_ref="approval.backup.1",
        approval_scope_digest=APPROVAL_DIGEST,
        approved_by="operator.1",
        approved_at="2026-08-05T12:00:00Z",
        acceptance_contract_version="contract.v1",
        acceptance_contract_digest=CONTRACT_DIGEST,
        created_at="2026-08-05T12:00:01Z",
        phases=phases,
        approved_runtime_digest=APPROVED_RUNTIME_DIGEST,
        approved_config_digest=APPROVED_CONFIG_DIGEST,
    )


def _chain(header: ProvisioningExecutionHeader) -> tuple[ProvisioningCheckpoint, ...]:
    checkpoints: list[ProvisioningCheckpoint] = []
    previous = header.header_digest
    ordinal = 0
    attestation = RuntimeAttestation(APPROVED_RUNTIME_DIGEST, APPROVED_RUNTIME_DIGEST, APPROVED_CONFIG_DIGEST, APPROVED_CONFIG_DIGEST, "process.1")
    acceptance = BehaviorAcceptance("contract.v1", CONTRACT_DIGEST, True, "ACCEPTANCE_PASSED", CONTRACT_DIGEST)
    for phase in header.phases:
        step = phase.steps[0]
        started = build_checkpoint(
            checkpoint_id=f"checkpoint.{ordinal}", execution_id=header.execution_id,
            checkpoint_ordinal=ordinal, previous_digest=previous, phase=phase.phase,
            phase_ordinal=phase.phase_ordinal, plan_step_ordinal=step.plan_step_ordinal,
            step_digest=step.forward.step_digest, event=CheckpointEvent.STEP_STARTED,
            observed_at=f"2026-08-05T12:{1 + ordinal // 60:02d}:{ordinal % 60:02d}Z",
        )
        checkpoints.append(started)
        previous = started.checkpoint_digest
        ordinal += 1
        evidence = ProvisioningStepEvidence(StepDisposition.CHANGED, "STEP_COMPLETED", CONTRACT_DIGEST, True)
        completed = build_checkpoint(
            checkpoint_id=f"checkpoint.{ordinal}", execution_id=header.execution_id,
            checkpoint_ordinal=ordinal, previous_digest=previous, phase=phase.phase,
            phase_ordinal=phase.phase_ordinal, plan_step_ordinal=step.plan_step_ordinal,
            step_digest=step.forward.step_digest, event=CheckpointEvent.STEP_COMPLETED,
            observed_at=f"2026-08-05T12:{1 + ordinal // 60:02d}:{ordinal % 60:02d}Z", step_evidence=evidence,
            runtime_attestation=attestation if phase.phase is ExecutionPhase.ATTEST else None,
            behavior_acceptance=acceptance if phase.phase is ExecutionPhase.ACCEPT else None,
        )
        checkpoints.append(completed)
        previous = completed.checkpoint_digest
        ordinal += 1
    final_step = header.phases[-1].steps[0]
    checkpoints.append(build_checkpoint(
        checkpoint_id=f"checkpoint.{ordinal}", execution_id=header.execution_id,
        checkpoint_ordinal=ordinal, previous_digest=previous, phase=ExecutionPhase.FINALIZE,
        phase_ordinal=5, plan_step_ordinal=final_step.plan_step_ordinal,
        step_digest=final_step.forward.step_digest, event=CheckpointEvent.EXECUTION_FINALIZED,
        observed_at="2026-08-05T12:03:00Z",
    ))
    return tuple(checkpoints)


def test_c1_contract_module_exposes_frozen_public_types() -> None:
    assert ExecutionPhase.MATERIALIZE.value == "materialize"
    assert StepDisposition.CHANGED.value == "changed"
    assert CheckpointEvent.EXECUTION_FINALIZED.value == "execution_finalized"
    assert ExecutionStepIdentity.__dataclass_params__.frozen
    assert ExecutionPhaseSpec.__dataclass_params__.frozen
    assert ProvisioningExecutionHeader.__dataclass_params__.frozen
    assert RuntimeAttestation.__dataclass_params__.frozen
    assert BehaviorAcceptance.__dataclass_params__.frozen
    assert ProvisioningStepEvidence.__dataclass_params__.frozen
    assert ProvisioningCheckpoint.__dataclass_params__.frozen
    assert ProvisioningExecutionView.__dataclass_params__.frozen


def test_canonical_contract_round_trips_exactly_and_preserves_duplicate_operations() -> None:
    header = _header()
    checkpoints = _chain(header)
    assert header_from_payload(header_payload(header)) == header
    assert checkpoint_from_payload(checkpoint_payload(checkpoints[0])) == checkpoints[0]
    assert execution_header_digest(header) == header.header_digest
    assert provisioning_checkpoint_digest(checkpoints[0]) == checkpoints[0].checkpoint_digest
    assert canonical_json(header) == header_payload(header)
    assert header.phases[0].steps[0].forward.operation == header.phases[1].steps[0].forward.operation
    assert header.phases[0].steps[0].forward.step_digest != header.phases[1].steps[0].forward.step_digest


def test_verified_chain_and_terminal_success_require_finalized_acceptance() -> None:
    header = _header()
    checkpoints = _chain(header)
    assert verify_backup_execution_chain(header, checkpoints) == checkpoints[-1].checkpoint_digest
    view = derive_backup_execution_view(header, checkpoints)
    assert view.terminal_success is True
    assert view.status == "succeeded"
    assert view.evidence_digest == checkpoints[-1].checkpoint_digest
    assert view.behavior_acceptance is not None

    incomplete = checkpoints[:-1]
    assert derive_backup_execution_view(header, incomplete).terminal_success is False


def test_store_persists_v4_header_and_append_only_chain(tmp_path) -> None:
    header = _header()
    checkpoints = _chain(header)
    assert CURRENT_SCHEMA_VERSION == 5
    assert header.schema_version == "2"
    assert checkpoints[0].schema_version == "2"
    with OverseerStore(tmp_path / "state.sqlite3") as store:
        store.save_backup_execution(header, checkpoints[0])
        store.save_backup_execution(header, checkpoints[0])
        for checkpoint in checkpoints[1:]:
            store.append_backup_execution_checkpoint(checkpoint)
        assert store.load_backup_execution_header(header.execution_id) == header
        assert store.load_backup_execution_header_for_plan(header.plan_id) == header
        assert store.load_backup_execution_checkpoints(header.execution_id) == checkpoints
        assert store.load_backup_execution_tail(header.execution_id) == checkpoints[-1]
        assert verify_backup_execution_chain(header, checkpoints) == checkpoints[-1].checkpoint_digest
        assert derive_backup_execution_view(header, checkpoints).terminal_success


def test_store_rejects_conflicting_replay_gaps_forks_and_foreign_steps(tmp_path) -> None:
    header = _header()
    checkpoints = _chain(header)
    with OverseerStore(tmp_path / "state.sqlite3") as store:
        store.save_backup_execution(header, checkpoints[0])
        store.append_backup_execution_checkpoint(checkpoints[0])
        store.append_backup_execution_checkpoint(checkpoints[0])
        with __import__("pytest").raises(ValueError, match="gap"):
            store.append_backup_execution_checkpoint(checkpoints[2])
        with __import__("pytest").raises(ValueError):
            store.append_backup_execution_checkpoint(build_checkpoint(
                checkpoint_id="checkpoint.fork", execution_id=header.execution_id,
                checkpoint_ordinal=1, previous_digest=header.header_digest,
                phase=ExecutionPhase.MATERIALIZE, phase_ordinal=0, plan_step_ordinal=0,
                step_digest=header.phases[0].steps[0].forward.step_digest,
                event=CheckpointEvent.STEP_STARTED, observed_at="2026-08-05T12:09:00Z",
            ))


def test_tamper_dimensions_are_detected() -> None:
    header = _header()
    checkpoints = _chain(header)
    import dataclasses
    import pytest

    for field_name in ("approval_ref", "approval_scope_digest", "acceptance_contract_digest", "created_at"):
        fields_copy = {field.name: getattr(header, field.name) for field in dataclasses.fields(header)}
        fields_copy[field_name] = "approval.changed" if field_name == "approval_ref" else ("2026-08-05T12:00:02Z" if field_name == "created_at" else ("sha256:" + "5" * 64 if field_name == "acceptance_contract_digest" else CONTRACT_DIGEST))
        with pytest.raises(ValueError):
            dataclasses.replace(header, **fields_copy)
    for index, field_name in enumerate(("phase_ordinal", "plan_step_ordinal", "step_digest", "observed_at")):
        checkpoint = checkpoints[0]
        value = 9 if field_name.endswith("ordinal") else (PLAN_DIGEST if field_name == "step_digest" else "2026-08-05T12:09:00Z")
        with pytest.raises(ValueError):
            dataclasses.replace(checkpoint, **{field_name: value})


def test_strict_timestamp_and_json_decoding_contract() -> None:
    header = _header()
    assert "+00:00" in header.approved_at
    assert header_from_payload(header_payload(header)) == header
    with pytest.raises(ValueError):
        header_from_payload(header_payload(header).replace('"plan_id":"plan.backup.1"', '"plan_id":"plan.backup.1","plan_id":"duplicate"'))
    with pytest.raises(ValueError):
        header_from_payload(header_payload(header).replace(header.approved_at, "2026-08-05T12:00:00Z"))
    with pytest.raises(ValueError):
        checkpoint_from_payload('{"checkpoint_id":NaN}')


def test_approved_plan_digest_accepts_absolute_paths_tuples_and_mapping_order() -> None:
    left = {"exec_start": ("/approved/bin", "--safe"), "paths": {"readonly": "/etc/approved"}}
    right = {"paths": {"readonly": "/etc/approved"}, "exec_start": ["/approved/bin", "--safe"]}
    assert canonical_step_digest(PLAN_DIGEST, "forward", 1, "approved", left) == canonical_step_digest(PLAN_DIGEST, "forward", 1, "approved", right)


def test_semantic_validator_rejects_impossible_event_and_evidence_sequences() -> None:
    header = _header()
    step = header.phases[0].steps[0]
    evidence = ProvisioningStepEvidence(StepDisposition.CHANGED, "STEP_COMPLETED", CONTRACT_DIGEST, True)

    def checkpoint(event: CheckpointEvent, *, ordinal: int = 0, previous: str | None = None, **kwargs: object) -> ProvisioningCheckpoint:
        return build_checkpoint(
            checkpoint_id=f"bad.{ordinal}", execution_id=header.execution_id, checkpoint_ordinal=ordinal,
            previous_digest=previous or header.header_digest, phase=ExecutionPhase.MATERIALIZE,
            phase_ordinal=0, plan_step_ordinal=step.plan_step_ordinal, step_digest=step.forward.step_digest,
            event=event, observed_at="2026-08-05T12:10:00Z", **kwargs,
        )

    invalid = (
        checkpoint(CheckpointEvent.STEP_COMPLETED, step_evidence=evidence),
        checkpoint(CheckpointEvent.STEP_STARTED, step_evidence=evidence),
        checkpoint(CheckpointEvent.STEP_STARTED, runtime_attestation=RuntimeAttestation(PLAN_DIGEST, PLAN_DIGEST, BUNDLE_DIGEST, BUNDLE_DIGEST, "process.1")),
    )
    for item in invalid:
        with pytest.raises(ValueError):
            verify_backup_execution_chain(header, (item,))
    started = checkpoint(CheckpointEvent.STEP_STARTED)
    failed_evidence = ProvisioningStepEvidence(StepDisposition.CHANGED, "STEP_COMPLETED", CONTRACT_DIGEST, True)
    failed = checkpoint(CheckpointEvent.STEP_FAILED, ordinal=1, previous=started.checkpoint_digest, step_evidence=failed_evidence)
    with pytest.raises(ValueError):
        verify_backup_execution_chain(header, (started, failed))


def test_direct_schema_update_delete_and_cancellation_rollback(tmp_path) -> None:
    header = _header()
    checkpoint = _chain(header)[0]
    with OverseerStore(tmp_path / "state.sqlite3") as store:
        store.save_backup_execution(header, checkpoint)
        with pytest.raises(Exception):
            store._connection.execute("UPDATE backup_provisioning_execution_headers SET payload='x'")
        with pytest.raises(Exception):
            store._connection.execute("DELETE FROM backup_provisioning_execution_headers")
        with pytest.raises(Exception):
            store._connection.execute("UPDATE backup_provisioning_execution_checkpoints SET payload='x'")
        with pytest.raises(Exception):
            store._connection.execute("DELETE FROM backup_provisioning_execution_checkpoints")
        store._connection.execute("CREATE TABLE tx_probe (value TEXT)")
        store._connection.commit()
        with pytest.raises(KeyboardInterrupt):
            with store.agent_transaction():
                store._connection.execute("INSERT INTO tx_probe VALUES ('rolled back')")
                raise KeyboardInterrupt()
        assert store._connection.execute("SELECT COUNT(*) FROM tx_probe").fetchone()[0] == 0
        with store.agent_transaction():
            store._connection.execute("INSERT INTO tx_probe VALUES ('reusable')")


def test_save_header_and_genesis_roll_back_as_one_transaction(tmp_path, monkeypatch) -> None:
    header = _header(); checkpoint = _chain(header)[0]
    with OverseerStore(tmp_path / "atomic-save.sqlite3") as store:
        def fail_after_header(_checkpoint):
            raise KeyboardInterrupt("injected checkpoint failure")
        monkeypatch.setattr(store, "_append_backup_execution_checkpoint_locked", fail_after_header)
        with pytest.raises(KeyboardInterrupt):
            store.save_backup_execution(header, checkpoint)
        assert store._connection.execute("SELECT COUNT(*) FROM backup_provisioning_execution_headers").fetchone()[0] == 0
        assert store._connection.execute("SELECT COUNT(*) FROM backup_provisioning_execution_checkpoints").fetchone()[0] == 0
        monkeypatch.undo()
        store.save_backup_execution(header, checkpoint)


def test_caught_inner_save_backup_failure_rolls_back_to_savepoint(tmp_path, monkeypatch) -> None:
    header = _header(); checkpoint = _chain(header)[0]
    with OverseerStore(tmp_path / "nested-atomic-save.sqlite3") as store:
        def fail_before_genesis(_checkpoint):
            raise KeyboardInterrupt("injected inner failure")
        monkeypatch.setattr(store, "_append_backup_execution_checkpoint_locked", fail_before_genesis)
        with store.agent_transaction():
            with pytest.raises(KeyboardInterrupt):
                store.save_backup_execution(header, checkpoint)
            assert store._agent_transaction_depth == 1
        assert store._agent_transaction_depth == 0
        assert store._connection.execute("SELECT COUNT(*) FROM backup_provisioning_execution_headers").fetchone()[0] == 0
        assert store._connection.execute("SELECT COUNT(*) FROM backup_provisioning_execution_checkpoints").fetchone()[0] == 0
        monkeypatch.undo()
        store.save_backup_execution(header, checkpoint)


def _payload_with_nested_extra(payload: str, path: tuple[str, ...]) -> str:
    value = json.loads(payload)
    target = value
    for key in path[:-1]:
        target = target[int(key)] if isinstance(target, list) else target[key]
    target[path[-1]] = "unexpected"
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def test_recursive_payload_unknown_fields_are_rejected_at_every_dto_level() -> None:
    header = _header()
    checkpoint = _chain(header)[1]
    cases = (
        (header_payload(header), ("phases", "0", "unexpected")),
        (header_payload(header), ("phases", "0", "steps", "0", "unexpected")),
        (header_payload(header), ("phases", "0", "steps", "0", "forward", "unexpected")),
        (header_payload(_rollback_header()), ("phases", "0", "steps", "0", "rollback", "unexpected")),
        (checkpoint_payload(_chain(header)[1]), ("step_evidence", "unexpected")),
        (checkpoint_payload(_chain(header)[7]), ("runtime_attestation", "unexpected")),
        (checkpoint_payload(_chain(header)[9]), ("behavior_acceptance", "unexpected")),
    )
    for original, path in cases:
        payload = _payload_with_nested_extra(original, path)
        with pytest.raises(ValueError):
            (header_from_payload if payload.startswith('{"acceptance_contract_digest"') else checkpoint_from_payload)(payload)
    for cls, value in (
        (ExecutionPhaseSpec, header.phases[0]),
        (ExecutionStepIdentity, header.phases[0].steps[0]),
        (ProvisioningStepEvidence, checkpoint.step_evidence),
        (RuntimeAttestation, _chain(header)[7].runtime_attestation),
        (BehaviorAcceptance, _chain(header)[9].behavior_acceptance),
    ):
        assert value is not None
        data = {field.name: getattr(value, field.name) for field in dataclasses.fields(cls)}
        data["phase_ordinal" if cls is ExecutionPhaseSpec else "safe_code" if cls is BehaviorAcceptance or cls is ProvisioningStepEvidence else "process_start_id" if cls is RuntimeAttestation else "plan_step_ordinal"] = object()
        with pytest.raises(ValueError):
            cls(**data)


def test_duplicate_keys_and_nonfinite_values_are_rejected_recursively() -> None:
    header = _header()
    payload = header_payload(header)
    with pytest.raises(ValueError):
        header_from_payload(payload.replace('"plan_id":"plan.backup.1"', '"plan_id":"plan.backup.1","plan_id":"duplicate"'))
    with pytest.raises(ValueError):
        checkpoint_from_payload('{"checkpoint_id":NaN}')
    with pytest.raises(ValueError):
        canonical_arguments_digest({"nested": float("inf")})


def test_mutated_header_checkpoint_and_nested_dto_fail_before_persistence(tmp_path) -> None:
    for case in ("header", "operation", "checkpoint"):
        header = _header()
        checkpoint = _chain(header)[0]
        if case == "header":
            object.__setattr__(header, "plan_id", "plan.poisoned")
            digest = lambda: execution_header_digest(header)
            payload = lambda: header_payload(header)
        elif case == "operation":
            object.__setattr__(header.phases[0].steps[0].forward, "operation", "poisoned-operation")
            digest = lambda: execution_header_digest(header)
            payload = lambda: header_payload(header)
        else:
            object.__setattr__(checkpoint, "observed_at", "2026-08-05T11:00:00+00:00")
            digest = lambda: provisioning_checkpoint_digest(checkpoint)
            payload = lambda: checkpoint_payload(checkpoint)
        with pytest.raises(ValueError):
            digest()
        with pytest.raises(ValueError):
            payload()
        with OverseerStore(tmp_path / f"{case}.sqlite3") as store:
            with pytest.raises(ValueError):
                store.save_backup_execution(header, checkpoint)
            assert store._connection.execute("SELECT COUNT(*) FROM backup_provisioning_execution_headers").fetchone()[0] == 0
            assert store._connection.execute("SELECT COUNT(*) FROM backup_provisioning_execution_checkpoints").fetchone()[0] == 0

    header = _header()
    chain = _chain(header)
    genesis = chain[0]
    mutated_checkpoint = chain[1]
    assert mutated_checkpoint.step_evidence is not None
    object.__setattr__(mutated_checkpoint.step_evidence, "safe_code", "POISONED")
    with OverseerStore(tmp_path / "evidence.sqlite3") as store:
        store.save_backup_execution(header, genesis)
        with pytest.raises(ValueError):
            verify_backup_execution_chain(header, (genesis, mutated_checkpoint))
        with pytest.raises(ValueError):
            store.append_backup_execution_checkpoint(mutated_checkpoint)
        assert store.load_backup_execution_header(header.execution_id) == header
        assert store.load_backup_execution_checkpoints(header.execution_id) == (genesis,)


def test_operation_digest_is_required_and_mismatch_cannot_be_bound() -> None:
    with pytest.raises((TypeError, ValueError)):
        ExecutionStepIdentity(0, "operation", "sha256:" + "1" * 64)  # type: ignore[arg-type]
    arguments_digest = canonical_arguments_digest({"x": 1})
    wrong = ExecutionOperationIdentity("operation", arguments_digest, "sha256:" + "1" * 64)
    phase = ExecutionPhaseSpec(0, ExecutionPhase.MATERIALIZE, (ExecutionStepIdentity(0, wrong),))
    with pytest.raises(ValueError):
        build_execution_header(
            execution_id="execution." + PLAN_DIGEST.removeprefix("sha256:"), plan_id="plan.bad", plan_digest=PLAN_DIGEST,
            bundle_id="bundle.bad", bundle_digest=BUNDLE_DIGEST, approval_ref="approval.bad", approval_scope_digest=APPROVAL_DIGEST,
            approved_by="operator.1", approved_at="2026-08-05T12:00:00Z", acceptance_contract_version="contract.v1",
            acceptance_contract_digest=CONTRACT_DIGEST, created_at="2026-08-05T12:00:01Z",
            phases=(phase, *(ExecutionPhaseSpec(i, p, (_header().phases[i].steps[0],)) for i, p in enumerate(ExecutionPhase) if i),),
            approved_runtime_digest=APPROVED_RUNTIME_DIGEST, approved_config_digest=APPROVED_CONFIG_DIGEST,
        )


def _rollback_header() -> ProvisioningExecutionHeader:
    base = _header()
    phases = []
    for phase in base.phases:
        step = phase.steps[0]
        args = {"rollback": step.plan_step_ordinal}
        rollback = ExecutionOperationIdentity(
            f"rollback-operation-{step.plan_step_ordinal}", canonical_arguments_digest(args),
            canonical_step_digest(PLAN_DIGEST, "rollback", step.plan_step_ordinal, f"rollback-operation-{step.plan_step_ordinal}", args),
        )
        phases.append(ExecutionPhaseSpec(phase.phase_ordinal, phase.phase, (ExecutionStepIdentity(step.plan_step_ordinal, step.forward, rollback),)))
    return build_execution_header(
        execution_id=base.execution_id, plan_id="plan.rollback", plan_digest=base.plan_digest, bundle_id="bundle.rollback",
        bundle_digest=base.bundle_digest, approval_ref="approval.rollback", approval_scope_digest=base.approval_scope_digest,
        approved_by=base.approved_by, approved_at=base.approved_at, acceptance_contract_version=base.acceptance_contract_version,
        acceptance_contract_digest=base.acceptance_contract_digest, created_at=base.created_at, phases=tuple(phases),
        approved_runtime_digest=base.approved_runtime_digest, approved_config_digest=base.approved_config_digest,
    )


def _failed_rollback_chain(header: ProvisioningExecutionHeader, rollback_count: int) -> tuple[ProvisioningCheckpoint, ...]:
    out = []
    previous = header.header_digest
    ordinal = 0
    observed = datetime(2026, 8, 5, 12, 1, tzinfo=UTC)
    evidence_ok = ProvisioningStepEvidence(StepDisposition.CHANGED, "STEP_COMPLETED", CONTRACT_DIGEST, True)
    evidence_failed = ProvisioningStepEvidence(StepDisposition.FAILED, "STEP_FAILED", CONTRACT_DIGEST, True)
    def add(step, event, *, rollback=False, evidence=None):
        nonlocal previous, ordinal, observed
        runtime = RuntimeAttestation(APPROVED_RUNTIME_DIGEST, APPROVED_RUNTIME_DIGEST, APPROVED_CONFIG_DIGEST, APPROVED_CONFIG_DIGEST, "process.1") if step == 3 and event is CheckpointEvent.STEP_COMPLETED else None
        behavior = BehaviorAcceptance("contract.v1", CONTRACT_DIGEST, True, "ACCEPTANCE_PASSED", CONTRACT_DIGEST) if step == 4 and event is CheckpointEvent.STEP_COMPLETED else None
        item = build_checkpoint(checkpoint_id=f"rollback.{ordinal}", execution_id=header.execution_id, checkpoint_ordinal=ordinal,
            previous_digest=previous, phase=header.phases[step].phase, phase_ordinal=step, plan_step_ordinal=step,
            step_digest=(header.phases[step].steps[0].rollback if rollback else header.phases[step].steps[0].forward).step_digest,
            event=event, observed_at=observed.isoformat(), step_evidence=evidence, runtime_attestation=runtime, behavior_acceptance=behavior)
        out.append(item); previous = item.checkpoint_digest; ordinal += 1; observed += timedelta(seconds=1)
    for step in range(5):
        add(step, CheckpointEvent.STEP_STARTED); add(step, CheckpointEvent.STEP_COMPLETED, evidence=evidence_ok)
    add(5, CheckpointEvent.STEP_STARTED); add(5, CheckpointEvent.STEP_FAILED, evidence=evidence_failed)
    for step in reversed(range(5)):
        if len(out) - 12 >= rollback_count * 2:
            break
        add(step, CheckpointEvent.ROLLBACK_STARTED, rollback=True)
        add(step, CheckpointEvent.ROLLBACK_COMPLETED, rollback=True, evidence=evidence_ok)
    return tuple(out)


def test_explicit_rollback_identity_and_projection_states() -> None:
    header = _rollback_header()
    partial = _failed_rollback_chain(header, 1)
    assert partial[-1].step_digest == header.phases[4].steps[0].rollback.step_digest
    assert derive_backup_execution_view(header, partial).rollback_status == "in_progress"
    complete = _failed_rollback_chain(header, 5)
    assert derive_backup_execution_view(header, complete).rollback_status == "completed"
    failed = list(complete)
    last = failed[-1]
    failed[-1] = build_checkpoint(checkpoint_id="rollback.failure", execution_id=header.execution_id, checkpoint_ordinal=last.checkpoint_ordinal,
        previous_digest=last.previous_digest, phase=last.phase, phase_ordinal=last.phase_ordinal, plan_step_ordinal=last.plan_step_ordinal,
        step_digest=last.step_digest, event=CheckpointEvent.ROLLBACK_FAILED, observed_at=last.observed_at,
        step_evidence=ProvisioningStepEvidence(StepDisposition.FAILED, "ROLLBACK_FAILED", CONTRACT_DIGEST, True))
    assert derive_backup_execution_view(header, tuple(failed)).rollback_status == "failed"


def test_explicit_wrong_rollback_order_is_rejected() -> None:
    header = _rollback_header()
    chain = list(_failed_rollback_chain(header, 2))
    chain[-4:] = [*chain[-2:], *chain[-4:-2]]
    rebuilt = []
    previous = header.header_digest
    for ordinal, checkpoint in enumerate(chain):
        checkpoint = _rebuild_checkpoint(checkpoint, checkpoint_ordinal=ordinal, previous_digest=previous)
        rebuilt.append(checkpoint)
        previous = checkpoint.checkpoint_digest
    with pytest.raises(ValueError, match="reverse order"):
        verify_backup_execution_chain(header, tuple(rebuilt))


def test_replay_corrupt_prefix_is_rejected_before_matching_checkpoint_return(tmp_path) -> None:
    header = _header(); checkpoints = _chain(header)
    with OverseerStore(tmp_path / "corrupt.sqlite3") as store:
        store.save_backup_execution(header, checkpoints[0])
        store.append_backup_execution_checkpoint(checkpoints[1])
        store._connection.execute("DROP TRIGGER backup_execution_checkpoints_no_update")
        store._connection.execute("UPDATE backup_provisioning_execution_checkpoints SET payload='{}' WHERE checkpoint_ordinal=0")
        store._connection.commit()
        with pytest.raises(ValueError):
            store.append_backup_execution_checkpoint(checkpoints[1])


def test_store_rejects_append_after_finalization_and_rolls_back_baseexception(tmp_path) -> None:
    header = _header(); checkpoints = _chain(header)
    with OverseerStore(tmp_path / "final.sqlite3") as store:
        store.save_backup_execution(header, checkpoints[0])
        for checkpoint in checkpoints[1:]: store.append_backup_execution_checkpoint(checkpoint)
        with pytest.raises(ValueError):
            store.append_backup_execution_checkpoint(build_checkpoint(checkpoint_id="after.final", execution_id=header.execution_id, checkpoint_ordinal=len(checkpoints), previous_digest=checkpoints[-1].checkpoint_digest, phase=ExecutionPhase.MATERIALIZE, phase_ordinal=0, plan_step_ordinal=0, step_digest=header.phases[0].steps[0].forward.step_digest, event=CheckpointEvent.STEP_STARTED, observed_at="2026-08-05T12:03:01+00:00"))
        store._connection.execute("CREATE TABLE probe (value TEXT)")
        store._connection.commit()
        with pytest.raises(BaseException):
            with store.agent_transaction():
                store._connection.execute("INSERT INTO probe VALUES ('poison')")
                raise KeyboardInterrupt()
        assert store._connection.execute("SELECT COUNT(*) FROM probe").fetchone()[0] == 0
        with store.agent_transaction(): store._connection.execute("INSERT INTO probe VALUES ('reusable')")


def _rebuild_checkpoint(checkpoint: ProvisioningCheckpoint, **changes: object) -> ProvisioningCheckpoint:
    values = {field.name: getattr(checkpoint, field.name) for field in dataclasses.fields(checkpoint) if field.name != "checkpoint_digest"}
    values.update(changes)
    return build_checkpoint(**values)


def test_runtime_config_and_acceptance_bindings_are_not_self_approvable() -> None:
    header = _header(); chain = _chain(header)
    bad_runtime = RuntimeAttestation("sha256:" + "9" * 64, "sha256:" + "9" * 64, BUNDLE_DIGEST, BUNDLE_DIGEST, "process.1")
    with pytest.raises(ValueError):
        verify_backup_execution_chain(header, chain[:7] + (_rebuild_checkpoint(chain[7], runtime_attestation=bad_runtime),))
    bad_acceptance = BehaviorAcceptance("contract.v1", "sha256:" + "9" * 64, True, "ACCEPTANCE_PASSED", CONTRACT_DIGEST)
    with pytest.raises(ValueError):
        verify_backup_execution_chain(header, chain[:9] + (_rebuild_checkpoint(chain[9], behavior_acceptance=bad_acceptance),))


def test_failed_attest_and_accept_details_require_their_step_failed_phase() -> None:
    header = _header(); chain = _chain(header)
    failed_evidence = ProvisioningStepEvidence(StepDisposition.FAILED, "ATTEST_FAILED", CONTRACT_DIGEST, True)
    mismatching_runtime = RuntimeAttestation(header.approved_runtime_digest, "sha256:" + "9" * 64, header.approved_config_digest, "sha256:" + "9" * 64, "process.1")
    failed_attest = _rebuild_checkpoint(chain[7], event=CheckpointEvent.STEP_FAILED, step_evidence=failed_evidence, runtime_attestation=mismatching_runtime)
    assert verify_backup_execution_chain(header, chain[:7] + (failed_attest,)) == failed_attest.checkpoint_digest
    assert derive_backup_execution_view(header, chain[:7] + (failed_attest,)).status == "failed"
    unbound_runtime = RuntimeAttestation("sha256:" + "9" * 64, PLAN_DIGEST, "sha256:" + "9" * 64, BUNDLE_DIGEST, "process.1")
    with pytest.raises(ValueError):
        verify_backup_execution_chain(header, chain[:7] + (_rebuild_checkpoint(chain[7], event=CheckpointEvent.STEP_FAILED, step_evidence=failed_evidence, runtime_attestation=unbound_runtime),))
    wrong_phase = _rebuild_checkpoint(chain[1], event=CheckpointEvent.STEP_FAILED, step_evidence=failed_evidence, runtime_attestation=chain[7].runtime_attestation)
    with pytest.raises(ValueError):
        verify_backup_execution_chain(header, (chain[0], wrong_phase))
    failed_acceptance = BehaviorAcceptance("contract.v1", CONTRACT_DIGEST, False, "ACCEPTANCE_FAILED", CONTRACT_DIGEST)
    failed_accept = _rebuild_checkpoint(chain[9], event=CheckpointEvent.STEP_FAILED, step_evidence=ProvisioningStepEvidence(StepDisposition.FAILED, "ACCEPT_FAILED", CONTRACT_DIGEST, True), behavior_acceptance=failed_acceptance)
    assert verify_backup_execution_chain(header, chain[:9] + (failed_accept,)) == failed_accept.checkpoint_digest
    assert derive_backup_execution_view(header, chain[:9] + (failed_accept,)).status == "failed"
    unbound_acceptance = BehaviorAcceptance("contract.v1", "sha256:" + "9" * 64, False, "ACCEPTANCE_FAILED", CONTRACT_DIGEST)
    with pytest.raises(ValueError):
        verify_backup_execution_chain(header, chain[:9] + (_rebuild_checkpoint(chain[9], event=CheckpointEvent.STEP_FAILED, step_evidence=failed_accept.step_evidence, behavior_acceptance=unbound_acceptance),))
    wrong_accept_phase = _rebuild_checkpoint(chain[7], event=CheckpointEvent.STEP_FAILED, step_evidence=failed_evidence, behavior_acceptance=failed_acceptance)
    with pytest.raises(ValueError):
        verify_backup_execution_chain(header, chain[:7] + (wrong_accept_phase,))


def test_approved_and_created_chronology_is_strict() -> None:
    with pytest.raises(ValueError):
        dataclasses.replace(_header(), created_at="2026-08-05T11:59:59+00:00")
    header = _header(); checkpoint = _chain(header)[0]
    with pytest.raises(ValueError):
        verify_backup_execution_chain(header, (_rebuild_checkpoint(checkpoint, observed_at="2026-08-05T11:59:59+00:00"),))
    chain = _chain(header)
    with pytest.raises(ValueError):
        verify_backup_execution_chain(header, chain[:2] + (_rebuild_checkpoint(chain[2], observed_at="2026-08-05T12:01:00+00:00"),))


def test_schema_contract_fk_indexes_and_trigger_sql_are_exact(tmp_path) -> None:
    with OverseerStore(tmp_path / "schema.sqlite3") as store:
        assert store._connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        fk = store._connection.execute("PRAGMA foreign_key_list(backup_provisioning_execution_checkpoints)").fetchone()
        assert tuple(fk)[2:7] == ("backup_provisioning_execution_headers", "execution_id", "execution_id", "RESTRICT", "RESTRICT")
        unique_tuples = {}
        for table in ("backup_provisioning_execution_headers", "backup_provisioning_execution_checkpoints"):
            unique_tuples[table] = {tuple(row[2] for row in store._connection.execute(f"PRAGMA index_info({index[1]})")) for index in store._connection.execute(f"PRAGMA index_list({table})") if index[2]}
        assert unique_tuples["backup_provisioning_execution_headers"] == {("execution_id",), ("plan_id",), ("plan_digest",), ("bundle_id",), ("bundle_digest",), ("header_digest",)}
        assert unique_tuples["backup_provisioning_execution_checkpoints"] == {("checkpoint_id",), ("checkpoint_digest",), ("execution_id", "checkpoint_ordinal")}
        checkpoint_sql = " ".join(store._connection.execute("SELECT sql FROM sqlite_master WHERE name='backup_provisioning_execution_checkpoints'").fetchone()[0].split()).lower()
        for clause in ("check (checkpoint_ordinal >= 0)", "check (phase_ordinal >= 0)", "check (plan_step_ordinal >= 0)"):
            assert clause in checkpoint_sql
        store._connection.execute("DROP TRIGGER backup_execution_headers_no_update")
        store._connection.execute("CREATE TRIGGER backup_execution_headers_no_update BEFORE UPDATE ON backup_provisioning_execution_headers BEGIN SELECT 1; END")
        store._connection.commit()
    with pytest.raises(ValueError, match="immutability triggers"):
        OverseerStore(tmp_path / "schema.sqlite3")


@pytest.mark.parametrize("corruption", ["missing_trigger", "missing_table"])
def test_typed_execution_authority_schema_corruption_is_rejected_on_reopen(tmp_path, corruption) -> None:
    path = tmp_path / f"typed-authority-{corruption}.sqlite3"
    with OverseerStore(path) as store:
        if corruption == "missing_trigger":
            store._connection.execute(
                "DROP TRIGGER backup_provisioning_plan_execution_modes_no_delete"
            )
        else:
            store._connection.execute(
                "DROP TABLE backup_provisioning_plan_execution_modes"
            )
        store._connection.commit()
    with pytest.raises(ValueError, match="typed execution authority|immutability"):
        OverseerStore(path)


def test_schema_rejects_commented_checks_and_partial_unique_indexes(tmp_path) -> None:
    path = tmp_path / "adversarial-schema.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.executescript("""
            CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, description TEXT NOT NULL, applied_at TEXT NOT NULL);
            INSERT INTO schema_migrations VALUES (4, 'current', '2026-08-05T00:00:00+00:00');
            CREATE TABLE agent_schema_migrations (version TEXT PRIMARY KEY, description TEXT NOT NULL, applied_at TEXT NOT NULL);
            INSERT INTO agent_schema_migrations VALUES ('agent_driver_v9', 'current', '2026-08-05T00:00:00+00:00');
            CREATE TABLE backup_provisioning_execution_headers (
                execution_id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, plan_digest TEXT NOT NULL,
                bundle_id TEXT NOT NULL, bundle_digest TEXT NOT NULL,
                approved_runtime_digest TEXT NOT NULL, approved_config_digest TEXT NOT NULL,
                header_digest TEXT NOT NULL, payload TEXT NOT NULL
            );
            CREATE TABLE backup_provisioning_execution_checkpoints (
                checkpoint_id TEXT PRIMARY KEY, execution_id TEXT NOT NULL,
                checkpoint_ordinal INTEGER NOT NULL /* CHECK (checkpoint_ordinal >= 0) */,
                phase_ordinal INTEGER NOT NULL /* CHECK (phase_ordinal >= 0) */,
                plan_step_ordinal INTEGER NOT NULL /* CHECK (plan_step_ordinal >= 0) */,
                step_digest TEXT NOT NULL, previous_digest TEXT NOT NULL,
                checkpoint_digest TEXT NOT NULL, payload TEXT NOT NULL,
                FOREIGN KEY(execution_id) REFERENCES backup_provisioning_execution_headers(execution_id) ON UPDATE RESTRICT ON DELETE RESTRICT
            );
            CREATE UNIQUE INDEX header_plan_id_partial ON backup_provisioning_execution_headers(plan_id) WHERE 0;
            CREATE UNIQUE INDEX header_plan_digest_partial ON backup_provisioning_execution_headers(plan_digest) WHERE 0;
            CREATE UNIQUE INDEX header_bundle_id_partial ON backup_provisioning_execution_headers(bundle_id) WHERE 0;
            CREATE UNIQUE INDEX header_bundle_digest_partial ON backup_provisioning_execution_headers(bundle_digest) WHERE 0;
            CREATE UNIQUE INDEX header_runtime_partial ON backup_provisioning_execution_headers(approved_runtime_digest) WHERE 0;
            CREATE UNIQUE INDEX header_config_partial ON backup_provisioning_execution_headers(approved_config_digest) WHERE 0;
            CREATE UNIQUE INDEX header_digest_partial ON backup_provisioning_execution_headers(header_digest) WHERE 0;
            CREATE UNIQUE INDEX checkpoint_digest_partial ON backup_provisioning_execution_checkpoints(checkpoint_digest) WHERE 0;
            CREATE UNIQUE INDEX checkpoint_execution_ordinal_partial ON backup_provisioning_execution_checkpoints(execution_id, checkpoint_ordinal) WHERE 0;
            CREATE TRIGGER backup_execution_headers_no_update BEFORE UPDATE ON backup_provisioning_execution_headers BEGIN SELECT RAISE(ABORT, 'backup execution headers are immutable'); END;
            CREATE TRIGGER backup_execution_headers_no_delete BEFORE DELETE ON backup_provisioning_execution_headers BEGIN SELECT RAISE(ABORT, 'backup execution headers are immutable'); END;
            CREATE TRIGGER backup_execution_checkpoints_no_update BEFORE UPDATE ON backup_provisioning_execution_checkpoints BEGIN SELECT RAISE(ABORT, 'backup execution checkpoints are immutable'); END;
            CREATE TRIGGER backup_execution_checkpoints_no_delete BEFORE DELETE ON backup_provisioning_execution_checkpoints BEGIN SELECT RAISE(ABORT, 'backup execution checkpoints are immutable'); END;
        """)
    with pytest.raises(ValueError, match="malformed backup execution"):
        OverseerStore(path)


def test_schema_rejects_extra_duplicate_partial_unique_index(tmp_path) -> None:
    path = tmp_path / "extra-index.sqlite3"
    with OverseerStore(path) as store:
        store._connection.execute("CREATE UNIQUE INDEX extra_partial_backup_header ON backup_provisioning_execution_headers(plan_id) WHERE 0")
        store._connection.commit()
    with pytest.raises(ValueError, match="schema indexes"):
        OverseerStore(path)


@pytest.mark.parametrize(
    ("table", "column", "value"),
    (
        ("backup_provisioning_execution_headers", "plan_id", "tampered-plan"),
        ("backup_provisioning_execution_headers", "plan_digest", "tampered-plan-digest"),
        ("backup_provisioning_execution_headers", "payload", "{}"),
        ("backup_provisioning_execution_checkpoints", "checkpoint_ordinal", "8"),
        ("backup_provisioning_execution_checkpoints", "phase_ordinal", "8"),
        ("backup_provisioning_execution_checkpoints", "plan_step_ordinal", "8"),
        ("backup_provisioning_execution_checkpoints", "step_digest", "tampered-step"),
        ("backup_provisioning_execution_checkpoints", "payload", "{}"),
    ),
)
def test_reopen_rejects_tampered_redundant_backup_fields(tmp_path, table, column, value) -> None:
    path = tmp_path / f"tamper-{table.rsplit('_', 1)[-1]}-{column}.sqlite3"
    header = _header(); checkpoint = _chain(header)[0]
    trigger = "backup_execution_headers_no_update" if table.endswith("headers") else "backup_execution_checkpoints_no_update"
    trigger_sql = "CREATE TRIGGER " + trigger + " BEFORE UPDATE ON " + table + " BEGIN SELECT RAISE(ABORT, '" + ("backup execution headers" if table.endswith("headers") else "backup execution checkpoints") + " are immutable'); END"
    with OverseerStore(path) as store:
        store.save_backup_execution(header, checkpoint)
        store._connection.execute(f"DROP TRIGGER {trigger}")
        store._connection.execute(f"UPDATE {table} SET {column}=?", (value,))
        store._connection.execute(trigger_sql)
        store._connection.commit()
    with OverseerStore(path) as store:
        with pytest.raises(ValueError):
            if table.endswith("headers"):
                store.load_backup_execution_header(header.execution_id)
            else:
                store.load_backup_execution_checkpoints(header.execution_id)


def test_v3_to_v4_migration_preserves_unrelated_rows_and_indexes(tmp_path) -> None:
    path = tmp_path / "v3.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.executescript("""
            CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, description TEXT NOT NULL, applied_at TEXT NOT NULL);
            INSERT INTO schema_migrations VALUES (3, 'old', '2026-08-05T00:00:00+00:00');
            CREATE TABLE unrelated (id TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE INDEX unrelated_value_idx ON unrelated(value);
            INSERT INTO unrelated VALUES ('keep', 'value');
            CREATE TABLE backup_provisioning_execution_headers (execution_id TEXT PRIMARY KEY, plan_id TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL UNIQUE, bundle_id TEXT NOT NULL UNIQUE, bundle_digest TEXT NOT NULL UNIQUE, header_digest TEXT NOT NULL UNIQUE, payload TEXT NOT NULL);
            CREATE TABLE backup_provisioning_execution_checkpoints (checkpoint_id TEXT PRIMARY KEY, execution_id TEXT NOT NULL, checkpoint_ordinal INTEGER NOT NULL CHECK (checkpoint_ordinal >= 0), phase_ordinal INTEGER NOT NULL CHECK (phase_ordinal >= 0), plan_step_ordinal INTEGER NOT NULL CHECK (plan_step_ordinal >= 0), step_digest TEXT NOT NULL, previous_digest TEXT NOT NULL, checkpoint_digest TEXT NOT NULL UNIQUE, payload TEXT NOT NULL, UNIQUE(execution_id, checkpoint_ordinal), FOREIGN KEY(execution_id) REFERENCES backup_provisioning_execution_headers(execution_id));
            CREATE TRIGGER backup_execution_headers_no_update BEFORE UPDATE ON backup_provisioning_execution_headers BEGIN SELECT RAISE(ABORT, 'backup execution headers are immutable'); END;
            CREATE TRIGGER backup_execution_headers_no_delete BEFORE DELETE ON backup_provisioning_execution_headers BEGIN SELECT RAISE(ABORT, 'backup execution headers are immutable'); END;
            CREATE TRIGGER backup_execution_checkpoints_no_update BEFORE UPDATE ON backup_provisioning_execution_checkpoints BEGIN SELECT RAISE(ABORT, 'backup execution checkpoints are immutable'); END;
            CREATE TRIGGER backup_execution_checkpoints_no_delete BEFORE DELETE ON backup_provisioning_execution_checkpoints BEGIN SELECT RAISE(ABORT, 'backup execution checkpoints are immutable'); END;
        """)
    with OverseerStore(path) as store:
        assert store._connection.execute("SELECT value FROM unrelated WHERE id='keep'").fetchone()[0] == "value"
        assert store._connection.execute("SELECT 1 FROM pragma_index_list('unrelated') WHERE name='unrelated_value_idx'").fetchone() is not None
        assert tuple(row[1] for row in store._connection.execute("PRAGMA table_info(backup_provisioning_execution_headers)")) == ("execution_id", "plan_id", "plan_digest", "bundle_id", "bundle_digest", "approved_runtime_digest", "approved_config_digest", "header_digest", "payload")


def test_v3_to_v4_migration_rolls_back_mid_statement_failure(tmp_path) -> None:
    path = tmp_path / "v3-failure.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.executescript("""
            CREATE TABLE backup_provisioning_execution_headers (execution_id TEXT PRIMARY KEY, plan_id TEXT NOT NULL UNIQUE, plan_digest TEXT NOT NULL UNIQUE, bundle_id TEXT NOT NULL UNIQUE, bundle_digest TEXT NOT NULL UNIQUE, header_digest TEXT NOT NULL UNIQUE, payload TEXT NOT NULL);
            CREATE TABLE backup_provisioning_execution_checkpoints (checkpoint_id TEXT PRIMARY KEY, execution_id TEXT NOT NULL, checkpoint_ordinal INTEGER NOT NULL CHECK (checkpoint_ordinal >= 0), phase_ordinal INTEGER NOT NULL CHECK (phase_ordinal >= 0), plan_step_ordinal INTEGER NOT NULL CHECK (plan_step_ordinal >= 0), step_digest TEXT NOT NULL, previous_digest TEXT NOT NULL, checkpoint_digest TEXT NOT NULL UNIQUE, payload TEXT NOT NULL, UNIQUE(execution_id, checkpoint_ordinal), FOREIGN KEY(execution_id) REFERENCES backup_provisioning_execution_headers(execution_id));
            CREATE TRIGGER backup_execution_headers_no_update BEFORE UPDATE ON backup_provisioning_execution_headers BEGIN SELECT RAISE(ABORT, 'backup execution headers are immutable'); END;
            CREATE TRIGGER backup_execution_headers_no_delete BEFORE DELETE ON backup_provisioning_execution_headers BEGIN SELECT RAISE(ABORT, 'backup execution headers are immutable'); END;
            CREATE TRIGGER backup_execution_checkpoints_no_update BEFORE UPDATE ON backup_provisioning_execution_checkpoints BEGIN SELECT RAISE(ABORT, 'backup execution checkpoints are immutable'); END;
            CREATE TRIGGER backup_execution_checkpoints_no_delete BEFORE DELETE ON backup_provisioning_execution_checkpoints BEGIN SELECT RAISE(ABORT, 'backup execution checkpoints are immutable'); END;
        """)

    class FailingConnection:
        def __init__(self, connection):
            self.connection = connection
            self.calls = 0
        @property
        def in_transaction(self):
            return self.connection.in_transaction
        def execute(self, sql, parameters=()):
            self.calls += 1
            if self.calls == 9:
                raise KeyboardInterrupt("injected migration failure")
            return self.connection.execute(sql, parameters)
        def rollback(self):
            return self.connection.rollback()
        def commit(self):
            return self.connection.commit()

    raw = sqlite3.connect(path)
    store = OverseerStore.__new__(OverseerStore)
    store._connection = FailingConnection(raw)
    with pytest.raises(KeyboardInterrupt):
        store._migrate_backup_execution_v3()
    assert {row[0] for row in raw.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()} == {"backup_provisioning_execution_headers", "backup_provisioning_execution_checkpoints"}
    assert tuple(row[1] for row in raw.execute("PRAGMA table_info(backup_provisioning_execution_headers)")) == ("execution_id", "plan_id", "plan_digest", "bundle_id", "bundle_digest", "header_digest", "payload")
    assert {row[0] for row in raw.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall()} == {"backup_execution_headers_no_update", "backup_execution_headers_no_delete", "backup_execution_checkpoints_no_update", "backup_execution_checkpoints_no_delete"}
    raw.execute("CREATE TABLE reusable_after_migration_failure (value TEXT NOT NULL)")
    raw.commit()
    raw.close()


def test_two_connections_racing_same_genesis_have_one_tail(tmp_path) -> None:
    path = tmp_path / "race.sqlite3"; header = _header(); checkpoint = _chain(header)[0]
    OverseerStore(path).close()
    barrier = Barrier(2); results: list[BaseException | None] = []
    def writer() -> None:
        try:
            with OverseerStore(path) as store:
                barrier.wait(); store.save_backup_execution(header, checkpoint)
            results.append(None)
        except BaseException as error:
            results.append(error)
    threads = [Thread(target=writer) for _ in range(2)]
    for thread in threads: thread.start()
    for thread in threads: thread.join()
    assert results.count(None) == 2
    with OverseerStore(path) as store:
        assert store.load_backup_execution_checkpoints(header.execution_id) == (checkpoint,)


def test_two_connections_racing_distinct_checkpoints_have_one_winner(tmp_path) -> None:
    path = tmp_path / "fork-race.sqlite3"; header = _header(); chain = _chain(header)
    with OverseerStore(path) as store:
        store.save_backup_execution(header, chain[0])
    competing = (chain[1], _rebuild_checkpoint(chain[1], checkpoint_id="checkpoint.other", observed_at="2026-08-05T12:01:02+00:00"))
    barrier = Barrier(2); results: list[BaseException | None] = []
    def writer(checkpoint: ProvisioningCheckpoint) -> None:
        try:
            with OverseerStore(path) as store:
                barrier.wait(); store.append_backup_execution_checkpoint(checkpoint)
            results.append(None)
        except BaseException as error:
            results.append(error)
    threads = [Thread(target=writer, args=(checkpoint,)) for checkpoint in competing]
    for thread in threads: thread.start()
    for thread in threads: thread.join()
    assert results.count(None) == 1
    with OverseerStore(path) as store:
        tail = store.load_backup_execution_checkpoints(header.execution_id)
        assert len(tail) == 2
        assert tail[1] in competing
