"""Contract-first tests for append-only backup execution persistence."""

from __future__ import annotations

import pytest

from overseer.backup_execution import (
    BehaviorAcceptance,
    CheckpointEvent,
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


def _header() -> ProvisioningExecutionHeader:
    steps = tuple(
        ExecutionStepIdentity(
            ordinal,
            "duplicate-operation",
            canonical_step_digest(PLAN_DIGEST, "forward", ordinal, "duplicate-operation", {"ordinal": ordinal}),
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
    )


def _chain(header: ProvisioningExecutionHeader) -> tuple[ProvisioningCheckpoint, ...]:
    checkpoints: list[ProvisioningCheckpoint] = []
    previous = header.header_digest
    ordinal = 0
    attestation = RuntimeAttestation(PLAN_DIGEST, PLAN_DIGEST, BUNDLE_DIGEST, BUNDLE_DIGEST, "process.1")
    acceptance = BehaviorAcceptance("contract.v1", True, "ACCEPTANCE_PASSED", CONTRACT_DIGEST)
    for phase in header.phases:
        step = phase.steps[0]
        started = build_checkpoint(
            checkpoint_id=f"checkpoint.{ordinal}", execution_id=header.execution_id,
            checkpoint_ordinal=ordinal, previous_digest=previous, phase=phase.phase,
            phase_ordinal=phase.phase_ordinal, plan_step_ordinal=step.plan_step_ordinal,
            step_digest=step.step_digest, event=CheckpointEvent.STEP_STARTED,
            observed_at=f"2026-08-05T12:01:{ordinal:02d}Z",
        )
        checkpoints.append(started)
        previous = started.checkpoint_digest
        ordinal += 1
        evidence = ProvisioningStepEvidence(StepDisposition.CHANGED, "STEP_COMPLETED", CONTRACT_DIGEST, True)
        completed = build_checkpoint(
            checkpoint_id=f"checkpoint.{ordinal}", execution_id=header.execution_id,
            checkpoint_ordinal=ordinal, previous_digest=previous, phase=phase.phase,
            phase_ordinal=phase.phase_ordinal, plan_step_ordinal=step.plan_step_ordinal,
            step_digest=step.step_digest, event=CheckpointEvent.STEP_COMPLETED,
            observed_at=f"2026-08-05T12:02:{ordinal:02d}Z", step_evidence=evidence,
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
        step_digest=final_step.step_digest, event=CheckpointEvent.EXECUTION_FINALIZED,
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
    assert header.phases[0].steps[0].operation == header.phases[1].steps[0].operation
    assert header.phases[0].steps[0].step_digest != header.phases[1].steps[0].step_digest


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
    assert CURRENT_SCHEMA_VERSION == 4
    with OverseerStore(tmp_path / "state.sqlite3") as store:
        store.save_backup_execution_header(header)
        store.save_backup_execution_header(header)
        for checkpoint in checkpoints:
            store.append_backup_execution_checkpoint(checkpoint)
        assert store.load_backup_execution_header(header.execution_id) == header
        assert store.load_backup_execution_header_for_plan(header.plan_id) == header
        assert store.load_backup_execution_checkpoints(header.execution_id) == checkpoints
        assert store.load_backup_execution_tail(header.execution_id) == checkpoints[-1]
        assert store.verify_backup_execution_chain(header, checkpoints) == checkpoints[-1].checkpoint_digest
        assert store.derive_backup_execution_view(header, checkpoints).terminal_success


def test_store_rejects_conflicting_replay_gaps_forks_and_foreign_steps(tmp_path) -> None:
    header = _header()
    checkpoints = _chain(header)
    with OverseerStore(tmp_path / "state.sqlite3") as store:
        store.save_backup_execution_header(header)
        store.append_backup_execution_checkpoint(checkpoints[0])
        store.append_backup_execution_checkpoint(checkpoints[0])
        with __import__("pytest").raises(ValueError, match="gap"):
            store.append_backup_execution_checkpoint(checkpoints[2])
        with __import__("pytest").raises(ValueError):
            store.append_backup_execution_checkpoint(build_checkpoint(
                checkpoint_id="checkpoint.fork", execution_id=header.execution_id,
                checkpoint_ordinal=1, previous_digest=header.header_digest,
                phase=ExecutionPhase.MATERIALIZE, phase_ordinal=0, plan_step_ordinal=0,
                step_digest=header.phases[0].steps[0].step_digest,
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
            phase_ordinal=0, plan_step_ordinal=step.plan_step_ordinal, step_digest=step.step_digest,
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
    with OverseerStore(tmp_path / "state.sqlite3") as store:
        store.save_backup_execution_header(header)
        with pytest.raises(Exception):
            store._connection.execute("UPDATE backup_provisioning_execution_headers SET payload='x'")
        with pytest.raises(Exception):
            store._connection.execute("DELETE FROM backup_provisioning_execution_headers")
        store._connection.execute("CREATE TABLE tx_probe (value TEXT)")
        store._connection.commit()
        with pytest.raises(KeyboardInterrupt):
            with store.agent_transaction():
                store._connection.execute("INSERT INTO tx_probe VALUES ('rolled back')")
                raise KeyboardInterrupt()
        assert store._connection.execute("SELECT COUNT(*) FROM tx_probe").fetchone()[0] == 0
        with store.agent_transaction():
            store._connection.execute("INSERT INTO tx_probe VALUES ('reusable')")
