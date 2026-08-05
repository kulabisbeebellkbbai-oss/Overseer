"""Integration coverage for the typed, resumable provisioning coordinator."""
from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
import hashlib
import multiprocessing
import os
from pathlib import Path
import sqlite3
import socket
import threading

import pytest

from overseer.backup_execution import (
    BehaviorAcceptance,
    CheckpointEvent,
    ExecutionPhase,
    RuntimeAttestation,
    _reconcile_executed,
    _manifest,
    canonical_arguments_digest,
    continue_execution,
    start_execution,
)
from overseer.backup_provisioning import ProvisioningStatus, ProvisioningStep, _dump, _stored, _typed_execution_enabled_for_plan_locked, approve_plan, build_plan, execute_plan, stage_plan
from overseer.crew import CrewReviewStatus
from overseer.store import SQLiteStore
from tests.test_backup_provisioning import _typed_bundle_with_reviews


class RecordingAdapter:
    def __init__(self, *, fail_operation: str | None = None) -> None:
        self.calls: list[ProvisioningStep] = []
        self.fail_operation = fail_operation

    def execute(self, step: ProvisioningStep) -> dict[str, object]:
        self.calls.append(step)
        if step.operation == self.fail_operation:
            return {
                "ok": False,
                "operation": step.operation,
                "disposition": "changed",
                "safe_code": "OPERATION_REPORTED_FAILURE",
                "evidence": {"secret": "must-not-persist"},
                "redactions_applied": True,
            }
        return {
            "ok": True,
            "operation": step.operation,
            "disposition": "changed",
            "safe_code": "STEP_COMPLETED",
            "evidence": {"private_path": "/should-not-persist"},
            "redactions_applied": True,
        }


class NoopAdapter(RecordingAdapter):
    def execute(self, step: ProvisioningStep) -> dict[str, object]:
        self.calls.append(step)
        return {
            "ok": True,
            "operation": step.operation,
            "disposition": "verified_noop",
            "safe_code": "STEP_VERIFIED_NOOP",
            "evidence": {},
            "redactions_applied": True,
        }


class BlockingAdapter(RecordingAdapter):
    def __init__(self, started: threading.Event, release: threading.Event) -> None:
        super().__init__()
        self.started = started
        self.release = release

    def execute(self, step: ProvisioningStep) -> dict[str, object]:
        self.started.set()
        self.release.wait(timeout=10)
        return super().execute(step)


class Runner:
    def __init__(self, *, wrong_runtime: bool = False, wrong_config: bool = False, passed: bool = True) -> None:
        self.wrong_runtime = wrong_runtime
        self.wrong_config = wrong_config
        self.passed = passed
        self.attest_calls = 0
        self.accept_calls = 0

    def attest(self, header):
        self.attest_calls += 1
        runtime = "sha256:" + "9" * 64 if self.wrong_runtime else header.approved_runtime_digest
        config = "sha256:" + "8" * 64 if self.wrong_config else header.approved_config_digest
        return RuntimeAttestation(runtime, runtime, config, config, "process.start.1")

    def accept(self, header, attestation):
        self.accept_calls += 1
        return BehaviorAcceptance(
            header.acceptance_contract_version,
            header.acceptance_contract_digest,
            self.passed,
            "ACCEPTANCE_PASSED" if self.passed else "ACCEPTANCE_FAILED",
            "sha256:" + "a" * 64,
        )


def _owner_lock_process(path: str, execution_id: str, ready, release, crash: bool) -> None:
    from types import SimpleNamespace
    from overseer.backup_execution import _RollbackOwnerLock

    status = Path(path).stat()
    lock = _RollbackOwnerLock.acquire(SimpleNamespace(path=Path(path), _database_identity=(status.st_dev, status.st_ino)), execution_id)
    ready.set()
    if crash:
        os._exit(0)
    release.wait(timeout=10)
    lock.release()


def _approved(tmp_path: Path):
    store_path, plan, bundle = _typed_bundle_with_reviews(tmp_path)
    approve_plan(store_path, plan.plan_id, "independent-human")
    return store_path, plan, bundle


def _execution_time_at_or_after_approval(store_path: str, plan_id: str) -> str:
    with SQLiteStore(store_path) as store:
        approved_at = _stored(store, plan_id).approved_at
    assert approved_at is not None
    return (datetime.fromisoformat(approved_at.replace("Z", "+00:00")).astimezone(UTC) + timedelta(seconds=1)).isoformat()


def test_exact_manifest_phase_order_and_arguments_are_used(tmp_path: Path) -> None:
    store_path, plan, _bundle = _approved(tmp_path)
    execution_time = _execution_time_at_or_after_approval(store_path, plan.plan_id)
    adapter = RecordingAdapter()
    runner = Runner()

    view = start_execution(store_path, plan.plan_id, adapter, runner)

    assert view.terminal_success is True
    assert [step.operation for step in adapter.calls] == [step.operation for step in plan.steps]
    assert [canonical_arguments_digest(step.arguments) for step in adapter.calls] == [canonical_arguments_digest(step.arguments) for step in plan.steps]
    with SQLiteStore(store_path) as store:
        header = store.load_backup_execution_header(view.execution_id)
        assert header.created_at == header.approved_at
        assert header.approved_runtime_digest == plan.runtime_artifact_identity
        assert tuple(phase.phase for phase in header.phases) == tuple(ExecutionPhase)
        assert tuple(step.plan_step_ordinal for phase in header.phases for step in phase.steps) == tuple(range(len(plan.steps) + 3))


def test_missing_runner_pauses_before_attest_and_later_resume_skips_prefix(tmp_path: Path) -> None:
    store_path, plan, _bundle = _approved(tmp_path)
    adapter = RecordingAdapter()

    paused = start_execution(store_path, plan.plan_id, adapter, None)
    assert paused.status == "in_progress"
    assert len(adapter.calls) == len(plan.steps)
    with SQLiteStore(store_path) as store:
        checkpoints = store.load_backup_execution_checkpoints(paused.execution_id)
        assert checkpoints[-1].event is CheckpointEvent.STEP_COMPLETED
        assert checkpoints[-1].plan_step_ordinal == len(plan.steps) - 1

    resumed = continue_execution(store_path, paused.execution_id, adapter, Runner())
    assert resumed.terminal_success is True
    assert len(adapter.calls) == len(plan.steps)


def test_wrong_runtime_fails_closed_and_rolls_back_exact_reverse_subset(tmp_path: Path) -> None:
    store_path, plan, _bundle = _approved(tmp_path)
    adapter = RecordingAdapter()
    view = start_execution(store_path, plan.plan_id, adapter, Runner(wrong_runtime=True))

    assert view.terminal_success is False
    assert view.rollback_status == "completed"
    forward = [step.operation for step in plan.steps]
    calls = [step.operation for step in adapter.calls]
    assert calls[: len(forward)] == forward
    assert calls[len(forward):] == [
        "stop_disable_system_service", "remove_systemd_unit", "restore_enable_user_service",
        "remove_private_config", "remove_read_only_acl", "remove_cursor_key_if_unreferenced",
        "remove_overseer_api_token", "remove_secret_file_if_no_backups",
        "remove_directory_if_empty", "remove_directory_if_empty",
        "remove_directory_if_empty", "remove_directory_if_empty",
        "remove_system_user_if_unused", "remove_runtime_if_unreferenced",
    ]
    assert "/should-not-persist" not in repr(view)
    assert "must-not-persist" not in repr(view)


def test_wrong_config_and_failed_acceptance_cannot_finalize(tmp_path: Path) -> None:
    store_path, plan, _bundle = _approved(tmp_path)
    adapter = RecordingAdapter()
    wrong_config = start_execution(store_path, plan.plan_id, adapter, Runner(wrong_config=True))
    assert wrong_config.terminal_success is False
    assert wrong_config.rollback_status == "completed"

    store_path, plan, _bundle = _approved(tmp_path / "acceptance")
    adapter = RecordingAdapter()
    failed = start_execution(store_path, plan.plan_id, adapter, Runner(passed=False))
    assert failed.terminal_success is False
    assert failed.behavior_acceptance is not None and failed.behavior_acceptance.passed is False
    assert failed.rollback_status == "completed"


def test_completed_rollback_pure_loser_performs_no_mutation_or_adapter_call(tmp_path: Path) -> None:
    store_path, plan, _bundle = _approved(tmp_path)
    winner_adapter = RecordingAdapter()
    winner = execute_plan(store_path, plan.plan_id, winner_adapter, acceptance_runner=Runner(wrong_runtime=True))
    assert winner["status"] == "rolled_back"

    loser_adapter = RecordingAdapter()
    loser = execute_plan(store_path, plan.plan_id, loser_adapter, acceptance_runner=Runner(wrong_runtime=True))

    assert loser["status"] == "rolled_back"
    assert loser["mutation_performed"] is False
    assert loser["host_mutation_performed"] is False
    assert loser["host_mutation_uncertain"] is False
    assert loser_adapter.calls == []


def test_concurrent_rollback_pure_loser_uses_zero_mutation_snapshot(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_execution as execution

    store_path, plan, _bundle = _approved(tmp_path)
    execution_time = _execution_time_at_or_after_approval(store_path, plan.plan_id)
    original_rollback = execution._rollback

    def stop_before_rollback(*args, **kwargs):
        raise BaseException("seed exact failed tail")

    monkeypatch.setattr(execution, "_rollback", stop_before_rollback)
    with pytest.raises(BaseException, match="seed exact failed tail"):
        start_execution(store_path, plan.plan_id, RecordingAdapter(), Runner(wrong_runtime=True), now=execution_time)
    monkeypatch.setattr(execution, "_rollback", original_rollback)

    caller_a_ready = threading.Event()
    release_a = threading.Event()
    original_claim = execution._claim_rollback
    adapter_a = RecordingAdapter()
    adapter_b = RecordingAdapter()
    results: dict[str, object] = {}

    def pause_a(store, header, requested, when, owner_id):
        if threading.current_thread().name == "rollback-loser" and not caller_a_ready.is_set():
            caller_a_ready.set()
            assert release_a.wait(timeout=10)
        return original_claim(store, header, requested, when, owner_id)

    monkeypatch.setattr(execution, "_claim_rollback", pause_a)

    def run_a() -> None:
        results["a"] = execute_plan(store_path, plan.plan_id, adapter_a, acceptance_runner=Runner(wrong_runtime=True))

    def run_b() -> None:
        results["b"] = execute_plan(store_path, plan.plan_id, adapter_b, acceptance_runner=Runner(wrong_runtime=True))

    caller_a = threading.Thread(target=run_a, name="rollback-loser")
    caller_b = threading.Thread(target=run_b, name="rollback-winner")
    caller_a.start()
    assert caller_a_ready.wait(timeout=10)
    caller_b.start()
    caller_b.join(timeout=10)
    assert not caller_b.is_alive()
    release_a.set()
    caller_a.join(timeout=10)
    assert not caller_a.is_alive()

    loser = results["a"]
    assert loser["status"] == "rolled_back"
    assert loser["mutation_performed"] is False
    assert loser["host_mutation_performed"] is False
    assert loser["host_mutation_uncertain"] is False
    assert adapter_a.calls == []
    assert len(adapter_b.calls) == len(plan.rollback_steps)
    assert [step.operation for step in adapter_b.calls] == [step.operation for step in plan.rollback_steps]


def test_rollback_owner_retains_prior_changed_attribution_when_next_is_claimed(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_execution as execution
    import overseer.backup_provisioning as provisioning

    store_path, plan, _bundle = _approved(tmp_path)
    owner_before_next_claim = threading.Event()
    next_rollback_claimed = threading.Event()
    release_owner = threading.Event()
    owner_adapter = RecordingAdapter()
    contender_adapter = RecordingAdapter()
    results: dict[str, object] = {}
    captured: dict[str, object] = {}
    original_claim = execution._claim_rollback
    original_public = provisioning._typed_execution_public

    rollback_operations = {step.operation for step in plan.rollback_steps}

    claim_count = {"owner": 0}

    def pause_before_next_claim(store, header, requested, when, owner_id):
        if threading.current_thread().name == "rollback-owner":
            claim_count["owner"] += 1
            if claim_count["owner"] == 2:
                owner_before_next_claim.set()
                assert release_owner.wait(timeout=10)
        return original_claim(store, header, requested, when, owner_id)

    def observe_public(plan_arg, view, checkpoints, **kwargs):
        if threading.current_thread().name == "rollback-owner":
            captured["owner"] = (view, kwargs["invocation_checkpoints"])
        return original_public(plan_arg, view, checkpoints, **kwargs)

    def observe_execute(step):
        if step.operation in rollback_operations and not next_rollback_claimed.is_set():
            next_rollback_claimed.set()
        return RecordingAdapter.execute(contender_adapter, step)

    monkeypatch.setattr(execution, "_claim_rollback", pause_before_next_claim)
    monkeypatch.setattr(provisioning, "_typed_execution_public", observe_public)
    contender_adapter.execute = observe_execute

    def run_owner() -> None:
        results["owner"] = execute_plan(
            store_path, plan.plan_id, owner_adapter, acceptance_runner=Runner(wrong_runtime=True)
        )

    def run_contender() -> None:
        results["contender"] = execute_plan(
            store_path, plan.plan_id, contender_adapter, acceptance_runner=Runner(wrong_runtime=True)
        )

    owner = threading.Thread(target=run_owner, name="rollback-owner")
    contender = threading.Thread(target=run_contender, name="rollback-contender")
    owner.start()
    assert owner_before_next_claim.wait(timeout=10)
    contender.start()
    assert next_rollback_claimed.wait(timeout=10)
    release_owner.set()
    owner.join(timeout=10)
    contender.join(timeout=10)

    assert not owner.is_alive()
    assert not contender.is_alive()
    assert results["owner"]["mutation_performed"] is True
    assert results["owner"]["host_mutation_performed"] is True
    owner_view, owner_checkpoints = captured["owner"]
    assert owner_view.rollback_status == "in_progress"
    assert any(item.event is CheckpointEvent.ROLLBACK_COMPLETED for item in owner_checkpoints)
    assert sum(step.operation in rollback_operations for step in owner_adapter.calls) == 1
    assert sum(step.operation in rollback_operations for step in contender_adapter.calls) == len(plan.rollback_steps) - 1


def test_rollback_does_not_swallow_unrelated_tamper_error_as_contention(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_execution as execution

    store_path, plan, _bundle = _approved(tmp_path)

    original_append = execution._append
    interrupted = {"value": False}

    def interrupt_after_claim(*args, **kwargs):
        result = original_append(*args, **kwargs)
        if args[4] is CheckpointEvent.ROLLBACK_STARTED and not interrupted["value"]:
            interrupted["value"] = True
            raise BaseException("crash after rollback claim")
        return result

    monkeypatch.setattr(execution, "_append", interrupt_after_claim)
    with pytest.raises(BaseException, match="crash after rollback claim"):
        start_execution(store_path, plan.plan_id, RecordingAdapter(), Runner(wrong_runtime=True))
    monkeypatch.setattr(execution, "_append", original_append)

    def unrelated_claim_error(*args, **kwargs):
        raise ValueError("rollback checkpoint persistence invariant was violated")

    monkeypatch.setattr(execution, "_claim_rollback", unrelated_claim_error)
    with pytest.raises(ValueError, match="persistence invariant"):
        continue_execution(store_path, execution_id_for(store_path, plan.plan_id), RecordingAdapter(), Runner(wrong_runtime=True))


def test_interrupted_durable_rollback_claim_is_replayed_after_lease_expiry(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_execution as execution

    store_path, plan, _bundle = _approved(tmp_path)
    execution_time = _execution_time_at_or_after_approval(store_path, plan.plan_id)
    claim_clock = datetime.fromisoformat(execution_time)
    monkeypatch.setattr(execution, "_rollback_claim_clock", lambda: claim_clock.isoformat())
    original_append = execution._append
    interrupted = {"value": False}

    def interrupt_after_claim(*args, **kwargs):
        result = original_append(*args, **kwargs)
        if args[4] is CheckpointEvent.ROLLBACK_STARTED and not interrupted["value"]:
            interrupted["value"] = True
            raise BaseException("crash after durable rollback claim")
        return result

    monkeypatch.setattr(execution, "_append", interrupt_after_claim)
    with pytest.raises(BaseException, match="crash after durable rollback claim"):
        start_execution(store_path, plan.plan_id, RecordingAdapter(), Runner(wrong_runtime=True), now=execution_time)
    monkeypatch.setattr(execution, "_append", original_append)

    adapter = RecordingAdapter()
    expired_clock = claim_clock + timedelta(seconds=61)
    monkeypatch.setattr(execution, "_rollback_claim_clock", lambda: expired_clock.isoformat())
    view = continue_execution(
        store_path,
        execution_id_for(store_path, plan.plan_id),
        adapter,
        Runner(wrong_runtime=True),
        now=expired_clock.isoformat(),
    )
    assert view.rollback_status == "completed"
    assert [step.operation for step in adapter.calls] == [step.operation for step in plan.rollback_steps]


def test_rollback_claim_insert_requires_exact_readback(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_execution as execution

    store_path, plan, _bundle = _approved(tmp_path)
    original_load = execution._load_rollback_claim
    calls = {"value": 0}

    def tamper_readback(store, execution_id):
        calls["value"] += 1
        row = original_load(store, execution_id)
        if calls["value"] >= 2 and row is not None:
            tampered = {key: row[key] for key in row.keys()}
            tampered["owner_id"] = "rewritten-owner"
            return tampered
        return row

    monkeypatch.setattr(execution, "_load_rollback_claim", tamper_readback)
    adapter = RecordingAdapter()
    with pytest.raises(ValueError, match="insert read-back mismatch"):
        start_execution(store_path, plan.plan_id, adapter, Runner(wrong_runtime=True))
    assert not any(step.operation in {item.operation for item in plan.rollback_steps} for step in adapter.calls)
    with SQLiteStore(store_path) as store:
        execution_id = store.load_backup_execution_header_for_plan(plan.plan_id).execution_id
        checkpoints = store.load_backup_execution_checkpoints(execution_id)
        assert all(item.event is not CheckpointEvent.ROLLBACK_STARTED for item in checkpoints)
        assert store._connection.execute(
            "SELECT COUNT(*) FROM backup_provisioning_execution_rollback_claims WHERE execution_id=?",
            (execution_id,),
        ).fetchone()[0] == 0


def test_rollback_claim_takeover_requires_exact_readback(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_execution as execution

    store_path, plan, _bundle = _approved(tmp_path)
    execution_time = _execution_time_at_or_after_approval(store_path, plan.plan_id)
    claim_clock = datetime.fromisoformat(execution_time)
    monkeypatch.setattr(execution, "_rollback_claim_clock", lambda: claim_clock.isoformat())
    original_append = execution._append
    interrupted = {"value": False}

    def interrupt_after_claim(*args, **kwargs):
        result = original_append(*args, **kwargs)
        if args[4] is CheckpointEvent.ROLLBACK_STARTED and not interrupted["value"]:
            interrupted["value"] = True
            raise BaseException("seed exact claim for readback")
        return result

    monkeypatch.setattr(execution, "_append", interrupt_after_claim)
    with pytest.raises(BaseException, match="seed exact claim for readback"):
        start_execution(store_path, plan.plan_id, RecordingAdapter(), Runner(wrong_runtime=True), now=execution_time)
    monkeypatch.setattr(execution, "_append", original_append)

    expired_clock = claim_clock + timedelta(seconds=61)
    monkeypatch.setattr(execution, "_rollback_claim_clock", lambda: expired_clock.isoformat())
    original_load = execution._load_rollback_claim
    calls = {"value": 0}

    def tamper_takeover_readback(store, execution_id):
        calls["value"] += 1
        row = original_load(store, execution_id)
        if calls["value"] >= 2 and row is not None:
            tampered = {key: row[key] for key in row.keys()}
            tampered["claim_epoch"] = int(row["claim_epoch"]) + 1
            return tampered
        return row

    monkeypatch.setattr(execution, "_load_rollback_claim", tamper_takeover_readback)
    adapter = RecordingAdapter()
    with pytest.raises(ValueError, match="takeover read-back mismatch"):
        continue_execution(
            store_path,
            execution_id_for(store_path, plan.plan_id),
            adapter,
            Runner(wrong_runtime=True),
            now=expired_clock.isoformat(),
        )
    assert not any(step.operation in {item.operation for item in plan.rollback_steps} for step in adapter.calls)
    with SQLiteStore(store_path) as store:
        execution_id = execution_id_for(store_path, plan.plan_id)
        checkpoints = store.load_backup_execution_checkpoints(execution_id)
        claim = store._connection.execute(
            "SELECT claim_epoch FROM backup_provisioning_execution_rollback_claims WHERE execution_id=?",
            (execution_id,),
        ).fetchone()
        assert checkpoints[-1].event is CheckpointEvent.ROLLBACK_STARTED
        assert claim["claim_epoch"] == 1


def test_rollback_lease_clock_is_independent_of_stale_or_future_evidence_time(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_execution as execution

    store_path, plan, _bundle = _approved(tmp_path)
    execution_time = _execution_time_at_or_after_approval(store_path, plan.plan_id)
    claim_clock = datetime.fromisoformat(execution_time) + timedelta(seconds=100)
    monkeypatch.setattr(execution, "_rollback_claim_clock", lambda: claim_clock.isoformat())
    original_append = execution._append
    interrupted = {"value": False}

    def interrupt_after_claim(*args, **kwargs):
        result = original_append(*args, **kwargs)
        if args[4] is CheckpointEvent.ROLLBACK_STARTED and not interrupted["value"]:
            interrupted["value"] = True
            raise BaseException("crash after trusted rollback claim")
        return result

    monkeypatch.setattr(execution, "_append", interrupt_after_claim)
    with pytest.raises(BaseException, match="crash after trusted rollback claim"):
        start_execution(store_path, plan.plan_id, RecordingAdapter(), Runner(wrong_runtime=True), now=execution_time)
    monkeypatch.setattr(execution, "_append", original_append)

    with SQLiteStore(store_path) as store:
        claim = store._connection.execute(
            "SELECT claimed_at, lease_expires_at FROM backup_provisioning_execution_rollback_claims"
        ).fetchone()
    assert claim["claimed_at"] == claim_clock.isoformat()
    assert claim["lease_expires_at"] == (claim_clock + timedelta(seconds=30)).isoformat()

    evidence_future = claim_clock + timedelta(hours=1)
    adapter = RecordingAdapter()
    with pytest.raises(ValueError, match="EXECUTION_IN_PROGRESS"):
        continue_execution(
            store_path,
            execution_id_for(store_path, plan.plan_id),
            adapter,
            Runner(wrong_runtime=True),
            now=evidence_future.isoformat(),
        )
    assert adapter.calls == []


def test_live_rollback_claim_contends_without_duplicate_adapter_call(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_execution as execution

    store_path, plan, _bundle = _approved(tmp_path)
    execution_time = _execution_time_at_or_after_approval(store_path, plan.plan_id)
    original_append = execution._append
    interrupted = {"value": False}

    def interrupt_after_claim(*args, **kwargs):
        result = original_append(*args, **kwargs)
        if args[4] is CheckpointEvent.ROLLBACK_STARTED and not interrupted["value"]:
            interrupted["value"] = True
            raise BaseException("live owner paused after claim")
        return result

    monkeypatch.setattr(execution, "_append", interrupt_after_claim)
    with pytest.raises(BaseException, match="live owner paused after claim"):
        start_execution(store_path, plan.plan_id, RecordingAdapter(), Runner(wrong_runtime=True), now=execution_time)
    monkeypatch.setattr(execution, "_append", original_append)

    adapter = RecordingAdapter()
    with pytest.raises(ValueError, match="EXECUTION_IN_PROGRESS"):
        continue_execution(
            store_path,
            execution_id_for(store_path, plan.plan_id),
            adapter,
            Runner(wrong_runtime=True),
            now=(datetime.fromisoformat(execution_time) + timedelta(seconds=1)).isoformat(),
        )
    assert adapter.calls == []


def test_foreign_owner_socket_prebind_without_claim_is_not_contention(tmp_path: Path) -> None:
    from overseer.backup_execution import _rollback_owner_socket_addresses

    store_path, plan, _bundle = _approved(tmp_path)
    execution_id = "execution." + plan.plan_digest.removeprefix("sha256:")
    with SQLiteStore(store_path) as store:
        address = _rollback_owner_socket_addresses(store, execution_id)[0]
    prebind = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    prebind.bind(address)
    try:
        with pytest.raises(ValueError, match="without an exact active claim"):
            start_execution(store_path, plan.plan_id, RecordingAdapter(), Runner(wrong_runtime=True))
    finally:
        prebind.close()


def test_exact_active_claim_socket_collision_is_typed_contention(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_execution as execution
    from overseer.backup_execution import _rollback_owner_socket_addresses

    store_path, plan, _bundle = _approved(tmp_path)
    execution_time = _execution_time_at_or_after_approval(store_path, plan.plan_id)
    original_append = execution._append
    interrupted = {"value": False}

    def interrupt_after_claim(*args, **kwargs):
        result = original_append(*args, **kwargs)
        if args[4] is CheckpointEvent.ROLLBACK_STARTED and not interrupted["value"]:
            interrupted["value"] = True
            raise BaseException("seed exact active claim")
        return result

    monkeypatch.setattr(execution, "_append", interrupt_after_claim)
    with pytest.raises(BaseException, match="seed exact active claim"):
        start_execution(store_path, plan.plan_id, RecordingAdapter(), Runner(wrong_runtime=True), now=execution_time)
    monkeypatch.setattr(execution, "_append", original_append)
    execution_id = execution_id_for(store_path, plan.plan_id)
    with SQLiteStore(store_path) as store:
        address = _rollback_owner_socket_addresses(store, execution_id)[0]
    prebind = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    prebind.bind(address)
    try:
        with pytest.raises(ValueError, match="EXECUTION_IN_PROGRESS"):
            continue_execution(store_path, execution_id, RecordingAdapter(), Runner(wrong_runtime=True), now=execution_time)
    finally:
        prebind.close()


def test_crash_after_durable_rollback_completion_allows_immediate_resume(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_execution as execution

    store_path, plan, _bundle = _approved(tmp_path)
    rollback_operations = {step.operation for step in plan.rollback_steps}
    adapter = RecordingAdapter()
    original_append = execution._append
    interrupted = {"value": False}

    def crash_after_completion(*args, **kwargs):
        result = original_append(*args, **kwargs)
        if args[4] is CheckpointEvent.ROLLBACK_COMPLETED and not interrupted["value"]:
            interrupted["value"] = True
            raise BaseException("crash after durable rollback completion")
        return result

    monkeypatch.setattr(execution, "_append", crash_after_completion)
    with pytest.raises(BaseException, match="crash after durable rollback completion"):
        start_execution(store_path, plan.plan_id, adapter, Runner(wrong_runtime=True))
    monkeypatch.setattr(execution, "_append", original_append)
    before_resume = len(adapter.calls)
    view = continue_execution(
        store_path, execution_id_for(store_path, plan.plan_id), adapter, Runner(wrong_runtime=True)
    )
    resumed_calls = adapter.calls[before_resume:]
    assert view.rollback_status == "completed"
    assert sum(step.operation in rollback_operations for step in resumed_calls) == len(plan.rollback_steps) - 1
    assert sum(step.operation == plan.rollback_steps[0].operation for step in resumed_calls) == 0


def test_rollback_completion_rejects_takeover_at_owner_boundary(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_execution as execution

    store_path, plan, _bundle = _approved(tmp_path)
    execution_time = _execution_time_at_or_after_approval(store_path, plan.plan_id)
    claim_clock = datetime.fromisoformat(execution_time)
    monkeypatch.setattr(execution, "_rollback_claim_clock", lambda: claim_clock.isoformat())
    original_append = execution._append
    interrupted = {"value": False}

    def interrupt_after_claim(*args, **kwargs):
        result = original_append(*args, **kwargs)
        if args[4] is CheckpointEvent.ROLLBACK_STARTED and not interrupted["value"]:
            interrupted["value"] = True
            raise BaseException("crash before completion boundary")
        return result

    monkeypatch.setattr(execution, "_append", interrupt_after_claim)
    with pytest.raises(BaseException, match="crash before completion boundary"):
        start_execution(store_path, plan.plan_id, RecordingAdapter(), Runner(wrong_runtime=True), now=execution_time)
    monkeypatch.setattr(execution, "_append", original_append)
    expired_clock = claim_clock + timedelta(seconds=61)
    monkeypatch.setattr(execution, "_rollback_claim_clock", lambda: expired_clock.isoformat())

    takeover = {"value": False}

    def takeover_before_completion(store, header, ordinal, identity, event, when, **kwargs):
        if event is CheckpointEvent.ROLLBACK_COMPLETED and not takeover["value"]:
            takeover["value"] = True
            store._connection.execute(
                "UPDATE backup_provisioning_execution_rollback_claims SET owner_id=? WHERE execution_id=?",
                ("stale-takeover", header.execution_id),
            )
        return original_append(store, header, ordinal, identity, event, when, **kwargs)

    monkeypatch.setattr(execution, "_append", takeover_before_completion)
    adapter = RecordingAdapter()
    with pytest.raises(ValueError, match="owner changed"):
        continue_execution(
            store_path,
            execution_id_for(store_path, plan.plan_id),
            adapter,
            Runner(wrong_runtime=True),
            now=execution_time,
        )
    assert sum(step.operation in {item.operation for item in plan.rollback_steps} for step in adapter.calls) == 1
    with SQLiteStore(store_path) as store:
        checkpoints = store.load_backup_execution_checkpoints(execution_id_for(store_path, plan.plan_id))
        assert checkpoints[-1].event is CheckpointEvent.ROLLBACK_STARTED


def test_rollback_completion_rejects_epoch_only_tampering(tmp_path: Path) -> None:
    store_path, plan, _bundle = _approved(tmp_path)
    rollback_operations = {step.operation for step in plan.rollback_steps}
    execution_id: str | None = None

    class EpochTamperingAdapter(RecordingAdapter):
        def execute(self, step):
            if step.operation in rollback_operations:
                with sqlite3.connect(store_path, timeout=30.0) as connection:
                    connection.execute(
                        "UPDATE backup_provisioning_execution_rollback_claims SET claim_epoch=8"
                    )
                    connection.commit()
            return super().execute(step)

    adapter = EpochTamperingAdapter()
    with pytest.raises(ValueError, match="owner changed"):
        start_execution(store_path, plan.plan_id, adapter, Runner(wrong_runtime=True))
    assert sum(step.operation in rollback_operations for step in adapter.calls) == 1
    with SQLiteStore(store_path) as store:
        execution_id = store.load_backup_execution_header_for_plan(plan.plan_id).execution_id
    assert execution_id is not None
    with SQLiteStore(store_path) as store:
        checkpoints = store.load_backup_execution_checkpoints(execution_id)
        claim = store._connection.execute(
            "SELECT owner_id, claim_epoch FROM backup_provisioning_execution_rollback_claims WHERE execution_id=?",
            (execution_id,),
        ).fetchone()
    assert checkpoints[-1].event is CheckpointEvent.ROLLBACK_STARTED
    assert claim is not None and claim["claim_epoch"] == 8


def test_live_owner_lock_prevents_expired_lease_takeover_during_adapter_call(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_execution as execution

    store_path, plan, _bundle = _approved(tmp_path)
    execution_time = _execution_time_at_or_after_approval(store_path, plan.plan_id)
    claim_clock = datetime.fromisoformat(execution_time)
    current_clock = {"value": claim_clock}
    monkeypatch.setattr(execution, "_rollback_claim_clock", lambda: current_clock["value"].isoformat())
    rollback_operations = {step.operation for step in plan.rollback_steps}
    started = threading.Event()
    release = threading.Event()
    owner_adapter = RecordingAdapter()

    def owner_execute(step):
        if step.operation in rollback_operations and not started.is_set():
            started.set()
            assert release.wait(timeout=10)
        return RecordingAdapter.execute(owner_adapter, step)

    owner_adapter.execute = owner_execute
    contender_adapter = RecordingAdapter()
    results: dict[str, object] = {}

    def run_owner() -> None:
        results["owner"] = start_execution(
            store_path, plan.plan_id, owner_adapter, Runner(wrong_runtime=True), now=execution_time
        )

    def run_contender() -> None:
        try:
            results["contender"] = continue_execution(
                store_path, execution_id_for(store_path, plan.plan_id), contender_adapter,
                Runner(wrong_runtime=True), now=(claim_clock + timedelta(seconds=31)).isoformat(),
            )
        except BaseException as error:
            results["contender"] = error

    owner = threading.Thread(target=run_owner, name="live-rollback-owner")
    owner.start()
    assert started.wait(timeout=10)
    current_clock["value"] = claim_clock + timedelta(seconds=31)
    contender = threading.Thread(target=run_contender, name="expired-lease-contender")
    contender.start()
    contender.join(timeout=10)
    assert not contender.is_alive()
    assert isinstance(results["contender"], ValueError)
    assert str(results["contender"]) == "EXECUTION_IN_PROGRESS"
    assert contender_adapter.calls == []
    release.set()
    owner.join(timeout=10)
    assert not owner.is_alive()
    assert sum(step.operation in rollback_operations for step in owner_adapter.calls) == len(plan.rollback_steps)
    with SQLiteStore(store_path) as store:
        checkpoints = store.load_backup_execution_checkpoints(execution_id_for(store_path, plan.plan_id))
    assert sum(item.event in (CheckpointEvent.ROLLBACK_COMPLETED, CheckpointEvent.ROLLBACK_FAILED) for item in checkpoints) == len(plan.rollback_steps)


def test_rollback_owner_lock_is_kernel_fenced_without_replaceable_artifact(tmp_path: Path) -> None:
    from types import SimpleNamespace
    from overseer.backup_execution import _RollbackOwnerLock

    store_path = tmp_path / "state.sqlite3"
    store_path.touch()
    status = store_path.stat()
    store = SimpleNamespace(path=store_path, _database_identity=(status.st_dev, status.st_ino))
    execution_id = "execution.lock.test"
    lock_path = Path(f"{store.path}.rollback-owner-{hashlib.sha256(execution_id.encode()).hexdigest()}.lock")
    with _RollbackOwnerLock.acquire(store, execution_id):
        assert not lock_path.exists()
        with pytest.raises(OSError):
            _RollbackOwnerLock.acquire(store, execution_id)
    assert not lock_path.exists()


def test_rollback_owner_lock_scopes_same_execution_id_to_store_identity(tmp_path: Path) -> None:
    from types import SimpleNamespace
    from overseer.backup_execution import _RollbackOwnerLock

    path_a = tmp_path / "store-a.sqlite3"
    path_b = tmp_path / "store-b.sqlite3"
    path_a.touch()
    path_b.touch()
    status_a = path_a.stat()
    status_b = path_b.stat()
    store_a = SimpleNamespace(path=path_a, _database_identity=(status_a.st_dev, status_a.st_ino))
    store_b = SimpleNamespace(path=path_b, _database_identity=(status_b.st_dev, status_b.st_ino))
    execution_id = "execution.same-id"
    with _RollbackOwnerLock.acquire(store_a, execution_id):
        with _RollbackOwnerLock.acquire(store_b, execution_id):
            pass


def test_rollback_owner_lock_alias_and_replacement_cannot_bypass_scope(tmp_path: Path) -> None:
    from types import SimpleNamespace
    from overseer.backup_execution import _RollbackOwnerLock

    original = tmp_path / "store.sqlite3"
    original.touch()
    alias = tmp_path / "store-hardlink.sqlite3"
    alias.hardlink_to(original)
    status = original.stat()
    store = SimpleNamespace(path=original, _database_identity=(status.st_dev, status.st_ino))
    hardlink_store = SimpleNamespace(path=alias, _database_identity=(status.st_dev, status.st_ino))
    execution_id = "execution.alias"
    with _RollbackOwnerLock.acquire(store, execution_id):
        with pytest.raises(OSError):
            _RollbackOwnerLock.acquire(hardlink_store, execution_id)

    replacement_store = SimpleNamespace(path=original, _database_identity=(status.st_dev, status.st_ino + 1))
    with _RollbackOwnerLock.acquire(store, execution_id):
        with pytest.raises(OSError):
            _RollbackOwnerLock.acquire(replacement_store, execution_id)


def test_rollback_owner_lock_survives_separate_process_and_releases_on_exit(tmp_path: Path) -> None:
    from types import SimpleNamespace
    from overseer.backup_execution import _RollbackOwnerLock

    store_path = tmp_path / "state.sqlite3"
    store_path.touch()
    status = store_path.stat()
    store = SimpleNamespace(path=store_path, _database_identity=(status.st_dev, status.st_ino))
    execution_id = "execution.process.lock"
    context = multiprocessing.get_context("fork")
    ready = context.Event()
    release = context.Event()
    worker = context.Process(target=_owner_lock_process, args=(str(store.path), execution_id, ready, release, False))
    worker.start()
    assert ready.wait(timeout=10)
    with pytest.raises(OSError):
        _RollbackOwnerLock.acquire(store, execution_id)
    release.set()
    worker.join(timeout=10)
    assert worker.exitcode == 0
    with _RollbackOwnerLock.acquire(store, execution_id):
        pass

    crashed_ready = context.Event()
    crashed = context.Process(target=_owner_lock_process, args=(str(store.path), execution_id, crashed_ready, release, True))
    crashed.start()
    assert crashed_ready.wait(timeout=10)
    with pytest.raises(OSError):
        _RollbackOwnerLock.acquire(store, execution_id)
    crashed.join(timeout=10)
    assert crashed.exitcode == 0
    with _RollbackOwnerLock.acquire(store, execution_id):
        pass


def test_rollback_claim_releases_owner_lock_when_commit_exit_raises(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_execution as execution

    store_path, plan, _bundle = _approved(tmp_path)
    original_rollback = execution._rollback

    def seed_interrupted(*args, **kwargs):
        raise BaseException("seed exact failed tail")

    monkeypatch.setattr(execution, "_rollback", seed_interrupted)
    with pytest.raises(BaseException, match="seed exact failed tail"):
        start_execution(store_path, plan.plan_id, RecordingAdapter(), Runner(wrong_runtime=True))
    monkeypatch.setattr(execution, "_rollback", original_rollback)

    from overseer.store import SQLiteStore
    original_commit = SQLiteStore._commit

    def commit_then_raise(store):
        original_commit(store)
        if store._connection.execute(
            "SELECT COUNT(*) FROM backup_provisioning_execution_rollback_claims"
        ).fetchone()[0]:
            raise RuntimeError("commit exit failure")

    monkeypatch.setattr(SQLiteStore, "_commit", commit_then_raise)
    with pytest.raises(RuntimeError, match="commit exit failure"):
        continue_execution(
            store_path, execution_id_for(store_path, plan.plan_id), RecordingAdapter(), Runner(wrong_runtime=True)
        )
    monkeypatch.setattr(SQLiteStore, "_commit", original_commit)
    with SQLiteStore(store_path) as store:
        claim = store._connection.execute(
            "SELECT owner_id, claim_epoch FROM backup_provisioning_execution_rollback_claims"
        ).fetchone()
        from overseer.backup_execution import _RollbackOwnerLock
        with _RollbackOwnerLock.acquire(store, execution_id_for(store_path, plan.plan_id)):
            pass
    assert claim["claim_epoch"] == 1


def test_typed_execute_plan_delegates_to_runner_coordinator(tmp_path: Path) -> None:
    from overseer.backup_provisioning import execute_plan

    store_path, plan, _bundle = _approved(tmp_path)
    result = execute_plan(store_path, plan.plan_id, RecordingAdapter(), acceptance_runner=Runner())
    assert result["status"] == "executed"
    assert result["host_mutation_performed"] is True
    assert result["execution_status"] == "succeeded"
    assert result["execution_id"].startswith("execution.")
    assert result["rollback_status"] == "not_started"
    assert result["failure_code"] is None


def test_typed_result_is_truthful_for_pause_failure_and_legacy(tmp_path: Path) -> None:
    from overseer.backup_provisioning import execute_plan

    store_path, plan, _bundle = _approved(tmp_path)
    adapter = RecordingAdapter()
    paused = execute_plan(store_path, plan.plan_id, adapter, acceptance_runner=None)
    assert paused["status"] == "in_progress"
    assert paused["execution_status"] == "in_progress"
    assert paused["host_mutation_performed"] is True

    store_path, plan, _bundle = _approved(tmp_path / "wrong-runtime")
    failed = execute_plan(store_path, plan.plan_id, RecordingAdapter(), acceptance_runner=Runner(wrong_runtime=True))
    assert failed["status"] == "rolled_back"
    assert failed["status"] != "approved"
    assert failed["failure_code"] == "OPERATION_FAILED"
    assert failed["host_mutation_performed"] is True

    store_path, plan, _bundle = _approved(tmp_path / "bad-acceptance")
    failed = execute_plan(store_path, plan.plan_id, RecordingAdapter(), acceptance_runner=Runner(passed=False))
    assert failed["status"] == "rolled_back"
    assert failed["failure_code"] == "ACCEPTANCE_FAILED"
    assert failed["host_mutation_performed"] is True


def test_authority_is_rechecked_before_each_forward_claim(tmp_path: Path) -> None:
    store_path, plan, _bundle = _approved(tmp_path)

    class RevokingAdapter(RecordingAdapter):
        def execute(self, step):
            result = super().execute(step)
            if len(self.calls) == 1:
                result["disposition"] = "verified_noop"
                result["safe_code"] = "STEP_VERIFIED_NOOP"
            if len(self.calls) == 2:
                with SQLiteStore(store_path) as store:
                    item = store.load_crew_message(plan.evidence_ids["kira"])
                    store.save_crew_message(replace(item, review_status=CrewReviewStatus.CORRECTION_REQUESTED))
            return result

    adapter = RevokingAdapter()
    view = start_execution(store_path, plan.plan_id, adapter, Runner())
    assert view.failure_code == "FORWARD_AUTHORITY_LOST"
    assert view.rollback_status == "completed"
    assert [step.operation for step in adapter.calls] == [
        "verify_published_adapter_source", "install_runtime", "remove_runtime_if_unreferenced",
    ]
    with SQLiteStore(store_path) as store:
        checkpoints = store.load_backup_execution_checkpoints(view.execution_id)
    assert checkpoints[-1].event is CheckpointEvent.ROLLBACK_COMPLETED
    assert any(item.event is CheckpointEvent.EXECUTION_ABORTED for item in checkpoints)
    assert sum(step.operation == "remove_runtime_if_unreferenced" for step in adapter.calls) == 1


def test_uninterrupted_execute_plan_fails_closed_when_exact_source_executes_after_install_runtime(tmp_path: Path) -> None:
    from overseer.backup_provisioning import execute_plan

    store_path, plan, _bundle = _approved(tmp_path)

    class ExecutingSourceAdapter(RecordingAdapter):
        def execute(self, step):
            result = super().execute(step)
            if step.operation == "install_runtime":
                with SQLiteStore(store_path) as store:
                    source = _stored(store, plan.plan_id)
                    executed = replace(
                        source,
                        status=ProvisioningStatus.EXECUTED,
                        executed_at="2026-08-05T12:00:00+00:00",
                        evidence_digest="sha256:" + "e" * 64,
                    )
                    store._connection.execute(
                        "UPDATE backup_provisioning_plans SET payload=? WHERE id=?",
                        (_dump(executed), plan.plan_id),
                    )
                    store._connection.commit()
            return result

    adapter = ExecutingSourceAdapter()
    with pytest.raises(ValueError, match="terminal execution"):
        execute_plan(store_path, plan.plan_id, adapter, acceptance_runner=Runner())
    assert [step.operation for step in adapter.calls] == [
        "verify_published_adapter_source", "install_runtime",
    ]
    with SQLiteStore(store_path) as store:
        checkpoints = store.load_backup_execution_checkpoints(
            store.load_backup_execution_header_for_plan(plan.plan_id).execution_id,
        )
    assert all(item.event is not CheckpointEvent.EXECUTION_ABORTED for item in checkpoints)
    assert all(item.event not in (
        CheckpointEvent.ROLLBACK_STARTED,
        CheckpointEvent.ROLLBACK_COMPLETED,
        CheckpointEvent.ROLLBACK_FAILED,
    ) for item in checkpoints)


def test_verified_noop_is_not_rolled_back_after_later_failure(tmp_path: Path) -> None:
    store_path, plan, _bundle = _approved(tmp_path)
    adapter = NoopAdapter()
    view = start_execution(store_path, plan.plan_id, adapter, Runner(wrong_runtime=True))
    assert view.failure_code == "OPERATION_FAILED"
    assert "remove_runtime_if_unreferenced" not in [step.operation for step in adapter.calls]


def test_interrupted_rollback_resumes_without_renewed_forward_authority(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_execution as execution

    store_path, plan, _bundle = _approved(tmp_path)
    adapter = RecordingAdapter(fail_operation="install_systemd_unit")
    original_append = execution._append
    interrupted = {"value": False}

    def interrupt_after_one_rollback(*args, **kwargs):
        result = original_append(*args, **kwargs)
        if args[4] is CheckpointEvent.ROLLBACK_COMPLETED and not interrupted["value"]:
            interrupted["value"] = True
            raise BaseException("crash after one rollback")
        return result

    monkeypatch.setattr(execution, "_append", interrupt_after_one_rollback)
    with pytest.raises(BaseException):
        start_execution(store_path, plan.plan_id, adapter, Runner())
    monkeypatch.setattr(execution, "_append", original_append)
    with SQLiteStore(store_path) as store:
        message = store.load_crew_message(plan.evidence_ids["kira"])
        store.save_crew_message(replace(message, review_status=CrewReviewStatus.CORRECTION_REQUESTED))
    before = len(adapter.calls)
    view = continue_execution(store_path, execution_id_for(store_path, plan.plan_id), adapter, Runner())
    assert view.rollback_status == "completed"
    assert [step.operation for step in adapter.calls[before:]] == [
        "remove_private_config",
        "remove_read_only_acl", "remove_cursor_key_if_unreferenced", "remove_overseer_api_token",
        "remove_secret_file_if_no_backups", "remove_directory_if_empty", "remove_directory_if_empty",
        "remove_directory_if_empty", "remove_directory_if_empty", "remove_system_user_if_unused",
        "remove_runtime_if_unreferenced",
    ]


def test_typed_execute_plan_reports_only_current_invocation_mutation(tmp_path: Path) -> None:
    from overseer.backup_provisioning import execute_plan

    store_path, plan, _bundle = _approved(tmp_path)
    first = execute_plan(store_path, plan.plan_id, RecordingAdapter(), acceptance_runner=Runner())
    assert first["mutation_performed"] is True and first["host_mutation_performed"] is True
    replay_adapter = RecordingAdapter()
    replay = execute_plan(store_path, plan.plan_id, replay_adapter, acceptance_runner=Runner())
    assert replay["mutation_performed"] is False
    assert replay["host_mutation_performed"] is False
    assert replay["host_mutation_uncertain"] is False
    assert replay_adapter.calls == []


def test_deleted_typed_bundle_fails_closed_before_execution(tmp_path: Path) -> None:
    store_path, plan, _bundle = _approved(tmp_path)
    adapter = RecordingAdapter()
    with sqlite3.connect(store_path) as connection:
        connection.execute("DELETE FROM provisioning_bundles WHERE plan_id=?", (plan.plan_id,))
        connection.commit()
    with SQLiteStore(store_path) as store:
        before = _stored(store, plan.plan_id)
    with pytest.raises(ValueError, match="SUCCESSOR_REQUIRED"):
        execute_plan(store_path, plan.plan_id, adapter, acceptance_runner=Runner())
    assert adapter.calls == []
    with SQLiteStore(store_path) as store:
        assert _stored(store, plan.plan_id) == before
        assert store._connection.execute(
            "SELECT COUNT(*) FROM backup_provisioning_execution_headers WHERE plan_id=?",
            (plan.plan_id,),
        ).fetchone()[0] == 0


def test_all_typed_execution_artifacts_deleted_stays_typed_and_fails_before_adapter(tmp_path: Path) -> None:
    store_path, plan, _bundle = _approved(tmp_path)
    adapter = RecordingAdapter()
    with sqlite3.connect(store_path) as connection:
        for table in ("provisioning_bundles", "provisioning_preflight_reports", "provisioning_review_outbox"):
            connection.execute(f"DELETE FROM {table} WHERE plan_id=?", (plan.plan_id,))
        connection.execute("DELETE FROM roadex_approval_bindings WHERE approval_ref=?", (f"approval.donuthole.{plan.plan_id}",))
        connection.commit()
    with pytest.raises(ValueError, match="SUCCESSOR_REQUIRED"):
        execute_plan(store_path, plan.plan_id, adapter, acceptance_runner=Runner())
    assert adapter.calls == []
    with SQLiteStore(store_path) as store:
        assert store.load_backup_provisioning_plan_execution_mode(plan.plan_id) == "typed"
        assert store._connection.execute("SELECT COUNT(*) FROM backup_provisioning_execution_headers WHERE plan_id=?", (plan.plan_id,)).fetchone()[0] == 0


def test_typed_execution_marker_rejects_downgrade(tmp_path: Path) -> None:
    store_path, plan, _bundle = _approved(tmp_path)
    with SQLiteStore(store_path) as store:
        assert store.load_backup_provisioning_plan_execution_mode(plan.plan_id) == "typed"
        with pytest.raises(sqlite3.IntegrityError):
            store._connection.execute(
                "UPDATE backup_provisioning_plan_execution_modes SET execution_mode='legacy' WHERE plan_id=?",
                (plan.plan_id,),
            )
        with pytest.raises(sqlite3.IntegrityError):
            store._connection.execute(
                "UPDATE backup_provisioning_plan_execution_modes SET execution_mode='typed' WHERE plan_id=?",
                (plan.plan_id,),
            )


def test_typed_execution_marker_rejects_delete(tmp_path: Path) -> None:
    store_path, plan, _bundle = _approved(tmp_path)
    with SQLiteStore(store_path) as store:
        with pytest.raises(sqlite3.IntegrityError):
            store._connection.execute(
                "DELETE FROM backup_provisioning_plan_execution_modes WHERE plan_id=?",
                (plan.plan_id,),
            )


def test_valid_source_rewrite_cannot_downgrade_typed_execution(tmp_path: Path) -> None:
    store_path, plan, _bundle = _approved(tmp_path)
    with SQLiteStore(store_path) as store:
        rewritten = replace(plan, decision_reason="rewritten legacy source")
        store._connection.execute(
            "UPDATE backup_provisioning_plans SET payload=? WHERE id=?",
            (_dump(rewritten), plan.plan_id),
        )
        store._connection.commit()
        assert store.load_backup_provisioning_plan_execution_mode(plan.plan_id) == "typed"
        assert _typed_execution_enabled_for_plan_locked(store, plan.plan_id) is True


@pytest.mark.parametrize(
    ("source_kind", "source_id", "approval_ref", "expected"),
    (
        ("admin-plan", "backup-provision.donuthole", "approval.donuthole.backup-provision.donuthole", False),
        ("roadex-human-decision", "other-plan", "approval.donuthole.backup-provision.donuthole", False),
        ("roadex-human-decision", "backup-provision.donuthole", "approval.donuthole.other-plan", False),
        ("roadex-human-decision", "backup-provision.donuthole", "approval.donuthole.backup-provision.donuthole", True),
    ),
)
def test_typed_fallback_and_v5_backfill_require_exact_roadex_binding(
    tmp_path: Path, source_kind: str, source_id: str, approval_ref: str, expected: bool,
) -> None:
    store_path, plan, _bundle = _approved(tmp_path)
    source_id = plan.plan_id if source_id == "backup-provision.donuthole" else source_id
    approval_ref = approval_ref.replace("backup-provision.donuthole", plan.plan_id)
    with sqlite3.connect(store_path) as connection:
        for table in ("provisioning_bundles", "provisioning_preflight_reports", "provisioning_review_outbox"):
            connection.execute(f"DELETE FROM {table} WHERE plan_id=?", (plan.plan_id,))
        connection.execute("DELETE FROM roadex_approval_bindings")
        connection.execute("DROP TRIGGER backup_provisioning_plan_execution_modes_no_delete")
        connection.execute("DELETE FROM backup_provisioning_plan_execution_modes")
        connection.execute("DELETE FROM schema_migrations WHERE version=5")
        connection.execute(
            "INSERT INTO roadex_approval_bindings "
            "(approval_ref, source_kind, source_id, payload) VALUES (?, ?, ?, '{}')",
            (approval_ref, source_kind, source_id),
        )
        connection.commit()

    with SQLiteStore(store_path) as store:
        assert store.load_backup_provisioning_plan_execution_mode(plan.plan_id) == ("typed" if expected else "legacy")
        assert _typed_execution_enabled_for_plan_locked(store, plan.plan_id) is expected
        assert store._connection.execute(
            "SELECT COUNT(*) FROM backup_provisioning_plan_execution_modes WHERE plan_id=?",
            (plan.plan_id,),
        ).fetchone()[0] == (1 if expected else 0)


def test_pre_upgrade_plan_shape_loads_and_scoped_artifacts_select_mode(tmp_path: Path) -> None:
    store_path, typed_plan, _bundle = _approved(tmp_path)
    with SQLiteStore(store_path) as store:
        store._connection.execute(
            "DROP TRIGGER backup_provisioning_plan_execution_modes_no_delete"
        )
        store._connection.execute(
            "DELETE FROM backup_provisioning_plan_execution_modes WHERE plan_id=?",
            (typed_plan.plan_id,),
        )
        store._connection.commit()
        loaded = _stored(store, typed_plan.plan_id)
        assert loaded.plan_digest == typed_plan.plan_digest
        assert _typed_execution_enabled_for_plan_locked(store, typed_plan.plan_id) is True

        legacy_plan = build_plan(
            "legacy-backup-plan",
            typed_plan.gpg_sha256,
            typed_plan.adapter_commit,
            typed_plan.runtime_digest,
            typed_plan.capability_digest,
            typed_plan.root_authorization_refs,
            typed_plan.root_registrations,
            typed_plan.overseer_token_source_file,
            typed_plan.overseer_token_file,
            typed_plan.cursor_key_file,
            {role: f"historical-missing-{role}" for role in typed_plan.evidence_ids},
        )
        stage_plan(store_path, legacy_plan)
        assert _typed_execution_enabled_for_plan_locked(store, legacy_plan.plan_id) is False


def test_v4_typed_artifact_reopen_backfills_marker_and_stays_fail_closed_after_cleanup(tmp_path: Path) -> None:
    store_path, plan, _bundle = _approved(tmp_path)
    with SQLiteStore(store_path) as store:
        store._connection.execute(
            "DROP TRIGGER backup_provisioning_plan_execution_modes_no_update"
        )
        store._connection.execute(
            "DROP TRIGGER backup_provisioning_plan_execution_modes_no_delete"
        )
        store._connection.execute(
            "CREATE TRIGGER backup_provisioning_plan_execution_modes_no_downgrade "
            "BEFORE UPDATE OF execution_mode ON backup_provisioning_plan_execution_modes "
            "WHEN OLD.execution_mode='typed' AND NEW.execution_mode<>'typed' "
            "BEGIN SELECT RAISE(ABORT, 'typed execution mode cannot be downgraded'); END"
        )
        store._connection.execute(
            "DELETE FROM backup_provisioning_plan_execution_modes WHERE plan_id=?",
            (plan.plan_id,),
        )
        store._connection.execute(
            "DELETE FROM schema_migrations WHERE version=5"
        )
        store._connection.commit()

    with SQLiteStore(store_path) as store:
        assert store.load_backup_provisioning_plan_execution_mode(plan.plan_id) == "typed"
        assert store._connection.execute(
            "SELECT COUNT(*) FROM backup_provisioning_plan_execution_modes WHERE plan_id=?",
            (plan.plan_id,),
        ).fetchone()[0] == 1
        for table in (
            "provisioning_bundles",
            "provisioning_preflight_reports",
            "provisioning_review_outbox",
        ):
            store._connection.execute(f"DELETE FROM {table} WHERE plan_id=?", (plan.plan_id,))
        store._connection.execute(
            "DELETE FROM roadex_approval_bindings WHERE approval_ref=?",
            (f"approval.donuthole.{plan.plan_id}",),
        )
        store._connection.commit()

    adapter = RecordingAdapter()
    with pytest.raises(ValueError, match="SUCCESSOR_REQUIRED"):
        execute_plan(store_path, plan.plan_id, adapter, acceptance_runner=Runner())
    assert adapter.calls == []


@pytest.mark.parametrize("artifact", ["binding", "preflight", "outbox"])
@pytest.mark.parametrize("entrypoint", ["start", "continue"])
def test_missing_authority_record_aborts_changed_prefix_and_rolls_back(
    tmp_path: Path, artifact: str, entrypoint: str,
) -> None:
    store_path, plan, bundle = _approved(tmp_path)
    adapter = RecordingAdapter()
    paused = start_execution(store_path, plan.plan_id, adapter, None)
    before = len(adapter.calls)
    with sqlite3.connect(store_path) as connection:
        if artifact == "binding":
            connection.execute("DELETE FROM roadex_approval_bindings WHERE approval_ref=?", (f"approval.donuthole.{plan.plan_id}",))
        elif artifact == "preflight":
            connection.execute("DELETE FROM provisioning_preflight_reports WHERE id=?", (bundle.preflight.report_id,))
        else:
            connection.execute("DELETE FROM provisioning_review_outbox WHERE plan_id=?", (plan.plan_id,))
        connection.commit()
    view = start_execution(store_path, plan.plan_id, adapter, Runner()) if entrypoint == "start" else continue_execution(store_path, paused.execution_id, adapter, Runner())
    assert view.failure_code == "FORWARD_AUTHORITY_LOST"
    assert view.rollback_status == "completed"
    assert len(adapter.calls) == before + 14
    with SQLiteStore(store_path) as store:
        checkpoints = store.load_backup_execution_checkpoints(paused.execution_id)
    assert any(item.event is CheckpointEvent.EXECUTION_ABORTED for item in checkpoints)
    assert checkpoints[-1].event is CheckpointEvent.ROLLBACK_COMPLETED


@pytest.mark.parametrize("source_state", ["missing", "malformed"])
@pytest.mark.parametrize("entrypoint", ["start", "continue"])
def test_missing_or_malformed_exact_source_fails_closed_after_changed_prefix(
    tmp_path: Path, source_state: str, entrypoint: str,
) -> None:
    store_path, plan, _bundle = _approved(tmp_path)
    adapter = RecordingAdapter()
    paused = start_execution(store_path, plan.plan_id, adapter, None)
    before_calls = list(adapter.calls)
    with sqlite3.connect(store_path) as connection:
        if source_state == "missing":
            connection.execute("DELETE FROM backup_provisioning_plans WHERE id=?", (plan.plan_id,))
        else:
            connection.execute("UPDATE backup_provisioning_plans SET payload='{}' WHERE id=?", (plan.plan_id,))
        connection.commit()
    before_checkpoints = _checkpoints(store_path, paused.execution_id)
    with pytest.raises(ValueError):
        if entrypoint == "start":
            start_execution(store_path, plan.plan_id, adapter, Runner())
        else:
            continue_execution(store_path, paused.execution_id, adapter, Runner())
    assert adapter.calls == before_calls
    assert _checkpoints(store_path, paused.execution_id) == before_checkpoints


def _checkpoints(store_path: str, execution_id: str):
    with SQLiteStore(store_path) as store:
        return store.load_backup_execution_checkpoints(execution_id)


def test_synchronized_execute_plan_loser_reports_no_mutation(tmp_path: Path) -> None:
    store_path, plan, _bundle = _approved(tmp_path)
    started = threading.Event()
    release = threading.Event()
    winner_adapter = BlockingAdapter(started, release)
    loser_adapter = RecordingAdapter()
    results: dict[str, object] = {}

    def run_winner() -> None:
        results["winner"] = execute_plan(store_path, plan.plan_id, winner_adapter, acceptance_runner=Runner())

    def run_loser() -> None:
        results["loser"] = execute_plan(store_path, plan.plan_id, loser_adapter, acceptance_runner=Runner())

    winner = threading.Thread(target=run_winner)
    winner.start()
    assert started.wait(timeout=10)
    loser = threading.Thread(target=run_loser)
    loser.start()
    loser.join(timeout=10)
    assert not loser.is_alive()
    release.set()
    winner.join(timeout=10)
    assert not winner.is_alive()
    assert not results.get("loser", {}).get("host_mutation_uncertain", True)
    winner_result = results["winner"]
    loser_result = results["loser"]
    assert len(winner_adapter.calls) == 21
    assert winner_result["host_mutation_performed"] is True
    assert loser_adapter.calls == []
    assert loser_result["mutation_performed"] is False
    assert loser_result["host_mutation_performed"] is False
    assert loser_result["host_mutation_uncertain"] is False


def test_typed_failed_terminal_replay_preserves_failed_operation_without_calls(tmp_path: Path) -> None:
    from overseer.backup_provisioning import execute_plan

    store_path, plan, _bundle = _approved(tmp_path)
    first = execute_plan(store_path, plan.plan_id, RecordingAdapter(fail_operation="install_runtime"), acceptance_runner=Runner())
    assert first["failed_operation"] == "install_runtime"
    replay_adapter = RecordingAdapter()
    replay = execute_plan(store_path, plan.plan_id, replay_adapter, acceptance_runner=Runner())
    assert replay["failed_operation"] == "install_runtime"
    assert replay["mutation_performed"] is False
    assert replay["host_mutation_performed"] is False
    assert replay["host_mutation_uncertain"] is False
    assert replay_adapter.calls == []


def test_typed_rollback_failed_response_and_replay_use_rollback_operation(tmp_path: Path) -> None:
    from overseer.backup_provisioning import execute_plan

    store_path, plan, _bundle = _approved(tmp_path)

    class FailForwardAndRollback(RecordingAdapter):
        def __init__(self):
            super().__init__(fail_operation="install_systemd_unit")
            self.failed_rollback = False

        def execute(self, step):
            if step.operation == "remove_private_config" and not self.failed_rollback:
                self.failed_rollback = True
                self.calls.append(step)
                return {"ok": False, "operation": step.operation, "disposition": "changed", "safe_code": "ROLLBACK_FAILED", "evidence": {}, "redactions_applied": True}
            return super().execute(step)

    first_adapter = FailForwardAndRollback()
    first = execute_plan(store_path, plan.plan_id, first_adapter, acceptance_runner=Runner())
    assert first["failed_operation"] == "remove_private_config"

    replay_adapter = RecordingAdapter()
    replay = execute_plan(store_path, plan.plan_id, replay_adapter, acceptance_runner=Runner())
    assert replay["failed_operation"] == "remove_private_config"
    assert replay["mutation_performed"] is False
    assert replay["host_mutation_performed"] is False
    assert replay["host_mutation_uncertain"] is False
    assert replay_adapter.calls == []


def test_typed_execution_abort_response_attributes_exact_next_forward_operation(tmp_path: Path) -> None:
    from overseer.backup_provisioning import execute_plan

    store_path, plan, _bundle = _approved(tmp_path)

    class RevokingAdapter(RecordingAdapter):
        def execute(self, step):
            result = super().execute(step)
            if len(self.calls) == 2:
                with SQLiteStore(store_path) as store:
                    item = store.load_crew_message(plan.evidence_ids["kira"])
                    store.save_crew_message(replace(item, review_status=CrewReviewStatus.CORRECTION_REQUESTED))
            return result

    result = execute_plan(store_path, plan.plan_id, RevokingAdapter(), acceptance_runner=Runner())
    assert result["failure_code"] == "FORWARD_AUTHORITY_LOST"
    assert result["failed_operation"] == "verify_endpoint_migration_ready"


def test_normalizes_coordinator_codes_and_discards_adapter_secrets(tmp_path: Path) -> None:
    store_path, plan, _bundle = _approved(tmp_path)

    class SecretAdapter(RecordingAdapter):
        def execute(self, step):
            self.calls.append(step)
            if step.operation == "install_runtime":
                return {"ok": True, "operation": step.operation, "disposition": "changed", "safe_code": "SUPERSECRET123", "evidence": {"secret": "SUPERSECRET123"}, "redactions_applied": True}
            return {"ok": True, "operation": step.operation, "disposition": "verified_noop", "safe_code": "SUPERSECRET123", "evidence": {}, "redactions_applied": True}

    view = start_execution(store_path, plan.plan_id, SecretAdapter(), Runner())
    assert view.terminal_success is True
    with SQLiteStore(store_path) as store:
        payload = " ".join(str(row[0]) for row in store._connection.execute("SELECT payload FROM backup_provisioning_execution_checkpoints"))
    assert "SUPERSECRET123" not in payload
    assert "STEP_COMPLETED" in payload and "STEP_VERIFIED_NOOP" in payload

    store_path, plan, _bundle = _approved(tmp_path / "dto-failure")

    class FailedDtoAdapter(RecordingAdapter):
        def execute(self, step):
            self.calls.append(step)
            return {"ok": False, "operation": step.operation, "disposition": "changed", "safe_code": "SUPERSECRET123", "evidence": {}, "redactions_applied": True}

    view = start_execution(store_path, plan.plan_id, FailedDtoAdapter(), Runner())
    assert view.failure_code == "OPERATION_REPORTED_FAILURE"

    store_path, plan, _bundle = _approved(tmp_path / "exception")

    class SecretError(RuntimeError):
        code = "SUPERSECRET123"

    class ExceptionAdapter(RecordingAdapter):
        def execute(self, step):
            self.calls.append(step)
            raise SecretError("do not persist")

    view = start_execution(store_path, plan.plan_id, ExceptionAdapter(), Runner())
    assert view.failure_code == "OPERATION_FAILED"

    store_path, plan, _bundle = _approved(tmp_path / "acceptance-secret")

    class UnsafeAcceptanceRunner(Runner):
        def accept(self, header, attestation):
            return BehaviorAcceptance(header.acceptance_contract_version, header.acceptance_contract_digest, False, "SUPERSECRET123", "sha256:" + "a" * 64)

    view = start_execution(store_path, plan.plan_id, RecordingAdapter(), UnsafeAcceptanceRunner())
    assert view.failure_code == "ACCEPTANCE_FAILED"
    with SQLiteStore(store_path) as store:
        payload = " ".join(str(row[0]) for row in store._connection.execute("SELECT payload FROM backup_provisioning_execution_checkpoints"))
    assert "SUPERSECRET123" not in payload and "SUPERSECRET123" not in repr(view)

    store_path, plan, _bundle = _approved(tmp_path / "acceptance-success-secret")

    class UnsafeSuccessfulAcceptanceRunner(Runner):
        def accept(self, header, attestation):
            return {
                "contract_version": header.acceptance_contract_version,
                "acceptance_contract_digest": header.acceptance_contract_digest,
                "passed": True,
                "safe_code": "SUPERSECRET123",
                "results_digest": "sha256:" + "a" * 64,
            }

    view = start_execution(store_path, plan.plan_id, RecordingAdapter(), UnsafeSuccessfulAcceptanceRunner())
    assert view.terminal_success is True
    assert view.behavior_acceptance is not None
    assert view.behavior_acceptance.safe_code == "ACCEPTANCE_PASSED"
    with SQLiteStore(store_path) as store:
        payload = " ".join(str(row[0]) for row in store._connection.execute("SELECT payload FROM backup_provisioning_execution_checkpoints"))
    assert "SUPERSECRET123" not in payload and "SUPERSECRET123" not in repr(view)


def test_genesis_header_and_claim_roll_back_together(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_execution as execution

    store_path, plan, _bundle = _approved(tmp_path)
    original = SQLiteStore.save_backup_execution

    def fail_after_save(self, header, checkpoint):
        original(self, header, checkpoint)
        raise RuntimeError("injected genesis failure")

    monkeypatch.setattr(SQLiteStore, "save_backup_execution", fail_after_save)
    with pytest.raises(RuntimeError, match="injected genesis failure"):
        execution.start_execution(store_path, plan.plan_id, RecordingAdapter(), Runner())
    with SQLiteStore(store_path) as store:
        with pytest.raises(KeyError):
            store.load_backup_execution_header_for_plan(plan.plan_id)


def test_reconcile_uses_terminal_checkpoint_observed_at(tmp_path: Path) -> None:
    from overseer.backup_provisioning import _stored

    store_path, plan, _bundle = _approved(tmp_path)
    view = start_execution(store_path, plan.plan_id, RecordingAdapter(), Runner(), now=_execution_time_at_or_after_approval(store_path, plan.plan_id))
    with SQLiteStore(store_path) as store:
        terminal = store.load_backup_execution_checkpoints(view.execution_id)[-1]
        assert _stored(store, plan.plan_id).executed_at == terminal.observed_at


def test_reconcile_reads_authoritative_chain_inside_transaction(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_provisioning as provisioning
    from overseer.backup_provisioning import ProvisioningStatus, _stored

    store_path, plan, _bundle = _approved(tmp_path)
    view = start_execution(store_path, plan.plan_id, RecordingAdapter(), Runner(), now=_execution_time_at_or_after_approval(store_path, plan.plan_id))
    with SQLiteStore(store_path) as store:
        terminal = SQLiteStore.load_backup_execution_checkpoints(store, view.execution_id)[-1]
        current = _stored(store, plan.plan_id)
    monkeypatch.setattr(
        provisioning,
        "_stored",
        lambda store, plan_id: replace(current, status=ProvisioningStatus.APPROVED, executed_at=None, evidence_digest=None),
    )
    depths: list[int] = []
    original_load = SQLiteStore.load_backup_execution_checkpoints

    def observe_transaction(self, execution_id):
        if self._agent_transaction_depth == 0:
            raise AssertionError("checkpoint chain was read before reconciliation transaction")
        depths.append(self._agent_transaction_depth)
        return original_load(self, execution_id)

    monkeypatch.setattr(SQLiteStore, "load_backup_execution_checkpoints", observe_transaction)
    with SQLiteStore(store_path) as store:
        header = store.load_backup_execution_header(view.execution_id)
        _reconcile_executed(store, header)
        assert store._agent_transaction_depth == 0
        assert store._connection.execute("SELECT payload FROM backup_provisioning_plans WHERE id=?", (plan.plan_id,)).fetchone()
    assert depths and all(depth > 0 for depth in depths)
    with SQLiteStore(store_path) as store:
        monkeypatch.setattr(provisioning, "_stored", _stored)
        assert _stored(store, plan.plan_id).executed_at == terminal.observed_at


def test_reconcile_repairs_only_terminal_timestamp_pair_and_rejects_digest_mismatch(tmp_path: Path) -> None:
    from overseer.backup_provisioning import _dump, _stored

    store_path, plan, _bundle = _approved(tmp_path)
    view = start_execution(store_path, plan.plan_id, RecordingAdapter(), Runner(), now=_execution_time_at_or_after_approval(store_path, plan.plan_id))
    with SQLiteStore(store_path) as store:
        header = store.load_backup_execution_header(view.execution_id)
        terminal = store.load_backup_execution_checkpoints(view.execution_id)[-1]
        current = _stored(store, plan.plan_id)
        store._connection.execute("UPDATE backup_provisioning_plans SET payload=? WHERE id=?", (_dump(replace(current, executed_at="2026-08-05T12:00:01+00:00")), plan.plan_id))
        store._connection.commit()
        _reconcile_executed(store, header)
        repaired = _stored(store, plan.plan_id)
        assert repaired.executed_at == terminal.observed_at
        assert repaired.evidence_digest == current.evidence_digest
        assert repaired.plan_digest == current.plan_digest
        _reconcile_executed(store, header)
        assert _stored(store, plan.plan_id) == repaired
        store._connection.execute("UPDATE backup_provisioning_plans SET payload=? WHERE id=?", (_dump(replace(repaired, evidence_digest="sha256:" + "f" * 64)), plan.plan_id))
        store._connection.commit()
        with pytest.raises(ValueError, match="evidence"):
            _reconcile_executed(store, header)


def test_typed_success_with_only_verified_noop_steps_reports_no_host_mutation(tmp_path: Path) -> None:
    from overseer.backup_provisioning import execute_plan

    class NoopAdapter(RecordingAdapter):
        def execute(self, step):
            self.calls.append(step)
            return {
                "ok": True,
                "operation": step.operation,
                "disposition": "verified_noop",
                "safe_code": "SUPERSECRET123",
                "evidence": {},
                "redactions_applied": True,
            }

    store_path, plan, _bundle = _approved(tmp_path)
    result = execute_plan(store_path, plan.plan_id, NoopAdapter(), acceptance_runner=Runner())
    assert result["status"] == "executed"
    assert result["host_mutation_performed"] is False
    assert result["host_mutation_uncertain"] is False


def test_typed_mutation_truth_and_failed_operation_are_bound_to_this_invocation(tmp_path: Path) -> None:
    from overseer.backup_provisioning import execute_plan

    class ReadOnlyFailure(RecordingAdapter):
        def execute(self, step):
            self.calls.append(step)
            if step.operation == "verify_published_adapter_source":
                raise RuntimeError("read-only probe failed")
            return super().execute(step)

    store_path, plan, _bundle = _approved(tmp_path / "readonly")
    result = execute_plan(store_path, plan.plan_id, ReadOnlyFailure(), acceptance_runner=Runner())
    assert result["host_mutation_performed"] is False
    assert result["host_mutation_uncertain"] is False
    assert result["failed_operation"] == "verify_published_adapter_source"

    class MutableFailure(RecordingAdapter):
        def execute(self, step):
            self.calls.append(step)
            if step.operation == "install_runtime":
                raise RuntimeError("mutable operation failed")
            return super().execute(step)

    store_path, plan, _bundle = _approved(tmp_path / "mutable")
    result = execute_plan(store_path, plan.plan_id, MutableFailure(), acceptance_runner=Runner())
    assert result["host_mutation_performed"] is False
    assert result["host_mutation_uncertain"] is True
    assert result["failed_operation"] == "install_runtime"


def test_same_now_racing_starts_have_one_durable_claim_and_one_adapter_call(tmp_path: Path) -> None:
    store_path, plan, _bundle = _approved(tmp_path)
    started = threading.Event()
    release = threading.Event()
    first_adapter = BlockingAdapter(started, release)
    second_adapter = RecordingAdapter()
    results: list[object] = []

    def run(adapter):
        try:
            results.append(start_execution(store_path, plan.plan_id, adapter, Runner(), now="2026-08-06T00:00:00+00:00"))
        except Exception as error:
            results.append(error)

    first = threading.Thread(target=run, args=(first_adapter,))
    second = threading.Thread(target=run, args=(second_adapter,))
    first.start()
    assert started.wait(timeout=10)
    second.start()
    second.join(timeout=10)
    release.set()
    first.join(timeout=10)

    assert len(first_adapter.calls) == len(plan.steps)
    assert second_adapter.calls == []
    assert any(isinstance(item, ValueError) and "EXECUTION_IN_PROGRESS" in str(item) for item in results)


def test_execute_plan_loser_serializes_its_captured_in_progress_snapshot(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_provisioning as provisioning

    store_path, plan, _bundle = _approved(tmp_path)
    winner_started = threading.Event()
    release_winner = threading.Event()
    loser_snapshot = threading.Event()
    winner_adapter = BlockingAdapter(winner_started, release_winner)
    loser_adapter = RecordingAdapter()
    results: dict[str, object] = {}
    original_public = provisioning._typed_execution_public

    def observe_loser_snapshot(*args, **kwargs):
        if kwargs.get("mutation") is False:
            loser_snapshot.set()
            assert release_winner.wait(timeout=10)
        return original_public(*args, **kwargs)

    monkeypatch.setattr(provisioning, "_typed_execution_public", observe_loser_snapshot)

    def run_winner() -> None:
        results["winner"] = execute_plan(store_path, plan.plan_id, winner_adapter, acceptance_runner=Runner())

    def run_loser() -> None:
        results["loser"] = execute_plan(store_path, plan.plan_id, loser_adapter, acceptance_runner=Runner())

    winner = threading.Thread(target=run_winner)
    loser = threading.Thread(target=run_loser)
    winner.start()
    assert winner_started.wait(timeout=10)
    loser.start()
    assert loser_snapshot.wait(timeout=10)
    release_winner.set()
    winner.join(timeout=10)
    loser.join(timeout=10)

    assert len(winner_adapter.calls) == len(plan.steps)
    assert loser_adapter.calls == []
    assert results["winner"]["status"] == "executed"
    assert results["winner"]["mutation_performed"] is True
    assert results["loser"]["status"] == "in_progress"
    assert results["loser"]["mutation_performed"] is False
    assert results["loser"]["host_mutation_performed"] is False
    assert results["loser"]["host_mutation_uncertain"] is False


def test_execute_plan_loser_uses_one_snapshot_across_winner_finalize_race(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_execution as execution
    import overseer.backup_provisioning as provisioning

    store_path, plan, _bundle = _approved(tmp_path)
    winner_started = threading.Event()
    release_winner = threading.Event()
    loser_snapshot_loaded = threading.Event()
    winner_finished = threading.Event()
    winner_adapter = BlockingAdapter(winner_started, release_winner)
    loser_adapter = RecordingAdapter()
    results: dict[str, object] = {}
    captured: dict[str, object] = {}
    original_snapshot = execution._load_execution_snapshot
    original_public = provisioning._typed_execution_public
    loser_snapshot_calls = 0

    def observe_snapshot(store, header, **kwargs):
        nonlocal loser_snapshot_calls
        if threading.current_thread().name == "loser":
            loser_snapshot_calls += 1
        if threading.current_thread().name == "loser" and loser_snapshot_calls == 2:
            def after_checkpoints() -> None:
                loser_snapshot_loaded.set()
                release_winner.set()

            snapshot = original_snapshot(store, header, after_checkpoints=after_checkpoints)
            captured["loser_snapshot"] = (header, snapshot)
            return snapshot
        return original_snapshot(store, header, **kwargs)

    def observe_public(plan_arg, view, checkpoints, **kwargs):
        if threading.current_thread().name == "loser":
            captured["public"] = (plan_arg, view, checkpoints, kwargs["header"])
            assert winner_finished.wait(timeout=10)
        return original_public(plan_arg, view, checkpoints, **kwargs)

    monkeypatch.setattr(execution, "_load_execution_snapshot", observe_snapshot)
    monkeypatch.setattr(provisioning, "_typed_execution_public", observe_public)

    def run_winner() -> None:
        results["winner"] = execute_plan(store_path, plan.plan_id, winner_adapter, acceptance_runner=Runner())
        winner_finished.set()

    def run_loser() -> None:
        results["loser"] = execute_plan(store_path, plan.plan_id, loser_adapter, acceptance_runner=Runner())

    winner = threading.Thread(target=run_winner, name="winner")
    loser = threading.Thread(target=run_loser, name="loser")
    winner.start()
    assert winner_started.wait(timeout=10)
    loser.start()
    assert loser_snapshot_loaded.wait(timeout=10)
    winner.join(timeout=10)
    loser.join(timeout=10)

    assert not winner.is_alive()
    assert not loser.is_alive()
    assert loser_adapter.calls == []
    assert results["winner"]["status"] == "executed"
    assert results["loser"]["status"] == "in_progress"
    assert results["loser"]["mutation_performed"] is False
    assert results["loser"]["host_mutation_performed"] is False
    assert results["loser"]["host_mutation_uncertain"] is False

    snapshot_header, (snapshot_checkpoints, snapshot_plan) = captured["loser_snapshot"]
    public_plan, public_view, public_checkpoints, public_header = captured["public"]
    assert public_header == snapshot_header
    assert public_plan == snapshot_plan
    assert public_checkpoints == snapshot_checkpoints
    assert public_view == execution.derive_backup_execution_view(snapshot_header, snapshot_checkpoints)
    assert snapshot_checkpoints[-1].event is CheckpointEvent.STEP_STARTED


def test_execute_plan_preserves_mutation_when_later_claim_is_contended(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_execution as execution
    import overseer.backup_provisioning as provisioning

    store_path, plan, _bundle = _approved(tmp_path)
    a_completed = threading.Event()
    b_claimed = threading.Event()
    release_a = threading.Event()
    b_started = threading.Event()
    release_b = threading.Event()
    a_finished = threading.Event()
    a_adapter = RecordingAdapter()
    b_adapter = BlockingAdapter(b_started, release_b)
    results: dict[str, object] = {}
    captured: dict[str, object] = {}
    original_append = execution._append
    original_claim = execution._claim_forward
    original_public = provisioning._typed_execution_public

    def observe_append(store, header, ordinal, identity, event, when, **kwargs):
        result = original_append(store, header, ordinal, identity, event, when, **kwargs)
        if (
            threading.current_thread().name == "caller-a"
            and event is CheckpointEvent.STEP_COMPLETED
            and identity.forward.operation == "install_runtime"
        ):
            captured["a_completed_checkpoint"] = store.load_backup_execution_checkpoints(header.execution_id)[-1]
            a_completed.set()
            assert b_claimed.wait(timeout=10)
            assert release_a.wait(timeout=10)
        return result

    def observe_claim(store, header, identity, when):
        claimed = original_claim(store, header, identity, when)
        if threading.current_thread().name == "caller-b" and claimed:
            if identity.forward.operation != "install_runtime":
                captured["b_claimed_checkpoint"] = store.load_backup_execution_checkpoints(header.execution_id)[-1]
                b_claimed.set()
        return claimed

    def observe_public(plan_arg, view, checkpoints, **kwargs):
        if threading.current_thread().name == "caller-a":
            captured["a_public"] = (plan_arg, view, checkpoints, kwargs["invocation_checkpoints"])
        return original_public(plan_arg, view, checkpoints, **kwargs)

    monkeypatch.setattr(execution, "_append", observe_append)
    monkeypatch.setattr(execution, "_claim_forward", observe_claim)
    monkeypatch.setattr(provisioning, "_typed_execution_public", observe_public)

    def run_a() -> None:
        results["a"] = execute_plan(store_path, plan.plan_id, a_adapter, acceptance_runner=Runner())
        a_finished.set()

    def run_b() -> None:
        results["b"] = execute_plan(store_path, plan.plan_id, b_adapter, acceptance_runner=Runner())

    thread_a = threading.Thread(target=run_a, name="caller-a")
    thread_b = threading.Thread(target=run_b, name="caller-b")
    thread_a.start()
    assert a_completed.wait(timeout=10)
    thread_b.start()
    assert b_claimed.wait(timeout=10)
    assert b_started.wait(timeout=10)
    release_a.set()
    assert a_finished.wait(timeout=10)

    assert a_adapter.calls.count(next(step for step in plan.steps if step.operation == "install_runtime")) == 1
    assert results["a"]["status"] == "in_progress"
    assert results["a"]["mutation_performed"] is True
    assert results["a"]["host_mutation_performed"] is True
    assert results["a"]["host_mutation_uncertain"] is False
    a_plan, a_view, a_checkpoints, a_invocation_checkpoints = captured["a_public"]
    assert a_plan.plan_id == plan.plan_id
    assert a_view.status == "in_progress"
    assert captured["a_completed_checkpoint"] in a_invocation_checkpoints
    assert captured["b_claimed_checkpoint"] in a_checkpoints
    assert captured["b_claimed_checkpoint"] not in a_invocation_checkpoints
    assert all(item.checkpoint_id != captured["b_claimed_checkpoint"].checkpoint_id for item in a_invocation_checkpoints)

    release_b.set()
    thread_a.join(timeout=10)
    thread_b.join(timeout=10)
    assert not thread_a.is_alive()
    assert not thread_b.is_alive()
    assert b_adapter.calls.count(next(step for step in plan.steps if step.operation == "install_runtime")) == 0


def test_execute_plan_preserves_mutation_when_later_completed_claim_is_contended(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_execution as execution
    import overseer.backup_provisioning as provisioning

    store_path, plan, _bundle = _approved(tmp_path)
    a_completed = threading.Event()
    b_completed = threading.Event()
    release_a = threading.Event()
    release_b = threading.Event()
    a_finished = threading.Event()
    a_adapter = RecordingAdapter()
    b_adapter = RecordingAdapter()
    execution_time = _execution_time_at_or_after_approval(store_path, plan.plan_id)
    results: dict[str, object] = {}
    captured: dict[str, object] = {}
    original_append = execution._append
    original_public = provisioning._typed_execution_public

    def observe_append(store, header, ordinal, identity, event, when, **kwargs):
        result = original_append(store, header, ordinal, identity, event, when, **kwargs)
        if event is CheckpointEvent.STEP_COMPLETED and identity.forward.operation == "install_runtime":
            if threading.current_thread().name == "caller-a":
                captured["a_completed_checkpoint"] = store.load_backup_execution_checkpoints(header.execution_id)[-1]
                a_completed.set()
                assert b_completed.wait(timeout=10)
                assert release_a.wait(timeout=10)
        elif event is CheckpointEvent.STEP_COMPLETED and identity.forward.operation == "verify_endpoint_migration_ready" and threading.current_thread().name == "caller-b":
            captured["b_completed_checkpoint"] = store.load_backup_execution_checkpoints(header.execution_id)[-1]
            b_completed.set()
            assert release_b.wait(timeout=10)

    def observe_public(plan_arg, view, checkpoints, **kwargs):
        if threading.current_thread().name == "caller-a":
            captured["a_public"] = (plan_arg, view, checkpoints, kwargs["invocation_checkpoints"])
        return original_public(plan_arg, view, checkpoints, **kwargs)

    monkeypatch.setattr(execution, "_append", observe_append)
    monkeypatch.setattr(provisioning, "_typed_execution_public", observe_public)

    def run_a() -> None:
        results["a"] = execute_plan(store_path, plan.plan_id, a_adapter, executed_at=execution_time, acceptance_runner=Runner())
        a_finished.set()

    def run_b() -> None:
        results["b"] = execute_plan(store_path, plan.plan_id, b_adapter, executed_at=execution_time, acceptance_runner=Runner())

    thread_a = threading.Thread(target=run_a, name="caller-a")
    thread_b = threading.Thread(target=run_b, name="caller-b")
    thread_a.start()
    assert a_completed.wait(timeout=10)
    thread_b.start()
    assert b_completed.wait(timeout=10)
    release_a.set()
    assert a_finished.wait(timeout=10)

    install_runtime = next(step for step in plan.steps if step.operation == "install_runtime")
    assert a_adapter.calls.count(install_runtime) == 1
    assert b_adapter.calls.count(install_runtime) == 0
    assert results["a"]["status"] in {"in_progress", "executed"}
    assert results["a"]["mutation_performed"] is True
    assert results["a"]["host_mutation_performed"] is True
    assert results["a"]["host_mutation_uncertain"] is False
    a_plan, a_view, a_checkpoints, a_invocation_checkpoints = captured["a_public"]
    assert a_plan.plan_id == plan.plan_id
    assert a_view.status == results["a"]["status"]
    assert captured["a_completed_checkpoint"] in a_invocation_checkpoints
    assert captured["b_completed_checkpoint"] in a_checkpoints
    assert captured["b_completed_checkpoint"] not in a_invocation_checkpoints
    assert all(item.checkpoint_id != captured["b_completed_checkpoint"].checkpoint_id for item in a_invocation_checkpoints)

    release_b.set()
    thread_a.join(timeout=10)
    thread_b.join(timeout=10)
    assert not thread_a.is_alive()
    assert not thread_b.is_alive()


def test_execute_plan_preserves_changed_mutation_when_terminal_claim_is_contended(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_execution as execution
    import overseer.backup_provisioning as provisioning

    store_path, plan, _bundle = _approved(tmp_path)
    a_completed = threading.Event()
    b_finished = threading.Event()
    release_a = threading.Event()
    a_finished = threading.Event()
    a_adapter = RecordingAdapter()
    b_adapter = RecordingAdapter()
    results: dict[str, object] = {}
    captured: dict[str, object] = {}
    original_append = execution._append
    original_public = provisioning._typed_execution_public

    def observe_append(store, header, ordinal, identity, event, when, **kwargs):
        result = original_append(store, header, ordinal, identity, event, when, **kwargs)
        if (
            threading.current_thread().name == "caller-a"
            and event is CheckpointEvent.STEP_COMPLETED
            and identity.forward.operation == "install_runtime"
        ):
            captured["a_completed_checkpoint"] = store.load_backup_execution_checkpoints(header.execution_id)[-1]
            a_completed.set()
            assert b_finished.wait(timeout=10)
            assert release_a.wait(timeout=10)
        return result

    def observe_public(plan_arg, view, checkpoints, **kwargs):
        if threading.current_thread().name == "caller-a":
            captured["a_public"] = (plan_arg, view, checkpoints, kwargs["invocation_checkpoints"])
        return original_public(plan_arg, view, checkpoints, **kwargs)

    monkeypatch.setattr(execution, "_append", observe_append)
    monkeypatch.setattr(provisioning, "_typed_execution_public", observe_public)

    def run_a() -> None:
        results["a"] = execute_plan(store_path, plan.plan_id, a_adapter, acceptance_runner=Runner())
        a_finished.set()

    def run_b() -> None:
        with SQLiteStore(store_path) as store:
            entry_checkpoint_ids = {
                checkpoint.checkpoint_id
                for checkpoint in store.load_backup_execution_checkpoints(
                    store.load_backup_execution_header_for_plan(plan.plan_id).execution_id
                )
            }
        results["b"] = execute_plan(store_path, plan.plan_id, b_adapter, acceptance_runner=Runner())
        with SQLiteStore(store_path) as store:
            captured["b_checkpoint_ids"] = {
                checkpoint.checkpoint_id
                for checkpoint in store.load_backup_execution_checkpoints(
                    store.load_backup_execution_header_for_plan(plan.plan_id).execution_id
                )
            } - entry_checkpoint_ids
        b_finished.set()

    thread_a = threading.Thread(target=run_a, name="caller-a")
    thread_b = threading.Thread(target=run_b, name="caller-b")
    thread_a.start()
    assert a_completed.wait(timeout=10)
    thread_b.start()
    assert b_finished.wait(timeout=10)
    release_a.set()
    assert a_finished.wait(timeout=10)
    thread_a.join(timeout=10)
    thread_b.join(timeout=10)

    assert not thread_a.is_alive()
    assert not thread_b.is_alive()
    install_runtime = next(step for step in plan.steps if step.operation == "install_runtime")
    assert a_adapter.calls.count(install_runtime) == 1
    assert b_adapter.calls.count(install_runtime) == 0
    assert results["b"]["status"] == "executed"
    assert results["a"]["status"] == "executed"
    assert results["a"]["mutation_performed"] is True
    assert results["a"]["host_mutation_performed"] is True
    assert results["a"]["host_mutation_uncertain"] is False
    a_plan, a_view, a_checkpoints, a_invocation_checkpoints = captured["a_public"]
    assert a_plan.plan_id == plan.plan_id
    assert a_view.status == "succeeded"
    assert a_view.terminal_success is True
    assert captured["a_completed_checkpoint"] in a_invocation_checkpoints
    assert {item.checkpoint_id for item in a_invocation_checkpoints}.isdisjoint(captured["b_checkpoint_ids"])
    assert a_checkpoints[-1].event is CheckpointEvent.EXECUTION_FINALIZED
    assert a_adapter.calls.count(install_runtime) == 1


def test_execute_plan_does_not_swallow_unrelated_claim_value_error(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_execution as execution

    store_path, plan, _bundle = _approved(tmp_path)

    def unrelated_claim_error(*args, **kwargs):
        raise ValueError("execution invariant was violated")

    monkeypatch.setattr(execution, "_claim_forward", unrelated_claim_error)
    with pytest.raises(ValueError, match="execution invariant was violated"):
        execute_plan(store_path, plan.plan_id, RecordingAdapter(), acceptance_runner=Runner())


def test_concurrent_advancement_with_authority_loss_fails_closed_without_contention(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_execution as execution

    store_path, plan, _bundle = _approved(tmp_path)
    a_completed = threading.Event()
    b_before_following_claim = threading.Event()
    release_a = threading.Event()
    release_b = threading.Event()
    a_finished = threading.Event()
    a_adapter = RecordingAdapter()
    b_adapter = RecordingAdapter()
    execution_time = _execution_time_at_or_after_approval(store_path, plan.plan_id)
    results: dict[str, object] = {}
    errors: dict[str, BaseException] = {}
    original_append = execution._append
    original_claim = execution._claim_forward

    def observe_append(store, header, ordinal, identity, event, when, **kwargs):
        result = original_append(store, header, ordinal, identity, event, when, **kwargs)
        if (
            threading.current_thread().name == "caller-a"
            and event is CheckpointEvent.STEP_COMPLETED
            and identity.forward.operation == "install_runtime"
        ):
            a_completed.set()
            assert b_before_following_claim.wait(timeout=10)
            with SQLiteStore(store_path) as authority_store:
                message = authority_store.load_crew_message(plan.evidence_ids["kira"])
                authority_store.save_crew_message(replace(message, review_status=CrewReviewStatus.CORRECTION_REQUESTED))
            release_a.set()
        return result

    def pause_before_following_claim(store, header, identity, when):
        if threading.current_thread().name == "caller-b" and identity.forward.operation == "ensure_system_user":
            b_before_following_claim.set()
            assert release_b.wait(timeout=10)
        return original_claim(store, header, identity, when)

    monkeypatch.setattr(execution, "_append", observe_append)
    monkeypatch.setattr(execution, "_claim_forward", pause_before_following_claim)

    def run_a() -> None:
        try:
            results["a"] = execute_plan(store_path, plan.plan_id, a_adapter, executed_at=execution_time, acceptance_runner=Runner())
        except BaseException as error:
            errors["a"] = error
        finally:
            a_finished.set()

    def run_b() -> None:
        try:
            results["b"] = execute_plan(store_path, plan.plan_id, b_adapter, executed_at=execution_time, acceptance_runner=Runner())
        except BaseException as error:
            errors["b"] = error

    thread_a = threading.Thread(target=run_a, name="caller-a")
    thread_b = threading.Thread(target=run_b, name="caller-b")
    thread_a.start()
    assert a_completed.wait(timeout=10)
    thread_b.start()
    assert b_before_following_claim.wait(timeout=10)
    assert a_finished.wait(timeout=10)

    assert "a" not in errors
    assert results["a"]["status"] in {"failed", "rolled_back", "in_progress"}
    assert results["a"]["mutation_performed"] is True
    assert results["a"]["host_mutation_performed"] is True
    assert results["a"]["host_mutation_uncertain"] is False
    with SQLiteStore(store_path) as store:
        checkpoints = store.load_backup_execution_checkpoints(store.load_backup_execution_header_for_plan(plan.plan_id).execution_id)
    assert any(item.event is CheckpointEvent.EXECUTION_ABORTED for item in checkpoints)
    assert any(item.step_evidence is not None and item.step_evidence.safe_code == "FORWARD_AUTHORITY_LOST" for item in checkpoints)

    release_b.set()
    thread_a.join(timeout=10)
    thread_b.join(timeout=10)
    assert not thread_a.is_alive()
    assert not thread_b.is_alive()


def test_paused_prefix_continuations_serialize_their_own_invocation_snapshots(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_execution as execution

    store_path, plan, _bundle = _approved(tmp_path)
    paused = execute_plan(store_path, plan.plan_id, RecordingAdapter(), acceptance_runner=None)
    assert paused["status"] == "in_progress"

    a_ready = threading.Event()
    b_finished = threading.Event()
    release_a = threading.Event()
    results: dict[str, object] = {}
    a_adapter = RecordingAdapter()
    b_adapter = RecordingAdapter()
    original_snapshot = execution._load_execution_snapshot
    snapshot_count = threading.local()

    def observe_snapshot(store, header):
        count = getattr(snapshot_count, "value", 0) + 1
        snapshot_count.value = count

        def after_checkpoints():
            if threading.current_thread().name == "caller-a" and count == 2:
                a_ready.set()
                assert b_finished.wait(timeout=10)
                assert release_a.wait(timeout=10)

        return original_snapshot(store, header, after_checkpoints=after_checkpoints)

    monkeypatch.setattr(execution, "_load_execution_snapshot", observe_snapshot)

    def run_a() -> None:
        results["a"] = execute_plan(store_path, plan.plan_id, a_adapter, acceptance_runner=None)

    def run_b() -> None:
        results["b"] = execute_plan(store_path, plan.plan_id, b_adapter, acceptance_runner=Runner())
        b_finished.set()

    thread_a = threading.Thread(target=run_a, name="caller-a")
    thread_b = threading.Thread(target=run_b)
    thread_a.start()
    assert a_ready.wait(timeout=10)
    thread_b.start()
    thread_b.join(timeout=10)
    assert not thread_b.is_alive()
    release_a.set()
    thread_a.join(timeout=10)
    assert not thread_a.is_alive()

    assert a_adapter.calls == []
    assert b_adapter.calls == []
    assert results["a"]["status"] == "in_progress"
    assert results["a"]["mutation_performed"] is False
    assert results["a"]["host_mutation_performed"] is False
    assert results["a"]["host_mutation_uncertain"] is False
    assert results["b"]["status"] == "executed"
    assert results["b"]["mutation_performed"] is True
    assert results["b"]["host_mutation_performed"] is False
    assert results["b"]["host_mutation_uncertain"] is False


def test_continuation_does_not_claim_mutation_when_b_completes_between_snapshots(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_execution as execution

    store_path, plan, _bundle = _approved(tmp_path)
    paused = execute_plan(store_path, plan.plan_id, RecordingAdapter(), acceptance_runner=None)
    assert paused["status"] == "in_progress"

    a_entry_ready = threading.Event()
    b_finished = threading.Event()
    release_a = threading.Event()
    results: dict[str, object] = {}
    a_adapter = RecordingAdapter()
    b_adapter = RecordingAdapter()
    original_snapshot = execution._load_execution_snapshot
    snapshot_count = threading.local()

    def observe_snapshot(store, header):
        count = getattr(snapshot_count, "value", 0) + 1
        snapshot_count.value = count
        snapshot = original_snapshot(store, header)
        if threading.current_thread().name == "caller-a" and count == 1:
            a_entry_ready.set()
            assert b_finished.wait(timeout=10)
            assert release_a.wait(timeout=10)
        return snapshot

    monkeypatch.setattr(execution, "_load_execution_snapshot", observe_snapshot)

    def run_a() -> None:
        results["a"] = execute_plan(store_path, plan.plan_id, a_adapter, acceptance_runner=None)

    def run_b() -> None:
        results["b"] = execute_plan(store_path, plan.plan_id, b_adapter, acceptance_runner=Runner())
        b_finished.set()

    thread_a = threading.Thread(target=run_a, name="caller-a")
    thread_b = threading.Thread(target=run_b)
    thread_a.start()
    assert a_entry_ready.wait(timeout=10)
    thread_b.start()
    thread_b.join(timeout=10)
    assert not thread_b.is_alive()
    release_a.set()
    thread_a.join(timeout=10)
    assert not thread_a.is_alive()

    assert a_adapter.calls == []
    assert results["b"]["status"] == "executed"
    assert results["a"]["status"] == "executed"
    assert results["a"]["mutation_performed"] is False
    assert results["a"]["host_mutation_performed"] is False
    assert results["a"]["host_mutation_uncertain"] is False


def test_pending_step_started_fails_closed_for_start_and_continue(tmp_path: Path) -> None:
    store_path, plan, _bundle = _approved(tmp_path)

    class CrashAfterClaim(RecordingAdapter):
        def execute(self, step):
            self.calls.append(step)
            raise BaseException("simulated process interruption")

    with pytest.raises(BaseException):
        start_execution(store_path, plan.plan_id, CrashAfterClaim(), Runner())
    adapter = RecordingAdapter()
    with pytest.raises(ValueError, match="EXECUTION_IN_PROGRESS"):
        start_execution(store_path, plan.plan_id, adapter, Runner())
    with SQLiteStore(store_path) as store:
        execution_id = store.load_backup_execution_header_for_plan(plan.plan_id).execution_id
    with pytest.raises(ValueError, match="EXECUTION_IN_PROGRESS"):
        continue_execution(store_path, execution_id, adapter, Runner())
    assert adapter.calls == []


@pytest.mark.parametrize("entrypoint", ["start", "continue"])
def test_paused_changed_prefix_authority_drift_aborts_and_rolls_back_without_forward_reexecution(tmp_path: Path, entrypoint: str) -> None:
    store_path, plan, _bundle = _approved(tmp_path)
    adapter = RecordingAdapter()
    paused = start_execution(store_path, plan.plan_id, adapter, None)
    before = len(adapter.calls)
    with SQLiteStore(store_path) as store:
        item = store.load_crew_message(plan.evidence_ids["kira"])
        store.save_crew_message(replace(item, review_status=CrewReviewStatus.CORRECTION_REQUESTED))
    view = start_execution(store_path, plan.plan_id, adapter, Runner()) if entrypoint == "start" else continue_execution(store_path, paused.execution_id, adapter, Runner())
    assert view.failure_code == "FORWARD_AUTHORITY_LOST"
    assert view.rollback_status == "completed"
    assert len(adapter.calls) == before + 14
    assert all(step.operation not in {item.operation for item in plan.steps} for step in adapter.calls[before:])
    with SQLiteStore(store_path) as store:
        checkpoints = store.load_backup_execution_checkpoints(paused.execution_id)
    assert any(item.event is CheckpointEvent.EXECUTION_ABORTED for item in checkpoints)
    assert checkpoints[-1].event is CheckpointEvent.ROLLBACK_COMPLETED


@pytest.mark.parametrize("entrypoint", ["start", "continue"])
def test_unrelated_value_error_after_changed_prefix_propagates_without_cleanup(tmp_path: Path, entrypoint: str, monkeypatch) -> None:
    import overseer.backup_execution as execution

    store_path, plan, _bundle = _approved(tmp_path)
    adapter = RecordingAdapter()
    paused = start_execution(store_path, plan.plan_id, adapter, None)
    before_calls = list(adapter.calls)
    before_checkpoints = _checkpoints(store_path, paused.execution_id)

    def unrelated_failure(*_args, **_kwargs):
        raise ValueError("injected unrelated validation failure")

    monkeypatch.setattr(execution, "_load_authoritative_bundle", unrelated_failure)
    with pytest.raises(ValueError, match="injected unrelated"):
        if entrypoint == "start":
            start_execution(store_path, plan.plan_id, adapter, Runner())
        else:
            continue_execution(store_path, paused.execution_id, adapter, Runner())
    assert adapter.calls == before_calls
    assert _checkpoints(store_path, paused.execution_id) == before_checkpoints
    assert all(item.event is not CheckpointEvent.EXECUTION_ABORTED for item in before_checkpoints)
    assert all(item.event not in (CheckpointEvent.ROLLBACK_STARTED, CheckpointEvent.ROLLBACK_COMPLETED, CheckpointEvent.ROLLBACK_FAILED) for item in before_checkpoints)


def test_paused_verified_noop_prefix_authority_drift_fails_closed_without_rollback(tmp_path: Path) -> None:
    store_path, plan, _bundle = _approved(tmp_path)
    adapter = NoopAdapter()
    paused = start_execution(store_path, plan.plan_id, adapter, None)
    before = len(adapter.calls)
    with SQLiteStore(store_path) as store:
        item = store.load_crew_message(plan.evidence_ids["kira"])
        store.save_crew_message(replace(item, review_status=CrewReviewStatus.CORRECTION_REQUESTED))
    with pytest.raises(ValueError):
        continue_execution(store_path, paused.execution_id, adapter, Runner())
    assert len(adapter.calls) == before


@pytest.mark.parametrize("entrypoint", ["start", "continue"])
def test_paused_prefix_with_executed_source_projection_fails_closed(tmp_path: Path, entrypoint: str) -> None:
    store_path, plan, _bundle = _approved(tmp_path)
    adapter = RecordingAdapter()
    paused = start_execution(store_path, plan.plan_id, adapter, None)
    before_calls = list(adapter.calls)
    with SQLiteStore(store_path) as store:
        current = _stored(store, plan.plan_id)
        tampered = replace(
            current,
            status=ProvisioningStatus.EXECUTED,
            executed_at="2026-08-05T12:00:00+00:00",
            evidence_digest="sha256:" + "e" * 64,
        )
        store._connection.execute(
            "UPDATE backup_provisioning_plans SET payload=? WHERE id=?",
            (_dump(tampered), plan.plan_id),
        )
        store._connection.commit()
        before_checkpoints = store.load_backup_execution_checkpoints(paused.execution_id)
    with pytest.raises(ValueError, match="terminal execution"):
        if entrypoint == "start":
            start_execution(store_path, plan.plan_id, adapter, Runner())
        else:
            continue_execution(store_path, paused.execution_id, adapter, Runner())
    assert adapter.calls == before_calls
    with SQLiteStore(store_path) as store:
        after_checkpoints = store.load_backup_execution_checkpoints(paused.execution_id)
    assert after_checkpoints == before_checkpoints
    assert all(item.event is not CheckpointEvent.EXECUTION_ABORTED for item in after_checkpoints)
    assert all(item.event not in (CheckpointEvent.ROLLBACK_STARTED, CheckpointEvent.ROLLBACK_COMPLETED, CheckpointEvent.ROLLBACK_FAILED) for item in after_checkpoints)


@pytest.mark.parametrize("entrypoint", ["start", "continue"])
def test_paused_changed_prefix_executed_source_and_malformed_binding_fail_closed(tmp_path: Path, entrypoint: str) -> None:
    store_path, plan, _bundle = _approved(tmp_path)
    adapter = RecordingAdapter()
    paused = start_execution(store_path, plan.plan_id, adapter, None)
    before_calls = list(adapter.calls)
    with SQLiteStore(store_path) as store:
        current = _stored(store, plan.plan_id)
        tampered = replace(
            current,
            status=ProvisioningStatus.EXECUTED,
            executed_at="2026-08-05T12:00:00+00:00",
            evidence_digest="sha256:" + "e" * 64,
        )
        store._connection.execute("UPDATE backup_provisioning_plans SET payload=? WHERE id=?", (_dump(tampered), plan.plan_id))
        store._connection.execute("UPDATE roadex_approval_bindings SET payload='{}' WHERE approval_ref=?", (f"approval.donuthole.{plan.plan_id}",))
        store._connection.commit()
        before_checkpoints = store.load_backup_execution_checkpoints(paused.execution_id)
    with pytest.raises(ValueError, match="terminal execution"):
        if entrypoint == "start":
            start_execution(store_path, plan.plan_id, adapter, Runner())
        else:
            continue_execution(store_path, paused.execution_id, adapter, Runner())
    assert adapter.calls == before_calls
    with SQLiteStore(store_path) as store:
        after_checkpoints = store.load_backup_execution_checkpoints(paused.execution_id)
    assert after_checkpoints == before_checkpoints
    assert all(item.event is not CheckpointEvent.EXECUTION_ABORTED for item in after_checkpoints)
    assert all(item.event not in (CheckpointEvent.ROLLBACK_STARTED, CheckpointEvent.ROLLBACK_COMPLETED, CheckpointEvent.ROLLBACK_FAILED) for item in after_checkpoints)


def test_authority_and_bundle_drift_reject_continuation_before_adapter(tmp_path: Path) -> None:
    store_path, plan, _bundle = _approved(tmp_path)
    adapter = RecordingAdapter()
    paused = start_execution(store_path, plan.plan_id, adapter, None)
    before = len(adapter.calls)
    with sqlite3.connect(store_path) as connection:
        payload = connection.execute("SELECT payload FROM provisioning_bundles WHERE plan_id=?", (plan.plan_id,)).fetchone()[0]
        connection.execute("UPDATE provisioning_bundles SET payload=? WHERE plan_id=?", (payload + " ", plan.plan_id))
        connection.commit()
    with pytest.raises(ValueError):
        continue_execution(store_path, paused.execution_id, adapter, Runner())
    assert len(adapter.calls) == before

def test_tampered_execution_aborted_evidence_is_rejected_without_forward_claim(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_execution as execution

    store_path, plan, _bundle = _approved(tmp_path)
    adapter = RecordingAdapter()
    paused = start_execution(store_path, plan.plan_id, adapter, None)
    original_append = execution._append
    original_load = execution._load_authoritative_bundle
    load_count = {"value": 0}

    def drift_on_claim(*args, **kwargs):
        load_count["value"] += 1
        if load_count["value"] == 2:
            raise execution._AuthorityMismatchError("review drift")
        return original_load(*args, **kwargs)

    def tamper_abort(*args, **kwargs):
        if args[4] is CheckpointEvent.EXECUTION_ABORTED:
            kwargs["evidence"] = replace(kwargs["evidence"], result_digest="sha256:" + "0" * 64)
        return original_append(*args, **kwargs)

    monkeypatch.setattr(execution, "_append", tamper_abort)
    monkeypatch.setattr(execution, "_load_authoritative_bundle", drift_on_claim)
    before_checkpoints = _checkpoints(store_path, paused.execution_id)
    with pytest.raises(ValueError, match="execution abort"):
        continue_execution(store_path, paused.execution_id, adapter, Runner())
    assert len(adapter.calls) == len(plan.steps)
    assert _checkpoints(store_path, paused.execution_id) == before_checkpoints


def test_exception_and_failed_forward_never_rerun_forward_or_persist_unsafe_text(tmp_path: Path) -> None:
    store_path, plan, _bundle = _approved(tmp_path)

    class Exploding(RecordingAdapter):
        def execute(self, step):
            self.calls.append(step)
            if step.operation == "verify_endpoint_migration_ready":
                raise RuntimeError("secret=shh path=/private/secret")
            return super().execute(step)

    adapter = Exploding()
    view = start_execution(store_path, plan.plan_id, adapter, Runner())
    assert view.terminal_success is False
    assert [step.operation for step in adapter.calls].count("verify_endpoint_migration_ready") == 1
    with SQLiteStore(store_path) as store:
        payloads = [str(row[0]) for row in store._connection.execute("SELECT payload FROM backup_provisioning_execution_checkpoints")]
    assert all(secret not in "".join(payloads) for secret in ("shh", "/private/secret"))
    assert "shh" not in repr(view) and "/private/secret" not in repr(view)


@pytest.mark.parametrize("resume_with_start", (False, True))
def test_interrupted_rollback_recovery_skips_failed_identity_and_forward(tmp_path: Path, monkeypatch, resume_with_start: bool) -> None:
    import overseer.backup_execution as execution

    store_path, plan, _bundle = _approved(tmp_path)

    class FailOnce(RecordingAdapter):
        def __init__(self):
            super().__init__(fail_operation="install_systemd_unit")
            self.failed_rollback = False

        def execute(self, step):
            if step.operation == "remove_private_config" and not self.failed_rollback:
                self.failed_rollback = True
                self.calls.append(step)
                return {"ok": False, "operation": step.operation, "disposition": "changed", "safe_code": "ROLLBACK_FAILED", "evidence": {}, "redactions_applied": True}
            return super().execute(step)

    adapter = FailOnce()
    original_append = execution._append
    rollback_starts = {"count": 0}

    def interrupt_after_failure(*args, **kwargs):
        result = original_append(*args, **kwargs)
        if args[4] is CheckpointEvent.ROLLBACK_FAILED:
            rollback_starts["count"] += 1
            if rollback_starts["count"] == 1:
                raise BaseException("crash after rollback failure")
        return result

    monkeypatch.setattr(execution, "_append", interrupt_after_failure)
    with pytest.raises(BaseException):
        start_execution(store_path, plan.plan_id, adapter, Runner())
    monkeypatch.setattr(execution, "_append", original_append)
    before = [step.operation for step in adapter.calls[:16]]
    view = (start_execution(store_path, plan.plan_id, adapter, Runner()) if resume_with_start else continue_execution(store_path, execution_id_for(store_path, plan.plan_id), adapter, Runner()))
    assert view.rollback_status == "failed"
    assert before == [step.operation for step in plan.steps[:16]]
    assert sum(step.operation == "remove_private_config" for step in adapter.calls) == 1
    assert sum(step.operation == "install_private_config" for step in adapter.calls) == 1


def test_ambiguous_rollback_started_tail_fails_closed(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_execution as execution

    store_path, plan, _bundle = _approved(tmp_path)
    adapter = RecordingAdapter(fail_operation="install_private_config")
    original_append = execution._append
    interrupted = {"value": False}

    def interrupt_after_rollback_claim(*args, **kwargs):
        result = original_append(*args, **kwargs)
        if args[4] is CheckpointEvent.ROLLBACK_STARTED and not interrupted["value"]:
            interrupted["value"] = True
            raise BaseException("crash after rollback claim")
        return result

    monkeypatch.setattr(execution, "_append", interrupt_after_rollback_claim)
    with pytest.raises(BaseException):
        start_execution(store_path, plan.plan_id, adapter, Runner())
    monkeypatch.setattr(execution, "_append", original_append)
    before = len(adapter.calls)
    with pytest.raises(ValueError, match="EXECUTION_IN_PROGRESS"):
        continue_execution(store_path, execution_id_for(store_path, plan.plan_id), adapter, Runner())
    assert len(adapter.calls) == before


def test_typed_execute_plan_pauses_before_runner_only_after_forward_prefix(tmp_path: Path) -> None:
    from overseer.backup_provisioning import execute_plan

    store_path, plan, _bundle = _approved(tmp_path)
    adapter = RecordingAdapter()
    result = execute_plan(store_path, plan.plan_id, adapter)
    assert result["status"] == "in_progress"
    assert result["host_mutation_performed"] is True
    assert len(adapter.calls) == len(plan.steps)


def test_finalize_step_crash_is_recovered_without_adapter_or_runner_calls(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_execution as execution

    store_path, plan, _bundle = _approved(tmp_path)
    original_append = execution._append

    def interrupt_before_terminal(*args, **kwargs):
        if args[4] is CheckpointEvent.EXECUTION_FINALIZED:
            raise BaseException("crash before terminal event")
        return original_append(*args, **kwargs)

    monkeypatch.setattr(execution, "_append", interrupt_before_terminal)
    with pytest.raises(BaseException):
        start_execution(store_path, plan.plan_id, RecordingAdapter(), Runner())
    monkeypatch.setattr(execution, "_append", original_append)

    adapter = RecordingAdapter()
    runner = Runner()
    view = continue_execution(store_path, execution_id_for(store_path, plan.plan_id), adapter, runner)
    assert view.terminal_success is True
    assert adapter.calls == []
    assert runner.attest_calls == runner.accept_calls == 0


def test_plan_projection_crash_after_terminal_event_is_reconciled_without_calls(tmp_path: Path, monkeypatch) -> None:
    import overseer.backup_execution as execution

    store_path, plan, _bundle = _approved(tmp_path)
    original_reconcile = execution._reconcile_executed
    interrupted = {"value": False}

    def interrupt_projection(*args, **kwargs):
        if not interrupted["value"]:
            interrupted["value"] = True
            raise BaseException("crash before plan projection")
        return original_reconcile(*args, **kwargs)

    monkeypatch.setattr(execution, "_reconcile_executed", interrupt_projection)
    with pytest.raises(BaseException):
        start_execution(store_path, plan.plan_id, RecordingAdapter(), Runner())
    monkeypatch.setattr(execution, "_reconcile_executed", original_reconcile)

    adapter = RecordingAdapter()
    runner = Runner()
    view = continue_execution(store_path, execution_id_for(store_path, plan.plan_id), adapter, runner)
    assert view.terminal_success is True
    assert adapter.calls == []
    assert runner.attest_calls == runner.accept_calls == 0


def execution_id_for(store_path: str, plan_id: str) -> str:
    with SQLiteStore(store_path) as store:
        return store.load_backup_execution_header_for_plan(plan_id).execution_id


def test_malformed_phase_layout_rejected_before_adapter_call(tmp_path: Path) -> None:
    _store_path, plan, _bundle = _approved(tmp_path)
    malformed = replace(plan, steps=(plan.steps[13],) + plan.steps[:13] + plan.steps[14:])
    with pytest.raises(ValueError, match="phase layout"):
        _manifest(malformed)
