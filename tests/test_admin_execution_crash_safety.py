from __future__ import annotations

import threading
import time
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from overseer.admin import AdminCommandResult, approve_admin_change_plan
from overseer.cli import (
    cancel_admin_change_status,
    execute_admin_change_status,
    plan_admin_change_status,
)
from overseer.store import SQLiteStore


def _cross_process_execute(
    store_path: str,
    plan_id: str,
    start: multiprocessing.synchronize.Event,
    results: multiprocessing.queues.Queue,
) -> None:
    calls = 0

    def runner(step):
        nonlocal calls
        calls += 1
        time.sleep(0.05)
        return AdminCommandResult(step.title, step.command, 0, "ok", "")

    start.wait(timeout=5)
    result = execute_admin_change_status(store_path, plan_id, runner=runner)
    results.put((result["replayed"], calls, result["status"]))


def _stage_approved_restart(store_path: Path, plan_id: str) -> None:
    plan_admin_change_status(
        store_path,
        plan_id,
        "user_service_restart",
        "overseer-approval-smoke.service",
        "exercise crash-safe admin execution",
        "inactive",
    )
    with SQLiteStore(store_path) as store:
        plan = store.load_admin_change_plan(plan_id)
        store.save_admin_change_plan(
            approve_admin_change_plan(
                plan,
                "sisko",
                "2026-08-26T05:00:00+00:00",
            )
        )


def test_runner_interruption_leaves_durable_claim_and_retry_fails_closed(
    tmp_path: Path,
) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    plan_id = "admin.approval.interrupted"
    _stage_approved_restart(store_path, plan_id)

    with pytest.raises(RuntimeError, match="simulated interruption"):
        execute_admin_change_status(
            store_path,
            plan_id,
            runner=lambda _step: (_ for _ in ()).throw(
                RuntimeError("simulated interruption")
            ),
        )

    with SQLiteStore(store_path) as store:
        claims = store.list_admin_execution_claims()

    assert len(claims) == 1
    assert claims[0].state.value == "claimed"
    assert claims[0].plan_digest
    with pytest.raises(ValueError, match="reconciliation required"):
        execute_admin_change_status(
            store_path,
            plan_id,
            runner=lambda step: pytest.fail(
                f"interrupted execution retry ran command {step.command}"
            ),
        )


def test_cancellation_waits_until_command_execution_releases_authority_lock(
    tmp_path: Path,
) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    plan_id = "admin.approval.cancel-race"
    _stage_approved_restart(store_path, plan_id)
    command_started = threading.Event()
    release_command = threading.Event()

    def blocking_runner(step):
        command_started.set()
        assert release_command.wait(timeout=5)
        return AdminCommandResult(step.title, step.command, 0, "ok", "")

    with ThreadPoolExecutor(max_workers=2) as executor:
        execution = executor.submit(
            execute_admin_change_status,
            store_path,
            plan_id,
            blocking_runner,
        )
        assert command_started.wait(timeout=5)
        cancellation = executor.submit(
            cancel_admin_change_status,
            store_path,
            plan_id,
            "sisko",
            "cancel only after the active execution has left its authority lock",
        )
        time.sleep(0.05)
        assert cancellation.done() is False
        release_command.set()
        assert execution.result(timeout=5)["status"] == "completed"
        assert cancellation.result(timeout=5)["canceled"] is True


def test_cross_process_execution_has_one_mutating_winner(tmp_path: Path) -> None:
    store_path = tmp_path / "overseer.sqlite3"
    plan_id = "admin.approval.cross-process"
    _stage_approved_restart(store_path, plan_id)
    context = multiprocessing.get_context("fork")
    start = context.Event()
    results = context.Queue()
    processes = [
        context.Process(
            target=_cross_process_execute,
            args=(str(store_path), plan_id, start, results),
        )
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    start.set()
    observed = [results.get(timeout=10) for _ in processes]
    for process in processes:
        process.join(timeout=10)
        assert process.exitcode == 0

    assert sorted(calls for _replayed, calls, _status in observed) == [0, 2]
    assert {replayed for replayed, _calls, _status in observed} == {False, True}
    assert {status for _replayed, _calls, status in observed} == {"completed"}
