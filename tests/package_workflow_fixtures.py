from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from overseer.admin import AdminCommandResult, AdminCommandStep
from overseer.admin import AdminExecutionResult, AdminExecutionStatus
from overseer.packages import PackageInspectionSnapshot, PackageUpdate
from overseer.store import SQLiteStore


class StaticPackageInspector:
    def __init__(self, snapshot: PackageInspectionSnapshot) -> None:
        self.snapshot = snapshot
        self.calls = 0

    def inspect(self, captured_at: str | None = None) -> PackageInspectionSnapshot:
        self.calls += 1
        return replace(self.snapshot, captured_at=captured_at or self.snapshot.captured_at)


class RecordingRunner:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []

    def __call__(self, step: AdminCommandStep) -> AdminCommandResult:
        self.commands.append(step.command)
        return AdminCommandResult(step.title, step.command, 0, "ok", "")


def bash_update(version: str = "5.2") -> PackageUpdate:
    return PackageUpdate(
        name="bash",
        repository="stable",
        candidate_version=version,
        architecture="amd64",
        installed_version="5.1",
    )


def package_snapshot(captured_at: str, *updates: PackageUpdate) -> PackageInspectionSnapshot:
    return PackageInspectionSnapshot(
        id=f"package-inspection.{captured_at}",
        captured_at=captured_at,
        command=("apt", "list", "--upgradable"),
        exit_code=0,
        updates=tuple(updates),
        stderr="",
    )


def initialized_store(tmp_path: Path) -> SQLiteStore:
    store = SQLiteStore(tmp_path / "overseer.sqlite3")
    store.initialize()
    return store


def blocked_execution(plan_id: str) -> AdminExecutionResult:
    return AdminExecutionResult(
        id=f"execution.{plan_id}",
        plan_id=plan_id,
        status=AdminExecutionStatus.BLOCKED,
        summary="blocked by policy",
        command_results=(),
    )
