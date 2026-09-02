from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from overseer.maintenance_window import (
    MAINTENANCE_APPROVAL_SCHEMA,
    MAINTENANCE_CONTRACT_SCHEMA,
    MAINTENANCE_RUNNER_STATE_SCHEMA,
    execute_maintenance_contract,
    maintenance_plan_digest,
    validate_maintenance_approval,
    validate_maintenance_contract,
)


STAGE_NAMES = (
    "preflight",
    "stopWriters",
    "proveQuiescence",
    "preserveState",
    "installRelease",
    "migrateOfflineStores",
    "switchServices",
    "acceptance",
)
PACKAGE_DIGEST = "a" * 64
PLAN_DIGEST = "b" * 64
PACKAGE_ROOT = "/opt/overseer/releases/replacement"
ADMIN_SECRET = "admin-secret-must-not-be-persisted"
ROADEX_SECRET = "roadex-secret-must-not-be-persisted"


def _contract() -> dict[str, Any]:
    return {
        "schemaVersion": MAINTENANCE_CONTRACT_SCHEMA,
        "packageRoot": PACKAGE_ROOT,
        "releaseManifestDigest": "e" * 64,
        "account": {
            "user": "overseer",
            "uid": 984,
            "group": "overseer",
            "gid": 984,
        },
        "scope": "maintenance-window-for-this-package-only",
        "storeBindings": [
            {
                "name": "overseer-main",
                "sourceDb": "/srv/overseer/overseer.sqlite3",
                "backupDb": "/var/lib/overseer-executor/maintenance/overseer.sqlite3",
                "destinationDb": "/var/lib/overseer/overseer.sqlite3",
                "storeKind": "overseer",
                "sourceIdentity": {
                    "device": 1,
                    "inode": 11,
                    "uid": 1000,
                    "gid": 1000,
                    "parentDevice": 1,
                    "parentInode": 10,
                    "parentMode": 448,
                },
            },
            {
                "name": "psychlo-bridge",
                "sourceDb": "/srv/overseer/psychlo.sqlite3",
                "backupDb": "/var/lib/overseer-executor/maintenance/psychlo.sqlite3",
                "destinationDb": "/var/lib/overseer/psychlo-bridge.sqlite3",
                "storeKind": "copy-only",
                "sourceIdentity": {
                    "device": 1,
                    "inode": 21,
                    "uid": 1000,
                    "gid": 1000,
                    "parentDevice": 1,
                    "parentInode": 20,
                    "parentMode": 448,
                },
            },
            {
                "name": "roadex-relay",
                "sourceDb": "/srv/overseer/roadex.sqlite3",
                "backupDb": "/var/lib/overseer-executor/maintenance/roadex.sqlite3",
                "destinationDb": "/var/lib/overseer/roadex-relay.sqlite3",
                "storeKind": "copy-only",
                "sourceIdentity": {
                    "device": 1,
                    "inode": 31,
                    "uid": 1000,
                    "gid": 1000,
                    "parentDevice": 1,
                    "parentInode": 30,
                    "parentMode": 448,
                },
            },
        ],
        "deferredStoreBindings": [
            {
                "name": "codex-usage",
                "sourceDb": "/srv/overseer/codex-usage.sqlite3",
                "policy": "preserve-and-resume-unchanged",
                "sourceIdentity": {
                    "device": 1,
                    "inode": 41,
                    "uid": 1000,
                    "gid": 1000,
                    "parentDevice": 1,
                    "parentInode": 40,
                    "parentMode": 448,
                },
            }
        ],
        "preservationInputs": {
            "currentRelease": "/opt/overseer/releases/current",
            "credentialsDirectory": "/etc/overseer",
            "userUnitsRuntimeEnv": "/home/god/.config/overseer/runtime.env",
            "rollbackBundle": "/opt/overseer/rollback/current",
            "userRuntimeUnit": "/home/god/.config/systemd/user/overseer.service",
            "userApiUnit": "/home/god/.config/systemd/user/overseer-api.service",
            "psychloCycleUnit": "/home/god/.config/systemd/user/overseer-psychlo-cycle.service",
            "psychloMeterUnit": "/home/god/.config/systemd/user/overseer-psychlo-meter.service",
            "psychloUsageUnit": "/home/god/.config/systemd/user/overseer-psychlo-usage.service",
            "psychloUsageTimer": "/home/god/.config/systemd/user/overseer-psychlo-usage.timer",
            "quarkSchedulerUnit": "/home/god/.config/systemd/user/overseer-quark-scheduler.service",
            "quarkSchedulerTimer": "/home/god/.config/systemd/user/overseer-quark-scheduler.timer",
            "codexUsageMcpUnit": "/home/god/.config/systemd/user/overseer-codex-usage-mcp.service",
            "codexUsageSnapshotUnit": "/home/god/.config/systemd/user/overseer-codex-usage-snapshot.service",
            "codexUsageSnapshotTimer": "/home/god/.config/systemd/user/overseer-codex-usage-snapshot.timer",
        },
        "evidenceRoot": "/var/lib/overseer-executor/maintenance/preserved",
        "acceptanceChecks": [
            "api",
            "authenticated-ui-data",
            "scheduler-freshness",
            "protected-gateway-read",
            "psychlo-read",
            "roadex-read",
            "credentials",
            "single-writer-inventory",
        ],
        "stages": [
            {
                "name": name,
                "commands": [["/usr/bin/true", name]],
            }
            for name in STAGE_NAMES
        ],
        "stageTimeoutSeconds": {name: 60 for name in STAGE_NAMES},
        "windowTimeoutSeconds": 5400,
        "rollbackCommands": [
            ["/usr/bin/true", "rollback-cleanup"],
            ["/usr/bin/true", "rollback-restart"],
        ],
        "rollbackTimeoutSeconds": [60, 60],
        "rollbackWindowTimeoutSeconds": 1800,
        "rollbackStartIndex": 1,
        "secretInputs": [
            "admin-approval-terminal",
            "roadex-fixture-approval-terminal",
        ],
    }


def _approval(*, allow_reboot: bool = False) -> dict[str, Any]:
    return {
        "schemaVersion": MAINTENANCE_APPROVAL_SCHEMA,
        "scope": "maintenance-window-for-this-package-only",
        "packageRoot": PACKAGE_ROOT,
        "packageDigest": PACKAGE_DIGEST,
        "planDigest": PLAN_DIGEST,
        "allowReboot": allow_reboot,
    }


def test_contract_requires_exact_ordered_nonempty_stages_and_rollback_commands() -> None:
    contract = _contract()

    assert validate_maintenance_contract(contract) is None

    assert [stage["name"] for stage in contract["stages"]] == list(STAGE_NAMES)
    assert all(stage["commands"] for stage in contract["stages"])
    assert contract["rollbackCommands"]
    assert [binding["name"] for binding in contract["storeBindings"]] == [
        "overseer-main",
        "psychlo-bridge",
        "roadex-relay",
    ]

    for index, name in enumerate(STAGE_NAMES):
        missing = _contract()
        missing["stages"] = [
            stage for stage in missing["stages"] if stage["name"] != name
        ]
        with pytest.raises(ValueError, match=name):
            validate_maintenance_contract(missing)

    reordered = _contract()
    reordered["stages"] = list(reversed(reordered["stages"]))
    with pytest.raises(ValueError, match="order"):
        validate_maintenance_contract(reordered)

    empty_stage = _contract()
    empty_stage["stages"][2]["commands"] = []
    with pytest.raises(ValueError, match="non-empty"):
        validate_maintenance_contract(empty_stage)

    without_rollback = _contract()
    del without_rollback["rollbackCommands"]
    with pytest.raises(ValueError, match="rollbackCommands"):
        validate_maintenance_contract(without_rollback)


@pytest.mark.parametrize(
    "forbidden_argv",
    [
        ["/bin/sh", "-c", "true"],
        ["/bin/bash", "-lc", "true"],
        ["/usr/bin/env", "bash", "-c", "true"],
        ["/usr/bin/virsh", "start", "overseer"],
        ["/usr/bin/qemu-system-x86_64", "-no-reboot"],
        ["/usr/bin/overseer", "claim", "continue"],
        ["/usr/bin/overseer", "claim", "activate"],
        ["/usr/sbin/nft", "list", "ruleset"],
        ["/usr/sbin/iptables", "-L"],
        ["/usr/bin/firewall-cmd", "--state"],
        ["/usr/bin/overseer", "execute-approved-staging-canary"],
        ["/usr/bin/overseer", "execute-approved-cutover"],
        ["/usr/bin/systemctl", "reboot"],
        ["/usr/bin/systemctl", "poweroff"],
    ],
)
def test_contract_rejects_forbidden_argv(forbidden_argv: list[str]) -> None:
    contract = _contract()
    contract["stages"][0]["commands"] = [forbidden_argv]

    with pytest.raises(ValueError, match="forbidden"):
        validate_maintenance_contract(contract)


def test_contract_rejects_embedded_secret_values() -> None:
    contract = _contract()
    contract["runtimeSecrets"] = {
        "adminApprovalSecret": ADMIN_SECRET,
        "roadexFixtureApprovalSecret": ROADEX_SECRET,
    }

    with pytest.raises(ValueError, match="secret"):
        validate_maintenance_contract(contract)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("scope", "admin-plan-approval"),
        ("packageRoot", "/opt/overseer/releases/other"),
        ("packageDigest", "c" * 64),
        ("planDigest", "d" * 64),
        ("allowReboot", True),
    ],
)
def test_approval_is_bound_to_one_package_plan_scope_and_reboot_policy(
    field: str,
    value: Any,
) -> None:
    document = _approval()
    document[field] = value

    with pytest.raises(ValueError):
        validate_maintenance_approval(
            document,
            PACKAGE_ROOT,
            PACKAGE_DIGEST,
            PLAN_DIGEST,
            False,
        )


def test_approval_accepts_exact_binding_and_rejects_schema_mismatch() -> None:
    assert (
        validate_maintenance_approval(
            _approval(),
            PACKAGE_ROOT,
            PACKAGE_DIGEST,
            PLAN_DIGEST,
            False,
        )
        is None
    )

    bad_schema = _approval()
    bad_schema["schemaVersion"] = "overseer.cutover-approval.v1"
    with pytest.raises(ValueError, match="schema"):
        validate_maintenance_approval(
            bad_schema,
            PACKAGE_ROOT,
            PACKAGE_DIGEST,
            PLAN_DIGEST,
            False,
        )


def test_plan_digest_is_stable_and_changes_when_contract_changes() -> None:
    contract = _contract()
    digest = maintenance_plan_digest(contract)

    assert isinstance(digest, str)
    assert len(digest) == 64
    assert digest == maintenance_plan_digest(json.loads(json.dumps(contract)))

    changed = json.loads(json.dumps(contract))
    changed["stages"][3]["commands"][0].append("replacement")
    assert maintenance_plan_digest(changed) != digest


def test_failure_before_writers_stop_does_not_run_rollback() -> None:
    calls: list[tuple[str, ...]] = []
    states: list[dict[str, Any]] = []

    def execute(argv: list[str], _timeout_seconds: int) -> None:
        calls.append(tuple(argv))
        if argv[1] == "stopWriters":
            raise RuntimeError("stop writers failed")

    with pytest.raises(RuntimeError, match="stop writers failed"):
        execute_maintenance_contract(
            _contract(),
            PACKAGE_DIGEST,
            execute,
            states.append,
        )

    assert calls == [
        ("/usr/bin/true", "preflight"),
        ("/usr/bin/true", "stopWriters"),
    ]
    assert all("rollback" not in call[1] for call in calls)


@pytest.mark.parametrize("failing_stage", ["proveQuiescence", "acceptance"])
def test_failure_after_writers_stop_runs_rollback_and_records_rolled_back(
    failing_stage: str,
) -> None:
    contract = _contract()
    calls: list[tuple[str, ...]] = []
    states: list[dict[str, Any]] = []

    def execute(argv: list[str], _timeout_seconds: int) -> None:
        calls.append(tuple(argv))
        if argv[1] == failing_stage:
            raise RuntimeError(f"{failing_stage} failed")

    with pytest.raises(RuntimeError, match=failing_stage):
        execute_maintenance_contract(
            contract,
            PACKAGE_DIGEST,
            execute,
            states.append,
        )

    assert calls[-1] == ("/usr/bin/true", "rollback-restart")
    assert states[-1]["schemaVersion"] == MAINTENANCE_RUNNER_STATE_SCHEMA
    assert states[-1]["status"] == "rolled_back"


def test_success_records_complete() -> None:
    states: list[dict[str, Any]] = []

    execute_maintenance_contract(
        _contract(),
        PACKAGE_DIGEST,
        lambda _argv, _timeout_seconds: None,
        states.append,
    )

    assert states[-1]["schemaVersion"] == MAINTENANCE_RUNNER_STATE_SCHEMA
    assert states[-1]["status"] == "complete"


def test_runner_checkpoints_bind_each_command_digest_and_writer_state() -> None:
    states: list[dict[str, Any]] = []

    execute_maintenance_contract(
        _contract(),
        PACKAGE_DIGEST,
        lambda _argv, _timeout_seconds: None,
        states.append,
    )

    command_states = [state for state in states if "commandIndex" in state]
    assert command_states
    assert all(
        isinstance(state.get("commandDigest"), str)
        and len(str(state["commandDigest"])) == 64
        for state in command_states
    )
    stop_after = next(
        state
        for state in states
        if state.get("stage") == "stopWriters"
        and state.get("status") == "after_command"
    )
    assert stop_after["writersStopped"] is True
    assert states[-1]["writersStopped"] is True


def test_runner_state_never_contains_secret_values() -> None:
    states: list[dict[str, Any]] = []

    execute_maintenance_contract(
        _contract(),
        PACKAGE_DIGEST,
        lambda _argv, _timeout_seconds: None,
        states.append,
    )

    serialized_states = json.dumps(states, sort_keys=True)
    assert ADMIN_SECRET not in serialized_states
    assert ROADEX_SECRET not in serialized_states


def test_rollback_never_restarts_legacy_units_after_prerequisite_failure() -> None:
    contract = _contract()
    calls: list[tuple[str, ...]] = []
    states: list[dict[str, Any]] = []

    def execute(argv: list[str], _timeout_seconds: int) -> None:
        calls.append(tuple(argv))
        if argv[1] == "acceptance":
            raise RuntimeError("acceptance failed")
        if argv[1] == "rollback-cleanup":
            raise RuntimeError("rollback prerequisite failed")

    with pytest.raises(RuntimeError, match="rollback prerequisite failed"):
        execute_maintenance_contract(
            contract,
            PACKAGE_DIGEST,
            execute,
            states.append,
        )

    assert ("/usr/bin/true", "rollback-restart") not in calls
    assert states[-1]["status"] == "rollback_failed"


def test_global_window_deadline_stops_before_writer_shutdown() -> None:
    calls: list[tuple[str, ...]] = []
    states: list[dict[str, Any]] = []
    moments = iter((0.0, 1.0, 5400.0))

    with pytest.raises(TimeoutError, match="sealed deadline"):
        execute_maintenance_contract(
            _contract(),
            PACKAGE_DIGEST,
            lambda argv, _timeout: calls.append(tuple(argv)),
            states.append,
            monotonic=lambda: next(moments),
        )

    assert calls == [("/usr/bin/true", "preflight")]
    assert states[-1]["status"] == "failed_before_stopWriters"
