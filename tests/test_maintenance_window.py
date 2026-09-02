from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from overseer.maintenance_window import (
    MAINTENANCE_APPROVAL_SCHEMA,
    MAINTENANCE_CONTRACT_SCHEMA,
    MAINTENANCE_RUNNER_STATE_SCHEMA,
    execute_maintenance_contract,
    maintenance_plan_digest,
    _validate_argv,
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
PACKAGE_ROOT = "/var/lib/overseer-executor/approved-package"
ADMIN_SECRET = "admin-secret-must-not-be-persisted"
ROADEX_SECRET = "roadex-secret-must-not-be-persisted"

WRITER_UNIT_BASELINE = [
    {
        "unit": unit,
        "loadState": load_state,
        "activeState": active_state,
        "unitFileState": unit_file_state,
    }
    for unit, load_state, active_state, unit_file_state in (
        ("overseer-psychlo-coordination-tick.timer", "not-found", "inactive", ""),
        ("overseer-psychlo-usage.timer", "loaded", "active", "enabled"),
        ("overseer-quark-scheduler.timer", "loaded", "active", "enabled"),
        ("overseer-codex-usage-snapshot.timer", "loaded", "active", "enabled"),
        ("overseer-psychlo-coordination-tick.service", "not-found", "inactive", ""),
        ("overseer-psychlo-cycle.service", "loaded", "inactive", "static"),
        ("overseer-psychlo-meter.service", "loaded", "inactive", "static"),
        ("overseer-psychlo-usage.service", "loaded", "inactive", "static"),
        ("overseer-quark-scheduler.service", "loaded", "inactive", "static"),
        ("overseer-codex-usage-snapshot.service", "loaded", "inactive", "static"),
        ("overseer-codex-usage-mcp.service", "loaded", "active", "enabled"),
        ("overseer-api.service", "loaded", "active", "enabled"),
        ("overseer.service", "loaded", "active", "enabled"),
    )
]
SUCCESSOR_UNIT_BASELINE = [
    {
        "unit": unit,
        "loadState": "loaded",
        "activeState": "inactive",
        "unitFileState": "disabled",
    }
    for unit in (
        "overseer-api.service",
        "overseer-runtime.service",
        "overseer-admin-executor.socket",
        "overseer-codex-user-bridge.socket",
    )
]


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
        "writerUnitBaseline": [dict(entry) for entry in WRITER_UNIT_BASELINE],
        "successorUnitBaseline": [dict(entry) for entry in SUCCESSOR_UNIT_BASELINE],
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
                    "mode": 384,
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
                    "mode": 384,
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
                    "mode": 384,
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
                    "mode": 420,
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
            "systemCredentialsDirectory": "/etc/overseer",
            "systemAdminSocketUnit": "/etc/systemd/system/overseer-admin-executor.socket",
            "systemAdminServiceUnit": "/etc/systemd/system/overseer-admin-executor@.service",
            "systemApiUnit": "/etc/systemd/system/overseer-api.service",
            "systemUserBridgeServiceUnit": "/etc/systemd/system/overseer-codex-user-bridge.service",
            "systemUserBridgeSocketUnit": "/etc/systemd/system/overseer-codex-user-bridge.socket",
            "systemRuntimeUnit": "/etc/systemd/system/overseer-runtime.service",
            "systemTmpfilesRule": "/etc/tmpfiles.d/overseer.conf",
            "compatibilityApiToken": "/home/god/.local/share/overseer/project/state/api-token",
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
        "earlyRollbackCommands": [
            ["/usr/bin/true", "early-restop"],
            ["/usr/bin/true", "early-restart"],
        ],
        "earlyRollbackTimeoutSeconds": [60, 60],
        "earlyRollbackWindowTimeoutSeconds": 300,
        "earlyRollbackStartIndex": 1,
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


def _execute_placeholder_contract(*args: Any, **kwargs: Any) -> None:
    """Exercise runner mechanics without weakening production validation."""

    with patch(
        "overseer.maintenance_window.validate_maintenance_contract",
        return_value=None,
    ):
        execute_maintenance_contract(*args, **kwargs)


def test_contract_requires_exact_ordered_nonempty_stages_and_rollback_commands() -> None:
    contract = _contract()

    assert [stage["name"] for stage in contract["stages"]] == list(STAGE_NAMES)
    assert all(stage["commands"] for stage in contract["stages"])
    assert contract["rollbackCommands"]
    assert [binding["name"] for binding in contract["storeBindings"]] == [
        "overseer-main",
        "psychlo-bridge",
        "roadex-relay",
    ]
    with pytest.raises(ValueError, match="forbidden executable"):
        validate_maintenance_contract(contract)

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
    empty_stage["stages"][0]["commands"] = []
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
        ["/usr/bin/systemctl", "stop", "unlisted.service"],
        [
            "/usr/sbin/runuser",
            "--user",
            "god",
            "--",
            "/usr/bin/env",
            "XDG_RUNTIME_DIR=/run/user/1000",
            "/usr/bin/systemctl",
            "--user",
            "stop",
            "unlisted.service",
        ],
    ],
)
def test_contract_rejects_forbidden_argv(forbidden_argv: list[str]) -> None:
    contract = _contract()
    contract["stages"][0]["commands"] = [forbidden_argv]

    with pytest.raises(ValueError, match="forbidden"):
        validate_maintenance_contract(contract)


@pytest.mark.parametrize(
    "unsafe_argv",
    [
        ["/tmp/systemctl", "daemon-reload"],
        ["/usr/bin/../bin/systemctl", "daemon-reload"],
        [
            "/usr/bin/install",
            "-o",
            "root",
            "-g",
            "root",
            "-m",
            "0644",
            "/var/lib/overseer-executor/approved-package/public/config/x",
            "/etc/overseer/../sudoers.d/x",
        ],
        [
            "/usr/bin/env",
            "LD_LIBRARY_PATH=/opt/overseer/releases/replacement/lib",
            "PYTHONHOME=/opt/overseer/releases/replacement/runtime",
            "PYTHONPATH=/opt/overseer/releases/replacement/app/src:/opt/overseer/releases/replacement/site-packages",
            "PYTHONDONTWRITEBYTECODE=1",
            "PYTHONNOUSERSITE=1",
            "PYTHONSAFEPATH=1",
            "/opt/overseer/releases/replacement/runtime/bin/python3.13",
            "-X",
            "dev",
            "-B",
            "-s",
            "-P",
            "-m",
            "overseer.activation_package",
            "verify-maintenance-preflight",
            "--package-root",
            PACKAGE_ROOT,
        ],
        [
            "/usr/bin/env",
            "LD_LIBRARY_PATH=/opt/overseer/releases/replacement/lib",
            "PYTHONHOME=/opt/overseer/releases/replacement/runtime",
            "PYTHONPATH=/opt/overseer/releases/replacement/app/src:/opt/overseer/releases/replacement/site-packages",
            "PYTHONDONTWRITEBYTECODE=1",
            "PYTHONNOUSERSITE=1",
            "PYTHONSAFEPATH=1",
            "/opt/overseer/releases/replacement/runtime/bin/python3.13",
            "-B",
            "-s",
            "-P",
            "-m",
            "unexpected.module",
            "verify-maintenance-preflight",
            "--package-root",
            PACKAGE_ROOT,
        ],
        [
            "/usr/bin/env",
            "LD_LIBRARY_PATH=/opt/overseer/releases/replacement/lib",
            "PYTHONHOME=/opt/overseer/releases/replacement/runtime",
            "PYTHONPATH=/opt/overseer/releases/replacement/app/src:/opt/overseer/releases/replacement/site-packages",
            "PYTHONDONTWRITEBYTECODE=1",
            "PYTHONNOUSERSITE=1",
            "PYTHONSAFEPATH=1",
            "/opt/overseer/releases/replacement/runtime/bin/python3.13",
            "-B",
            "-s",
            "-P",
            "-m",
            "overseer.activation_package",
            "-c",
            "print('unexpected')",
        ],
    ],
)
def test_contract_rejects_noncanonical_or_unexpected_command_shapes(
    unsafe_argv: list[str],
) -> None:
    contract = _contract()
    contract["stages"][0]["commands"] = [unsafe_argv]

    with pytest.raises(ValueError):
        validate_maintenance_contract(contract)


def test_contract_rejects_arbitrary_options_after_allowlisted_helper() -> None:
    contract = _contract()
    contract["stages"][0]["commands"] = [[
        "/usr/bin/env",
        "LD_LIBRARY_PATH=/opt/overseer/releases/replacement/lib",
        "PYTHONHOME=/opt/overseer/releases/replacement/runtime",
        "PYTHONPATH=/opt/overseer/releases/replacement/app/src:/opt/overseer/releases/replacement/site-packages",
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTHONNOUSERSITE=1",
        "PYTHONSAFEPATH=1",
        "/opt/overseer/releases/replacement/runtime/bin/python3.13",
        "-B",
        "-s",
        "-P",
        "-m",
        "overseer.activation_package",
        "verify-maintenance-preflight",
        "--package-root",
        PACKAGE_ROOT,
        "--unexpected",
        "value",
    ]]

    with pytest.raises(ValueError):
        validate_maintenance_contract(contract)


def test_argv_accepts_an_allowlisted_release_file_named_for_claim_logic() -> None:
    source = (
        f"{PACKAGE_ROOT}/public/release/replacement/"
        "app/src/overseer/claim_transition.py"
    )
    target = (
        "/opt/overseer/releases/replacement/"
        "app/src/overseer/claim_transition.py"
    )
    argv = [
        "/usr/bin/install",
        "-o",
        "root",
        "-g",
        "root",
        "-m",
        "0444",
        source,
        target,
    ]

    assert _validate_argv(argv, "claim source install", PACKAGE_ROOT) == argv


def test_argv_accepts_a_sealed_rollback_file_with_interior_spaces() -> None:
    digest = "a" * 64
    relative = (
        "v1.1.5-release/docs/"
        "overseer-pending-approval-gates-executive-summary - completed.md"
    )
    argv = [
        "/usr/bin/install",
        "-o",
        "root",
        "-g",
        "god",
        "-m",
        "0440",
        f"{PACKAGE_ROOT}/private/rollback-inputs/{relative}",
        f"/opt/overseer/rollback/{digest}/{relative}",
    ]

    assert _validate_argv(argv, "rollback install", PACKAGE_ROOT) == argv


@pytest.mark.parametrize("unsafe_name", (" leading.md", "trailing.md ", "tab\tname.md"))
def test_argv_rejects_unsafe_whitespace_in_rollback_names(unsafe_name: str) -> None:
    digest = "a" * 64
    relative = f"v1.1.5-release/docs/{unsafe_name}"
    argv = [
        "/usr/bin/install",
        "-o",
        "root",
        "-g",
        "god",
        "-m",
        "0440",
        f"{PACKAGE_ROOT}/private/rollback-inputs/{relative}",
        f"/opt/overseer/rollback/{digest}/{relative}",
    ]

    with pytest.raises(ValueError, match="rollback|install"):
        _validate_argv(argv, "rollback install", PACKAGE_ROOT)


def test_contract_rejects_removed_prepare_final_store_helper() -> None:
    contract = _contract()
    contract["stages"][0]["commands"] = [[
        "/usr/bin/env",
        "LD_LIBRARY_PATH=/opt/overseer/releases/replacement/lib",
        "PYTHONHOME=/opt/overseer/releases/replacement/runtime",
        "PYTHONPATH=/opt/overseer/releases/replacement/app/src:/opt/overseer/releases/replacement/site-packages",
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTHONNOUSERSITE=1",
        "PYTHONSAFEPATH=1",
        "/opt/overseer/releases/replacement/runtime/bin/python3.13",
        "-B", "-s", "-P", "-m", "overseer.activation_package",
        "prepare-final-store", "--package-root", PACKAGE_ROOT,
    ]]

    with pytest.raises(ValueError):
        validate_maintenance_contract(contract)


def test_contract_rejects_allowed_handoff_install_moved_to_preflight() -> None:
    contract = _contract()
    contract["stages"][0]["commands"] = [[
        "/usr/bin/install", "-o", "root", "-g", "root", "-m", "0644",
        f"{PACKAGE_ROOT}/public/systemd/overseer-api.service",
        "/etc/systemd/system/overseer-api.service",
    ]]

    with pytest.raises(ValueError, match="preflight|stage|profile"):
        validate_maintenance_contract(contract)


def test_contract_accepts_rendered_python_install_and_systemctl_shapes() -> None:
    commands = [
        [
            "/usr/bin/env",
            "LD_LIBRARY_PATH=/opt/overseer/releases/replacement/lib",
            "PYTHONHOME=/opt/overseer/releases/replacement/runtime",
            "PYTHONPATH=/opt/overseer/releases/replacement/app/src:/opt/overseer/releases/replacement/site-packages",
            "PYTHONDONTWRITEBYTECODE=1",
            "PYTHONNOUSERSITE=1",
            "PYTHONSAFEPATH=1",
            "/opt/overseer/releases/replacement/runtime/bin/python3.13",
            "-B",
            "-s",
            "-P",
            "-m",
            "overseer.activation_package",
            "verify-maintenance-preflight",
            "--package-root",
            PACKAGE_ROOT,
        ],
        [
            "/usr/bin/install",
            "-d",
            "-o",
            "root",
            "-g",
            "root",
            "-m",
            "0755",
            "/opt/overseer/releases",
        ],
        [
            "/usr/bin/install",
            "-o",
            "root",
            "-g",
            "root",
            "-m",
            "0644",
            f"{PACKAGE_ROOT}/public/systemd/overseer-api.service",
            "/etc/systemd/system/overseer-api.service",
        ],
        ["/usr/bin/systemctl", "daemon-reload"],
        [
            "/usr/sbin/runuser",
            "--user",
            "god",
            "--",
            "/usr/bin/env",
            "XDG_RUNTIME_DIR=/run/user/1000",
            "/usr/bin/systemctl",
            "--user",
            "start",
            "overseer-quark-scheduler.timer",
            "overseer-codex-usage-mcp.service",
            "overseer-codex-usage-snapshot.timer",
        ],
    ]

    for index, command in enumerate(commands):
        assert _validate_argv(command, f"command[{index}]") == command


def test_contract_rejects_embedded_secret_values() -> None:
    contract = _contract()
    contract["runtimeSecrets"] = {
        "adminApprovalSecret": ADMIN_SECRET,
        "roadexFixtureApprovalSecret": ROADEX_SECRET,
    }

    with pytest.raises(ValueError, match="secret"):
        validate_maintenance_contract(contract)


def test_contract_rejects_writer_unit_baseline_drift() -> None:
    unknown = _contract()
    unknown["writerUnitBaseline"][0]["unit"] = "unlisted.service"
    with pytest.raises(ValueError, match="writer unit baseline"):
        validate_maintenance_contract(unknown)

    duplicate = _contract()
    duplicate["writerUnitBaseline"][1]["unit"] = duplicate[
        "writerUnitBaseline"
    ][0]["unit"]
    with pytest.raises(ValueError, match="writer unit baseline"):
        validate_maintenance_contract(duplicate)

    transient = _contract()
    transient["writerUnitBaseline"][1]["activeState"] = "activating"
    with pytest.raises(ValueError, match="writer unit baseline"):
        validate_maintenance_contract(transient)

    missing = _contract()
    del missing["writerUnitBaseline"]
    with pytest.raises(ValueError, match="writerUnitBaseline"):
        validate_maintenance_contract(missing)


def test_contract_rejects_successor_unit_baseline_drift() -> None:
    wrong_state = _contract()
    wrong_state["successorUnitBaseline"][0]["activeState"] = "active"
    with pytest.raises(ValueError, match="successor unit baseline"):
        validate_maintenance_contract(wrong_state)

    unknown = _contract()
    unknown["successorUnitBaseline"][0]["unit"] = "unlisted.service"
    with pytest.raises(ValueError, match="successor unit baseline"):
        validate_maintenance_contract(unknown)


def test_contract_rejects_store_destination_drift() -> None:
    contract = _contract()
    contract["storeBindings"][0]["destinationDb"] = (
        "/var/lib/overseer/unsealed.sqlite3"
    )

    with pytest.raises(ValueError, match="store destination"):
        validate_maintenance_contract(contract)


def test_contract_rejects_store_source_mode_drift() -> None:
    migrated = _contract()
    migrated["storeBindings"][0]["sourceIdentity"]["mode"] = 0o644
    with pytest.raises(ValueError, match="migrated store source mode"):
        validate_maintenance_contract(migrated)

    deferred = _contract()
    deferred["deferredStoreBindings"][0]["sourceIdentity"]["mode"] = 0o666
    with pytest.raises(ValueError, match="deferred store source mode"):
        validate_maintenance_contract(deferred)


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
    with patch(
        "overseer.maintenance_window.validate_maintenance_contract",
        return_value=None,
    ):
        digest = maintenance_plan_digest(contract)

        assert isinstance(digest, str)
        assert len(digest) == 64
        assert digest == maintenance_plan_digest(json.loads(json.dumps(contract)))

        changed = json.loads(json.dumps(contract))
        changed["stages"][3]["commands"][0].append("replacement")
        assert maintenance_plan_digest(changed) != digest


def test_writer_stop_failure_runs_only_the_early_recovery_profile() -> None:
    calls: list[tuple[str, ...]] = []
    states: list[dict[str, Any]] = []

    def execute(argv: list[str], _timeout_seconds: int) -> None:
        calls.append(tuple(argv))
        if argv[1] == "stopWriters":
            raise RuntimeError("stop writers failed")

    with pytest.raises(RuntimeError, match="stop writers failed"):
        _execute_placeholder_contract(
            _contract(),
            PACKAGE_DIGEST,
            execute,
            states.append,
        )

    assert calls == [
        ("/usr/bin/true", "preflight"),
        ("/usr/bin/true", "stopWriters"),
        ("/usr/bin/true", "early-restop"),
        ("/usr/bin/true", "early-restart"),
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
        _execute_placeholder_contract(
            contract,
            PACKAGE_DIGEST,
            execute,
            states.append,
        )

    assert calls[-1] == (
        "/usr/bin/true",
        "early-restart" if failing_stage == "proveQuiescence" else "rollback-restart",
    )
    assert states[-1]["schemaVersion"] == MAINTENANCE_RUNNER_STATE_SCHEMA
    assert states[-1]["status"] == "rolled_back"


def test_success_records_complete() -> None:
    states: list[dict[str, Any]] = []

    _execute_placeholder_contract(
        _contract(),
        PACKAGE_DIGEST,
        lambda _argv, _timeout_seconds: None,
        states.append,
    )

    assert states[-1]["schemaVersion"] == MAINTENANCE_RUNNER_STATE_SCHEMA
    assert states[-1]["status"] == "complete"


def test_runner_checkpoints_bind_each_command_digest_and_writer_state() -> None:
    states: list[dict[str, Any]] = []

    _execute_placeholder_contract(
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
    stop_before = next(
        state
        for state in states
        if state.get("stage") == "stopWriters"
        and state.get("status") == "writer_stop_in_progress"
    )
    assert stop_before["writersStopped"] is True
    assert states[-1]["writersStopped"] is True


def test_runner_state_never_contains_secret_values() -> None:
    states: list[dict[str, Any]] = []

    _execute_placeholder_contract(
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
        _execute_placeholder_contract(
            contract,
            PACKAGE_DIGEST,
            execute,
            states.append,
        )

    assert ("/usr/bin/true", "rollback-restart") not in calls
    assert states[-1]["status"] == "rollback_failed"


def test_global_window_deadline_exits_without_touching_writers() -> None:
    calls: list[tuple[str, ...]] = []
    states: list[dict[str, Any]] = []
    moments = iter((0.0, 1.0, 5400.0))

    with pytest.raises(TimeoutError, match="sealed deadline"):
        _execute_placeholder_contract(
            _contract(),
            PACKAGE_DIGEST,
            lambda argv, _timeout: calls.append(tuple(argv)),
            states.append,
            monotonic=lambda: next(moments),
        )

    assert calls == [("/usr/bin/true", "preflight")]
    assert states[-1]["status"] == "failed_before_stopWriters"
    assert states[-1]["writersStopped"] is False
