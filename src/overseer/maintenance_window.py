"""Pure, fail-closed primitives for the bounded maintenance-window runner.

This module deliberately has no operating-system, filesystem, network, or
service dependencies.  The eventual runner may provide those capabilities
through explicitly injected, already-sealed callables; this first slice only
validates the contract and models the checkpointed execution protocol.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any


MAINTENANCE_APPROVAL_SCHEMA = "overseer.maintenance-window-approval.v1"
MAINTENANCE_CONTRACT_SCHEMA = "overseer.maintenance-window-contract.v1"
MAINTENANCE_RUNNER_STATE_SCHEMA = "overseer.maintenance-window-runner-state.v1"

_EXPECTED_SCOPE = "maintenance-window-for-this-package-only"
MAINTENANCE_WRITER_UNITS = (
    "overseer-psychlo-coordination-tick.timer",
    "overseer-psychlo-usage.timer",
    "overseer-quark-scheduler.timer",
    "overseer-codex-usage-snapshot.timer",
    "overseer-psychlo-coordination-tick.service",
    "overseer-psychlo-cycle.service",
    "overseer-psychlo-meter.service",
    "overseer-psychlo-usage.service",
    "overseer-quark-scheduler.service",
    "overseer-codex-usage-snapshot.service",
    "overseer-codex-usage-mcp.service",
    "overseer-api.service",
    "overseer.service",
)
MAINTENANCE_EXPECTED_ACTIVE_UNITS = (
    "overseer.service",
    "overseer-api.service",
    "overseer-psychlo-usage.timer",
    "overseer-quark-scheduler.timer",
    "overseer-codex-usage-mcp.service",
    "overseer-codex-usage-snapshot.timer",
)
MAINTENANCE_SUCCESSOR_SYSTEM_UNITS = (
    "overseer-api.service",
    "overseer-runtime.service",
    "overseer-admin-executor.socket",
    "overseer-codex-user-bridge.socket",
)
_OPTIONAL_ABSENT_WRITER_UNITS = {
    "overseer-psychlo-coordination-tick.timer",
    "overseer-psychlo-coordination-tick.service",
}
_SYSTEM_SERVICE_UNITS = set(MAINTENANCE_SUCCESSOR_SYSTEM_UNITS)
_STAGE_NAMES = (
    "preflight",
    "stopWriters",
    "proveQuiescence",
    "preserveState",
    "installRelease",
    "migrateOfflineStores",
    "switchServices",
    "acceptance",
)
_CONTRACT_FIELDS = {
    "schemaVersion",
    "packageRoot",
    "releaseManifestDigest",
    "account",
    "scope",
    "writerUnitBaseline",
    "successorUnitBaseline",
    "storeBindings",
    "deferredStoreBindings",
    "preservationInputs",
    "evidenceRoot",
    "acceptanceChecks",
    "stages",
    "stageTimeoutSeconds",
    "windowTimeoutSeconds",
    "earlyRollbackCommands",
    "earlyRollbackTimeoutSeconds",
    "earlyRollbackWindowTimeoutSeconds",
    "earlyRollbackStartIndex",
    "rollbackCommands",
    "rollbackTimeoutSeconds",
    "rollbackWindowTimeoutSeconds",
    "rollbackStartIndex",
    "secretInputs",
}
_STAGE_FIELDS = {"name", "commands"}
_APPROVAL_FIELDS = {
    "schemaVersion",
    "scope",
    "packageRoot",
    "packageDigest",
    "planDigest",
    "allowReboot",
}
_HEX_DIGEST_LENGTH = 64
_PRESERVATION_INPUT_NAMES = {
    "currentRelease",
    "credentialsDirectory",
    "userUnitsRuntimeEnv",
    "rollbackBundle",
    "userRuntimeUnit",
    "userApiUnit",
    "psychloCycleUnit",
    "psychloMeterUnit",
    "psychloUsageUnit",
    "psychloUsageTimer",
    "quarkSchedulerUnit",
    "quarkSchedulerTimer",
    "codexUsageMcpUnit",
    "codexUsageSnapshotUnit",
    "codexUsageSnapshotTimer",
    "systemCredentialsDirectory",
    "systemAdminSocketUnit",
    "systemAdminServiceUnit",
    "systemApiUnit",
    "systemUserBridgeServiceUnit",
    "systemUserBridgeSocketUnit",
    "systemRuntimeUnit",
    "systemTmpfilesRule",
}

_SHELL_NAMES = {
    "ash",
    "bash",
    "csh",
    "dash",
    "fish",
    "ksh",
    "rbash",
    "sh",
    "tcsh",
    "zsh",
}
_VIRTUALIZATION_NAMES = {
    "virsh",
    "qemu-img",
    "qemu-system-aarch64",
    "qemu-system-arm",
    "qemu-system-i386",
    "qemu-system-riscv32",
    "qemu-system-riscv64",
    "qemu-system-x86_64",
    "qemu-system-x86_64-spice",
    "virt-install",
    "virt-manager",
    "vboxmanage",
}
_NETWORK_NAMES = {
    "firewall-cmd",
    "ip",
    "ip6tables",
    "iptables",
    "nft",
    "nmcli",
    "pfctl",
    "route",
    "tailscale",
    "ufw",
    "wg",
}
_REBOOT_NAMES = {"halt", "kexec", "poweroff", "reboot", "shutdown"}
_ALLOWED_EXECUTABLE_NAMES = {
    "curl",
    "chmod",
    "env",
    "install",
    "runuser",
    "systemctl",
    "systemd-tmpfiles",
    "true",
}
_ALLOWED_SYSTEMCTL_ACTIONS = {
    "daemon-reload",
    "disable",
    "enable",
    "start",
    "stop",
}
_SECRET_KEY_MARKERS = (
    "credential",
    "password",
    "secret",
    "token",
    "privatekey",
    "private_key",
)


def _fail(message: str) -> None:
    raise ValueError(message)


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{label} must be an object")
    return value


def _require_exact_fields(
    value: Mapping[str, Any], expected: set[str], label: str
) -> None:
    unexpected = set(value) - expected
    missing = expected - set(value)
    if unexpected:
        _fail(f"{label} has unexpected fields: {sorted(unexpected)}")
    if missing:
        _fail(f"{label} is missing fields: {sorted(missing)}")


def _require_absolute_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or not value.startswith("/"):
        _fail(f"{label} must be a nonempty absolute path")
    if "\x00" in value:
        _fail(f"{label} contains a NUL")
    return value


def _require_digest(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != _HEX_DIGEST_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _fail(f"{label} must be a lowercase SHA-256 digest")
    return value


def _key_is_secret_bearing(key: Any) -> bool:
    if not isinstance(key, str):
        return True
    normalized = key.replace("-", "").replace(" ", "").lower()
    return any(marker in normalized for marker in _SECRET_KEY_MARKERS)


def _reject_secret_bearing_fields(value: Any, *, path: str = "contract") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if key == "preservationInputs":
                continue
            if _key_is_secret_bearing(key) and key != "secretInputs":
                _fail(f"{path}.{key} is a secret-bearing field")
            _reject_secret_bearing_fields(child, path=f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            _reject_secret_bearing_fields(child, path=f"{path}[{index}]")


def _executable_name(argv0: str) -> str:
    return posixpath.basename(argv0).lower()


def _validate_argv(argv: Any, label: str) -> list[str]:
    if not isinstance(argv, Sequence) or isinstance(argv, (str, bytes, bytearray)):
        _fail(f"{label} must be a nonempty argv")
    if not argv:
        _fail(f"{label} must be a nonempty argv")
    if any(not isinstance(argument, str) or not argument or "\x00" in argument for argument in argv):
        _fail(f"{label} contains an empty or invalid argv element")
    if not argv[0].startswith("/"):
        _fail(f"{label} executable must be an absolute path")

    names = [_executable_name(argument) for argument in argv]
    first_name = names[0]
    if first_name not in _ALLOWED_EXECUTABLE_NAMES:
        _fail(f"{label} contains a forbidden executable")
    if first_name in _SHELL_NAMES or first_name == "env":
        if first_name in _SHELL_NAMES:
            _fail(f"{label} contains a forbidden shell interpreter")
        # env may carry assignments and options, so inspect every subsequent
        # token for a shell executable rather than trusting argv position.
        if any(name in _SHELL_NAMES for name in names[1:]):
            _fail(f"{label} contains a forbidden env-wrapped shell interpreter")

    forbidden_names = _VIRTUALIZATION_NAMES | _NETWORK_NAMES | _REBOOT_NAMES
    if any(name in forbidden_names for name in names):
        _fail(f"{label} contains a forbidden command")

    lowered = [argument.lower() for argument in argv]
    if any("claim" in argument or "claims" in argument for argument in lowered):
        _fail(f"{label} contains a forbidden claims command")
    if any(
        marker in argument
        for argument in lowered
        for marker in ("staging-canary", "approved-staging", "cutover")
    ):
        _fail(f"{label} contains a forbidden legacy staging/cutover runner")
    if any(
        marker in argument
        for argument in lowered
        for marker in ("--reboot", "--poweroff", "systemctl-reboot")
    ):
        _fail(f"{label} contains a forbidden reboot command")
    if "systemctl" in names and any(
        argument in _REBOOT_NAMES for argument in lowered
    ):
        _fail(f"{label} contains a forbidden systemctl power command")
    if first_name == "env" and not (
        "-m" in argv and "overseer.activation_package" in argv
    ):
        _fail(f"{label} contains a forbidden env payload")
    if first_name == "runuser" and not (
        len(argv) >= 8
        and argv[1:4] == ["--user", "god", "--"]
        and "/usr/bin/systemctl" in argv
        and "--user" in argv
    ):
        _fail(f"{label} contains a forbidden runuser payload")
    if "systemctl" in names:
        systemctl_index = names.index("systemctl")
        systemctl_tail = argv[systemctl_index + 1 :]
        action_offset = next(
            (
                index
                for index, argument in enumerate(systemctl_tail)
                if not argument.startswith("-")
            ),
            None,
        )
        action = (
            None if action_offset is None else systemctl_tail[action_offset]
        )
        if action not in _ALLOWED_SYSTEMCTL_ACTIONS:
            _fail(f"{label} contains a forbidden systemctl action")
        prefix_options = systemctl_tail[:action_offset]
        trailing = systemctl_tail[action_offset + 1 :]
        if first_name == "runuser":
            if prefix_options != ["--user"]:
                _fail(f"{label} contains forbidden systemctl options")
            allowed_units = set(MAINTENANCE_WRITER_UNITS)
        else:
            if prefix_options:
                _fail(f"{label} contains forbidden systemctl options")
            allowed_units = _SYSTEM_SERVICE_UNITS
        trailing_options = [argument for argument in trailing if argument.startswith("-")]
        units = [argument for argument in trailing if not argument.startswith("-")]
        if any(option != "--now" for option in trailing_options):
            _fail(f"{label} contains forbidden systemctl options")
        if action == "daemon-reload":
            if trailing:
                _fail(f"{label} contains forbidden systemctl arguments")
        elif not units or any(unit not in allowed_units for unit in units):
            _fail(f"{label} contains a forbidden systemctl unit")
    if first_name == "systemd-tmpfiles" and argv != [
        "/usr/bin/systemd-tmpfiles",
        "--create",
        "/etc/tmpfiles.d/overseer.conf",
    ]:
        _fail(f"{label} contains a forbidden tmpfiles payload")
    if first_name == "curl" and not any(
        argument == "http://127.0.0.1:8766/health" for argument in argv
    ):
        _fail(f"{label} contains a forbidden curl target")
    if first_name == "install":
        target = argv[-1]
        if not any(
            target == prefix or target.startswith(prefix + "/")
            for prefix in (
                "/etc/overseer",
                "/etc/systemd/system",
                "/etc/tmpfiles.d",
                "/opt/overseer",
                "/var/lib/overseer",
                "/var/lib/overseer-executor",
                "/home/god/.local/share/overseer/project/state",
            )
        ):
            _fail(f"{label} contains a forbidden install target")
    if first_name == "chmod" and not (
        len(argv) == 3
        and argv[1] in {"0550", "0555"}
        and argv[2].startswith("/opt/overseer/")
    ):
        _fail(f"{label} contains a forbidden chmod target")

    return list(argv)


def _validate_command_list(commands: Any, label: str) -> None:
    if not isinstance(commands, Sequence) or isinstance(commands, (str, bytes, bytearray)):
        _fail(f"{label} must be non-empty")
    if not commands:
        _fail(f"{label} must be non-empty")
    for index, argv in enumerate(commands):
        _validate_argv(argv, f"{label}[{index}]")


def validate_maintenance_contract(contract: Mapping[str, Any]) -> None:
    """Validate the digest-cycle-free contract and raise ``ValueError`` on drift."""

    document = _require_mapping(contract, "contract")
    _reject_secret_bearing_fields(document)
    _require_exact_fields(document, _CONTRACT_FIELDS, "contract")

    if document["schemaVersion"] != MAINTENANCE_CONTRACT_SCHEMA:
        _fail("contract schema does not match maintenance contract schema")
    _require_absolute_path(document["packageRoot"], "contract.packageRoot")
    _require_digest(document["releaseManifestDigest"], "contract.releaseManifestDigest")
    account = _require_mapping(document["account"], "contract.account")
    _require_exact_fields(
        account,
        {"user", "uid", "group", "gid"},
        "contract.account",
    )
    if account != {
        "user": "overseer",
        "uid": 984,
        "group": "overseer",
        "gid": 984,
    }:
        _fail("contract.account must be the exact overseer 984:984 account")
    if document["scope"] != _EXPECTED_SCOPE:
        _fail("contract.scope does not match maintenance-window scope")

    writer_baseline = document["writerUnitBaseline"]
    if (
        not isinstance(writer_baseline, Sequence)
        or isinstance(writer_baseline, (str, bytes, bytearray))
        or [
            entry.get("unit") if isinstance(entry, Mapping) else None
            for entry in writer_baseline
        ]
        != list(MAINTENANCE_WRITER_UNITS)
    ):
        _fail("contract writer unit baseline must contain the exact ordered unit set")
    expected_active = set(MAINTENANCE_EXPECTED_ACTIVE_UNITS)
    for index, entry in enumerate(writer_baseline):
        baseline = _require_mapping(
            entry, f"contract.writerUnitBaseline[{index}]"
        )
        _require_exact_fields(
            baseline,
            {"unit", "loadState", "activeState", "unitFileState"},
            f"contract.writerUnitBaseline[{index}]",
        )
        unit = str(baseline["unit"])
        observed = (
            baseline["loadState"],
            baseline["activeState"],
            baseline["unitFileState"],
        )
        if unit in _OPTIONAL_ABSENT_WRITER_UNITS:
            expected = ("not-found", "inactive", "")
        elif unit in expected_active:
            expected = ("loaded", "active", "enabled")
        else:
            expected = ("loaded", "inactive", "static")
        if observed != expected:
            _fail("contract writer unit baseline does not match the stable deployment profile")

    successor_baseline = document["successorUnitBaseline"]
    if (
        not isinstance(successor_baseline, Sequence)
        or isinstance(successor_baseline, (str, bytes, bytearray))
        or [
            entry.get("unit") if isinstance(entry, Mapping) else None
            for entry in successor_baseline
        ]
        != list(MAINTENANCE_SUCCESSOR_SYSTEM_UNITS)
    ):
        _fail("contract successor unit baseline must contain the exact ordered unit set")
    for index, entry in enumerate(successor_baseline):
        baseline = _require_mapping(
            entry, f"contract.successorUnitBaseline[{index}]"
        )
        _require_exact_fields(
            baseline,
            {"unit", "loadState", "activeState", "unitFileState"},
            f"contract.successorUnitBaseline[{index}]",
        )
        if (
            baseline["loadState"],
            baseline["activeState"],
            baseline["unitFileState"],
        ) != ("loaded", "inactive", "disabled"):
            _fail("contract successor unit baseline does not match the inactive profile")

    bindings = document["storeBindings"]
    expected_store_names = (
        "overseer-main",
        "psychlo-bridge",
        "roadex-relay",
    )
    if (
        not isinstance(bindings, Sequence)
        or isinstance(bindings, (str, bytes, bytearray))
        or [
            binding.get("name") if isinstance(binding, Mapping) else None
            for binding in bindings
        ]
        != list(expected_store_names)
    ):
        _fail("contract.storeBindings must contain the exact ordered store set")
    observed_paths: set[str] = set()
    for index, binding in enumerate(bindings):
        store = _require_mapping(binding, f"contract.storeBindings[{index}]")
        _require_exact_fields(
            store,
            {
                "name",
                "sourceDb",
                "backupDb",
                "destinationDb",
                "storeKind",
                "sourceIdentity",
            },
            f"contract.storeBindings[{index}]",
        )
        expected_kind = "overseer" if index == 0 else "copy-only"
        if store["name"] != expected_store_names[index] or store["storeKind"] != expected_kind:
            _fail("contract store name or kind is invalid")
        for field in ("sourceDb", "backupDb", "destinationDb"):
            path = _require_absolute_path(
                store[field],
                f"contract.storeBindings[{index}].{field}",
            )
            if path in observed_paths:
                _fail("contract store paths must be distinct")
            observed_paths.add(path)
        identity = _require_mapping(
            store["sourceIdentity"],
            f"contract.storeBindings[{index}].sourceIdentity",
        )
        _require_exact_fields(
            identity,
            {
                "device",
                "inode",
                "uid",
                "gid",
                "parentDevice",
                "parentInode",
                "parentMode",
            },
            f"contract.storeBindings[{index}].sourceIdentity",
        )
        if any(type(value) is not int or value < 0 for value in identity.values()):
            _fail("contract store source identity is invalid")
        if identity["parentMode"] not in {0o700, 0o750, 0o770, 0o775}:
            _fail("contract store parent mode is invalid")

    deferred = document["deferredStoreBindings"]
    if (
        not isinstance(deferred, Sequence)
        or isinstance(deferred, (str, bytes, bytearray))
        or len(deferred) != 1
    ):
        _fail("contract.deferredStoreBindings must contain codex-usage")
    deferred_store = _require_mapping(
        deferred[0], "contract.deferredStoreBindings[0]"
    )
    _require_exact_fields(
        deferred_store,
        {"name", "sourceDb", "policy", "sourceIdentity"},
        "contract.deferredStoreBindings[0]",
    )
    if (
        deferred_store["name"] != "codex-usage"
        or deferred_store["policy"] != "preserve-and-resume-unchanged"
    ):
        _fail("contract deferred store policy is invalid")
    deferred_path = _require_absolute_path(
        deferred_store["sourceDb"],
        "contract.deferredStoreBindings[0].sourceDb",
    )
    if deferred_path in observed_paths:
        _fail("contract store paths must be distinct")
    deferred_identity = _require_mapping(
        deferred_store["sourceIdentity"],
        "contract.deferredStoreBindings[0].sourceIdentity",
    )
    _require_exact_fields(
        deferred_identity,
        {
            "device",
            "inode",
            "uid",
            "gid",
            "parentDevice",
            "parentInode",
            "parentMode",
        },
        "contract.deferredStoreBindings[0].sourceIdentity",
    )
    if any(type(value) is not int or value < 0 for value in deferred_identity.values()):
        _fail("contract deferred store source identity is invalid")
    if deferred_identity["parentMode"] not in {0o700, 0o750, 0o770, 0o775}:
        _fail("contract deferred store parent mode is invalid")

    preservation = _require_mapping(
        document["preservationInputs"],
        "contract.preservationInputs",
    )
    _require_exact_fields(
        preservation,
        _PRESERVATION_INPUT_NAMES,
        "contract.preservationInputs",
    )
    for name, value in preservation.items():
        _require_absolute_path(value, f"contract.preservationInputs.{name}")
    _require_absolute_path(document["evidenceRoot"], "contract.evidenceRoot")
    expected_checks = [
        "api",
        "authenticated-ui-data",
        "scheduler-freshness",
        "protected-gateway-read",
        "psychlo-read",
        "roadex-read",
        "credentials",
        "single-writer-inventory",
    ]
    if document["acceptanceChecks"] != expected_checks:
        _fail("contract.acceptanceChecks must contain the exact bounded check set")

    stages = document["stages"]
    if not isinstance(stages, Sequence) or isinstance(stages, (str, bytes, bytearray)):
        _fail("contract.stages must be an ordered sequence")
    if [stage.get("name") if isinstance(stage, Mapping) else None for stage in stages] != list(_STAGE_NAMES):
        _fail("contract stages have an invalid order: expected " + ", ".join(_STAGE_NAMES))
    for index, stage in enumerate(stages):
        stage_document = _require_mapping(stage, f"contract.stages[{index}]")
        _require_exact_fields(stage_document, _STAGE_FIELDS, f"contract.stages[{index}]")
        if stage_document["name"] != _STAGE_NAMES[index]:
            _fail(f"contract stage {index} has an invalid name")
        _validate_command_list(stage_document["commands"], f"contract.stages[{index}].commands")

    stage_timeouts = _require_mapping(
        document["stageTimeoutSeconds"], "contract.stageTimeoutSeconds"
    )
    _require_exact_fields(
        stage_timeouts, set(_STAGE_NAMES), "contract.stageTimeoutSeconds"
    )
    if any(
        type(value) is not int or not 1 <= value <= 3600
        for value in stage_timeouts.values()
    ):
        _fail("contract stage timeout is invalid")
    if (
        type(document["windowTimeoutSeconds"]) is not int
        or not 1 <= document["windowTimeoutSeconds"] <= 7200
    ):
        _fail("contract window timeout is invalid")

    _validate_command_list(document["rollbackCommands"], "contract.rollbackCommands")
    _validate_command_list(
        document["earlyRollbackCommands"], "contract.earlyRollbackCommands"
    )
    early_rollback_timeouts = document["earlyRollbackTimeoutSeconds"]
    if (
        not isinstance(early_rollback_timeouts, Sequence)
        or isinstance(early_rollback_timeouts, (str, bytes, bytearray))
        or len(early_rollback_timeouts) != len(document["earlyRollbackCommands"])
        or any(
            type(value) is not int or not 1 <= value <= 3600
            for value in early_rollback_timeouts
        )
    ):
        _fail("contract early rollback timeouts are invalid")
    if (
        type(document["earlyRollbackWindowTimeoutSeconds"]) is not int
        or not 1 <= document["earlyRollbackWindowTimeoutSeconds"] <= 3600
    ):
        _fail("contract early rollback window timeout is invalid")
    early_start_index = document["earlyRollbackStartIndex"]
    if (
        type(early_start_index) is not int
        or not 0 <= early_start_index < len(document["earlyRollbackCommands"])
    ):
        _fail("contract early rollback start index is invalid")
    rollback_timeouts = document["rollbackTimeoutSeconds"]
    if (
        not isinstance(rollback_timeouts, Sequence)
        or isinstance(rollback_timeouts, (str, bytes, bytearray))
        or len(rollback_timeouts) != len(document["rollbackCommands"])
        or any(
            type(value) is not int or not 1 <= value <= 3600
            for value in rollback_timeouts
        )
    ):
        _fail("contract rollback timeouts are invalid")
    if (
        type(document["rollbackWindowTimeoutSeconds"]) is not int
        or not 1 <= document["rollbackWindowTimeoutSeconds"] <= 3600
    ):
        _fail("contract rollback window timeout is invalid")
    rollback_start_index = document["rollbackStartIndex"]
    if (
        type(rollback_start_index) is not int
        or not 0 <= rollback_start_index < len(document["rollbackCommands"])
    ):
        _fail("contract rollback start index is invalid")
    secret_inputs = document["secretInputs"]
    if not isinstance(secret_inputs, Sequence) or isinstance(secret_inputs, (str, bytes, bytearray)):
        _fail("contract.secretInputs must be a sequence")
    if any(not isinstance(item, str) or not item for item in secret_inputs):
        _fail("contract.secretInputs must contain only nonempty names")


def validate_maintenance_approval(
    approval: Mapping[str, Any],
    package_root: str,
    package_digest: str,
    plan_digest: str,
    allow_reboot: bool,
) -> None:
    """Validate the exact approval binding for one immutable package and plan."""

    document = _require_mapping(approval, "approval")
    _require_exact_fields(document, _APPROVAL_FIELDS, "approval")
    if document["schemaVersion"] != MAINTENANCE_APPROVAL_SCHEMA:
        _fail("approval schema does not match maintenance approval schema")
    if document["scope"] != _EXPECTED_SCOPE:
        _fail("approval scope does not match maintenance-window scope")
    if document["packageRoot"] != package_root:
        _fail("approval packageRoot does not match")
    if document["packageDigest"] != _require_digest(package_digest, "package_digest"):
        _fail("approval packageDigest does not match")
    if document["planDigest"] != _require_digest(plan_digest, "plan_digest"):
        _fail("approval planDigest does not match")
    if type(allow_reboot) is not bool or type(document["allowReboot"]) is not bool:
        _fail("approval reboot policy must be boolean")
    if document["allowReboot"] is not allow_reboot:
        _fail("approval allowReboot policy does not match")


def maintenance_plan_digest(contract: Mapping[str, Any]) -> str:
    """Return the canonical SHA-256 digest of a validated contract."""

    validate_maintenance_contract(contract)
    canonical = json.dumps(
        contract,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _checkpoint(
    checkpoint: Callable[[dict[str, Any]], Any],
    *,
    package_digest: str,
    status: str,
    stage: str | None,
    command_index: int | None,
    command_digest: str | None,
    writers_stopped: bool,
) -> None:
    # Deliberately omit argv, secretInputs, exceptions, and callback results.
    state = {
        "schemaVersion": MAINTENANCE_RUNNER_STATE_SCHEMA,
        "packageDigest": package_digest,
        "status": status,
        "writersStopped": writers_stopped,
    }
    if stage is not None:
        state["stage"] = stage
    if command_index is not None:
        state["commandIndex"] = command_index
    if command_digest is not None:
        state["commandDigest"] = command_digest
    checkpoint(state)


def _command_digest(argv: Sequence[str]) -> str:
    return hashlib.sha256(
        json.dumps(
            list(argv),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def execute_maintenance_contract(
    contract: Mapping[str, Any],
    package_digest: str,
    execute: Callable[[list[str], int], Any],
    checkpoint: Callable[[dict[str, Any]], Any],
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    """Execute a validated contract through injected effects only.

    Writer shutdown becomes rollback-required before its first effect starts.
    Failures before offline migration use the idempotent early recovery profile;
    later failures use the full store-and-service rollback.  A prerequisite
    rollback failure blocks restart commands, and a successful rollback
    re-raises the original exception.
    """

    validate_maintenance_contract(contract)
    digest = _require_digest(package_digest, "package_digest")
    if not callable(execute) or not callable(checkpoint):
        _fail("execute and checkpoint must be callable")
    if not callable(monotonic):
        _fail("monotonic must be callable")
    window_deadline = monotonic() + int(contract["windowTimeoutSeconds"])

    def bounded_timeout(configured: int, deadline: float) -> int:
        remaining = int(deadline - monotonic())
        if remaining < 1:
            raise TimeoutError("maintenance window exceeded its sealed deadline")
        return min(configured, remaining)

    writers_stopped = False
    current_stage: str | None = None
    current_index: int | None = None
    try:
        for stage in contract["stages"]:
            current_stage = stage["name"]
            timeout_seconds = int(contract["stageTimeoutSeconds"][current_stage])
            for current_index, argv in enumerate(stage["commands"]):
                command_digest = _command_digest(argv)
                command_timeout = bounded_timeout(timeout_seconds, window_deadline)
                if current_stage == "stopWriters":
                    # Writer shutdown is uncertain as soon as the effect starts.
                    # Persist rollback-required state before invoking it so a
                    # crash cannot strand stopped services behind a false flag.
                    writers_stopped = True
                _checkpoint(
                    checkpoint,
                    package_digest=digest,
                    status=(
                        "writer_stop_in_progress"
                        if current_stage == "stopWriters"
                        else "before_command"
                    ),
                    stage=current_stage,
                    command_index=current_index,
                    command_digest=command_digest,
                    writers_stopped=writers_stopped,
                )
                result = execute(list(argv), command_timeout)
                if type(result) is int and result != 0:
                    raise RuntimeError(
                        f"maintenance command returned nonzero status: {result}"
                    )
                _checkpoint(
                    checkpoint,
                    package_digest=digest,
                    status="after_command",
                    stage=current_stage,
                    command_index=current_index,
                    command_digest=command_digest,
                    writers_stopped=writers_stopped,
                )
        _checkpoint(
            checkpoint,
            package_digest=digest,
            status="complete",
            stage=None,
            command_index=None,
            command_digest=None,
            writers_stopped=writers_stopped,
        )
    except BaseException as original_error:
        if not writers_stopped:
            _checkpoint(
                checkpoint,
                package_digest=digest,
                status="failed_before_stopWriters",
                stage=current_stage,
                command_index=current_index,
                command_digest=(
                    None if current_stage is None or current_index is None
                    else _command_digest(contract["stages"][_STAGE_NAMES.index(current_stage)]["commands"][current_index])
                ),
                writers_stopped=False,
            )
            raise

        use_early_rollback = (
            current_stage is not None
            and _STAGE_NAMES.index(current_stage)
            < _STAGE_NAMES.index("migrateOfflineStores")
        )
        command_field = (
            "earlyRollbackCommands" if use_early_rollback else "rollbackCommands"
        )
        timeout_field = (
            "earlyRollbackTimeoutSeconds"
            if use_early_rollback
            else "rollbackTimeoutSeconds"
        )
        start_field = (
            "earlyRollbackStartIndex" if use_early_rollback else "rollbackStartIndex"
        )
        window_field = (
            "earlyRollbackWindowTimeoutSeconds"
            if use_early_rollback
            else "rollbackWindowTimeoutSeconds"
        )
        rollback_stage = "earlyRollback" if use_early_rollback else "rollback"
        rollback_error: BaseException | None = None
        rollback_start_index = int(contract[start_field])
        rollback_deadline = monotonic() + int(contract[window_field])
        for rollback_index, argv in enumerate(contract[command_field]):
            if rollback_error is not None and rollback_index >= rollback_start_index:
                break
            rollback_digest = _command_digest(argv)
            try:
                _checkpoint(
                    checkpoint,
                    package_digest=digest,
                    status="before_rollback_command",
                    stage=rollback_stage,
                    command_index=rollback_index,
                    command_digest=rollback_digest,
                    writers_stopped=True,
                )
                result = execute(
                    list(argv),
                    bounded_timeout(
                        int(contract[timeout_field][rollback_index]),
                        rollback_deadline,
                    ),
                )
                if type(result) is int and result != 0:
                    raise RuntimeError(
                        f"maintenance rollback command returned nonzero status: {result}"
                    )
                _checkpoint(
                    checkpoint,
                    package_digest=digest,
                    status="after_rollback_command",
                    stage=rollback_stage,
                    command_index=rollback_index,
                    command_digest=rollback_digest,
                    writers_stopped=True,
                )
            except BaseException as error:
                if rollback_error is None:
                    rollback_error = error

        if rollback_error is not None:
            _checkpoint(
                checkpoint,
                package_digest=digest,
                status="rollback_failed",
                stage=rollback_stage,
                command_index=None,
                command_digest=None,
                writers_stopped=True,
            )
            raise rollback_error from original_error
        _checkpoint(
            checkpoint,
            package_digest=digest,
            status="rolled_back",
            stage=rollback_stage,
            command_index=None,
            command_digest=None,
            writers_stopped=True,
        )
        raise
