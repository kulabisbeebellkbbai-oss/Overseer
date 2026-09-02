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
import re
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
MAINTENANCE_STORE_DESTINATIONS = (
    ("overseer-main", "/var/lib/overseer/overseer.sqlite3"),
    ("psychlo-bridge", "/var/lib/overseer/psychlo-bridge.sqlite3"),
    ("roadex-relay", "/var/lib/overseer/roadex-relay.sqlite3"),
)
_OPTIONAL_ABSENT_WRITER_UNITS = {
    "overseer-psychlo-coordination-tick.timer",
    "overseer-psychlo-coordination-tick.service",
}
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
    "compatibilityApiToken",
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
_ALLOWED_EXECUTABLE_PATHS = {
    "/usr/bin/chmod",
    "/usr/bin/curl",
    "/usr/bin/env",
    "/usr/bin/install",
    "/usr/bin/systemctl",
    "/usr/bin/systemd-tmpfiles",
    "/usr/sbin/runuser",
}
_SECRET_KEY_MARKERS = (
    "credential",
    "password",
    "secret",
    "token",
    "privatekey",
    "private_key",
)

_MAINTENANCE_PYTHON_MODULE = "overseer.activation_package"
_MAINTENANCE_SIMPLE_HELPER_SUBCOMMANDS = {
    "ensure-dedicated-principal",
    "prepare-maintenance-stores",
    "preserve-maintenance-state",
    "restop-maintenance-writers",
    "restore-maintenance-handoff-artifacts",
    "restore-maintenance-store-access",
    "restore-maintenance-writers",
    "stop-maintenance-writers",
    "verify-maintenance-acceptance",
    "verify-maintenance-installed-release",
    "verify-maintenance-preservation",
    "verify-maintenance-preflight",
    "verify-maintenance-quiescence",
}
_MAINTENANCE_PYTHON_SUBCOMMANDS = _MAINTENANCE_SIMPLE_HELPER_SUBCOMMANDS | {
    "verify-compatibility-token",
    "verify-rollback-bundle",
}
_MAINTENANCE_SYSTEMCTL_TUPLES = {
    ("systemctl", "daemon-reload"),
    (
        "systemctl",
        "stop",
        "overseer-api.service",
        "overseer-runtime.service",
        "overseer-admin-executor.socket",
        "overseer-codex-user-bridge.socket",
    ),
    (
        "systemctl",
        "disable",
        "overseer-api.service",
        "overseer-runtime.service",
        "overseer-admin-executor.socket",
        "overseer-codex-user-bridge.socket",
    ),
    (
        "systemctl",
        "enable",
        "--now",
        "overseer-codex-user-bridge.socket",
        "overseer-admin-executor.socket",
    ),
    (
        "systemctl",
        "enable",
        "--now",
        "overseer-runtime.service",
        "overseer-api.service",
    ),
}
_MAINTENANCE_USER_SYSTEMCTL_TUPLES = {
    (
        "disable",
        "overseer-psychlo-usage.timer",
        "overseer-psychlo-cycle.service",
        "overseer-psychlo-meter.service",
        "overseer-psychlo-usage.service",
        "overseer-api.service",
        "overseer.service",
    ),
    (
        "start",
        "overseer-quark-scheduler.timer",
        "overseer-codex-usage-mcp.service",
        "overseer-codex-usage-snapshot.timer",
    ),
}
_MAINTENANCE_HANDOFF_CREDENTIAL_TARGETS = {
    "/etc/overseer/admin-approval-verifier.json": ("984", "984", "0600"),
    "/etc/overseer/roadex-fixture-approval-verifier.json": ("984", "984", "0600"),
    "/etc/overseer/api-token": ("root", "root", "0600"),
    "/etc/overseer/psychlo-peer-secret": ("root", "root", "0600"),
    "/etc/overseer/roadex-project-human-thread-secret": ("root", "root", "0600"),
    "/etc/overseer/psychlo-project-bindings.json": ("root", "root", "0644"),
    "/etc/overseer/admin-executor-public-key": ("root", "root", "0644"),
    "/etc/overseer/admin-executor-allowlist.json": ("root", "root", "0644"),
    "/etc/overseer/admin-ticket-private-key": ("984", "984", "0600"),
    "/etc/overseer/protected-gateway-ca.crt": ("root", "root", "0644"),
}
_MAINTENANCE_HANDOFF_SYSTEM_TARGETS = {
    "/etc/systemd/system/overseer-admin-executor.socket",
    "/etc/systemd/system/overseer-admin-executor@.service",
    "/etc/systemd/system/overseer-api.service",
    "/etc/systemd/system/overseer-codex-user-bridge.service",
    "/etc/systemd/system/overseer-codex-user-bridge.socket",
    "/etc/systemd/system/overseer-runtime.service",
    "/etc/tmpfiles.d/overseer.conf",
}
_MAINTENANCE_FIXED_DIRECTORY_TARGETS = {
    "/opt/overseer": ("root", "root", {"0755"}),
    "/opt/overseer/releases": ("root", "root", {"0755"}),
    "/opt/overseer/rollback": ("root", "root", {"0755"}),
    "/var/lib/overseer": ("984", "984", {"0700"}),
    "/var/lib/overseer-executor": ("root", "root", {"0700"}),
    "/etc/overseer": ("0", "984", {"0710"}),
}
_MAINTENANCE_PACKAGE_ROOT = "/var/lib/overseer-executor/approved-package"
_MAINTENANCE_COMPATIBILITY_TOKEN_TARGET = (
    "/home/god/.local/share/overseer/project/state/api-token"
)
_MAINTENANCE_RELEASE_PREFIX = "/opt/overseer/releases/"
_MAINTENANCE_ROLLBACK_PREFIX = "/opt/overseer/rollback/"
_MAINTENANCE_CREDENTIAL_SOURCES = {
    "/etc/overseer/admin-approval-verifier.json": "private/credentials/admin-approval-verifier.json",
    "/etc/overseer/roadex-fixture-approval-verifier.json": "private/credentials/roadex-fixture-approval-verifier.json",
    "/etc/overseer/api-token": "private/credentials/api-token",
    "/etc/overseer/psychlo-peer-secret": "private/credentials/psychlo-peer-secret",
    "/etc/overseer/roadex-project-human-thread-secret": "private/credentials/roadex-project-human-thread-secret",
    "/etc/overseer/psychlo-project-bindings.json": "public/config/psychlo-project-bindings.json",
    "/etc/overseer/admin-executor-public-key": "public/config/admin-executor-public-key",
    "/etc/overseer/admin-executor-allowlist.json": "public/config/admin-executor-allowlist.json",
    "/etc/overseer/admin-ticket-private-key": "private/credentials/admin-ticket-private-key",
    "/etc/overseer/protected-gateway-ca.crt": "public/config/protected-gateway-ca.crt",
}
_MAINTENANCE_SYSTEM_SOURCES = {
    "/etc/systemd/system/overseer-admin-executor.socket": "public/systemd/overseer-admin-executor.socket",
    "/etc/systemd/system/overseer-admin-executor@.service": "public/systemd/overseer-admin-executor@.service",
    "/etc/systemd/system/overseer-api.service": "public/systemd/overseer-api.service",
    "/etc/systemd/system/overseer-codex-user-bridge.service": "public/systemd/overseer-codex-user-bridge.service",
    "/etc/systemd/system/overseer-codex-user-bridge.socket": "public/systemd/overseer-codex-user-bridge.socket",
    "/etc/systemd/system/overseer-runtime.service": "public/systemd/overseer-runtime.service",
    "/etc/tmpfiles.d/overseer.conf": "public/systemd/overseer-tmpfiles.conf",
}


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


def _require_canonical_absolute_path(value: str, label: str) -> str:
    path = _require_absolute_path(value, label)
    if path != posixpath.normpath(path) or path.startswith("//"):
        _fail(f"{label} must be canonical")
    return path


def _safe_named_path_suffix(path: str, prefix: str, label: str) -> bool:
    if not path.startswith(prefix):
        return False
    suffix = path[len(prefix) :]
    parts = suffix.split("/")
    if not suffix or any(
        not part or part in {".", ".."} or re.fullmatch(r"[A-Za-z0-9_.@-]+", part) is None
        for part in parts
    ):
        return False
    _require_canonical_absolute_path(path, label)
    return True


def _validate_python_env_argv(
    argv: list[str], label: str, package_root: str = _MAINTENANCE_PACKAGE_ROOT
) -> None:
    if len(argv) < 14:
        _fail(f"{label} contains a forbidden Python environment")
    if not argv[1].startswith("LD_LIBRARY_PATH="):
        _fail(f"{label} contains an invalid Python environment")
    library_path = argv[1][len("LD_LIBRARY_PATH=") :]
    if not library_path.endswith("/lib"):
        _fail(f"{label} contains a forbidden Python environment")
    release_root = library_path[: -len("/lib")]
    _require_canonical_absolute_path(release_root, f"{label} Python release root")
    valid_roots = (
        _MAINTENANCE_RELEASE_PREFIX,
        f"{package_root}/public/release/",
    )
    if not any(
        _safe_named_path_suffix(release_root, prefix, f"{label} Python release root")
        and release_root.count("/") == prefix.count("/")
        for prefix in valid_roots
    ):
        _fail(f"{label} contains a forbidden Python release root")
    expected_environment = [
        f"LD_LIBRARY_PATH={release_root}/lib",
        f"PYTHONHOME={release_root}/runtime",
        f"PYTHONPATH={release_root}/app/src:{release_root}/site-packages",
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTHONNOUSERSITE=1",
        "PYTHONSAFEPATH=1",
    ]
    if argv[1:7] != expected_environment:
        _fail(f"{label} contains forbidden Python environment arguments")
    interpreter = _require_canonical_absolute_path(
        argv[7], f"{label} Python interpreter"
    )
    if interpreter != f"{release_root}/runtime/bin/python3.13":
        _fail(f"{label} contains a forbidden Python interpreter path")
    if argv[8:13] != ["-B", "-s", "-P", "-m", _MAINTENANCE_PYTHON_MODULE]:
        _fail(f"{label} contains forbidden Python or module arguments")
    subcommand = argv[13] if len(argv) > 13 else None
    if subcommand not in _MAINTENANCE_PYTHON_SUBCOMMANDS:
        _fail(f"{label} contains a forbidden maintenance Python command")
    if subcommand in _MAINTENANCE_SIMPLE_HELPER_SUBCOMMANDS:
        expected_tail = [subcommand, "--package-root", package_root]
        if argv[13:] != expected_tail:
            _fail(f"{label} contains an unexpected maintenance helper argument")
    elif subcommand == "verify-compatibility-token":
        if len(argv) != 26 or argv[13:17] != [
            "verify-compatibility-token",
            "--source-token",
            "/etc/overseer/api-token",
            "--target-token",
        ] or argv[17] != _MAINTENANCE_COMPATIBILITY_TOKEN_TARGET:
            _fail(f"{label} contains an invalid compatibility-token verification shape")
        expected_options = [
            "--expected-target-uid",
            "--expected-target-gid",
            "--expected-parent-device",
            "--expected-parent-inode",
        ]
        for index, option in enumerate(expected_options):
            option_index = 18 + index * 2
            if argv[option_index] != option or re.fullmatch(r"[0-9]+", argv[option_index + 1]) is None:
                _fail(f"{label} contains an invalid sealed compatibility-token identity")
    elif subcommand == "verify-rollback-bundle":
        if len(argv) != 18 or argv[13] != "verify-rollback-bundle":
            _fail(f"{label} contains an invalid rollback-bundle verification shape")
        bundle_root = argv[15]
        if (
            argv[14] != "--bundle-root"
            or re.fullmatch(r"/opt/overseer/rollback/[0-9a-f]{64}", bundle_root) is None
            or _require_canonical_absolute_path(bundle_root, f"{label} rollback bundle root") != bundle_root
            or argv[16:] != [
                "--rollback-manifest",
                f"{package_root}/public/rollback-manifest.json",
            ]
        ):
            _fail(f"{label} contains an invalid rollback-bundle verification shape")


def _validate_systemctl_argv(argv: list[str], label: str) -> None:
    if tuple(["systemctl", *argv[1:]]) in _MAINTENANCE_SYSTEMCTL_TUPLES:
        return
    _fail(f"{label} contains a forbidden systemctl tuple")


def _validate_user_systemctl_argv(argv: list[str], label: str) -> None:
    if len(argv) < 9 or argv[:5] != [
        "/usr/sbin/runuser",
        "--user",
        "god",
        "--",
        "/usr/bin/env",
    ]:
        _fail(f"{label} contains a forbidden runuser payload")
    if (
        re.fullmatch(r"XDG_RUNTIME_DIR=/run/user/[0-9]+", argv[5]) is None
        or argv[6:8] != ["/usr/bin/systemctl", "--user"]
        or tuple(argv[8:]) not in _MAINTENANCE_USER_SYSTEMCTL_TUPLES
    ):
        _fail(f"{label} contains a forbidden user systemctl tuple")


def _install_target_kind(path: str) -> str | None:
    if path in _MAINTENANCE_FIXED_DIRECTORY_TARGETS:
        return "directory-fixed"
    if _maintenance_release_parts(path) is not None:
        return "release"
    if _maintenance_rollback_parts(path) is not None:
        return "rollback"
    if path in _MAINTENANCE_HANDOFF_CREDENTIAL_TARGETS:
        return "credential"
    if path in _MAINTENANCE_HANDOFF_SYSTEM_TARGETS:
        return "system"
    if path == _MAINTENANCE_COMPATIBILITY_TOKEN_TARGET:
        return "compatibility-token"
    return None


def _maintenance_release_parts(path: str) -> tuple[str, list[str]] | None:
    if not _safe_named_path_suffix(path, _MAINTENANCE_RELEASE_PREFIX, "release path"):
        return None
    parts = path[len(_MAINTENANCE_RELEASE_PREFIX) :].split("/")
    return parts[0], parts[1:]


def _maintenance_rollback_parts(path: str) -> tuple[str, list[str]] | None:
    if not _safe_named_path_suffix(path, _MAINTENANCE_ROLLBACK_PREFIX, "rollback path"):
        return None
    parts = path[len(_MAINTENANCE_ROLLBACK_PREFIX) :].split("/")
    if re.fullmatch(r"[0-9a-f]{64}", parts[0]) is None:
        return None
    return parts[0], parts[1:]


def _validate_install_argv(
    argv: list[str], label: str, package_root: str = _MAINTENANCE_PACKAGE_ROOT
) -> None:
    if len(argv) not in {9}:
        _fail(f"{label} contains an invalid install shape")
    if argv[1] == "-d":
        if argv[2:8:2] != ["-o", "-g", "-m"]:
            _fail(f"{label} contains an invalid install directory shape")
        target = _require_canonical_absolute_path(argv[8], f"{label} install target")
        kind = _install_target_kind(target)
        if kind == "directory-fixed":
            owner, group, modes = _MAINTENANCE_FIXED_DIRECTORY_TARGETS[target]
        elif kind == "release":
            owner, group, modes = "root", "root", {"0755"}
        elif kind == "rollback":
            owner, group, modes = "root", "god", {"0750"}
        else:
            _fail(f"{label} contains an unapproved install directory target")
        if (argv[3], argv[5], argv[7]) != (owner, group, next(iter(modes))):
            _fail(f"{label} contains an unsafe install directory owner or mode")
        return
    if argv[1:2] != ["-o"] or argv[3:4] != ["-g"] or argv[5:6] != ["-m"]:
        _fail(f"{label} contains an invalid install file shape")
    source = _require_canonical_absolute_path(argv[7], f"{label} install source")
    target = _require_canonical_absolute_path(argv[8], f"{label} install target")
    kind = _install_target_kind(target)
    if kind is None:
        _fail(f"{label} contains an unapproved install target")
    if target == _MAINTENANCE_COMPATIBILITY_TOKEN_TARGET:
        expected = ("root", "god", "0640")
        if source != "/etc/overseer/api-token":
            _fail(f"{label} contains an unapproved compatibility-token source")
    elif kind == "release":
        target_parts = _maintenance_release_parts(target)
        source_prefix = f"{package_root}/public/release/"
        if target_parts is None or not _safe_named_path_suffix(source, source_prefix, f"{label} install source"):
            _fail(f"{label} contains an unapproved release source")
        source_parts = source[len(source_prefix) :].split("/")
        if source_parts != [target_parts[0], *target_parts[1]]:
            _fail(f"{label} release source and target do not correspond")
        if argv[6] not in {"0444", "0555"}:
            _fail(f"{label} contains an unsafe release mode")
        expected = ("root", "root", argv[6])
    elif kind == "rollback":
        target_parts = _maintenance_rollback_parts(target)
        source_prefix = f"{package_root}/private/rollback-inputs/"
        if target_parts is None or not _safe_named_path_suffix(source, source_prefix, f"{label} install source"):
            _fail(f"{label} contains an unapproved rollback source")
        source_parts = source[len(source_prefix) :].split("/")
        if source_parts != target_parts[1]:
            _fail(f"{label} rollback source and target do not correspond")
        if argv[6] not in {"0440", "0550"}:
            _fail(f"{label} contains an unsafe rollback mode")
        expected = ("root", "god", argv[6])
    elif kind == "credential":
        expected = _MAINTENANCE_HANDOFF_CREDENTIAL_TARGETS[target]
        expected_source = f"{package_root}/{_MAINTENANCE_CREDENTIAL_SOURCES[target]}"
        if source != expected_source:
            _fail(f"{label} credential source and target do not correspond")
    elif kind == "system":
        expected = ("root", "root", "0644")
        expected_source = f"{package_root}/{_MAINTENANCE_SYSTEM_SOURCES[target]}"
        if source != expected_source:
            _fail(f"{label} system source and target do not correspond")
    else:
        _fail(f"{label} contains an unsupported install target")
    if (argv[2], argv[4], argv[6]) != expected:
        _fail(f"{label} contains an unsafe install owner or mode")


def _validate_argv(
    argv: Any, label: str, package_root: str = _MAINTENANCE_PACKAGE_ROOT
) -> list[str]:
    if not isinstance(argv, Sequence) or isinstance(argv, (str, bytes, bytearray)):
        _fail(f"{label} must be a nonempty argv")
    if not argv:
        _fail(f"{label} must be a nonempty argv")
    if any(not isinstance(argument, str) or not argument or "\x00" in argument for argument in argv):
        _fail(f"{label} contains an empty or invalid argv element")
    if argv[0] not in _ALLOWED_EXECUTABLE_PATHS:
        _fail(f"{label} contains a forbidden executable")
    for index, argument in enumerate(argv):
        if argument.startswith("/"):
            _require_canonical_absolute_path(argument, f"{label}[{index}]")

    names = [posixpath.basename(argument).lower() for argument in argv]
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

    executable = argv[0]
    if executable == "/usr/bin/env":
        _validate_python_env_argv(list(argv), label, package_root)
    elif executable == "/usr/sbin/runuser":
        _validate_user_systemctl_argv(list(argv), label)
    elif executable == "/usr/bin/systemctl":
        _validate_systemctl_argv(list(argv), label)
    elif executable == "/usr/bin/systemd-tmpfiles":
        if list(argv) != [
            "/usr/bin/systemd-tmpfiles",
            "--create",
            "/etc/tmpfiles.d/overseer.conf",
        ]:
            _fail(f"{label} contains a forbidden tmpfiles payload")
    elif executable == "/usr/bin/curl":
        valid_curls = {
            (
                "/usr/bin/curl",
                "--fail",
                "--silent",
                "--show-error",
                "http://127.0.0.1:8766/health",
            ),
            (
                "/usr/bin/curl",
                "--fail",
                "--silent",
                "--show-error",
                "--connect-timeout",
                "2",
                "--max-time",
                "5",
                "http://127.0.0.1:8766/health",
            ),
            (
                "/usr/bin/curl",
                "--fail",
                "--silent",
                "--show-error",
                "--connect-timeout",
                "1",
                "--max-time",
                "3",
                "--retry",
                "15",
                "--retry-delay",
                "2",
                "--retry-max-time",
                "45",
                "--retry-all-errors",
                "http://127.0.0.1:8766/health",
            ),
        }
        if tuple(argv) not in valid_curls:
            _fail(f"{label} contains a forbidden curl shape")
    elif executable == "/usr/bin/install":
        _validate_install_argv(list(argv), label, package_root)
    elif executable == "/usr/bin/chmod":
        if len(argv) != 3:
            _fail(f"{label} contains an invalid chmod shape")
        target = _require_canonical_absolute_path(argv[2], f"{label} chmod target")
        if not (
            (argv[1] == "0555" and _safe_named_path_suffix(target, _MAINTENANCE_RELEASE_PREFIX, label))
            or (argv[1] == "0550" and _safe_named_path_suffix(target, _MAINTENANCE_ROLLBACK_PREFIX, label))
        ):
            _fail(f"{label} contains a forbidden chmod target")
    return list(argv)


def _validate_command_list(commands: Any, label: str, package_root: str) -> None:
    if not isinstance(commands, Sequence) or isinstance(commands, (str, bytes, bytearray)):
        _fail(f"{label} must be non-empty")
    if not commands:
        _fail(f"{label} must be non-empty")
    for index, argv in enumerate(commands):
        _validate_argv(argv, f"{label}[{index}]", package_root)


def _is_simple_helper(argv: list[str], subcommand: str) -> bool:
    return argv[0] == "/usr/bin/env" and argv[13] == subcommand


def _python_release_root(argv: list[str]) -> str:
    return argv[1].removeprefix("LD_LIBRARY_PATH=").removesuffix("/lib")


def _exact_install_file(
    argv: list[str], source: str, target: str, owner: str, group: str, mode: str
) -> bool:
    return argv == [
        "/usr/bin/install",
        "-o",
        owner,
        "-g",
        group,
        "-m",
        mode,
        source,
        target,
    ]


def _exact_install_directory(
    argv: list[str], target: str, owner: str, group: str, mode: str
) -> bool:
    return argv == [
        "/usr/bin/install",
        "-d",
        "-o",
        owner,
        "-g",
        group,
        "-m",
        mode,
        target,
    ]


def _expected_maintenance_python_subcommand(argv: list[str], subcommand: str) -> bool:
    return _is_simple_helper(argv, subcommand)


def _validate_maintenance_stage_profiles(
    document: Mapping[str, Any], package_root: str
) -> None:
    stages = document["stages"]
    stage_commands = {stage["name"]: stage["commands"] for stage in stages}
    package_stage_commands = {
        "preflight": "verify-maintenance-preflight",
        "stopWriters": "stop-maintenance-writers",
        "proveQuiescence": "verify-maintenance-quiescence",
        "preserveState": "preserve-maintenance-state",
    }
    installed_stage_commands = {
        "migrateOfflineStores": "prepare-maintenance-stores",
    }
    package_release_root: str | None = None
    for stage_name, subcommand in package_stage_commands.items():
        commands = stage_commands[stage_name]
        if len(commands) != 1 or not _expected_maintenance_python_subcommand(commands[0], subcommand):
            _fail(f"contract stage profile places {stage_name} commands incorrectly")
        observed_root = _python_release_root(commands[0])
        if package_release_root is None:
            package_release_root = observed_root
        if observed_root != package_release_root:
            _fail("contract pre-install helpers do not share one package release root")
    package_release_prefix = f"{package_root}/public/release/"
    if package_release_root is None or not package_release_root.startswith(
        package_release_prefix
    ):
        _fail("contract pre-install helpers must run from the sealed package")

    installed_release_root: str | None = None
    for stage_name, subcommand in installed_stage_commands.items():
        commands = stage_commands[stage_name]
        if len(commands) != 1 or not _expected_maintenance_python_subcommand(commands[0], subcommand):
            _fail(f"contract stage profile places {stage_name} commands incorrectly")
        observed_root = _python_release_root(commands[0])
        if installed_release_root is None:
            installed_release_root = observed_root
        if observed_root != installed_release_root:
            _fail("contract installed helpers do not share one release root")
    if installed_release_root is None or not installed_release_root.startswith(
        _MAINTENANCE_RELEASE_PREFIX
    ):
        _fail("contract post-install helpers must run from the installed release")
    release_name = package_release_root[len(package_release_prefix) :]
    if installed_release_root != f"{_MAINTENANCE_RELEASE_PREFIX}{release_name}":
        _fail("contract package and installed release roots do not correspond")

    install_commands = stage_commands["installRelease"]
    fixed_directories = [
        ("/opt/overseer", "root", "root", "0755"),
        ("/opt/overseer/releases", "root", "root", "0755"),
        ("/opt/overseer/rollback", "root", "root", "0755"),
        ("/var/lib/overseer-executor", "root", "root", "0700"),
    ]
    if len(install_commands) < len(fixed_directories) + 3:
        _fail("contract installRelease stage profile is incomplete")
    for index, (target, owner, group, mode) in enumerate(fixed_directories):
        if not _exact_install_directory(install_commands[index], target, owner, group, mode):
            _fail("contract installRelease stage profile has an invalid fixed directory")
    if not _is_simple_helper(install_commands[-1], "verify-maintenance-installed-release"):
        _fail("contract installRelease stage profile must end with its verifier")
    if _python_release_root(install_commands[-1]) != package_release_root:
        _fail("contract install verifier must run from the sealed package")

    release_seen = False
    rollback_seen = False
    rollback_phase = False
    for command in install_commands[len(fixed_directories) : -1]:
        if command[0] == "/usr/bin/install":
            target = command[-1]
            release = _maintenance_release_parts(target)
            rollback = _maintenance_rollback_parts(target)
        elif command[0] == "/usr/bin/chmod":
            target = command[2]
            release = _maintenance_release_parts(target)
            rollback = _maintenance_rollback_parts(target)
        else:
            _fail("contract installRelease stage profile contains a non-immutable command")
        if release is not None:
            if rollback_phase:
                _fail("contract installRelease stage profile interleaves release and rollback")
            if release[0] != release_name:
                _fail("contract immutable release target does not match its runtime")
            release_seen = True
        elif rollback is not None:
            if rollback[0] != document["releaseManifestDigest"]:
                _fail("contract rollback root does not match the release manifest")
            rollback_phase = True
            rollback_seen = True
        else:
            _fail("contract installRelease stage profile contains an invalid target")
    if not release_seen or not rollback_seen:
        _fail("contract installRelease stage profile must contain release and rollback artifacts")

    switch_commands = stage_commands["switchServices"]
    if len(switch_commands) != 30:
        _fail("contract switchServices stage profile has an invalid command count")
    position = 0
    if not _is_simple_helper(switch_commands[position], "verify-maintenance-preservation"):
        _fail("contract switchServices stage profile has an invalid preservation verifier")
    if _python_release_root(switch_commands[position]) != package_release_root:
        _fail("contract preservation verifier must run from the sealed package")
    position += 1
    if not _is_simple_helper(switch_commands[position], "ensure-dedicated-principal"):
        _fail("contract switchServices stage profile has an invalid principal helper")
    if _python_release_root(switch_commands[position]) != package_release_root:
        _fail("contract principal helper must run from the sealed package")
    position += 1
    if not _exact_install_directory(switch_commands[position], "/var/lib/overseer", "984", "984", "0700"):
        _fail("contract switchServices stage profile has an invalid Overseer store directory")
    position += 1
    if not _exact_install_directory(switch_commands[position], "/etc/overseer", "0", "984", "0710"):
        _fail("contract switchServices stage profile has an invalid credentials directory")
    position += 1

    for target in _MAINTENANCE_CREDENTIAL_SOURCES:
        source = f"{package_root}/{_MAINTENANCE_CREDENTIAL_SOURCES[target]}"
        owner, group, mode = _MAINTENANCE_HANDOFF_CREDENTIAL_TARGETS[target]
        if not _exact_install_file(switch_commands[position], source, target, owner, group, mode):
            _fail("contract switchServices stage profile has reordered or invalid credentials")
        position += 1

    for target, source_suffix in _MAINTENANCE_SYSTEM_SOURCES.items():
        if not _exact_install_file(
            switch_commands[position],
            f"{package_root}/{source_suffix}",
            target,
            "root",
            "root",
            "0644",
        ):
            _fail("contract switchServices stage profile has reordered or invalid system files")
        position += 1

    if tuple(switch_commands[position][8:]) not in _MAINTENANCE_USER_SYSTEMCTL_TUPLES or switch_commands[position][8] != "disable":
        _fail("contract switchServices stage profile has an invalid writer disable command")
    position += 1
    if not _is_simple_helper(switch_commands[position], "verify-maintenance-quiescence"):
        _fail("contract switchServices stage profile has an invalid quiescence verifier")
    if _python_release_root(switch_commands[position]) != package_release_root:
        _fail("contract switch quiescence verifier must run from the sealed package")
    position += 1
    if switch_commands[position] != ["/usr/bin/systemctl", "daemon-reload"]:
        _fail("contract switchServices stage profile has an invalid daemon reload")
    position += 1
    if switch_commands[position] != [
        "/usr/bin/systemd-tmpfiles", "--create", "/etc/tmpfiles.d/overseer.conf"
    ]:
        _fail("contract switchServices stage profile has an invalid tmpfiles command")
    position += 1
    for expected in (
        ("enable", "--now", "overseer-codex-user-bridge.socket", "overseer-admin-executor.socket"),
        ("enable", "--now", "overseer-runtime.service", "overseer-api.service"),
    ):
        if tuple(switch_commands[position][1:]) != expected:
            _fail("contract switchServices stage profile has reordered service handoff commands")
        position += 1
    if not _exact_install_file(
        switch_commands[position],
        "/etc/overseer/api-token",
        _MAINTENANCE_COMPATIBILITY_TOKEN_TARGET,
        "root",
        "god",
        "0640",
    ):
        _fail("contract switchServices stage profile has an invalid compatibility-token install")
    position += 1
    if switch_commands[position][13] != "verify-compatibility-token":
        _fail("contract switchServices stage profile has an invalid compatibility-token verifier")
    if _python_release_root(switch_commands[position]) != installed_release_root:
        _fail("contract compatibility verifier must run from the installed release")
    position += 1
    if tuple(switch_commands[position][8:]) != next(
        value for value in _MAINTENANCE_USER_SYSTEMCTL_TUPLES if value[0] == "start"
    ):
        _fail("contract switchServices stage profile has an invalid writer start command")
    if position + 1 != len(switch_commands):
        _fail("contract switchServices stage profile contains extra commands")

    acceptance = stage_commands["acceptance"]
    expected_acceptance_curl = [
        "/usr/bin/curl", "--fail", "--silent", "--show-error",
        "--connect-timeout", "1", "--max-time", "3", "--retry", "15",
        "--retry-delay", "2", "--retry-max-time", "45", "--retry-all-errors",
        "http://127.0.0.1:8766/health",
    ]
    if len(acceptance) != 2 or acceptance[0] != expected_acceptance_curl:
        _fail("contract acceptance stage profile must begin with the exact health check")
    if not _is_simple_helper(acceptance[1], "verify-maintenance-acceptance"):
        _fail("contract acceptance stage profile must end with its verifier")
    if _python_release_root(acceptance[1]) != installed_release_root:
        _fail("contract acceptance verifier must run from the installed release")

    early_rollback = document["earlyRollbackCommands"]
    if len(early_rollback) != 2:
        _fail("contract early rollback profile has invalid command count")
    if early_rollback[0][13:] != [
        "restop-maintenance-writers", "--package-root", package_root
    ] or early_rollback[1][13:] != [
        "restore-maintenance-writers", "--package-root", package_root
    ]:
        _fail("contract early rollback profile has invalid command order")
    if any(
        _python_release_root(command) != package_release_root
        for command in early_rollback
    ):
        _fail("contract early rollback must run from the sealed package")

    rollback = document["rollbackCommands"]
    if len(rollback) != 9:
        _fail("contract rollback profile has invalid command count")
    expected_direct = [
        ["/usr/bin/systemctl", "stop", "overseer-api.service", "overseer-runtime.service", "overseer-admin-executor.socket", "overseer-codex-user-bridge.socket"],
        ["/usr/bin/systemctl", "disable", "overseer-api.service", "overseer-runtime.service", "overseer-admin-executor.socket", "overseer-codex-user-bridge.socket"],
        ["/usr/bin/systemctl", "daemon-reload"],
    ]
    if rollback[:3] != expected_direct:
        _fail("contract rollback profile has invalid prerequisite order")
    if rollback[3][13] != "verify-rollback-bundle":
        _fail("contract rollback profile must verify the bundle before restoration")
    if rollback[3][15] != f"{_MAINTENANCE_ROLLBACK_PREFIX}{document['releaseManifestDigest']}":
        _fail("contract rollback verifier has a mismatched bundle root")
    if _python_release_root(rollback[3]) != package_release_root:
        _fail("contract rollback verifier must run from the sealed package")
    if rollback[4][13:] != ["restore-maintenance-store-access", "--package-root", package_root]:
        _fail("contract rollback profile has invalid store restoration order")
    if rollback[5][13:] != ["restore-maintenance-handoff-artifacts", "--package-root", package_root]:
        _fail("contract rollback profile has invalid handoff restoration order")
    if rollback[6] != ["/usr/bin/systemctl", "daemon-reload"]:
        _fail("contract rollback profile has invalid second daemon reload")
    if rollback[7][13:] != ["restore-maintenance-writers", "--package-root", package_root]:
        _fail("contract rollback profile has invalid writer restoration order")
    if rollback[8] != [
        "/usr/bin/curl", "--fail", "--silent", "--show-error",
        "--connect-timeout", "2", "--max-time", "5",
        "http://127.0.0.1:8766/health",
    ]:
        _fail("contract rollback profile must end with the exact health check")
    if any(
        _python_release_root(rollback[index]) != package_release_root
        for index in (4, 5, 7)
    ):
        _fail("contract rollback helpers must run from the sealed package")


def validate_maintenance_contract(contract: Mapping[str, Any]) -> None:
    """Validate the digest-cycle-free contract and raise ``ValueError`` on drift."""

    document = _require_mapping(contract, "contract")
    _reject_secret_bearing_fields(document)
    _require_exact_fields(document, _CONTRACT_FIELDS, "contract")

    if document["schemaVersion"] != MAINTENANCE_CONTRACT_SCHEMA:
        _fail("contract schema does not match maintenance contract schema")
    package_root = _require_canonical_absolute_path(
        document["packageRoot"], "contract.packageRoot"
    )
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
    expected_store_names = tuple(
        name for name, _path in MAINTENANCE_STORE_DESTINATIONS
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
        if store["destinationDb"] != MAINTENANCE_STORE_DESTINATIONS[index][1]:
            _fail("contract store destination is invalid")
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
                "mode",
                "parentDevice",
                "parentInode",
                "parentMode",
            },
            f"contract.storeBindings[{index}].sourceIdentity",
        )
        if any(type(value) is not int or value < 0 for value in identity.values()):
            _fail("contract store source identity is invalid")
        if identity["mode"] != 0o600:
            _fail("contract migrated store source mode is invalid")
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
            "mode",
            "parentDevice",
            "parentInode",
            "parentMode",
        },
        "contract.deferredStoreBindings[0].sourceIdentity",
    )
    if any(type(value) is not int or value < 0 for value in deferred_identity.values()):
        _fail("contract deferred store source identity is invalid")
    if deferred_identity["mode"] not in {0o600, 0o644}:
        _fail("contract deferred store source mode is invalid")
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
        _validate_command_list(
            stage_document["commands"],
            f"contract.stages[{index}].commands",
            package_root,
        )

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

    _validate_command_list(
        document["rollbackCommands"], "contract.rollbackCommands", package_root
    )
    _validate_command_list(
        document["earlyRollbackCommands"],
        "contract.earlyRollbackCommands",
        package_root,
    )
    _validate_maintenance_stage_profiles(document, package_root)
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
