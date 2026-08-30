"""Bounded, secret-free progress telemetry for approved activation phases."""

from __future__ import annotations

import json
import re
import sys
from pathlib import PurePosixPath
from typing import Sequence, TextIO


ACTIVATION_PROGRESS_SCHEMA = "overseer.activation-progress.v1"
_PHASES = frozenset({"staging-canary", "cutover"})
_STATUSES = frozenset(
    {
        "phase-started",
        "waiting-for-human-authorization",
        "human-authorization-complete",
        "stage-started",
        "stage-complete",
        "cleanup-started",
        "cleanup-complete",
        "cleanup-failed",
        "evidence-seal-started",
        "evidence-seal-complete",
        "evidence-seal-failed",
        "phase-complete",
    }
)
_STAGES = frozenset(
    {
        "principal-bootstrap",
        "release-install",
        "credential-install",
        "unit-install",
        "canary-store-stage",
        "staging-verification",
        "systemd-reload",
        "runtime-directory-create",
        "human-authorization",
        "canary-socket-start",
        "canary-service-start",
        "canary-health",
        "canary-acceptance",
        "canary-stop",
        "evidence-seal",
        "cleanup",
        "unknown-sealed-command",
    }
)
_BOUNDED_FAILURE = re.compile(r"(?:exit-[0-9]+|[A-Za-z_][A-Za-z0-9_]*)\Z")
_MAX_FAILURE_LENGTH = 128


def _validate_digest(package_digest: object) -> str:
    if not isinstance(package_digest, str) or re.fullmatch(r"[0-9a-f]{64}", package_digest) is None:
        raise ValueError("activation progress package digest is invalid")
    return package_digest


def _validate_failure(failure: object) -> str | None:
    if failure is None:
        return None
    if (
        not isinstance(failure, str)
        or len(failure) > _MAX_FAILURE_LENGTH
        or _BOUNDED_FAILURE.fullmatch(failure) is None
    ):
        raise ValueError("activation progress failure classification is invalid")
    return failure


def emit_activation_progress(
    *,
    package_digest: str,
    phase: str,
    status: str,
    stage: str,
    command_index: int | None = None,
    failure: str | None = None,
    stream: TextIO | None = None,
) -> dict[str, object]:
    """Validate and emit exactly one canonical, secret-free progress record."""

    digest = _validate_digest(package_digest)
    if not isinstance(phase, str) or phase not in _PHASES:
        raise ValueError("activation progress phase is invalid")
    if not isinstance(status, str) or status not in _STATUSES:
        raise ValueError("activation progress status is invalid")
    if not isinstance(stage, str) or stage not in _STAGES:
        raise ValueError("activation progress stage is invalid")
    if command_index is not None and type(command_index) is not int:
        raise ValueError("activation progress command index is invalid")
    bounded_failure = _validate_failure(failure)
    record: dict[str, object] = {
        "schemaVersion": ACTIVATION_PROGRESS_SCHEMA,
        "packageDigest": digest,
        "phase": phase,
        "status": status,
        "stage": stage,
        "commandIndex": command_index,
        "failure": bounded_failure,
        "secretValuesRecorded": False,
    }
    output = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
    destination = sys.stderr if stream is None else stream
    destination.write(output)
    destination.flush()
    return record


def classify_phase_b_command(command: Sequence[str]) -> str:
    """Classify a sealed Phase B argv without returning or emitting its contents."""

    values = tuple(command)
    if not all(isinstance(value, str) for value in values):
        return "unknown-sealed-command"
    basename = PurePosixPath(values[0]).name if values else ""
    if "ensure-dedicated-principal" in values:
        return "principal-bootstrap"
    if "stage-canary-store" in values:
        return "canary-store-stage"
    if "verify-approved-staging" in values:
        return "staging-verification"
    if "run-approved-canary" in values:
        return "canary-acceptance"
    if "handoff-start-canary" in values:
        return "canary-service-start"
    if basename == "systemctl" and "daemon-reload" in values:
        return "systemd-reload"
    if basename == "systemd-tmpfiles":
        return "runtime-directory-create"
    if basename == "curl" and "--unix-socket" in values and any(value.endswith("/health") for value in values):
        return "canary-health"
    if basename == "systemctl" and "start" in values:
        return "canary-socket-start" if any(value.endswith(".socket") for value in values) else "canary-service-start"
    if basename == "systemctl" and "stop" in values:
        return "canary-stop"
    if "cleanup" in values:
        return "cleanup"
    if basename == "install":
        if any("/etc/systemd/system/" in value or "/etc/tmpfiles.d/" in value for value in values):
            return "unit-install"
        if any("/etc/overseer/" in value and "credential" in value for value in values):
            return "credential-install"
        if any(value.startswith("/etc/overseer/") for value in values):
            return "credential-install"
        return "release-install"
    return "unknown-sealed-command"
