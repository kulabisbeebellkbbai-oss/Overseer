"""Live read-only HTTP health probe adapter."""

from __future__ import annotations

import json
import shlex
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import parse_qs, urlsplit

from .adapters import HealthProbeAdapter
from .health import HealthEvidence, HealthStatus, HealthTarget, ProbeResult, ProbeType, classify_probe
from .host import CommandRunner, HostCommandObservation, run_read_only_command


class HttpHealthProbeAdapter(HealthProbeAdapter):
    def __init__(self, timeout_seconds: float = 5.0, max_body_bytes: int = 2048) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_body_bytes = max_body_bytes

    def probe(self, target: HealthTarget) -> HealthEvidence:
        started = time.monotonic()
        captured_at = datetime.now(UTC).isoformat()
        request = Request(target.target, headers={"User-Agent": "overseer-health-probe/0.1"})
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                body = response.read(self.max_body_bytes)
                result = ProbeResult(
                    target=target.target,
                    probe_type=target.probe_type,
                    status_code=response.status,
                    content_type=response.headers.get("content-type"),
                    body_summary=_body_summary(target.probe_type, body),
                    latency_ms=_elapsed_ms(started),
                    captured_at=captured_at,
                )
        except HTTPError as error:
            body = error.read(self.max_body_bytes)
            result = ProbeResult(
                target=target.target,
                probe_type=target.probe_type,
                status_code=error.code,
                content_type=error.headers.get("content-type") if error.headers else None,
                body_summary=_body_summary(target.probe_type, body),
                latency_ms=_elapsed_ms(started),
                captured_at=captured_at,
            )
        except (TimeoutError, URLError, OSError) as error:
            result = ProbeResult(
                target=target.target,
                probe_type=target.probe_type,
                error=str(error),
                latency_ms=_elapsed_ms(started),
                captured_at=captured_at,
            )
        return classify_probe(target, result)


class LocalProcessHealthProbeAdapter(HealthProbeAdapter):
    """Read-only process and systemd health probes with injectable command I/O."""

    def __init__(self, command_runner: CommandRunner | None = None, timeout_seconds: float = 5.0) -> None:
        self.command_runner = command_runner or run_read_only_command
        self.timeout_seconds = timeout_seconds

    def probe(self, target: HealthTarget) -> HealthEvidence:
        captured_at = datetime.now(UTC).isoformat()
        observation = self.command_runner(_process_probe_command(target.target), self.timeout_seconds)
        result = ProbeResult(
            target=target.target,
            probe_type=target.probe_type,
            body_summary=_process_body_summary(observation),
            error="" if observation.exit_code == 0 else _process_error(observation),
            captured_at=captured_at,
        )
        if target.target.startswith(("systemd:user:", "systemd:system:")) and observation.stdout.strip() in {"activating", "deactivating"}:
            result = ProbeResult(
                target=target.target,
                probe_type=target.probe_type,
                body_summary=observation.stdout.strip(),
                error=f"systemd unit is {observation.stdout.strip()}",
                captured_at=captured_at,
            )
        return classify_probe(target, result)


class LocalCommandHealthProbeAdapter(HealthProbeAdapter):
    """Read-only command health probes with constrained command shapes."""

    def __init__(self, command_runner: CommandRunner | None = None, timeout_seconds: float = 5.0) -> None:
        self.command_runner = command_runner or run_read_only_command
        self.timeout_seconds = timeout_seconds

    def probe(self, target: HealthTarget) -> HealthEvidence:
        captured_at = datetime.now(UTC).isoformat()
        try:
            command = _command_probe_command(target.target)
        except ValueError as error:
            return classify_probe(
                target,
                ProbeResult(
                    target=target.target,
                    probe_type=target.probe_type,
                    error=str(error),
                    captured_at=captured_at,
                ),
            )
        observation = self.command_runner(command, self.timeout_seconds)
        result = ProbeResult(
            target=target.target,
            probe_type=target.probe_type,
            body_summary=_process_body_summary(observation),
            error="" if observation.exit_code == 0 else _process_error(observation),
            captured_at=captured_at,
        )
        return classify_probe(target, result)


class LocalLogHealthProbeAdapter(HealthProbeAdapter):
    """Read-only log health probes that never persist raw log content."""

    def __init__(self, max_tail_bytes: int = 4096) -> None:
        self.max_tail_bytes = max_tail_bytes

    def probe(self, target: HealthTarget) -> HealthEvidence:
        captured_at = datetime.now(UTC).isoformat()
        try:
            path, contains, absent = _log_probe_target(target.target)
            sample = _read_log_tail(path, self.max_tail_bytes)
            body_summary, error = _classify_log_sample(sample, contains, absent)
        except ValueError as error:
            body_summary = ""
            error = str(error)
        except OSError as error:
            body_summary = ""
            error = f"log read failed: {error.strerror or error}"
        result = ProbeResult(
            target=target.target,
            probe_type=target.probe_type,
            body_summary=body_summary,
            error=error,
            captured_at=captured_at,
        )
        return classify_probe(target, result)


class ManualHealthProbeAdapter(HealthProbeAdapter):
    """Convert explicit operator status targets into health evidence."""

    def probe(self, target: HealthTarget) -> HealthEvidence:
        captured_at = datetime.now(UTC).isoformat()
        try:
            status, error = _manual_probe_target(target.target)
        except ValueError as parse_error:
            status = HealthStatus.FAILED
            error = str(parse_error)
        return HealthEvidence(
            id=f"health.{target.id}.{captured_at.replace(':', '').replace('-', '')}",
            resource_id=target.resource_id,
            target=target.target,
            probe_type=target.probe_type,
            observed_status=status,
            owner_domain=target.owner_domain,
            observed_error=error,
            recovery_required=status in {HealthStatus.DEGRADED, HealthStatus.FAILED, HealthStatus.UNKNOWN},
            captured_at=captured_at,
        )


class RoutedHealthProbeAdapter(HealthProbeAdapter):
    def __init__(self, timeout_seconds: float = 5.0) -> None:
        self.timeout_seconds = timeout_seconds

    def probe(self, target: HealthTarget) -> HealthEvidence:
        return health_probe_adapter_for(target, timeout_seconds=self.timeout_seconds).probe(target)


def health_probe_adapter_for(target: HealthTarget, timeout_seconds: float = 5.0) -> HealthProbeAdapter:
    if target.probe_type == ProbeType.PROCESS:
        return LocalProcessHealthProbeAdapter(timeout_seconds=timeout_seconds)
    if target.probe_type == ProbeType.COMMAND:
        return LocalCommandHealthProbeAdapter(timeout_seconds=timeout_seconds)
    if target.probe_type == ProbeType.LOG:
        return LocalLogHealthProbeAdapter()
    if target.probe_type == ProbeType.MANUAL:
        return ManualHealthProbeAdapter()
    return HttpHealthProbeAdapter(timeout_seconds=timeout_seconds)


def _elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def _body_summary(probe_type: ProbeType, body: bytes) -> str:
    text = body.decode("utf-8", errors="replace").strip()
    if probe_type == ProbeType.JSON:
        try:
            json.loads(text)
        except json.JSONDecodeError as error:
            return f"invalid json: {error.msg}"
    if len(text) > 200:
        return f"{text[:200]}..."
    return text


def _process_probe_command(target: str) -> tuple[str, ...]:
    if target.startswith("systemd:user:"):
        return ("systemctl", "--user", "is-active", target.removeprefix("systemd:user:"))
    if target.startswith("systemd:system:"):
        return ("systemctl", "is-active", target.removeprefix("systemd:system:"))
    if target.startswith("pid:"):
        return ("ps", "-p", target.removeprefix("pid:"), "-o", "pid=")
    return ("pgrep", "-af", target)


def _command_probe_command(target: str) -> tuple[str, ...]:
    command_text = target.removeprefix("command:").strip()
    try:
        command = tuple(shlex.split(command_text))
    except ValueError as error:
        raise ValueError(f"invalid command probe target: {error}") from error
    if _is_read_only_health_command(command):
        return command
    raise ValueError("unsupported command probe target; only read-only health command shapes are allowed")


def _is_read_only_health_command(command: tuple[str, ...]) -> bool:
    if len(command) == 4 and command[:3] == ("systemctl", "--user", "is-active"):
        return bool(command[3].strip())
    if len(command) == 3 and command[:2] == ("systemctl", "is-active"):
        return bool(command[2].strip())
    if len(command) == 3 and command[:2] == ("pgrep", "-af"):
        return bool(command[2].strip())
    if len(command) == 5 and command[0] == "ps" and command[1] == "-p" and command[3:] == ("-o", "pid="):
        return command[2].isdigit()
    if len(command) == 3 and command[:2] == ("test", "-e"):
        return bool(command[2].strip())
    if len(command) == 4 and command[:3] == ("stat", "-c", "%F"):
        return bool(command[3].strip())
    return False


def _log_probe_target(target: str) -> tuple[Path, str | None, str | None]:
    parsed = urlsplit(target)
    if parsed.scheme == "log":
        path = Path(parsed.path)
        query = parse_qs(parsed.query)
    else:
        path = Path(target.removeprefix("log:"))
        query = {}
    contains = _query_one(query, "contains")
    absent = _query_one(query, "absent")
    if contains and absent:
        raise ValueError("log probe target cannot require both contains and absent markers")
    if not path.is_absolute():
        raise ValueError("log probe target path must be absolute")
    return path, contains, absent


def _query_one(query: dict[str, list[str]], key: str) -> str | None:
    values = query.get(key, [])
    if not values:
        return None
    value = values[0]
    return value if value else None


def _read_log_tail(path: Path, max_tail_bytes: int) -> str:
    with path.open("rb") as handle:
        handle.seek(0, 2)
        size = handle.tell()
        handle.seek(max(0, size - max_tail_bytes))
        return handle.read(max_tail_bytes).decode("utf-8", errors="replace")


def _classify_log_sample(sample: str, contains: str | None, absent: str | None) -> tuple[str, str]:
    if contains is not None:
        if contains in sample:
            return "expected log marker found", ""
        return "", "expected log marker not found"
    if absent is not None:
        if absent in sample:
            return "", "blocked log marker found"
        return "blocked log marker absent", ""
    return "log readable", ""


def _manual_probe_target(target: str) -> tuple[HealthStatus, str]:
    parsed = urlsplit(target)
    if parsed.scheme != "manual":
        raise ValueError("manual probe target must start with manual:")
    status_text = parsed.path.strip().lower()
    if not status_text:
        raise ValueError("manual probe target must include a status")
    status = HealthStatus(status_text)
    query = parse_qs(parsed.query)
    error = _query_one(query, "error") or ""
    if status in {HealthStatus.DEGRADED, HealthStatus.FAILED, HealthStatus.UNKNOWN} and not error:
        error = f"manual status recorded: {status.value}"
    return status, error


def _process_body_summary(observation: HostCommandObservation) -> str:
    output = observation.stdout.strip() or observation.stderr.strip()
    if len(output) > 200:
        return f"{output[:200]}..."
    return output


def _process_error(observation: HostCommandObservation) -> str:
    if observation.stderr.strip():
        return observation.stderr.strip()
    if observation.stdout.strip():
        return observation.stdout.strip()
    return f"{' '.join(observation.command)} exited {observation.exit_code}"
