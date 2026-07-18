"""Live read-only HTTP health probe adapter."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .adapters import HealthProbeAdapter
from .health import HealthEvidence, HealthTarget, ProbeResult, ProbeType, classify_probe


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
