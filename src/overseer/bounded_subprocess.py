"""Small Linux subprocess runner with streaming output and time bounds."""

from __future__ import annotations

import math
import os
import selectors
import signal
import subprocess
import time
from pathlib import Path
from typing import Mapping


class BoundedSubprocessOutputError(ValueError):
    """A child exceeded the approved combined stdout/stderr byte bound."""


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
    try:
        process.wait(timeout=1.0)
    except (OSError, subprocess.TimeoutExpired):
        pass


def run_bounded(
    command: tuple[str, ...],
    *,
    cwd: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    timeout_seconds: float,
    max_output_bytes: int,
) -> subprocess.CompletedProcess[str]:
    """Run one argv without a shell while bounding bytes as pipes are read."""

    if not command or not all(isinstance(item, str) and item for item in command):
        raise ValueError("bounded subprocess command is invalid")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(float(timeout_seconds))
        or timeout_seconds <= 0
    ):
        raise ValueError("bounded subprocess timeout is invalid")
    if (
        isinstance(max_output_bytes, bool)
        or not isinstance(max_output_bytes, int)
        or max_output_bytes <= 0
    ):
        raise ValueError("bounded subprocess output limit is invalid")
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=None if env is None else dict(env),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        start_new_session=True,
    )
    stdout = bytearray()
    stderr = bytearray()
    streams = selectors.DefaultSelector()
    assert process.stdout is not None
    assert process.stderr is not None
    streams.register(process.stdout, selectors.EVENT_READ, stdout)
    streams.register(process.stderr, selectors.EVENT_READ, stderr)
    deadline = time.monotonic() + float(timeout_seconds)
    try:
        while streams.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout_seconds)
            events = streams.select(remaining)
            if not events:
                raise subprocess.TimeoutExpired(command, timeout_seconds)
            for key, _mask in events:
                chunk = os.read(key.fd, min(16 * 1024, max_output_bytes + 1))
                if not chunk:
                    streams.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                target = key.data
                target.extend(chunk)
                if len(stdout) + len(stderr) > max_output_bytes:
                    raise BoundedSubprocessOutputError(
                        "bounded subprocess output exceeds its limit"
                    )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, timeout_seconds)
        returncode = process.wait(timeout=remaining)
    except BaseException:
        _stop_process(process)
        raise
    finally:
        streams.close()
        for stream in (process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()
    return subprocess.CompletedProcess(
        command,
        returncode,
        stdout.decode("utf-8", errors="replace"),
        stderr.decode("utf-8", errors="replace"),
    )
