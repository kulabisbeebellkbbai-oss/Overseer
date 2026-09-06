from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest

from overseer.bounded_subprocess import (
    BoundedSubprocessOutputError,
    run_bounded,
)


def test_bounded_subprocess_stops_while_streaming_oversized_output() -> None:
    with pytest.raises(BoundedSubprocessOutputError, match="exceeds"):
        run_bounded(
            (
                "/usr/bin/python3.13",
                "-c",
                "import os; os.write(1, b'x' * 131072)",
            ),
            timeout_seconds=2.0,
            max_output_bytes=1024,
        )


def test_bounded_subprocess_returns_both_small_streams() -> None:
    result = run_bounded(
        (
            "/usr/bin/python3.13",
            "-c",
            "import os; os.write(1, b'out'); os.write(2, b'err')",
        ),
        timeout_seconds=2.0,
        max_output_bytes=1024,
    )

    assert result.returncode == 0
    assert result.stdout == "out"
    assert result.stderr == "err"


def test_bounded_subprocess_kills_pipe_holding_descendant_after_leader_exit(
    tmp_path: Path,
) -> None:
    pid_file = tmp_path / "descendant.pid"
    command = (
        "/usr/bin/python3.13",
        "-c",
        (
            "import pathlib, subprocess, sys; "
            "child = subprocess.Popen([sys.executable, '-c', "
            "'import time; time.sleep(30)']); "
            "pathlib.Path(sys.argv[1]).write_text(str(child.pid))"
        ),
        str(pid_file),
    )

    with pytest.raises(subprocess.TimeoutExpired):
        run_bounded(
            command,
            timeout_seconds=0.2,
            max_output_bytes=1024,
        )
    descendant_pid = int(pid_file.read_text(encoding="utf-8"))
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        try:
            state = Path(f"/proc/{descendant_pid}/stat").read_text().split()[2]
        except (FileNotFoundError, ProcessLookupError):
            break
        if state == "Z":
            break
        time.sleep(0.01)
    else:
        os.kill(descendant_pid, 0)
        pytest.fail("pipe-holding descendant survived bounded cleanup")
