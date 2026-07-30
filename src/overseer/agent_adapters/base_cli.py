"""Shell-free, allowlisted command execution for CLI adapters."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Sequence
import os
import signal
import subprocess
import tempfile


class CliOutputLimitExceeded(RuntimeError):
    """Raised before oversized provider output is materialized in memory."""


@dataclass(frozen=True)
class CliCommandRunner:
    """Run a provider CLI with a caller-supplied environment and allowlist."""

    executable_path: str | Path
    executable_allowlist: Sequence[str]
    environment: Mapping[str, str]

    def __post_init__(self) -> None:
        allowlist = tuple(self.executable_allowlist)
        if not allowlist or any(not isinstance(item, str) or not item for item in allowlist):
            raise ValueError("executable allowlist must contain executable names")
        configured_path = Path(self.executable_path)
        if not configured_path.is_absolute():
            raise ValueError("executable_path must be absolute")
        canonical_path = configured_path.resolve(strict=True)
        if not canonical_path.is_file() or canonical_path.name not in allowlist and str(
            canonical_path
        ) not in allowlist:
            raise ValueError("executable_path is not allowlisted")
        if not isinstance(self.environment, Mapping) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in self.environment.items()
        ):
            raise TypeError("environment must be a mapping of strings")
        object.__setattr__(self, "executable_path", str(canonical_path))
        object.__setattr__(self, "executable_allowlist", allowlist)
        object.__setattr__(self, "environment", MappingProxyType(dict(self.environment)))

    def run(
        self,
        argv: Sequence[str],
        input_text: str | None = None,
        timeout_seconds: float = 30,
        cwd: str | Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if isinstance(argv, (str, bytes)) or not isinstance(argv, Sequence):
            raise TypeError("argv must be a Sequence[str], not a shell command string")
        command = tuple(argv)
        if not command or any(not isinstance(argument, str) or not argument for argument in command):
            raise ValueError("argv must contain non-empty string arguments")
        if command[0] not in {self.executable_path, Path(self.executable_path).name}:
            raise ValueError("executable is not allowlisted")
        if input_text is not None and not isinstance(input_text, str):
            raise TypeError("input_text must be a string or None")
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be positive")
        working_directory = None
        if cwd is not None:
            configured_cwd = Path(cwd)
            if not configured_cwd.is_absolute():
                raise ValueError("cwd must be absolute")
            working_directory = str(configured_cwd.resolve(strict=True))
            if not Path(working_directory).is_dir():
                raise ValueError("cwd must be a directory")
        return subprocess.run(
            (self.executable_path, *command[1:]),
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=dict(self.environment),
            shell=False,
            check=False,
            cwd=working_directory,
        )

    def run_bounded(
        self,
        argv: Sequence[str],
        input_text: str | None = None,
        timeout_seconds: float = 30,
        cwd: str | Path | None = None,
        *,
        stdout_limit_bytes: int,
        stderr_limit_bytes: int,
    ) -> subprocess.CompletedProcess[str]:
        """Run with output spooled to disk and enforce bounds before reading."""

        command, working_directory = self._validate_invocation(
            argv, input_text, timeout_seconds, cwd
        )
        for value, label in (
            (stdout_limit_bytes, "stdout limit"),
            (stderr_limit_bytes, "stderr limit"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{label} must be a non-negative integer")
        with tempfile.TemporaryFile(mode="w+b") as stdout_file, tempfile.TemporaryFile(
            mode="w+b"
        ) as stderr_file:
            process = subprocess.Popen(
                (self.executable_path, *command[1:]),
                stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                env=dict(self.environment),
                shell=False,
                cwd=working_directory,
                start_new_session=True,
            )
            try:
                process.communicate(
                    input=input_text.encode("utf-8") if input_text is not None else None,
                    timeout=timeout_seconds,
                )
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                raise
            stdout_file.seek(0, os.SEEK_END)
            stderr_file.seek(0, os.SEEK_END)
            stdout_size = stdout_file.tell()
            stderr_size = stderr_file.tell()
            if stdout_size > stdout_limit_bytes:
                raise CliOutputLimitExceeded("provider stdout exceeded configured limit")
            if stderr_size > stderr_limit_bytes:
                raise CliOutputLimitExceeded("provider stderr exceeded configured limit")
            stdout_file.seek(0)
            stderr_file.seek(0)
            return subprocess.CompletedProcess(
                args=(self.executable_path, *command[1:]),
                returncode=process.returncode,
                stdout=stdout_file.read().decode("utf-8", errors="replace"),
                stderr=stderr_file.read().decode("utf-8", errors="replace"),
            )

    def _validate_invocation(
        self,
        argv: Sequence[str],
        input_text: str | None,
        timeout_seconds: float,
        cwd: str | Path | None,
    ) -> tuple[tuple[str, ...], str | None]:
        if isinstance(argv, (str, bytes)) or not isinstance(argv, Sequence):
            raise TypeError("argv must be a Sequence[str], not a shell command string")
        command = tuple(argv)
        if not command or any(
            not isinstance(argument, str) or not argument for argument in command
        ):
            raise ValueError("argv must contain non-empty string arguments")
        if command[0] not in {self.executable_path, Path(self.executable_path).name}:
            raise ValueError("executable is not allowlisted")
        if input_text is not None and not isinstance(input_text, str):
            raise TypeError("input_text must be a string or None")
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be positive")
        working_directory = None
        if cwd is not None:
            configured_cwd = Path(cwd)
            if not configured_cwd.is_absolute():
                raise ValueError("cwd must be absolute")
            working_directory = str(configured_cwd.resolve(strict=True))
            if not Path(working_directory).is_dir():
                raise ValueError("cwd must be a directory")
        return command, working_directory
