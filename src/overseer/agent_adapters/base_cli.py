"""Shell-free, allowlisted command execution for CLI adapters."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Sequence
import subprocess


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
        return subprocess.run(
            (self.executable_path, *command[1:]),
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=dict(self.environment),
            shell=False,
            check=False,
        )
