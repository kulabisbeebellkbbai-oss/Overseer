"""Explicit one-shot CLI for the signed Psychlo percentage observation."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Callable, Sequence

from .codex_usage import CodexAppServerClient
from .psychlo_usage_meter import (
    MeterAuthority,
    ProviderPercentageMeter,
    ProviderPercentageMeterConfig,
    atomic_publish_observation,
)


_MAX_INPUT_BYTES = 64 * 1024


def _read_private_file(path: Path, name: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"{name} must be an owner-only regular file and not a symlink") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
            raise ValueError(f"{name} must be an owner-only regular file and not a symlink")
        if metadata.st_size <= 0 or metadata.st_size > _MAX_INPUT_BYTES:
            raise ValueError(f"{name} has an invalid size")
        content = bytearray()
        while len(content) <= _MAX_INPUT_BYTES:
            chunk = os.read(descriptor, min(8192, _MAX_INPUT_BYTES + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        if not content or len(content) > _MAX_INPUT_BYTES:
            raise ValueError(f"{name} has an invalid size")
        return bytes(content)
    finally:
        os.close(descriptor)


def _read_private_json(path: Path, name: str) -> dict[str, Any]:
    try:
        value = json.loads(_read_private_file(path, name))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{name} is not valid JSON") from error
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a JSON object")
    return value


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description="Publish one signed Psychlo provider-percentage observation")
    result.add_argument("--authority", type=Path, required=True)
    result.add_argument("--meter-config", type=Path, required=True)
    result.add_argument("--private-key", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    return result


def main(argv: Sequence[str] | None = None, *, client: CodexAppServerClient | None = None, clock: Callable[[], str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        authority = MeterAuthority.from_json(_read_private_json(args.authority, "authority configuration"))
        config = ProviderPercentageMeterConfig.from_json(_read_private_json(args.meter_config, "meter configuration"))
        meter = ProviderPercentageMeter.from_pem(authority, config, _read_private_file(args.private_key, "authority private key"))
        observation = meter.observe((client or CodexAppServerClient()).read_rate_limits(), observed_at=clock() if clock else None)
        atomic_publish_observation(args.output, observation)
    except (OSError, RuntimeError, TimeoutError, ValueError) as error:
        print(json.dumps({"published": False, "error": str(error)}, sort_keys=True), file=sys.stderr)
        return 1
    print(json.dumps({
        "published": True,
        "observationId": observation["observationId"],
        "digest": observation["digest"],
        "output": str(args.output),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
