#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = ROOT / "artifacts" / "regression"
MAX_DIAGNOSTIC_LINES = 12
MAX_DIAGNOSTIC_LINE_CHARS = 240
MAX_RESULT_JSON_CHARS = 12_000
MAX_COMMAND_ARGUMENTS = 32

_SENSITIVE_ARGUMENT_FLAGS = {
    "--api-key",
    "--authorization",
    "--cookie",
    "--password",
    "--prompt",
    "--token",
    "--workspace",
}
_SENSITIVE_LINE_RE = re.compile(
    r"(?i)(authorization|bearer|cookie|password|api[_-]?key|secret|token|prompt|workspace)"
)
_PRIVATE_PATH_RE = re.compile(r"(?:/home|/Users)/[^\s\"']+")
_PYTEST_COUNT_RE = re.compile(
    r"\b(\d+)\s+(passed|failed|skipped|deselected|xfailed|xpassed|errors?)\b"
)

SUITES = [
    {
        "name": "provider-neutral-agent",
        "command": [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-m",
            "not live_agent",
            "tests/test_agent_contracts.py",
            "tests/test_agent_registry.py",
            "tests/test_agent_store.py",
            "tests/test_agent_handoff.py",
            "tests/test_agent_manager.py",
            "tests/test_agent_operations.py",
            "tests/test_agent_failover.py",
            "tests/test_agent_adapter_contract.py",
            "tests/test_agent_api.py",
            "tests/test_agent_migration.py",
        ],
    },
    {
        "name": "operator-functional",
        "command": [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "tests/test_ui_regression.py",
            "tests/test_ui_full_regression.py",
            "tests/test_operator_workflow_regression.py",
            "tests/test_operations_gap_coverage.py",
        ],
    },
    {
        "name": "operator-performance",
        "command": [sys.executable, "-m", "pytest", "-q", "tests/test_performance_regression.py"],
    },
    {
        "name": "project-regression",
        "command": [sys.executable, "-m", "pytest", "-q"],
    },
]


def _sanitize_command(argv: object) -> list[str]:
    if not isinstance(argv, (list, tuple)):
        return ["[INVALID_COMMAND]"]
    safe: list[str] = []
    redact_next = False
    for index, raw in enumerate(argv[:MAX_COMMAND_ARGUMENTS]):
        value = str(raw)
        if redact_next:
            safe.append("[REDACTED]")
            redact_next = False
            continue
        flag = value.casefold().split("=", 1)[0]
        if flag in _SENSITIVE_ARGUMENT_FLAGS:
            safe.append(flag)
            if "=" in value:
                safe[-1] = f"{flag}=[REDACTED]"
            else:
                redact_next = True
            continue
        if index == 0 and Path(value).is_absolute():
            safe.append(Path(value).name)
            continue
        if _PRIVATE_PATH_RE.search(value):
            safe.append("[REDACTED_PATH]")
            continue
        safe.append(value[:MAX_DIAGNOSTIC_LINE_CHARS])
    if len(argv) > MAX_COMMAND_ARGUMENTS:
        safe.append("[TRUNCATED_ARGUMENTS]")
    return safe


def _test_counts(output: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for count, label in _PYTEST_COUNT_RE.findall(output):
        normalized = "error" if label == "errors" else label
        counts[normalized] = max(counts.get(normalized, 0), int(count))
    return counts


def _redacted_diagnostic_lines(output: str) -> list[str]:
    lines: list[str] = []
    in_private_key = False
    for raw in output.splitlines():
        if re.search(r"BEGIN [^-]*PRIVATE KEY", raw):
            in_private_key = True
            if "[REDACTED_PRIVATE_KEY]" not in lines:
                lines.append("[REDACTED_PRIVATE_KEY]")
            continue
        if in_private_key:
            if re.search(r"END [^-]*PRIVATE KEY", raw):
                in_private_key = False
            continue
        if _SENSITIVE_LINE_RE.search(raw):
            value = "[REDACTED_SENSITIVE_LINE]"
        else:
            value = _PRIVATE_PATH_RE.sub("[REDACTED_PATH]", raw)
            value = value[:MAX_DIAGNOSTIC_LINE_CHARS]
        if value and value not in lines:
            lines.append(value)
        if len(lines) >= MAX_DIAGNOSTIC_LINES:
            break
    return lines


def _failure_diagnostic(stdout: str, stderr: str) -> dict[str, object]:
    combined = "\n".join(part for part in (stdout, stderr) if part)
    counts = _test_counts(combined)
    classification = (
        "test_failure"
        if counts.get("failed", 0) or counts.get("error", 0)
        else "command_failure"
    )
    return {
        "classification": classification,
        "stdout_sha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr.encode("utf-8")).hexdigest(),
        "redacted_lines": _redacted_diagnostic_lines(combined),
        "truncated": len(combined.splitlines()) > MAX_DIAGNOSTIC_LINES,
    }


def _run_suite(suite: dict[str, object]) -> dict[str, object]:
    start = time.perf_counter()
    process = subprocess.run(
        suite["command"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    elapsed = time.perf_counter() - start
    combined_output = "\n".join((process.stdout, process.stderr))
    result: dict[str, object] = {
        "name": str(suite["name"])[:80],
        "command": _sanitize_command(suite["command"]),
        "returncode": process.returncode,
        "status": "passed" if process.returncode == 0 else "failed",
        "duration_seconds": round(elapsed, 3),
        "test_counts": _test_counts(combined_output),
    }
    if process.returncode != 0:
        result["diagnostic"] = _failure_diagnostic(process.stdout, process.stderr)
    if len(json.dumps(result)) > MAX_RESULT_JSON_CHARS:
        result["command"] = ["[TRUNCATED_COMMAND]"]
        diagnostic = result.get("diagnostic")
        if isinstance(diagnostic, dict):
            diagnostic["redacted_lines"] = ["[REDACTED_DIAGNOSTIC_TRUNCATED]"]
            diagnostic["truncated"] = True
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Overseer's full local regression package.")
    parser.add_argument("--output", type=Path, help="Write the JSON report to this path.")
    args = parser.parse_args()

    started = datetime.now(timezone.utc)
    output_path = args.output
    if output_path is None:
        DEFAULT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        stamp = started.strftime("%Y%m%dT%H%M%SZ")
        output_path = DEFAULT_OUTPUT_DIR / f"full-regression-{stamp}.json"
    else:
        output_path.parent.mkdir(parents=True, exist_ok=True)

    results = [_run_suite(suite) for suite in SUITES]
    status = "passed" if all(result["returncode"] == 0 for result in results) else "failed"
    finished = datetime.now(timezone.utc)
    report = {
        "schema": "overseer.local-regression.result.v1",
        "status": status,
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "duration_seconds": round(sum(result["duration_seconds"] for result in results), 3),
        "suites": results,
    }
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(f"status: {status}")
    print(f"report: {output_path}")
    for result in results:
        print(f"{result['name']}: {result['status']} ({result['duration_seconds']}s)")
        if result["returncode"] != 0:
            diagnostic = result.get("diagnostic") or {}
            print(
                f"failure: {diagnostic.get('classification', 'command_failure')}",
                file=sys.stderr,
            )
            for line in diagnostic.get("redacted_lines", ()):
                print(line, file=sys.stderr)

    return 0 if status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
