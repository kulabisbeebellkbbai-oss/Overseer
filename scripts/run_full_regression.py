#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = ROOT / "artifacts" / "regression"

SUITES = [
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
    return {
        "name": suite["name"],
        "command": suite["command"],
        "returncode": process.returncode,
        "status": "passed" if process.returncode == 0 else "failed",
        "duration_seconds": round(elapsed, 3),
        "stdout": process.stdout,
        "stderr": process.stderr,
    }


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
            print(result["stdout"])
            print(result["stderr"], file=sys.stderr)

    return 0 if status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
