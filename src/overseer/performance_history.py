"""Read-only regression and performance history from local artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def performance_history_status(project_root: str | Path, limit: int = 50) -> dict[str, object]:
    root = Path(project_root)
    reports = []
    for path in sorted((root / "artifacts" / "regression").glob("full-regression-*.json"), reverse=True)[: max(1, int(limit))]:
        row = _report_row(root, path)
        if row:
            reports.append(row)
    return {
        "root": str(root),
        "reports": reports,
        "report_count": len(reports),
        "latest": reports[0] if reports else {},
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def _report_row(root: Path, path: Path) -> dict[str, object] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    suites = {str(suite.get("name")): suite for suite in data.get("suites", []) if isinstance(suite, dict)}
    operator = _suite_row(suites.get("operator-performance"))
    functional = _suite_row(suites.get("operator-functional"))
    project = _suite_row(suites.get("project-regression"))
    return {
        "report": _relative_or_name(root, path),
        "status": data.get("status", "unknown"),
        "started_at": data.get("started_at", ""),
        "finished_at": data.get("finished_at", ""),
        "duration_seconds": data.get("duration_seconds", ""),
        "operator_performance_status": operator["status"],
        "operator_performance_seconds": operator["duration_seconds"],
        "operator_functional_seconds": functional["duration_seconds"],
        "project_regression_seconds": project["duration_seconds"],
        "next_step": "investigate failed or slower operator-performance runs" if operator["status"] != "passed" else "compare future regression runs against this baseline",
    }


def _suite_row(suite: dict[str, Any] | None) -> dict[str, object]:
    if not suite:
        return {"status": "missing", "duration_seconds": ""}
    return {
        "status": suite.get("status", "unknown"),
        "duration_seconds": suite.get("duration_seconds", ""),
    }


def _relative_or_name(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name
