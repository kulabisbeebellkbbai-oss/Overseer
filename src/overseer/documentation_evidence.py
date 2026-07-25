"""Read-only documentation freshness and coverage evidence for Ezri."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path


REQUIRED_RUNBOOKS = (
    "operator-workflows.md",
    "ui-regression-testing.md",
    "sysops-task-gap-analysis.md",
    "maintenance-and-patch-operations.md",
    "operations-gap-coverage.md",
)


def documentation_evidence_status(project_root: str | Path | None = None, stale_days: int = 90) -> dict[str, object]:
    root = Path(project_root or Path.cwd())
    docs_root = root / "docs"
    docs = sorted(docs_root.glob("*.md")) if docs_root.exists() else []
    runbooks = _runbook_rows(docs_root)
    workflows = _workflow_rows(docs_root / "operator-workflows.md")
    return {
        "root": str(root),
        "docs_root": str(docs_root),
        "docs": len(docs),
        "runbook_coverage": runbooks,
        "workflow_coverage": workflows,
        "stale_documents": _stale_rows(docs, stale_days),
        "adr_index": _index_rows(docs_root, ("adr", "decision")),
        "release_index": _index_rows(docs_root, ("release", "changelog")),
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def _runbook_rows(docs_root: Path) -> list[dict[str, object]]:
    return [
        {
            "runbook": name,
            "present": (docs_root / name).exists(),
            "path": f"docs/{name}",
            "status": "ready" if (docs_root / name).exists() else "missing",
        }
        for name in REQUIRED_RUNBOOKS
    ]


def _workflow_rows(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    headings = re.findall(r"^###\s+(.+)$", text, flags=re.MULTILINE)
    return [
        {
            "workflow": heading.strip(),
            "source": "docs/operator-workflows.md",
            "status": "documented",
        }
        for heading in headings
    ]


def _stale_rows(docs: list[Path], stale_days: int) -> list[dict[str, object]]:
    now = datetime.now(UTC).timestamp()
    threshold = stale_days * 24 * 60 * 60
    rows = []
    for path in docs:
        age_seconds = max(0, now - path.stat().st_mtime)
        if age_seconds >= threshold:
            rows.append(
                {
                    "path": f"docs/{path.name}",
                    "age_days": int(age_seconds / (24 * 60 * 60)),
                    "status": "review",
                }
            )
    return rows


def _index_rows(docs_root: Path, keywords: tuple[str, ...]) -> list[dict[str, object]]:
    if not docs_root.exists():
        return []
    rows = []
    for path in sorted(docs_root.glob("*.md")):
        name = path.name.lower()
        if any(keyword in name for keyword in keywords):
            rows.append({"path": f"docs/{path.name}", "status": "indexed"})
    return rows
