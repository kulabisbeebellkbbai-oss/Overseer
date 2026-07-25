"""Read-only software lifecycle evidence for O'Brien."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from datetime import UTC, datetime

from .advisories import advisory_status


def software_evidence_status(store_path: str | Path | None = None) -> dict[str, object]:
    apt_lists = Path("/var/lib/apt/lists")
    advisories = advisory_status(store_path) if store_path else None
    return {
        "package_managers": _package_manager_rows(),
        "apt": {
            "available": shutil.which("apt") is not None,
            "held_packages": _command_lines(("apt-mark", "showhold")),
            "source_count": _apt_source_count(),
            "metadata_files": len(list(apt_lists.glob("*"))) if apt_lists.exists() else 0,
            "metadata_age_days": _metadata_age_days(apt_lists),
            "status": "ready" if shutil.which("apt") else "missing",
        },
        "provenance": _provenance_rows(),
        "release_notes": _release_note_rows(),
        "patch_readiness": _patch_readiness_rows(advisories),
        "advisories": advisories,
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def _package_manager_rows() -> list[dict[str, object]]:
    managers = ("apt", "dpkg-query", "pip", "pip3", "npm", "flatpak", "snap", "cargo")
    return [{"manager": manager, "available": shutil.which(manager) is not None} for manager in managers]


def _provenance_rows() -> list[dict[str, object]]:
    rows = []
    for path in (Path("/etc/apt/sources.list"), Path("/etc/apt/sources.list.d")):
        rows.append(
            {
                "source": str(path),
                "present": path.exists(),
                "status": "review_trust" if path.exists() else "missing",
            }
        )
    return rows


def _patch_readiness_rows(advisories: dict[str, object] | None = None) -> list[dict[str, object]]:
    cve_status = "available" if advisories else "not_configured"
    cve_next_step = "refresh advisory cache before risk scoring packages" if advisories else "add advisory feed adapter before risk scoring packages"
    return [
        {"check": "update plan", "status": "available", "next_step": "use Plan Updates before applying package changes"},
        {"check": "rollback plan", "status": "required", "next_step": "verify rollback notes on each admin plan"},
        {"check": "post-change validation", "status": "required", "next_step": "run service evidence and health probes after execution"},
        {"check": "CVE correlation", "status": cve_status, "next_step": cve_next_step},
    ]


def _release_note_rows() -> list[dict[str, object]]:
    rows = []
    for path in (Path("/usr/share/doc/apt/changelog.gz"), Path("/usr/share/doc/dpkg/changelog.gz")):
        rows.append({"path": str(path), "present": path.exists(), "status": "local_reference" if path.exists() else "missing"})
    return rows


def _metadata_age_days(path: Path) -> int | None:
    if not path.exists():
        return None
    files = [item for item in path.glob("*") if item.is_file()]
    if not files:
        return None
    newest = max(item.stat().st_mtime for item in files)
    return int((datetime.now(UTC).timestamp() - newest) / (24 * 60 * 60))


def _apt_source_count() -> int:
    total = 0
    for path in (Path("/etc/apt/sources.list"),):
        if path.exists():
            total += _non_comment_lines(path)
    sources_dir = Path("/etc/apt/sources.list.d")
    if sources_dir.exists():
        for path in sources_dir.glob("*.list"):
            total += _non_comment_lines(path)
        for path in sources_dir.glob("*.sources"):
            total += _non_comment_lines(path)
    return total


def _non_comment_lines(path: Path) -> int:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return 0
    return len([line for line in lines if line.strip() and not line.strip().startswith("#")])


def _command_lines(command: tuple[str, ...]) -> list[str]:
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=1.5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]
