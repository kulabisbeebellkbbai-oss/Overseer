"""Read-only git status and link helpers for Ezri."""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from .store import SQLiteStore

GIT_STATUS_PROJECTION_ID = "dashboard.git.status"


def git_status_status(
    repo_path: str | Path | None = None,
    account_root: str | Path | None = None,
    *,
    include_account: bool = True,
    command_timeout_seconds: float = 5.0,
) -> dict[str, object]:
    root = Path(repo_path or Path.cwd()).resolve()
    account_base = Path(account_root).resolve() if account_root is not None else root.parent
    current = _repo_status(root, timeout_seconds=command_timeout_seconds)
    account = git_account_status(account_base, current["repo_path"]) if include_account else {
        "root": str(account_base),
        "repositories": [],
        "repository_count": 0,
        "dirty_count": 0,
        "conflicted_count": 0,
        "with_remote_count": 0,
        "source": "scheduled_current_repository_only",
    }
    return {**current, "account": account}


def capture_git_status_projection(
    store_path: str | Path,
    repo_path: str | Path | None = None,
    *,
    timeout_seconds: float = 5.0,
) -> dict[str, object]:
    """Collect one bounded Git snapshot for later dashboard reads."""

    root = Path(repo_path or Path.cwd()).resolve()
    per_command_timeout = max(0.1, min(0.75, float(timeout_seconds) / 10.0))
    try:
        payload = git_status_status(
            root,
            account_root=root.parent,
            include_account=False,
            command_timeout_seconds=per_command_timeout,
        )
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        return {
            "outcome": "failed",
            "failure_category": "unavailable",
            "evidence_ids": (),
            "error": type(error).__name__,
        }
    captured_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    projection_id = f"git.status.{digest[:32]}"
    document = {
        "projection_id": projection_id,
        "captured_at": captured_at,
        "payload": payload,
    }
    try:
        with SQLiteStore(store_path) as store:
            store.save_dashboard_projection(GIT_STATUS_PROJECTION_ID, document)
    except (OSError, ValueError):
        return {
            "outcome": "failed",
            "failure_category": "contract_mismatch",
            "evidence_ids": (),
        }
    return {
        "outcome": "succeeded",
        "evidence_ids": (projection_id,),
        "projection_id": projection_id,
        "captured_at": captured_at,
    }


def git_status_projection_status(
    store_path: str | Path,
    repo_path: str | Path | None = None,
) -> dict[str, object]:
    """Read the latest scheduled Git snapshot without invoking Git."""

    root = Path(repo_path or Path.cwd()).resolve()
    try:
        with SQLiteStore(store_path) as store:
            document = store.load_dashboard_projection(GIT_STATUS_PROJECTION_ID)
        payload = document["payload"]
        if not isinstance(payload, dict):
            raise ValueError("projection payload is invalid")
    except (KeyError, OSError, ValueError):
        return {
            "repo_path": str(root),
            "branch": "unknown",
            "head": "",
            "short_head": "",
            "upstream": None,
            "ahead": None,
            "behind": None,
            "dirty": None,
            "changed": None,
            "staged": None,
            "unstaged": None,
            "untracked": None,
            "conflicted": None,
            "remote": {},
            "links": {},
            "status_lines": [],
            "files": [],
            "account": {"repositories": [], "repository_count": 0},
            "projection_available": False,
            "collection_mode": "durable_sqlite_projection",
            "next_step": "wait for the scheduled Git inspection or request its queued collection job",
        }
    return {
        **payload,
        "projection_available": True,
        "projection_id": str(document.get("projection_id") or ""),
        "captured_at": str(document.get("captured_at") or ""),
        "collection_mode": "durable_sqlite_projection",
    }


def git_account_status(account_root: str | Path, current_repo_path: str | Path | None = None) -> dict[str, object]:
    root = Path(account_root).resolve()
    repos: list[dict[str, object]] = []
    for repo in _discover_git_repositories(root):
        try:
            status = _repo_account_summary(repo)
        except (ValueError, subprocess.SubprocessError):
            continue
        repos.append(
            {
                "name": repo.name,
                "path": str(repo),
                "relative_path": _relative_path(repo, root),
                "branch": status["branch"],
                "upstream": status["upstream"],
                "dirty": status["dirty"],
                "changed": status["changed"],
                "staged": status["staged"],
                "unstaged": status["unstaged"],
                "untracked": status["untracked"],
                "conflicted": status["conflicted"],
                "remote_owner": status["remote_owner"],
                "remote_repo": status["remote_repo"],
                "remote_url": status["remote_url"],
                "links": status["links"],
                "is_current": str(repo.resolve()) == str(Path(current_repo_path).resolve()) if current_repo_path else False,
            }
        )
    repos.sort(key=lambda item: (str(item.get("remote_owner") or ""), str(item.get("name") or "")))
    return {
        "root": str(root),
        "repositories": repos,
        "repository_count": len(repos),
        "dirty_count": sum(1 for repo in repos if repo["dirty"]),
        "conflicted_count": sum(1 for repo in repos if repo["conflicted"]),
        "with_remote_count": sum(1 for repo in repos if repo["remote_url"]),
    }


def _repo_account_summary(root: Path) -> dict[str, object]:
    top_level = _git(root, "rev-parse", "--show-toplevel", timeout=1).stdout.strip()
    if top_level:
        root = Path(top_level)
    branch = _git(root, "branch", "--show-current", timeout=1).stdout.strip() or "detached"
    porcelain = _git(root, "status", "--porcelain=v1", "--branch", timeout=1).stdout.splitlines()
    remote_url = _git(root, "remote", "get-url", "origin", check=False, timeout=1).stdout.strip()
    web_url = _remote_web_url(remote_url)
    owner, repo = _owner_repo(web_url)
    counts = _porcelain_counts(porcelain)
    return {
        "branch": branch,
        "upstream": None,
        "dirty": counts["changed"] > 0,
        "changed": counts["changed"],
        "staged": counts["staged"],
        "unstaged": counts["unstaged"],
        "untracked": counts["untracked"],
        "conflicted": counts["conflicted"],
        "remote_owner": owner,
        "remote_repo": repo,
        "remote_url": web_url or None,
        "links": _links(web_url, branch, ""),
    }


def _repo_status(root: Path, *, timeout_seconds: float = 5.0) -> dict[str, object]:
    top_level = _git(root, "rev-parse", "--show-toplevel", timeout=timeout_seconds).stdout.strip()
    if top_level:
        root = Path(top_level)
    branch = _git(root, "branch", "--show-current", timeout=timeout_seconds).stdout.strip()
    head = _git(root, "rev-parse", "HEAD", timeout=timeout_seconds).stdout.strip()
    short_head = _git(root, "rev-parse", "--short", "HEAD", timeout=timeout_seconds).stdout.strip()
    upstream_result = _git(root, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}", check=False, timeout=timeout_seconds)
    upstream = upstream_result.stdout.strip() if upstream_result.returncode == 0 else ""
    porcelain = _git(root, "status", "--porcelain=v1", "--branch", timeout=timeout_seconds).stdout.splitlines()
    remote_url = _git(root, "remote", "get-url", "origin", check=False, timeout=timeout_seconds).stdout.strip()
    remote = _remote_status(remote_url, branch, head)
    counts = _porcelain_counts(porcelain)
    ahead, behind = _ahead_behind(root, upstream, timeout_seconds=timeout_seconds) if upstream else (None, None)
    links = _links(remote.get("web_url", ""), branch, head)
    status_lines = _safe_status_lines(porcelain)
    return {
        "repo_path": str(root),
        "branch": branch or "detached",
        "head": head,
        "short_head": short_head,
        "upstream": upstream or None,
        "ahead": ahead,
        "behind": behind,
        "dirty": counts["changed"] > 0,
        "changed": counts["changed"],
        "staged": counts["staged"],
        "unstaged": counts["unstaged"],
        "untracked": counts["untracked"],
        "conflicted": counts["conflicted"],
        "remote": remote,
        "links": links,
        "status_lines": status_lines,
        "files": status_lines,
    }


def _discover_git_repositories(root: Path, limit: int = 200) -> list[Path]:
    if not root.exists():
        return []
    repos: list[Path] = []
    stack = [root]
    while stack and len(repos) < limit:
        current = stack.pop()
        if (current / ".git").exists():
            repos.append(current)
            continue
        try:
            children = sorted(current.iterdir(), key=lambda item: item.name, reverse=True)
        except OSError:
            continue
        for child in children:
            if child.name in {".git", "node_modules", ".venv", "venv", "__pycache__", "local-secrets"}:
                continue
            if child.is_dir() and not child.is_symlink():
                stack.append(child)
    return repos


def _relative_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _git(root: Path, *args: str, check: bool = True, timeout: float = 5) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ("git", *args),
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if check and completed.returncode != 0:
        raise ValueError((completed.stderr or completed.stdout or "git command failed").strip())
    return completed


def _remote_status(remote_url: str, branch: str, head: str) -> dict[str, object]:
    web_url = _remote_web_url(remote_url)
    owner, repo = _owner_repo(web_url)
    return {
        "name": "origin" if remote_url else None,
        "url": remote_url or None,
        "web_url": web_url or None,
        "owner": owner,
        "repo": repo,
        "default_branch_guess": branch or None,
        "current_commit_url": f"{web_url}/commit/{head}" if web_url and head else None,
    }


def _remote_web_url(remote_url: str) -> str:
    if not remote_url:
        return ""
    if remote_url.startswith("git@github.com:"):
        path = remote_url.removeprefix("git@github.com:").removesuffix(".git")
        return f"https://github.com/{path}"
    if remote_url.startswith("https://github.com/"):
        return remote_url.removesuffix(".git")
    return remote_url.removesuffix(".git")


def _owner_repo(web_url: str) -> tuple[str | None, str | None]:
    prefix = "https://github.com/"
    if not web_url.startswith(prefix):
        return None, None
    parts = web_url.removeprefix(prefix).split("/")
    if len(parts) < 2:
        return None, None
    return parts[0], parts[1]


def _links(web_url: str, branch: str, head: str) -> dict[str, str | None]:
    if not web_url:
        return {"repository": None, "branch": None, "commit": None, "pulls": None, "actions": None}
    encoded_branch = quote(branch, safe="") if branch else ""
    return {
        "repository": web_url,
        "branch": f"{web_url}/tree/{encoded_branch}" if encoded_branch else None,
        "commit": f"{web_url}/commit/{head}" if head else None,
        "pulls": f"{web_url}/pulls",
        "actions": f"{web_url}/actions",
    }


def _ahead_behind(root: Path, upstream: str, *, timeout_seconds: float = 5.0) -> tuple[int, int]:
    result = _git(root, "rev-list", "--left-right", "--count", f"HEAD...{upstream}", check=False, timeout=timeout_seconds)
    if result.returncode != 0:
        return (0, 0)
    ahead_text, behind_text = result.stdout.strip().split()
    return int(ahead_text), int(behind_text)


def _porcelain_counts(lines: list[str]) -> dict[str, int]:
    counts = {"changed": 0, "staged": 0, "unstaged": 0, "untracked": 0, "conflicted": 0}
    for line in lines:
        if not line or line.startswith("##"):
            continue
        status = line[:2]
        counts["changed"] += 1
        if status == "??":
            counts["untracked"] += 1
            continue
        if status[0] == "U" or status[1] == "U" or status in {"AA", "DD"}:
            counts["conflicted"] += 1
        if status[0] != " ":
            counts["staged"] += 1
        if status[1] != " ":
            counts["unstaged"] += 1
    return counts


def _safe_status_lines(lines: list[str], limit: int = 25) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for line in lines:
        if not line or line.startswith("##"):
            continue
        items.append({"status": line[:2].strip() or "modified", "path": line[3:]})
        if len(items) >= limit:
            break
    return items
