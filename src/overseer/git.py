"""Read-only git status and link helpers for Ezri."""

from __future__ import annotations

import hashlib
import json
import math
import re
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable
from urllib.parse import quote

from .store import SQLiteStore

GIT_STATUS_PROJECTION_ID = "dashboard.git.status"
_BRIDGE_GIT_FIELDS = frozenset(
    {
        "repository", "branch", "head", "short_head", "upstream",
        "ahead", "behind", "dirty", "changed", "staged", "unstaged",
        "untracked", "conflicted", "remote_owner", "remote_repo",
    }
)
_BRIDGE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
_BRIDGE_REMOTE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_BRIDGE_GIT_OUTPUT_BYTES = 256 * 1024
_BRIDGE_GIT_ENVIRONMENT = {
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_COUNT": "4",
    "GIT_CONFIG_KEY_0": "core.fsmonitor",
    "GIT_CONFIG_VALUE_0": "false",
    "GIT_CONFIG_KEY_1": "core.hooksPath",
    "GIT_CONFIG_VALUE_1": "/dev/null",
    "GIT_CONFIG_KEY_2": "diff.external",
    "GIT_CONFIG_VALUE_2": "",
    "GIT_CONFIG_KEY_3": "credential.helper",
    "GIT_CONFIG_VALUE_3": "",
    "GIT_EXTERNAL_DIFF": "/usr/bin/false",
    "GIT_PAGER": "cat",
    "GIT_TERMINAL_PROMPT": "0",
    "HOME": "/nonexistent",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/bin:/bin",
}


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
    return _persist_git_status_projection(store_path, payload, captured_at=captured_at)


def _persist_git_status_projection(
    store_path: str | Path,
    payload: dict[str, object],
    *,
    captured_at: str,
) -> dict[str, object]:
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


def persist_bridge_git_status_projection(
    store_path: str | Path,
    projection: object,
    *,
    observed_at: object,
) -> dict[str, object]:
    """Persist one fixed-repository Git projection received from the user bridge."""

    try:
        if not isinstance(projection, dict) or set(projection) - _BRIDGE_GIT_FIELDS:
            raise ValueError("bridge Git projection fields are invalid")
        required = {
            "repository", "branch", "head", "short_head", "dirty",
            "changed", "staged", "unstaged", "untracked", "conflicted",
        }
        if not required <= set(projection) or projection.get("repository") != "overseer":
            raise ValueError("bridge Git projection is incomplete")
        branch = projection.get("branch")
        head = projection.get("head")
        short_head = projection.get("short_head")
        upstream = projection.get("upstream")
        if (
            not isinstance(branch, str)
            or _BRIDGE_NAME_RE.fullmatch(branch) is None
            or not isinstance(head, str)
            or len(head) not in {40, 64}
            or any(character not in "0123456789abcdef" for character in head)
            or not isinstance(short_head, str)
            or not 7 <= len(short_head) <= 16
            or any(character not in "0123456789abcdef" for character in short_head)
            or (
                upstream is not None
                and (
                    not isinstance(upstream, str)
                    or _BRIDGE_NAME_RE.fullmatch(upstream) is None
                )
            )
        ):
            raise ValueError("bridge Git identity is invalid")
        counts: dict[str, int] = {}
        for key in ("changed", "staged", "unstaged", "untracked", "conflicted"):
            value = projection.get(key)
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 1_000_000:
                raise ValueError("bridge Git count is invalid")
            counts[key] = value
        dirty = projection.get("dirty")
        if type(dirty) is not bool:
            raise ValueError("bridge Git dirty state is invalid")
        numeric_optional: dict[str, int | None] = {}
        for key in ("ahead", "behind"):
            value = projection.get(key)
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 <= value <= 1_000_000
            ):
                raise ValueError("bridge Git comparison is invalid")
            numeric_optional[key] = value
        owner = projection.get("remote_owner")
        repo = projection.get("remote_repo")
        if (owner is None) != (repo is None):
            raise ValueError("bridge Git remote identity is incomplete")
        if owner is not None and (
            not isinstance(owner, str)
            or not isinstance(repo, str)
            or _BRIDGE_REMOTE_RE.fullmatch(owner) is None
            or _BRIDGE_REMOTE_RE.fullmatch(repo) is None
        ):
            raise ValueError("bridge Git remote identity is invalid")
        if not isinstance(observed_at, str) or len(observed_at) > 256:
            raise ValueError("bridge Git observation time is invalid")
        parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("bridge Git observation time is invalid")
        web_url = f"https://github.com/{owner}/{repo}" if owner is not None else ""
        payload: dict[str, object] = {
            "repo_path": "Overseer",
            "branch": branch,
            "head": head,
            "short_head": short_head,
            "upstream": upstream,
            "ahead": numeric_optional["ahead"],
            "behind": numeric_optional["behind"],
            "dirty": dirty,
            **counts,
            "remote": {
                "name": "origin" if web_url else None,
                "url": None,
                "web_url": web_url or None,
                "owner": owner,
                "repo": repo,
                "default_branch_guess": branch,
                "current_commit_url": f"{web_url}/commit/{head}" if web_url else None,
            },
            "links": _links(web_url, branch, head),
            "status_lines": [],
            "files": [],
            "account": {
                "root": "Overseer",
                "repositories": [],
                "repository_count": 1,
                "dirty_count": 1 if dirty else 0,
                "conflicted_count": 1 if counts["conflicted"] else 0,
                "with_remote_count": 1 if web_url else 0,
                "source": "bounded_user_bridge",
            },
        }
        return _persist_git_status_projection(
            store_path,
            payload,
            captured_at=parsed.astimezone(UTC).isoformat(),
        )
    except (OSError, TypeError, ValueError):
        return {
            "outcome": "failed",
            "failure_category": "contract_mismatch",
            "evidence_ids": (),
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


def _repo_status(
    root: Path,
    *,
    timeout_seconds: float = 5.0,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> dict[str, object]:
    run = runner or _git
    top_level = run(root, "rev-parse", "--show-toplevel", timeout=timeout_seconds).stdout.strip()
    if top_level:
        root = Path(top_level)
    branch = run(root, "branch", "--show-current", timeout=timeout_seconds).stdout.strip()
    head = run(root, "rev-parse", "HEAD", timeout=timeout_seconds).stdout.strip()
    short_head = run(root, "rev-parse", "--short", "HEAD", timeout=timeout_seconds).stdout.strip()
    upstream_result = run(root, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}", check=False, timeout=timeout_seconds)
    upstream = upstream_result.stdout.strip() if upstream_result.returncode == 0 else ""
    porcelain = run(root, "status", "--porcelain=v1", "--branch", timeout=timeout_seconds).stdout.splitlines()
    remote_url = run(root, "remote", "get-url", "origin", check=False, timeout=timeout_seconds).stdout.strip()
    remote = _remote_status(remote_url, branch, head)
    counts = _porcelain_counts(porcelain)
    ahead, behind = _ahead_behind(
        root,
        upstream,
        timeout_seconds=timeout_seconds,
        runner=run,
    ) if upstream else (None, None)
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
        ("/usr/bin/git", *args),
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if check and completed.returncode != 0:
        raise ValueError((completed.stderr or completed.stdout or "git command failed").strip())
    return completed


def _bridge_git(
    root: Path,
    *args: str,
    check: bool = True,
    timeout: float = 0.75,
) -> subprocess.CompletedProcess[str]:
    """Run one fixed local Git read without inherited config or optional locks."""

    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(float(timeout))
        or timeout <= 0
    ):
        raise ValueError("bridge Git timeout is invalid")
    completed = subprocess.run(
        ("/usr/bin/git", "--no-optional-locks", *args),
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=float(timeout),
        stdin=subprocess.DEVNULL,
        env=dict(_BRIDGE_GIT_ENVIRONMENT),
        shell=False,
    )
    if (
        len(completed.stdout.encode("utf-8", errors="replace"))
        + len(completed.stderr.encode("utf-8", errors="replace"))
        > _BRIDGE_GIT_OUTPUT_BYTES
    ):
        raise ValueError("bridge Git output exceeds its bound")
    if check and completed.returncode != 0:
        raise ValueError("bridge Git command failed")
    return completed


def bridge_git_status_status(
    repo_path: str | Path,
    *,
    command_timeout_seconds: float = 0.75,
) -> dict[str, object]:
    """Read the fixed Overseer status under one sealed total Git deadline."""

    root = Path(repo_path).resolve()
    if (
        isinstance(command_timeout_seconds, bool)
        or not isinstance(command_timeout_seconds, (int, float))
        or not math.isfinite(float(command_timeout_seconds))
        or command_timeout_seconds <= 0
    ):
        raise ValueError("bridge Git deadline is invalid")
    deadline = time.monotonic() + float(command_timeout_seconds)

    def bounded(
        selected_root: Path,
        *args: str,
        check: bool = True,
        timeout: float = command_timeout_seconds,
    ) -> subprocess.CompletedProcess[str]:
        del timeout
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired("/usr/bin/git", 0)
        return _bridge_git(
            selected_root,
            *args,
            check=check,
            timeout=remaining,
        )

    status = _repo_status(
        root,
        timeout_seconds=float(command_timeout_seconds),
        runner=bounded,
    )
    if Path(str(status.get("repo_path", ""))).resolve() != root:
        raise ValueError("bridge Git repository root changed")
    return status


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


def _ahead_behind(
    root: Path,
    upstream: str,
    *,
    timeout_seconds: float = 5.0,
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> tuple[int, int]:
    run = runner or _git
    result = run(root, "rev-list", "--left-right", "--count", f"HEAD...{upstream}", check=False, timeout=timeout_seconds)
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
