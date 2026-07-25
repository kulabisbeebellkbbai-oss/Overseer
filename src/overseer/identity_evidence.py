"""Read-only identity, access, and secret custody evidence for Odo."""

from __future__ import annotations

import hashlib
from pathlib import Path

from .identity_ops import identity_rotation_requests_status


def identity_evidence_status(project_root: str | Path | None = None, home: str | Path | None = None) -> dict[str, object]:
    root = Path(project_root or Path.cwd())
    home_path = Path(home or Path.home())
    users = _passwd_rows(Path("/etc/passwd"))
    groups = _group_rows(Path("/etc/group"))
    ssh_keys = _ssh_public_keys(home_path)
    secret_candidates = _secret_candidates(root)
    rotation_requests = identity_rotation_requests_status(root)
    return {
        "root": str(root),
        "local_users": len(users),
        "service_accounts": sum(1 for user in users if user["login_shell"] in {"/usr/sbin/nologin", "/bin/false"}),
        "local_groups": len(groups),
        "sudoers_present": Path("/etc/sudoers").exists(),
        "ssh_public_keys": len(ssh_keys),
        "secret_candidates": len(secret_candidates),
        "users": users,
        "groups": groups[:50],
        "ssh_keys": ssh_keys,
        "secret_files": secret_candidates,
        "rotation_reminders": _rotation_reminders(secret_candidates, ssh_keys),
        "rotation_requests": rotation_requests["requests"],
        "mutation_performed": False,
        "host_mutation_performed": False,
    }


def _passwd_rows(path: Path) -> list[dict[str, object]]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    rows = []
    for line in lines:
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        rows.append(
            {
                "user": parts[0],
                "uid": parts[2],
                "gid": parts[3],
                "home": _redact_home(parts[5]),
                "login_shell": parts[6],
                "account_type": "service" if parts[6] in {"/usr/sbin/nologin", "/bin/false"} else "login",
            }
        )
    return rows


def _group_rows(path: Path) -> list[dict[str, object]]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    rows = []
    for line in lines:
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 4:
            rows.append({"group": parts[0], "gid": parts[2], "member_count": len([item for item in parts[3].split(",") if item])})
    return rows


def _ssh_public_keys(home: Path) -> list[dict[str, object]]:
    rows = []
    for path in sorted((home / ".ssh").glob("*.pub")) if (home / ".ssh").exists() else []:
        try:
            text = path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        rows.append(
            {
                "path": f"~/.ssh/{path.name}",
                "fingerprint": f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()[:16]}",
                "kind": text.split()[0] if text.split() else "unknown",
                "status": "review_custody",
            }
        )
    return rows


def _secret_candidates(root: Path) -> list[dict[str, object]]:
    names = (".env", "api-token", "token", "secret", "credential", "credentials", "key")
    rows = []
    for base in (root, root / "state", root / "local-secrets"):
        if not base.exists():
            continue
        for path in sorted(base.glob("**/*")):
            if len(rows) >= 80:
                break
            if path.is_dir():
                continue
            lowered = path.name.lower()
            if lowered in names or any(name in lowered for name in names):
                rows.append({"path": _relative_or_name(root, path), "status": "local_only_review", "content": "[redacted]"})
    return rows


def _rotation_reminders(secret_candidates: list[dict[str, object]], ssh_keys: list[dict[str, object]]) -> list[dict[str, object]]:
    rows = []
    if secret_candidates:
        rows.append({"area": "local secret files", "items": len(secret_candidates), "next_step": "verify ignore rules and rotation owner"})
    if ssh_keys:
        rows.append({"area": "ssh public keys", "items": len(ssh_keys), "next_step": "verify key custody and replacement date"})
    return rows


def _relative_or_name(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return path.name


def _redact_home(value: str) -> str:
    if value in {"/", "/root", "/nonexistent"}:
        return value
    if value.startswith("/home/"):
        return "/home/[user]"
    return value
