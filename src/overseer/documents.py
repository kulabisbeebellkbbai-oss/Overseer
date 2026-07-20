"""Secret-safe Obsidian Local REST API helpers for Overseer documents."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


DEFAULT_OBSIDIAN_ENV_FILE = "/home/god/.local/share/overseer/secrets/obsidian-mcp.env"
DEFAULT_ALLOWED_WRITE_PREFIXES = ("Overseer/", "Inbox/")


@dataclass(frozen=True)
class ObsidianDocumentsConfig:
    base_url: str
    api_key: str
    env_file: str = DEFAULT_OBSIDIAN_ENV_FILE
    allowed_write_prefixes: tuple[str, ...] = DEFAULT_ALLOWED_WRITE_PREFIXES


def documents_config_status(env_file: str = DEFAULT_OBSIDIAN_ENV_FILE) -> dict[str, Any]:
    try:
        config = load_obsidian_documents_config(env_file)
    except ValueError as error:
        return {
            "configured": False,
            "available": False,
            "env_file": env_file,
            "error": str(error),
        }
    status = ObsidianDocumentsClient(config).status()
    return {
        **status,
        "configured": True,
        "env_file": env_file,
        "base_url": _redacted_base_url(config.base_url),
        "allowed_write_prefixes": list(config.allowed_write_prefixes),
    }


def documents_list_notes_status(
    env_file: str = DEFAULT_OBSIDIAN_ENV_FILE,
    folder: str = "",
) -> dict[str, Any]:
    config = load_obsidian_documents_config(env_file)
    return ObsidianDocumentsClient(config).list_notes(folder)


def documents_search_status(
    env_file: str = DEFAULT_OBSIDIAN_ENV_FILE,
    query: str = "",
    context_length: int = 100,
) -> dict[str, Any]:
    config = load_obsidian_documents_config(env_file)
    return ObsidianDocumentsClient(config).search(query, context_length)


def documents_write_note_status(
    env_file: str = DEFAULT_OBSIDIAN_ENV_FILE,
    path: str = "",
    content: str = "",
    mode: str = "append",
) -> dict[str, Any]:
    config = load_obsidian_documents_config(env_file)
    return ObsidianDocumentsClient(config).write_note(path, content, mode)


def load_obsidian_documents_config(env_file: str = DEFAULT_OBSIDIAN_ENV_FILE) -> ObsidianDocumentsConfig:
    values = _read_env_file(env_file)
    base_url = (values.get("OBSIDIAN_BASE_URL") or os.environ.get("OBSIDIAN_BASE_URL") or "").strip()
    api_key = (values.get("OBSIDIAN_API_KEY") or os.environ.get("OBSIDIAN_API_KEY") or "").strip()
    if not base_url:
        raise ValueError("OBSIDIAN_BASE_URL is not configured")
    if not api_key:
        raise ValueError("OBSIDIAN_API_KEY is not configured")
    if not (base_url.startswith("http://127.0.0.1:") or base_url.startswith("http://localhost:") or base_url.startswith("https://127.0.0.1:") or base_url.startswith("https://localhost:")):
        raise ValueError("Obsidian Documents API must remain loopback-bound")
    return ObsidianDocumentsConfig(base_url=base_url.rstrip("/"), api_key=api_key, env_file=env_file)


class ObsidianDocumentsClient:
    def __init__(self, config: ObsidianDocumentsConfig, timeout: float = 5.0) -> None:
        self.config = config
        self.timeout = timeout

    def status(self) -> dict[str, Any]:
        try:
            response = self._request_json("GET", "/")
        except ValueError as error:
            return {"available": False, "authenticated": False, "error": str(error)}
        return {
            "available": response.get("status") == "OK" or response.get("ok") == "OK",
            "authenticated": bool(response.get("authenticated")),
            "service": response.get("service"),
            "versions": response.get("versions", {}),
            "manifest": _safe_manifest(response.get("manifest", {})),
        }

    def list_notes(self, folder: str = "") -> dict[str, Any]:
        normalized_folder = _normalize_folder(folder)
        suffix = f"/{quote(normalized_folder, safe='/')}" if normalized_folder else ""
        response = self._request_json("GET", f"/vault{suffix}/")
        files = [str(item) for item in response.get("files", [])]
        return {"folder": normalized_folder, "count": len(files), "files": files}

    def search(self, query: str, context_length: int = 100) -> dict[str, Any]:
        query = query.strip()
        if not query:
            raise ValueError("query is required")
        if context_length < 0:
            raise ValueError("context_length must be non-negative")
        params = urlencode({"query": query, "contextLength": str(context_length)})
        results = self._request_json("POST", f"/search/simple/?{params}", body=b"")
        if not isinstance(results, list):
            raise ValueError("unexpected Obsidian search response")
        return {"query": query, "count": len(results), "results": results}

    def write_note(self, path: str, content: str, mode: str = "append") -> dict[str, Any]:
        normalized_path = _validate_note_path(path, self.config.allowed_write_prefixes)
        if mode not in {"append", "replace"}:
            raise ValueError("mode must be append or replace")
        if not content.strip():
            raise ValueError("content is required")
        method = "POST" if mode == "append" else "PUT"
        self._request_text(method, f"/vault/{quote(normalized_path, safe='/')}", body=content.encode("utf-8"))
        return {"path": normalized_path, "mode": mode, "mutation_performed": True, "host_mutation_performed": False}

    def _request_json(self, method: str, path: str, body: bytes | None = None) -> Any:
        text = self._request_text(method, path, body)
        try:
            return json.loads(text or "{}")
        except json.JSONDecodeError as error:
            raise ValueError("Obsidian returned invalid JSON") from error

    def _request_text(self, method: str, path: str, body: bytes | None = None) -> str:
        headers = {"Authorization": f"Bearer {self.config.api_key}"}
        if body is not None:
            headers["Content-Type"] = "text/markdown; charset=utf-8"
        request = Request(f"{self.config.base_url}{path}", data=body, headers=headers, method=method)
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return response.read().decode("utf-8")
        except HTTPError as error:
            detail = error.read().decode("utf-8", "replace")
            raise ValueError(f"Obsidian request failed: HTTP {error.code} {detail}".strip()) from error
        except URLError as error:
            raise ValueError(f"Obsidian is unavailable: {error.reason}") from error


def _read_env_file(path: str) -> dict[str, str]:
    if not os.path.exists(path):
        return {}
    values: dict[str, str] = {}
    with open(path, encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _normalize_folder(folder: str) -> str:
    folder = folder.strip().replace("\\", "/").strip("/")
    if not folder:
        return ""
    path = PurePosixPath(folder)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("folder must be vault-relative")
    return str(path)


def _validate_note_path(path: str, allowed_prefixes: tuple[str, ...]) -> str:
    normalized = path.strip().replace("\\", "/").lstrip("/")
    note_path = PurePosixPath(normalized)
    if not normalized or note_path.is_absolute() or ".." in note_path.parts:
        raise ValueError("path must be vault-relative")
    if not normalized.endswith(".md"):
        raise ValueError("path must end in .md")
    if not any(normalized.startswith(prefix) for prefix in allowed_prefixes):
        raise ValueError("path is outside allowed Documents write folders")
    return normalized


def _safe_manifest(manifest: object) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        return {}
    return {key: manifest.get(key) for key in ("id", "name", "version", "isDesktopOnly", "dir") if key in manifest}


def _redacted_base_url(base_url: str) -> str:
    return base_url.replace("localhost", "127.0.0.1")
