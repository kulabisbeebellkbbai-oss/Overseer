#!/usr/bin/env python3
"""Narrow routing/evidence guard for Codex account usage questions."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen


DOMAIN = re.compile(
    r"\b(codex\s+(?:usage|quota|limit|capacity|credits?|reset|tokens?|burn)|"
    r"(?:usage|quota|capacity)\s+(?:left|remaining|used)|when\s+does\s+(?:my\s+)?codex\s+reset)\b",
    re.IGNORECASE,
)
EVIDENCE = re.compile(
    r"\b(codex-usage|codex usage mcp|get_usage_summary|get_usage_heuristics|"
    r"get_usage_history|get_source_status|refresh_usage|127\.0\.0\.1:8797)\b",
    re.IGNORECASE,
)


def _payload() -> dict:
    try:
        return json.load(sys.stdin)
    except (json.JSONDecodeError, OSError):
        return {}


def _text(payload: dict) -> str:
    for key in ("prompt", "user_prompt", "message"):
        if isinstance(payload.get(key), str):
            return payload[key]
    return json.dumps(payload, sort_keys=True)


def _transcript(path: str | None) -> tuple[str, str]:
    if not path:
        return "", ""
    user, assistant = [], []
    try:
        for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
            item = json.loads(line)
            payload = item.get("payload", {})
            if item.get("type") != "response_item" or payload.get("type") != "message":
                continue
            text = " ".join(
                part.get("text", "") for part in payload.get("content", []) if isinstance(part, dict)
            )
            if payload.get("role") == "user":
                user.append(text)
            elif payload.get("role") == "assistant":
                assistant.append(text)
    except (OSError, json.JSONDecodeError):
        return "", ""
    return "\n".join(user[-1:]), "\n".join(assistant[-1:])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--stop-check", action="store_true")
    args = parser.parse_args()
    payload = _payload()
    if args.preflight:
        if DOMAIN.search(_text(payload)):
            try:
                with urlopen("http://127.0.0.1:8797/health", timeout=2) as response:
                    healthy = response.status == 200 and json.loads(response.read()).get("status") == "ok"
            except (OSError, URLError, json.JSONDecodeError):
                healthy = False
            if not healthy:
                print(
                    "codex-usage MCP is required but unavailable. Check "
                    "`systemctl --user status overseer-codex-usage-mcp.service` and "
                    "`codex mcp get codex-usage`.",
                    file=sys.stderr,
                )
                return 2
            print(
                json.dumps(
                    {
                        "continue": True,
                        "suppressOutput": True,
                        "systemMessage": (
                            "Use the codex-usage MCP server for this Codex account usage question. "
                            "Include brief server/tool evidence and do not guess undisclosed absolute quota."
                        ),
                    }
                )
            )
        return 0
    user, assistant = _transcript(payload.get("transcript_path"))
    if DOMAIN.search(user) and not EVIDENCE.search(assistant):
        print(
            "codex-usage MCP evidence required: call get_usage_summary, get_usage_heuristics, "
            "get_usage_history, or get_source_status and cite the tool used.",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
