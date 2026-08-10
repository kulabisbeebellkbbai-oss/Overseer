"""Scheduled Psychlo bridge operations."""

from __future__ import annotations

import argparse
import json
import os

from .codex_usage import CodexUsageTracker
from .psychlo_bridge import create_bridge_from_environment


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one bounded Psychlo bridge operation")
    subparsers = parser.add_subparsers(dest="command", required=True)
    emit = subparsers.add_parser("emit-usage")
    emit.add_argument("--usage-db", default=os.environ.get("OVERSEER_CODEX_USAGE_DB", "/home/god/.local/share/overseer/codex-usage-mcp/state.sqlite3"))
    emit.add_argument("--policy-version", default=os.environ.get("OVERSEER_PSYCHLO_POLICY_VERSION", "2026-08-09"))
    sync = subparsers.add_parser("sync-projects")
    sync.add_argument("--handoff-file", default=os.environ.get("OVERSEER_A_TEAM_HANDOFF_FILE", "/home/god/Documents/Codex Workspace/The A-Team/data/handoffs.json"))
    args = parser.parse_args(argv)
    if args.command == "emit-usage":
        bridge = create_bridge_from_environment()
        history = CodexUsageTracker(args.usage_db).history(1000)
        result = bridge.emit_usage(history, args.policy_version)
        print(json.dumps({"accepted": result.get("accepted") is True}, sort_keys=True))
        return 0
    if args.command == "sync-projects":
        bridge = create_bridge_from_environment()
        with open(args.handoff_file, encoding="utf-8") as handle:
            payload = json.load(handle)
        records = payload.get("records", []) if isinstance(payload, dict) else []
        synchronized = 0
        for record in records:
            if not isinstance(record, dict) or record.get("state") != "delivered" or not isinstance(record.get("receipt"), dict):
                continue
            bridge.register_project({"envelope": record.get("envelope"), "receipt": record["receipt"]})
            synchronized += 1
        print(json.dumps({"accepted": True, "synchronized": synchronized}, sort_keys=True))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
