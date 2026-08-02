#!/usr/bin/env python3
"""Install the canonical Overseer project guard at user scope."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--codex-home", type=Path, default=Path.home() / ".codex")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    source = Path(__file__).with_name("overseer_project_guard.py")
    target = args.codex_home.expanduser() / "hooks/overseer_project_guard.py"
    if args.dry_run:
        print(f"would install {source} -> {target}")
        return 0
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    target.chmod(0o755)
    print(f"installed {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
