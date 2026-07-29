"""Install the Codex Usage MCP skill and enforcement hook at user scope."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path


PLUGIN_NAME = "codex-usage"
SKILL_NAME = "codex-usage-mcp"
HOOK_NAME = "codex-usage-mcp-usage-guard.py"


def _hook(command: str, status: str) -> dict:
    return {
        "type": "command",
        "command": command,
        "timeout": 10,
        "statusMessage": status,
    }


def _merge_hook(config: dict, event: str, hook: dict) -> None:
    groups = config.setdefault("hooks", {}).setdefault(event, [])
    if not groups:
        groups.append({"hooks": []})
    hooks = groups[0].setdefault("hooks", [])
    basename = HOOK_NAME
    hooks[:] = [item for item in hooks if basename not in str(item.get("command", ""))]
    hooks.append(hook)


def install(codex_home: Path, source_root: Path) -> dict:
    plugin_root = source_root / "plugins" / PLUGIN_NAME
    skill_source = plugin_root / "skills" / SKILL_NAME
    hook_source = plugin_root / "hooks" / HOOK_NAME
    skill_target = codex_home / "skills" / SKILL_NAME
    hook_target = codex_home / "hooks" / HOOK_NAME
    plugin_target = codex_home / "plugins" / PLUGIN_NAME

    for target in (skill_target, plugin_target):
        if target.exists():
            shutil.rmtree(target)
    skill_target.parent.mkdir(parents=True, exist_ok=True)
    hook_target.parent.mkdir(parents=True, exist_ok=True)
    plugin_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(skill_source, skill_target)
    shutil.copy2(hook_source, hook_target)
    shutil.copytree(plugin_root, plugin_target)

    hooks_path = codex_home / "hooks.json"
    hooks = json.loads(hooks_path.read_text(encoding="utf-8")) if hooks_path.exists() else {"hooks": {}}
    command = f"python3 {hook_target}"
    _merge_hook(hooks, "UserPromptSubmit", _hook(f"{command} --preflight", "Checking Codex usage MCP routing"))
    _merge_hook(hooks, "Stop", _hook(f"{command} --stop-check", "Checking Codex usage MCP evidence"))
    hooks_path.write_text(json.dumps(hooks, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    skill_bytes = (skill_target / "SKILL.md").read_bytes()
    registry_path = codex_home / "skill-version-registry" / "registry.json"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    timestamp = datetime.now(UTC).isoformat()
    registry.setdefault("skills", {})[SKILL_NAME] = {
        "plugin": PLUGIN_NAME,
        "sha256": hashlib.sha256(skill_bytes).hexdigest(),
        "source": f"plugins/{PLUGIN_NAME}/skills/{SKILL_NAME}/SKILL.md",
        "updated_at": timestamp,
        "version": "0.1.0",
    }
    registry["updated_at"] = timestamp
    registry_path.write_text(json.dumps(registry, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "skill": str(skill_target),
        "hook": str(hook_target),
        "plugin": str(plugin_target),
        "hooks_config": str(hooks_path),
        "registry": str(registry_path),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--codex-home", type=Path, default=Path.home() / ".codex")
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    print(json.dumps(install(args.codex_home.expanduser(), args.source_root.resolve()), sort_keys=True))


if __name__ == "__main__":
    main()
