from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class InstallResult:
    project_path: Path
    settings_path: Path
    backup_path: Path
    policy_argument: str
    changes: list[str]

    @property
    def summary(self) -> str:
        lines = [
            "Sentinel Guard Claude Code hook installer",
            f"Project: {self.project_path}",
            f"Settings: {self.settings_path}",
            f"Backup: {self.backup_path}",
            f"Policy: {self.policy_argument}",
            "Changes:",
        ]
        lines.extend(f"- {change}" for change in self.changes)
        return "\n".join(lines)


def load_settings(settings_path: Path) -> tuple[dict[str, Any], bool]:
    if not settings_path.exists():
        return {}, False
    data = json.loads(settings_path.read_text())
    if not isinstance(data, dict):
        raise ValueError(f"{settings_path} must contain a JSON object.")
    return data, True


def policy_argument(project_path: Path, policy_path: Path) -> str:
    if policy_path.is_absolute():
        return str(policy_path)

    project_relative = project_path / policy_path
    if project_relative.exists() or policy_path.name == "sentinel.policy.yaml":
        return str(policy_path)

    return str(policy_path.resolve())


def sentinel_hook(policy_arg: str, task_type: str) -> dict[str, Any]:
    return {
        "type": "command",
        "command": "sentinel-claude-hook",
        "args": [
            "--policy",
            policy_arg,
            "--task",
            task_type,
        ],
    }


def install_claude_code_hook(
    project_path: Path,
    policy_path: Path,
    task_type: str = "coding_agent",
) -> InstallResult:
    project = project_path.resolve()
    claude_dir = project / ".claude"
    settings_path = claude_dir / "settings.json"
    backup_path = claude_dir / "settings.sentinel.backup.json"
    changes: list[str] = []

    claude_dir.mkdir(parents=True, exist_ok=True)
    settings, existed = load_settings(settings_path)
    backup_path.write_text(json.dumps(settings, indent=2) + "\n")
    changes.append("Created .claude/settings.sentinel.backup.json")

    if not existed:
        changes.append("Created .claude/settings.json")

    hooks = settings.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("settings.hooks must be a JSON object when present.")

    pre_tool_use = hooks.setdefault("PreToolUse", [])
    if not isinstance(pre_tool_use, list):
        raise ValueError("settings.hooks.PreToolUse must be a list when present.")

    policy_arg = policy_argument(project, policy_path)
    hook_group = {
        "matcher": "*",
        "hooks": [sentinel_hook(policy_arg, task_type)],
    }

    if hook_group not in pre_tool_use:
        pre_tool_use.append(hook_group)
        changes.append('Added PreToolUse hook with matcher "*"')
    else:
        changes.append('PreToolUse hook with matcher "*" already present')

    settings_path.write_text(json.dumps(settings, indent=2) + "\n")
    changes.append("Wrote .claude/settings.json")

    return InstallResult(
        project_path=project,
        settings_path=settings_path,
        backup_path=backup_path,
        policy_argument=policy_arg,
        changes=changes,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Install Sentinel Guard for Claude Code.")
    parser.add_argument("--project", type=Path, default=Path("."))
    parser.add_argument("--policy", type=Path, default=Path("sentinel.policy.yaml"))
    parser.add_argument("--task", default="coding_agent")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    result = install_claude_code_hook(args.project, args.policy, args.task)
    print(result.summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
