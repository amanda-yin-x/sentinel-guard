from __future__ import annotations

import json
from pathlib import Path

from sentinel.integrations.claude_code_installer import install_claude_code_hook


def test_installer_writes_settings_and_backup(tmp_path: Path):
    project = tmp_path / "project"
    project.mkdir()
    claude_dir = project / ".claude"
    claude_dir.mkdir()
    settings_path = claude_dir / "settings.json"
    settings_path.write_text(json.dumps({"existing": True}, indent=2))

    result = install_claude_code_hook(
        project_path=project,
        policy_path=Path("sentinel.policy.yaml"),
    )

    assert result.settings_path.exists()
    assert result.backup_path.exists()

    backup = json.loads(result.backup_path.read_text())
    settings = json.loads(result.settings_path.read_text())
    assert backup["existing"] is True
    assert settings["existing"] is True

    pre_tool_use = settings["hooks"]["PreToolUse"]
    hook_group = pre_tool_use[-1]
    assert hook_group["matcher"] == "*"
    assert hook_group["hooks"][0]["command"] == "sentinel-claude-hook"
    assert "--policy" in hook_group["hooks"][0]["args"]
    assert "Added PreToolUse hook" in result.summary
