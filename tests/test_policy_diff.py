from __future__ import annotations

from pathlib import Path

from sentinel.policy_diff import diff_policies, format_policy_diff


def test_policy_diff_reports_task_tool_changes(tmp_path: Path):
    old = tmp_path / "old.yaml"
    new = tmp_path / "new.yaml"
    old.write_text(
        """
tools:
  read_file:
    effect: read
tasks:
  coding_agent:
    allowed_tools: [read_file]
"""
    )
    new.write_text(
        """
tools:
  read_file:
    effect: read
  shell_command:
    effect: local_command
tasks:
  coding_agent:
    allowed_tools: [read_file, shell_command]
"""
    )

    diff = diff_policies(old, new)
    text = format_policy_diff(diff)

    assert diff["tools_added"] == ["shell_command"]
    assert diff["task_changes"][0]["added_tools"] == ["shell_command"]
    assert "shell_command" in text
