from __future__ import annotations

from pathlib import Path

from sentinel.risk_scan import scan_project


def test_risk_scan_flags_unrestricted_shell_policy(tmp_path: Path):
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
tools:
  read_file:
    effect: read
    returns_labels: [private]
  shell_command:
    effect: local_command
    returns_labels: [public]
tasks:
  coding_agent:
    allowed_tools: [read_file, shell_command]
"""
    )

    findings = scan_project(tmp_path)
    messages = [finding.message for finding in findings]

    assert any("Bash/shell command is allowed without command restrictions" in message for message in messages)
    assert any(".env/private-key paths" in message for message in messages)
