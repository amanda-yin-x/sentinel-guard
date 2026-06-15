from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from sentinel.ui import DEFAULT_BUILDER, generate_policy_yaml, policy_from_yaml_text


ROOT = Path(__file__).resolve().parents[1]


def test_policy_studio_smoke_test():
    result = subprocess.run(
        [sys.executable, "-m", "sentinel.ui", "--smoke-test"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "Policy Studio smoke test passed" in result.stdout


def test_policy_generation_and_validation():
    policy_yaml = generate_policy_yaml(DEFAULT_BUILDER)
    policy = policy_from_yaml_text(policy_yaml)

    assert "coding_agent" in policy.tasks
    assert "shell_command" in policy.tools
    assert policy.tools["shell_command"]["deny_if_arg_matches"][0]["rule"] == "dangerous_shell"


def test_policy_validation_preserves_temporal_rules():
    policy = policy_from_yaml_text(
        """
tools:
  draft_to_user:
    effect: user_output
  send_email:
    effect: external_write
tasks:
  email_agent:
    allowed_tools: [draft_to_user, send_email]
temporal_rules:
  - id: send_after_draft
    before: send_email
    require_events: [draft_to_user]
"""
    )

    assert policy.temporal_rules == [
        {
            "id": "send_after_draft",
            "before": "send_email",
            "require_events": ["draft_to_user"],
        }
    ]
