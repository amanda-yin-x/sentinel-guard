from __future__ import annotations

from pathlib import Path

from sentinel.monitor import PermissionMonitor
from sentinel.policy import Policy
from sentinel.policy_synthesizer import synthesize_policy, write_synthesized_policy
from sentinel.types import TaskContext, ToolCall


def test_read_only_task_denies_write_and_edit():
    profile = synthesize_policy("Summarize this repo and run tests, but do not edit files.")
    assert "write_file" in profile.denied_tools
    assert "edit_file" in profile.denied_tools
    assert "shell_command" in profile.allowed_tools


def test_test_task_allows_only_test_like_bash_commands():
    profile = synthesize_policy("Summarize this repo and run tests, but do not edit files.")
    policy = Policy(**{key: profile.to_policy_dict()[key] for key in ("tools", "tasks")})
    monitor = PermissionMonitor(policy)
    context = TaskContext(task_type=profile.task_type, user_goal=profile.task)

    allowed = monitor.check(ToolCall("shell_command", {"command": "pytest -q"}), context)
    blocked = monitor.check(ToolCall("shell_command", {"command": "python deploy.py"}), context)

    assert allowed.allowed
    assert not blocked.allowed
    assert blocked.rule == "bash_command_not_allowed"


def test_delete_and_deploy_tasks_require_confirmation():
    delete_profile = synthesize_policy("Delete temporary files.")
    deploy_profile = synthesize_policy("Deploy the app.")

    assert "delete_file" in delete_profile.confirmation_required
    assert "shell_command" in delete_profile.confirmation_required
    assert "shell_command" in deploy_profile.confirmation_required
    assert "web_fetch" in deploy_profile.confirmation_required


def test_email_draft_denies_send_unless_explicit_send_requested():
    draft_only = synthesize_policy("Review this email and draft a reply, but do not send anything.")
    send_allowed = synthesize_policy("Review this email and send the reply after approval.")

    assert "send_email" in draft_only.denied_tools
    assert "send_email" in send_allowed.allowed_tools


def test_write_synthesized_policy(tmp_path: Path):
    out = tmp_path / "generated.policy.yaml"
    profile = write_synthesized_policy("Fix the failing test, but ask before editing files.", out)

    assert out.exists()
    assert "confirmation_required" in out.read_text()
    assert "edit_file" in profile.confirmation_required
