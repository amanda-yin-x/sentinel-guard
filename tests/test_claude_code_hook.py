from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run_hook(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sentinel.integrations.claude_code_hook", *args],
        cwd=ROOT,
        input=stdin,
        capture_output=True,
        text=True,
    )


def hook_output(result: subprocess.CompletedProcess[str]) -> dict:
    return json.loads(result.stdout)


def test_blocked_claude_code_input_produces_deny():
    result = run_hook(
        "--dry-run-json",
        "examples/claude_code/pretooluse_read_env.json",
        "--explain",
    )
    assert result.returncode == 0
    payload = hook_output(result)
    output = payload["hookSpecificOutput"]
    assert output["hookEventName"] == "PreToolUse"
    assert output["permissionDecision"] == "deny"
    assert "blocked_path" in output["permissionDecisionReason"]


def test_allowed_claude_code_input_exits_cleanly_without_stdout():
    result = run_hook(
        "--dry-run-json",
        "examples/claude_code/pretooluse_bash_safe.json",
    )
    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""


def test_malformed_input_fails_safely_with_helpful_error(tmp_path: Path):
    malformed = tmp_path / "bad_hook.json"
    malformed.write_text("{not json")

    result = run_hook("--dry-run-json", str(malformed))
    assert result.returncode == 0
    payload = hook_output(result)
    output = payload["hookSpecificOutput"]
    assert output["permissionDecision"] == "deny"
    assert "malformed_input" in output["permissionDecisionReason"]
    assert "Malformed Claude Code hook JSON" in output["permissionDecisionReason"]


def test_dry_run_json_allowed_explain_outputs_allow():
    result = run_hook(
        "--dry-run-json",
        "examples/claude_code/pretooluse_bash_safe.json",
        "--explain",
    )
    assert result.returncode == 0
    payload = hook_output(result)
    output = payload["hookSpecificOutput"]
    assert output["hookEventName"] == "PreToolUse"
    assert output["permissionDecision"] == "allow"


def test_dangerous_bash_produces_dangerous_shell_deny():
    result = run_hook(
        "--dry-run-json",
        "examples/claude_code/pretooluse_bash_destructive.json",
        "--explain",
    )
    assert result.returncode == 0
    payload = hook_output(result)
    output = payload["hookSpecificOutput"]
    assert output["permissionDecision"] == "deny"
    assert "dangerous_shell" in output["permissionDecisionReason"]
