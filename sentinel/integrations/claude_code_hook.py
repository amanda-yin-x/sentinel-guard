from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import replace
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from sentinel.audit import append_decision
from sentinel.monitor import PermissionMonitor
from sentinel.policy import Policy
from sentinel.types import Artifact, Decision, TaskContext, ToolCall


DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[2] / "policy.yaml"
SENSITIVE_TEXT_RE = re.compile(
    r"(\.env|secret|secrets|credential|credentials|token|private|private_notes|id_rsa|ssh_key)",
    re.IGNORECASE,
)


class ClaudeHookInputError(ValueError):
    """Raised when Claude Code hook input cannot be parsed safely."""


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sentinel Claude Code PreToolUse hook adapter.")
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY_PATH)
    parser.add_argument("--task", default="coding_agent")
    parser.add_argument("--explain", action="store_true")
    parser.add_argument("--dry-run-json", type=Path, help="Read hook input from a JSON fixture.")
    return parser.parse_args(argv)


def read_hook_payload(args: argparse.Namespace) -> dict[str, Any]:
    try:
        raw_input = args.dry_run_json.read_text() if args.dry_run_json else sys.stdin.read()
    except OSError as exc:
        raise ClaudeHookInputError(f"Could not read hook input: {exc}") from exc

    if not raw_input.strip():
        raise ClaudeHookInputError("Expected Claude Code PreToolUse JSON on stdin.")

    try:
        payload = json.loads(raw_input)
    except JSONDecodeError as exc:
        raise ClaudeHookInputError(
            f"Malformed Claude Code hook JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc

    if not isinstance(payload, dict):
        raise ClaudeHookInputError("Claude Code hook input must be a JSON object.")
    return payload


def labels_for_text(value: object) -> frozenset[str]:
    text = json.dumps(value, sort_keys=True) if not isinstance(value, str) else value
    labels: set[str] = set()
    if SENSITIVE_TEXT_RE.search(text):
        labels.add("private")
    if re.search(r"(\.env|secret|token|credential|id_rsa|ssh_key)", text, re.IGNORECASE):
        labels.add("secret")
    return frozenset(labels)


def add_input_artifact(
    monitor: PermissionMonitor,
    labels: frozenset[str],
    artifact_id: str = "claude_tool_input",
) -> frozenset[str]:
    if not labels:
        return frozenset()

    monitor.artifacts[artifact_id] = Artifact(
        artifact_id=artifact_id,
        value="Claude Code tool input metadata.",
        labels=labels,
        source_tool="claude_code_hook",
    )
    return frozenset({artifact_id})


def map_claude_tool(
    payload: dict[str, Any],
    monitor: PermissionMonitor,
) -> ToolCall:
    tool_name = payload.get("tool_name")
    tool_input = payload.get("tool_input", {})
    if not isinstance(tool_name, str) or not tool_name:
        raise ClaudeHookInputError("Claude Code input must include a non-empty tool_name.")
    if not isinstance(tool_input, dict):
        raise ClaudeHookInputError("Claude Code input tool_input must be an object.")

    labels = labels_for_text(tool_input)

    if tool_name == "Bash":
        command = tool_input.get("command", "")
        return ToolCall(
            "shell_command",
            {"command": command, "claude_tool": tool_name},
        )

    if tool_name == "Read":
        path = tool_input.get("file_path") or tool_input.get("path")
        return ToolCall(
            "read_file",
            {"path": path, "claude_tool": tool_name},
        )

    if tool_name == "Write":
        return ToolCall(
            "write_file",
            {"path": tool_input.get("file_path"), "claude_tool": tool_name},
        )

    if tool_name in {"Edit", "MultiEdit"}:
        return ToolCall(
            "edit_file",
            {"path": tool_input.get("file_path"), "claude_tool": tool_name},
        )

    if tool_name == "WebFetch":
        derived_from = add_input_artifact(monitor, labels)
        return ToolCall(
            "web_fetch",
            {
                "url": tool_input.get("url"),
                "prompt": tool_input.get("prompt", ""),
                "claude_tool": tool_name,
            },
            derived_from=derived_from,
        )

    if tool_name == "WebSearch":
        derived_from = add_input_artifact(monitor, labels)
        return ToolCall(
            "web_search",
            {"query": tool_input.get("query", ""), "claude_tool": tool_name},
            derived_from=derived_from,
        )

    if tool_name.startswith("mcp__"):
        derived_from = add_input_artifact(monitor, labels)
        return ToolCall(
            "mcp_tool",
            {"claude_tool": tool_name, "tool_input": tool_input},
            derived_from=derived_from,
        )

    return ToolCall(
        tool_name,
        {"claude_tool": tool_name, "tool_input": tool_input},
        derived_from=add_input_artifact(monitor, labels),
    )


def metadata_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        key: payload[key]
        for key in ("hook_event_name", "session_id", "transcript_path", "cwd", "tool_name")
        if key in payload
    }


def decision_with_metadata(decision: Decision, payload: dict[str, Any]) -> Decision:
    trace_context = dict(decision.trace_context)
    trace_context["claude_code"] = metadata_from_payload(payload)
    return replace(decision, trace_context=trace_context)


def run_monitor(policy_path: Path, task_type: str, payload: dict[str, Any]) -> Decision:
    policy = Policy.from_yaml(policy_path)
    monitor = PermissionMonitor(policy)
    context = TaskContext(
        task_type=task_type,
        user_goal=f"Claude Code PreToolUse check for task '{task_type}'.",
        user_confirmed=False,
    )
    call = map_claude_tool(payload, monitor)
    return decision_with_metadata(monitor.check(call, context), payload)


def claude_decision(permission_decision: str, reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": permission_decision,
            "permissionDecisionReason": reason,
        }
    }


def print_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2))


def run(args: argparse.Namespace) -> int:
    try:
        payload = read_hook_payload(args)
        decision = run_monitor(args.policy, args.task, payload)
    except (ClaudeHookInputError, ValueError, OSError) as exc:
        print_json(
            claude_decision(
                "deny",
                f"Blocked by Sentinel: malformed_input - {exc}",
            )
        )
        return 0

    append_decision(decision, source="claude_code_hook")

    if not decision.allowed:
        print_json(
            claude_decision(
                "deny",
                f"Blocked by Sentinel: {decision.rule} - {decision.reason}",
            )
        )
        return 0

    if args.explain:
        print_json(
            claude_decision(
                "allow",
                f"Allowed by Sentinel: {decision.rule} - {decision.reason}",
            )
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    return run(parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
