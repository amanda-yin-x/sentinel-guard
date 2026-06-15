from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


ALL_TOOLS = [
    "read_email",
    "read_file",
    "shell_command",
    "write_file",
    "edit_file",
    "summarize_to_user",
    "draft_to_user",
    "send_email",
    "web_request",
    "web_fetch",
    "web_search",
    "mcp_tool",
    "delete_file",
]
EXTERNAL_SINKS = {"send_email", "web_request", "web_fetch", "web_search", "mcp_tool"}
PROTECTED_LABELS = ["private", "secret", "untrusted"]
BLOCKED_PATH_PATTERNS = [".env", "*.env", "*.env.*", "*secret*", "*credential*", "*id_rsa*", "*ssh_key*"]
DANGEROUS_SHELL_PATTERNS = ["rm -rf*", "* rm -rf*", "sudo *", "chmod -R *", "*curl*|*sh*", "*wget*|*sh*"]
TEST_COMMAND_PATTERNS = ["pytest*", "python -m pytest*", "npm test*", "npm run test*", "uv run pytest*"]


@dataclass(frozen=True)
class PolicyProfile:
    task: str
    task_type: str
    allowed_tools: list[str]
    denied_tools: list[str]
    confirmation_required: list[str]
    allowed_bash_patterns: list[str]
    blocked_path_patterns: list[str]
    external_sink_restrictions: list[str]
    protected_labels: list[str]
    explanation: str

    def to_policy_dict(self) -> dict[str, Any]:
        tools = base_tool_rules(
            protected_labels=self.protected_labels,
            blocked_path_patterns=self.blocked_path_patterns,
            allowed_bash_patterns=self.allowed_bash_patterns,
        )
        for tool_name in self.confirmation_required:
            if tool_name in tools:
                tools[tool_name]["requires_confirmation"] = True

        return {
            "profile": {
                "task": self.task,
                "task_type": self.task_type,
                "allowed_tools": self.allowed_tools,
                "denied_tools": self.denied_tools,
                "confirmation_required": self.confirmation_required,
                "allowed_bash_patterns": self.allowed_bash_patterns,
                "blocked_path_patterns": self.blocked_path_patterns,
                "external_sink_restrictions": self.external_sink_restrictions,
                "protected_labels": self.protected_labels,
                "explanation": self.explanation,
            },
            "tools": tools,
            "tasks": {
                self.task_type: {
                    "allowed_tools": self.allowed_tools,
                }
            },
            "guardrails": {
                "protected_labels": self.protected_labels,
                "blocked_path_patterns": self.blocked_path_patterns,
                "dangerous_shell_patterns": DANGEROUS_SHELL_PATTERNS,
            },
        }

    def to_yaml(self) -> str:
        return yaml.safe_dump(self.to_policy_dict(), sort_keys=False)


def has_any(text: str, words: list[str]) -> bool:
    return any(re.search(rf"\b{re.escape(word)}\b", text) for word in words)


def explicit_send_requested(text: str) -> bool:
    return has_any(text, ["send"]) and not any(
        phrase in text for phrase in ["do not send", "don't send", "without sending", "not send anything"]
    )


def edit_is_negated(text: str) -> bool:
    return any(phrase in text for phrase in ["do not edit", "don't edit", "no edits", "read only", "read-only"])


def infer_task_type(text: str) -> str:
    if has_any(text, ["deploy", "release", "publish"]):
        return "deploy_requires_confirmation"
    if has_any(text, ["delete", "remove", "cleanup", "clean"]):
        return "destructive_requires_confirmation"
    if has_any(text, ["email", "reply", "draft"]):
        return "email_draft"
    if has_any(text, ["fix", "edit", "modify", "refactor", "implement"]) and not edit_is_negated(text):
        return "code_change_with_confirmation"
    if has_any(text, ["test", "tests", "pytest"]):
        return "read_only_test"
    return "read_only_review"


def synthesize_policy(task: str) -> PolicyProfile:
    text = task.lower()
    task_type = infer_task_type(text)
    allowed: set[str] = {"read_file", "summarize_to_user"}
    confirmation_required: set[str] = {"send_email", "delete_file"}
    allowed_bash_patterns: list[str] = []
    explanation = "Read-only review task with external sinks blocked by default."

    if has_any(text, ["repo", "code", "summarize", "review", "read"]):
        allowed.update({"read_file", "summarize_to_user"})

    if has_any(text, ["test", "tests", "pytest"]):
        allowed.add("shell_command")
        allowed_bash_patterns = TEST_COMMAND_PATTERNS
        explanation = "Read-only review task with narrow test execution."

    if has_any(text, ["fix", "edit", "modify", "refactor", "implement"]) and not edit_is_negated(text):
        allowed.update({"read_file", "shell_command", "write_file", "edit_file", "summarize_to_user"})
        confirmation_required.update({"write_file", "edit_file"})
        if not allowed_bash_patterns:
            allowed_bash_patterns = TEST_COMMAND_PATTERNS
        explanation = "Code-change task with edits gated by confirmation and Bash limited to test commands."

    if task_type == "email_draft":
        allowed = {"read_email", "read_file", "summarize_to_user", "draft_to_user"}
        explanation = "Email review task: draft to user is allowed, direct sending is denied unless explicitly requested."
        if explicit_send_requested(text):
            allowed.add("send_email")
            confirmation_required.add("send_email")
            explanation = "Email task with sending allowed only after draft review and confirmation."

    if task_type == "deploy_requires_confirmation":
        allowed.update({"shell_command", "web_fetch", "web_search"})
        confirmation_required.update({"shell_command", "web_fetch", "web_search"})
        allowed_bash_patterns = ["pytest*", "python -m pytest*", "npm test*", "npm run build*", "npm run deploy*"]
        explanation = "Deployment task: build/deploy commands and network tools require explicit confirmation."

    if task_type == "destructive_requires_confirmation":
        allowed.update({"shell_command", "delete_file"})
        confirmation_required.update({"shell_command", "delete_file"})
        allowed_bash_patterns = ["rm *", "find * -delete", "pytest*", "python -m pytest*"]
        explanation = "Destructive cleanup task: delete operations require explicit confirmation."

    if any(phrase in text for phrase in ["do not edit", "don't edit", "read only", "read-only"]):
        allowed.discard("write_file")
        allowed.discard("edit_file")
        confirmation_required.discard("write_file")
        confirmation_required.discard("edit_file")
        explanation = "Read-only task: Write/Edit are denied and any Bash access is narrowly scoped."

    if any(phrase in text for phrase in ["do not use network", "no network", "do not browse"]):
        allowed.difference_update({"web_request", "web_fetch", "web_search", "mcp_tool"})

    denied = [tool for tool in ALL_TOOLS if tool not in allowed]
    external_restrictions = sorted(EXTERNAL_SINKS)

    return PolicyProfile(
        task=task,
        task_type=task_type,
        allowed_tools=sorted(allowed),
        denied_tools=denied,
        confirmation_required=sorted(confirmation_required.intersection(ALL_TOOLS)),
        allowed_bash_patterns=allowed_bash_patterns,
        blocked_path_patterns=BLOCKED_PATH_PATTERNS,
        external_sink_restrictions=external_restrictions,
        protected_labels=PROTECTED_LABELS,
        explanation=explanation,
    )


def base_tool_rules(
    protected_labels: list[str],
    blocked_path_patterns: list[str],
    allowed_bash_patterns: list[str],
) -> dict[str, dict[str, Any]]:
    tools: dict[str, dict[str, Any]] = {
        "read_email": {"effect": "read", "returns_labels": ["untrusted"]},
        "read_file": {
            "effect": "read",
            "returns_labels": ["private"],
            "deny_if_arg_matches": [
                {
                    "arg": "path",
                    "rule": "blocked_path",
                    "reason": "Protected paths such as secrets, credentials, and private keys may not be read.",
                    "patterns": blocked_path_patterns,
                }
            ],
        },
        "shell_command": {
            "effect": "local_command",
            "returns_labels": ["public"],
            "deny_if_arg_matches": [
                {
                    "arg": "command",
                    "rule": "dangerous_shell",
                    "reason": "Destructive or remote-install shell commands are blocked before execution.",
                    "patterns": DANGEROUS_SHELL_PATTERNS,
                }
            ],
        },
        "write_file": {"effect": "file_write", "returns_labels": ["public"]},
        "edit_file": {"effect": "file_write", "returns_labels": ["public"]},
        "summarize_to_user": {"effect": "user_output", "returns_labels": ["public"]},
        "draft_to_user": {"effect": "user_output", "returns_labels": ["public"]},
        "send_email": {
            "effect": "external_write",
            "external_sink": True,
            "requires_confirmation": True,
            "requires_prior_event": "draft_to_user",
            "deny_if_input_labels": protected_labels,
        },
        "web_request": {
            "effect": "external_write",
            "external_sink": True,
            "requires_confirmation": True,
            "deny_if_input_labels": protected_labels,
        },
        "web_fetch": {
            "effect": "external_read",
            "external_sink": True,
            "deny_if_input_labels": protected_labels,
        },
        "web_search": {
            "effect": "external_read",
            "external_sink": True,
            "deny_if_input_labels": protected_labels,
        },
        "mcp_tool": {
            "effect": "external_tool",
            "external_sink": True,
            "deny_if_input_labels": protected_labels,
        },
        "delete_file": {"effect": "destructive", "requires_confirmation": True},
    }
    if allowed_bash_patterns:
        tools["shell_command"]["allow_if_arg_matches"] = [
            {
                "arg": "command",
                "rule": "bash_command_not_allowed",
                "reason": "This task-scoped policy allows only narrow test/build shell commands.",
                "patterns": allowed_bash_patterns,
            }
        ]
    return tools


def write_synthesized_policy(task: str, out_path: Path) -> PolicyProfile:
    profile = synthesize_policy(task)
    out_path.write_text(profile.to_yaml())
    return profile
