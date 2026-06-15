from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinel.policy import Policy


@dataclass(frozen=True)
class RiskFinding:
    severity: str
    message: str
    source: str


def scan_project(path: Path) -> list[RiskFinding]:
    project = path.resolve()
    findings: list[RiskFinding] = []

    findings.extend(scan_claude_settings(project / ".claude" / "settings.json"))
    findings.extend(scan_claude_settings(project / ".claude" / "settings.local.json"))

    policy_path = project / "sentinel.policy.yaml"
    if not policy_path.exists():
        policy_path = project / "policy.yaml"
    if policy_path.exists():
        findings.extend(scan_policy(policy_path))
    else:
        findings.append(RiskFinding("MEDIUM", "No Sentinel policy file found.", str(project)))

    mcp_tools = project / "examples" / "mcp_tools.json"
    if mcp_tools.exists():
        findings.extend(scan_mcp_tools(mcp_tools))

    audit_log = project / ".sentinel" / "audit.log"
    if audit_log.exists():
        findings.append(RiskFinding("LOW", "Audit log exists.", str(audit_log)))
    else:
        findings.append(RiskFinding("LOW", "No local audit log found yet.", str(audit_log)))

    return findings


def scan_claude_settings(path: Path) -> list[RiskFinding]:
    if not path.exists():
        return []
    findings: list[RiskFinding] = []
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        return [RiskFinding("HIGH", f"Claude settings JSON is malformed: {exc}", str(path))]

    text = json.dumps(data)
    if '"matcher": "*"' in text and "sentinel-claude-hook" not in text:
        findings.append(RiskFinding("HIGH", "Claude Code PreToolUse matcher '*' exists without Sentinel hook.", str(path)))
    if "Bash" in text and "sentinel-claude-hook" not in text:
        findings.append(RiskFinding("MEDIUM", "Claude settings mention Bash without Sentinel hook enforcement.", str(path)))
    if "WebFetch" in text or "WebSearch" in text:
        if "sentinel-claude-hook" not in text:
            findings.append(RiskFinding("MEDIUM", "WebFetch/WebSearch appear in settings without Sentinel hook.", str(path)))
    return findings


def scan_policy(path: Path) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    policy = Policy.from_yaml(path)

    read_rule = policy.tool_rule("read_file") or {}
    blocked_patterns = [
        str(pattern)
        for rule in read_rule.get("deny_if_arg_matches", [])
        for pattern in rule.get("patterns", [])
    ]
    if not any(".env" in pattern or "id_rsa" in pattern for pattern in blocked_patterns):
        findings.append(RiskFinding("HIGH", ".env/private-key paths are not listed in read_file blocked patterns.", str(path)))

    shell_rule = policy.tool_rule("shell_command") or {}
    shell_allowed = any("shell_command" in task.get("allowed_tools", []) for task in policy.tasks.values())
    if shell_allowed and not shell_rule.get("allow_if_arg_matches") and not shell_rule.get("deny_if_arg_matches"):
        findings.append(RiskFinding("HIGH", "Bash/shell command is allowed without command restrictions.", str(path)))

    for tool_name in ("web_fetch", "web_search", "web_request"):
        rule = policy.tool_rule(tool_name) or {}
        allowed = any(tool_name in task.get("allowed_tools", []) for task in policy.tasks.values())
        if allowed and rule.get("external_sink") and not rule.get("deny_if_input_labels"):
            findings.append(RiskFinding("MEDIUM", f"{tool_name} is an external sink without label restrictions.", str(path)))

    for tool_name in ("write_file", "edit_file"):
        rule = policy.tool_rule(tool_name) or {}
        allowed = any(tool_name in task.get("allowed_tools", []) for task in policy.tasks.values())
        if allowed and not rule.get("requires_confirmation") and not rule.get("deny_if_arg_matches"):
            findings.append(RiskFinding("MEDIUM", f"{tool_name} is allowed without confirmation or protected-path rules.", str(path)))

    mcp_rule = policy.tool_rule("mcp_tool") or {}
    mcp_allowed = any("mcp_tool" in task.get("allowed_tools", []) for task in policy.tasks.values())
    if mcp_allowed and not mcp_rule.get("deny_if_input_labels"):
        findings.append(RiskFinding("MEDIUM", "MCP tools are allowed without protected-label restrictions.", str(path)))

    if not findings:
        findings.append(RiskFinding("LOW", "No high-risk policy gaps found by the lightweight scanner.", str(path)))
    return findings


def scan_mcp_tools(path: Path) -> list[RiskFinding]:
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        return [RiskFinding("MEDIUM", f"MCP tool manifest is malformed: {exc}", str(path))]
    tools = data if isinstance(data, list) else data.get("tools", []) if isinstance(data, dict) else []
    findings = []
    for tool in tools:
        if isinstance(tool, dict) and tool.get("external_network", False):
            findings.append(RiskFinding("MEDIUM", f"MCP tool '{tool.get('name', 'unknown')}' has external network access.", str(path)))
    return findings


def findings_to_dict(findings: list[RiskFinding]) -> list[dict[str, str]]:
    return [
        {"severity": finding.severity, "message": finding.message, "source": finding.source}
        for finding in findings
    ]


def format_findings(findings: list[RiskFinding]) -> str:
    lines = ["Risk scan"]
    if not findings:
        lines.append("  No findings.")
        return "\n".join(lines)
    for finding in findings:
        lines.append(f"  {finding.severity}: {finding.message}")
        lines.append(f"    source: {finding.source}")
    return "\n".join(lines)
