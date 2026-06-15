from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sentinel.policy import Policy


def diff_policies(old_path: Path, new_path: Path) -> dict[str, Any]:
    old = Policy.from_yaml(old_path)
    new = Policy.from_yaml(new_path)

    old_tasks = set(old.tasks)
    new_tasks = set(new.tasks)
    old_tools = set(old.tools)
    new_tools = set(new.tools)

    task_changes = []
    for task_name in sorted(old_tasks | new_tasks):
        old_allowed = set(old.tasks.get(task_name, {}).get("allowed_tools", []))
        new_allowed = set(new.tasks.get(task_name, {}).get("allowed_tools", []))
        if old_allowed != new_allowed:
            task_changes.append(
                {
                    "task": task_name,
                    "added_tools": sorted(new_allowed - old_allowed),
                    "removed_tools": sorted(old_allowed - new_allowed),
                }
            )

    tool_changes = []
    for tool_name in sorted(old_tools | new_tools):
        old_rule = old.tools.get(tool_name)
        new_rule = new.tools.get(tool_name)
        if old_rule == new_rule:
            continue
        if old_rule is None:
            tool_changes.append({"tool": tool_name, "change": "added", "new_rule": new_rule})
        elif new_rule is None:
            tool_changes.append({"tool": tool_name, "change": "removed", "old_rule": old_rule})
        else:
            changed_fields = sorted(set(old_rule) | set(new_rule))
            tool_changes.append(
                {
                    "tool": tool_name,
                    "change": "modified",
                    "fields": [
                        field
                        for field in changed_fields
                        if old_rule.get(field) != new_rule.get(field)
                    ],
                }
            )

    temporal_changes = {
        "old_count": len(old.temporal_rules),
        "new_count": len(new.temporal_rules),
        "changed": old.temporal_rules != new.temporal_rules,
    }

    return {
        "old": str(old_path),
        "new": str(new_path),
        "tasks_added": sorted(new_tasks - old_tasks),
        "tasks_removed": sorted(old_tasks - new_tasks),
        "tools_added": sorted(new_tools - old_tools),
        "tools_removed": sorted(old_tools - new_tools),
        "task_changes": task_changes,
        "tool_changes": tool_changes,
        "temporal_rules": temporal_changes,
    }


def format_policy_diff(diff: dict[str, Any]) -> str:
    lines = [
        "Policy diff",
        f"  old: {diff['old']}",
        f"  new: {diff['new']}",
    ]
    for key, label in [
        ("tasks_added", "Tasks added"),
        ("tasks_removed", "Tasks removed"),
        ("tools_added", "Tools added"),
        ("tools_removed", "Tools removed"),
    ]:
        values = diff[key]
        lines.append(f"  {label}: {', '.join(values) if values else 'none'}")

    lines.append("")
    lines.append("Task allowed-tool changes:")
    if diff["task_changes"]:
        for change in diff["task_changes"]:
            lines.append(f"  {change['task']}:")
            lines.append(f"    added: {', '.join(change['added_tools']) if change['added_tools'] else 'none'}")
            lines.append(f"    removed: {', '.join(change['removed_tools']) if change['removed_tools'] else 'none'}")
    else:
        lines.append("  none")

    lines.append("")
    lines.append("Tool rule changes:")
    if diff["tool_changes"]:
        for change in diff["tool_changes"]:
            if change["change"] == "modified":
                fields = ", ".join(change["fields"]) if change["fields"] else "none"
                lines.append(f"  {change['tool']}: modified fields: {fields}")
            else:
                lines.append(f"  {change['tool']}: {change['change']}")
    else:
        lines.append("  none")

    if diff["temporal_rules"]["changed"]:
        lines.append("")
        lines.append(
            "Temporal rules changed: "
            f"{diff['temporal_rules']['old_count']} -> {diff['temporal_rules']['new_count']}"
        )
    return "\n".join(lines)


def diff_to_json(diff: dict[str, Any]) -> str:
    return json.dumps(diff, indent=2, sort_keys=True) + "\n"
