from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class Policy:
    tools: dict[str, dict[str, Any]]
    tasks: dict[str, dict[str, Any]]
    temporal_rules: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Policy":
        data = yaml.safe_load(Path(path).read_text())
        if not isinstance(data, dict):
            raise ValueError("Policy file must contain a mapping at the top level.")
        temporal_rules = data.get("temporal_rules", [])
        if temporal_rules is None:
            temporal_rules = []
        if not isinstance(temporal_rules, list):
            raise ValueError("Policy field 'temporal_rules' must be a list when present.")
        return cls(
            tools=data.get("tools", {}),
            tasks=data.get("tasks", {}),
            temporal_rules=temporal_rules,
        )

    def allowed_tools_for_task(self, task_type: str) -> set[str]:
        task = self.tasks.get(task_type)
        if task is None:
            return set()
        return set(task.get("allowed_tools", []))

    def tool_rule(self, tool_name: str) -> dict[str, Any] | None:
        return self.tools.get(tool_name)

    def temporal_rules_before(self, tool_name: str) -> list[dict[str, Any]]:
        return [rule for rule in self.temporal_rules if rule.get("before") == tool_name]
