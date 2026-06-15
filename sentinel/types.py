from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, FrozenSet


@dataclass(frozen=True)
class Artifact:
    """A value produced by a tool, with security labels attached."""

    artifact_id: str
    value: str
    labels: FrozenSet[str]
    source_tool: str


@dataclass(frozen=True)
class ToolCall:
    """A proposed action from the agent.

    derived_from records which previous artifacts influenced this call. In a real
    agent system this would come from provenance tracking; here it is explicit so
    the demo remains deterministic and inspectable.
    """

    name: str
    args: Mapping[str, Any] = field(default_factory=dict)
    derived_from: FrozenSet[str] = frozenset()


@dataclass(frozen=True)
class TaskContext:
    """The user's high-level task and authorization state."""

    task_type: str
    user_goal: str
    user_confirmed: bool = False


@dataclass(frozen=True)
class Decision:
    action_name: str
    allowed: bool
    rule: str
    reason: str
    labels_seen: FrozenSet[str] = frozenset()
    trace_context: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TraceEvent:
    call: ToolCall
    decision: Decision
    result: Artifact | None = None
