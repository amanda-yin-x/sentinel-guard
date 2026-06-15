from __future__ import annotations

from sentinel.monitor import PermissionMonitor
from sentinel.policy import Policy
from sentinel.types import TaskContext, ToolCall


def temporal_policy() -> Policy:
    return Policy(
        tools={
            "draft_to_user": {"effect": "user_output", "returns_labels": ["public"]},
            "web_request": {"effect": "external_write", "external_sink": True},
        },
        tasks={
            "temporal_demo": {
                "allowed_tools": ["draft_to_user", "web_request"],
            }
        },
        temporal_rules=[
            {
                "id": "web_requires_user_draft",
                "before": "web_request",
                "require_events": ["draft_to_user"],
            }
        ],
    )


def test_temporal_rule_blocks_missing_prior_event():
    monitor = PermissionMonitor(temporal_policy())
    context = TaskContext(task_type="temporal_demo", user_goal="Use web only after draft.")

    event = monitor.step(ToolCall("web_request", {"url": "https://example.com"}), context)

    assert not event.decision.allowed
    assert event.decision.rule == "web_requires_user_draft"
    assert event.decision.trace_context["missing_events"] == ["draft_to_user"]


def test_temporal_rule_allows_after_required_event():
    monitor = PermissionMonitor(temporal_policy())
    context = TaskContext(task_type="temporal_demo", user_goal="Use web only after draft.")

    monitor.step(ToolCall("draft_to_user"), context)
    event = monitor.step(ToolCall("web_request", {"url": "https://example.com"}), context)

    assert event.decision.allowed
