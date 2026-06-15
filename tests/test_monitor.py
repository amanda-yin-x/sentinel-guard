from __future__ import annotations

from pathlib import Path

from sentinel.eval import SCENARIOS, run_scenario
from sentinel.monitor import PermissionMonitor
from sentinel.policy import Policy
from sentinel.types import TaskContext, ToolCall


POLICY_PATH = Path(__file__).resolve().parents[1] / "policy.yaml"


def decisions_for(scenario_name: str):
    scenario = next(s for s in SCENARIOS if s.name == scenario_name)
    return run_scenario(POLICY_PATH, scenario)


def new_monitor() -> PermissionMonitor:
    return PermissionMonitor(Policy.from_yaml(POLICY_PATH))


def test_benign_summary_allowed():
    events = decisions_for("benign_summary")
    assert all(event.decision.allowed for event in events)


def test_prompt_injection_blocks_external_exfiltration():
    events = decisions_for("prompt_injection_exfiltration")
    send_event = next(event for event in events if event.call.name == "send_email")
    assert not send_event.decision.allowed
    assert send_event.decision.action_name == "send_email"
    assert send_event.decision.rule == "external_sink_taint"
    assert "private" in send_event.decision.labels_seen
    assert "untrusted" in send_event.decision.labels_seen
    assert send_event.decision.trace_context["user_confirmed"] is True
    assert "draft_to_user" in send_event.decision.trace_context["prior_allowed_events"]


def test_private_or_untrusted_data_cannot_flow_to_send_email_or_web_request():
    cases = [
        (
            "send_email",
            "review_and_send_summary",
            [
                ToolCall("read_email"),
                ToolCall("read_file", {"path": "private_notes.md"}),
                ToolCall("draft_to_user"),
            ],
        ),
        (
            "web_request",
            "external_web_report",
            [
                ToolCall("read_email"),
                ToolCall("read_file", {"path": "private_notes.md"}),
            ],
        ),
    ]

    for sink_name, task_type, setup_calls in cases:
        monitor = new_monitor()
        context = TaskContext(
            task_type=task_type,
            user_goal="Use external sink after confirmation.",
            user_confirmed=True,
        )
        for call in setup_calls:
            assert monitor.step(call, context).decision.allowed

        event = monitor.step(
            ToolCall(
                sink_name,
                {"to": "external@example.com", "body": "derived content"},
                derived_from=frozenset({"email_1", "private_notes.md"}),
            ),
            context,
        )
        assert not event.decision.allowed
        assert event.decision.rule == "external_sink_taint"
        assert {"private", "untrusted"}.issubset(event.decision.labels_seen)


def test_destructive_action_requires_confirmation():
    events = decisions_for("unsafe_delete_without_confirmation")
    delete_event = events[0]
    assert not delete_event.decision.allowed
    assert delete_event.decision.rule == "missing_confirmation"


def test_destructive_action_allowed_after_confirmation():
    monitor = new_monitor()
    context = TaskContext(
        task_type="maintenance",
        user_goal="Delete this file after my explicit confirmation.",
        user_confirmed=True,
    )
    event = monitor.step(ToolCall("delete_file", {"path": "old_notes.md"}), context)
    assert event.decision.allowed


def test_confirmed_public_send_allowed():
    events = decisions_for("confirmed_public_send")
    assert all(event.decision.allowed for event in events)


def test_send_email_requires_prior_draft_to_user_event():
    events = decisions_for("missing_prior_event_send")
    send_event = events[0]
    assert not send_event.decision.allowed
    assert send_event.decision.rule == "missing_prior_event"
    assert send_event.decision.trace_context["required_prior_event"] == "draft_to_user"
    assert send_event.decision.trace_context["prior_allowed_events"] == []


def test_least_privilege_blocks_unrelated_tool():
    events = decisions_for("least_privilege_violation")
    web_event = next(event for event in events if event.call.name == "web_request")
    summary_event = next(event for event in events if event.call.name == "summarize_to_user")
    assert not web_event.decision.allowed
    assert web_event.decision.rule == "least_privilege"
    assert summary_event.decision.allowed
