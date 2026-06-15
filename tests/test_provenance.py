from __future__ import annotations

from pathlib import Path

from sentinel.monitor import PermissionMonitor
from sentinel.policy import Policy
from sentinel.types import TaskContext, ToolCall


POLICY_PATH = Path(__file__).resolve().parents[1] / "policy.yaml"


def new_monitor() -> PermissionMonitor:
    return PermissionMonitor(Policy.from_yaml(POLICY_PATH))


def test_derived_artifact_inherits_parent_labels():
    monitor = new_monitor()
    context = TaskContext(
        task_type="review_and_send_summary",
        user_goal="Review email and notes.",
        user_confirmed=True,
    )

    monitor.step(ToolCall("read_email"), context)
    monitor.step(ToolCall("read_file", {"path": "private_notes.md"}), context)
    draft = monitor.step(
        ToolCall("draft_to_user", derived_from=frozenset({"email_1", "private_notes.md"})),
        context,
    )

    assert draft.result is not None
    assert {"private", "untrusted", "public"}.issubset(draft.result.labels)


def test_private_untrusted_derived_artifact_is_blocked_to_external_sink():
    monitor = new_monitor()
    context = TaskContext(
        task_type="review_and_send_summary",
        user_goal="Review email and notes, then send only if safe.",
        user_confirmed=True,
    )

    monitor.step(ToolCall("read_email"), context)
    monitor.step(ToolCall("read_file", {"path": "private_notes.md"}), context)
    monitor.step(
        ToolCall("draft_to_user", derived_from=frozenset({"email_1", "private_notes.md"})),
        context,
    )
    event = monitor.step(
        ToolCall(
            "send_email",
            {"to": "external@example.com", "body": "draft_to_user"},
            derived_from=frozenset({"draft_to_user"}),
        ),
        context,
    )

    assert not event.decision.allowed
    assert event.decision.rule == "external_sink_taint"
    assert {"private", "untrusted"}.issubset(event.decision.labels_seen)
    assert "provenance" in event.decision.trace_context


def test_public_artifact_can_go_to_external_sink_with_approval_and_prior_event():
    monitor = new_monitor()
    context = TaskContext(
        task_type="confirmed_public_send",
        user_goal="Send public update after approval.",
        user_confirmed=True,
    )

    monitor.step(ToolCall("draft_to_user"), context)
    event = monitor.step(
        ToolCall(
            "send_email",
            {"to": "teammate@example.com", "body": "Public project update."},
            derived_from=frozenset({"draft_to_user"}),
        ),
        context,
    )

    assert event.decision.allowed
    assert event.decision.labels_seen == frozenset({"public"})
