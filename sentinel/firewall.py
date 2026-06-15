from __future__ import annotations

import json
from dataclasses import dataclass
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from sentinel.monitor import PermissionMonitor
from sentinel.policy import Policy
from sentinel.types import Artifact, Decision, TaskContext, ToolCall, TraceEvent


class FirewallInputError(ValueError):
    """Raised when a tool-call firewall input file is malformed."""


@dataclass(frozen=True)
class FirewallResult:
    decision: Decision
    context: TaskContext
    proposed_action: ToolCall


def load_json_file(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise FirewallInputError(f"Input file not found: {path}") from exc
    except JSONDecodeError as exc:
        raise FirewallInputError(f"Malformed JSON: {exc.msg} at line {exc.lineno}, column {exc.colno}") from exc

    if not isinstance(payload, dict):
        raise FirewallInputError("Input JSON must be an object.")
    return payload


def parse_context(payload: dict[str, Any]) -> TaskContext:
    raw_context = payload.get("task_context", payload.get("context"))
    if not isinstance(raw_context, dict):
        raise FirewallInputError("Input must include a task_context object.")

    task_type = raw_context.get("task_type")
    if not isinstance(task_type, str) or not task_type:
        raise FirewallInputError("task_context.task_type must be a non-empty string.")

    user_goal = raw_context.get("user_goal", "")
    if not isinstance(user_goal, str):
        raise FirewallInputError("task_context.user_goal must be a string.")

    user_confirmed = raw_context.get("user_confirmed", False)
    if not isinstance(user_confirmed, bool):
        raise FirewallInputError("task_context.user_confirmed must be a boolean.")

    return TaskContext(
        task_type=task_type,
        user_goal=user_goal,
        user_confirmed=user_confirmed,
    )


def parse_tool_call(raw_call: Any, field_name: str) -> ToolCall:
    if not isinstance(raw_call, dict):
        raise FirewallInputError(f"{field_name} must be an object.")

    name = raw_call.get("name", raw_call.get("action"))
    if not isinstance(name, str) or not name:
        raise FirewallInputError(f"{field_name}.name or {field_name}.action must be a non-empty string.")

    args = raw_call.get("args", {})
    if not isinstance(args, dict):
        raise FirewallInputError(f"{field_name}.args must be an object when present.")

    derived_from = raw_call.get("derived_from", [])
    if not isinstance(derived_from, list) or not all(isinstance(item, str) for item in derived_from):
        raise FirewallInputError(f"{field_name}.derived_from must be a list of strings.")

    return ToolCall(name=name, args=args, derived_from=frozenset(derived_from))


def parse_artifact(raw_artifact: Any, field_name: str) -> Artifact:
    if not isinstance(raw_artifact, dict):
        raise FirewallInputError(f"{field_name} must be an object.")

    artifact_id = raw_artifact.get("artifact_id")
    if not isinstance(artifact_id, str) or not artifact_id:
        raise FirewallInputError(f"{field_name}.artifact_id must be a non-empty string.")

    labels = raw_artifact.get("labels", [])
    if not isinstance(labels, list) or not all(isinstance(item, str) for item in labels):
        raise FirewallInputError(f"{field_name}.labels must be a list of strings.")

    value = raw_artifact.get("value", "")
    if not isinstance(value, str):
        raise FirewallInputError(f"{field_name}.value must be a string when present.")

    source_tool = raw_artifact.get("source_tool", "external_trace")
    if not isinstance(source_tool, str):
        raise FirewallInputError(f"{field_name}.source_tool must be a string when present.")

    return Artifact(
        artifact_id=artifact_id,
        value=value,
        labels=frozenset(labels),
        source_tool=source_tool,
    )


def seed_artifacts(monitor: PermissionMonitor, payload: dict[str, Any]) -> None:
    raw_artifacts = payload.get("artifacts", [])
    if not isinstance(raw_artifacts, list):
        raise FirewallInputError("artifacts must be a list when present.")

    for index, raw_artifact in enumerate(raw_artifacts):
        artifact = parse_artifact(raw_artifact, f"artifacts[{index}]")
        artifact = monitor.provenance.add_artifact(artifact)
        monitor.artifacts[artifact.artifact_id] = artifact


def seed_prior_events(monitor: PermissionMonitor, payload: dict[str, Any]) -> None:
    raw_events = payload.get("prior_events", payload.get("trace", []))
    if not isinstance(raw_events, list):
        raise FirewallInputError("prior_events must be a list when present.")

    for index, raw_event in enumerate(raw_events):
        if not isinstance(raw_event, dict):
            raise FirewallInputError(f"prior_events[{index}] must be an object.")

        call = parse_tool_call(raw_event, f"prior_events[{index}]")
        allowed = raw_event.get("allowed", True)
        if not isinstance(allowed, bool):
            raise FirewallInputError(f"prior_events[{index}].allowed must be a boolean when present.")

        result = None
        if raw_event.get("result") is not None:
            result = parse_artifact(raw_event["result"], f"prior_events[{index}].result")
            if allowed:
                result = monitor.provenance.add_artifact(result, parents=call.derived_from)
                monitor.artifacts[result.artifact_id] = result

        decision = Decision(
            action_name=call.name,
            allowed=allowed,
            rule=str(raw_event.get("rule_id", "allowed" if allowed else "blocked_in_trace")),
            reason=str(raw_event.get("reason", "Loaded from input trace.")),
            labels_seen=frozenset(result.labels if result else []),
            trace_context={"loaded_from": "input_trace"},
        )
        monitor.trace.append(TraceEvent(call=call, decision=decision, result=result))


def build_firewall_result_from_policy(policy: Policy, payload: dict[str, Any]) -> FirewallResult:
    monitor = PermissionMonitor(policy)
    context = parse_context(payload)

    seed_artifacts(monitor, payload)
    seed_prior_events(monitor, payload)

    raw_action = payload.get("proposed_action", payload.get("tool_call"))
    proposed_action = parse_tool_call(raw_action, "proposed_action")
    decision = monitor.check(proposed_action, context)
    return FirewallResult(decision=decision, context=context, proposed_action=proposed_action)


def build_firewall_result(policy_path: Path, payload: dict[str, Any]) -> FirewallResult:
    return build_firewall_result_from_policy(Policy.from_yaml(policy_path), payload)


def check_file(policy_path: Path, input_path: Path) -> FirewallResult:
    payload = load_json_file(input_path)
    return build_firewall_result(policy_path, payload)


def decision_to_dict(result: FirewallResult) -> dict[str, Any]:
    decision = result.decision
    return {
        "decision": "allow" if decision.allowed else "block",
        "allowed": decision.allowed,
        "action": decision.action_name,
        "rule_id": decision.rule,
        "reason": decision.reason,
        "labels": sorted(decision.labels_seen),
        "labels_seen": sorted(decision.labels_seen),
        "trace_context": dict(decision.trace_context),
    }


def format_human_decision(result: FirewallResult) -> str:
    decision = result.decision
    status = "ALLOW" if decision.allowed else "BLOCK"
    labels = ", ".join(sorted(decision.labels_seen)) if decision.labels_seen else "none"
    prior_events = decision.trace_context.get("prior_allowed_events", [])
    if isinstance(prior_events, list) and prior_events:
        prior_text = ", ".join(str(item) for item in prior_events)
    else:
        prior_text = "none"

    return "\n".join(
        [
            "Tool-call firewall decision",
            "-" * 32,
            f"Action: {decision.action_name}",
            f"Decision: {status}",
            f"Rule ID: {decision.rule}",
            f"Labels: {labels}",
            f"Task type: {result.context.task_type}",
            f"Prior allowed events: {prior_text}",
            f"Reason: {decision.reason}",
        ]
    )
