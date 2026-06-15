from __future__ import annotations

from fnmatch import fnmatch

from sentinel.policy import Policy
from sentinel.provenance import ProvenanceGraph
from sentinel.tools import SimulatedTools
from sentinel.types import Artifact, Decision, TaskContext, ToolCall, TraceEvent


class PermissionMonitor:
    """Deterministic monitor for proposed tool calls.

    The core invariant demonstrated here is:

        private or untrusted-derived artifacts must not flow to external sinks
        unless the policy explicitly allows it, and this toy policy never does.

    The monitor also enforces least-privilege task capabilities and confirmation
    requirements for external or destructive actions.
    """

    def __init__(self, policy: Policy, tools: SimulatedTools | None = None):
        self.policy = policy
        self.tools = tools or SimulatedTools()
        self.artifacts: dict[str, Artifact] = {}
        self.provenance = ProvenanceGraph()
        self.trace: list[TraceEvent] = []

    def labels_for(self, artifact_ids: set[str] | frozenset[str]) -> frozenset[str]:
        labels: set[str] = set(self.provenance.labels_for(artifact_ids))
        for artifact_id in artifact_ids:
            artifact = self.artifacts.get(artifact_id)
            if artifact is not None:
                labels.update(artifact.labels)
        return frozenset(labels)

    def has_allowed_event(self, tool_name: str) -> bool:
        return any(event.call.name == tool_name and event.decision.allowed for event in self.trace)

    def trace_context(
        self,
        call: ToolCall,
        context: TaskContext,
        allowed_tools: set[str],
        **extra: object,
    ) -> dict[str, object]:
        """Return compact audit metadata for this decision."""

        audit_context: dict[str, object] = {
            "task_type": context.task_type,
            "allowed_tools": sorted(allowed_tools),
            "derived_from": sorted(call.derived_from),
            "prior_allowed_events": [
                event.call.name for event in self.trace if event.decision.allowed
            ],
            "user_confirmed": context.user_confirmed,
        }
        if call.derived_from:
            audit_context["provenance"] = self.provenance.subgraph_for(call.derived_from)
        audit_context.update(extra)
        return audit_context

    def check(self, call: ToolCall, context: TaskContext) -> Decision:
        allowed_tools = self.policy.allowed_tools_for_task(context.task_type)
        labels_seen = self.labels_for(call.derived_from)
        base_context = self.trace_context(call, context, allowed_tools)
        rule = self.policy.tool_rule(call.name)
        if rule is None:
            return Decision(
                action_name=call.name,
                allowed=False,
                rule="unknown_tool",
                reason=f"Unknown tool: {call.name}",
                labels_seen=labels_seen,
                trace_context=base_context,
            )

        if call.name not in allowed_tools:
            return Decision(
                action_name=call.name,
                allowed=False,
                rule="least_privilege",
                reason=f"Tool '{call.name}' is not granted for task '{context.task_type}'.",
                labels_seen=labels_seen,
                trace_context=base_context,
            )

        for arg_rule in rule.get("allow_if_arg_matches", []):
            arg_name = arg_rule.get("arg")
            value = call.args.get(arg_name, "") if isinstance(arg_name, str) else ""
            value_text = str(value)
            patterns = [str(pattern) for pattern in arg_rule.get("patterns", [])]
            if patterns and not any(fnmatch(value_text, pattern) or pattern in value_text for pattern in patterns):
                rule_id = str(arg_rule.get("rule", "arg_pattern_not_allowed"))
                reason = str(
                    arg_rule.get(
                        "reason",
                        f"Tool '{call.name}' argument '{arg_name}' does not match allowed patterns.",
                    )
                )
                return Decision(
                    action_name=call.name,
                    allowed=False,
                    rule=rule_id,
                    reason=reason,
                    labels_seen=labels_seen,
                    trace_context=self.trace_context(
                        call,
                        context,
                        allowed_tools,
                        checked_arg=arg_name,
                        allowed_patterns=patterns,
                    ),
                )

        for arg_rule in rule.get("deny_if_arg_matches", []):
            arg_name = arg_rule.get("arg")
            value = call.args.get(arg_name, "") if isinstance(arg_name, str) else ""
            value_text = str(value)
            for pattern in arg_rule.get("patterns", []):
                if fnmatch(value_text, str(pattern)) or str(pattern) in value_text:
                    rule_id = str(arg_rule.get("rule", "arg_pattern_denied"))
                    reason = str(
                        arg_rule.get(
                            "reason",
                            f"Tool '{call.name}' argument '{arg_name}' matches blocked pattern '{pattern}'.",
                        )
                    )
                    return Decision(
                        action_name=call.name,
                        allowed=False,
                        rule=rule_id,
                        reason=reason,
                        labels_seen=labels_seen,
                        trace_context=self.trace_context(
                            call,
                            context,
                            allowed_tools,
                            matched_arg=arg_name,
                            matched_pattern=str(pattern),
                        ),
                    )

        denied_labels = set(rule.get("deny_if_input_labels", []))
        if rule.get("external_sink") and denied_labels.intersection(labels_seen):
            return Decision(
                action_name=call.name,
                allowed=False,
                rule="external_sink_taint",
                reason=(
                    "External sinks may not receive private data or content derived "
                    "from untrusted tool output."
                ),
                labels_seen=labels_seen,
                trace_context=self.trace_context(
                    call,
                    context,
                    allowed_tools,
                    denied_labels=sorted(denied_labels),
                ),
            )

        required_prior_event = rule.get("requires_prior_event")
        if required_prior_event and not self.has_allowed_event(required_prior_event):
            return Decision(
                action_name=call.name,
                allowed=False,
                rule="missing_prior_event",
                reason=f"Tool '{call.name}' requires a prior allowed '{required_prior_event}' event.",
                labels_seen=labels_seen,
                trace_context=self.trace_context(
                    call,
                    context,
                    allowed_tools,
                    required_prior_event=required_prior_event,
                ),
            )

        for temporal_rule in self.policy.temporal_rules_before(call.name):
            required_events = [str(event) for event in temporal_rule.get("require_events", [])]
            missing_events = [
                event_name for event_name in required_events if not self.has_allowed_event(event_name)
            ]
            if missing_events:
                rule_id = str(temporal_rule.get("id", "temporal_rule_violation"))
                return Decision(
                    action_name=call.name,
                    allowed=False,
                    rule=rule_id,
                    reason=(
                        f"Temporal rule '{rule_id}' requires prior allowed event(s): "
                        f"{', '.join(missing_events)}."
                    ),
                    labels_seen=labels_seen,
                    trace_context=self.trace_context(
                        call,
                        context,
                        allowed_tools,
                        temporal_rule=rule_id,
                        required_events=required_events,
                        missing_events=missing_events,
                    ),
                )
            if temporal_rule.get("require_confirmation") and not context.user_confirmed:
                rule_id = str(temporal_rule.get("id", "temporal_confirmation_missing"))
                return Decision(
                    action_name=call.name,
                    allowed=False,
                    rule=rule_id,
                    reason=f"Temporal rule '{rule_id}' requires explicit user confirmation.",
                    labels_seen=labels_seen,
                    trace_context=self.trace_context(
                        call,
                        context,
                        allowed_tools,
                        temporal_rule=rule_id,
                        required_confirmation=True,
                    ),
                )

        if rule.get("requires_confirmation") and not context.user_confirmed:
            return Decision(
                action_name=call.name,
                allowed=False,
                rule="missing_confirmation",
                reason=f"Tool '{call.name}' requires explicit user confirmation.",
                labels_seen=labels_seen,
                trace_context=base_context,
            )

        return Decision(
            action_name=call.name,
            allowed=True,
            rule="allowed",
            reason="Allowed by policy.",
            labels_seen=labels_seen,
            trace_context=base_context,
        )

    def step(self, call: ToolCall, context: TaskContext) -> TraceEvent:
        decision = self.check(call, context)
        result = None
        if decision.allowed:
            result = self.tools.execute(call)
            result = self.provenance.add_artifact(
                result,
                parents=call.derived_from,
                summary=f"Produced by {call.name}",
            )
            self.artifacts[result.artifact_id] = result
        event = TraceEvent(call=call, decision=decision, result=result)
        self.trace.append(event)
        return event

    def run(self, calls: list[ToolCall], context: TaskContext) -> list[TraceEvent]:
        return [self.step(call, context) for call in calls]
