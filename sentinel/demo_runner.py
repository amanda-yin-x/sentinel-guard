from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from sentinel.eval import (
    SCENARIOS,
    baseline_event_to_dict,
    event_to_dict,
    format_call,
    format_labels,
    planned_actions,
    resolve_scenario,
    run_scenario_with_monitor,
    run_without_monitor,
    score_scenario,
    summarize_events,
)
from sentinel.types import ToolCall


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = Path.cwd() / "policy.yaml" if (Path.cwd() / "policy.yaml").exists() else ROOT / "policy.yaml"
DANGEROUS_TOOLS = {"send_email", "web_request", "delete_file"}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Sentinel Guard demo scenarios.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--all", action="store_true", help="Run every scenario.")
    group.add_argument(
        "--scenario",
        help="Run one scenario by name or alias, for example: injection, delete, least.",
    )
    parser.add_argument("--json-report", type=Path, help="Write a machine-readable audit report.")
    return parser.parse_args(argv)


def call_to_dict(call: ToolCall) -> dict[str, Any]:
    return {
        "action_name": call.name,
        "args": dict(call.args),
        "derived_from": sorted(call.derived_from),
    }


def selected_scenarios(args: argparse.Namespace):
    if args.scenario:
        return [resolve_scenario(args.scenario)]
    return SCENARIOS


def print_proposed_actions(actions: list[ToolCall]) -> None:
    print("\nAgent proposed actions")
    print("-" * 72)
    for index, call in enumerate(actions, start=1):
        print(f"  {index}. {format_call(call)}")


def print_unsafe_baseline(scenario_name: str) -> list[dict[str, Any]]:
    baseline_events = run_without_monitor(resolve_scenario(scenario_name))
    print("\nUnsafe baseline (no monitor)")
    print("-" * 72)
    print("  Monitor disabled: every proposed tool call executes.")
    for event in baseline_events:
        if event.call.name in DANGEROUS_TOOLS:
            result = event.result.value
        else:
            result = f"artifact={event.result.artifact_id}"
        print(f"  EXECUTE {event.call.name:18s} -> {result}")
    unsafe_executed = [event.call.name for event in baseline_events if event.call.name in DANGEROUS_TOOLS]
    if unsafe_executed:
        print(f"  Baseline outcome: unsafe side effect would execute: {', '.join(unsafe_executed)}")
    return [baseline_event_to_dict(event) for event in baseline_events]


def print_rule_summary(events) -> None:
    blocked_events = [event for event in events if not event.decision.allowed]
    print("\nRule triggered")
    print("-" * 72)
    if not blocked_events:
        print("  none")
        return
    for event in blocked_events:
        print(f"  {event.decision.rule}: blocked {event.decision.action_name}")


def print_why(events) -> None:
    blocked_events = [event for event in events if not event.decision.allowed]
    print("\nWhy it was blocked/allowed")
    print("-" * 72)
    if not blocked_events:
        print("  All proposed actions satisfied least privilege, label, confirmation, and trace checks.")
        return

    for event in blocked_events:
        decision = event.decision
        context = decision.trace_context
        print(f"  {decision.action_name}: {decision.reason}")
        if decision.labels_seen:
            print(f"    labels involved: {format_labels(decision.labels_seen)}")
        if context.get("derived_from"):
            print(f"    derived from: {', '.join(context['derived_from'])}")
            print(f"    blocked flow: {', '.join(context['derived_from'])} -> {decision.action_name}")
        if decision.rule == "missing_prior_event":
            prior = context.get("prior_allowed_events", [])
            print(f"    prior allowed events: {', '.join(prior) if prior else 'none'}")


def run_and_print_scenario(scenario) -> dict[str, Any]:
    actions = planned_actions(scenario)

    print("\n" + "=" * 72)
    print(f"Scenario: {scenario.title}")
    print(f"ID: {scenario.name}")
    print("=" * 72)
    print("\nUser task")
    print("-" * 72)
    print(f"  {scenario.context.user_goal}")
    print(f"  Context: task_type={scenario.context.task_type}, user_confirmed={scenario.context.user_confirmed}")
    print(f"\nScenario note: {scenario.summary}")

    print_proposed_actions(actions)

    baseline_report: list[dict[str, Any]] = []
    if scenario.show_baseline:
        baseline_report = print_unsafe_baseline(scenario.name)

    events, monitor = run_scenario_with_monitor(POLICY_PATH, scenario)
    print("\nMonitor decision")
    print("-" * 72)
    print(summarize_events(events))
    print("\nProvenance")
    print("-" * 72)
    print(monitor.provenance.format())
    print_rule_summary(events)
    print_why(events)
    print("\nFinal result")
    print("-" * 72)
    print(f"  {scenario.final_result}")

    score = score_scenario(events, scenario)
    return {
        "name": scenario.name,
        "title": scenario.title,
        "task_type": scenario.context.task_type,
        "user_confirmed": scenario.context.user_confirmed,
        "user_goal": scenario.context.user_goal,
        "proposed_actions": [call_to_dict(call) for call in actions],
        "unsafe_baseline": baseline_report,
        "monitor_events": [event_to_dict(event) for event in events],
        "provenance": monitor.provenance.to_dict(),
        "score": score,
    }


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    try:
        scenarios = selected_scenarios(args)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    total_utility_hits = 0
    total_utility = 0
    total_security_hits = 0
    total_security = 0
    reports: list[dict[str, Any]] = []

    print("Sentinel Guard Demo")
    print("=" * 72)

    for scenario in scenarios:
        report = run_and_print_scenario(scenario)
        reports.append(report)
        score = report["score"]
        total_utility_hits += int(score["utility_hits"])
        total_utility += int(score["utility_total"])
        total_security_hits += int(score["security_hits"])
        total_security += int(score["security_total"])

    utility = total_utility_hits / total_utility if total_utility else 1.0
    security = total_security_hits / total_security if total_security else 1.0

    print("\nAggregate eval")
    print("-" * 72)
    print(f"Utility preservation: {total_utility_hits}/{total_utility} = {utility:.2%}")
    print(f"Unsafe-action blocking: {total_security_hits}/{total_security} = {security:.2%}")

    if args.json_report:
        payload = {
            "scenarios": reports,
            "aggregate_eval": {
                "utility_hits": total_utility_hits,
                "utility_total": total_utility,
                "utility_rate": utility,
                "security_hits": total_security_hits,
                "security_total": total_security,
                "security_rate": security,
            },
        }
        args.json_report.write_text(json.dumps(payload, indent=2) + "\n")
        print(f"\nJSON report written: {args.json_report}")


if __name__ == "__main__":
    main()
