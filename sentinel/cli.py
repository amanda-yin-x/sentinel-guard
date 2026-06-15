from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sentinel import __version__
from sentinel.audit import append_decision
from sentinel.firewall import (
    FirewallInputError,
    check_file,
    decision_to_dict,
    format_human_decision,
)
from sentinel.integrations.claude_code_installer import install_claude_code_hook
from sentinel.policy_synthesizer import write_synthesized_policy, synthesize_policy


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY_PATH = ROOT / "policy.yaml"


def add_check_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    check_parser = subparsers.add_parser(
        "check",
        help="Check one proposed tool call from a JSON trace file.",
    )
    check_parser.add_argument("input", type=Path, help="Path to a JSON tool-call trace.")
    check_parser.add_argument(
        "--policy",
        type=Path,
        default=DEFAULT_POLICY_PATH,
        help=f"Policy YAML path. Default: {DEFAULT_POLICY_PATH}",
    )
    check_parser.add_argument(
        "--json",
        action="store_true",
        help="Print the decision as machine-readable JSON.",
    )


def add_install_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    install_parser = subparsers.add_parser(
        "install-claude-code",
        help="Install the Sentinel Guard Claude Code PreToolUse hook.",
    )
    install_parser.add_argument("--project", type=Path, default=Path("."))
    install_parser.add_argument("--policy", type=Path, default=Path("sentinel.policy.yaml"))
    install_parser.add_argument("--task", default="coding_agent")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel Guard: local runtime permissions for tool-using agents.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    demo_parser = subparsers.add_parser("demo", help="Run demo scenarios.")
    demo_parser.add_argument("--all", action="store_true", help="Run every scenario.")
    demo_parser.add_argument("--scenario", help="Run one scenario by name or alias.")
    demo_parser.add_argument("--json-report", type=Path, help="Write a machine-readable audit report.")

    add_check_parser(subparsers)

    ui_parser = subparsers.add_parser("ui", help="Start the local Policy Studio.")
    ui_parser.add_argument("--host", default="127.0.0.1")
    ui_parser.add_argument("--port", type=int, default=8765)
    ui_parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY_PATH)
    ui_parser.add_argument("--smoke-test", action="store_true")
    ui_parser.add_argument("--no-open", action="store_true", help="Do not open a browser automatically.")

    add_install_parser(subparsers)

    synth_parser = subparsers.add_parser(
        "synthesize-policy",
        help="Generate a task-scoped Sentinel policy from a user task string.",
    )
    synth_parser.add_argument("task", help="User task to synthesize a policy for.")
    synth_parser.add_argument("--out", type=Path, help="Write generated policy YAML to this path.")

    eval_parser = subparsers.add_parser("eval", help="Run Sentinel Guard security/utility evals.")
    eval_parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY_PATH)
    eval_parser.add_argument("--report", type=Path, help="Write JSON eval report.")
    eval_parser.add_argument("--html", type=Path, help="Write HTML eval dashboard.")

    scan_parser = subparsers.add_parser("scan-project", help="Scan local agent settings/policies for permission risks.")
    scan_parser.add_argument("--path", type=Path, default=Path("."))
    scan_parser.add_argument("--json", action="store_true", help="Print findings as JSON.")

    diff_parser = subparsers.add_parser("diff-policy", help="Compare two Sentinel policy YAML files.")
    diff_parser.add_argument("old", type=Path)
    diff_parser.add_argument("new", type=Path)
    diff_parser.add_argument("--json", action="store_true", help="Print diff as JSON.")

    subparsers.add_parser("version", help="Print the Sentinel Guard version.")
    return parser.parse_args(argv)


def run_check(args: argparse.Namespace) -> int:
    try:
        result = check_file(args.policy, args.input)
    except (FirewallInputError, ValueError, OSError) as exc:
        if args.json:
            print(json.dumps({"decision": "error", "error": str(exc)}, indent=2))
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(decision_to_dict(result), indent=2))
    else:
        print(format_human_decision(result))

    append_decision(result.decision, source="sentinel check")
    return 0 if result.decision.allowed else 2


def run_demo(args: argparse.Namespace) -> int:
    forwarded: list[str] = []
    if args.all:
        forwarded.append("--all")
    if args.scenario:
        forwarded.extend(["--scenario", args.scenario])
    if args.json_report:
        forwarded.extend(["--json-report", str(args.json_report)])

    from sentinel.demo_runner import main as demo_main

    demo_main(forwarded)
    return 0


def run_ui(args: argparse.Namespace) -> int:
    from sentinel import ui

    forwarded = [
        "--host",
        args.host,
        "--port",
        str(args.port),
        "--policy",
        str(args.policy),
    ]
    if args.smoke_test:
        forwarded.append("--smoke-test")
    if args.no_open:
        forwarded.append("--no-open")
    return ui.main(forwarded)


def run_install_claude_code(args: argparse.Namespace) -> int:
    result = install_claude_code_hook(
        project_path=args.project,
        policy_path=args.policy,
        task_type=args.task,
    )
    print(result.summary)
    return 0


def run_synthesize_policy(args: argparse.Namespace) -> int:
    if args.out:
        profile = write_synthesized_policy(args.task, args.out)
    else:
        profile = synthesize_policy(args.task)
    print("Task-scoped policy synthesis")
    print(f"Task type: {profile.task_type}")
    print(f"Allowed tools: {', '.join(profile.allowed_tools) if profile.allowed_tools else 'none'}")
    print(f"Denied tools: {', '.join(profile.denied_tools) if profile.denied_tools else 'none'}")
    print(
        "Confirmation required: "
        f"{', '.join(profile.confirmation_required) if profile.confirmation_required else 'none'}"
    )
    if profile.allowed_bash_patterns:
        print(f"Allowed Bash patterns: {', '.join(profile.allowed_bash_patterns)}")
    print(f"Explanation: {profile.explanation}")
    if args.out:
        print(f"Policy written: {args.out}")
    else:
        print(profile.to_yaml())
    return 0


def run_eval(args: argparse.Namespace) -> int:
    from sentinel.eval import (
        evaluate_scenarios,
        format_eval_summary,
        write_html_report,
        write_json_report,
    )

    report = evaluate_scenarios(args.policy)
    print(format_eval_summary(report))
    if args.report:
        write_json_report(report, args.report)
        print(f"JSON report written: {args.report}")
    if args.html:
        write_html_report(report, args.html)
        print(f"HTML report written: {args.html}")
    return 0


def run_scan_project(args: argparse.Namespace) -> int:
    from sentinel.risk_scan import findings_to_dict, format_findings, scan_project

    findings = scan_project(args.path)
    if args.json:
        print(json.dumps({"findings": findings_to_dict(findings)}, indent=2))
    else:
        print(format_findings(findings))
    return 0


def run_diff_policy(args: argparse.Namespace) -> int:
    from sentinel.policy_diff import diff_policies, diff_to_json, format_policy_diff

    diff = diff_policies(args.old, args.new)
    if args.json:
        print(diff_to_json(diff), end="")
    else:
        print(format_policy_diff(diff))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.command == "demo":
        return run_demo(args)
    if args.command == "check":
        return run_check(args)
    if args.command == "ui":
        return run_ui(args)
    if args.command == "install-claude-code":
        return run_install_claude_code(args)
    if args.command == "synthesize-policy":
        return run_synthesize_policy(args)
    if args.command == "eval":
        return run_eval(args)
    if args.command == "scan-project":
        return run_scan_project(args)
    if args.command == "diff-policy":
        return run_diff_policy(args)
    if args.command == "version":
        print(f"Sentinel Guard {__version__}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
