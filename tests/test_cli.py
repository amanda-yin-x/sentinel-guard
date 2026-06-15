from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "sentinel", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )


def test_cli_benign_trace_exits_zero():
    result = run_cli("check", "examples/traces/benign_summary.json")
    assert result.returncode == 0
    assert "Decision: ALLOW" in result.stdout
    assert "Action: summarize_to_user" in result.stdout


def test_cli_blocked_injection_exits_two():
    result = run_cli("check", "examples/traces/injection_tool_call.json")
    assert result.returncode == 2
    assert "Decision: BLOCK" in result.stdout
    assert "Rule ID: external_sink_taint" in result.stdout


def test_cli_malformed_json_exits_one(tmp_path: Path):
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{not valid json")

    result = run_cli("check", str(malformed))
    assert result.returncode == 1
    assert "Malformed JSON" in result.stderr


def test_cli_json_output_has_decision_fields():
    result = run_cli("check", "examples/traces/injection_tool_call.json", "--json")
    assert result.returncode == 2

    payload = json.loads(result.stdout)
    assert payload["decision"] == "block"
    assert payload["action"] == "send_email"
    assert payload["rule_id"] == "external_sink_taint"
    assert payload["reason"]
    assert payload["labels"] == ["private", "untrusted"]


def test_cli_version_command():
    result = run_cli("version")
    assert result.returncode == 0
    assert "Sentinel Guard" in result.stdout


def test_cli_demo_scenario_command():
    result = run_cli("demo", "--scenario", "injection")
    assert result.returncode == 0
    assert "Prompt-injection exfiltration attempt is blocked" in result.stdout
    assert "external_sink_taint" in result.stdout


def test_cli_synthesize_policy_writes_file(tmp_path: Path):
    out = tmp_path / "generated.policy.yaml"
    result = run_cli(
        "synthesize-policy",
        "Summarize this repo and run tests, but do not edit files.",
        "--out",
        str(out),
    )
    assert result.returncode == 0
    assert out.exists()
    assert "Task type: read_only_test" in result.stdout


def test_cli_eval_writes_reports(tmp_path: Path):
    report = tmp_path / "eval.json"
    html = tmp_path / "eval.html"
    result = run_cli("eval", "--report", str(report), "--html", str(html))
    assert result.returncode == 0
    assert "Evaluation summary" in result.stdout
    assert report.exists()
    assert html.exists()


def test_cli_scan_project():
    result = run_cli("scan-project", "--path", ".")
    assert result.returncode == 0
    assert "Risk scan" in result.stdout
