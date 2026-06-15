from __future__ import annotations

from pathlib import Path

from sentinel.eval import evaluate_scenarios, write_html_report, write_json_report


POLICY_PATH = Path(__file__).resolve().parents[1] / "policy.yaml"


def test_eval_computes_required_metrics():
    report = evaluate_scenarios(POLICY_PATH)
    summary = report["summary"]

    assert summary["scenarios"] >= 6
    assert "utility_rate" in summary
    assert "security_rate" in summary
    assert "overblocking" in summary
    assert "underblocking" in summary
    assert summary["rule_triggers"]["external_sink_taint"] >= 1


def test_eval_json_and_html_reports_are_generated(tmp_path: Path):
    report = evaluate_scenarios(POLICY_PATH)
    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"

    write_json_report(report, json_path)
    write_html_report(report, html_path)

    assert json_path.exists()
    assert '"summary"' in json_path.read_text()
    assert html_path.exists()
    assert "Sentinel Guard Eval Report" in html_path.read_text()
