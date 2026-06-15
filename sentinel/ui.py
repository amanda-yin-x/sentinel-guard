from __future__ import annotations

import argparse
import html
import json
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from sentinel.audit import append_decision, clear as clear_audit, default_audit_log_path, read_recent
from sentinel.firewall import (
    FirewallInputError,
    build_firewall_result_from_policy,
    decision_to_dict,
    load_json_file,
)
from sentinel.policy import Policy


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY_PATH = ROOT / "policy.yaml"
TRACE_DIR = ROOT / "examples" / "traces"
DEFAULT_EXPORT_POLICY_PATH = ROOT / "sentinel.policy.yaml"

TOOL_EFFECTS = {
    "read_email": "read",
    "read_file": "read",
    "read_secret_file": "read",
    "shell_command": "local_command",
    "write_file": "file_write",
    "edit_file": "file_write",
    "summarize_to_user": "user_output",
    "draft_to_user": "user_output",
    "send_email": "external_write",
    "web_request": "external_write",
    "web_fetch": "external_read",
    "web_search": "external_read",
    "mcp_tool": "external_tool",
    "delete_file": "destructive",
}
DEFAULT_BUILDER = {
    "task_profile": "coding_agent",
    "allowed_tools": [
        "read_file",
        "shell_command",
        "write_file",
        "edit_file",
        "web_fetch",
        "web_search",
        "mcp_tool",
    ],
    "confirmation_required": ["send_email", "delete_file"],
    "external_sinks": ["send_email", "web_request", "web_fetch", "web_search", "mcp_tool"],
    "protected_labels": ["private", "secret", "untrusted"],
    "blocked_path_patterns": [".env", "*.env", "*.env.*", "*secret*", "*credential*", "*id_rsa*"],
    "dangerous_shell_patterns": ["rm -rf*", "* rm -rf*", "sudo *", "chmod -R *", "*curl*|*sh*", "*wget*|*sh*"],
}
RULES = [
    ("external_sink_taint", "Private, secret, or untrusted data cannot flow to external sinks."),
    ("least_privilege", "A task can only use tools listed in its allowed set."),
    ("missing_confirmation", "Sensitive actions can require explicit confirmation."),
    ("missing_prior_event", "Actions can require earlier trace events such as draft_to_user."),
    ("dangerous_shell", "Shell commands matching blocked patterns are denied before execution."),
    ("blocked_path", "Reads of configured secret or credential paths are denied."),
    ("protected_write", "Writes to configured auth or security paths are denied."),
]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Start Sentinel Guard Policy Studio.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY_PATH)
    parser.add_argument("--smoke-test", action="store_true")
    parser.add_argument("--no-open", action="store_true")
    return parser.parse_args(argv)


def policy_from_yaml_text(text: str) -> Policy:
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("Policy YAML must contain a mapping at the top level.")
    tools = data.get("tools", {})
    tasks = data.get("tasks", {})
    temporal_rules = data.get("temporal_rules", [])
    if not isinstance(tools, dict):
        raise ValueError("Policy field 'tools' must be a mapping.")
    if not isinstance(tasks, dict):
        raise ValueError("Policy field 'tasks' must be a mapping.")
    if temporal_rules is None:
        temporal_rules = []
    if not isinstance(temporal_rules, list):
        raise ValueError("Policy field 'temporal_rules' must be a list when present.")
    return Policy(tools=tools, tasks=tasks, temporal_rules=temporal_rules)


def as_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item)]


def generate_policy_yaml(config: dict[str, Any]) -> str:
    task_profile = str(config.get("task_profile") or "custom")
    allowed_tools = as_string_list(config.get("allowed_tools"))
    confirmation_required = set(as_string_list(config.get("confirmation_required")))
    external_sinks = set(as_string_list(config.get("external_sinks")))
    protected_labels = as_string_list(config.get("protected_labels")) or ["private", "secret", "untrusted"]
    blocked_path_patterns = as_string_list(config.get("blocked_path_patterns"))
    dangerous_shell_patterns = as_string_list(config.get("dangerous_shell_patterns"))

    tools: dict[str, dict[str, Any]] = {}
    for tool_name, effect in TOOL_EFFECTS.items():
        rule: dict[str, Any] = {"effect": effect}
        if effect in {"read", "user_output", "local_command", "file_write"}:
            rule["returns_labels"] = ["public" if effect != "read" else "private"]
        if tool_name in external_sinks:
            rule["external_sink"] = True
            rule["deny_if_input_labels"] = protected_labels
        if tool_name in confirmation_required:
            rule["requires_confirmation"] = True
        if tool_name == "send_email":
            rule.setdefault("requires_prior_event", "draft_to_user")
        if tool_name == "read_file" and blocked_path_patterns:
            rule["deny_if_arg_matches"] = [
                {
                    "arg": "path",
                    "rule": "blocked_path",
                    "reason": "Protected paths such as secrets, credentials, and private keys may not be read.",
                    "patterns": blocked_path_patterns,
                }
            ]
        if tool_name == "shell_command" and dangerous_shell_patterns:
            rule["deny_if_arg_matches"] = [
                {
                    "arg": "command",
                    "rule": "dangerous_shell",
                    "reason": "Destructive or remote-install shell commands are blocked before execution.",
                    "patterns": dangerous_shell_patterns,
                }
            ]
        if tool_name in {"write_file", "edit_file"} and blocked_path_patterns:
            rule["deny_if_arg_matches"] = [
                {
                    "arg": "path",
                    "rule": "protected_write",
                    "reason": "Security-sensitive files require a narrower policy before editing.",
                    "patterns": blocked_path_patterns,
                }
            ]
        tools[tool_name] = rule

    policy = {
        "tools": tools,
        "tasks": {task_profile: {"allowed_tools": allowed_tools}},
        "guardrails": {
            "protected_labels": protected_labels,
            "blocked_path_patterns": blocked_path_patterns,
            "dangerous_shell_patterns": dangerous_shell_patterns,
        },
    }
    return yaml.safe_dump(policy, sort_keys=False)


def policy_summary(policy: Policy) -> dict[str, Any]:
    return {
        "tasks": [
            {
                "name": task_name,
                "allowed_tools": task.get("allowed_tools", []),
            }
            for task_name, task in sorted(policy.tasks.items())
        ],
        "tools": [
            {
                "name": tool_name,
                "effect": rule.get("effect", ""),
                "external_sink": bool(rule.get("external_sink", False)),
                "requires_confirmation": bool(rule.get("requires_confirmation", False)),
                "requires_prior_event": rule.get("requires_prior_event", ""),
                "deny_if_input_labels": rule.get("deny_if_input_labels", []),
                "arg_rules": rule.get("deny_if_arg_matches", []),
            }
            for tool_name, rule in sorted(policy.tools.items())
        ],
        "temporal_rules": [
            {
                "id": str(rule.get("id", "temporal_rule")),
                "before": str(rule.get("before", "")),
                "require_events": rule.get("require_events", []),
                "require_confirmation": bool(rule.get("require_confirmation", False)),
            }
            for rule in policy.temporal_rules
        ],
    }


def trace_options() -> list[str]:
    return sorted(path.name for path in TRACE_DIR.glob("*.json"))


def load_trace(trace_name: str) -> dict[str, Any]:
    if Path(trace_name).name != trace_name:
        raise FirewallInputError("Trace must be one of the local example filenames.")
    trace_path = TRACE_DIR / trace_name
    if trace_path not in TRACE_DIR.glob("*.json"):
        raise FirewallInputError(f"Unknown example trace: {trace_name}")
    return load_json_file(trace_path)


def install_status(policy_path: Path) -> dict[str, Any]:
    settings_path = Path.cwd() / ".claude" / "settings.json"
    return {
        "settings_exists": settings_path.exists(),
        "settings_path": str(settings_path),
        "policy_path": str(policy_path),
        "install_command": "sentinel install-claude-code --project . --policy sentinel.policy.yaml",
    }


def json_response(handler: BaseHTTPRequestHandler, payload: dict[str, Any], status: int = 200) -> None:
    body = json.dumps(payload, indent=2).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def text_response(handler: BaseHTTPRequestHandler, body: str, status: int = 200) -> None:
    encoded = body.encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(encoded)))
    handler.end_headers()
    handler.wfile.write(encoded)


def make_handler(policy_path: Path):
    class PolicyStudioHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            if path == "/":
                text_response(self, render_index(policy_path))
                return
            if path == "/api/policy":
                json_response(
                    self,
                    {
                        "policy_yaml": policy_path.read_text(),
                        "summary": policy_summary(Policy.from_yaml(policy_path)),
                        "traces": trace_options(),
                        "install": install_status(policy_path),
                        "audit": read_recent(),
                    },
                )
                return
            if path == "/api/audit":
                json_response(self, {"ok": True, "audit": read_recent()})
                return
            json_response(self, {"error": "not found"}, status=404)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            try:
                payload = json.loads(self.rfile.read(length).decode() or "{}")
                if not isinstance(payload, dict):
                    raise ValueError("Request body must be a JSON object.")
            except (json.JSONDecodeError, ValueError) as exc:
                json_response(self, {"ok": False, "error": str(exc)}, status=400)
                return

            path = urlparse(self.path).path
            if path == "/api/generate-policy":
                self.handle_generate(payload)
                return
            if path == "/api/summary":
                self.handle_summary(payload)
                return
            if path == "/api/check":
                self.handle_check(payload)
                return
            if path == "/api/save":
                self.handle_save(payload, policy_path)
                return
            if path == "/api/audit/clear":
                clear_audit()
                json_response(self, {"ok": True, "audit": []})
                return
            json_response(self, {"ok": False, "error": "not found"}, status=404)

        def handle_generate(self, payload: dict[str, Any]) -> None:
            try:
                policy_yaml = generate_policy_yaml(payload)
                policy = policy_from_yaml_text(policy_yaml)
            except (ValueError, yaml.YAMLError) as exc:
                json_response(self, {"ok": False, "error": str(exc)}, status=400)
                return
            json_response(
                self,
                {"ok": True, "policy_yaml": policy_yaml, "summary": policy_summary(policy)},
            )

        def handle_summary(self, payload: dict[str, Any]) -> None:
            try:
                policy = policy_from_yaml_text(str(payload.get("policy_yaml", "")))
            except (ValueError, yaml.YAMLError) as exc:
                json_response(self, {"ok": False, "error": str(exc)}, status=400)
                return
            json_response(self, {"ok": True, "summary": policy_summary(policy)})

        def handle_check(self, payload: dict[str, Any]) -> None:
            try:
                policy = policy_from_yaml_text(str(payload.get("policy_yaml", "")))
                trace = load_trace(str(payload.get("trace", "")))
                result = build_firewall_result_from_policy(policy, trace)
            except (ValueError, yaml.YAMLError, FirewallInputError) as exc:
                json_response(self, {"ok": False, "error": str(exc)}, status=400)
                return
            append_decision(result.decision, source="policy_studio", extra={"trace": payload.get("trace")})
            json_response(self, {"ok": True, "result": decision_to_dict(result), "audit": read_recent()})

        def handle_save(self, payload: dict[str, Any], active_policy_path: Path) -> None:
            policy_yaml = str(payload.get("policy_yaml", ""))
            target = str(payload.get("target", "export"))
            try:
                policy_from_yaml_text(policy_yaml)
            except (ValueError, yaml.YAMLError) as exc:
                json_response(self, {"ok": False, "error": str(exc)}, status=400)
                return

            output_path = active_policy_path if target == "source" else DEFAULT_EXPORT_POLICY_PATH
            output_path.write_text(policy_yaml)
            json_response(self, {"ok": True, "path": str(output_path), "install": install_status(output_path)})

    return PolicyStudioHandler


def render_index(policy_path: Path) -> str:
    policy_text = policy_path.read_text()
    summary = policy_summary(Policy.from_yaml(policy_path))
    traces = trace_options()
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sentinel Guard Policy Studio</title>
  <style>
    :root {{
      color-scheme: light;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f4f7fb;
      color: #172033;
    }}
    body {{ margin: 0; }}
    header {{
      background: #172033;
      color: #fff;
      padding: 16px 22px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      flex-wrap: wrap;
    }}
    header h1 {{ font-size: 22px; margin: 0; letter-spacing: 0; }}
    header span {{ color: #c9d7e8; font-size: 14px; }}
    main {{
      display: grid;
      grid-template-columns: minmax(300px, 0.9fr) minmax(360px, 1.1fr) minmax(320px, 0.9fr);
      gap: 14px;
      padding: 14px;
    }}
    section {{
      background: #fff;
      border: 1px solid #d9e2ee;
      border-radius: 8px;
      padding: 14px;
      margin-bottom: 14px;
    }}
    h2 {{ margin: 0 0 10px; font-size: 16px; letter-spacing: 0; }}
    h3 {{ margin: 14px 0 8px; font-size: 14px; letter-spacing: 0; }}
    label {{ display: block; font-size: 13px; margin: 6px 0; }}
    input[type="checkbox"] {{ margin-right: 6px; }}
    select, button, input[type="text"] {{
      border: 1px solid #b9c6d3;
      border-radius: 6px;
      padding: 8px 10px;
      background: #fff;
      color: #172033;
      font-size: 14px;
    }}
    button {{ cursor: pointer; background: #edf3f8; }}
    textarea {{
      width: 100%;
      box-sizing: border-box;
      border: 1px solid #c8d3df;
      border-radius: 6px;
      padding: 10px;
      font: 13px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      resize: vertical;
    }}
    #policyText {{ min-height: 520px; }}
    .small-textarea {{ min-height: 76px; }}
    .row {{ display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin: 10px 0; }}
    .grid2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 4px 10px; }}
    .muted {{ color: #607086; font-size: 13px; }}
    .status {{ min-height: 22px; font-size: 14px; color: #334155; }}
    .local {{ background: #f8fafc; border: 1px solid #d9e2ee; border-radius: 6px; padding: 8px; font-size: 13px; }}
    pre {{
      background: #101826;
      color: #e9f1ff;
      border-radius: 6px;
      padding: 12px;
      overflow: auto;
      min-height: 130px;
      font-size: 13px;
    }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ border-bottom: 1px solid #e6ecf3; padding: 7px 6px; text-align: left; vertical-align: top; }}
    .pill {{ display: inline-block; border: 1px solid #cad5e0; border-radius: 999px; padding: 2px 8px; margin: 2px 3px 2px 0; background: #f8fafc; white-space: nowrap; }}
    .decision-block {{ color: #b42318; font-weight: 700; }}
    .decision-allow {{ color: #067647; font-weight: 700; }}
    @media (max-width: 1080px) {{ main {{ grid-template-columns: 1fr; }} }}
  </style>
</head>
<body>
  <header>
    <h1>Sentinel Guard Policy Studio</h1>
    <span>Local only: http://127.0.0.1:8765</span>
  </header>
  <main>
    <div>
      <section>
        <h2>Policy Builder</h2>
        <label>Task profile</label>
        <select id="taskProfile">
          <option value="coding_agent">coding_agent</option>
          <option value="email_agent">email_agent</option>
          <option value="research_agent">research_agent</option>
          <option value="custom">custom</option>
        </select>
        <h3>Allowed tools</h3>
        <div class="grid2" id="allowedTools"></div>
        <h3>Confirmation required</h3>
        <div class="grid2" id="confirmationTools"></div>
        <h3>External sinks</h3>
        <div class="grid2" id="externalSinks"></div>
        <h3>Protected labels</h3>
        <div class="grid2" id="protectedLabels"></div>
        <h3>Blocked path patterns</h3>
        <textarea class="small-textarea" id="blockedPaths"></textarea>
        <h3>Dangerous shell patterns</h3>
        <textarea class="small-textarea" id="shellPatterns"></textarea>
        <div class="row">
          <button id="generateBtn">Generate YAML</button>
          <button id="validateBtn">Validate YAML</button>
        </div>
        <div class="status" id="builderStatus"></div>
      </section>
      <section>
        <h2>Install Panel</h2>
        <div class="local" id="installPanel">Loading install status...</div>
      </section>
    </div>
    <div>
      <section>
        <h2>YAML Editor</h2>
        <textarea id="policyText">{html.escape(policy_text)}</textarea>
        <div class="row">
          <button id="saveSourceBtn">Save current policy</button>
          <button id="exportBtn">Export sentinel.policy.yaml</button>
        </div>
        <div class="status" id="policyStatus"></div>
      </section>
      <section>
        <h2>Rule Table</h2>
        <table>
          <thead><tr><th>Rule ID</th><th>Meaning</th></tr></thead>
          <tbody>{''.join(f'<tr><td><code>{html.escape(rule)}</code></td><td>{html.escape(description)}</td></tr>' for rule, description in RULES)}</tbody>
        </table>
      </section>
    </div>
    <div>
      <section>
        <h2>Scenario Tester</h2>
        <div class="row">
          <select id="traceSelect">{''.join(f'<option value="{html.escape(trace)}">{html.escape(trace)}</option>' for trace in traces)}</select>
          <button id="runBtn">Run Monitor</button>
          <button id="exportReportBtn">Export JSON Report</button>
        </div>
        <pre id="resultBox">Choose a trace and run the monitor.</pre>
      </section>
      <section>
        <h2>Policy Summary</h2>
        <div id="summary"></div>
      </section>
      <section>
        <h2>Audit Log</h2>
        <div class="row">
          <button id="refreshAuditBtn">Refresh</button>
          <button id="clearAuditBtn">Clear log</button>
        </div>
        <pre id="auditBox">No audit entries loaded.</pre>
      </section>
    </div>
  </main>
  <script>
    const initialSummary = {json.dumps(summary)};
    const initialInstall = {json.dumps(install_status(policy_path))};
    const defaultBuilder = {json.dumps(DEFAULT_BUILDER)};
    const allTools = {json.dumps(list(TOOL_EFFECTS.keys()))};
    const labels = ["private", "secret", "untrusted", "credential"];
    let lastReport = null;

    function checkboxList(containerId, names, checked) {{
      const container = document.getElementById(containerId);
      container.innerHTML = names.map(name => `
        <label><input type="checkbox" value="${{name}}" ${{checked.includes(name) ? "checked" : ""}}>${{name}}</label>
      `).join("");
    }}

    function selected(containerId) {{
      return Array.from(document.querySelectorAll(`#${{containerId}} input:checked`)).map(input => input.value);
    }}

    function lines(id) {{
      return document.getElementById(id).value.split("\\n").map(line => line.trim()).filter(Boolean);
    }}

    function builderConfig() {{
      return {{
        task_profile: document.getElementById("taskProfile").value,
        allowed_tools: selected("allowedTools"),
        confirmation_required: selected("confirmationTools"),
        external_sinks: selected("externalSinks"),
        protected_labels: selected("protectedLabels"),
        blocked_path_patterns: lines("blockedPaths"),
        dangerous_shell_patterns: lines("shellPatterns")
      }};
    }}

    function toolsList(items) {{
      return (items || []).map(item => `<span class="pill">${{item}}</span>`).join("");
    }}

    function renderSummary(summary) {{
      const taskRows = summary.tasks.map(task => `<tr><td><code>${{task.name}}</code></td><td>${{toolsList(task.allowed_tools)}}</td></tr>`).join("");
      const toolRows = summary.tools.map(tool => `
        <tr>
          <td><code>${{tool.name}}</code></td>
          <td>${{tool.effect}}</td>
          <td>${{tool.external_sink ? "yes" : "no"}}</td>
          <td>${{tool.requires_confirmation ? "yes" : "no"}}</td>
          <td>${{tool.requires_prior_event || ""}}</td>
        </tr>
      `).join("");
      const temporalRows = (summary.temporal_rules || []).map(rule => `
        <tr>
          <td><code>${{rule.id}}</code></td>
          <td><code>${{rule.before}}</code></td>
          <td>${{toolsList(rule.require_events || [])}}</td>
          <td>${{rule.require_confirmation ? "yes" : "no"}}</td>
        </tr>
      `).join("");
      document.getElementById("summary").innerHTML = `
        <h3>Task Types</h3>
        <table><thead><tr><th>Task</th><th>Allowed tools</th></tr></thead><tbody>${{taskRows}}</tbody></table>
        <h3>Tool Rules</h3>
        <table><thead><tr><th>Tool</th><th>Effect</th><th>Sink</th><th>Confirm</th><th>Prior</th></tr></thead><tbody>${{toolRows}}</tbody></table>
        <h3>Temporal Rules</h3>
        <table><thead><tr><th>Rule</th><th>Before</th><th>Required events</th><th>Confirm</th></tr></thead><tbody>${{temporalRows || "<tr><td colspan='4'>none</td></tr>"}}</tbody></table>
      `;
    }}

    function renderInstall(install) {{
      document.getElementById("installPanel").innerHTML = `
        <div><strong>.claude/settings.json:</strong> ${{install.settings_exists ? "exists" : "not found"}}</div>
        <div><strong>Settings path:</strong><br><code>${{install.settings_path}}</code></div>
        <div><strong>Current policy:</strong><br><code>${{install.policy_path}}</code></div>
        <div style="margin-top:8px"><strong>Command:</strong><br><code>${{install.install_command}}</code></div>
      `;
    }}

    async function postJSON(path, payload) {{
      const response = await fetch(path, {{
        method: "POST",
        headers: {{"Content-Type": "application/json"}},
        body: JSON.stringify(payload)
      }});
      const body = await response.json();
      if (!response.ok || body.ok === false) throw new Error(body.error || "request failed");
      return body;
    }}

    async function getJSON(path) {{
      const response = await fetch(path);
      const body = await response.json();
      if (!response.ok || body.ok === false) throw new Error(body.error || "request failed");
      return body;
    }}

    async function generatePolicy() {{
      const status = document.getElementById("builderStatus");
      try {{
        const body = await postJSON("/api/generate-policy", builderConfig());
        document.getElementById("policyText").value = body.policy_yaml;
        renderSummary(body.summary);
        status.textContent = "Generated policy YAML from builder settings.";
      }} catch (error) {{
        status.textContent = `Generation failed: ${{error.message}}`;
      }}
    }}

    async function validatePolicy() {{
      const status = document.getElementById("builderStatus");
      try {{
        const body = await postJSON("/api/summary", {{policy_yaml: document.getElementById("policyText").value}});
        renderSummary(body.summary);
        status.textContent = "Policy YAML is valid.";
      }} catch (error) {{
        status.textContent = `Invalid policy: ${{error.message}}`;
      }}
    }}

    async function savePolicy(target) {{
      const status = document.getElementById("policyStatus");
      try {{
        const body = await postJSON("/api/save", {{policy_yaml: document.getElementById("policyText").value, target}});
        status.textContent = `Saved: ${{body.path}}`;
        renderInstall(body.install);
      }} catch (error) {{
        status.textContent = `Save failed: ${{error.message}}`;
      }}
    }}

    function renderDecision(result) {{
      const cls = result.decision === "block" ? "decision-block" : "decision-allow";
      return `Decision: <span class="${{cls}}">${{result.decision.toUpperCase()}}</span>
Action: ${{result.action}}
Rule: ${{result.rule_id}}
Labels: ${{(result.labels || []).join(", ") || "none"}}
Reason: ${{result.reason}}

Trace context:
${{JSON.stringify(result.trace_context, null, 2)}}`;
    }}

    async function runMonitor() {{
      const resultBox = document.getElementById("resultBox");
      try {{
        const body = await postJSON("/api/check", {{
          policy_yaml: document.getElementById("policyText").value,
          trace: document.getElementById("traceSelect").value
        }});
        lastReport = body.result;
        resultBox.innerHTML = renderDecision(body.result);
        renderAudit(body.audit);
      }} catch (error) {{
        resultBox.textContent = `Error: ${{error.message}}`;
      }}
    }}

    function exportReport() {{
      if (!lastReport) return;
      const blob = new Blob([JSON.stringify(lastReport, null, 2)], {{type: "application/json"}});
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "sentinel-report.json";
      link.click();
      URL.revokeObjectURL(url);
    }}

    function renderAudit(records) {{
      const box = document.getElementById("auditBox");
      if (!records || records.length === 0) {{
        box.textContent = "No audit entries.";
        return;
      }}
      box.textContent = records.slice().reverse().map(record =>
        `${{record.timestamp}}  ${{record.decision.toUpperCase()}}  ${{record.action}}  ${{record.rule_id}}\\n${{record.reason}}`
      ).join("\\n\\n");
    }}

    async function refreshAudit() {{
      try {{
        const body = await getJSON("/api/audit");
        renderAudit(body.audit);
      }} catch (error) {{
        document.getElementById("auditBox").textContent = `Audit error: ${{error.message}}`;
      }}
    }}

    async function clearAuditLog() {{
      const body = await postJSON("/api/audit/clear", {{}});
      renderAudit(body.audit);
    }}

    checkboxList("allowedTools", allTools, defaultBuilder.allowed_tools);
    checkboxList("confirmationTools", allTools, defaultBuilder.confirmation_required);
    checkboxList("externalSinks", allTools, defaultBuilder.external_sinks);
    checkboxList("protectedLabels", labels, defaultBuilder.protected_labels);
    document.getElementById("blockedPaths").value = defaultBuilder.blocked_path_patterns.join("\\n");
    document.getElementById("shellPatterns").value = defaultBuilder.dangerous_shell_patterns.join("\\n");
    document.getElementById("generateBtn").addEventListener("click", generatePolicy);
    document.getElementById("validateBtn").addEventListener("click", validatePolicy);
    document.getElementById("saveSourceBtn").addEventListener("click", () => savePolicy("source"));
    document.getElementById("exportBtn").addEventListener("click", () => savePolicy("export"));
    document.getElementById("runBtn").addEventListener("click", runMonitor);
    document.getElementById("exportReportBtn").addEventListener("click", exportReport);
    document.getElementById("refreshAuditBtn").addEventListener("click", refreshAudit);
    document.getElementById("clearAuditBtn").addEventListener("click", clearAuditLog);
    renderSummary(initialSummary);
    renderInstall(initialInstall);
    refreshAudit();
  </script>
</body>
</html>"""


def run_smoke_test(policy_path: Path) -> int:
    policy_text = policy_path.read_text()
    policy = policy_from_yaml_text(policy_text)
    summary = policy_summary(policy)
    traces = trace_options()
    generated = generate_policy_yaml(DEFAULT_BUILDER)
    policy_from_yaml_text(generated)
    if not summary["tasks"] or not summary["tools"]:
        raise SystemExit("Policy Studio smoke test failed: empty policy summary.")
    if not traces:
        raise SystemExit("Policy Studio smoke test failed: no example traces found.")
    render_index(policy_path)
    print(
        "Policy Studio smoke test passed: "
        f"{len(summary['tasks'])} task types, {len(summary['tools'])} tools, {len(traces)} traces. "
        f"Audit log: {default_audit_log_path()}"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.smoke_test:
        return run_smoke_test(args.policy)

    server = HTTPServer((args.host, args.port), make_handler(args.policy))
    url = f"http://{args.host}:{args.port}"
    print(f"Sentinel Guard Policy Studio running at {url}")
    if not args.no_open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nPolicy Studio stopped.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
