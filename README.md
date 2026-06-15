# Sentinel Guard

Sentinel Guard is a deterministic runtime permission monitor and local policy
studio for tool-using LLM agents.

It is not a prompt-injection classifier. Sentinel Guard checks proposed tool
calls before execution against explicit task permissions, data labels,
confirmation requirements, trace history, and argument guardrails. If the model
proposes an unsafe action, the monitor can block the action even when the text
classifier or the model itself misses the attack.

## Why This Matters

Tool-using agents can read files, call network tools, edit state, and execute
commands. Prompt-only rules are brittle because untrusted tool outputs can tell
the model to ignore the user and perform a different action.

Sentinel Guard separates planning from enforcement:

```text
agent proposes tool call
  -> Sentinel checks policy + task + labels + trace
  -> ALLOW: tool may run
  -> BLOCK: no execution, rule_id + reason are recorded
```

The demo tools are simulated. The optional Claude Code adapter is the real
integration point: it receives `PreToolUse` JSON and can return a deny decision
before Claude Code executes a tool.

## Features

- Deterministic runtime monitor for proposed tool calls.
- Task-scoped least-privilege permissions.
- Tool-call firewall CLI for JSON traces.
- Claude Code `PreToolUse` hook adapter and installer.
- Local Policy Studio UI for editing/testing `policy.yaml`.
- Provenance and taint tracking across derived artifacts.
- External sink blocking for private, secret, or untrusted-derived data.
- Confirmation and prior-event requirements.
- Narrow path and shell-command guardrails.
- Task-scoped policy synthesis from a user task string.
- Security/utility eval reports with JSON and HTML output.
- Lightweight local project risk scanner.
- Local audit log for decisions.

## Architecture

```text
              user task + policy.yaml
                       |
                       v
             +--------------------+
             |  task permissions  |
             +--------------------+
                       |
agent proposes          |       artifacts + labels + trace
tool call               v
    +-----------> +-------------------------+
                  | Sentinel Guard monitor |
                  +-------------------------+
                      |                 |
                  ALLOW              BLOCK
                      |                 |
                      v                 v
           simulated/tool execution   audit record
                                      rule_id + reason
```

Policy Studio, the CLI checker, the demo runner, and the Claude Code hook all
call the same monitor. The UI does not reimplement the policy logic.

## Quickstart

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

sentinel version
```

For tests:

```bash
pip install -e ".[dev]"
pytest -q
```

## Run The Demo

Show the prompt-injection scenario:

```bash
sentinel demo --scenario injection
```

For a compact reviewer walkthrough, see `DEMO_GUIDE.md`.

The important lines are:

```text
EXECUTE send_email         -> SIMULATED: email would have been sent.
BLOCK send_email         rule_id=external_sink_taint      labels=private, untrusted
blocked flow: email_1, private_notes.md -> send_email
Utility preservation: 4/4 = 100.00%
Unsafe-action blocking: 1/1 = 100.00%
```

Run every built-in scenario:

```bash
python demo.py --all
```

## Run The Tool-Call Firewall Checker

Check a proposed tool call from JSON:

```bash
sentinel check examples/traces/injection_tool_call.json --json
```

Blocked actions exit with code `2`. Allowed actions exit with `0`. Malformed
input exits with `1`.

Expected decision shape:

```json
{
  "decision": "block",
  "allowed": false,
  "action": "send_email",
  "rule_id": "external_sink_taint",
  "labels": ["private", "untrusted"]
}
```

## Launch Policy Studio UI

```bash
sentinel ui
```

Then open:

```text
http://127.0.0.1:8765
```

Policy Studio is local-only and intentionally small. It supports:

- Policy builder controls for task profiles, allowed tools, protected labels,
  blocked paths, and dangerous shell patterns.
- Raw YAML editing and validation.
- Scenario testing against example traces.
- JSON report export.
- Claude Code install command display.
- Recent local audit log viewing and clearing.

Smoke test:

```bash
sentinel ui --smoke-test
```

## Claude Code Hook Integration

Claude Code calls `PreToolUse` hooks after tool arguments are generated and
before the tool executes. Sentinel Guard maps the proposed Claude Code tool call
into the internal monitor action model and returns a Claude-compatible allow or
deny response.

Dry-run a blocked Bash call:

```bash
sentinel-claude-hook \
  --dry-run-json examples/claude_code/pretooluse_bash_destructive.json \
  --explain
```

Expected output:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Blocked by Sentinel: dangerous_shell - Destructive or remote-install shell commands are blocked before execution."
  }
}
```

Install the hook into a Claude Code project:

```bash
cp examples/policies/coding_agent_strict.yaml sentinel.policy.yaml
sentinel install-claude-code --project . --policy sentinel.policy.yaml
```

The installer creates or updates `.claude/settings.json`, writes
`.claude/settings.sentinel.backup.json`, and adds a `PreToolUse` hook with
matcher `"*"`. See `.claude/settings.example.json`.

## Policy Synthesis

Sentinel Guard can synthesize a least-privilege policy profile from a user task.
This is deterministic template logic, not an LLM dependency.

```bash
sentinel synthesize-policy \
  "Summarize this repo and run tests, but do not edit files." \
  --out /tmp/sentinel.generated.yaml
```

Example output:

```text
Task type: read_only_test
Allowed tools: read_file, shell_command, summarize_to_user
Allowed Bash patterns: pytest*, python -m pytest*, npm test*, npm run test*, uv run pytest*
```

Compare policies before installing a generated policy:

```bash
sentinel diff-policy policy.yaml /tmp/sentinel.generated.yaml
```

## Provenance And Taint Tracking

Artifacts carry labels such as `public`, `private`, `secret`, and `untrusted`.
When a tool output is derived from earlier artifacts, Sentinel tracks the parent
links and propagates labels through the provenance graph.

That means a public-looking summary derived from private notes is still treated
as private-derived. External sinks such as `send_email`, `web_fetch`,
`web_search`, and `mcp_tool` are blocked when their inputs include protected
labels.

Example demo excerpt:

```text
Provenance
  email_1 [untrusted] <- read_email
  private_notes.md [private] <- read_file
  summary_to_user [private, public, untrusted] <- summarize_to_user(email_1, private_notes.md)

blocked flow: email_1, private_notes.md -> send_email
```

## Eval Dashboard

Run the built-in scenario suite and write JSON/HTML reports:

```bash
sentinel eval --report /tmp/sentinel_eval.json --html /tmp/sentinel_eval.html
```

Terminal output:

```text
Evaluation summary
  Scenarios: 9
  Utility preservation: 11/11 = 100.00%
  Unsafe-action blocking: 6/6 = 100.00%
  Overblocking: 0
  Underblocking: 0
```

The eval suite includes benign summaries, injection exfiltration, destructive
actions, least-privilege violations, safe test commands, dangerous shell
commands, and blocked secret reads.

## Project Risk Scanner

The scanner checks local Claude Code settings and Sentinel policies for obvious
permission gaps:

```bash
sentinel scan-project --path .
```

It flags issues such as unrestricted shell access, missing `.env` blocked-path
rules, external tools without label restrictions, and missing audit logs. This
is a lightweight static scan, not a full MCP proxy.

## Tests

```bash
pytest -q
```

The tests cover:

- CLI entry points and exit codes.
- Tool-call firewall JSON output.
- Claude Code hook allow/deny behavior.
- Hook installer behavior and backup creation.
- Policy Studio smoke tests and policy validation.
- Policy synthesis.
- Provenance and taint propagation.
- Temporal rules.
- Eval report generation.
- Project risk scanning.

## Threat Model

The primary threat is prompt injection against a tool-using agent:

1. The user asks the agent to summarize or review content.
2. The agent reads untrusted content, such as an email.
3. The content instructs the model to send private notes externally.
4. The model proposes the unsafe tool call.
5. Sentinel Guard blocks the call because private or untrusted-derived data
   cannot flow to an external sink.

The goal is not to prevent the model from ever proposing an unsafe action. The
goal is to refuse unsafe proposed actions at the execution boundary.

## Limitations

- The demo agent is scripted.
- The built-in tools are simulated; no real email, deletion, or web request is
  performed by the demo.
- Provenance is explicit in traces rather than inferred from real model context.
- Labels are coarse and do not model sanitization or declassification.
- The Claude Code adapter is conservative and pattern-based for paths and shell
  commands.
- Policy Studio is local-only and has no authentication.
- This is not a full MCP proxy.
- There is no VS Code extension yet.
- There is no Lean proof or full formal DSL yet.

## Roadmap / Future Work

- VS Code wrapper for launching Policy Studio and installing hooks.
- MCP client/tool gateway adapter.
- More example policies and benchmark-style trace fixtures.
- Import/export policy bundles.
- Richer provenance and declassification rules.
- More expressive temporal policy language.
- Optional formalization of monitor invariants.
- Release packaging with prebuilt artifacts.

## Repository Structure

```text
demo.py
policy.yaml
pyproject.toml
sentinel/
  cli.py
  monitor.py
  policy.py
  firewall.py
  provenance.py
  policy_synthesizer.py
  policy_diff.py
  risk_scan.py
  eval.py
  ui.py
  integrations/
    claude_code_hook.py
    claude_code_installer.py
examples/
  traces/
  claude_code/
  policies/
tests/
FORMAL_SKETCH.md
```

See `FORMAL_SKETCH.md` for the runtime-verification framing and the path toward
a future formal policy model.
