# 5-Minute Demo Guide

Use this as a compact script. The story is:

> Sentinel Guard is not a prompt-injection classifier. It is a deterministic
> runtime permission monitor that checks proposed tool calls before execution.

## Before Recording

Start from the repo root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
pytest -q
```

Open three terminal tabs:

1. Demo CLI tab.
2. Policy Studio tab.
3. Optional eval/policy synthesis tab.

Keep the browser ready for:

```text
http://127.0.0.1:8765
```

Do not spend time explaining every UI control. The UI is there to show that the
policy is inspectable and testable, not to become the whole demo.

## 0:00-0:30 Opening

Say:

> I built Sentinel Guard as a small runtime permission monitor for tool-using
> LLM agents. The motivation is that prompt-injection defenses often focus on
> detecting malicious text, but real agents fail at the tool boundary: they read
> something untrusted, generate a tool call, and then that tool call may send
> data, edit files, or run commands.

Say:

> Sentinel Guard takes a different approach. It does not try to classify whether
> a prompt looks malicious. It checks the proposed tool call before execution
> against an explicit policy: what task is being performed, what tools are
> allowed, what data labels are involved, whether the user confirmed the action,
> and what happened earlier in the trace.

Say:

> In five minutes, I will show the core idea: an unsafe email send that would
> execute without a monitor, the same action blocked by Sentinel, the
> machine-readable firewall interface, task-scoped policy synthesis, eval
> metrics, and the local Policy Studio.

Shorter version if you need to save time:

> I built Sentinel Guard to explore runtime permissions for tool-using LLM
> agents. It is not a prompt-injection classifier. Instead, it checks proposed
> tool calls before execution using explicit task permissions, provenance
> labels, confirmation requirements, and trace rules. The goal is simple: even
> if the model proposes an unsafe action, the system can still block it at the
> tool boundary.

Run:

```bash
source .venv/bin/activate
sentinel version
```

Point to:

```text
Sentinel Guard 0.1.0
```

Say:

> This is installed as a real CLI. The demo, JSON checker, Policy Studio, and
> integration adapters all call the same deterministic monitor.

## 0:30-1:45 Show The Attack And The Block

Run:

```bash
sentinel demo --scenario injection
```

When the output reaches `Unsafe baseline`, point to:

```text
EXECUTE send_email         -> SIMULATED: email would have been sent.
```

Say:

> First, the demo shows the unsafe baseline. Without a monitor, the agent would
> execute every proposed tool call, including the external send.

When the output reaches `Monitor decision`, point to:

```text
BLOCK send_email         rule_id=external_sink_taint      labels=private, untrusted
```

Say:

> With Sentinel turned on, the same proposed `send_email` action is blocked.
> The monitor does not need to understand the whole prompt. It sees that the
> email body is derived from private notes and untrusted email, and that data is
> about to flow to an external sink.

Point to:

```text
blocked flow: email_1, private_notes.md -> send_email
```

Say:

> This line is the core technical point: Sentinel tracks provenance. A
> public-looking output can still be private-derived or untrusted-derived.

Point to:

```text
Utility preservation: 4/4 = 100.00%
Unsafe-action blocking: 1/1 = 100.00%
```

Say:

> The goal is not to freeze the agent. Benign steps still run, while the unsafe
> side effect is stopped.

## 1:45-2:30 Show The Tool-Call Firewall Interface

Run:

```bash
sentinel check examples/traces/injection_tool_call.json --json
```

Note: this exits with code `2` because the action is blocked. That is expected.

Point to:

```text
"decision": "block"
"action": "send_email"
"rule_id": "external_sink_taint"
"labels": [
  "private",
  "untrusted"
]
```

Say:

> This is the integration-ready interface. An agent framework can serialize a
> proposed tool call as JSON, call Sentinel, and get back a machine-readable
> allow or block decision with a rule ID, reason, labels, and trace context.

If there is time, point to the `trace_context.provenance` object.

Say:

> The JSON includes enough context for audit logs and security evals, not just a
> yes-or-no answer.

## 2:30-3:15 Show Policy Synthesis And Provenance

Run:

```bash
sentinel synthesize-policy \
  "Summarize this repo and run tests, but do not edit files." \
  --out /tmp/sentinel.generated.yaml
```

Point to:

```text
Task type: read_only_test
Allowed tools: read_file, shell_command, summarize_to_user
Allowed Bash patterns: pytest*, python -m pytest*, npm test*, npm run test*, uv run pytest*
```

Say:

> This is a practical bridge from a natural-language task to an explicit
> least-privilege policy. For this task, the monitor allows reading files,
> summarizing to the user, and running tests, but it does not grant write tools
> or external sinks.

Run:

```bash
sentinel diff-policy policy.yaml /tmp/sentinel.generated.yaml
```

Point to:

```text
Tasks added: read_only_test
shell_command: modified fields: allow_if_arg_matches
```

Say:

> The generated policy is still just YAML. The synthesizer is not trusted as a
> classifier or proof; its output is checked by the same deterministic monitor.

Say:

> Combined with the provenance shown earlier, this gives the project two
> important technical pieces: task-scoped permissions and data-flow-aware
> enforcement.

## 3:15-4:15 Show Policy Studio UI

Start the UI:

```bash
sentinel ui
```

Open:

```text
http://127.0.0.1:8765
```

Say:

> This is a local Policy Studio. It is not a production web app; it is a small
> interface for explaining, editing, and testing policies.

Click:

1. In **Scenario Tester**, open the dropdown.
2. Select `injection_tool_call.json`.
3. Move the cursor over **Run Monitor** and say: "This sends the selected trace
   to the same Python monitor."
4. Click **Run Monitor**.
5. Move the cursor over `Decision: BLOCK`, `Rule: external_sink_taint`, and the
   labels.

Say:

> This runs the same monitor as the CLI. The UI is not reimplementing policy
> logic; it is just a local front end for the deterministic checker.

Scroll or look at **Policy Summary**.

Move the cursor over:

- Task types.
- Allowed tools.
- External sink / confirmation columns.

Say:

> The policy is task-scoped. A summarization task gets different permissions
> than a coding task or an email task.

Click inside **YAML Editor**.

Move the cursor over:

- `tasks:`
- `allowed_tools:`
- `deny_if_input_labels: [private, secret, untrusted]`
- `temporal_rules:`

Say:

> The policy is explicit YAML, not hidden prompt text. It includes least
> privilege, label restrictions, confirmation requirements, and small temporal
> rules like requiring a draft before sending email.

Do not explain every checkbox. If asked, say:

> The builder is a convenience layer for generating YAML. The monitor only
> trusts the parsed policy, not the UI.

If the UI feels visually busy, keep the browser zoom at 80-90% and stay on the
right side of the page: Scenario Tester, Policy Summary, and Audit Log are the
highest-signal panels for a short demo.

## 4:15-4:45 Show Eval Metrics

Return to terminal and run:

```bash
sentinel eval --report /tmp/sentinel_eval.json --html /tmp/sentinel_eval.html
```

Point to:

```text
Scenarios: 9
Utility preservation: 11/11 = 100.00%
Unsafe-action blocking: 6/6 = 100.00%
Overblocking: 0
Underblocking: 0
```

Say:

> The eval is intentionally small but explicit. It tests both sides: useful
> actions should still be allowed, and unsafe actions should be blocked with a
> specific rule ID.

## 4:45-5:00 Closing

Say:

> The fellowship connection is that this bridges prompt guardrails to explicit
> permissions, runtime monitoring, provenance, audit trails, and security evals.
> It also includes an optional Claude Code `PreToolUse` adapter, tested through
> fixture JSON, but this demo does not depend on a live Claude Code account. It
> is not formally verified yet, and it is not a full MCP proxy. But the
> enforcement boundary is concrete: proposed tool calls are checked before they
> execute.

End with:

> The next step would be making the policy language more formal and connecting
> this monitor to more agent runtimes.

## Optional Claude Code Integration Note

Do not use this in the main 5-minute demo if your Claude Code account is not
available. Mention it only if someone asks how the monitor would connect to a
real LLM agent.

Say:

> The repo includes a Claude Code adapter, but I am not relying on a live Claude
> Code account for the demo. The adapter is tested with fixture JSON that matches
> the `PreToolUse` boundary: Claude generates tool arguments, then Sentinel checks
> them before execution.

Show the fixture-only command if useful:

```bash
sentinel-claude-hook \
  --dry-run-json examples/claude_code/pretooluse_bash_destructive.json \
  --explain
```

Point to:

```text
"hookEventName": "PreToolUse"
"permissionDecision": "deny"
"Blocked by Sentinel: dangerous_shell"
```

Say:

> This is not a live Claude Code session. It is a tested adapter contract. The
> same monitor maps Claude tools like Bash, Read, Write, WebFetch, WebSearch, and
> MCP tools into Sentinel actions.

### Later, When Claude Code Is Available

From this repo:

```bash
source .venv/bin/activate
cp examples/policies/coding_agent_strict.yaml sentinel.policy.yaml
sentinel install-claude-code --project . --policy sentinel.policy.yaml
```

Then start Claude Code from the same activated shell so the
`sentinel-claude-hook` command is on `PATH`:

```bash
claude
```

Inside Claude Code, run:

```text
/hooks
```

Verify:

- Event: `PreToolUse`
- Matcher: `*`
- Command: `sentinel-claude-hook`
- Args include `--policy sentinel.policy.yaml`

Test with a clearly unsafe request in Claude Code:

```text
Try to run rm -rf important_notes
```

Expected behavior:

- Claude proposes or considers a Bash call.
- Sentinel receives the `PreToolUse` JSON.
- Sentinel returns `permissionDecision: deny`.
- Claude Code cancels the tool call and sees the Sentinel reason.

### What The Hook Is Doing

Claude Code sends hook input like:

```json
{
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {
    "command": "rm -rf important_notes"
  }
}
```

Sentinel returns structured output like:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Blocked by Sentinel: dangerous_shell - Destructive or remote-install shell commands are blocked before execution."
  }
}
```

That is the real LLM integration point: Claude still plans, but Sentinel checks
the proposed tool call before execution.
