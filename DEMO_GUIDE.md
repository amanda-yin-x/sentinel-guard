# 5-Minute Demo Guide

This is the tightest walkthrough for a reviewer. Keep the story simple:
Sentinel Guard is not classifying prompt text; it is enforcing permissions at
the tool-call boundary.

## 0. Setup

```bash
source .venv/bin/activate
sentinel version
```

Say: "This is an installable local CLI. The same monitor is used by the demo,
JSON checker, UI, and Claude Code hook."

## 1. Show The Attack And The Block

```bash
sentinel demo --scenario injection
```

Point to these lines:

```text
EXECUTE send_email         -> SIMULATED: email would have been sent.
BLOCK send_email         rule_id=external_sink_taint      labels=private, untrusted
blocked flow: email_1, private_notes.md -> send_email
```

Say: "The unsafe baseline would send the email. The monitor blocks the proposed
send because the body is derived from private notes and untrusted email."

## 2. Show The Machine-Readable Firewall

```bash
sentinel check examples/traces/injection_tool_call.json --json
```

This command exits `2` because the action is blocked. That is expected.

Point to:

```text
"decision": "block"
"rule_id": "external_sink_taint"
"labels": [
  "private",
  "untrusted"
]
```

Say: "This is the integration boundary. Any agent framework with a pre-tool-call
hook can adapt this JSON decision."

## 3. Show Claude Code Hook Shape

```bash
sentinel-claude-hook \
  --dry-run-json examples/claude_code/pretooluse_bash_destructive.json \
  --explain
```

Point to:

```text
"permissionDecision": "deny"
"Blocked by Sentinel: dangerous_shell"
```

Say: "Claude Code can call this before Bash, Read, Write, WebFetch, WebSearch,
or MCP tools. The adapter returns Claude-compatible `PreToolUse` output."

## 4. Show Eval Metrics

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

Say: "The eval is small but explicit: benign useful actions should still work,
unsafe actions should be blocked, and every block has a rule ID."

## 5. Show Policy Studio Without Explaining Every Control

```bash
sentinel ui
```

Open:

```text
http://127.0.0.1:8765
```

Click only three things:

1. Scenario Tester: choose `injection_tool_call.json`, run monitor, show BLOCK.
2. Policy Summary: show task types and allowed tools.
3. YAML Editor: show that policy is explicit YAML, not hidden prompt text.

Say: "The UI is only for local editing and explanation. The deterministic Python
monitor remains the source of truth."

## 6. Close With Limitations

Say: "This is an applied runtime verification prototype, not a proof assistant
project. The demo tools are simulated, the Claude Code hook is optional, and
there is no Lean proof or full formal DSL yet. The work sample shows the bridge
from prompt guardrails to explicit permissions, runtime monitoring, provenance,
audit trails, and security evals."
