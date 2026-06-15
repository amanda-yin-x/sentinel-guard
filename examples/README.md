# Examples

This directory contains small fixtures used by the demo, CLI checker, Policy
Studio, and Claude Code hook adapter.

## `traces/`

JSON tool-call firewall inputs:

- `benign_summary.json` allows a user-visible summary.
- `injection_tool_call.json` blocks prompt-injection exfiltration.
- `destructive_without_confirmation.json` blocks an unconfirmed delete.
- `public_send_with_confirmation.json` allows a confirmed public send.
- `least_privilege_violation.json` blocks an unrelated external tool.

## `claude_code/`

Claude Code `PreToolUse` fixture payloads for dry-running the hook adapter.

```bash
sentinel-claude-hook \
  --dry-run-json examples/claude_code/pretooluse_bash_destructive.json \
  --explain
```

## `policies/`

Example policy profiles:

- `coding_agent_strict.yaml`
- `coding_agent_balanced.yaml`
- `research_agent.yaml`
