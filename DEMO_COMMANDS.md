# Demo Commands

## 0. Before Recording

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
pytest -q
```

## 1. Opening

```bash
source .venv/bin/activate
sentinel version
```

## 2. Attack And Block

```bash
sentinel demo --scenario injection
```

## 3. Tool-Call Firewall

```bash
sentinel check examples/traces/injection_tool_call.json --json
```

## 4. Policy Synthesis

```bash
sentinel synthesize-policy \
  "Summarize this repo and run tests, but do not edit files." \
  --out /tmp/sentinel.generated.yaml
```

## 5. Policy Diff

```bash
sentinel diff-policy policy.yaml /tmp/sentinel.generated.yaml
```

## 6. Policy Studio

```bash
sentinel ui
```

```bash
open http://127.0.0.1:8765
```

## 7. Eval Metrics

```bash
sentinel eval --report /tmp/sentinel_eval.json --html /tmp/sentinel_eval.html
```

## 8. Optional Claude Code Fixture

```bash
sentinel-claude-hook \
  --dry-run-json examples/claude_code/pretooluse_bash_destructive.json \
  --explain
```

## 9. Optional Claude Code Install Later

```bash
source .venv/bin/activate
cp examples/policies/coding_agent_strict.yaml sentinel.policy.yaml
sentinel install-claude-code --project . --policy sentinel.policy.yaml
claude
```

```text
/hooks
```
