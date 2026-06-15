# Contributing

Sentinel Guard is a small work-sample project, so contributions should keep the
scope narrow and readable.

Before opening a pull request:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
sentinel ui --smoke-test
```

Guidelines:

- Keep the deterministic monitor as the source of truth.
- Do not add real email, destructive file operations, or external API side
  effects to the demo tools.
- Prefer small examples and focused tests over framework-heavy integrations.
- Update `README.md` when changing user-facing commands.
