from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel.types import Decision


def default_audit_log_path(base_dir: Path | None = None) -> Path:
    root = base_dir or Path.cwd()
    return root / ".sentinel" / "audit.log"


def append_decision(
    decision: Decision,
    source: str,
    audit_log_path: Path | None = None,
    extra: dict[str, Any] | None = None,
) -> Path:
    path = audit_log_path or default_audit_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    record: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "decision": "allow" if decision.allowed else "block",
        "allowed": decision.allowed,
        "action": decision.action_name,
        "rule_id": decision.rule,
        "reason": decision.reason,
        "labels": sorted(decision.labels_seen),
        "trace_context": dict(decision.trace_context),
    }
    if extra:
        record.update(extra)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    return path


def read_recent(audit_log_path: Path | None = None, limit: int = 20) -> list[dict[str, Any]]:
    path = audit_log_path or default_audit_log_path()
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records[-limit:]


def clear(audit_log_path: Path | None = None) -> Path:
    path = audit_log_path or default_audit_log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="utf-8")
    return path
