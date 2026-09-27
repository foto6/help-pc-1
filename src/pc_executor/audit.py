from __future__ import annotations

import json
from collections import Counter, deque
from pathlib import Path
from typing import Any, Protocol

from .models import AuditEvent

MAX_SANITIZED_AUDIT_EVENTS = 200
MAX_AUDIT_SCAN_BYTES = 2 * 1024 * 1024


class AuditSink(Protocol):
    def emit(self, event: AuditEvent) -> None: ...


def _sanitize_event(raw: AuditEvent | dict[str, Any]) -> dict[str, Any]:
    if isinstance(raw, AuditEvent):
        payload = raw.to_dict()
    else:
        payload = raw
    return {
        "request_id": str(payload.get("request_id") or ""),
        "action": str(payload.get("action") or ""),
        "phase": str(payload.get("phase") or ""),
        "timestamp": str(payload.get("timestamp") or ""),
        "dry_run": bool(payload.get("dry_run", False)),
        "outcome": payload.get("outcome") if isinstance(payload.get("outcome"), str) else None,
    }


def _usage(events: list[dict[str, Any]]) -> dict[str, Any]:
    finished = [event for event in events if event["phase"] == "finish"]
    by_action = Counter(event["action"] for event in finished if event["action"])
    by_outcome = Counter((event["outcome"] or "unknown") for event in finished)
    return {
        "contract_version": "pc_executor.usage_metrics.v1",
        "window_events": len(events),
        "completed_calls": len(finished),
        "actions": dict(sorted(by_action.items())),
        "outcomes": dict(sorted(by_outcome.items())),
    }


class InMemoryAuditSink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)

    def recent_sanitized(self, *, limit: int = 50) -> list[dict[str, Any]]:
        bounded = max(1, min(int(limit), MAX_SANITIZED_AUDIT_EVENTS))
        return [_sanitize_event(event) for event in self.events[-bounded:]]

    def usage_metrics(self) -> dict[str, Any]:
        events = [_sanitize_event(event) for event in self.events[-MAX_SANITIZED_AUDIT_EVENTS:]]
        return _usage(events)


class JsonlAuditSink:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event: AuditEvent) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")

    def _tail_records(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self.path.open("rb") as handle:
            handle.seek(0, 2)
            size = handle.tell()
            start = max(0, size - MAX_AUDIT_SCAN_BYTES)
            handle.seek(start)
            raw = handle.read(MAX_AUDIT_SCAN_BYTES)
        if start:
            newline = raw.find(b"\n")
            raw = raw[newline + 1 :] if newline >= 0 else b""
        rows: deque[dict[str, Any]] = deque(maxlen=MAX_SANITIZED_AUDIT_EVENTS)
        for line in raw.splitlines():
            if not line:
                continue
            try:
                payload = json.loads(line.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError):
                continue
            if isinstance(payload, dict):
                rows.append(_sanitize_event(payload))
        return list(rows)

    def recent_sanitized(self, *, limit: int = 50) -> list[dict[str, Any]]:
        bounded = max(1, min(int(limit), MAX_SANITIZED_AUDIT_EVENTS))
        return self._tail_records()[-bounded:]

    def usage_metrics(self) -> dict[str, Any]:
        return _usage(self._tail_records())
