from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(slots=True)
class ActionRequest:
    action: str
    params: dict[str, Any] = field(default_factory=dict)
    request_id: str = field(default_factory=lambda: str(uuid4()))
    dry_run: bool | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ActionRequest":
        return cls(
            action=str(raw["action"]),
            params=dict(raw.get("params") or {}),
            request_id=str(raw.get("request_id") or uuid4()),
            dry_run=raw.get("dry_run"),
        )


@dataclass(slots=True)
class ActionResult:
    request_id: str
    action: str
    ok: bool
    status: str
    started_at: str
    finished_at: str
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    dry_run: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AuditEvent:
    request_id: str
    action: str
    phase: str
    timestamp: str
    dry_run: bool
    outcome: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True, frozen=True)
class WindowInfo:
    hwnd: int
    title: str
    visible: bool
    pid: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True, frozen=True)
class ElementQuery:
    automation_id: str | None = None
    name: str | None = None
    control_type: str | None = None
    class_name: str | None = None
    window_title: str | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ElementQuery":
        allowed = {"automation_id", "name", "control_type", "class_name", "window_title"}
        return cls(**{k: raw.get(k) for k in allowed})


@dataclass(slots=True, frozen=True)
class ElementInfo:
    name: str | None
    automation_id: str | None
    control_type: str | None
    is_enabled: bool
    is_password: bool
    native_handle: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
