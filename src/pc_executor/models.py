from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable
from uuid import uuid4


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(slots=True)
class ActionRequest:
    action: str
    params: dict[str, Any] = field(default_factory=dict)
    request_id: str = field(default_factory=lambda: str(uuid4()))
    dry_run: bool | None = None
    timeout_ms: int | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ActionRequest":
        if not isinstance(raw, dict):
            raise ValueError("request must be an object")
        action = raw.get("action")
        if not isinstance(action, str) or not action.strip():
            raise ValueError("action must be a non-empty string")
        params = raw.get("params", {})
        if params is None:
            params = {}
        if not isinstance(params, dict):
            raise ValueError("params must be an object")
        timeout_ms = raw.get("timeout_ms")
        if timeout_ms is not None:
            if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or timeout_ms <= 0:
                raise ValueError("timeout_ms must be a positive integer")
        dry_run = raw.get("dry_run")
        if dry_run is not None and not isinstance(dry_run, bool):
            raise ValueError("dry_run must be a boolean or null")
        return cls(
            action=action,
            params=dict(params),
            request_id=str(raw.get("request_id") or uuid4()),
            dry_run=dry_run,
            timeout_ms=timeout_ms,
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
    error_kind: str | None = None
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
class Rect:
    x: int
    y: int
    width: int
    height: int

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


@dataclass(slots=True, frozen=True)
class DisplayGeometry:
    display_id: str
    bounds: Rect
    is_primary: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"display_id": self.display_id, "bounds": self.bounds.to_dict(), "is_primary": self.is_primary}


@dataclass(slots=True, frozen=True)
class WindowInfo:
    hwnd: int
    title: str
    visible: bool
    pid: int | None = None
    app_name: str | None = None

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
        if not isinstance(raw, dict):
            raise ValueError("UIA query must be an object")
        allowed = {"automation_id", "name", "control_type", "class_name", "window_title"}
        unknown = set(raw) - allowed
        if unknown:
            raise ValueError(f"unsupported UIA query keys: {sorted(unknown)}")
        values = {k: raw.get(k) for k in allowed}
        for key, value in values.items():
            if value is not None and not isinstance(value, str):
                raise ValueError(f"UIA query {key} must be a string or null")
        if not any(value and value.strip() for value in values.values()):
            raise ValueError("UIA query requires at least one non-empty selector")
        return cls(**values)


@dataclass(slots=True, frozen=True)
class ElementInfo:
    name: str | None
    automation_id: str | None
    control_type: str | None
    is_enabled: bool
    is_password: bool
    native_handle: int | None = None
    bounds: Rect | None = None
    display_id: str | None = None
    window_handle: int | None = None
    process_id: int | None = None
    class_name: str | None = None
    is_offscreen: bool = False
    supports_invoke: bool = False
    supports_value: bool = False

    def to_dict(self) -> dict[str, Any]:
        raw = asdict(self)
        if self.bounds is not None:
            raw["bounds"] = self.bounds.to_dict()
        return raw


@dataclass(slots=True, frozen=True)
class UINodeSnapshot:
    node_id: str
    role: str | None
    name: str | None
    automation_id: str | None
    class_name: str | None
    is_enabled: bool
    is_offscreen: bool
    bounds: Rect | None
    display_id: str | None
    window_handle: int | None
    process_id: int | None
    supports_invoke: bool
    supports_value: bool

    def to_dict(self) -> dict[str, Any]:
        raw = asdict(self)
        if self.bounds is not None:
            raw["bounds"] = self.bounds.to_dict()
        return raw


@dataclass(slots=True, frozen=True)
class UIObservationSnapshot:
    snapshot_id: str
    captured_at: str
    app: dict[str, Any]
    window: dict[str, Any]
    displays: tuple[DisplayGeometry, ...]
    nodes: tuple[UINodeSnapshot, ...]

    @classmethod
    def create(
        cls,
        *,
        app: dict[str, Any],
        window: dict[str, Any],
        displays: Iterable[DisplayGeometry],
        nodes: Iterable[UINodeSnapshot],
        captured_at: str | None = None,
    ) -> "UIObservationSnapshot":
        captured = captured_at or utc_now_iso()
        ordered_displays = tuple(sorted(displays, key=lambda d: d.display_id))
        ordered_nodes = tuple(sorted(nodes, key=lambda n: n.node_id))
        body = {
            "captured_at": captured,
            "app": app,
            "window": window,
            "displays": [d.to_dict() for d in ordered_displays],
            "nodes": [n.to_dict() for n in ordered_nodes],
        }
        digest = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
        return cls(
            snapshot_id=f"uia:{digest}",
            captured_at=captured,
            app=dict(app),
            window=dict(window),
            displays=ordered_displays,
            nodes=ordered_nodes,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "captured_at": self.captured_at,
            "app": self.app,
            "window": self.window,
            "displays": [d.to_dict() for d in self.displays],
            "nodes": [n.to_dict() for n in self.nodes],
            "coordinate_space": "physical_screen_px",
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())
