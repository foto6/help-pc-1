from __future__ import annotations

import hashlib
import os
from collections import deque
from typing import Protocol

from .errors import AmbiguousTargetError, PolicyBlockedError, StaleTargetError
from .models import (
    ElementInfo,
    ElementQuery,
    Rect,
    UIObservationSnapshot,
    UINodeSnapshot,
    canonical_json,
)
from .safety import ensure_not_sensitive_text
from .windows import (
    display_for_rect,
    list_display_geometries,
    process_start_epoch_ms,
    root_window_handle,
)


class AccessibilityAdapter(Protocol):
    def inspect(self, query: ElementQuery) -> ElementInfo: ...
    def invoke(self, query: ElementQuery) -> ElementInfo: ...
    def focus(self, query: ElementQuery) -> ElementInfo: ...
    def set_value(self, query: ElementQuery, value: str, *, sensitive: bool = False) -> ElementInfo: ...
    def snapshot(self, *, window_title: str | None = None) -> UIObservationSnapshot: ...


class WindowsUIAutomationAdapter:
    """Deterministic UIA adapter. Action methods always re-resolve current controls."""

    def _automation(self):
        if os.name != "nt":
            raise RuntimeError("UI Automation is only available on Windows")
        try:
            import uiautomation as auto
        except ImportError as exc:
            raise RuntimeError("install the Windows dependency uiautomation") from exc
        return auto

    def _root(self, window_title: str | None):
        auto = self._automation()
        desktop = auto.GetRootControl()
        if not window_title:
            return desktop
        matches = [
            child
            for child in self._children(desktop)
            if (getattr(child, "Name", "") or "").casefold() == window_title.casefold()
        ]
        matches.sort(
            key=lambda control: (
                int(getattr(control, "ProcessId", 0) or 0),
                int(getattr(control, "NativeWindowHandle", 0) or 0),
            )
        )
        if not matches:
            raise StaleTargetError(f"window not found: {window_title}")
        if len(matches) > 1:
            raise AmbiguousTargetError(
                f"window title matched {len(matches)} top-level windows: {window_title}"
            )
        return matches[0]

    @staticmethod
    def _children(control) -> list:
        try:
            return list(control.GetChildren())
        except Exception:
            return []

    def _walk(self, root, *, max_depth: int = 12):
        queue = deque([(root, (), 0)])
        while queue:
            control, path, depth = queue.popleft()
            yield control, path
            if depth >= max_depth:
                continue
            children = self._children(control)
            for index, child in enumerate(children):
                queue.append((child, path + (index,), depth + 1))

    @staticmethod
    def _rect(control) -> Rect | None:
        try:
            rect = control.BoundingRectangle
            left = int(getattr(rect, "left", getattr(rect, "Left", 0)))
            top = int(getattr(rect, "top", getattr(rect, "Top", 0)))
            right = int(getattr(rect, "right", getattr(rect, "Right", left)))
            bottom = int(getattr(rect, "bottom", getattr(rect, "Bottom", top)))
            return Rect(left, top, max(0, right - left), max(0, bottom - top))
        except Exception:
            return None

    @staticmethod
    def _supports_pattern(control, method: str) -> bool:
        try:
            return getattr(control, method)() is not None
        except Exception:
            return False

    @staticmethod
    def _runtime_id(control) -> tuple[int, ...] | None:
        try:
            raw = control.GetRuntimeId()
            if raw is None:
                return None
            return tuple(int(value) for value in raw)
        except Exception:
            return None

    def _info(
        self,
        control,
        *,
        include_execution_identity: bool = False,
    ) -> ElementInfo:
        bounds = self._rect(control)
        native_handle = int(getattr(control, "NativeWindowHandle", 0) or 0) or None
        process_id = int(getattr(control, "ProcessId", 0) or 0) or None
        return ElementInfo(
            name=getattr(control, "Name", None),
            automation_id=getattr(control, "AutomationId", None),
            control_type=getattr(control, "ControlTypeName", None),
            is_enabled=bool(getattr(control, "IsEnabled", True)),
            is_password=bool(getattr(control, "IsPassword", False)),
            native_handle=native_handle,
            bounds=bounds,
            display_id=display_for_rect(bounds),
            window_handle=(
                root_window_handle(native_handle)
                if include_execution_identity
                else native_handle
            ),
            process_id=process_id,
            class_name=getattr(control, "ClassName", None),
            is_offscreen=bool(getattr(control, "IsOffscreen", False)),
            supports_invoke=self._supports_pattern(control, "GetInvokePattern"),
            supports_value=self._supports_pattern(control, "GetValuePattern"),
            process_start_epoch_ms=(
                process_start_epoch_ms(process_id)
                if include_execution_identity and process_id is not None
                else None
            ),
            runtime_id=(
                self._runtime_id(control) if include_execution_identity else None
            ),
        )

    @staticmethod
    def _matches(info: ElementInfo, query: ElementQuery) -> bool:
        comparisons = (
            (query.automation_id, info.automation_id),
            (query.name, info.name),
            (query.control_type, info.control_type),
            (query.class_name, info.class_name),
        )
        for expected, observed in comparisons:
            if expected is not None and expected.casefold() != (observed or "").casefold():
                return False
        return True

    def _find(self, query: ElementQuery):
        root = self._root(query.window_title)
        candidates = []
        for control, path in self._walk(root):
            info = self._info(control)
            if self._matches(info, query):
                candidates.append((path, info, control))
        candidates.sort(
            key=lambda item: (
                (item[1].automation_id or "").casefold(),
                (item[1].name or "").casefold(),
                (item[1].control_type or "").casefold(),
                item[1].process_id or -1,
                item[1].native_handle or -1,
                item[0],
            )
        )
        if not candidates:
            if query.automation_id:
                raise StaleTargetError(f"UIA automation_id not found: {query.automation_id}")
            raise StaleTargetError(f"UIA element not found: {query}")
        if len(candidates) > 1:
            raise AmbiguousTargetError(
                f"UIA selector matched {len(candidates)} elements; add stable selector metadata"
            )
        return candidates[0][2]

    def inspect(self, query: ElementQuery) -> ElementInfo:
        return self._info(
            self._find(query),
            include_execution_identity=True,
        )

    def invoke(self, query: ElementQuery) -> ElementInfo:
        control = self._find(query)
        info = self._info(control, include_execution_identity=True)
        if not info.is_enabled or info.is_offscreen:
            raise PolicyBlockedError("UIA target is not currently actionable")
        if not info.supports_invoke:
            raise PolicyBlockedError("UIA target does not expose a deterministic invoke capability")
        control.GetInvokePattern().Invoke()
        return self._info(control, include_execution_identity=True)

    def focus(self, query: ElementQuery) -> ElementInfo:
        control = self._find(query)
        info = self._info(control, include_execution_identity=True)
        if not info.is_enabled or info.is_offscreen:
            raise PolicyBlockedError("UIA target cannot be focused safely")
        control.SetFocus()
        return self._info(control, include_execution_identity=True)

    def set_value(self, query: ElementQuery, value: str, *, sensitive: bool = False) -> ElementInfo:
        control = self._find(query)
        info = self._info(control, include_execution_identity=True)
        ensure_not_sensitive_text(is_password=info.is_password, sensitive=sensitive)
        if not info.is_enabled or info.is_offscreen:
            raise PolicyBlockedError("UIA target is not currently actionable")
        if not info.supports_value:
            raise PolicyBlockedError("UIA target does not support deterministic value setting")
        control.GetValuePattern().SetValue(value)
        return self._info(control, include_execution_identity=True)

    def snapshot(self, *, window_title: str | None = None) -> UIObservationSnapshot:
        root = self._root(window_title)
        root_info = self._info(root)
        nodes: list[UINodeSnapshot] = []
        for control, path in self._walk(root):
            info = self._info(control)
            identity = {
                "path": list(path),
                "automation_id": info.automation_id,
                "name": info.name,
                "role": info.control_type,
                "process_id": info.process_id,
                "bounds": info.bounds.to_dict() if info.bounds else None,
            }
            node_id = "uia-node:" + hashlib.sha256(
                canonical_json(identity).encode("utf-8")
            ).hexdigest()
            nodes.append(
                UINodeSnapshot(
                    node_id=node_id,
                    role=info.control_type,
                    name=info.name,
                    automation_id=info.automation_id,
                    class_name=info.class_name,
                    is_enabled=info.is_enabled,
                    is_offscreen=info.is_offscreen,
                    bounds=info.bounds,
                    display_id=info.display_id,
                    window_handle=info.window_handle,
                    process_id=info.process_id,
                    supports_invoke=info.supports_invoke,
                    supports_value=info.supports_value,
                )
            )
        return UIObservationSnapshot.create(
            app={"process_id": root_info.process_id},
            window={
                "title": root_info.name or window_title or "",
                "handle": root_info.native_handle,
                "process_id": root_info.process_id,
            },
            displays=list_display_geometries(),
            nodes=nodes,
        )
