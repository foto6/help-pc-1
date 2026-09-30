from __future__ import annotations

import hashlib
import os
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from time import monotonic
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


SNAPSHOT_OBSERVATION_VERSION = "pc_executor.uia_snapshot_observation.v1"
_SNAPSHOT_INFO_WORK_UNITS = 8


@dataclass(frozen=True, slots=True)
class UIASnapshotBudget:
    max_nodes: int = 256
    max_children_per_node: int = 64
    max_work_units: int = 2048
    max_depth: int = 12
    time_budget_seconds: float = 2.0

    def validated(self) -> "UIASnapshotBudget":
        limits = (
            ("max_nodes", self.max_nodes, 1, 1024),
            ("max_children_per_node", self.max_children_per_node, 1, 256),
            ("max_work_units", self.max_work_units, 16, 8192),
            ("max_depth", self.max_depth, 1, 20),
        )
        for name, value, lower, upper in limits:
            if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
                raise ValueError(f"{name} must be between {lower} and {upper}")
        if (
            isinstance(self.time_budget_seconds, bool)
            or not isinstance(self.time_budget_seconds, (int, float))
            or not 0.001 <= float(self.time_budget_seconds) <= 3.0
        ):
            raise ValueError("time_budget_seconds must be between 0.001 and 3.0")
        return self

    def to_dict(self) -> dict[str, int]:
        return {
            "max_nodes": self.max_nodes,
            "max_children_per_node": self.max_children_per_node,
            "max_work_units": self.max_work_units,
            "max_depth": self.max_depth,
            "time_budget_ms": max(1, int(float(self.time_budget_seconds) * 1000)),
        }


DEFAULT_SNAPSHOT_BUDGET = UIASnapshotBudget()


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

    @contextmanager
    def _uia_thread(self):
        """Initialize UIAutomation COM state in Executor worker threads.

        Upstream uiautomation requires UIAutomationInitializerInThread when
        controls are used from a new thread. Fake adapters without that helper
        retain the same deterministic test behavior.
        """
        auto = self._automation()
        initializer = getattr(auto, "UIAutomationInitializerInThread", None)
        if initializer is None:
            yield
            return
        with initializer():
            yield

    def _clock(self) -> float:
        return monotonic()

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

    @staticmethod
    def _children_bounded(control, limit: int) -> tuple[list, bool, int]:
        """Read at most limit children without materializing an entire UIA subtree."""
        if limit <= 0:
            return [], True, 0
        first = getattr(control, "GetFirstChildControl", None)
        if callable(first):
            children = []
            calls = 1
            try:
                child = first()
            except Exception:
                return [], False, calls
            while child is not None and len(children) < limit:
                children.append(child)
                next_sibling = getattr(child, "GetNextSiblingControl", None)
                if not callable(next_sibling):
                    return children, False, calls
                calls += 1
                try:
                    child = next_sibling()
                except Exception:
                    return children, False, calls
            return children, child is not None, calls
        try:
            children = list(control.GetChildren())
        except Exception:
            return [], False, 1
        truncated = len(children) > limit
        return children[:limit], truncated, 1 + min(len(children), limit)

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
        with self._uia_thread():
            return self._info(
                self._find(query),
                include_execution_identity=True,
            )

    def invoke(self, query: ElementQuery) -> ElementInfo:
        with self._uia_thread():
            control = self._find(query)
            info = self._info(control, include_execution_identity=True)
            if not info.is_enabled or info.is_offscreen:
                raise PolicyBlockedError("UIA target is not currently actionable")
            if not info.supports_invoke:
                raise PolicyBlockedError("UIA target does not expose a deterministic invoke capability")
            control.GetInvokePattern().Invoke()
            return self._info(control, include_execution_identity=True)

    def focus(self, query: ElementQuery) -> ElementInfo:
        with self._uia_thread():
            control = self._find(query)
            info = self._info(control, include_execution_identity=True)
            if not info.is_enabled or info.is_offscreen:
                raise PolicyBlockedError("UIA target cannot be focused safely")
            control.SetFocus()
            return self._info(control, include_execution_identity=True)

    def set_value(self, query: ElementQuery, value: str, *, sensitive: bool = False) -> ElementInfo:
        with self._uia_thread():
            control = self._find(query)
            info = self._info(control, include_execution_identity=True)
            ensure_not_sensitive_text(is_password=info.is_password, sensitive=sensitive)
            if not info.is_enabled or info.is_offscreen:
                raise PolicyBlockedError("UIA target is not currently actionable")
            if not info.supports_value:
                raise PolicyBlockedError("UIA target does not support deterministic value setting")
            control.GetValuePattern().SetValue(value)
            return self._info(control, include_execution_identity=True)

    @staticmethod
    def _snapshot_node(info: ElementInfo, path: tuple[int, ...]) -> UINodeSnapshot:
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
        return UINodeSnapshot(
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

    def snapshot_bounded(
        self,
        *,
        window_title: str | None = None,
        budget: UIASnapshotBudget | None = None,
    ) -> UIObservationSnapshot:
        selected = (budget or DEFAULT_SNAPSHOT_BUDGET).validated()
        with self._uia_thread():
            started = self._clock()
            deadline = started + float(selected.time_budget_seconds)
            root = self._root(window_title)
            root_info = self._info(root)
            nodes: list[UINodeSnapshot] = [self._snapshot_node(root_info, ())]
            work_units = _SNAPSHOT_INFO_WORK_UNITS
            queue = deque()
            children_truncated = 0
            depth_boundary_nodes = 0
            max_queue_size = 0
            stop_reason: str | None = None
            structural_reason: str | None = None

            if self._clock() >= deadline:
                stop_reason = "time_budget_exhausted"
            else:
                remaining = selected.max_work_units - work_units
                child_limit = min(selected.max_children_per_node, max(0, remaining))
                if child_limit <= 0:
                    stop_reason = "work_budget_exhausted"
                else:
                    children, truncated, calls = self._children_bounded(root, child_limit)
                    work_units += calls
                    if truncated:
                        children_truncated += 1
                        structural_reason = "child_budget_exhausted"
                    for index, child in enumerate(children):
                        queue.append((child, (index,), 1))
                    max_queue_size = len(queue)

            while queue and stop_reason is None:
                if len(nodes) >= selected.max_nodes:
                    stop_reason = "node_budget_exhausted"
                    break
                if work_units + _SNAPSHOT_INFO_WORK_UNITS > selected.max_work_units:
                    stop_reason = "work_budget_exhausted"
                    break
                if self._clock() >= deadline:
                    stop_reason = "time_budget_exhausted"
                    break

                control, path, depth = queue.popleft()
                info = self._info(control)
                work_units += _SNAPSHOT_INFO_WORK_UNITS
                nodes.append(self._snapshot_node(info, path))

                if self._clock() >= deadline:
                    stop_reason = "time_budget_exhausted"
                    break
                if depth >= selected.max_depth:
                    depth_boundary_nodes += 1
                    if structural_reason is None:
                        structural_reason = "depth_budget_exhausted"
                    continue

                remaining = selected.max_work_units - work_units
                child_limit = min(selected.max_children_per_node, max(0, remaining))
                if child_limit <= 0:
                    stop_reason = "work_budget_exhausted"
                    break
                children, truncated, calls = self._children_bounded(control, child_limit)
                work_units += calls
                if truncated:
                    children_truncated += 1
                    if structural_reason is None:
                        structural_reason = "child_budget_exhausted"
                for index, child in enumerate(children):
                    queue.append((child, path + (index,), depth + 1))
                max_queue_size = max(max_queue_size, len(queue))
                if work_units > selected.max_work_units:
                    stop_reason = "work_budget_exhausted"
                    break

            reason = stop_reason or structural_reason
            elapsed_ms = max(0, int((self._clock() - started) * 1000))
            observation = {
                "contract_version": SNAPSHOT_OBSERVATION_VERSION,
                "status": "partial" if reason is not None else "complete",
                "partial": reason is not None,
                "timed_out": reason == "time_budget_exhausted",
                "reason": reason,
                "budget": selected.to_dict(),
                "work": {
                    "nodes_emitted": len(nodes),
                    "work_units": work_units,
                    "children_truncated": children_truncated,
                    "depth_boundary_nodes": depth_boundary_nodes,
                    "max_queue_size": max_queue_size,
                    "elapsed_ms": elapsed_ms,
                },
                "safety": {
                    "coordinate_fallback_used": False,
                    "side_effects": False,
                },
            }
            return UIObservationSnapshot.create(
                app={"process_id": root_info.process_id},
                window={
                    "title": root_info.name or window_title or "",
                    "handle": root_info.native_handle,
                    "process_id": root_info.process_id,
                },
                displays=list_display_geometries(),
                nodes=nodes,
                observation=observation,
            )

    def snapshot(self, *, window_title: str | None = None) -> UIObservationSnapshot:
        return self.snapshot_bounded(window_title=window_title)
