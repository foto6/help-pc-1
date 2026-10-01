from __future__ import annotations

import hashlib
import os
import threading
from collections import deque
from time import monotonic
from typing import Any, Protocol

from .cancellation import CancellationToken
from .errors import OperationTimeoutError

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
    def inspect(
        self,
        query: ElementQuery,
        *,
        cancellation: CancellationToken | None = None,
        deadline_monotonic: float | None = None,
    ) -> ElementInfo:
        control = self._find(
            query,
            cancellation=cancellation,
            deadline_monotonic=deadline_monotonic,
        )
        info = self._info(control, include_execution_identity=True)
        self._set_diagnostics(
            operation="inspect",
            target_process_id=info.process_id,
            target_window_handle=info.window_handle,
        )
        return info

    def invoke(
        self,
        query: ElementQuery,
        *,
        cancellation: CancellationToken | None = None,
        deadline_monotonic: float | None = None,
    ) -> ElementInfo:
        control = self._find(
            query,
            cancellation=cancellation,
            deadline_monotonic=deadline_monotonic,
        )
        info = self._info(control, include_execution_identity=True)
        self._set_diagnostics(
            operation="invoke",
            target_process_id=info.process_id,
            target_window_handle=info.window_handle,
        )
        if not info.is_enabled or info.is_offscreen:
            raise PolicyBlockedError("UIA target is not currently actionable")
        if not info.supports_invoke:
            raise PolicyBlockedError("UIA target does not expose a deterministic invoke capability")
        self._check_budget(cancellation, deadline_monotonic)
        control.GetInvokePattern().Invoke()
        self._check_budget(cancellation, deadline_monotonic)
        return self._info(control, include_execution_identity=True)

    def focus(
        self,
        query: ElementQuery,
        *,
        cancellation: CancellationToken | None = None,
        deadline_monotonic: float | None = None,
    ) -> ElementInfo:
        control = self._find(
            query,
            cancellation=cancellation,
            deadline_monotonic=deadline_monotonic,
        )
        info = self._info(control, include_execution_identity=True)
        if not info.is_enabled or info.is_offscreen:
            raise PolicyBlockedError("UIA target cannot be focused safely")
        self._check_budget(cancellation, deadline_monotonic)
        control.SetFocus()
        self._check_budget(cancellation, deadline_monotonic)
        return self._info(control, include_execution_identity=True)

    def set_value(
        self,
        query: ElementQuery,
        value: str,
        *,
        sensitive: bool = False,
        cancellation: CancellationToken | None = None,
        deadline_monotonic: float | None = None,
    ) -> ElementInfo:
        control = self._find(
            query,
            cancellation=cancellation,
            deadline_monotonic=deadline_monotonic,
        )
        info = self._info(control, include_execution_identity=True)
        ensure_not_sensitive_text(is_password=info.is_password, sensitive=sensitive)
        if not info.is_enabled or info.is_offscreen:
            raise PolicyBlockedError("UIA target is not currently actionable")
        if not info.supports_value:
            raise PolicyBlockedError("UIA target does not support deterministic value setting")
        self._check_budget(cancellation, deadline_monotonic)
        control.GetValuePattern().SetValue(value)
        self._check_budget(cancellation, deadline_monotonic)
        return self._info(control, include_execution_identity=True)

    def snapshot(self, *, window_title: str | None = None) -> UIObservationSnapshot: ...


MAX_UIA_WALK_DEPTH = 12
MAX_UIA_WALK_NODES = 2000


class WindowsUIAutomationAdapter:
    """Deterministic UIA adapter with cooperative deadline/cancellation checks.

    Windows UI Automation COM calls can still be slow or uninterruptible. The
    Executor supplies an outer worker deadline; these checks ensure a walk that
    resumes after such a call exits promptly instead of continuing to traverse.
    """

    def _diagnostic_lock_value(self):
        lock = getattr(self, "_diagnostic_lock", None)
        if lock is None:
            lock = threading.RLock()
            self._diagnostic_lock = lock
        return lock

    def _set_diagnostics(self, **values: Any) -> None:
        with self._diagnostic_lock_value():
            current = dict(getattr(self, "_last_diagnostics", {}) or {})
            current.update(values)
            self._last_diagnostics = current

    def diagnostics_snapshot(self) -> dict[str, Any]:
        with self._diagnostic_lock_value():
            return dict(getattr(self, "_last_diagnostics", {}) or {})

    @staticmethod
    def _check_budget(
        cancellation: CancellationToken | None,
        deadline_monotonic: float | None,
    ) -> None:
        if cancellation is not None:
            cancellation.raise_if_cancelled()
        if deadline_monotonic is not None and monotonic() >= deadline_monotonic:
            raise OperationTimeoutError("UIA traversal deadline exceeded")

    def _automation(self):
        if os.name != "nt":
            raise RuntimeError("UI Automation is only available on Windows")
        try:
            import uiautomation as auto
        except ImportError as exc:
            raise RuntimeError("install the Windows dependency uiautomation") from exc
        return auto

    def _root(
        self,
        window_title: str | None,
        *,
        cancellation: CancellationToken | None = None,
        deadline_monotonic: float | None = None,
    ):
        self._check_budget(cancellation, deadline_monotonic)
        auto = self._automation()
        desktop = auto.GetRootControl()
        self._check_budget(cancellation, deadline_monotonic)
        if not window_title:
            return desktop
        matches = [
            child
            for child in self._children(
                desktop,
                cancellation=cancellation,
                deadline_monotonic=deadline_monotonic,
            )
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

    @classmethod
    def _children(
        cls,
        control,
        *,
        cancellation: CancellationToken | None = None,
        deadline_monotonic: float | None = None,
    ) -> list:
        cls._check_budget(cancellation, deadline_monotonic)
        try:
            children = list(control.GetChildren())
        except OperationTimeoutError:
            raise
        except Exception:
            children = []
        cls._check_budget(cancellation, deadline_monotonic)
        return children

    def _walk(
        self,
        root,
        *,
        max_depth: int = MAX_UIA_WALK_DEPTH,
        max_nodes: int = MAX_UIA_WALK_NODES,
        cancellation: CancellationToken | None = None,
        deadline_monotonic: float | None = None,
    ):
        queue = deque([(root, (), 0)])
        visited = 0
        while queue:
            self._check_budget(cancellation, deadline_monotonic)
            if visited >= max_nodes:
                raise OperationTimeoutError(
                    f"UIA traversal node budget exceeded ({max_nodes})"
                )
            control, path, depth = queue.popleft()
            visited += 1
            self._set_diagnostics(
                nodes_visited=visited,
                current_depth=depth,
                max_depth=max_depth,
                max_nodes=max_nodes,
            )
            yield control, path
            if depth >= max_depth:
                continue
            children = self._children(
                control,
                cancellation=cancellation,
                deadline_monotonic=deadline_monotonic,
            )
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

    def _find(
        self,
        query: ElementQuery,
        *,
        cancellation: CancellationToken | None = None,
        deadline_monotonic: float | None = None,
    ):
        self._set_diagnostics(
            operation="find",
            window_title_sha256=(
                hashlib.sha256(query.window_title.encode("utf-8")).hexdigest()
                if query.window_title else None
            ),
            selector_fields=sorted(
                name for name, value in (
                    ("automation_id", query.automation_id),
                    ("name", query.name),
                    ("control_type", query.control_type),
                    ("class_name", query.class_name),
                ) if value is not None
            ),
        )
        root = self._root(
            query.window_title,
            cancellation=cancellation,
            deadline_monotonic=deadline_monotonic,
        )
        candidates = []
        for control, path in self._walk(
            root,
            cancellation=cancellation,
            deadline_monotonic=deadline_monotonic,
        ):
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

    def snapshot(
        self,
        *,
        window_title: str | None = None,
        cancellation: CancellationToken | None = None,
        deadline_monotonic: float | None = None,
        max_nodes: int = MAX_UIA_WALK_NODES,
        max_depth: int = MAX_UIA_WALK_DEPTH,
    ) -> UIObservationSnapshot:
        self._set_diagnostics(
            operation="snapshot",
            window_title_sha256=(
                hashlib.sha256(window_title.encode("utf-8")).hexdigest()
                if window_title else None
            ),
            nodes_visited=0,
            max_nodes=max_nodes,
            max_depth=max_depth,
        )
        root = self._root(
            window_title,
            cancellation=cancellation,
            deadline_monotonic=deadline_monotonic,
        )
        root_info = self._info(root)
        self._set_diagnostics(
            target_process_id=root_info.process_id,
            target_window_handle=root_info.window_handle,
        )
        nodes: list[UINodeSnapshot] = []
        for control, path in self._walk(
            root,
            max_nodes=max_nodes,
            max_depth=max_depth,
            cancellation=cancellation,
            deadline_monotonic=deadline_monotonic,
        ):
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

    def health_probe(
        self,
        *,
        cancellation: CancellationToken | None = None,
        deadline_monotonic: float | None = None,
    ) -> dict[str, Any]:
        """Minimal read-only UIA liveness probe; never walks the desktop tree."""
        self._set_diagnostics(operation="health_probe")
        self._check_budget(cancellation, deadline_monotonic)
        root = self._root(
            None,
            cancellation=cancellation,
            deadline_monotonic=deadline_monotonic,
        )
        process_id = int(getattr(root, "ProcessId", 0) or 0) or None
        handle = int(getattr(root, "NativeWindowHandle", 0) or 0) or None
        self._check_budget(cancellation, deadline_monotonic)
        diagnostics = {
            "probe": "root_control_only",
            "root_process_id": process_id,
            "root_window_handle": handle,
            "tree_walk_performed": False,
        }
        self._set_diagnostics(**diagnostics)
        return diagnostics
