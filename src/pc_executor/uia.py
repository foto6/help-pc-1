from __future__ import annotations

import os
from typing import Protocol

from .models import ElementInfo, ElementQuery
from .safety import ensure_not_sensitive_text


class AccessibilityAdapter(Protocol):
    def inspect(self, query: ElementQuery) -> ElementInfo: ...
    def invoke(self, query: ElementQuery) -> ElementInfo: ...
    def focus(self, query: ElementQuery) -> ElementInfo: ...
    def set_value(self, query: ElementQuery, value: str, *, sensitive: bool = False) -> ElementInfo: ...


class WindowsUIAutomationAdapter:
    """Accessibility-first adapter backed by the optional uiautomation package."""

    def _automation(self):
        if os.name != "nt":
            raise RuntimeError("UI Automation is only available on Windows")
        try:
            import uiautomation as auto
        except ImportError as exc:
            raise RuntimeError("install the Windows dependency uiautomation") from exc
        return auto

    def _find(self, query: ElementQuery):
        auto = self._automation()
        root = auto.GetRootControl()
        if query.window_title:
            root = auto.WindowControl(searchDepth=1, Name=query.window_title)
            if not root.Exists(2, 0.1):
                raise LookupError(f"window not found: {query.window_title}")

        kwargs: dict[str, object] = {"searchDepth": 12}
        if query.automation_id:
            kwargs["AutomationId"] = query.automation_id
        if query.name:
            kwargs["Name"] = query.name
        if query.class_name:
            kwargs["ClassName"] = query.class_name

        control = root.Control(**kwargs)
        if not control.Exists(2, 0.1):
            raise LookupError(f"UIA element not found: {query}")
        if query.control_type:
            observed = str(getattr(control, "ControlTypeName", ""))
            if observed.lower() != query.control_type.lower():
                raise LookupError(f"UIA control type mismatch: expected {query.control_type}, got {observed}")
        return control

    @staticmethod
    def _info(control) -> ElementInfo:
        return ElementInfo(
            name=getattr(control, "Name", None),
            automation_id=getattr(control, "AutomationId", None),
            control_type=getattr(control, "ControlTypeName", None),
            is_enabled=bool(getattr(control, "IsEnabled", True)),
            is_password=bool(getattr(control, "IsPassword", False)),
            native_handle=int(getattr(control, "NativeWindowHandle", 0) or 0) or None,
        )

    def inspect(self, query: ElementQuery) -> ElementInfo:
        return self._info(self._find(query))

    def invoke(self, query: ElementQuery) -> ElementInfo:
        control = self._find(query)
        info = self._info(control)
        if not info.is_enabled:
            raise RuntimeError("UIA element is disabled")
        try:
            pattern = control.GetInvokePattern()
            pattern.Invoke()
        except Exception:
            control.Click(simulateMove=False)
        return info

    def focus(self, query: ElementQuery) -> ElementInfo:
        control = self._find(query)
        control.SetFocus()
        return self._info(control)

    def set_value(self, query: ElementQuery, value: str, *, sensitive: bool = False) -> ElementInfo:
        control = self._find(query)
        info = self._info(control)
        ensure_not_sensitive_text(is_password=info.is_password, sensitive=sensitive)
        if not info.is_enabled:
            raise RuntimeError("UIA element is disabled")
        try:
            pattern = control.GetValuePattern()
            pattern.SetValue(value)
        except Exception as exc:
            raise RuntimeError("UIA element does not support deterministic value setting") from exc
        return info
