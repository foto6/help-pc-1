from __future__ import annotations

import pytest

from pc_executor.errors import AmbiguousTargetError, PolicyBlockedError, StaleTargetError
from pc_executor.models import ElementQuery
from pc_executor.uia import WindowsUIAutomationAdapter


class FakeRect:
    def __init__(self, left=0, top=0, right=20, bottom=10):
        self.left = left
        self.top = top
        self.right = right
        self.bottom = bottom


class InvokePattern:
    def __init__(self, control):
        self.control = control

    def Invoke(self):
        self.control.invocations += 1
        self.control.BoundingRectangle = FakeRect(5, 6, 45, 26)


class ValuePattern:
    def __init__(self, control):
        self.control = control

    def SetValue(self, value):
        self.control.value = value


class FakeControl:
    def __init__(
        self,
        *,
        name="",
        automation_id="",
        role="PaneControl",
        children=None,
        invoke=False,
        value=False,
        enabled=True,
        offscreen=False,
        handle=0,
        pid=1,
    ):
        self.Name = name
        self.AutomationId = automation_id
        self.ControlTypeName = role
        self.ClassName = role.replace("Control", "")
        self.IsEnabled = enabled
        self.IsPassword = False
        self.IsOffscreen = offscreen
        self.NativeWindowHandle = handle
        self.ProcessId = pid
        self.BoundingRectangle = FakeRect()
        self._children = list(children or [])
        self._invoke = invoke
        self._value = value
        self.invocations = 0
        self.clicks = 0
        self.value = None

    def GetChildren(self):
        return list(self._children)

    def GetInvokePattern(self):
        if not self._invoke:
            raise RuntimeError("no invoke")
        return InvokePattern(self)

    def GetValuePattern(self):
        if not self._value:
            raise RuntimeError("no value")
        return ValuePattern(self)

    def Click(self, **kwargs):
        self.clicks += 1

    def SetFocus(self):
        return None


class FakeAutomation:
    def __init__(self, root):
        self.root = root

    def GetRootControl(self):
        return self.root


class Adapter(WindowsUIAutomationAdapter):
    def __init__(self, root):
        self.fake_auto = FakeAutomation(root)

    def _automation(self):
        return self.fake_auto


def test_windows_adapter_unique_automation_id_is_deterministic_and_refreshes_bounds():
    button = FakeControl(
        name="Save",
        automation_id="save",
        role="ButtonControl",
        invoke=True,
        handle=42,
        pid=7,
    )
    adapter = Adapter(FakeControl(children=[button]))

    info = adapter.invoke(ElementQuery(automation_id="save"))

    assert info.automation_id == "save"
    assert info.supports_invoke is True
    assert info.bounds.width == 40
    assert info.bounds.height == 20
    assert button.invocations == 1
    assert button.clicks == 0


def test_windows_adapter_ambiguous_automation_id_fails_closed():
    root = FakeControl(
        children=[
            FakeControl(automation_id="save", invoke=True),
            FakeControl(automation_id="save", invoke=True),
        ]
    )
    adapter = Adapter(root)

    with pytest.raises(AmbiguousTargetError):
        adapter.inspect(ElementQuery(automation_id="save"))


def test_windows_adapter_missing_automation_id_is_stale():
    adapter = Adapter(FakeControl(children=[]))

    with pytest.raises(StaleTargetError):
        adapter.inspect(ElementQuery(automation_id="missing"))


def test_windows_adapter_non_invokable_never_falls_back_to_click():
    button = FakeControl(automation_id="save", invoke=False)
    adapter = Adapter(FakeControl(children=[button]))

    with pytest.raises(PolicyBlockedError):
        adapter.invoke(ElementQuery(automation_id="save"))

    assert button.clicks == 0


def test_windows_adapter_duplicate_window_titles_are_ambiguous():
    desktop = FakeControl(
        children=[
            FakeControl(name="Editor", handle=10, pid=1),
            FakeControl(name="Editor", handle=20, pid=2),
        ]
    )
    adapter = Adapter(desktop)

    with pytest.raises(AmbiguousTargetError):
        adapter.snapshot(window_title="Editor")
