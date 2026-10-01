from __future__ import annotations

import time

import pytest

from pc_executor.cancellation import CancellationToken
from pc_executor.errors import OperationCancelledError, OperationTimeoutError
from pc_executor.uia import WindowsUIAutomationAdapter


class _Root:
    Name = "Desktop"
    AutomationId = ""
    ControlTypeName = "PaneControl"
    ClassName = "Desktop"
    ProcessId = 0
    NativeWindowHandle = 0
    IsEnabled = True
    IsPassword = False
    IsOffscreen = False

    class BoundingRectangle:
        left = 0
        top = 0
        right = 1
        bottom = 1

    def GetChildren(self):
        return []

    def GetInvokePattern(self):
        return None

    def GetValuePattern(self):
        return None

    def GetRuntimeId(self):
        return (1,)


class _Automation:
    def GetRootControl(self):
        return _Root()


class _SafeWindowsAdapter(WindowsUIAutomationAdapter):
    def _automation(self):
        return _Automation()


@pytest.mark.skipif(__import__("os").name != "nt", reason="Windows evidence lane")
def test_r24_windows_health_probe_is_root_only_and_bounded():
    adapter = _SafeWindowsAdapter()
    token = CancellationToken()
    result = adapter.health_probe(
        cancellation=token,
        deadline_monotonic=time.monotonic() + 0.2,
    )

    assert result["probe"] == "root_control_only"
    assert result["tree_walk_performed"] is False
    assert adapter.diagnostics_snapshot()["tree_walk_performed"] is False


@pytest.mark.skipif(__import__("os").name != "nt", reason="Windows evidence lane")
def test_r24_windows_health_probe_honors_cancel_and_expired_deadline():
    adapter = _SafeWindowsAdapter()
    cancelled = CancellationToken()
    cancelled.cancel()
    with pytest.raises(OperationCancelledError):
        adapter.health_probe(cancellation=cancelled)

    with pytest.raises(OperationTimeoutError, match="deadline"):
        adapter.health_probe(deadline_monotonic=time.monotonic() - 0.001)
