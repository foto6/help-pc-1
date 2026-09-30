from __future__ import annotations

import sys
import threading

import pytest

import pc_executor.uia as uia_module
from pc_executor.executor import Executor
from pc_executor.models import ActionRequest
from pc_executor.uia import UIASnapshotBudget, WindowsUIAutomationAdapter


pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="R18 worker-thread UIA regression is Windows-specific",
)


class FakeRect:
    left = 0
    top = 0
    right = 100
    bottom = 30


class FakeControl:
    def __init__(
        self,
        *,
        name="",
        automation_id="",
        role="PaneControl",
        children=(),
        handle=0,
        pid=77,
    ):
        self.Name = name
        self.AutomationId = automation_id
        self.ControlTypeName = role
        self.ClassName = role.replace("Control", "")
        self.IsEnabled = True
        self.IsPassword = False
        self.IsOffscreen = False
        self.NativeWindowHandle = handle
        self.ProcessId = pid
        self.BoundingRectangle = FakeRect()
        self._children = list(children)
        self._next = None
        for left, right in zip(self._children, self._children[1:]):
            left._next = right

    def GetChildren(self):
        return list(self._children)

    def GetFirstChildControl(self):
        return self._children[0] if self._children else None

    def GetNextSiblingControl(self):
        return self._next

    def GetInvokePattern(self):
        raise RuntimeError("no invoke")

    def GetValuePattern(self):
        raise RuntimeError("no value")


class FakeAutomation:
    def __init__(self, root):
        self.root = root
        self.enter_threads = []
        self.exit_threads = []

    def GetRootControl(self):
        return self.root

    def UIAutomationInitializerInThread(self):
        owner = self

        class Initializer:
            def __enter__(self):
                owner.enter_threads.append(threading.get_ident())
                return self

            def __exit__(self, exc_type, exc, tb):
                owner.exit_threads.append(threading.get_ident())
                return False

        return Initializer()


class Adapter(WindowsUIAutomationAdapter):
    def __init__(self, automation):
        self.fake_auto = automation

    def _automation(self):
        return self.fake_auto


class StepClockAdapter(Adapter):
    def __init__(self, automation, step=0.02):
        super().__init__(automation)
        self.value = 0.0
        self.step = step

    def _clock(self):
        self.value += self.step
        return self.value


def leaf(name):
    return FakeControl(name=name, automation_id=name.casefold())


def chrome_like_tree():
    branch = leaf("deep-leaf")
    for depth in range(14, -1, -1):
        siblings = [leaf(f"chrome-{depth}-{i}") for i in range(24)]
        branch = FakeControl(
            name=f"chrome-depth-{depth}",
            role="GroupControl",
            children=[branch, *siblings],
        )
    window = FakeControl(
        name="Chrome Fixture",
        role="WindowControl",
        children=[branch],
        handle=68302,
    )
    return FakeControl(name="Desktop", children=[window])


def explorer_like_tree():
    items = [leaf(f"explorer-item-{i}") for i in range(300)]
    window = FakeControl(
        name="Explorer Fixture",
        role="WindowControl",
        children=items,
        handle=9701010,
    )
    return FakeControl(name="Desktop", children=[window])


@pytest.fixture(autouse=True)
def no_real_display_probe(monkeypatch):
    monkeypatch.setattr(uia_module, "display_for_rect", lambda bounds: None)
    monkeypatch.setattr(uia_module, "list_display_geometries", lambda: [])


def test_chrome_like_deep_tree_returns_partial_instead_of_executor_timeout():
    automation = FakeAutomation(chrome_like_tree())
    adapter = Adapter(automation)
    executor = Executor(
        accessibility=adapter,
        dry_run=False,
        operation_timeout_seconds=1.0,
        allow_coordinate_fallback=False,
    )
    main_thread = threading.get_ident()

    result = executor.execute(
        ActionRequest(
            "uia.snapshot",
            {"window_title": "Chrome Fixture"},
            request_id="r18-chrome",
            timeout_ms=1000,
        )
    )

    assert result.ok is True
    observation = result.data["observation"]
    assert observation["status"] == "partial"
    assert observation["reason"] in {
        "work_budget_exhausted",
        "node_budget_exhausted",
        "depth_budget_exhausted",
    }
    assert observation["work"]["nodes_emitted"] <= 256
    assert observation["work"]["work_units"] <= 2048
    assert observation["safety"] == {
        "coordinate_fallback_used": False,
        "side_effects": False,
    }
    assert result.data["snapshot"]["observation"] == observation
    assert automation.enter_threads
    assert automation.enter_threads == automation.exit_threads
    assert all(thread_id != main_thread for thread_id in automation.enter_threads)


def test_explorer_like_wide_tree_is_truncated_per_parent_not_materialized():
    automation = FakeAutomation(explorer_like_tree())
    adapter = Adapter(automation)

    snapshot = adapter.snapshot_bounded(
        window_title="Explorer Fixture",
        budget=UIASnapshotBudget(
            max_nodes=256,
            max_children_per_node=64,
            max_work_units=2048,
            max_depth=12,
            time_budget_seconds=2.0,
        ),
    )

    observation = snapshot.observation
    assert observation["status"] == "partial"
    assert observation["reason"] == "child_budget_exhausted"
    assert observation["work"]["children_truncated"] == 1
    assert observation["work"]["nodes_emitted"] == 65
    assert len(snapshot.nodes) == 65


def test_time_budget_exhaustion_is_structured_partial_not_outer_timeout():
    automation = FakeAutomation(explorer_like_tree())
    adapter = StepClockAdapter(automation, step=0.02)

    snapshot = adapter.snapshot_bounded(
        window_title="Explorer Fixture",
        budget=UIASnapshotBudget(
            max_nodes=256,
            max_children_per_node=64,
            max_work_units=2048,
            max_depth=12,
            time_budget_seconds=0.025,
        ),
    )

    observation = snapshot.observation
    assert observation["status"] == "partial"
    assert observation["timed_out"] is True
    assert observation["reason"] == "time_budget_exhausted"
    assert observation["work"]["nodes_emitted"] >= 1


def test_worker_thread_initializer_also_wraps_uia_inspect():
    target = FakeControl(
        name="Save",
        automation_id="save",
        role="ButtonControl",
        handle=88,
    )
    window = FakeControl(
        name="Editor",
        role="WindowControl",
        children=[target],
        handle=77,
    )
    automation = FakeAutomation(FakeControl(name="Desktop", children=[window]))
    adapter = Adapter(automation)
    executor = Executor(accessibility=adapter, dry_run=False)

    result = executor.execute(
        ActionRequest(
            "uia.inspect",
            {"query": {"automation_id": "save", "window_title": "Editor"}},
            request_id="r18-inspect",
            timeout_ms=1000,
        )
    )

    assert result.ok is True
    assert result.data["element"]["automation_id"] == "save"
    assert automation.enter_threads == automation.exit_threads
    assert len(automation.enter_threads) == 1
