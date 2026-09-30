from __future__ import annotations

import pytest

from pc_executor.models import Rect, UIObservationSnapshot, UINodeSnapshot
from pc_executor.uia import (
    DEFAULT_SNAPSHOT_BUDGET,
    SNAPSHOT_OBSERVATION_VERSION,
    UIASnapshotBudget,
    WindowsUIAutomationAdapter,
)


def _node() -> UINodeSnapshot:
    return UINodeSnapshot(
        node_id="node:1",
        role="ButtonControl",
        name="Save",
        automation_id="save",
        class_name="Button",
        is_enabled=True,
        is_offscreen=False,
        bounds=Rect(1, 2, 3, 4),
        display_id=None,
        window_handle=10,
        process_id=20,
        supports_invoke=True,
        supports_value=False,
    )


def test_snapshot_budget_defaults_and_hard_caps_are_strict():
    assert DEFAULT_SNAPSHOT_BUDGET.to_dict() == {
        "max_nodes": 256,
        "max_children_per_node": 64,
        "max_work_units": 2048,
        "max_depth": 12,
        "time_budget_ms": 2000,
    }
    DEFAULT_SNAPSHOT_BUDGET.validated()
    for bad in (
        UIASnapshotBudget(max_nodes=0),
        UIASnapshotBudget(max_nodes=1025),
        UIASnapshotBudget(max_children_per_node=257),
        UIASnapshotBudget(max_work_units=15),
        UIASnapshotBudget(max_depth=21),
        UIASnapshotBudget(time_budget_seconds=0),
        UIASnapshotBudget(time_budget_seconds=3.1),
    ):
        with pytest.raises(ValueError):
            bad.validated()


def test_legacy_snapshot_shape_and_digest_remain_backward_compatible():
    snapshot = UIObservationSnapshot.create(
        app={"process_id": 20},
        window={"title": "Editor", "handle": 10, "process_id": 20},
        displays=(),
        nodes=(_node(),),
        captured_at="2026-10-01T00:00:00.000Z",
    )
    payload = snapshot.to_dict()
    assert "observation" not in payload
    assert snapshot.observation == {}
    assert payload["coordinate_space"] == "physical_screen_px"


def test_structured_partial_observation_is_in_snapshot_and_canonical_json():
    observation = {
        "contract_version": SNAPSHOT_OBSERVATION_VERSION,
        "status": "partial",
        "partial": True,
        "timed_out": True,
        "reason": "time_budget_exhausted",
        "budget": DEFAULT_SNAPSHOT_BUDGET.to_dict(),
        "work": {
            "nodes_emitted": 1,
            "work_units": 8,
            "children_truncated": 0,
            "depth_boundary_nodes": 0,
            "max_queue_size": 0,
            "elapsed_ms": 2000,
        },
        "safety": {
            "coordinate_fallback_used": False,
            "side_effects": False,
        },
    }
    snapshot = UIObservationSnapshot.create(
        app={"process_id": 20},
        window={"title": "Editor", "handle": 10, "process_id": 20},
        displays=(),
        nodes=(_node(),),
        observation=observation,
        captured_at="2026-10-01T00:00:00.000Z",
    )
    assert snapshot.to_dict()["observation"] == observation
    assert '"reason":"time_budget_exhausted"' in snapshot.to_json()


class SiblingOnly:
    def __init__(self, value: int):
        self.value = value
        self.next = None

    def GetNextSiblingControl(self):
        return self.next


class SiblingParent:
    def __init__(self, count: int):
        self.children = [SiblingOnly(i) for i in range(count)]
        for left, right in zip(self.children, self.children[1:]):
            left.next = right
        self.materialize_calls = 0

    def GetFirstChildControl(self):
        return self.children[0] if self.children else None

    def GetChildren(self):
        self.materialize_calls += 1
        raise AssertionError("bounded traversal must not materialize all children")


def test_bounded_child_reader_uses_tree_walker_and_stops_at_limit():
    parent = SiblingParent(1000)
    children, truncated, calls = WindowsUIAutomationAdapter._children_bounded(
        parent, 7
    )
    assert [child.value for child in children] == list(range(7))
    assert truncated is True
    assert calls == 8
    assert parent.materialize_calls == 0
