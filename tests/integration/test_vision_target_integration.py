from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from pc_executor.executor import Executor
from pc_executor.models import ActionRequest, ElementInfo


A1_VISION_HEAD = "5e5499f7446ca964584b79e9f6b572111220c56b"
FIXTURE = Path(__file__).parents[1] / "fixtures" / "grounded_target_v1.json"


def load_fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class RecordingAccessibility:
    def __init__(self) -> None:
        self.invocations = []

    def invoke(self, query):
        self.invocations.append(query)
        return ElementInfo("Save", query.automation_id, "ButtonControl", True, False, 42)


class RecordingInput:
    def __init__(self) -> None:
        self.calls = []

    def click(self, x, y, *, button="left"):
        self.calls.append(("click", x, y, button))

    def press(self, key):
        self.calls.append(("press", key))

    def type_text(self, text):
        self.calls.append(("type", text))

    def clipboard_get(self):
        self.calls.append(("clipboard_get",))
        return ""

    def clipboard_set(self, text):
        self.calls.append(("clipboard_set", text))


def make_executor(*, dry_run=False, allow_coordinate_fallback=False):
    accessibility = RecordingAccessibility()
    input_adapter = RecordingInput()
    executor = Executor(
        accessibility=accessibility,
        input_adapter=input_adapter,
        dry_run=dry_run,
        allow_coordinate_fallback=allow_coordinate_fallback,
    )
    return executor, accessibility, input_adapter


def invoke(executor: Executor, payload: dict, *, request_id="vision-a2"):
    return executor.execute(
        ActionRequest(
            "vision.target.invoke",
            {"target": payload},
            request_id=request_id,
        )
    )


def test_canonical_a1_save_fixture_maps_to_exactly_one_uia_invoke():
    payload = load_fixture()
    executor, accessibility, input_adapter = make_executor()

    result = invoke(executor, payload)

    assert result.ok is True
    assert result.status == "completed"
    assert len(accessibility.invocations) == 1
    assert accessibility.invocations[0].automation_id == "save"
    assert accessibility.invocations[0].name is None
    assert input_adapter.calls == []


def test_supplied_screen_coordinates_never_reach_input_adapter():
    payload = load_fixture()
    payload["target"]["bounds_screen"] = {
        "x": 9000,
        "y": 8000,
        "width": 200,
        "height": 100,
    }
    payload["target"]["click_point_screen"] = {"x": 9100.0, "y": 8050.0}
    executor, accessibility, input_adapter = make_executor(
        allow_coordinate_fallback=True
    )

    result = invoke(executor, payload)

    assert result.ok is True
    assert [query.automation_id for query in accessibility.invocations] == ["save"]
    assert input_adapter.calls == []


@pytest.mark.parametrize("source", ["vision", "ocr"])
def test_target_without_automation_id_is_blocked(source):
    payload = load_fixture()
    payload["target"]["sources"] = [source]
    payload["target"]["automation_id"] = None
    executor, accessibility, input_adapter = make_executor()

    result = invoke(executor, payload)

    assert result.ok is False
    assert result.status == "blocked"
    assert "non-empty automation_id" in result.error
    assert accessibility.invocations == []
    assert input_adapter.calls == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda payload: payload.__setitem__(
            "contract_version", "vision.grounded_target.v2"
        ),
        lambda payload: payload["target"].__setitem__("unexpected", True),
        lambda payload: payload["target"].__setitem__(
            "click_point_screen", {"x": 1.0, "y": 2.0}
        ),
    ],
)
def test_unknown_or_malformed_contract_blocks_without_side_effects(mutate):
    payload = load_fixture()
    mutate(payload)
    executor, accessibility, input_adapter = make_executor()

    result = invoke(executor, payload)

    assert result.ok is False
    assert result.status == "blocked"
    assert "invalid vision target contract" in result.error
    assert accessibility.invocations == []
    assert input_adapter.calls == []


def test_default_dry_run_has_zero_side_effects():
    payload = load_fixture()
    accessibility = RecordingAccessibility()
    input_adapter = RecordingInput()
    executor = Executor(
        accessibility=accessibility,
        input_adapter=input_adapter,
    )

    result = invoke(executor, payload, request_id="vision-dry-run")

    assert result.ok is True
    assert result.status == "dry_run"
    assert result.data == {
        "would_execute": "vision.target.invoke",
        "query": {"automation_id": "save"},
    }
    assert accessibility.invocations == []
    assert input_adapter.calls == []


def test_empty_uia_automation_id_is_blocked():
    payload = copy.deepcopy(load_fixture())
    payload["target"]["automation_id"] = ""
    executor, accessibility, input_adapter = make_executor()

    result = invoke(executor, payload)

    assert result.ok is False
    assert result.status == "blocked"
    assert accessibility.invocations == []
    assert input_adapter.calls == []


def test_jsonl_envelope_reaches_vision_target_action_in_default_dry_run():
    payload = load_fixture()
    request = {
        "request_id": "cli-a2",
        "action": "vision.target.invoke",
        "params": {"target": payload},
    }

    completed = subprocess.run(
        [sys.executable, "-m", "pc_executor"],
        input=json.dumps(request) + "\n",
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0
    response = json.loads(completed.stdout.strip())
    assert response["request_id"] == "cli-a2"
    assert response["action"] == "vision.target.invoke"
    assert response["ok"] is True
    assert response["status"] == "dry_run"
    assert response["data"]["query"] == {"automation_id": "save"}
