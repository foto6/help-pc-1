from __future__ import annotations

import copy
import json
import time
from pathlib import Path

import pytest

from pc_executor.cancellation import CancellationToken
from pc_executor.executor import Executor
from pc_executor.fakes import ReplayInputAdapter, ReplayUIAAdapter
from pc_executor.models import ActionRequest, ElementInfo


FIXTURE = Path(__file__).parents[1] / "fixtures" / "grounded_target_v1.json"


def load_fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def actionable(*, automation_id: str = "save", invoke: bool = True) -> ElementInfo:
    return ElementInfo(
        name="Save",
        automation_id=automation_id,
        control_type="ButtonControl",
        is_enabled=True,
        is_password=False,
        native_handle=7,
        process_id=70,
        supports_invoke=invoke,
    )


def invoke(executor: Executor, payload: dict, **kwargs):
    return executor.execute(
        ActionRequest(
            "vision.target.invoke",
            {"target": payload},
            timeout_ms=kwargs.pop("timeout_ms", None),
        ),
        **kwargs,
    )


def test_stale_automation_id_is_classified_without_coordinate_fallback():
    adapter = ReplayUIAAdapter([])
    raw_input = ReplayInputAdapter()
    executor = Executor(
        accessibility=adapter,
        input_adapter=raw_input,
        dry_run=False,
        allow_coordinate_fallback=True,
    )

    result = invoke(executor, load_fixture())

    assert result.status == "stale_target"
    assert result.error_kind == "stale_target"
    assert raw_input.events == []


def test_ambiguous_automation_id_is_classified():
    adapter = ReplayUIAAdapter([actionable(), actionable()])
    executor = Executor(accessibility=adapter, dry_run=False)

    result = invoke(executor, load_fixture())

    assert result.status == "ambiguous_target"
    assert result.error_kind == "ambiguous_target"


def test_non_actionable_grounded_target_is_policy_blocked():
    adapter = ReplayUIAAdapter([actionable(invoke=False)])
    executor = Executor(accessibility=adapter, dry_run=False)

    result = invoke(executor, load_fixture())

    assert result.status == "blocked"
    assert result.error_kind == "policy_blocked"


@pytest.mark.parametrize(
    "mutator",
    [
        lambda p: p["target"].__setitem__("automation_id", 123),
        lambda p: p["frame"].__setitem__("sequence", -1),
        lambda p: p["target"].__setitem__("confidence", float("inf")),
        lambda p: p["target"].__setitem__("sources", []),
        lambda p: p["target"].__setitem__("bounds_screen", {"x": 1}),
    ],
)
def test_additional_malformed_contracts_are_policy_blocked(mutator):
    payload = copy.deepcopy(load_fixture())
    mutator(payload)
    executor = Executor(dry_run=False)

    result = invoke(executor, payload)

    assert result.status == "blocked"
    assert result.error_kind == "policy_blocked"


def test_protected_path_shell_input_remains_blocked_in_round2():
    executor = Executor(dry_run=True)
    result = executor.execute(
        ActionRequest("shell.run", {"argv": ["python", r"E:\manhwa\never.py"]})
    )
    assert result.status == "blocked"
    assert result.error_kind == "policy_blocked"


def test_precancelled_vision_invoke_never_calls_adapter():
    adapter = ReplayUIAAdapter([actionable()])
    executor = Executor(accessibility=adapter, dry_run=False)
    token = CancellationToken()
    token.cancel()

    result = invoke(executor, load_fixture(), cancellation=token)

    assert result.status == "cancelled"
    assert adapter.events == []


class SlowAccessibility:
    def invoke(self, query):
        time.sleep(0.2)
        return actionable()

    def inspect(self, query):
        return actionable()

    def focus(self, query):
        return actionable()

    def set_value(self, query, value, *, sensitive=False):
        return actionable()

    def snapshot(self, *, window_title=None):
        raise NotImplementedError


def test_vision_invoke_timeout_is_structured():
    executor = Executor(accessibility=SlowAccessibility(), dry_run=False)
    result = invoke(executor, load_fixture(), timeout_ms=20)

    assert result.status == "timeout"
    assert result.error_kind == "timeout"
