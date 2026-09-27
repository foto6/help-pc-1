from __future__ import annotations

from pc_executor.executor import Executor
from pc_executor.fakes import ReplayInputAdapter, ReplayUIAAdapter
from pc_executor.models import ActionRequest, ElementInfo, ElementQuery


def element(
    automation_id: str,
    *,
    enabled: bool = True,
    offscreen: bool = False,
    invoke: bool = True,
) -> ElementInfo:
    return ElementInfo(
        name="Save",
        automation_id=automation_id,
        control_type="ButtonControl",
        is_enabled=enabled,
        is_password=False,
        native_handle=42,
        process_id=99,
        is_offscreen=offscreen,
        supports_invoke=invoke,
    )


def test_replay_uia_reports_stale_target():
    adapter = ReplayUIAAdapter([])
    executor = Executor(accessibility=adapter, dry_run=False)

    result = executor.execute(
        ActionRequest("uia.invoke", {"query": {"automation_id": "save"}})
    )

    assert result.status == "stale_target"
    assert result.error_kind == "stale_target"


def test_replay_uia_reports_ambiguous_target_without_invocation():
    adapter = ReplayUIAAdapter([element("save"), element("save")])
    executor = Executor(accessibility=adapter, dry_run=False)

    result = executor.execute(
        ActionRequest("uia.invoke", {"query": {"automation_id": "save"}})
    )

    assert result.status == "ambiguous_target"
    assert result.error_kind == "ambiguous_target"


def test_non_actionable_target_is_policy_blocked_not_clicked():
    adapter = ReplayUIAAdapter([element("save", invoke=False)])
    raw_input = ReplayInputAdapter()
    executor = Executor(
        accessibility=adapter,
        input_adapter=raw_input,
        dry_run=False,
        allow_coordinate_fallback=True,
    )

    result = executor.execute(
        ActionRequest("uia.invoke", {"query": {"automation_id": "save"}})
    )

    assert result.status == "blocked"
    assert result.error_kind == "policy_blocked"
    assert raw_input.events == []


def test_automation_id_is_reresolved_for_each_action():
    adapter = ReplayUIAAdapter([element("save")])
    executor = Executor(accessibility=adapter, dry_run=False)

    first = executor.execute(
        ActionRequest("uia.inspect", {"query": {"automation_id": "save"}})
    )
    adapter.elements = []
    second = executor.execute(
        ActionRequest("uia.invoke", {"query": {"automation_id": "save"}})
    )

    assert first.ok is True
    assert second.status == "stale_target"
    assert adapter.events == [("inspect", "save"), ("invoke", "save")]


def test_coordinate_fallback_stays_disabled_in_live_and_dry_run():
    live = Executor(dry_run=False)
    dry = Executor(dry_run=True)

    live_result = live.execute(ActionRequest("mouse.click", {"x": 1, "y": 2}))
    dry_result = dry.execute(ActionRequest("mouse.click", {"x": 1, "y": 2}))

    assert live_result.status == "blocked"
    assert dry_result.status == "blocked"
    assert live_result.error_kind == dry_result.error_kind == "policy_blocked"


def test_uia_query_rejects_unknown_or_empty_selectors():
    executor = Executor(dry_run=True)

    unknown = executor.execute(
        ActionRequest("uia.inspect", {"query": {"automation_id": "save", "bogus": 1}})
    )
    empty = executor.execute(ActionRequest("uia.inspect", {"query": {}}))

    assert unknown.status == "blocked"
    assert empty.status == "blocked"
