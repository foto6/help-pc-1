"""R16 independent Executor-side adversarial contracts.

Only pytest tmp_path state, a synthetic UIA element, and synthetic process
handles are used. Never starts/terminates an OS process or Windows service.
The protected Windows path occurs only as a string supplied to the lexical
guard; no filesystem function receives that path.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from pc_executor.context_binding import binding_from_uia_element
from pc_executor.executor import Executor
from pc_executor.models import ActionRequest, ElementInfo, Rect, canonical_json
from pc_executor.operations import OPS_ACTIONS, OPS_SIDE_EFFECT_ACTIONS, LocalOperations
from pc_executor.outcome_journal import OutcomeJournal
from pc_executor.shell import SafeShellAdapter
from pc_remote_transport.agent import TransportDispatchContext, UnknownDispatchOutcome
from pc_remote_transport.executor_adapter import (
    EXPECTED_COMPAT_TOOL_REGISTRY_V1_DIGEST,
    NATIVE_CONTROL_PROTOCOL_V1,
    NATIVE_TOOL_REGISTRY_V1,
    PARITY_TOOL_REGISTRY_V1,
    PARITY_TOOL_REGISTRY,
    PARITY_TOOL_REGISTRY_DIGEST,
    PARITY_TOOL_REGISTRY_LIST,
    TOOL_REGISTRY,
    TOOL_REGISTRY_DIGEST,
    TOOL_REGISTRY_LIST,
    ExecutorRemoteDispatcher,
    _HandleRecord,
)
from pc_remote_transport.protocol import digest_json


MATRIX = json.loads(
    (Path(__file__).parent / "fixtures" / "r16_executor_chaos" / "matrix.v1.json")
    .read_text(encoding="utf-8")
)
SCENARIOS = {row["id"]: row for row in MATRIX["scenarios"]}
CONTROL = NATIVE_CONTROL_PROTOCOL_V1


def _executor(
    tmp_path: Path,
    *,
    accessibility=None,
    state_root: Path | None = None,
    journal_path: Path | None = None,
) -> Executor:
    shell = SafeShellAdapter(
        allow_executables={Path(sys.executable).name.lower(), "python", "python.exe", "python3"},
        output_limit_bytes=4096,
    )
    operations = LocalOperations(
        shell=shell,
        state_root=state_root if state_root is not None else tmp_path / "isolated-ops",
    )
    return Executor(
        shell=shell,
        operations=operations,
        accessibility=accessibility,
        outcome_journal=OutcomeJournal(
            journal_path if journal_path is not None else tmp_path / "isolated-outcomes.jsonl"
        ),
        dry_run=False,
        operation_timeout_seconds=2.0,
    )


def _context(
    dispatcher: ExecutorRemoteDispatcher,
    *,
    epoch: str = "r16-device-epoch-a",
) -> TransportDispatchContext:
    return TransportDispatchContext(
        device_id="r16-synthetic-device",
        session_epoch=epoch,
        session_capabilities_digest=digest_json(dispatcher.capability_manifest()),
    )


def _body(
    rid: str,
    tool: str,
    args: dict | None = None,
    *,
    registry_version: str = PARITY_TOOL_REGISTRY_V1,
) -> dict:
    return {
        "contract_version": CONTROL,
        "registry_version": registry_version,
        "session_id": "r16-control-session",
        "request_id": rid,
        "tool": tool,
        "arguments": args if args is not None else {},
    }


async def _dispatch(
    dispatcher: ExecutorRemoteDispatcher,
    ctx: TransportDispatchContext,
    rid: str,
    tool: str,
    args: dict | None = None,
    *,
    registry_version: str = PARITY_TOOL_REGISTRY_V1,
):
    return await dispatcher.dispatch(
        request_version=CONTROL,
        request_id=rid,
        body=_body(rid, tool, args, registry_version=registry_version),
        transport_context=ctx,
    )


def _registry_digest(version: str, tools) -> str:
    return hashlib.sha256(
        canonical_json({
            "contract_version": version,
            "tools": [tool.registry_digest_dict() for tool in tools],
        }).encode("utf-8")
    ).hexdigest()


def test_r16_matrix_is_versioned_complete_and_temp_only() -> None:
    assert MATRIX["schema"] == "pc.native.executor.r16.chaos_matrix.v1"
    assert MATRIX["provenance"]["exact_base_sha"] == "04f817299b46ecb0ffa8aa908ce84fdb4c3300d0"
    assert set(SCENARIOS) == {f"R16-{i:02d}" for i in range(1, 12)}
    assert MATRIX["semantics"]["unknown_outcome"].startswith("lookup/reconcile")
    assert "tmp_path" in MATRIX["provenance"]["fixture_scope"]


def test_r16_frozen_compatibility_and_separate_parity_registry_digests(
    tmp_path: Path,
) -> None:
    pinned = MATRIX["frozen_registries"]
    compat = pinned["compatibility"]
    parity = pinned["parity"]
    assert compat["contract_version"] == NATIVE_TOOL_REGISTRY_V1
    assert parity["contract_version"] == PARITY_TOOL_REGISTRY_V1
    assert TOOL_REGISTRY_DIGEST == EXPECTED_COMPAT_TOOL_REGISTRY_V1_DIGEST
    assert TOOL_REGISTRY_DIGEST == compat["sha256"]
    assert PARITY_TOOL_REGISTRY_DIGEST == parity["sha256"]
    assert parity["sha256"] != compat["sha256"]
    assert _registry_digest(NATIVE_TOOL_REGISTRY_V1, TOOL_REGISTRY_LIST) == compat["sha256"]
    assert _registry_digest(PARITY_TOOL_REGISTRY_V1, PARITY_TOOL_REGISTRY_LIST) == parity["sha256"]

    manifest = ExecutorRemoteDispatcher(_executor(tmp_path)).capability_manifest()
    assert manifest["registry_digest"] == compat["sha256"]
    assert manifest["compatibility"]["registry_digest"] == compat["sha256"]
    assert manifest["internal_registry"]["contract_version"] == PARITY_TOOL_REGISTRY_V1
    assert manifest["internal_registry"]["registry_digest"] == parity["sha256"]
    assert manifest["compatibility"]["default_for_unversioned_requests"] is True


def test_r16_exact_read_only_and_side_effect_route_resolution(
    tmp_path: Path,
) -> None:
    dispatcher = ExecutorRemoteDispatcher(_executor(tmp_path))
    ctx = _context(dispatcher)
    manifest = dispatcher.capability_manifest()
    parity_snapshot = dispatcher.executor.operations.capabilities_snapshot()
    legacy_snapshot = dispatcher.executor.capabilities_snapshot()
    assert len(PARITY_TOOL_REGISTRY_LIST) >= 40
    for tool in PARITY_TOOL_REGISTRY_LIST:
        action, current_digest, surface = dispatcher._assert_capability_stability(
            ctx, tool, PARITY_TOOL_REGISTRY_V1
        )
        assert surface == "parity"
        assert action == tool.executor_action
        assert current_digest == parity_snapshot["attestation"]["digest"]
        entry = parity_snapshot["actions"][action]
        assert entry["supported"] is True
        assert entry["side_effecting"] is (tool.effect == "side_effect")
        assert (action in OPS_SIDE_EFFECT_ACTIONS) is (tool.effect == "side_effect")
        assert action in OPS_ACTIONS

    routes = manifest["compatibility"]["routes"]
    assert set(routes) == set(TOOL_REGISTRY)
    for tool in TOOL_REGISTRY_LIST:
        route = routes[tool.name]
        if route["status"] == "capability_unavailable":
            assert route["target_action"] is None
            assert tool.name == "uia.find"
            continue
        action, digest, surface = dispatcher._assert_capability_stability(
            ctx, tool, NATIVE_TOOL_REGISTRY_V1
        )
        assert action == route["target_action"]
        assert surface == route["surface"]
        snapshot = parity_snapshot if surface == "parity" else legacy_snapshot
        assert digest == snapshot["attestation"]["digest"]
        assert snapshot["actions"][action]["supported"] is True
        assert snapshot["actions"][action]["side_effecting"] is (tool.effect == "side_effect")


def _element(
    *,
    process_start_epoch_ms: int = 1000,
    window_handle: int = 77,
    runtime_id: tuple[int, ...] = (1, 2, 3),
) -> ElementInfo:
    return ElementInfo(
        name="synthetic",
        automation_id="r16-button",
        control_type="ButtonControl",
        is_enabled=True,
        is_password=False,
        native_handle=88,
        bounds=Rect(10, 20, 100, 40),
        display_id="display:r16",
        window_handle=window_handle,
        process_id=42,
        class_name="Button",
        is_offscreen=False,
        supports_invoke=True,
        supports_value=True,
        process_start_epoch_ms=process_start_epoch_ms,
        runtime_id=runtime_id,
    )


class SyntheticUIA:
    def __init__(self) -> None:
        self.current = _element()
        self.inspects = 0
        self.effects = 0

    def inspect(self, query):
        self.inspects += 1
        return self.current

    def invoke(self, query):
        self.effects += 1
        return self.current

    def focus(self, query):
        raise AssertionError("synthetic focus must not dispatch")

    def set_value(self, query, value, *, sensitive=False):
        raise AssertionError("synthetic set_value must not dispatch")

    def snapshot(self, *, window_title=None):
        raise AssertionError("synthetic snapshot must not dispatch")


@pytest.mark.parametrize(
    ("scenario", "changed"),
    [
        ("R16-03", {"process_start_epoch_ms": 2000}),
        ("R16-04", {"window_handle": 78}),
        ("R16-05", {"runtime_id": (1, 2, 99)}),
    ],
)
def test_r16_context_revalidated_immediately_before_synthetic_uia_effect(
    tmp_path: Path, scenario: str, changed: dict,
) -> None:
    uia = SyntheticUIA()
    executor = _executor(tmp_path, accessibility=uia)
    request = ActionRequest(
        action="uia.invoke",
        params={"query": {"automation_id": "r16-button"}},
        request_id=f"r16-{scenario}-stale",
    )
    request.execution_context_binding = executor.bind_execution_context(request)
    assert request.execution_context_binding["context_digest"]
    # A valid binding exists, then the observed process/window/UI epoch changes
    # before _effectful's last-moment revalidation. No real UI interaction occurs.
    uia.current = _element(**changed)
    result = executor.execute(request)
    expected = SCENARIOS[scenario]
    assert result.ok is False
    assert result.status == "blocked"
    assert result.error.startswith(expected["error"] + ":")
    assert result.outcome_evidence is not None
    assert result.outcome_evidence.effect_state == expected["effect_state"]
    assert result.outcome_evidence.dispatch_started is expected["dispatch_started"]
    assert result.data["execution_context_validation"]["adapter_dispatch_started"] is False
    assert uia.effects == expected["adapter_effect_count"]
    assert uia.inspects >= 2
    lookup = executor.read_outcome_evidence(request_id=request.request_id, action="uia.invoke")
    assert all(
        not item.get("outcome_evidence", {}).get("dispatch_started", False)
        for item in lookup.get("history", [])
    ) if isinstance(lookup.get("history"), list) else True


@pytest.mark.asyncio
async def test_r16_completed_duplicate_request_and_conflicting_args_never_reexecute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = _executor(tmp_path)
    calls: list[str] = []
    operations_execute = executor.operations.execute

    def counted(action, params, *, cancellation=None):
        calls.append(action)
        return operations_execute(action, params, cancellation=cancellation)

    monkeypatch.setattr(executor.operations, "execute", counted)
    dispatcher = ExecutorRemoteDispatcher(executor)
    first = await _dispatch(
        dispatcher, _context(dispatcher), "r16-duplicate-effect",
        "device.set_config", {"key": "diagnostics.max_recent_calls", "value": 21},
    )
    assert first.payload["status"] == "completed"
    assert executor.operations.settings.value("diagnostics.max_recent_calls") == 21
    assert calls == ["config.set"]

    for value in (21, 31):
        with pytest.raises(UnknownDispatchOutcome):
            await _dispatch(
                dispatcher, _context(dispatcher), "r16-duplicate-effect",
                "device.set_config",
                {"key": "diagnostics.max_recent_calls", "value": value},
            )
    assert calls == ["config.set"]
    assert executor.operations.settings.value("diagnostics.max_recent_calls") == 21
    lookup = executor.read_outcome_evidence(
        request_id="r16-duplicate-effect", action="config.set"
    )
    assert lookup["provenance"]["matched_records"] >= 1
    assert lookup["replay_authorized"] is False


@pytest.mark.asyncio
async def test_r16_effect_then_lost_result_journal_restart_and_reconnect_no_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_root = tmp_path / "r16-only-ops-state"
    journal_path = tmp_path / "r16-only-outcomes.jsonl"
    executor = _executor(tmp_path, state_root=state_root, journal_path=journal_path)
    actual_execute = executor.operations.execute
    effect_count = 0

    def lost_after_effect(action, params, *, cancellation=None):
        nonlocal effect_count
        value = actual_execute(action, params, cancellation=cancellation)
        if action == "config.set":
            effect_count += 1
            raise RuntimeError("R16 injected loss AFTER isolated settings effect")
        return value

    monkeypatch.setattr(executor.operations, "execute", lost_after_effect)
    dispatcher = ExecutorRemoteDispatcher(executor)
    with pytest.raises(UnknownDispatchOutcome):
        await _dispatch(
            dispatcher, _context(dispatcher), "r16-effect-then-loss",
            "device.set_config", {"key": "diagnostics.max_recent_calls", "value": 27},
        )
    assert effect_count == SCENARIOS["R16-07"]["adapter_effect_count"]
    assert executor.operations.settings.value("diagnostics.max_recent_calls") == 27

    first_lookup = executor.read_outcome_evidence(
        request_id="r16-effect-then-loss", action="config.set"
    )
    assert first_lookup["outcome"] == "unknown"
    assert first_lookup["replay_authorized"] is False
    assert first_lookup["provenance"]["matched_records"] >= 1
    assert first_lookup["latest_valid_evidence"]["effect_state"] == "unknown"

    # New local Executor/operations objects model process restart, new dispatcher
    # models relay/control reconnect; only tmp_path journal + settings are reused.
    recovered = _executor(
        tmp_path, state_root=state_root, journal_path=journal_path,
    )
    assert recovered.operations.settings.value("diagnostics.max_recent_calls") == 27
    recovered_dispatcher = ExecutorRemoteDispatcher(recovered)
    attempts: list[str] = []

    def forbidden_second_execute(request):
        attempts.append(request.action)
        raise AssertionError("R16 unsafe replay reached Executor.execute")

    monkeypatch.setattr(recovered, "execute", forbidden_second_execute)
    with pytest.raises(UnknownDispatchOutcome):
        await _dispatch(
            recovered_dispatcher,
            _context(recovered_dispatcher, epoch="r16-device-epoch-reconnected"),
            "r16-effect-then-loss",
            "device.set_config",
            {"key": "diagnostics.max_recent_calls", "value": 99},
        )
    assert attempts == []
    assert effect_count == 1
    assert recovered.operations.settings.value("diagnostics.max_recent_calls") == 27
    retry_lookup = recovered.read_outcome_evidence(
        request_id="r16-effect-then-loss", action="config.set"
    )
    assert retry_lookup["replay_authorized"] is False
    assert retry_lookup["outcome"] == "unknown"


@pytest.mark.asyncio
async def test_r16_synthetic_process_handle_stale_epoch_and_restart_pre_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = _executor(tmp_path)
    dispatcher = ExecutorRemoteDispatcher(executor)
    ctx = _context(dispatcher)
    handle = "r16-synthetic-never-spawned"
    dispatcher._handles[handle] = _HandleRecord(
        handle=handle,
        session_id="r16-control-session",
        device_id=ctx.device_id,
        session_epoch=ctx.session_epoch,
        capabilities_digest=ctx.session_capabilities_digest,
        tool="process.start",
    )
    preflight_calls: list[str] = []
    execute_calls: list[str] = []

    def forbidden_preflight(payload):
        preflight_calls.append(payload["request"]["action"])
        raise AssertionError("stale handle reached preflight")

    def forbidden_execute(request):
        execute_calls.append(request.action)
        raise AssertionError("stale handle reached Executor")

    monkeypatch.setattr(executor, "preflight", forbidden_preflight)
    monkeypatch.setattr(executor, "execute", forbidden_execute)
    new_epoch = TransportDispatchContext(
        device_id=ctx.device_id,
        session_epoch="r16-reconnected-epoch",
        session_capabilities_digest=ctx.session_capabilities_digest,
    )
    for tool, args in (
        ("process.read", {"process_handle": handle, "max_bytes": 16}),
        ("process.terminate", {"process_handle": handle, "grace_ms": 10}),
    ):
        result = await _dispatch(
            dispatcher, new_epoch, f"r16-stale-epoch-{tool}",
            tool, args,
        )
        assert result.payload["status"] == "error"
        assert result.payload["error"]["code"] == SCENARIOS["R16-09"]["error"]

    fresh_dispatcher = ExecutorRemoteDispatcher(executor)
    fresh_context = _context(fresh_dispatcher, epoch="r16-restart-epoch")
    for tool in ("process.read", "process.terminate"):
        result = await _dispatch(
            fresh_dispatcher, fresh_context, f"r16-stale-restart-{tool}",
            tool, {"process_handle": handle},
        )
        assert result.payload["status"] == "error"
        assert result.payload["error"]["code"] == SCENARIOS["R16-10"]["error"]
    assert preflight_calls == []
    assert execute_calls == []


@pytest.mark.asyncio
async def test_r16_protected_path_is_lexically_rejected_before_any_fs_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = _executor(tmp_path)
    dispatcher = ExecutorRemoteDispatcher(executor)
    ctx = _context(dispatcher)
    preflight_calls: list[str] = []
    executor_calls: list[str] = []
    fs_calls: list[str] = []

    def deny_preflight(payload):
        preflight_calls.append(payload["request"]["action"])
        raise AssertionError("protected path reached Executor preflight")

    def deny_executor(request):
        executor_calls.append(request.action)
        raise AssertionError("protected path reached Executor dispatch")

    def deny_filesystem(action, params, *, cancellation=None):
        fs_calls.append(action)
        raise AssertionError("protected path reached LocalOperations")

    monkeypatch.setattr(executor, "preflight", deny_preflight)
    monkeypatch.setattr(executor, "execute", deny_executor)
    monkeypatch.setattr(executor.operations, "execute", deny_filesystem)

    # Literal values ONLY; never Path(...), exists(), stat(), open() or access.
    protected_literal = "E:" + "\\" + "Manhwa" + "\\" + "r16-synthetic-only"
    for tool, arguments in (
        ("file.read", {"path": protected_literal}),
        ("file.read_multiple", {"paths": [str(tmp_path / "safe-only.txt"), protected_literal]}),
        ("file.write", {"path": protected_literal, "text": "not-written"}),
    ):
        result = await _dispatch(
            dispatcher, ctx, f"r16-protected-{tool}", tool, arguments,
        )
        assert result.payload["status"] == "error"
        assert result.payload["error"]["code"] == SCENARIOS["R16-11"]["error"]
    assert preflight_calls == executor_calls == fs_calls == []
