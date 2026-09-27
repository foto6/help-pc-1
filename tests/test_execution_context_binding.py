from __future__ import annotations

import json
import os

import pytest

from pc_executor.cancellation import CancellationToken
from pc_executor.context_binding import (
    CONTRACT_VERSION,
    ContextMismatchBlockedError,
    CwdIdentity,
    ExecutionContextBinding,
    ForegroundContext,
    SystemExecutionContextObserver,
    binding_from_foreground,
    binding_from_shell,
    binding_from_uia_element,
    parse_execution_context_binding,
    validate_execution_context_binding,
)
from pc_executor.errors import StaleTargetError
from pc_executor.executor import Executor
from pc_executor.models import ActionRequest, ElementInfo, Rect
from pc_executor.outcome_journal import OutcomeJournal
from pc_executor.preflight import CONTRACT_VERSION as PREFLIGHT_VERSION
from pc_executor.shell import ShellResult
from pc_executor.windows import process_start_epoch_ms


def element(
    *,
    process_id: int = 42,
    start_epoch_ms: int = 1000,
    window_handle: int = 77,
    native_handle: int = 88,
    runtime_id: tuple[int, ...] = (1, 2, 3),
    display_id: str = "display:a",
    automation_id: str = "save",
) -> ElementInfo:
    return ElementInfo(
        name="Save",
        automation_id=automation_id,
        control_type="ButtonControl",
        is_enabled=True,
        is_password=False,
        native_handle=native_handle,
        bounds=Rect(10, 20, 100, 40),
        display_id=display_id,
        window_handle=window_handle,
        process_id=process_id,
        class_name="Button",
        is_offscreen=False,
        supports_invoke=True,
        supports_value=True,
        process_start_epoch_ms=start_epoch_ms,
        runtime_id=runtime_id,
    )


class SequenceUIA:
    def __init__(self, observations):
        self.observations = list(observations)
        self.inspect_calls = 0
        self.side_effects = []

    def inspect(self, query):
        self.inspect_calls += 1
        if not self.observations:
            raise AssertionError("unexpected UIA inspect")
        value = self.observations.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value

    def invoke(self, query):
        self.side_effects.append(("invoke", query.automation_id))
        return element(automation_id=query.automation_id or "save")

    def focus(self, query):
        self.side_effects.append(("focus", query.automation_id))
        return element(automation_id=query.automation_id or "save")

    def set_value(self, query, value, *, sensitive=False):
        self.side_effects.append(("set_value", query.automation_id, len(value)))
        return element(automation_id=query.automation_id or "save")

    def snapshot(self, *, window_title=None):
        raise AssertionError("context validation must not snapshot")


class RecordingInput:
    def __init__(self):
        self.events = []

    def click(self, x, y, *, button="left"):
        self.events.append(("click", x, y, button))

    def press(self, key):
        self.events.append(("press", key))

    def type_text(self, text):
        self.events.append(("type_text", len(text)))

    def clipboard_get(self):
        raise AssertionError("binding validation must not read clipboard")

    def clipboard_set(self, text):
        self.events.append(("clipboard_set", len(text)))


class SequenceObserver:
    def __init__(
        self,
        foregrounds=(),
        displays=(),
        cwds=(),
        on_foreground_call=None,
    ):
        self.foregrounds = list(foregrounds)
        self.displays = list(displays)
        self.cwds = list(cwds)
        self.foreground_calls = 0
        self.display_calls = 0
        self.cwd_calls = 0
        self.on_foreground_call = on_foreground_call

    def foreground(self):
        self.foreground_calls += 1
        if self.on_foreground_call is not None:
            self.on_foreground_call(self.foreground_calls)
        if not self.foregrounds:
            raise AssertionError("unexpected foreground observation")
        return self.foregrounds.pop(0)

    def display_at(self, x, y):
        self.display_calls += 1
        if not self.displays:
            return None
        return self.displays.pop(0)

    def cwd_identity(self, cwd):
        self.cwd_calls += 1
        if not self.cwds:
            raise AssertionError("unexpected cwd observation")
        return self.cwds.pop(0)


class RecordingShell:
    def __init__(self):
        self.validate_calls = []
        self.run_calls = []

    def validate(self, argv, *, cwd=None):
        self.validate_calls.append((list(argv), cwd))
        if not argv:
            raise ValueError("argv empty")
        return [str(x) for x in argv]

    def run(
        self,
        argv,
        *,
        cwd=None,
        timeout_seconds=None,
        cancellation=None,
    ):
        self.run_calls.append((list(argv), cwd))
        return ShellResult(
            argv=list(argv),
            returncode=0,
            stdout="",
            stderr="",
            stdout_bytes=0,
            stderr_bytes=0,
            stdout_truncated=False,
            stderr_truncated=False,
            output_limit_bytes=1024,
        )


def preflight_payload(request_id="req", action="uia.invoke"):
    return {
        "contract_version": PREFLIGHT_VERSION,
        "request": {
            "request_id": request_id,
            "action": action,
            "params": {"query": {"automation_id": "save"}},
            "dry_run": None,
            "timeout_ms": 1000,
        },
    }


def assert_context_mismatch(result, *, adapter_events):
    assert result.ok is False
    assert result.status == "blocked"
    assert result.error_kind == "policy_blocked"
    assert result.error.startswith("context_mismatch:")
    assert adapter_events == []
    evidence = result.outcome_evidence
    assert evidence is not None
    assert evidence.effect_state == "not_started"
    assert evidence.dispatch_started is False
    assert evidence.reexecution_safe is True
    assert evidence.reason == "policy_blocked"
    validation = result.data["execution_context_validation"]
    assert validation["contract_version"] == (
        "pc_executor.execution_context_validation.v1"
    )
    assert validation["reason"] == "context_mismatch"
    assert validation["status"] == "blocked"
    assert validation["adapter_dispatch_started"] is False
    assert validation["reexecution_safe"] is True
    assert validation["mismatches"]


def test_binding_contract_round_trip_and_digest_are_strict():
    bound = binding_from_uia_element(
        request_id="req",
        action="uia.invoke",
        element=element(),
        capture_id="shot:abc",
    )
    payload = bound.to_dict()

    assert payload["contract_version"] == CONTRACT_VERSION
    assert len(payload["context_digest"]) == 64
    assert payload["display"] == {
        "display_id": "display:a",
        "capture_id": "shot:abc",
    }
    assert "display.display_id" not in payload["authoritative_fields"]
    assert parse_execution_context_binding(payload).to_dict() == payload
    validate_execution_context_binding(payload)

    tampered = json.loads(json.dumps(payload))
    tampered["window"]["window_handle"] = 999
    with pytest.raises(ValueError):
        validate_execution_context_binding(tampered)


def test_binding_excludes_payload_bodies_and_raw_coordinates():
    foreground = ForegroundContext(42, 1000, 77, "display:a")
    binding = binding_from_foreground(
        request_id="req",
        action="mouse.click",
        foreground=foreground,
        capture_id="shot:abc",
        display_id="display:a",
    ).to_dict()
    serialized = json.dumps(binding, sort_keys=True)
    assert "123456789" not in serialized
    assert "-987654321" not in serialized
    assert "DO-NOT-PERSIST" not in serialized

    shell = binding_from_shell(
        request_id="shell",
        action="shell.run",
        executable=r"C:\Python\python.exe",
        cwd=CwdIdentity("a" * 64, 1, 2),
    ).to_dict()
    shell_serialized = json.dumps(shell, sort_keys=True)
    assert "--password" not in shell_serialized
    assert "secret-value" not in shell_serialized


def test_process_restart_same_title_blocks_before_uia_invoke():
    first = element(start_epoch_ms=1000)
    restarted = element(start_epoch_ms=2000)
    uia = SequenceUIA([first, restarted])
    executor = Executor(accessibility=uia, dry_run=False)
    request = ActionRequest(
        "uia.invoke",
        {"query": {"automation_id": "save"}},
        request_id="restart",
    )
    request.execution_context_binding = executor.bind_execution_context(request)

    result = executor.execute(request)

    assert_context_mismatch(result, adapter_events=uia.side_effects)
    assert result.data["execution_context_validation"]["mismatches"] == [
        "process.start_epoch_ms"
    ]


def test_window_recreated_same_automation_id_blocks_before_uia_invoke():
    first = element(window_handle=77)
    recreated = element(window_handle=78)
    uia = SequenceUIA([first, recreated])
    executor = Executor(accessibility=uia, dry_run=False)
    request = ActionRequest(
        "uia.invoke",
        {"query": {"automation_id": "save"}},
        request_id="window-recreated",
    )
    request.execution_context_binding = executor.bind_execution_context(request)

    result = executor.execute(request)

    assert_context_mismatch(result, adapter_events=uia.side_effects)
    assert result.data["execution_context_validation"]["mismatches"] == [
        "window.window_handle"
    ]


def test_target_rebound_same_window_blocks_before_uia_invoke():
    first = element(runtime_id=(1, 2, 3))
    rebound = element(runtime_id=(9, 9, 9))
    uia = SequenceUIA([first, rebound])
    executor = Executor(accessibility=uia, dry_run=False)
    request = ActionRequest(
        "uia.invoke",
        {"query": {"automation_id": "save"}},
        request_id="target-rebound",
    )
    request.execution_context_binding = executor.bind_execution_context(request)

    result = executor.execute(request)

    assert_context_mismatch(result, adapter_events=uia.side_effects)
    assert result.data["execution_context_validation"]["mismatches"] == [
        "target.identity_digest"
    ]


def test_target_disappeared_maps_to_context_mismatch_without_invoke():
    uia = SequenceUIA([element(), StaleTargetError("gone")])
    executor = Executor(accessibility=uia, dry_run=False)
    request = ActionRequest(
        "uia.invoke",
        {"query": {"automation_id": "save"}},
        request_id="target-gone",
    )
    request.execution_context_binding = executor.bind_execution_context(request)

    result = executor.execute(request)

    assert_context_mismatch(result, adapter_events=uia.side_effects)
    assert result.data["execution_context_validation"]["mismatches"] == [
        "target_resolution_changed"
    ]


def test_uia_display_move_same_process_window_target_is_benign():
    first = element(display_id="display:a")
    moved = element(display_id="display:b")
    uia = SequenceUIA([first, moved])
    executor = Executor(accessibility=uia, dry_run=False)
    request = ActionRequest(
        "uia.invoke",
        {"query": {"automation_id": "save"}},
        request_id="display-move",
    )
    request.execution_context_binding = executor.bind_execution_context(
        request,
        capture_id="shot:before",
    )

    result = executor.execute(request)

    assert result.ok is True
    assert result.outcome_evidence.effect_state == "completed"
    assert uia.side_effects == [("invoke", "save")]


def test_preflight_ready_then_context_restart_fails_closed():
    current = element(start_epoch_ms=1000)
    uia = SequenceUIA([current, current, element(start_epoch_ms=2000)])
    executor = Executor(accessibility=uia, dry_run=False)

    preflight = executor.preflight(preflight_payload("preflight-bound"))
    assert preflight.status == "ready"

    request = ActionRequest(
        "uia.invoke",
        {"query": {"automation_id": "save"}},
        request_id="preflight-bound",
    )
    request.execution_context_binding = executor.bind_execution_context(request)

    result = executor.execute(request)
    assert_context_mismatch(result, adapter_events=uia.side_effects)


def test_mouse_binding_rechecks_foreground_and_display_without_click():
    same = ForegroundContext(42, 1000, 77, "display:a")
    observer = SequenceObserver(
        foregrounds=[same, same],
        displays=["display:a", "display:b"],
    )
    input_adapter = RecordingInput()
    executor = Executor(
        input_adapter=input_adapter,
        context_observer=observer,
        dry_run=False,
        allow_coordinate_fallback=True,
    )
    request = ActionRequest(
        "mouse.click",
        {"x": 10, "y": 20},
        request_id="mouse-display",
    )
    request.execution_context_binding = executor.bind_execution_context(
        request,
        capture_id="shot:mouse",
    )

    result = executor.execute(request)

    assert_context_mismatch(result, adapter_events=input_adapter.events)
    assert result.data["execution_context_validation"]["mismatches"] == [
        "display.display_id"
    ]


def test_clipboard_binding_rechecks_foreground_without_clipboard_access():
    bound = ForegroundContext(42, 1000, 77, "display:a")
    changed = ForegroundContext(42, 1000, 78, "display:a")
    observer = SequenceObserver(foregrounds=[bound, changed])
    input_adapter = RecordingInput()
    executor = Executor(
        input_adapter=input_adapter,
        context_observer=observer,
        dry_run=False,
    )
    request = ActionRequest(
        "clipboard.set",
        {"text": "ordinary"},
        request_id="clipboard-window",
    )
    request.execution_context_binding = executor.bind_execution_context(request)

    result = executor.execute(request)

    assert_context_mismatch(result, adapter_events=input_adapter.events)


def test_cancellation_after_validation_before_dispatch_is_not_started():
    token = CancellationToken()
    foreground = ForegroundContext(42, 1000, 77, "display:a")

    def cancel_on_second_read(call):
        if call == 2:
            token.cancel()

    observer = SequenceObserver(
        foregrounds=[foreground, foreground],
        on_foreground_call=cancel_on_second_read,
    )
    input_adapter = RecordingInput()
    executor = Executor(
        input_adapter=input_adapter,
        context_observer=observer,
        dry_run=False,
    )
    request = ActionRequest(
        "keyboard.press",
        {"key": "enter"},
        request_id="cancel-after-validation",
    )
    request.execution_context_binding = executor.bind_execution_context(request)

    result = executor.execute(request, cancellation=token)

    assert result.status == "cancelled"
    assert input_adapter.events == []
    assert result.outcome_evidence.effect_state == "not_started"
    assert result.outcome_evidence.dispatch_started is False
    assert result.outcome_evidence.reexecution_safe is True


class CrashAfterValidationExecutor(Executor):
    def _validate_execution_context(self, request):
        value = super()._validate_execution_context(request)
        raise SystemExit("crash after context validation")


def test_crash_after_validation_before_adapter_call_has_no_side_effect():
    foreground = ForegroundContext(42, 1000, 77, "display:a")
    observer = SequenceObserver(foregrounds=[foreground, foreground])
    input_adapter = RecordingInput()
    executor = CrashAfterValidationExecutor(
        input_adapter=input_adapter,
        context_observer=observer,
        dry_run=False,
    )
    request = ActionRequest(
        "keyboard.press",
        {"key": "enter"},
        request_id="crash-before-adapter",
    )
    request.execution_context_binding = executor.bind_execution_context(request)

    with pytest.raises(SystemExit):
        executor.execute(request)

    assert input_adapter.events == []


class CrashBeforeTerminalJournal(OutcomeJournal):
    def append_terminal(self, evidence, *, correlation=None):
        if evidence.effect_state == "completed":
            raise SystemExit("crash before terminal outcome write")
        return super().append_terminal(evidence, correlation=correlation)


def test_crash_after_adapter_side_effect_before_outcome_write_stays_unknown(
    tmp_path,
):
    foreground = ForegroundContext(42, 1000, 77, "display:a")
    observer = SequenceObserver(foregrounds=[foreground, foreground])
    input_adapter = RecordingInput()
    journal = CrashBeforeTerminalJournal(tmp_path / "wave7.jsonl")
    executor = Executor(
        input_adapter=input_adapter,
        context_observer=observer,
        outcome_journal=journal,
        dry_run=False,
    )
    request = ActionRequest(
        "keyboard.press",
        {"key": "enter"},
        request_id="crash-after-effect",
    )
    request.execution_context_binding = executor.bind_execution_context(request)

    with pytest.raises(SystemExit):
        executor.execute(request)

    assert input_adapter.events == [("press", "enter")]
    lookup = journal.lookup(
        request_id="crash-after-effect",
        action="keyboard.press",
    ).to_dict()
    assert lookup["outcome"] == "unknown"
    assert lookup["latest_valid_evidence"]["effect_state"] == "unknown"
    assert lookup["latest_valid_evidence"]["reexecution_safe"] is False


def test_shell_binding_uses_no_gui_context_and_cwd_replacement_blocks_run():
    first = CwdIdentity("a" * 64, 1, 10)
    replaced = CwdIdentity("a" * 64, 1, 11)
    observer = SequenceObserver(cwds=[first, replaced])
    shell = RecordingShell()
    executor = Executor(
        shell=shell,
        context_observer=observer,
        dry_run=False,
    )
    request = ActionRequest(
        "shell.run",
        {"argv": ["python", "-V"], "cwd": None},
        request_id="shell-cwd",
    )
    request.execution_context_binding = executor.bind_execution_context(request)
    binding = parse_execution_context_binding(
        request.execution_context_binding
    )
    assert binding.context_kind == "shell"
    assert binding.process is None
    assert binding.window is None
    assert binding.target is None
    assert binding.display is None
    assert observer.foreground_calls == 0

    result = executor.execute(request)

    assert_context_mismatch(result, adapter_events=shell.run_calls)
    assert observer.foreground_calls == 0


def test_matching_shell_binding_executes_after_read_only_validation():
    cwd = CwdIdentity("b" * 64, 2, 20)
    observer = SequenceObserver(cwds=[cwd, cwd])
    shell = RecordingShell()
    executor = Executor(
        shell=shell,
        context_observer=observer,
        dry_run=False,
    )
    request = ActionRequest(
        "shell.run",
        {"argv": ["python", "-V"]},
        request_id="shell-match",
    )
    request.execution_context_binding = executor.bind_execution_context(request)

    result = executor.execute(request)

    assert result.ok is True
    assert shell.run_calls == [(["python", "-V"], None)]
    assert observer.foreground_calls == 0


def test_request_identity_reuse_is_blocked_before_context_observation():
    first = element()
    uia = SequenceUIA([first])
    executor = Executor(accessibility=uia, dry_run=False)
    original = ActionRequest(
        "uia.invoke",
        {"query": {"automation_id": "save"}},
        request_id="original",
    )
    binding = executor.bind_execution_context(original)

    reused = ActionRequest(
        "uia.invoke",
        {"query": {"automation_id": "save"}},
        request_id="different",
        execution_context_binding=binding,
    )
    result = executor.execute(reused)

    assert_context_mismatch(result, adapter_events=uia.side_effects)
    assert uia.inspect_calls == 1
    assert result.data["execution_context_validation"]["mismatches"] == [
        "request_id_changed"
    ]


def test_invalid_binding_version_blocks_without_adapter_dispatch():
    first = element()
    uia = SequenceUIA([first])
    executor = Executor(accessibility=uia, dry_run=False)
    request = ActionRequest(
        "uia.invoke",
        {"query": {"automation_id": "save"}},
        request_id="invalid-binding",
    )
    binding = executor.bind_execution_context(request)
    binding["contract_version"] = "pc_executor.execution_context_binding.v2"
    request.execution_context_binding = binding

    result = executor.execute(request)

    assert result.status == "blocked"
    assert result.error_kind == "policy_blocked"
    assert result.error.startswith("invalid execution_context_binding:")
    assert result.outcome_evidence.effect_state == "not_started"
    assert result.outcome_evidence.reexecution_safe is True
    assert uia.side_effects == []


def test_action_request_json_transport_preserves_optional_binding():
    binding = binding_from_uia_element(
        request_id="transport",
        action="uia.invoke",
        element=element(),
    ).to_dict()
    parsed = ActionRequest.from_dict(
        {
            "request_id": "transport",
            "action": "uia.invoke",
            "params": {"query": {"automation_id": "save"}},
            "execution_context_binding": binding,
        }
    )
    assert parsed.execution_context_binding == binding

    with pytest.raises(ValueError):
        ActionRequest.from_dict(
            {
                "request_id": "bad",
                "action": "uia.invoke",
                "params": {"query": {"automation_id": "save"}},
                "execution_context_binding": [],
            }
        )


def test_element_info_exposes_optional_execution_provenance_only_when_present():
    enriched = element().to_dict()
    assert enriched["process_start_epoch_ms"] == 1000
    assert enriched["runtime_id"] == [1, 2, 3]

    legacy = ElementInfo(
        "Save",
        "save",
        "ButtonControl",
        True,
        False,
        88,
    ).to_dict()
    assert "process_start_epoch_ms" not in legacy
    assert "runtime_id" not in legacy


def test_system_process_start_and_cwd_identity_are_portable_and_read_only():
    start = process_start_epoch_ms(os.getpid())
    assert start is None or start > 0

    observer = SystemExecutionContextObserver()
    first = observer.cwd_identity(None)
    second = observer.cwd_identity(None)
    assert first.path_digest == second.path_digest
    assert len(first.path_digest) == 64


def test_context_mismatch_error_evidence_has_no_context_values():
    error = ContextMismatchBlockedError(
        binding_digest="a" * 64,
        mismatches=[
            "process.start_epoch_ms",
            "window.window_handle",
            "target.identity_digest",
        ],
    )
    payload = error.validation_evidence
    assert payload["reason"] == "context_mismatch"
    assert payload["mismatches"] == [
        "process.start_epoch_ms",
        "window.window_handle",
        "target.identity_digest",
    ]
    serialized = json.dumps(payload)
    assert "1000" not in serialized
    assert "window title" not in serialized.lower()
