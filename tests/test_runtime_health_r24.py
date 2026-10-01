from __future__ import annotations

import hashlib
import sys
import time
from pathlib import Path

import pytest

from pc_executor.cancellation import CancellationToken
from pc_executor.errors import OperationCancelledError, OperationTimeoutError
from pc_executor.executor import Executor
from pc_executor.models import ActionRequest, ElementInfo, Rect
from pc_executor.operations import LocalOperations
from pc_executor.outcome_journal import OutcomeJournal
from pc_executor.runtime_health import (
    CONTRACT_VERSION,
    probe_outcome_journal_integrity,
    validate_runtime_health,
)
from pc_executor.shell import SafeShellAdapter, ShellResult
from pc_executor.uia import WindowsUIAutomationAdapter


class SlowCooperativeUIA:
    def __init__(self) -> None:
        self.slow = True
        self.calls = 0

    def _wait(self, *, cancellation=None, deadline_monotonic=None):
        self.calls += 1
        while self.slow:
            if cancellation is not None:
                cancellation.raise_if_cancelled()
            if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
                raise OperationTimeoutError("synthetic UIA deadline")
            time.sleep(0.002)
        return None

    def health_probe(self, *, cancellation=None, deadline_monotonic=None):
        self._wait(
            cancellation=cancellation,
            deadline_monotonic=deadline_monotonic,
        )
        return {"synthetic": True}

    def snapshot(
        self,
        *,
        window_title=None,
        cancellation=None,
        deadline_monotonic=None,
    ):
        self._wait(
            cancellation=cancellation,
            deadline_monotonic=deadline_monotonic,
        )
        raise AssertionError("healthy synthetic snapshot not used")

    def inspect(self, query, *, cancellation=None, deadline_monotonic=None):
        self._wait(
            cancellation=cancellation,
            deadline_monotonic=deadline_monotonic,
        )
        return _element()

    def invoke(self, query, *, cancellation=None, deadline_monotonic=None):
        return self.inspect(
            query,
            cancellation=cancellation,
            deadline_monotonic=deadline_monotonic,
        )

    def focus(self, query, *, cancellation=None, deadline_monotonic=None):
        return self.inspect(
            query,
            cancellation=cancellation,
            deadline_monotonic=deadline_monotonic,
        )

    def set_value(
        self,
        query,
        value,
        *,
        sensitive=False,
        cancellation=None,
        deadline_monotonic=None,
    ):
        return self.inspect(
            query,
            cancellation=cancellation,
            deadline_monotonic=deadline_monotonic,
        )


class FastWindows:
    def __init__(self) -> None:
        self.calls = 0

    def list_windows(self):
        self.calls += 1
        return []


class FastScreenshot:
    def __init__(self) -> None:
        self.calls = 0

    def capture_png(self):
        self.calls += 1
        return b"r24-fake-png"


class FastInput:
    def click(self, x, y, *, button="left"):
        return None

    def press(self, key):
        return None

    def type_text(self, text):
        return None

    def clipboard_get(self):
        return "fixture"

    def clipboard_set(self, text):
        return None


class FastShell:
    allow_executables = {"python", "python.exe", Path(sys.executable).name.lower()}
    output_limit_bytes = 4096

    def validate(self, argv, *, cwd=None):
        return [str(v) for v in argv]

    def run(
        self,
        argv,
        *,
        cwd=None,
        timeout_seconds=None,
        cancellation=None,
    ):
        if cancellation is not None:
            cancellation.raise_if_cancelled()
        return ShellResult(
            argv=[str(v) for v in argv],
            returncode=0,
            stdout="r24-ok",
            stderr="",
            stdout_bytes=6,
            stderr_bytes=0,
            stdout_truncated=False,
            stderr_truncated=False,
            output_limit_bytes=4096,
        )


def _element() -> ElementInfo:
    return ElementInfo(
        name="synthetic",
        automation_id="r24",
        control_type="ButtonControl",
        is_enabled=True,
        is_password=False,
        native_handle=1,
        bounds=Rect(0, 0, 10, 10),
        display_id=None,
        window_handle=1,
        process_id=777,
        class_name="Button",
        is_offscreen=False,
        supports_invoke=True,
        supports_value=True,
        process_start_epoch_ms=1,
        runtime_id=(1, 2, 3),
    )


def _executor(tmp_path: Path, uia=None):
    shell = FastShell()
    operations = LocalOperations(
        shell=SafeShellAdapter(
            allow_executables={"python", "python.exe", Path(sys.executable).name.lower()},
            output_limit_bytes=4096,
        ),
        state_root=tmp_path / "ops",
    )
    journal = OutcomeJournal(tmp_path / "outcome.jsonl")
    return Executor(
        screenshot=FastScreenshot(),
        windows=FastWindows(),
        accessibility=uia or SlowCooperativeUIA(),
        input_adapter=FastInput(),
        shell=shell,
        operations=operations,
        outcome_journal=journal,
        dry_run=False,
        operation_timeout_seconds=0.4,
    )


def _request(action: str, params=None, rid="r24", timeout_ms=500):
    return ActionRequest(
        action=action,
        params=dict(params or {}),
        request_id=rid,
        timeout_ms=timeout_ms,
    )


def test_health_contract_contains_required_adapters_and_preserves_legacy_fields(tmp_path: Path):
    uia = SlowCooperativeUIA()
    uia.slow = False
    executor = _executor(tmp_path, uia=uia)

    result = executor.execute(_request("health.get", rid="health", timeout_ms=1200))

    assert result.ok
    assert result.data["contract_version"] == "pc_executor.ops.v1"
    assert "managed_processes_live" in result.data
    health = result.data["runtime_health"]
    validate_runtime_health(health)
    assert health["contract_version"] == CONTRACT_VERSION
    assert set(
        ["uia", "screenshot", "windows", "shell", "clipboard", "input",
         "outcome_journal", "search", "process"]
    ) <= set(health["adapters"])
    assert health["adapters"]["uia"]["state"] == "responsive"
    assert health["adapters"]["windows"]["state"] == "responsive"
    assert health["adapters"]["outcome_journal"]["state"] == "responsive"
    assert health["outcome_journal"]["integrity"] == "healthy"
    assert health["generation"]["operations_generation_id"] == executor.operations.generation_id


def test_two_uia_timeouts_open_circuit_without_degrading_unrelated_lanes(tmp_path: Path):
    uia = SlowCooperativeUIA()
    executor = _executor(tmp_path, uia=uia)
    executor.runtime_health.breaker_cooldown_seconds = 5.0

    measured = []
    for index in range(2):
        started = time.monotonic()
        result = executor.execute(
            _request("uia.snapshot", rid=f"uia-timeout-{index}", timeout_ms=40)
        )
        measured.append(time.monotonic() - started)
        assert result.status == "timeout"
        assert result.error_kind == "timeout"
    assert max(measured) < 0.35

    started = time.monotonic()
    fast_fail = executor.execute(
        _request("uia.snapshot", rid="uia-circuit", timeout_ms=400)
    )
    fast_fail_elapsed = time.monotonic() - started
    assert fast_fail.status == "timeout"
    assert fast_fail_elapsed < 0.12
    print(
        "R24_UIA_BOUND_METRICS",
        {
            "requested_timeout_ms": 40,
            "observed_timeout_ms": [round(value * 1000, 3) for value in measured],
            "circuit_fast_fail_ms": round(fast_fail_elapsed * 1000, 3),
        },
    )

    windows = executor.execute(
        _request("windows.list", rid="windows-after-uia", timeout_ms=200)
    )
    screenshot = executor.execute(
        _request("screenshot.capture", rid="screenshot-after-uia", timeout_ms=200)
    )
    shell = executor.execute(
        _request(
            "shell.run",
            {"argv": ["python", "-c", "print('not-executed-by-fake')"]},
            rid="shell-after-uia",
            timeout_ms=200,
        )
    )
    assert windows.ok and screenshot.ok and shell.ok

    health = executor.execute(
        _request("health.get", rid="health-after-uia", timeout_ms=1000)
    )
    runtime = health.data["runtime_health"]
    assert health.ok
    assert runtime["adapters"]["uia"]["state"] == "unhealthy"
    assert runtime["adapters"]["uia"]["circuit"]["state"] == "open"
    assert runtime["adapters"]["uia"]["timeout_count"] >= 2
    assert runtime["adapters"]["windows"]["state"] == "responsive"
    assert runtime["adapters"]["screenshot"]["state"] == "responsive"
    assert runtime["adapters"]["shell"]["state"] == "responsive"
    assert runtime["outcome_journal"]["integrity"] == "healthy"


def test_uia_timeout_recovers_after_half_open_success(tmp_path: Path):
    uia = SlowCooperativeUIA()
    executor = _executor(tmp_path, uia=uia)
    executor.runtime_health.breaker_cooldown_seconds = 0.01

    for index in range(2):
        result = executor.execute(
            _request("uia.snapshot", rid=f"open-{index}", timeout_ms=25)
        )
        assert result.status == "timeout"
    assert executor.runtime_health.circuit_state("uia") == "open"

    time.sleep(0.02)
    uia.slow = False
    health = executor.execute(
        _request("health.get", rid="recover-health", timeout_ms=800)
    )
    entry = health.data["runtime_health"]["adapters"]["uia"]
    assert entry["state"] == "responsive"
    assert entry["circuit"]["state"] == "closed"
    assert entry["last_success_at"] is not None


def test_corrupt_outcome_journal_is_reported_read_only_and_bounded(tmp_path: Path):
    executor = _executor(tmp_path)
    journal_path = executor.outcome_journal.path
    journal_path.write_bytes(b'{"not":"a-record"}\n')

    before = journal_path.read_bytes()
    health = executor.execute(
        _request("health.get", rid="corrupt-health", timeout_ms=1000)
    )
    after = journal_path.read_bytes()
    runtime = health.data["runtime_health"]

    assert health.ok
    assert before == after
    assert runtime["outcome_journal"]["integrity"] == "corrupt"
    assert runtime["outcome_journal"]["bounded"] is True
    assert runtime["outcome_journal"]["bytes_checked"] == len(before)
    assert runtime["adapters"]["outcome_journal"]["state"] == "unhealthy"
    assert runtime["outcome_journal"]["corruption"]["kind"] in {
        "malformed_record", "malformed_tail"
    }


def test_large_journal_health_is_unknown_without_unbounded_scan(tmp_path: Path):
    executor = _executor(tmp_path)
    journal_path = executor.outcome_journal.path
    journal_path.write_bytes(b"x" * (2 * 1024 * 1024 + 1))

    status = probe_outcome_journal_integrity(
        executor.outcome_journal,
        max_bytes=2 * 1024 * 1024,
    )

    assert status["integrity"] == "unknown"
    assert status["reason"] == "size_limit_exceeded"
    assert status["bytes_checked"] == 0
    assert status["journal_sha256"] is None


def test_generation_identity_changes_after_executor_restart(tmp_path: Path):
    first = _executor(tmp_path)
    first_health = first.execute(
        _request("health.get", rid="generation-1", timeout_ms=800)
    ).data["runtime_health"]
    second = _executor(tmp_path)
    second_health = second.execute(
        _request("health.get", rid="generation-2", timeout_ms=800)
    ).data["runtime_health"]

    assert first_health["generation"]["executor_process_id"] == second_health["generation"]["executor_process_id"]
    assert (
        first_health["generation"]["operations_generation_id"]
        != second_health["generation"]["operations_generation_id"]
    )
    for name in ("search", "process", "outcome_journal"):
        assert (
            second_health["adapters"][name]["generation"]["operations_generation_id"]
            == second.operations.generation_id
        )


def test_health_probe_timeout_does_not_cancel_parent_or_skip_windows(tmp_path: Path):
    uia = SlowCooperativeUIA()
    executor = _executor(tmp_path, uia=uia)
    token = CancellationToken()

    started = time.monotonic()
    result = executor.execute(
        _request("health.get", rid="probe-timeout", timeout_ms=900),
        cancellation=token,
    )
    elapsed = time.monotonic() - started

    assert result.ok
    assert token.cancelled is False
    runtime = result.data["runtime_health"]
    assert runtime["adapters"]["uia"]["state"] == "degraded"
    assert runtime["adapters"]["uia"]["timeout_count"] >= 1
    assert runtime["adapters"]["windows"]["state"] == "responsive"
    assert elapsed < 0.75


def test_r22_native_registry_action_inventory_not_changed_by_runtime_health():
    from pc_executor.operations import OPS_ACTIONS
    from pc_remote_transport.executor_adapter import (
        EXPECTED_COMPAT_TOOL_REGISTRY_V1_DIGEST,
        TOOL_REGISTRY_DIGEST,
    )

    assert "health.get" in OPS_ACTIONS
    assert "runtime.health.get" not in OPS_ACTIONS
    assert (
        TOOL_REGISTRY_DIGEST
        == EXPECTED_COMPAT_TOOL_REGISTRY_V1_DIGEST
        == "58b2bde8c6a49825747dcd7010f105dad0b6d548c7e8341cdafb32d2319f6dcd"
    )


class _Rect:
    left = 0
    top = 0
    right = 10
    bottom = 10


class TreeControl:
    def __init__(self, *, children=(), name="", pid=0, handle=0):
        self._children = list(children)
        self.Name = name
        self.AutomationId = ""
        self.ControlTypeName = "PaneControl"
        self.ClassName = "Synthetic"
        self.ProcessId = pid
        self.NativeWindowHandle = handle
        self.IsEnabled = True
        self.IsPassword = False
        self.IsOffscreen = False
        self.BoundingRectangle = _Rect()

    def GetChildren(self):
        return list(self._children)

    def GetInvokePattern(self):
        return None

    def GetValuePattern(self):
        return None

    def GetRuntimeId(self):
        return (1,)

class TreeAutomation:
    def __init__(self, root):
        self.root = root

    def GetRootControl(self):
        return self.root


class DirectWindowsUIA(WindowsUIAutomationAdapter):
    def __init__(self, root):
        self.auto = TreeAutomation(root)

    def _automation(self):
        return self.auto


def test_windows_uia_empty_tree_is_not_timeout_and_node_budget_is_timeout():
    empty = DirectWindowsUIA(TreeControl(name="Desktop", pid=1, handle=2))
    snapshot = empty.snapshot()
    assert len(snapshot.nodes) == 1

    chain = TreeControl(children=[TreeControl(children=[TreeControl()])])
    bounded = DirectWindowsUIA(chain)
    with pytest.raises(OperationTimeoutError, match="node budget"):
        bounded.snapshot(max_nodes=2)


def test_windows_uia_cancellation_and_deadline_are_distinct_from_empty_tree():
    adapter = DirectWindowsUIA(TreeControl())
    cancelled = CancellationToken()
    cancelled.cancel()
    with pytest.raises(OperationCancelledError):
        adapter.snapshot(cancellation=cancelled)
    with pytest.raises(OperationTimeoutError, match="deadline"):
        adapter.snapshot(deadline_monotonic=time.monotonic() - 0.001)


def test_windows_uia_diagnostics_hash_window_title_and_include_process_only():
    root = TreeControl(
        children=[TreeControl(name="Editor", pid=444, handle=55)],
        name="Desktop",
    )
    adapter = DirectWindowsUIA(root)
    snapshot = adapter.snapshot(window_title="Editor")
    diagnostics = adapter.diagnostics_snapshot()

    assert snapshot.window["process_id"] == 444
    assert diagnostics["target_process_id"] == 444
    assert diagnostics["window_title_sha256"] == hashlib.sha256(b"Editor").hexdigest()
    assert "Editor" not in str(diagnostics)
