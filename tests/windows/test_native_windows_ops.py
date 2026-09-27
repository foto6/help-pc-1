from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

from pc_executor.executor import Executor
from pc_executor.models import ActionRequest
from pc_executor.operations import LocalOperations
from pc_executor.outcome_journal import OutcomeJournal
from pc_executor.shell import SafeShellAdapter


pytestmark = pytest.mark.skipif(
    os.name != "nt",
    reason="Windows-native adapter coverage",
)


def _shell() -> SafeShellAdapter:
    executable = Path(sys.executable).name.lower()
    return SafeShellAdapter(
        allow_executables={"python", "python.exe", executable},
        output_limit_bytes=4096,
    )


def _executor(tmp_path: Path) -> Executor:
    shell = _shell()
    return Executor(
        shell=shell,
        operations=LocalOperations(
            shell=shell,
            state_root=tmp_path / "ops-state",
        ),
        outcome_journal=OutcomeJournal(tmp_path / "outcomes.jsonl"),
        dry_run=False,
        operation_timeout_seconds=5.0,
    )


def _request(action: str, params: dict, request_id: str) -> ActionRequest:
    return ActionRequest(
        action=action,
        params=params,
        request_id=request_id,
        timeout_ms=5000,
    )


def test_windows_process_listing_uses_native_snapshot_not_tasklist(
    tmp_path: Path,
    monkeypatch,
) -> None:
    import pc_executor.operations as operations_module

    original_run = operations_module.subprocess.run
    original_snapshot = operations_module.LocalOperations._windows_process_entries
    snapshot_calls = 0

    def guarded_subprocess_run(args, *run_args, **run_kwargs):
        parts = args if isinstance(args, (list, tuple)) else [args]
        command = " ".join(str(part) for part in parts).casefold()
        forbidden = ("tasklist", "wmic", "get-process", "ps -eo")
        if any(marker in command for marker in forbidden):
            raise AssertionError(
                f"Windows process listing used an external enumerator: {command}"
            )
        return original_run(args, *run_args, **run_kwargs)

    def observed_snapshot(self):
        nonlocal snapshot_calls
        snapshot_calls += 1
        return original_snapshot(self)

    monkeypatch.setattr(
        operations_module.subprocess,
        "run",
        guarded_subprocess_run,
    )
    monkeypatch.setattr(
        operations_module.LocalOperations,
        "_windows_process_entries",
        observed_snapshot,
    )
    executor = _executor(tmp_path)
    listed = executor.execute(
        _request(
            "process.list",
            {"pid": os.getpid(), "max_results": 5},
            "windows-list",
        )
    )
    assert listed.ok
    assert snapshot_calls == 1
    assert listed.data["count"] == 1
    assert listed.data["processes"][0]["pid"] == os.getpid()


def test_windows_system_process_kill_uses_pid_name_identity(
    tmp_path: Path,
) -> None:
    executor = _executor(tmp_path)
    started = executor.execute(
        _request(
            "process.start",
            {
                "argv": [
                    sys.executable,
                    "-c",
                    "import time; time.sleep(30)",
                ],
                "cwd": str(tmp_path),
            },
            "kill-start",
        )
    )
    assert started.ok
    pid = started.data["pid"]
    handle_id = started.data["handle_id"]
    inspected = executor.execute(
        _request("process.inspect", {"pid": pid}, "kill-inspect")
    )
    assert inspected.ok

    killed = executor.execute(
        _request(
            "system.process.kill",
            {
                "pid": pid,
                "expected_name": inspected.data["name"],
                "exit_code": 7,
            },
            "kill-direct",
        )
    )
    assert killed.ok
    assert killed.data["pid"] == pid
    assert killed.data["terminated"] is True

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        status = executor.execute(
            _request(
                "process.status",
                {"handle_id": handle_id},
                f"kill-status-{time.monotonic_ns()}",
            )
        )
        assert status.ok
        if status.data["status"] == "exited":
            break
        time.sleep(0.02)
    else:
        pytest.fail("terminated child remained running")


def test_windows_system_process_kill_name_mismatch_is_preflight_blocked(
    tmp_path: Path,
) -> None:
    executor = _executor(tmp_path)
    started = executor.execute(
        _request(
            "process.start",
            {
                "argv": [
                    sys.executable,
                    "-c",
                    "import time; time.sleep(30)",
                ],
                "cwd": str(tmp_path),
            },
            "mismatch-start",
        )
    )
    assert started.ok
    try:
        blocked = executor.execute(
            _request(
                "system.process.kill",
                {
                    "pid": started.data["pid"],
                    "expected_name": "definitely-not-the-process.exe",
                },
                "mismatch-kill",
            )
        )
        assert blocked.status == "blocked"
        assert blocked.outcome_evidence.effect_state == "not_started"
    finally:
        stopped = executor.execute(
            _request(
                "process.terminate",
                {
                    "handle_id": started.data["handle_id"],
                    "grace_ms": 20,
                },
                "mismatch-stop",
            )
        )
        assert stopped.ok
