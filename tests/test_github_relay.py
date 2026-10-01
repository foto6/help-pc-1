from __future__ import annotations

import pytest

from pc_executor.safety import SafetyViolation, ensure_argv_allowed
from tools.github_relay import (
    DEFAULT_ALLOWED_ACTIONS,
    RELAY_SHELL_EXECUTABLES,
    REQUEST_VERSION,
    HEALTH_VERSION,
    _pending_result_paths,
    _validate_request,
    classify_health_snapshot,
)


def test_relay_accepts_strict_shell_request() -> None:
    payload = _validate_request(
        {
            "version": REQUEST_VERSION,
            "id": "smoke-001",
            "action": "shell.run",
            "params": {
                "argv": ["powershell.exe", "-NoProfile", "-Command", "Write-Output ok"],
                "cwd": "C:\\",
            },
            "timeout_ms": 5000,
        },
        DEFAULT_ALLOWED_ACTIONS,
    )
    assert payload["id"] == "smoke-001"
    assert payload["action"] == "shell.run"


@pytest.mark.parametrize(
    "exe",
    ["powershell", "powershell.exe", "pwsh", "pwsh.exe", "cmd", "cmd.exe"],
)
def test_relay_shell_allowlist_explicitly_includes_windows_shells(exe: str) -> None:
    args = ensure_argv_allowed([exe, "/?"], RELAY_SHELL_EXECUTABLES)
    assert args[0] == exe


def test_relay_rejects_unknown_request_fields() -> None:
    with pytest.raises(ValueError, match="unknown request keys"):
        _validate_request(
            {
                "version": REQUEST_VERSION,
                "id": "bad",
                "action": "shell.run",
                "params": {},
                "surprise": True,
            },
            DEFAULT_ALLOWED_ACTIONS,
        )


def test_relay_rejects_unenabled_action() -> None:
    with pytest.raises(ValueError, match="not enabled"):
        _validate_request(
            {
                "version": REQUEST_VERSION,
                "id": "mouse",
                "action": "mouse.click",
                "params": {"x": 1, "y": 2},
            },
            DEFAULT_ALLOWED_ACTIONS,
        )


def test_relay_shell_still_blocks_direct_protected_path() -> None:
    with pytest.raises(SafetyViolation, match="protected path"):
        ensure_argv_allowed(
            [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                r"Get-ChildItem E:\manhwa",
            ],
            RELAY_SHELL_EXECUTABLES,
        )



def test_health_pid_presence_is_not_enough_for_healthy() -> None:
    assert classify_health_snapshot(
        None,
        now_unix=100.0,
        process_exists=True,
        stale_after_seconds=30.0,
    ) == "PROCESS_EXISTS"


def test_health_stale_alive_process_is_stale() -> None:
    snapshot = {
        "health_version": HEALTH_VERSION,
        "status": "healthy",
        "updated_at_unix": 60.0,
        "reconciliation_required": False,
    }
    assert classify_health_snapshot(
        snapshot,
        now_unix=100.1,
        process_exists=True,
        stale_after_seconds=30.0,
    ) == "STALE"


def test_health_fresh_healthy_snapshot_is_healthy() -> None:
    snapshot = {
        "health_version": HEALTH_VERSION,
        "status": "healthy",
        "updated_at_unix": 95.0,
        "reconciliation_required": False,
    }
    assert classify_health_snapshot(
        snapshot,
        now_unix=100.0,
        process_exists=True,
        stale_after_seconds=30.0,
    ) == "HEALTHY"


def test_health_reconciliation_required_fails_closed() -> None:
    snapshot = {
        "health_version": HEALTH_VERSION,
        "status": "healthy",
        "updated_at_unix": 99.0,
        "reconciliation_required": True,
    }
    assert classify_health_snapshot(
        snapshot,
        now_unix=100.0,
        process_exists=True,
        stale_after_seconds=30.0,
    ) == "RECONCILIATION_REQUIRED"


def test_pending_result_paths_only_returns_git_dirty_results(tmp_path, monkeypatch) -> None:
    repo = tmp_path
    results = repo / "relay" / "results"
    results.mkdir(parents=True)
    historical = results / "old.json"
    pending = results / "new.json"
    historical.write_text("{}", encoding="utf-8")
    pending.write_text("{}", encoding="utf-8")

    class Probe:
        returncode = 0
        stdout = "?? relay/results/new.json\n"
        stderr = ""

    monkeypatch.setattr("tools.github_relay._run_git", lambda *args, **kwargs: Probe())
    assert _pending_result_paths(repo, results) == [pending.resolve()]
