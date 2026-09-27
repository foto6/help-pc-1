from __future__ import annotations

import pytest

from pc_executor.safety import SafetyViolation, ensure_argv_allowed
from tools.github_relay import (
    DEFAULT_ALLOWED_ACTIONS,
    RELAY_SHELL_EXECUTABLES,
    REQUEST_VERSION,
    _validate_request,
)


def test_relay_accepts_strict_shell_request() -> None:
    payload = _validate_request(
        {
            "version": REQUEST_VERSION,
            "id": "smoke-001",
            "action": "shell.run",
            "params": {
                "argv": ["powershell.exe", "-NoProfile", "-Command", "Write-Output ok"],
                "cwd": r"C:\",
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
