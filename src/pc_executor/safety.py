from __future__ import annotations

import ntpath
from pathlib import PureWindowsPath
from typing import Iterable


class SafetyViolation(RuntimeError):
    pass


PROTECTED_WINDOWS_ROOTS = (r"E:\manhwa",)
DEFAULT_SAFE_EXECUTABLES = {
    "where",
    "where.exe",
    "whoami",
    "whoami.exe",
    "hostname",
    "hostname.exe",
    "ipconfig",
    "ipconfig.exe",
    "tasklist",
    "tasklist.exe",
    "git",
    "git.exe",
    "python",
    "python.exe",
    "py",
    "py.exe",
}


def _normalize_windows_path(value: str) -> str:
    return ntpath.normcase(ntpath.normpath(str(PureWindowsPath(value))))


def ensure_path_allowed(value: str | None) -> None:
    if not value:
        return
    normalized = _normalize_windows_path(value)
    for protected in PROTECTED_WINDOWS_ROOTS:
        protected_norm = _normalize_windows_path(protected)
        if normalized == protected_norm or normalized.startswith(protected_norm + "\\"):
            raise SafetyViolation(f"protected path is not accessible: {protected}")


def ensure_argv_allowed(argv: Iterable[str], allow_executables: set[str] | None = None) -> list[str]:
    args = [str(part) for part in argv]
    if not args:
        raise SafetyViolation("shell argv must not be empty")
    executable = ntpath.basename(args[0]).lower()
    allowed = {x.lower() for x in (allow_executables or DEFAULT_SAFE_EXECUTABLES)}
    if executable not in allowed:
        raise SafetyViolation(f"executable is not in safe allowlist: {executable}")
    for part in args:
        ensure_path_allowed(part)
    return args


def ensure_not_sensitive_text(*, is_password: bool, sensitive: bool = False) -> None:
    if is_password or sensitive:
        raise SafetyViolation("credential/sensitive text entry is not supported")
