from __future__ import annotations

import ntpath
import os
from pathlib import Path, PureWindowsPath
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
    raw = str(value).strip().strip('"').replace("/", "\\")
    normalized = _normalize_windows_path(raw)
    raw_folded = raw.casefold()
    for protected in PROTECTED_WINDOWS_ROOTS:
        protected_norm = _normalize_windows_path(protected)
        protected_folded = protected.replace("/", "\\").casefold()
        index = raw_folded.find(protected_folded)
        embedded_protected = False
        while index >= 0:
            after = index + len(protected_folded)
            if after == len(raw_folded) or raw_folded[after] in {"\\", '"', "'"}:
                embedded_protected = True
                break
            index = raw_folded.find(protected_folded, index + 1)
        if (
            normalized == protected_norm
            or normalized.startswith(protected_norm + "\\")
            or embedded_protected
        ):
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


def ensure_resolved_path_allowed(
    value: str | os.PathLike[str],
    *,
    for_creation: bool = False,
) -> Path:
    """Resolve relative paths and link/junction targets before allowing access."""
    raw = str(value)
    ensure_path_allowed(raw)
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate

    if for_creation and not candidate.exists():
        missing: list[str] = []
        probe = candidate
        while not probe.exists():
            if probe.parent == probe:
                raise SafetyViolation(f"path has no resolvable existing ancestor: {candidate}")
            missing.append(probe.name)
            probe = probe.parent
        base = probe.resolve(strict=True)
        ensure_path_allowed(str(base))
        resolved = base.joinpath(*reversed(missing))
    else:
        resolved = candidate.resolve(strict=False)
    ensure_path_allowed(str(resolved))

    # Re-check all existing ancestors. This catches path aliases where an
    # intermediate link/junction/reparse point resolves under a protected root.
    probe = candidate if candidate.exists() else candidate.parent
    while True:
        try:
            if probe.exists():
                ensure_path_allowed(str(probe.resolve(strict=True)))
        except OSError as exc:
            raise SafetyViolation(f"path resolution failed closed: {probe}: {exc}") from exc
        if probe.parent == probe:
            break
        probe = probe.parent
    return resolved
