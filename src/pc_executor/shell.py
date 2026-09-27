from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Sequence

from .safety import DEFAULT_SAFE_EXECUTABLES, ensure_argv_allowed, ensure_path_allowed


@dataclass(slots=True)
class ShellResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str

    def to_dict(self) -> dict[str, object]:
        return {
            "argv": self.argv,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


class SafeShellAdapter:
    def __init__(self, *, allow_executables: set[str] | None = None, timeout_seconds: float = 15.0) -> None:
        self.allow_executables = allow_executables or set(DEFAULT_SAFE_EXECUTABLES)
        self.timeout_seconds = timeout_seconds

    def validate(self, argv: Sequence[str], *, cwd: str | None = None) -> list[str]:
        args = ensure_argv_allowed(argv, self.allow_executables)
        ensure_path_allowed(cwd)
        return args

    def run(self, argv: Sequence[str], *, cwd: str | None = None) -> ShellResult:
        args = self.validate(argv, cwd=cwd)
        completed = subprocess.run(
            args,
            cwd=cwd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=self.timeout_seconds,
            check=False,
        )
        return ShellResult(args, completed.returncode, completed.stdout, completed.stderr)
