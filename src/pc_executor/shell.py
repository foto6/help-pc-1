from __future__ import annotations

import subprocess
from dataclasses import dataclass
from time import monotonic, sleep
from typing import Sequence

from .cancellation import CancellationToken
from .errors import OperationCancelledError, OperationTimeoutError
from .safety import DEFAULT_SAFE_EXECUTABLES, ensure_argv_allowed, ensure_path_allowed


@dataclass(slots=True)
class ShellResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    stdout_bytes: int
    stderr_bytes: int
    stdout_truncated: bool
    stderr_truncated: bool
    output_limit_bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "argv": self.argv,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
            "output_limit_bytes": self.output_limit_bytes,
        }


def _truncate(raw: bytes, limit: int) -> tuple[str, int, bool]:
    size = len(raw)
    clipped = raw[:limit]
    return clipped.decode("utf-8", errors="replace"), size, size > limit


class SafeShellAdapter:
    def __init__(
        self,
        *,
        allow_executables: set[str] | None = None,
        timeout_seconds: float = 15.0,
        output_limit_bytes: int = 64 * 1024,
    ) -> None:
        self.allow_executables = allow_executables or set(DEFAULT_SAFE_EXECUTABLES)
        self.timeout_seconds = timeout_seconds
        if output_limit_bytes <= 0:
            raise ValueError("output_limit_bytes must be positive")
        self.output_limit_bytes = output_limit_bytes

    def validate(self, argv: Sequence[str], *, cwd: str | None = None) -> list[str]:
        args = ensure_argv_allowed(argv, self.allow_executables)
        ensure_path_allowed(cwd)
        return args

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: str | None = None,
        timeout_seconds: float | None = None,
        cancellation: CancellationToken | None = None,
    ) -> ShellResult:
        args = self.validate(argv, cwd=cwd)
        timeout = self.timeout_seconds if timeout_seconds is None else timeout_seconds
        token = cancellation or CancellationToken()
        token.raise_if_cancelled()
        process = subprocess.Popen(
            args,
            cwd=cwd,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        deadline = monotonic() + timeout
        try:
            while process.poll() is None:
                if token.cancelled:
                    process.kill()
                    process.communicate()
                    raise OperationCancelledError("shell execution cancelled")
                if monotonic() >= deadline:
                    process.kill()
                    process.communicate()
                    raise OperationTimeoutError("shell execution timed out")
                sleep(0.02)
            stdout_raw, stderr_raw = process.communicate()
        except BaseException:
            if process.poll() is None:
                process.kill()
                process.communicate()
            raise

        stdout, stdout_bytes, stdout_truncated = _truncate(stdout_raw, self.output_limit_bytes)
        stderr, stderr_bytes, stderr_truncated = _truncate(stderr_raw, self.output_limit_bytes)
        return ShellResult(
            argv=args,
            returncode=int(process.returncode or 0),
            stdout=stdout,
            stderr=stderr,
            stdout_bytes=stdout_bytes,
            stderr_bytes=stderr_bytes,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            output_limit_bytes=self.output_limit_bytes,
        )
