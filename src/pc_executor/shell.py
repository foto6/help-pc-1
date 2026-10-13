from __future__ import annotations

import os
import signal
import subprocess
from dataclasses import dataclass
from time import monotonic
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


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return

    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
        except Exception:
            process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except Exception:
            process.kill()

    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _drain_process_pipes(process: subprocess.Popen[bytes]) -> tuple[bytes, bytes]:
    # Exception-path cleanup only. This helper must never replace the
    # original timeout/cancellation outcome with its own TimeoutExpired.
    # A spawned Windows descendant may outlive the direct process while
    # inheriting stdout/stderr pipe handles; communicate() then cannot see
    # EOF, even after the parent process has exited successfully.
    try:
        return process.communicate(timeout=1)
    except subprocess.TimeoutExpired:
        if process.poll() is None:
            _terminate_process_tree(process)
        # Never call communicate() again. A grandchild that retained the
        # inherited pipe handles can hold this open indefinitely. The caller
        # will re-raise the original timeout/cancellation and keep its
        # side effect UNKNOWN rather than incorrectly reporting success.
        return b"", b""


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
            start_new_session=(os.name != "nt"),
        )
        deadline = monotonic() + timeout
        try:
            # Draining only after process.poll() reports exit deadlocks on
            # Windows: a child writing > one pipe buffer blocks in write(),
            # so it never exits and our poll loop eventually times out.
            #
            # communicate() drains stdout AND stderr while the child runs.
            # Repeated calls after TimeoutExpired are supported by Popen
            # and keep cancellation checks responsive without threads or
            # busy-waiting on unconsumed pipes.
            while True:
                if token.cancelled:
                    raise OperationCancelledError("shell execution cancelled")
                remaining = deadline - monotonic()
                if remaining <= 0:
                    raise OperationTimeoutError("shell execution timed out")
                try:
                    stdout_raw, stderr_raw = process.communicate(
                        timeout=min(0.05, remaining)
                    )
                    break
                except subprocess.TimeoutExpired:
                    continue
        except BaseException:
            if process.poll() is None:
                _terminate_process_tree(process)
            try:
                _drain_process_pipes(process)
            except Exception:
                pass
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
