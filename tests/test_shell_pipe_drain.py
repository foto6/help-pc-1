from __future__ import annotations

import sys
from pathlib import Path

import pytest

from pc_executor.errors import OperationTimeoutError
from pc_executor.shell import SafeShellAdapter


def _adapter(timeout: float = 5.0, limit: int = 16 * 1024) -> SafeShellAdapter:
    return SafeShellAdapter(
        allow_executables={Path(sys.executable).name.lower()},
        timeout_seconds=timeout,
        output_limit_bytes=limit,
    )


def test_large_child_stdout_and_stderr_do_not_block_process_exit() -> None:
    # Both child pipes exceed the default Windows anonymous pipe capacity.
    # The old implementation waited for poll() BEFORE draining the pipes and
    # timed out, even though the child only wrote a deterministic burst.
    total = 192 * 1024
    program = (
        "import sys; "
        f"sys.stdout.buffer.write(b'A'*{total}); "
        "sys.stdout.flush(); "
        f"sys.stderr.buffer.write(b'B'*{total}); "
        "sys.stderr.flush()"
    )
    result = _adapter().run([sys.executable, "-c", program])
    assert result.returncode == 0
    assert result.stdout_bytes == total
    assert result.stderr_bytes == total
    assert result.stdout_truncated is True
    assert result.stderr_truncated is True
    assert result.stdout == "A" * (16 * 1024)
    assert result.stderr == "B" * (16 * 1024)


def test_child_sleep_still_enforces_execution_timeout() -> None:
    with pytest.raises(OperationTimeoutError, match="timed out"):
        _adapter(timeout=0.25).run(
            [sys.executable, "-c", "import time; time.sleep(10)"]
        )


def test_small_exit_status_and_stderr_are_preserved() -> None:
    result = _adapter().run(
        [sys.executable, "-c",
         "import sys; print('short output'); "
         "print('diagnostic', file=sys.stderr); sys.exit(3)"]
    )
    assert result.returncode == 3
    assert result.stdout.strip() == "short output"
    assert result.stderr.strip() == "diagnostic"
    assert not result.stdout_truncated
    assert not result.stderr_truncated
