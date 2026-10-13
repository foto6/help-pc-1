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


def test_cleanup_timeout_does_not_mask_original_when_parent_already_exited() -> None:
    import subprocess
    from pc_executor.shell import _drain_process_pipes

    class ExitedParentWithInheritedPipes:
        calls = 0

        def communicate(self, timeout: float):
            self.calls += 1
            raise subprocess.TimeoutExpired(cmd="fake", timeout=timeout)

        def poll(self):
            return 0

    process = ExitedParentWithInheritedPipes()
    assert _drain_process_pipes(process) == (b"", b"")
    # A second communicate() would block on the child-held pipes again.
    assert process.calls == 1


def test_cleanup_timeout_kills_active_parent_but_does_not_retry_communicate(
    monkeypatch,
) -> None:
    import subprocess
    import pc_executor.shell as shell

    class LiveParentWithInheritedPipes:
        calls = 0
        stopped = False

        def communicate(self, timeout: float):
            self.calls += 1
            raise subprocess.TimeoutExpired(cmd="fake", timeout=timeout)

        def poll(self):
            return 0 if self.stopped else None

    process = LiveParentWithInheritedPipes()
    monkeypatch.setattr(shell, "_terminate_process_tree",
                        lambda candidate: setattr(candidate, "stopped", True))
    assert shell._drain_process_pipes(process) == (b"", b"")
    assert process.stopped is True
    assert process.calls == 1
