from __future__ import annotations

from queue import Empty, Queue
from threading import Event, Thread
from time import monotonic
from typing import Callable, TypeVar

from .errors import OperationCancelledError, OperationTimeoutError

T = TypeVar("T")


class CancellationToken:
    def __init__(self) -> None:
        self._event = Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self) -> None:
        if self.cancelled:
            raise OperationCancelledError()


def run_bounded(
    operation: Callable[[], T],
    *,
    timeout_seconds: float,
    cancellation: CancellationToken | None = None,
    label: str = "operation",
) -> T:
    """Run one operation behind a hard caller-side deadline.

    The worker is daemonized intentionally: some Windows APIs can ignore Python
    cancellation while blocked inside native code. A timeout therefore returns
    control immediately and cannot make interpreter shutdown wait for a wedged
    adapter thread. Cooperative adapters still receive the shared token and
    should stop as soon as it is cancelled. Higher layers use circuit breakers
    to avoid accumulating workers for a persistently wedged adapter.
    """
    token = cancellation or CancellationToken()
    token.raise_if_cancelled()
    if timeout_seconds <= 0:
        raise OperationTimeoutError(f"{label} timed out before execution")

    result: Queue[tuple[str, object]] = Queue(maxsize=1)

    def worker() -> None:
        try:
            value = operation()
        except BaseException as exc:
            try:
                result.put_nowait(("error", exc))
            except Exception:
                pass
            return
        try:
            result.put_nowait(("result", value))
        except Exception:
            pass

    thread = Thread(
        target=worker,
        name="pc-executor-bounded",
        daemon=True,
    )
    thread.start()
    deadline = monotonic() + timeout_seconds
    while True:
        token.raise_if_cancelled()
        remaining = deadline - monotonic()
        if remaining <= 0:
            token.cancel()
            raise OperationTimeoutError(f"{label} timed out")
        try:
            kind, value = result.get(timeout=min(0.05, remaining))
        except Empty:
            continue
        token.raise_if_cancelled()
        if kind == "error":
            assert isinstance(value, BaseException)
            raise value
        return value  # type: ignore[return-value]
