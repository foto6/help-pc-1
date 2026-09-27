from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from threading import Event
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
    token = cancellation or CancellationToken()
    token.raise_if_cancelled()
    if timeout_seconds <= 0:
        raise OperationTimeoutError(f"{label} timed out before execution")

    pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="pc-executor")
    future = pool.submit(operation)
    deadline = monotonic() + timeout_seconds
    try:
        while True:
            token.raise_if_cancelled()
            remaining = deadline - monotonic()
            if remaining <= 0:
                future.cancel()
                raise OperationTimeoutError(f"{label} timed out")
            try:
                result = future.result(timeout=min(0.05, remaining))
                token.raise_if_cancelled()
                return result
            except FutureTimeout:
                continue
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
