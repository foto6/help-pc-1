from __future__ import annotations

from dataclasses import dataclass


ERROR_KINDS = {
    "transient",
    "stale_target",
    "ambiguous_target",
    "policy_blocked",
    "timeout",
    "cancelled",
    "executor_failure",
}


@dataclass(slots=True)
class ExecutorError(RuntimeError):
    kind: str
    message: str

    def __post_init__(self) -> None:
        if self.kind not in ERROR_KINDS:
            raise ValueError(f"unsupported executor error kind: {self.kind}")
        RuntimeError.__init__(self, self.message)

    def __str__(self) -> str:
        return self.message


class TransientExecutorError(ExecutorError):
    def __init__(self, message: str) -> None:
        super().__init__("transient", message)


class StaleTargetError(ExecutorError):
    def __init__(self, message: str) -> None:
        super().__init__("stale_target", message)


class AmbiguousTargetError(ExecutorError):
    def __init__(self, message: str) -> None:
        super().__init__("ambiguous_target", message)


class PolicyBlockedError(ExecutorError):
    def __init__(self, message: str) -> None:
        super().__init__("policy_blocked", message)


class OperationTimeoutError(ExecutorError):
    def __init__(self, message: str) -> None:
        super().__init__("timeout", message)


class OperationCancelledError(ExecutorError):
    def __init__(self, message: str = "operation cancelled") -> None:
        super().__init__("cancelled", message)


class ExecutorFailureError(ExecutorError):
    def __init__(self, message: str) -> None:
        super().__init__("executor_failure", message)
