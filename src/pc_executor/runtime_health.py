from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from time import monotonic
from typing import Any, Callable

from .cancellation import CancellationToken, run_bounded
from .errors import OperationCancelledError, OperationTimeoutError
from .models import utc_now_iso
from .outcome_journal import OutcomeJournal


CONTRACT_VERSION = "pc_executor.runtime_health.v1"
RUNTIME_STATES = frozenset({"responsive", "degraded", "unhealthy", "unknown"})
DEFAULT_PROBE_TIMEOUT_SECONDS = 0.25
DEFAULT_BREAKER_TIMEOUT_THRESHOLD = 2
DEFAULT_BREAKER_COOLDOWN_SECONDS = 10.0


@dataclass(slots=True)
class _State:
    last_success_at: str | None = None
    last_failure_at: str | None = None
    last_failure_kind: str | None = None
    timeout_count: int = 0
    error_count: int = 0
    consecutive_timeouts: int = 0
    circuit_opened_at_monotonic: float | None = None
    circuit_opened_at: str | None = None
    diagnostics: dict[str, Any] | None = None


class RuntimeHealthMonitor:
    """Thread-safe runtime health accounting plus a small timeout circuit breaker.

    The monitor never probes by itself. Callers supply explicitly read-only probe
    functions, each of which is run in its own bounded worker. A timeout in one
    probe therefore does not cancel or serialize unrelated adapter probes.
    """

    def __init__(
        self,
        *,
        operation_timeout_seconds: float,
        breaker_timeout_threshold: int = DEFAULT_BREAKER_TIMEOUT_THRESHOLD,
        breaker_cooldown_seconds: float = DEFAULT_BREAKER_COOLDOWN_SECONDS,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        self.operation_timeout_seconds = max(0.001, float(operation_timeout_seconds))
        self.breaker_timeout_threshold = max(1, int(breaker_timeout_threshold))
        self.breaker_cooldown_seconds = max(0.001, float(breaker_cooldown_seconds))
        self._clock = clock
        self._states: dict[str, _State] = {}
        self._lock = threading.RLock()

    def _state(self, name: str) -> _State:
        with self._lock:
            return self._states.setdefault(name, _State())

    def circuit_state(self, name: str) -> str:
        with self._lock:
            state = self._states.setdefault(name, _State())
            opened = state.circuit_opened_at_monotonic
            if opened is None:
                return "closed"
            if self._clock() - opened >= self.breaker_cooldown_seconds:
                return "half_open"
            return "open"

    def operation_allowed(self, name: str) -> bool:
        return self.circuit_state(name) != "open"

    def record_success(
        self,
        name: str,
        *,
        diagnostics: dict[str, Any] | None = None,
    ) -> None:
        with self._lock:
            state = self._states.setdefault(name, _State())
            state.last_success_at = utc_now_iso()
            state.last_failure_kind = None
            state.consecutive_timeouts = 0
            state.circuit_opened_at_monotonic = None
            state.circuit_opened_at = None
            if diagnostics is not None:
                state.diagnostics = dict(diagnostics)

    def record_failure(
        self,
        name: str,
        *,
        kind: str,
        diagnostics: dict[str, Any] | None = None,
    ) -> None:
        now = utc_now_iso()
        with self._lock:
            state = self._states.setdefault(name, _State())
            state.last_failure_at = now
            state.last_failure_kind = str(kind)
            if kind == "timeout":
                state.timeout_count += 1
                state.consecutive_timeouts += 1
                if state.consecutive_timeouts >= self.breaker_timeout_threshold:
                    state.circuit_opened_at_monotonic = self._clock()
                    state.circuit_opened_at = now
            else:
                state.error_count += 1
                state.consecutive_timeouts = 0
            if diagnostics is not None:
                state.diagnostics = dict(diagnostics)

    def _entry(
        self,
        name: str,
        *,
        available: bool,
        provider: str,
        probe_state: str | None,
        bounded_timeout_ms: int,
        diagnostics: dict[str, Any] | None,
        generation_id: str | None,
    ) -> dict[str, Any]:
        with self._lock:
            state = self._states.setdefault(name, _State())
            circuit = self.circuit_state(name)
            if not available:
                runtime_state = "unknown"
            elif circuit == "open":
                runtime_state = "unhealthy"
            elif probe_state is not None:
                runtime_state = probe_state
            elif state.last_failure_kind is not None:
                runtime_state = "degraded"
            elif state.last_success_at is not None:
                runtime_state = "responsive"
            else:
                runtime_state = "unknown"
            if runtime_state not in RUNTIME_STATES:
                raise ValueError(f"invalid runtime state {runtime_state!r}")
            merged_diagnostics = (
                dict(diagnostics)
                if diagnostics is not None
                else dict(state.diagnostics or {})
            )
            return {
                "available": bool(available),
                "state": runtime_state,
                "provider": str(provider),
                "last_success_at": state.last_success_at,
                "last_failure_at": state.last_failure_at,
                "last_failure_kind": state.last_failure_kind,
                "timeout_count": state.timeout_count,
                "error_count": state.error_count,
                "bounded_operation_timeout_ms": int(bounded_timeout_ms),
                "circuit": {
                    "state": circuit,
                    "timeout_threshold": self.breaker_timeout_threshold,
                    "consecutive_timeouts": state.consecutive_timeouts,
                    "opened_at": state.circuit_opened_at,
                    "cooldown_ms": int(self.breaker_cooldown_seconds * 1000),
                },
                "generation": {
                    "executor_process_id": os.getpid(),
                    "operations_generation_id": generation_id,
                },
                "diagnostics": merged_diagnostics,
            }

    def probe(
        self,
        name: str,
        *,
        available: bool,
        provider: str,
        probe: Callable[[CancellationToken, float], dict[str, Any]] | None,
        parent_cancellation: CancellationToken,
        timeout_seconds: float,
        generation_id: str | None,
        passive_diagnostics: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        timeout = max(0.001, min(float(timeout_seconds), self.operation_timeout_seconds))
        timeout_ms = max(1, int(timeout * 1000))
        parent_cancellation.raise_if_cancelled()
        if not available:
            return self._entry(
                name,
                available=False,
                provider=provider,
                probe_state="unknown",
                bounded_timeout_ms=timeout_ms,
                diagnostics=passive_diagnostics,
                generation_id=generation_id,
            )
        if probe is None:
            return self._entry(
                name,
                available=True,
                provider=provider,
                probe_state=None,
                bounded_timeout_ms=timeout_ms,
                diagnostics=passive_diagnostics,
                generation_id=generation_id,
            )
        if not self.operation_allowed(name):
            return self._entry(
                name,
                available=True,
                provider=provider,
                probe_state="unhealthy",
                bounded_timeout_ms=timeout_ms,
                diagnostics=passive_diagnostics,
                generation_id=generation_id,
            )

        child = CancellationToken()
        deadline = self._clock() + timeout
        try:
            diagnostics = run_bounded(
                lambda: probe(child, deadline),
                timeout_seconds=timeout,
                cancellation=child,
                label=f"runtime health probe {name}",
            )
            parent_cancellation.raise_if_cancelled()
            self.record_success(name, diagnostics=diagnostics)
            return self._entry(
                name,
                available=True,
                provider=provider,
                probe_state="responsive",
                bounded_timeout_ms=timeout_ms,
                diagnostics=diagnostics,
                generation_id=generation_id,
            )
        except OperationTimeoutError:
            self.record_failure(name, kind="timeout", diagnostics=passive_diagnostics)
            return self._entry(
                name,
                available=True,
                provider=provider,
                probe_state="degraded",
                bounded_timeout_ms=timeout_ms,
                diagnostics=passive_diagnostics,
                generation_id=generation_id,
            )
        except OperationCancelledError:
            parent_cancellation.raise_if_cancelled()
            self.record_failure(name, kind="cancelled", diagnostics=passive_diagnostics)
            return self._entry(
                name,
                available=True,
                provider=provider,
                probe_state="degraded",
                bounded_timeout_ms=timeout_ms,
                diagnostics=passive_diagnostics,
                generation_id=generation_id,
            )
        except Exception as exc:
            self.record_failure(
                name,
                kind=type(exc).__name__,
                diagnostics=passive_diagnostics,
            )
            return self._entry(
                name,
                available=True,
                provider=provider,
                probe_state="degraded",
                bounded_timeout_ms=timeout_ms,
                diagnostics=passive_diagnostics,
                generation_id=generation_id,
            )



def probe_outcome_journal_integrity(
    journal: OutcomeJournal,
    *,
    max_bytes: int = 2 * 1024 * 1024,
    cancellation: CancellationToken | None = None,
) -> dict[str, Any]:
    """Read-only bounded validation using the frozen journal's own scanner.

    Size is checked while holding the same journal lock used by the producer.
    The subsequent frozen scan therefore cannot grow past the admitted bound.
    No repair, append, truncate, or replay decision is performed here.
    """
    token = cancellation or CancellationToken()
    token.raise_if_cancelled()
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    path = journal.path
    lock = getattr(journal, "_lock", None)
    scanner = getattr(journal, "_scan_locked", None)
    if lock is None or not callable(scanner):
        raise RuntimeError("outcome journal bounded scanner unavailable")
    with lock:
        token.raise_if_cancelled()
        if path.exists():
            size = path.stat().st_size
            token.raise_if_cancelled()
            if size > max_bytes:
                return {
                    "configured": True,
                    "integrity": "unknown",
                    "reason": "size_limit_exceeded",
                    "bytes_checked": 0,
                    "record_count": None,
                    "journal_sha256": None,
                    "corruption": None,
                    "bounded": True,
                    "max_bytes": max_bytes,
                }
        else:
            size = 0
        scan = scanner()
        token.raise_if_cancelled()
    corruption = getattr(scan, "corruption", None)
    corruption_payload = (
        None
        if corruption is None
        else {
            "kind": corruption.kind,
            "line_number": corruption.line_number,
            "byte_offset": corruption.byte_offset,
            "safe_prefix_bytes": corruption.safe_prefix_bytes,
        }
    )
    return {
        "configured": True,
        "integrity": "healthy" if corruption_payload is None else "corrupt",
        "reason": "validated" if corruption_payload is None else "integrity_failure",
        "bytes_checked": size,
        "record_count": len(scan.records),
        "journal_sha256": scan.journal_sha256,
        "corruption": corruption_payload,
        "bounded": True,
        "max_bytes": max_bytes,
    }

def validate_runtime_health(payload: Any) -> None:
    if not isinstance(payload, dict):
        raise ValueError("runtime health must be an object")
    required = {
        "contract_version",
        "observed_at",
        "complete",
        "probe_budget_ms",
        "elapsed_ms",
        "generation",
        "adapters",
        "outcome_journal",
        "summary",
    }
    if set(payload) != required:
        raise ValueError("runtime health top-level keys mismatch")
    if payload["contract_version"] != CONTRACT_VERSION:
        raise ValueError("runtime health contract_version mismatch")
    if not isinstance(payload["complete"], bool):
        raise ValueError("runtime health complete must be boolean")
    for key in ("probe_budget_ms", "elapsed_ms"):
        value = payload[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"runtime health {key} must be nonnegative integer")
    generation = payload["generation"]
    if not isinstance(generation, dict) or set(generation) != {
        "executor_process_id",
        "operations_generation_id",
    }:
        raise ValueError("runtime health generation mismatch")
    if isinstance(generation["executor_process_id"], bool) or not isinstance(
        generation["executor_process_id"], int
    ):
        raise ValueError("invalid executor_process_id")
    adapters = payload["adapters"]
    if not isinstance(adapters, dict):
        raise ValueError("runtime health adapters must be an object")
    required_adapters = {
        "uia",
        "screenshot",
        "windows",
        "shell",
        "clipboard",
        "input",
        "outcome_journal",
        "search",
        "process",
    }
    if not required_adapters <= set(adapters):
        raise ValueError("runtime health required adapters missing")
    for name, entry in adapters.items():
        if not isinstance(entry, dict):
            raise ValueError(f"runtime health adapter {name} must be an object")
        expected = {
            "available",
            "state",
            "provider",
            "last_success_at",
            "last_failure_at",
            "last_failure_kind",
            "timeout_count",
            "error_count",
            "bounded_operation_timeout_ms",
            "circuit",
            "generation",
            "diagnostics",
        }
        if set(entry) != expected:
            raise ValueError(f"runtime health adapter {name} keys mismatch")
        if not isinstance(entry["available"], bool) or entry["state"] not in RUNTIME_STATES:
            raise ValueError(f"invalid runtime health adapter {name}")
        for counter in ("timeout_count", "error_count", "bounded_operation_timeout_ms"):
            value = entry[counter]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"invalid {name}.{counter}")
        circuit = entry["circuit"]
        if not isinstance(circuit, dict) or circuit.get("state") not in {
            "closed",
            "open",
            "half_open",
        }:
            raise ValueError(f"invalid {name} circuit")
        if not isinstance(entry["diagnostics"], dict):
            raise ValueError(f"invalid {name} diagnostics")
    journal = payload["outcome_journal"]
    if not isinstance(journal, dict) or not isinstance(journal.get("configured"), bool):
        raise ValueError("invalid runtime health outcome_journal")
    if journal.get("integrity") not in {"healthy", "corrupt", "unknown", "unconfigured"}:
        raise ValueError("invalid outcome journal integrity state")
    summary = payload["summary"]
    if not isinstance(summary, dict) or set(summary) != {
        "responsive",
        "degraded",
        "unhealthy",
        "unknown",
    }:
        raise ValueError("invalid runtime health summary")
