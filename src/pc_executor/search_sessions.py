from __future__ import annotations

import json
import os
import threading
import time
from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from .cancellation import CancellationToken
from .errors import OperationCancelledError, OperationTimeoutError
from .safety import SafetyViolation


SEARCH_SESSION_VERSION = "pc_executor.search_session.v1"
DEFAULT_SEARCH_RETENTION_SECONDS = 300.0
DEFAULT_SEARCH_WORKERS = 4
MAX_SEARCH_SESSIONS = 32
MAX_RETAINED_SEARCH_SESSIONS = 32
MAX_SEARCH_RESULTS = 500
MAX_SEARCH_TIMEOUT_MS = 120_000
DEFAULT_SEARCH_TIMEOUT_MS = 30_000
MAX_SEARCH_PAGE_LENGTH = 500
MAX_SEARCH_CONTEXT_LINES = 20
MAX_SEARCH_CONTEXT_CHARS = 1024
MAX_SEARCH_STALE_TOMBSTONES = 128
MAX_SEARCH_EXPIRED_TOMBSTONES = 128


def _utc_now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


@dataclass
class SearchSession:
    search_id: str
    generation_id: str
    search_type: str
    pattern: str
    path: str
    literal_search: bool
    ignore_case: bool
    context_lines: int
    include_hidden: bool
    max_results: int
    timeout_ms: int
    started_at: str
    started_monotonic: float
    cancellation: CancellationToken = field(default_factory=CancellationToken)
    results: list[dict[str, Any]] = field(default_factory=list)
    status: str = "running"
    stop_requested: bool = False
    finished_at: str | None = None
    finished_monotonic: float | None = None
    error_kind: str | None = None
    future: Future[None] | None = None

    @property
    def deadline_monotonic(self) -> float:
        return self.started_monotonic + (self.timeout_ms / 1000.0)

    def checkpoint(self) -> None:
        self.cancellation.raise_if_cancelled()
        if time.monotonic() >= self.deadline_monotonic:
            raise OperationTimeoutError("search session timed out")


SearchRunner = Callable[
    [SearchSession, Callable[[dict[str, Any]], bool]], str
]


class SearchSessionManager:
    def __init__(
        self,
        state_path: str | Path,
        *,
        generation_id: str,
        retention_seconds: float = DEFAULT_SEARCH_RETENTION_SECONDS,
        max_workers: int = DEFAULT_SEARCH_WORKERS,
    ) -> None:
        if retention_seconds <= 0:
            raise ValueError("search retention must be positive")
        if max_workers <= 0 or max_workers > DEFAULT_SEARCH_WORKERS:
            raise ValueError(
                f"search max_workers must be between 1 and {DEFAULT_SEARCH_WORKERS}"
            )
        self.state_path = Path(state_path)
        self.generation_id = generation_id
        self.retention_seconds = float(retention_seconds)
        self.lock = threading.RLock()
        self.sessions: dict[str, SearchSession] = {}
        self.stale: dict[str, dict[str, Any]] = {}
        self.expired: deque[str] = deque(maxlen=MAX_SEARCH_EXPIRED_TOMBSTONES)
        self.pool = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="pc-search",
        )
        self._load_stale()

    def _load_stale(self) -> None:
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except (OSError, UnicodeError, json.JSONDecodeError):
            return
        if raw.get("version") != SEARCH_SESSION_VERSION:
            return
        prior = list(raw.get("sessions") or []) + list(raw.get("stale") or [])
        for item in prior[-MAX_SEARCH_STALE_TOMBSTONES:]:
            search_id = item.get("search_id")
            generation_id = item.get("generation_id")
            if not isinstance(search_id, str) or not search_id:
                continue
            if generation_id == self.generation_id:
                continue
            self.stale[search_id] = {
                "search_id": search_id,
                "generation_id": generation_id,
                "status": "stale_after_restart",
            }

    def _persist_locked(self) -> None:
        sessions = [
            {
                "search_id": item.search_id,
                "generation_id": item.generation_id,
                "search_type": item.search_type,
                "pattern": item.pattern,
                "status": item.status,
                "started_at": item.started_at,
                "finished_at": item.finished_at,
                "result_count": len(item.results),
            }
            for _, item in sorted(self.sessions.items())
        ]
        stale = [
            dict(item)
            for _, item in sorted(self.stale.items())[
                -MAX_SEARCH_STALE_TOMBSTONES:
            ]
        ]
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        with temp.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(
                {
                    "version": SEARCH_SESSION_VERSION,
                    "generation_id": self.generation_id,
                    "sessions": sessions,
                    "stale": stale,
                },
                handle,
                sort_keys=True,
                indent=2,
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, self.state_path)

    def _gc_locked(self) -> None:
        now = time.monotonic()
        expired_ids = [
            search_id
            for search_id, item in self.sessions.items()
            if item.finished_monotonic is not None
            and now - item.finished_monotonic >= self.retention_seconds
        ]
        if not expired_ids:
            return
        for search_id in expired_ids:
            self.sessions.pop(search_id, None)
            self.expired.append(search_id)
        self._persist_locked()

    def _get_locked(self, search_id: str) -> SearchSession:
        self._gc_locked()
        item = self.sessions.get(search_id)
        if item is not None:
            return item
        if search_id in self.stale:
            raise SafetyViolation(
                "search handle belongs to a previous executor/device generation"
            )
        if search_id in self.expired:
            raise SafetyViolation("search handle expired after retention window")
        raise SafetyViolation(f"unknown search handle: {search_id}")

    def assert_current(self, search_id: str) -> None:
        with self.lock:
            self._get_locked(search_id)

    def start(
        self,
        *,
        search_type: str,
        pattern: str,
        path: str,
        literal_search: bool,
        ignore_case: bool,
        context_lines: int,
        include_hidden: bool,
        max_results: int,
        timeout_ms: int,
        runner: SearchRunner,
    ) -> dict[str, Any]:
        with self.lock:
            self._gc_locked()
            if len(self.sessions) >= MAX_RETAINED_SEARCH_SESSIONS:
                raise SafetyViolation(
                    "too many retained search sessions; wait for retention expiry"
                )
            active = sum(
                1 for item in self.sessions.values() if item.status == "running"
            )
            if active >= MAX_SEARCH_SESSIONS:
                raise SafetyViolation("too many active search sessions")
            item = SearchSession(
                search_id=f"search:{uuid4()}",
                generation_id=self.generation_id,
                search_type=search_type,
                pattern=pattern,
                path=path,
                literal_search=literal_search,
                ignore_case=ignore_case,
                context_lines=context_lines,
                include_hidden=include_hidden,
                max_results=max_results,
                timeout_ms=timeout_ms,
                started_at=_utc_now_iso(),
                started_monotonic=time.monotonic(),
            )
            self.sessions[item.search_id] = item
            self._persist_locked()
            item.future = self.pool.submit(self._run, item, runner)
            return self._summary_locked(item)

    def _run(self, item: SearchSession, runner: SearchRunner) -> None:
        def emit(result: dict[str, Any]) -> bool:
            with self.lock:
                current = self.sessions.get(item.search_id)
                if current is not item or item.status != "running":
                    return False
                if item.stop_requested or item.cancellation.cancelled:
                    return False
                if len(item.results) >= item.max_results:
                    return False
                item.results.append(dict(result))
                return len(item.results) < item.max_results

        terminal = "completed"
        error_kind = None
        try:
            terminal = runner(item, emit)
        except OperationTimeoutError:
            terminal = "timed_out"
        except OperationCancelledError:
            terminal = "cancelled"
        except Exception as exc:
            terminal = "failed"
            error_kind = type(exc).__name__
        with self.lock:
            if item.status == "running":
                if item.stop_requested and terminal not in {"failed", "timed_out"}:
                    terminal = "cancelled"
                item.status = terminal
                item.error_kind = error_kind
                item.finished_at = _utc_now_iso()
                item.finished_monotonic = time.monotonic()
                self._persist_locked()

    def stop(self, search_id: str) -> dict[str, Any]:
        with self.lock:
            item = self._get_locked(search_id)
            already_finished = item.status != "running"
            if not already_finished:
                item.stop_requested = True
                item.cancellation.cancel()
            summary = self._summary_locked(item)
            summary["already_finished"] = already_finished
            summary["stop_requested"] = not already_finished
            return summary

    def read(
        self,
        search_id: str,
        *,
        offset: int,
        length: int,
    ) -> dict[str, Any]:
        with self.lock:
            item = self._get_locked(search_id)
            total = len(item.results)
            if offset < 0:
                requested = min(-offset, total)
                resolved_offset = total - requested
                page = item.results[resolved_offset:]
            else:
                resolved_offset = min(offset, total)
                page = item.results[resolved_offset : resolved_offset + length]
            summary = self._summary_locked(item)
            summary.update(
                {
                    "offset": resolved_offset,
                    "requested_offset": offset,
                    "length": None if offset < 0 else length,
                    "results": [dict(value) for value in page],
                    "returned_count": len(page),
                    "next_offset": resolved_offset + len(page),
                    "has_more": (
                        resolved_offset + len(page) < total
                        or item.status == "running"
                    ),
                }
            )
            return summary

    def list(self) -> dict[str, Any]:
        with self.lock:
            self._gc_locked()
            items = [
                self._summary_locked(item)
                for item in sorted(
                    self.sessions.values(),
                    key=lambda value: (value.started_monotonic, value.search_id),
                )
            ]
            return {
                "searches": items,
                "count": len(items),
                "generation_id": self.generation_id,
                "retention_seconds": self.retention_seconds,
            }

    def _summary_locked(self, item: SearchSession) -> dict[str, Any]:
        end = item.finished_monotonic or time.monotonic()
        runtime_ms = max(0, int((end - item.started_monotonic) * 1000))
        return {
            "search_id": item.search_id,
            "generation_id": item.generation_id,
            "search_type": item.search_type,
            "pattern": item.pattern,
            "status": item.status,
            "runtime_ms": runtime_ms,
            "result_count": len(item.results),
            "max_results": item.max_results,
            "timeout_ms": item.timeout_ms,
            "started_at": item.started_at,
            "finished_at": item.finished_at,
            "error_kind": item.error_kind,
        }

    def shutdown(self) -> None:
        with self.lock:
            for item in self.sessions.values():
                if item.status == "running":
                    item.stop_requested = True
                    item.cancellation.cancel()
        self.pool.shutdown(wait=False, cancel_futures=True)
