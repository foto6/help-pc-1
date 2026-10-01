from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterable
from uuid import uuid4


PROGRESS_VERSION = "pc_relay.progress.v1"
LIVENESS_VERSION = "pc_relay.liveness_probe.v1"
SOURCE_REPOSITORY = "foto6/help-pc-1"
MAX_ERROR_CHARS = 512
MAX_BATCH_PER_CYCLE = 64
DEFAULT_STALL_SECONDS = 15.0
_PROGRESS_STATES = {
    "starting",
    "publishing_pending",
    "fetching",
    "rebasing",
    "scanning",
    "executing",
    "publishing",
    "sleeping",
    "recovering",
    "error",
    "stopped",
}
_ERROR_CLASSIFICATIONS = {
    "none",
    "transient_network",
    "transient_git_lock",
    "remote_advanced",
    "rebase_conflict",
    "git_auth_or_permission",
    "checkout_dirty",
    "request_invalid",
    "executor_error",
    "publish_error",
    "unknown",
}


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(
        f".{path.name}.tmp.{os.getpid()}.{threading.get_ident()}.{uuid4().hex}"
    )
    try:
        with tmp.open("w", encoding="utf-8", newline="\n") as fh:
            json.dump(payload, fh, ensure_ascii=False, sort_keys=True, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def _bounded_text(value: object, limit: int = MAX_ERROR_CHARS) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    # Git diagnostics may echo credential-bearing remotes. Keep health safe for
    # read-only inspection without publishing URL userinfo or secret-like values.
    text = re.sub(
        r"([A-Za-z][A-Za-z0-9+.-]*://)[^/@\\s]+@",
        r"\\1<redacted>@",
        text,
    )
    text = re.sub(
        r"(?i)\\b(token|password|authorization|credential)\\s*[:=]\\s*[^\\s]+",
        r"\\1=<redacted>",
        text,
    )
    return text[:limit]


def classify_error(
    exc_or_text: object,
    *,
    operation: str,
    returncode: int | None = None,
) -> dict[str, Any]:
    text = _bounded_text(exc_or_text)
    folded = text.casefold()
    if any(
        marker in folded
        for marker in (
            "could not resolve host",
            "failed to connect",
            "connection timed out",
            "connection reset",
            "network is unreachable",
            "remote end hung up",
            "unable to access",
            "tls",
            "temporarily unavailable",
        )
    ):
        classification, retryable = "transient_network", True
    elif any(marker in folded for marker in ("index.lock", "cannot lock ref", "another git process")):
        classification, retryable = "transient_git_lock", True
    elif any(
        marker in folded
        for marker in (
            "non-fast-forward",
            "fetch first",
            "rejected",
            "remote contains work",
        )
    ) and operation == "push":
        classification, retryable = "remote_advanced", True
    elif any(marker in folded for marker in ("conflict", "could not apply")) and operation == "rebase":
        classification, retryable = "rebase_conflict", False
    elif any(
        marker in folded
        for marker in (
            "authentication failed",
            "permission denied",
            "repository not found",
            "could not read username",
        )
    ):
        classification, retryable = "git_auth_or_permission", False
    else:
        classification, retryable = "unknown", False
    return {
        "classification": classification,
        "retryable": retryable,
        "operation": operation,
        "returncode": returncode,
        "message": text,
    }


class RelayProgress:
    def __init__(
        self,
        path: Path,
        *,
        branch: str,
        startup_head: str,
        relay_script_sha256: str,
        poll_seconds: float,
        clock: Callable[[], float] = time.time,
        pid: int | None = None,
        instance_id: str | None = None,
        generation_id: str | None = None,
    ) -> None:
        self.path = Path(path)
        self.branch = branch
        self.clock = clock
        self.poll_seconds = float(poll_seconds)
        now = self.clock()
        self._record: dict[str, Any] = {
            "contract_version": PROGRESS_VERSION,
            "source": {
                "repository": SOURCE_REPOSITORY,
                "branch": branch,
                "startup_head": startup_head,
                "relay_script_sha256": relay_script_sha256,
            },
            "process": {
                "pid": int(os.getpid() if pid is None else pid),
                "started_at_unix": now,
                "instance_id": instance_id or str(uuid4()),
            },
            "loop_generation_id": generation_id or str(uuid4()),
            "loop_epoch": 0,
            "last_fetch_success": None,
            "last_request_observed": None,
            "last_result_committed": None,
            "last_successful_cycle_at_unix": None,
            "consecutive_cycle_failures": 0,
            "queue": {
                "pending_count": 0,
                "oldest_pending_request_id": None,
                "oldest_pending_age_seconds": None,
                "last_progress_at_unix": now,
            },
            "current_cycle": {
                "state": "starting",
                "started_at_unix": now,
                "updated_at_unix": now,
                "deadline_at_unix": None,
            },
            "last_error": None,
            "limits": {
                "max_batch_per_cycle": MAX_BATCH_PER_CYCLE,
                "max_error_chars": MAX_ERROR_CHARS,
                "poll_seconds": self.poll_seconds,
            },
            "recorded_at_unix": now,
        }
        self.write()

    def _touch(
        self,
        state: str | None = None,
        *,
        deadline_at_unix: float | None = None,
    ) -> None:
        now = self.clock()
        if state is not None:
            if state not in _PROGRESS_STATES:
                raise ValueError(f"invalid relay progress state: {state}")
            if self._record["current_cycle"]["state"] != state:
                self._record["current_cycle"]["started_at_unix"] = now
            self._record["current_cycle"]["state"] = state
        self._record["current_cycle"]["updated_at_unix"] = now
        self._record["current_cycle"]["deadline_at_unix"] = deadline_at_unix
        self._record["recorded_at_unix"] = now
        self.write()

    def start_cycle(self) -> None:
        self._record["loop_epoch"] += 1
        self._record["current_cycle"]["started_at_unix"] = self.clock()
        self._touch("publishing_pending")

    def state(self, value: str, *, deadline_at_unix: float | None = None) -> None:
        self._touch(value, deadline_at_unix=deadline_at_unix)

    def fetch_success(self, *, remote_head: str | None = None) -> None:
        self._record["last_fetch_success"] = {
            "at_unix": self.clock(),
            "remote_head": remote_head,
        }
        self._touch("rebasing")

    def request_observed(
        self,
        request_id: str,
        *,
        action: str | None,
        timeout_ms: int | None,
    ) -> None:
        now = self.clock()
        previous = self._record.get("last_request_observed")
        if not isinstance(previous, dict) or previous.get("id") != request_id:
            self._record["last_request_observed"] = {
                "id": request_id,
                "action": action,
                "at_unix": now,
            }
        deadline = (
            None
            if timeout_ms is None
            else now + max(0.1, float(timeout_ms) / 1000.0)
        )
        self._touch("executing", deadline_at_unix=deadline)

    def result_committed(self, request_id: str, *, commit_sha: str | None) -> None:
        now = self.clock()
        self._record["last_result_committed"] = {
            "id": request_id,
            "at_unix": now,
            "commit_sha": commit_sha,
        }
        self._record["queue"]["last_progress_at_unix"] = now
        self._touch("publishing")

    def queue_metrics(
        self,
        *,
        pending_count: int,
        oldest_pending_request_id: str | None,
        oldest_pending_age_seconds: float | None,
    ) -> None:
        self._record["queue"].update(
            {
                "pending_count": max(0, int(pending_count)),
                "oldest_pending_request_id": oldest_pending_request_id,
                "oldest_pending_age_seconds": (
                    None
                    if oldest_pending_age_seconds is None
                    else max(0.0, float(oldest_pending_age_seconds))
                ),
            }
        )
        self._touch("scanning")

    def cycle_success(self) -> None:
        now = self.clock()
        self._record["last_successful_cycle_at_unix"] = now
        self._record["consecutive_cycle_failures"] = 0
        self._record["last_error"] = None
        self._touch("sleeping")

    def cycle_failure(self, error: dict[str, Any]) -> None:
        classification = str(error.get("classification") or "unknown")
        if classification not in _ERROR_CLASSIFICATIONS:
            classification = "unknown"
        self._record["consecutive_cycle_failures"] += 1
        self._record["last_error"] = {
            "classification": classification,
            "retryable": bool(error.get("retryable", False)),
            "operation": _bounded_text(error.get("operation") or "cycle", 64),
            "returncode": error.get("returncode"),
            "message": _bounded_text(error.get("message") or "", MAX_ERROR_CHARS),
            "at_unix": self.clock(),
        }
        self._touch("error")

    def snapshot(self) -> dict[str, Any]:
        return json.loads(json.dumps(self._record))

    def write(self) -> None:
        validate_progress(self._record)
        _atomic_json(self.path, self._record)


def validate_progress(payload: Any) -> None:
    if not isinstance(payload, dict):
        raise ValueError("relay progress must be an object")
    required = {
        "contract_version",
        "source",
        "process",
        "loop_generation_id",
        "loop_epoch",
        "last_fetch_success",
        "last_request_observed",
        "last_result_committed",
        "last_successful_cycle_at_unix",
        "consecutive_cycle_failures",
        "queue",
        "current_cycle",
        "last_error",
        "limits",
        "recorded_at_unix",
    }
    if set(payload) != required:
        raise ValueError("relay progress top-level keys mismatch")
    if payload["contract_version"] != PROGRESS_VERSION:
        raise ValueError("relay progress contract version mismatch")
    source = payload["source"]
    if not isinstance(source, dict) or set(source) != {
        "repository",
        "branch",
        "startup_head",
        "relay_script_sha256",
    }:
        raise ValueError("relay progress source mismatch")
    if source["repository"] != SOURCE_REPOSITORY:
        raise ValueError("relay progress source repository mismatch")
    process = payload["process"]
    if not isinstance(process, dict) or set(process) != {
        "pid",
        "started_at_unix",
        "instance_id",
    }:
        raise ValueError("relay progress process mismatch")
    if isinstance(process["pid"], bool) or not isinstance(process["pid"], int) or process["pid"] <= 0:
        raise ValueError("relay progress pid invalid")
    if not isinstance(payload["loop_generation_id"], str) or not payload["loop_generation_id"]:
        raise ValueError("relay progress generation invalid")
    if isinstance(payload["loop_epoch"], bool) or not isinstance(payload["loop_epoch"], int) or payload["loop_epoch"] < 0:
        raise ValueError("relay progress epoch invalid")
    if (
        isinstance(payload["consecutive_cycle_failures"], bool)
        or not isinstance(payload["consecutive_cycle_failures"], int)
        or payload["consecutive_cycle_failures"] < 0
    ):
        raise ValueError("relay progress consecutive failures invalid")
    queue = payload["queue"]
    if not isinstance(queue, dict) or set(queue) != {
        "pending_count",
        "oldest_pending_request_id",
        "oldest_pending_age_seconds",
        "last_progress_at_unix",
    }:
        raise ValueError("relay progress queue mismatch")
    if isinstance(queue["pending_count"], bool) or not isinstance(queue["pending_count"], int) or queue["pending_count"] < 0:
        raise ValueError("relay progress pending count invalid")
    current = payload["current_cycle"]
    if not isinstance(current, dict) or set(current) != {
        "state",
        "started_at_unix",
        "updated_at_unix",
        "deadline_at_unix",
    } or current["state"] not in _PROGRESS_STATES:
        raise ValueError("relay progress current cycle invalid")
    error = payload["last_error"]
    if error is not None:
        if not isinstance(error, dict) or error.get("classification") not in _ERROR_CLASSIFICATIONS:
            raise ValueError("relay progress error invalid")
        if len(str(error.get("message", ""))) > MAX_ERROR_CHARS:
            raise ValueError("relay progress error message unbounded")


def load_progress(path: Path) -> dict[str, Any] | None:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    validate_progress(raw)
    return raw


def liveness_probe(
    progress: dict[str, Any] | None,
    *,
    observed_pids: Iterable[int] | None = None,
    expected_pid: int | None = None,
    now: float | None = None,
    stall_seconds: float = DEFAULT_STALL_SECONDS,
) -> dict[str, Any]:
    current_time = time.time() if now is None else float(now)
    stall_after = max(1.0, float(stall_seconds))
    pids = None if observed_pids is None else sorted({int(pid) for pid in observed_pids if int(pid) > 0})

    if progress is None:
        state = "unknown" if pids is None else ("no_process" if not pids else "alive_unknown")
        return {
            "contract_version": LIVENESS_VERSION,
            "state": state,
            "reason": "progress_record_missing",
            "observed_pids": pids,
            "progress_age_seconds": None,
            "queue_progress_age_seconds": None,
            "pending_count": None,
            "loop_generation_id": None,
            "loop_epoch": None,
            "process_pid": None,
            "last_error_classification": None,
        }

    validate_progress(progress)
    process_pid = int(progress["process"]["pid"])
    record_age = max(0.0, current_time - float(progress["recorded_at_unix"]))
    queue = progress["queue"]
    queue_progress_age = max(0.0, current_time - float(queue["last_progress_at_unix"]))
    pending = int(queue["pending_count"])
    current_cycle = progress["current_cycle"]
    deadline = current_cycle["deadline_at_unix"]
    within_execution_deadline = (
        current_cycle["state"] == "executing"
        and isinstance(deadline, (int, float))
        and current_time <= float(deadline) + max(1.0, float(progress["limits"]["poll_seconds"]))
    )

    if pids is not None:
        if len(pids) > 1:
            state, reason = "duplicate_processes_ambiguous", "multiple_matching_relay_processes"
        elif not pids:
            state, reason = "stale_record_no_process", "progress_record_exists_but_process_absent"
        elif expected_pid is not None and pids[0] != int(expected_pid):
            state, reason = "alive_ambiguous_identity", "observed_pid_does_not_match_expected_pid"
        elif pids[0] != process_pid:
            state, reason = "alive_ambiguous_identity", "progress_pid_does_not_match_observed_process"
        elif within_execution_deadline:
            state, reason = "healthy_progressing", "bounded_request_execution_in_progress"
        elif record_age > stall_after:
            state, reason = "alive_stalled", "progress_record_not_updating"
        elif pending > 0 and queue_progress_age > stall_after:
            state, reason = "alive_stalled", "pending_queue_has_no_result_progress"
        else:
            state, reason = "healthy_progressing", "cycle_and_queue_progress_within_bound"
    else:
        if within_execution_deadline:
            state, reason = "progress_record_current", "bounded_request_execution_in_progress"
        elif record_age > stall_after or (pending > 0 and queue_progress_age > stall_after):
            state, reason = "stalled_record", "progress_age_exceeds_bound"
        else:
            state, reason = "progress_record_current", "progress_age_within_bound"

    return {
        "contract_version": LIVENESS_VERSION,
        "state": state,
        "reason": reason,
        "observed_pids": pids,
        "progress_age_seconds": round(record_age, 3),
        "queue_progress_age_seconds": round(queue_progress_age, 3),
        "pending_count": pending,
        "loop_generation_id": progress["loop_generation_id"],
        "loop_epoch": progress["loop_epoch"],
        "process_pid": process_pid,
        "last_error_classification": (
            None
            if progress["last_error"] is None
            else progress["last_error"]["classification"]
        ),
    }
