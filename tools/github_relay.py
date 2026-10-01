from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable

from pc_executor.audit import JsonlAuditSink
from pc_executor.executor import Executor
from pc_executor.models import ActionRequest
from pc_executor.outcome_journal import OutcomeJournal
from pc_executor.safety import DEFAULT_SAFE_EXECUTABLES
from pc_executor.shell import SafeShellAdapter

REQUEST_VERSION = "pc_relay.request.v1"
RESULT_VERSION = "pc_relay.result.v1"
HEALTH_VERSION = "pc_relay.health.v1"
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
GIT_TIMEOUT_SECONDS = 30.0
DEFAULT_STALE_AFTER_SECONDS = 30.0
LONG_RUNNING_PHASE_STALE_AFTER_SECONDS = 150.0

READ_ONLY_ACTIONS = {
    "capabilities.get",
    "action.preflight",
    "outcome.lookup",
    "windows.list",
    "uia.snapshot",
    "uia.inspect",
    "screenshot.capture",
    "clipboard.get",
}
DEFAULT_ALLOWED_ACTIONS = READ_ONLY_ACTIONS | {
    "shell.run",
}

RELAY_SHELL_EXECUTABLES = set(DEFAULT_SAFE_EXECUTABLES) | {
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
    "cmd",
    "cmd.exe",
}


def _run_git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        text=True,
        capture_output=True,
        check=check,
        timeout=GIT_TIMEOUT_SECONDS,
    )


def _abort_stale_rebase(repo: Path) -> bool:
    """Abort a rebase left behind by this dedicated relay checkout."""
    for marker in ("rebase-merge", "rebase-apply"):
        probe = _run_git(repo, "rev-parse", "--git-path", marker, check=False)
        if probe.returncode != 0:
            continue
        raw = probe.stdout.strip()
        if not raw:
            continue
        marker_path = Path(raw)
        if not marker_path.is_absolute():
            marker_path = repo / marker_path
        if marker_path.exists():
            _run_git(repo, "rebase", "--abort", check=False)
            return True
    return False


def _rebase_onto_remote(repo: Path, branch: str) -> None:
    # A failed pull/rebase from an earlier cycle must never poison all future cycles.
    _abort_stale_rebase(repo)
    _run_git(repo, "fetch", "origin", branch)
    rebased = _run_git(repo, "rebase", f"origin/{branch}", check=False)
    if rebased.returncode == 0:
        return
    _run_git(repo, "rebase", "--abort", check=False)
    raise RuntimeError(
        "relay branch rebase failed; manual reconciliation required: "
        + (rebased.stderr.strip() or rebased.stdout.strip())
    )


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as fh:
        json.dump(payload, fh, ensure_ascii=False, sort_keys=True, indent=2)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _load_json(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("request/result JSON must be an object")
    return raw


def _git_head(repo: Path, ref: str = "HEAD") -> str | None:
    probe = _run_git(repo, "rev-parse", ref, check=False)
    if probe.returncode != 0:
        return None
    value = probe.stdout.strip()
    return value or None


def _bounded_error(value: object, limit: int = 512) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    text = re.sub(
        r"([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+@",
        r"\1<redacted>@",
        text,
    )
    text = re.sub(
        r"(?i)\b(token|password|authorization|credential)\s*[:=]\s*[^\s]+",
        r"\1=<redacted>",
        text,
    )
    return text[:limit]


def _git_head_relation(repo: Path, local_head: str | None, remote_head: str | None) -> str:
    if not local_head or not remote_head:
        return "unknown"
    if local_head == remote_head:
        return "equal"
    local_ancestor = _run_git(
        repo,
        "merge-base",
        "--is-ancestor",
        local_head,
        remote_head,
        check=False,
    )
    if local_ancestor.returncode == 0:
        return "local_behind_remote"
    remote_ancestor = _run_git(
        repo,
        "merge-base",
        "--is-ancestor",
        remote_head,
        local_head,
        check=False,
    )
    if remote_ancestor.returncode == 0:
        return "local_ahead_remote"
    return "diverged"


def _tree_queue_counts(repo: Path, ref: str) -> dict[str, int] | None:
    probe = _run_git(
        repo,
        "ls-tree",
        "-r",
        "--name-only",
        ref,
        "--",
        "relay/requests",
        "relay/results",
        check=False,
    )
    if probe.returncode != 0:
        return None
    request_names: set[str] = set()
    result_names: set[str] = set()
    for raw in probe.stdout.splitlines():
        path = raw.strip().replace("\\", "/")
        if path.startswith("relay/requests/") and path.endswith(".json"):
            request_names.add(Path(path).name)
        elif path.startswith("relay/results/") and path.endswith(".json"):
            result_names.add(Path(path).name)
    return {
        "request_count": len(request_names),
        "result_count": len(result_names),
        "backlog_count": len(request_names - result_names),
    }


def _parse_observed_processes(values: Iterable[str]) -> dict[str, Any]:
    rows: list[dict[str, int]] = []
    seen: set[int] = set()
    for raw in values:
        text = str(raw)
        if ":" not in text:
            raise ValueError("observed process must be PID:PARENTPID")
        pid_text, parent_text = text.split(":", 1)
        pid = int(pid_text)
        parent_pid = int(parent_text)
        if pid <= 0 or parent_pid < 0 or pid in seen:
            raise ValueError("observed process identities must be unique positive PIDs")
        seen.add(pid)
        rows.append({"pid": pid, "parent_pid": parent_pid})
    roots = sorted(
        row["pid"]
        for row in rows
        if row["parent_pid"] not in seen
    )
    return {
        "matching_pids": sorted(seen),
        "logical_roots": roots,
        "logical_process_count": len(roots),
    }


def classify_health_snapshot(
    snapshot: dict[str, Any] | None,
    *,
    now_unix: float,
    process_exists: bool,
    stale_after_seconds: float = DEFAULT_STALE_AFTER_SECONDS,
    logical_process_count: int = 1,
    health_pid_observed: bool = True,
    head_relation: str = "unknown",
    observed_remote_head: str | None = None,
    observed_remote_backlog_count: int | None = None,
) -> str:
    if logical_process_count > 1:
        return "DUPLICATE_AMBIGUOUS"
    if not process_exists:
        return "PROCESS_MISSING"
    if not snapshot:
        return "PROCESS_EXISTS"
    if snapshot.get("health_version") != HEALTH_VERSION:
        return "PROCESS_EXISTS"
    if snapshot.get("reconciliation_required") is True:
        return "RECONCILIATION_REQUIRED"
    if not health_pid_observed:
        return "PROCESS_EXISTS"
    try:
        updated_at = float(snapshot.get("updated_at_unix"))
    except (TypeError, ValueError):
        return "PROCESS_EXISTS"
    effective_stale_after = max(1.0, float(stale_after_seconds))
    if snapshot.get("phase") in {"execute_request", "reconcile_interrupted_side_effect"}:
        effective_stale_after = max(
            effective_stale_after,
            LONG_RUNNING_PHASE_STALE_AFTER_SECONDS,
        )
    updated_age = max(0.0, now_unix - updated_at)
    if updated_age > effective_stale_after:
        return "STALE"

    cycle_at = snapshot.get("last_cycle_completed_at_unix")
    try:
        cycle_age = (
            max(0.0, now_unix - float(cycle_at))
            if cycle_at is not None
            else max(0.0, now_unix - float(snapshot.get("started_at_unix", now_unix)))
        )
    except (TypeError, ValueError):
        cycle_age = effective_stale_after + 1.0

    sync_at = snapshot.get("last_sync_at_unix")
    try:
        sync_age = (
            max(0.0, now_unix - float(sync_at))
            if sync_at is not None
            else max(0.0, now_unix - float(snapshot.get("started_at_unix", now_unix)))
        )
    except (TypeError, ValueError):
        sync_age = effective_stale_after + 1.0

    if (
        head_relation in {"local_behind_remote", "diverged"}
        and sync_age > effective_stale_after
    ):
        return "STALE"
    if (
        observed_remote_head
        and snapshot.get("remote_head")
        and observed_remote_head != snapshot.get("remote_head")
        and cycle_age > effective_stale_after
    ):
        return "STALE"
    if observed_remote_backlog_count is not None:
        try:
            recorded_backlog = int(snapshot.get("backlog_count", 0))
        except (TypeError, ValueError):
            recorded_backlog = 0
        if (
            observed_remote_backlog_count > recorded_backlog
            and cycle_age > effective_stale_after
        ):
            return "STALE"
    if snapshot.get("status") == "healthy":
        return "HEALTHY"
    return "PROCESS_EXISTS"


def build_watchdog_status(
    repo: Path,
    *,
    snapshot: dict[str, Any] | None,
    observed_processes: Iterable[str],
    now_unix: float,
    stale_after_seconds: float = DEFAULT_STALE_AFTER_SECONDS,
) -> dict[str, Any]:
    process = _parse_observed_processes(observed_processes)
    local_head = _git_head(repo)
    branch = (
        snapshot.get("branch")
        if isinstance(snapshot, dict) and isinstance(snapshot.get("branch"), str)
        else "agent/pc-github-relay"
    )
    remote_ref = f"origin/{branch}"
    remote_head = _git_head(repo, remote_ref)
    relation = _git_head_relation(repo, local_head, remote_head)
    remote_counts = _tree_queue_counts(repo, remote_ref)
    health_pid = (
        int(snapshot["pid"])
        if isinstance(snapshot, dict)
        and isinstance(snapshot.get("pid"), int)
        and not isinstance(snapshot.get("pid"), bool)
        else None
    )
    matching_pids = process["matching_pids"]
    process_exists = bool(matching_pids)
    health_pid_observed = health_pid is not None and health_pid in matching_pids

    safe_snapshot = None
    if isinstance(snapshot, dict):
        safe_snapshot = dict(snapshot)
        if safe_snapshot.get("last_error") is not None:
            safe_snapshot["last_error"] = _bounded_error(safe_snapshot["last_error"])

    state = classify_health_snapshot(
        snapshot,
        now_unix=now_unix,
        process_exists=process_exists,
        stale_after_seconds=stale_after_seconds,
        logical_process_count=process["logical_process_count"],
        health_pid_observed=health_pid_observed,
        head_relation=relation,
        observed_remote_head=remote_head,
        observed_remote_backlog_count=(
            None if remote_counts is None else remote_counts["backlog_count"]
        ),
    )
    stale_reasons: list[str] = []
    if state == "STALE":
        try:
            updated_age = max(0.0, now_unix - float(snapshot["updated_at_unix"]))
        except Exception:
            updated_age = None
        if updated_age is None or updated_age > stale_after_seconds:
            stale_reasons.append("health_record_age_exceeded")
        if relation == "local_behind_remote":
            stale_reasons.append("local_head_behind_remote_tracking_head")
        if (
            isinstance(snapshot, dict)
            and remote_head
            and snapshot.get("remote_head")
            and remote_head != snapshot.get("remote_head")
        ):
            stale_reasons.append("remote_tracking_head_advanced_since_last_relay_sync")
        if (
            remote_counts is not None
            and isinstance(snapshot, dict)
            and remote_counts["backlog_count"] > int(snapshot.get("backlog_count", 0))
        ):
            stale_reasons.append("remote_backlog_advanced_without_completed_cycle")

    return {
        "status_version": "pc_relay.watchdog_status.v1",
        "state": state,
        "observed_at_unix": now_unix,
        "process": {
            **process,
            "health_pid": health_pid,
            "health_pid_observed": health_pid_observed,
        },
        "observations": {
            "local_head": local_head,
            "remote_tracking_head": remote_head,
            "head_relation": relation,
            "remote_tracking_queue": remote_counts,
            "remote_observation_source": "local_remote_tracking_ref_no_network",
        },
        "stale_reasons": stale_reasons,
        "health": safe_snapshot,
        "error": None,
        "recovery": {
            "automatic_restart": False,
            "automatic_kill": False,
            "automatic_side_effect_replay": False,
            "preserve_state_dir": ".pc-relay/state",
            "preserve_outcome_journal": ".pc-relay/outcomes.jsonl",
            "unknown_side_effect_requires_outcome_lookup": True,
        },
    }


def _pending_result_paths(repo: Path, results_dir: Path) -> list[Path]:
    rel_dir = results_dir.relative_to(repo).as_posix()
    status = _run_git(
        repo,
        "status",
        "--porcelain",
        "--untracked-files=all",
        "--",
        rel_dir,
        check=False,
    )
    if status.returncode != 0:
        raise RuntimeError(status.stderr.strip() or "git status failed for relay results")
    root = results_dir.resolve()
    pending: list[Path] = []
    for line in status.stdout.splitlines():
        if len(line) < 4:
            continue
        rel = line[3:].strip()
        if " -> " in rel:
            rel = rel.split(" -> ", 1)[1]
        candidate = (repo / rel).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            continue
        if candidate.suffix == ".json" and candidate.exists():
            pending.append(candidate)
    return sorted(set(pending))


def _validate_request(raw: dict[str, Any], allowed_actions: set[str]) -> dict[str, Any]:
    allowed_keys = {"version", "id", "action", "params", "timeout_ms", "note"}
    unknown = set(raw) - allowed_keys
    if unknown:
        raise ValueError(f"unknown request keys: {sorted(unknown)}")
    if raw.get("version") != REQUEST_VERSION:
        raise ValueError(f"unsupported request version: {raw.get('version')!r}")
    request_id = raw.get("id")
    if not isinstance(request_id, str) or not REQUEST_ID_RE.fullmatch(request_id):
        raise ValueError("id must match [A-Za-z0-9._-]{1,80}")
    action = raw.get("action")
    if action not in allowed_actions:
        raise ValueError(f"action is not enabled by relay: {action!r}")
    params = raw.get("params", {})
    if not isinstance(params, dict):
        raise ValueError("params must be an object")
    timeout_ms = raw.get("timeout_ms", 15_000)
    if not isinstance(timeout_ms, int) or isinstance(timeout_ms, bool) or not (100 <= timeout_ms <= 120_000):
        raise ValueError("timeout_ms must be an integer in [100, 120000]")
    return {
        "version": REQUEST_VERSION,
        "id": request_id,
        "action": action,
        "params": params,
        "timeout_ms": timeout_ms,
        "note": raw.get("note"),
    }


class Relay:
    def __init__(
        self,
        repo: Path,
        *,
        branch: str,
        live: bool,
        poll_seconds: float,
        allowed_actions: set[str],
    ) -> None:
        self.repo = repo
        self.branch = branch
        self.live = live
        self.poll_seconds = poll_seconds
        self.allowed_actions = allowed_actions

        self.runtime_dir = repo / ".pc-relay"
        self.state_dir = self.runtime_dir / "state"
        self.audit_path = self.runtime_dir / "audit.jsonl"
        self.journal_path = self.runtime_dir / "outcomes.jsonl"
        self.health_path = self.runtime_dir / "health.json"
        self.requests_dir = repo / "relay" / "requests"
        self.results_dir = repo / "relay" / "results"

        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.requests_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)

        shell = SafeShellAdapter(allow_executables=RELAY_SHELL_EXECUTABLES, timeout_seconds=120.0)
        self.executor = Executor(
            shell=shell,
            audit=JsonlAuditSink(str(self.audit_path)),
            outcome_journal=OutcomeJournal(str(self.journal_path)),
            dry_run=not live,
            allow_coordinate_fallback=False,
            operation_timeout_seconds=120.0,
        )
        now = time.time()
        self._health: dict[str, Any] = {
            "health_version": HEALTH_VERSION,
            "pid": os.getpid(),
            "branch": self.branch,
            "live": self.live,
            "status": "starting",
            "phase": "startup",
            "updated_at_unix": now,
            "started_at_unix": now,
            "last_fetch_success_at_unix": None,
            "last_sync_at_unix": None,
            "last_cycle_completed_at_unix": None,
            "last_request_processed_at_unix": None,
            "last_request_processed_id": None,
            "last_result_published_at_unix": None,
            "last_result_published_id": None,
            "local_head": _git_head(self.repo),
            "remote_head": _git_head(self.repo, f"origin/{self.branch}"),
            "remote_head_observed_at_unix": None,
            "request_count": 0,
            "result_count": 0,
            "backlog_count": 0,
            "last_backlog_change_at_unix": None,
            "backlog_high_watermark": 0,
            "current_request_id": None,
            "last_error": None,
            "last_reconciliation_request_id": None,
            "reconciliation_required": False,
        }
        self._refresh_queue_counts()
        self._write_health("startup", status="starting")

    def _refresh_queue_counts(self) -> None:
        request_names = {path.name for path in self.requests_dir.glob("*.json")}
        result_names = {path.name for path in self.results_dir.glob("*.json")}
        backlog = len(request_names - result_names)
        previous_backlog = int(self._health.get("backlog_count", 0))
        self._health["request_count"] = len(request_names)
        self._health["result_count"] = len(result_names)
        self._health["backlog_count"] = backlog
        self._health["backlog_high_watermark"] = max(
            int(self._health.get("backlog_high_watermark", 0)),
            backlog,
        )
        if backlog != previous_backlog:
            self._health["last_backlog_change_at_unix"] = time.time()

    def _write_health(
        self,
        phase: str,
        *,
        status: str | None = None,
        current_request_id: str | None = None,
        mark_fetch: bool = False,
        mark_sync: bool = False,
        mark_cycle: bool = False,
        mark_request: bool = False,
        mark_result: bool = False,
        event_request_id: str | None = None,
        local_head: str | None = None,
        remote_head: str | None = None,
        error: str | None = None,
    ) -> None:
        now = time.time()
        self._health["phase"] = phase
        self._health["updated_at_unix"] = now
        if status is not None:
            self._health["status"] = status
        self._health["current_request_id"] = current_request_id
        if mark_fetch:
            self._health["last_fetch_success_at_unix"] = now
        if mark_sync:
            self._health["last_sync_at_unix"] = now
        if mark_cycle:
            self._health["last_cycle_completed_at_unix"] = now
        if mark_request:
            self._health["last_request_processed_at_unix"] = now
            self._health["last_request_processed_id"] = event_request_id
        if mark_result:
            self._health["last_result_published_at_unix"] = now
            self._health["last_result_published_id"] = event_request_id
        if local_head is not None:
            self._health["local_head"] = local_head
        if remote_head is not None:
            self._health["remote_head"] = remote_head
            self._health["remote_head_observed_at_unix"] = now
        self._health["last_error"] = None if error is None else _bounded_error(error)
        _atomic_json(self.health_path, self._health)

    def sync(self) -> None:
        # The remote queue may advance while this checkout creates local result commits.
        # Rebase preserves those local result commits over newly queued remote requests
        # and clears any stale relay-owned rebase state before trying again.
        self._write_health("sync_fetch", status="process_exists")
        _rebase_onto_remote(self.repo, self.branch)
        status = _run_git(self.repo, "status", "--porcelain").stdout.strip()
        tracked_dirty = [
            line for line in status.splitlines()
            if line and ".pc-relay/" not in line.replace("\\", "/")
        ]
        if tracked_dirty:
            raise RuntimeError(f"relay checkout has uncommitted tracked changes: {tracked_dirty[:5]}")
        local_head = _git_head(self.repo)
        remote_head = _git_head(self.repo, f"origin/{self.branch}")
        self._write_health(
            "sync_complete",
            status="healthy",
            mark_fetch=True,
            mark_sync=True,
            local_head=local_head,
            remote_head=remote_head,
        )

    def _state_path(self, request_id: str) -> Path:
        return self.state_dir / f"{request_id}.json"

    def _result_path(self, request_id: str) -> Path:
        return self.results_dir / f"{request_id}.json"

    def _reconcile_after_interrupted_side_effect(self, req: dict[str, Any]) -> dict[str, Any]:
        lookup = ActionRequest.from_dict({
            "request_id": f"{req['id']}.relay-reconcile",
            "action": "outcome.lookup",
            "params": {
                "request_id": req["id"],
                "action": req["action"],
                "execution_attempt": 1,
            },
            "dry_run": True,
            "timeout_ms": min(req["timeout_ms"], 10_000),
        })
        result = self.executor.execute(lookup).to_dict()
        return {
            "version": RESULT_VERSION,
            "id": req["id"],
            "action": req["action"],
            "relay_status": "interrupted_requires_reconciliation",
            "live": self.live,
            "executor_result": None,
            "reconciliation": result,
            "reexecuted": False,
            "replay_authorized": False,
        }

    def execute_one(self, request_path: Path) -> dict[str, Any]:
        raw = _load_json(request_path)
        req = _validate_request(raw, self.allowed_actions)
        request_id = req["id"]
        result_path = self._result_path(request_id)
        if result_path.exists():
            return {"skipped": True, "id": request_id, "reason": "result_exists"}

        state_path = self._state_path(request_id)
        if state_path.exists():
            state = _load_json(state_path)
            if state.get("status") == "finished" and isinstance(state.get("result"), dict):
                result = state["result"]
                self.publish_result(result)
                return result
            if state.get("status") == "started":
                if req["action"] in READ_ONLY_ACTIONS:
                    pass
                else:
                    self._health["last_reconciliation_request_id"] = request_id
                    self._health["reconciliation_required"] = True
                    self._write_health(
                        "reconcile_interrupted_side_effect",
                        status="healthy",
                        current_request_id=request_id,
                    )
                    result = self._reconcile_after_interrupted_side_effect(req)
                    _atomic_json(state_path, {"status": "finished", "result": result})
                    self.publish_result(result)
                    return result

        _atomic_json(state_path, {
            "status": "started",
            "request": req,
            "live": self.live,
            "started_at_unix": time.time(),
        })
        self._write_health(
            "execute_request",
            status="healthy",
            current_request_id=request_id,
        )

        action_payload = {
            "request_id": request_id,
            "action": req["action"],
            "params": req["params"],
            "dry_run": not self.live,
            "timeout_ms": req["timeout_ms"],
        }
        executor_request = ActionRequest.from_dict(action_payload)
        executor_result = self.executor.execute(executor_request).to_dict()

        result = {
            "version": RESULT_VERSION,
            "id": request_id,
            "action": req["action"],
            "relay_status": "completed",
            "live": self.live,
            "executor_result": executor_result,
            "reconciliation": None,
            "reexecuted": False,
        }
        _atomic_json(state_path, {"status": "finished", "result": result})
        self.publish_result(result)
        return result

    def publish_result(self, result: dict[str, Any]) -> None:
        request_id = result["id"]
        result_path = self._result_path(request_id)
        if not result_path.exists():
            _atomic_json(result_path, result)

        _run_git(self.repo, "add", result_path.relative_to(self.repo).as_posix())
        diff = _run_git(self.repo, "diff", "--cached", "--quiet", check=False)
        if diff.returncode == 0:
            return
        _run_git(
            self.repo,
            "-c",
            "user.name=PC GitHub Relay",
            "-c",
            "user.email=pc-relay@local.invalid",
            "commit",
            "-m",
            f"relay result {request_id}",
        )

        for attempt in range(3):
            pushed = _run_git(
                self.repo,
                "push",
                "origin",
                f"HEAD:{self.branch}",
                check=False,
            )
            if pushed.returncode == 0:
                self._write_health(
                    "result_published",
                    status="healthy",
                    mark_result=True,
                    event_request_id=request_id,
                )
                return
            # Remote queue advanced between our commit and push. Rebase the local
            # result commit over it, and always clean up failed rebase state.
            _rebase_onto_remote(self.repo, self.branch)
        raise RuntimeError(f"failed to push relay result {request_id}")

    def _publish_pending_results(self) -> None:
        # Recover only result files that Git says are uncommitted/untracked.
        # Scanning every historical result and running git add/diff for each one
        # made cycle cost grow linearly with the lifetime result corpus and could
        # make an alive relay appear hung before it ever reached sync().
        for result_path in _pending_result_paths(self.repo, self.results_dir):
            result = _load_json(result_path)
            request_id = result.get("id")
            if isinstance(request_id, str) and REQUEST_ID_RE.fullmatch(request_id):
                self.publish_result(result)

    def cycle(self) -> int:
        self._refresh_queue_counts()
        self._write_health("publish_pending", status="process_exists")
        self._publish_pending_results()
        self.sync()
        processed = 0
        for request_path in sorted(self.requests_dir.glob("*.json")):
            try:
                raw = _load_json(request_path)
                request_id = raw.get("id")
                if isinstance(request_id, str) and self._result_path(request_id).exists():
                    continue
                self.execute_one(request_path)
                self._write_health(
                    "request_processed",
                    status="healthy",
                    mark_request=True,
                    event_request_id=request_id,
                )
                processed += 1
            except Exception as exc:
                request_id = request_path.stem
                if REQUEST_ID_RE.fullmatch(request_id):
                    error_result = {
                        "version": RESULT_VERSION,
                        "id": request_id,
                        "action": None,
                        "relay_status": "relay_error",
                        "live": self.live,
                        "executor_result": None,
                        "reconciliation": None,
                        "reexecuted": False,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                    _atomic_json(self._state_path(request_id), {
                        "status": "finished",
                        "result": error_result,
                    })
                    self.publish_result(error_result)
                else:
                    print(f"[relay] invalid request file {request_path.name}: {exc}", file=sys.stderr)
        self._refresh_queue_counts()
        self._write_health(
            "idle",
            status="healthy",
            current_request_id=None,
            mark_cycle=True,
        )
        return processed

    def run_forever(self) -> None:
        mode = "LIVE" if self.live else "DRY-RUN"
        print(f"[relay] started mode={mode} branch={self.branch} repo={self.repo}", flush=True)
        while True:
            try:
                count = self.cycle()
                if count:
                    print(f"[relay] processed {count} request(s)", flush=True)
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                message = f"{type(exc).__name__}: {exc}"
                self._write_health("cycle_error", status="degraded", error=message)
                print(f"[relay] cycle error: {message}", file=sys.stderr, flush=True)
            time.sleep(self.poll_seconds)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="GitHub-backed relay for PC Executor")
    parser.add_argument("--repo", default=".", help="dedicated checkout path")
    parser.add_argument("--branch", default="agent/pc-github-relay")
    parser.add_argument("--poll-seconds", type=float, default=3.0)
    parser.add_argument("--live", action="store_true", help="allow Executor side effects; default is dry-run")
    parser.add_argument(
        "--allow-action",
        action="append",
        default=[],
        help="additional Executor action to expose through relay",
    )
    parser.add_argument("--once", action="store_true", help="process one sync cycle and exit")
    parser.add_argument("--status", action="store_true", help="print the read-only relay watchdog status and exit")
    parser.add_argument(
        "--observed-process",
        action="append",
        default=[],
        metavar="PID:PARENTPID",
        help="matching relay process identity already observed by the caller; repeatable",
    )
    parser.add_argument(
        "--stale-after-seconds",
        type=float,
        default=DEFAULT_STALE_AFTER_SECONDS,
        help="freshness threshold used by --status",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    repo = Path(args.repo).resolve()
    if not (repo / ".git").exists():
        raise SystemExit(f"not a git checkout: {repo}")
    if args.status:
        health_path = repo / ".pc-relay" / "health.json"
        snapshot = _load_json(health_path) if health_path.exists() else None
        try:
            status = build_watchdog_status(
                repo,
                snapshot=snapshot,
                observed_processes=args.observed_process,
                now_unix=time.time(),
                stale_after_seconds=max(1.0, args.stale_after_seconds),
            )
        except (OSError, RuntimeError, ValueError) as exc:
            status = {
                "status_version": "pc_relay.watchdog_status.v1",
                "state": "PROCESS_EXISTS" if args.observed_process else "PROCESS_MISSING",
                "observed_at_unix": time.time(),
                "process": None,
                "observations": None,
                "stale_reasons": ["status_probe_error"],
                "health": snapshot,
                "error": {
                    "classification": type(exc).__name__,
                    "message": _bounded_error(exc),
                },
                "recovery": {
                    "automatic_restart": False,
                    "automatic_kill": False,
                    "automatic_side_effect_replay": False,
                    "preserve_state_dir": ".pc-relay/state",
                    "preserve_outcome_journal": ".pc-relay/outcomes.jsonl",
                    "unknown_side_effect_requires_outcome_lookup": True,
                },
            }
        else:
            status["error"] = None
        print(json.dumps(status, ensure_ascii=False, sort_keys=True))
        return 0 if status["state"] == "HEALTHY" else 2

    allowed = set(DEFAULT_ALLOWED_ACTIONS) | set(args.allow_action)
    relay = Relay(
        repo,
        branch=args.branch,
        live=args.live,
        poll_seconds=max(0.5, args.poll_seconds),
        allowed_actions=allowed,
    )
    if args.once:
        relay.cycle()
        return 0
    try:
        relay.run_forever()
    except KeyboardInterrupt:
        print("\n[relay] stopped", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
