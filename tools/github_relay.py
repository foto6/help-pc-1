from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

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


def classify_health_snapshot(
    snapshot: dict[str, Any] | None,
    *,
    now_unix: float,
    process_exists: bool,
    stale_after_seconds: float = DEFAULT_STALE_AFTER_SECONDS,
) -> str:
    if not process_exists:
        return "PROCESS_MISSING"
    if not snapshot:
        return "PROCESS_EXISTS"
    if snapshot.get("reconciliation_required") is True:
        return "RECONCILIATION_REQUIRED"
    try:
        updated_at = float(snapshot.get("updated_at_unix"))
    except (TypeError, ValueError):
        return "PROCESS_EXISTS"
    if now_unix - updated_at > stale_after_seconds:
        return "STALE"
    if snapshot.get("status") == "healthy":
        return "HEALTHY"
    return "PROCESS_EXISTS"


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
            "last_sync_at_unix": None,
            "last_cycle_completed_at_unix": None,
            "last_result_published_at_unix": None,
            "local_head": _git_head(self.repo),
            "remote_head": _git_head(self.repo, f"origin/{self.branch}"),
            "request_count": 0,
            "result_count": 0,
            "backlog_count": 0,
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
        self._health["request_count"] = len(request_names)
        self._health["result_count"] = len(result_names)
        self._health["backlog_count"] = len(request_names - result_names)

    def _write_health(
        self,
        phase: str,
        *,
        status: str | None = None,
        current_request_id: str | None = None,
        mark_sync: bool = False,
        mark_cycle: bool = False,
        mark_result: bool = False,
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
        if mark_sync:
            self._health["last_sync_at_unix"] = now
        if mark_cycle:
            self._health["last_cycle_completed_at_unix"] = now
        if mark_result:
            self._health["last_result_published_at_unix"] = now
        if local_head is not None:
            self._health["local_head"] = local_head
        if remote_head is not None:
            self._health["remote_head"] = remote_head
        self._health["last_error"] = error
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
                self._write_health("result_published", status="healthy", mark_result=True)
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
    parser.add_argument("--status", action="store_true", help="print the durable relay health snapshot and exit")
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
        state = classify_health_snapshot(
            snapshot,
            now_unix=time.time(),
            process_exists=True,
            stale_after_seconds=max(1.0, args.stale_after_seconds),
        )
        print(json.dumps({
            "state": state,
            "health": snapshot,
        }, ensure_ascii=False, sort_keys=True))
        return 0 if state == "HEALTHY" else 2

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
