from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

from pc_executor.audit import JsonlAuditSink
from pc_executor.executor import Executor
from pc_executor.models import ActionRequest
from pc_executor.outcome_journal import OutcomeJournal
from pc_executor.safety import DEFAULT_SAFE_EXECUTABLES
from pc_executor.shell import SafeShellAdapter
from pc_relay.progress import (
    DEFAULT_STALL_SECONDS,
    MAX_BATCH_PER_CYCLE,
    RelayProgress,
    classify_error,
    liveness_probe,
    load_progress,
)

REQUEST_VERSION = "pc_relay.request.v1"
RESULT_VERSION = "pc_relay.result.v1"
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
MAX_GIT_ATTEMPTS = 3
MAX_RECOVERY_RESULTS_PER_CYCLE = 64

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


class RelayTransportError(RuntimeError):
    def __init__(self, error: dict[str, Any]) -> None:
        self.error = dict(error)
        super().__init__(
            f"{self.error.get('classification', 'unknown')}: "
            f"{self.error.get('operation', 'git')}: "
            f"{self.error.get('message', '')}"
        )


def _run_git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        text=True,
        capture_output=True,
        check=check,
    )


def _git_retry(
    repo: Path,
    *args: str,
    operation: str,
    attempts: int = MAX_GIT_ATTEMPTS,
    sleep_fn: Callable[[float], None] = time.sleep,
    progress: RelayProgress | None = None,
) -> subprocess.CompletedProcess[str]:
    if attempts < 1:
        raise ValueError("attempts must be positive")
    last_error: dict[str, Any] | None = None
    for attempt in range(attempts):
        proc = _run_git(repo, *args, check=False)
        if proc.returncode == 0:
            return proc
        message = proc.stderr.strip() or proc.stdout.strip() or f"git {operation} failed"
        error = classify_error(
            message,
            operation=operation,
            returncode=proc.returncode,
        )
        last_error = error
        if not error["retryable"]:
            raise RelayTransportError(error)
        if attempt + 1 < attempts:
            if progress is not None:
                progress.state("recovering")
            sleep_fn(min(0.25 * (2**attempt), 1.0))
    assert last_error is not None
    raise RelayTransportError(last_error)


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


def _rebase_onto_remote(
    repo: Path,
    branch: str,
    *,
    progress: RelayProgress | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> None:
    # A failed pull/rebase from an earlier cycle must never poison all future cycles.
    _abort_stale_rebase(repo)
    if progress is not None:
        progress.state("fetching")
    _git_retry(
        repo,
        "fetch",
        "origin",
        branch,
        operation="fetch",
        sleep_fn=sleep_fn,
        progress=progress,
    )
    remote_head_proc = _run_git(repo, "rev-parse", f"origin/{branch}", check=False)
    remote_head = (
        remote_head_proc.stdout.strip()
        if remote_head_proc.returncode == 0 and remote_head_proc.stdout.strip()
        else None
    )
    if progress is not None:
        progress.fetch_success(remote_head=remote_head)
        progress.state("rebasing")
    rebased = _run_git(repo, "rebase", f"origin/{branch}", check=False)
    if rebased.returncode == 0:
        return
    _run_git(repo, "rebase", "--abort", check=False)
    message = rebased.stderr.strip() or rebased.stdout.strip() or "relay rebase failed"
    error = classify_error(message, operation="rebase", returncode=rebased.returncode)
    if error["classification"] == "unknown":
        error = {
            **error,
            "classification": "rebase_conflict",
            "retryable": False,
        }
    raise RelayTransportError(error)


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}.{time.time_ns()}")
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


def _load_json(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("request/result JSON must be an object")
    return raw


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
        executor: Executor | None = None,
        clock: Callable[[], float] = time.time,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> None:
        self.repo = repo
        self.branch = branch
        self.live = live
        self.poll_seconds = poll_seconds
        self.allowed_actions = allowed_actions
        self.clock = clock
        self.sleep_fn = sleep_fn

        self.runtime_dir = repo / ".pc-relay"
        self.state_dir = self.runtime_dir / "state"
        self.audit_path = self.runtime_dir / "audit.jsonl"
        self.journal_path = self.runtime_dir / "outcomes.jsonl"
        self.progress_path = self.runtime_dir / "progress.v1.json"
        self.requests_dir = repo / "relay" / "requests"
        self.results_dir = repo / "relay" / "results"

        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.requests_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)

        if executor is None:
            shell = SafeShellAdapter(
                allow_executables=RELAY_SHELL_EXECUTABLES,
                timeout_seconds=120.0,
            )
            executor = Executor(
                shell=shell,
                audit=JsonlAuditSink(str(self.audit_path)),
                outcome_journal=OutcomeJournal(str(self.journal_path)),
                dry_run=not live,
                allow_coordinate_fallback=False,
                operation_timeout_seconds=120.0,
            )
        self.executor = executor

        head_proc = _run_git(repo, "rev-parse", "HEAD", check=False)
        startup_head = (
            head_proc.stdout.strip()
            if head_proc.returncode == 0 and head_proc.stdout.strip()
            else "unknown"
        )
        script_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        self.progress = RelayProgress(
            self.progress_path,
            branch=branch,
            startup_head=startup_head,
            relay_script_sha256=script_sha,
            poll_seconds=poll_seconds,
            clock=clock,
        )

    def sync(self) -> None:
        # The remote queue may advance while this checkout creates local result commits.
        # Rebase preserves local result commits over queued remote requests.
        _rebase_onto_remote(
            self.repo,
            self.branch,
            progress=self.progress,
            sleep_fn=self.sleep_fn,
        )
        status = _run_git(self.repo, "status", "--porcelain").stdout.strip()
        tracked_dirty = [
            line
            for line in status.splitlines()
            if line and ".pc-relay/" not in line.replace("\\", "/")
        ]
        if tracked_dirty:
            raise RelayTransportError(
                {
                    "classification": "checkout_dirty",
                    "retryable": False,
                    "operation": "status",
                    "returncode": None,
                    "message": f"relay checkout has uncommitted tracked changes: {tracked_dirty[:5]}",
                }
            )

    def _state_path(self, request_id: str) -> Path:
        return self.state_dir / f"{request_id}.json"

    def _result_path(self, request_id: str) -> Path:
        return self.results_dir / f"{request_id}.json"

    def _reconcile_after_interrupted_side_effect(self, req: dict[str, Any]) -> dict[str, Any]:
        lookup = ActionRequest.from_dict(
            {
                "request_id": f"{req['id']}.relay-reconcile",
                "action": "outcome.lookup",
                "params": {
                    "request_id": req["id"],
                    "action": req["action"],
                    "execution_attempt": 1,
                },
                "dry_run": True,
                "timeout_ms": min(req["timeout_ms"], 10_000),
            }
        )
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
        self.progress.request_observed(
            request_id,
            action=req["action"],
            timeout_ms=req["timeout_ms"],
        )
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
                if req["action"] not in READ_ONLY_ACTIONS:
                    result = self._reconcile_after_interrupted_side_effect(req)
                    _atomic_json(state_path, {"status": "finished", "result": result})
                    self.publish_result(result)
                    return result
                # Read-only operations may be safely retried with the same logical id.

        _atomic_json(
            state_path,
            {
                "status": "started",
                "request": req,
                "live": self.live,
                "started_at_unix": self.clock(),
            },
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

    def _push_head_with_recovery(self) -> None:
        last_error: dict[str, Any] | None = None
        for attempt in range(MAX_GIT_ATTEMPTS):
            pushed = _run_git(
                self.repo,
                "push",
                "origin",
                f"HEAD:{self.branch}",
                check=False,
            )
            if pushed.returncode == 0:
                return
            message = pushed.stderr.strip() or pushed.stdout.strip() or "git push failed"
            error = classify_error(
                message,
                operation="push",
                returncode=pushed.returncode,
            )
            last_error = error
            if not error["retryable"]:
                raise RelayTransportError(error)
            if error["classification"] == "remote_advanced":
                _rebase_onto_remote(
                    self.repo,
                    self.branch,
                    progress=self.progress,
                    sleep_fn=self.sleep_fn,
                )
            elif attempt + 1 < MAX_GIT_ATTEMPTS:
                self.progress.state("recovering")
                self.sleep_fn(min(0.25 * (2**attempt), 1.0))
        assert last_error is not None
        raise RelayTransportError(last_error)

    def _recover_local_ahead_commits(self) -> None:
        """Push durable local result commits left by a prior interrupted process."""
        ahead = _run_git(
            self.repo,
            "rev-list",
            "--count",
            f"origin/{self.branch}..HEAD",
            check=False,
        )
        if ahead.returncode != 0:
            return
        try:
            count = int(ahead.stdout.strip() or "0")
        except ValueError:
            return
        if count <= 0:
            return

        latest = _run_git(
            self.repo,
            "log",
            "-1",
            "--format=%H%x00%s",
            check=False,
        )
        if latest.returncode == 0 and "\x00" in latest.stdout:
            commit_sha, subject = latest.stdout.strip().split("\x00", 1)
            prefix = "relay result "
            if subject.startswith(prefix):
                request_id = subject[len(prefix):].strip()
                if REQUEST_ID_RE.fullmatch(request_id):
                    self.progress.result_committed(
                        request_id,
                        commit_sha=commit_sha or None,
                    )
        self.progress.state("publishing_pending")
        self._push_head_with_recovery()

    def publish_result(self, result: dict[str, Any]) -> None:
        request_id = result["id"]
        result_path = self._result_path(request_id)
        if not result_path.exists():
            _atomic_json(result_path, result)

        self.progress.state("publishing")
        _run_git(self.repo, "add", result_path.relative_to(self.repo).as_posix())
        diff = _run_git(self.repo, "diff", "--cached", "--quiet", check=False)
        if diff.returncode != 0:
            commit = _run_git(
                self.repo,
                "-c",
                "user.name=PC GitHub Relay",
                "-c",
                "user.email=pc-relay@local.invalid",
                "commit",
                "-m",
                f"relay result {request_id}",
                check=False,
            )
            if commit.returncode != 0:
                raise RelayTransportError(
                    {
                        "classification": "publish_error",
                        "retryable": False,
                        "operation": "commit",
                        "returncode": commit.returncode,
                        "message": commit.stderr.strip() or commit.stdout.strip(),
                    }
                )
            head = _run_git(self.repo, "rev-parse", "HEAD", check=False)
            committed_sha = (
                head.stdout.strip()
                if head.returncode == 0 and head.stdout.strip()
                else None
            )
            self.progress.result_committed(request_id, commit_sha=committed_sha)

        self._push_head_with_recovery()

    def _publish_pending_results(self) -> None:
        # First recover clean local commits that were durable before a prior
        # process died during push. This never executes a request again.
        self.progress.state("publishing_pending")
        self._recover_local_ahead_commits()
        # Then recover dirty/untracked result files. Historical committed results
        # are not re-walked every cycle, keeping memory and Git work bounded.
        status = _run_git(
            self.repo,
            "status",
            "--porcelain",
            "--",
            "relay/results",
            check=False,
        )
        if status.returncode != 0:
            raise RelayTransportError(
                classify_error(
                    status.stderr.strip() or status.stdout.strip() or "git status failed",
                    operation="status",
                    returncode=status.returncode,
                )
            )
        recovered = 0
        for line in status.stdout.splitlines():
            if recovered >= MAX_RECOVERY_RESULTS_PER_CYCLE:
                break
            if not line.strip():
                continue
            raw_path = line[3:].strip().strip('"').replace("\\", "/")
            if not raw_path.startswith("relay/results/") or not raw_path.endswith(".json"):
                continue
            result_path = self.repo / raw_path
            if not result_path.exists():
                continue
            result = _load_json(result_path)
            request_id = result.get("id")
            if isinstance(request_id, str) and REQUEST_ID_RE.fullmatch(request_id):
                self.publish_result(result)
                recovered += 1

    def _queue_snapshot(self) -> tuple[list[Path], dict[str, Any]]:
        now = self.clock()
        pending_count = 0
        oldest_id: str | None = None
        oldest_age: float | None = None
        candidates: list[tuple[str, Path]] = []
        with os.scandir(self.requests_dir) as entries:
            for entry in entries:
                if not entry.is_file() or not entry.name.endswith(".json"):
                    continue
                path = Path(entry.path)
                request_id = path.stem
                try:
                    raw = _load_json(path)
                    raw_id = raw.get("id")
                    if isinstance(raw_id, str) and REQUEST_ID_RE.fullmatch(raw_id):
                        request_id = raw_id
                except Exception:
                    pass
                if REQUEST_ID_RE.fullmatch(request_id) and self._result_path(request_id).exists():
                    continue
                pending_count += 1
                try:
                    age = max(0.0, now - entry.stat().st_mtime)
                except OSError:
                    age = 0.0
                if oldest_age is None or age > oldest_age:
                    oldest_age = age
                    oldest_id = request_id
                bisect.insort(candidates, (entry.name, path))
                if len(candidates) > MAX_BATCH_PER_CYCLE:
                    candidates.pop()
        metrics = {
            "pending_count": pending_count,
            "oldest_pending_request_id": oldest_id,
            "oldest_pending_age_seconds": oldest_age,
        }
        self.progress.queue_metrics(**metrics)
        return [path for _name, path in candidates], metrics

    def cycle(self) -> int:
        self.progress.start_cycle()
        try:
            self._publish_pending_results()
            self.sync()
            request_paths, _metrics = self._queue_snapshot()
            processed = 0
            for request_path in request_paths:
                try:
                    raw = _load_json(request_path)
                    request_id = raw.get("id")
                    if isinstance(request_id, str) and self._result_path(request_id).exists():
                        continue
                    self.execute_one(request_path)
                    processed += 1
                except RelayTransportError:
                    # A result/state already written locally must remain recoverable.
                    # Never replace it with relay_error or replay a side effect.
                    raise
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
                            "error": f"{type(exc).__name__}: {str(exc)[:512]}",
                        }
                        _atomic_json(
                            self._state_path(request_id),
                            {"status": "finished", "result": error_result},
                        )
                        self.publish_result(error_result)
                    else:
                        print(
                            f"[relay] invalid request file {request_path.name}: {exc}",
                            file=sys.stderr,
                        )
            # Refresh lag after the bounded batch so health reflects remaining work.
            self._queue_snapshot()
            self.progress.cycle_success()
            return processed
        except RelayTransportError as exc:
            self.progress.cycle_failure(exc.error)
            raise
        except Exception as exc:
            error = {
                "classification": "unknown",
                "retryable": False,
                "operation": "cycle",
                "returncode": None,
                "message": f"{type(exc).__name__}: {str(exc)[:512]}",
            }
            self.progress.cycle_failure(error)
            raise

    def run_forever(self) -> None:
        mode = "LIVE" if self.live else "DRY-RUN"
        print(
            f"[relay] started mode={mode} branch={self.branch} repo={self.repo}",
            flush=True,
        )
        while True:
            try:
                count = self.cycle()
                if count:
                    print(f"[relay] processed {count} request(s)", flush=True)
            except KeyboardInterrupt:
                self.progress.state("stopped")
                raise
            except Exception as exc:
                print(
                    f"[relay] cycle error: {type(exc).__name__}: {exc}",
                    file=sys.stderr,
                    flush=True,
                )
            self.sleep_fn(self.poll_seconds)


def _health_probe(args: argparse.Namespace, repo: Path) -> int:
    progress_path = repo / ".pc-relay" / "progress.v1.json"
    try:
        progress = load_progress(progress_path)
        probe = liveness_probe(
            progress,
            observed_pids=args.observed_pid if args.observed_pid else None,
            expected_pid=args.expected_pid,
            stall_seconds=args.stall_seconds,
        )
        payload = {
            "probe": probe,
            "progress": progress,
        }
    except Exception as exc:
        payload = {
            "probe": {
                "contract_version": "pc_relay.liveness_probe.v1",
                "state": "unknown",
                "reason": "progress_record_invalid",
                "error_kind": type(exc).__name__,
            },
            "progress": None,
        }
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="GitHub-backed relay for PC Executor")
    parser.add_argument("--repo", default=".", help="dedicated checkout path")
    parser.add_argument("--branch", default="agent/pc-github-relay")
    parser.add_argument("--poll-seconds", type=float, default=3.0)
    parser.add_argument(
        "--live",
        action="store_true",
        help="allow Executor side effects; default is dry-run",
    )
    parser.add_argument(
        "--allow-action",
        action="append",
        default=[],
        help="additional Executor action to expose through relay",
    )
    parser.add_argument("--once", action="store_true", help="process one sync cycle and exit")
    parser.add_argument(
        "--health",
        action="store_true",
        help="read only the bounded local relay progress record and print JSON",
    )
    parser.add_argument(
        "--observed-pid",
        action="append",
        default=[],
        type=int,
        help="matching relay PID observed by an external launcher; repeatable",
    )
    parser.add_argument("--expected-pid", type=int)
    parser.add_argument("--stall-seconds", type=float, default=DEFAULT_STALL_SECONDS)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    repo = Path(args.repo).resolve()
    if args.health:
        return _health_probe(args, repo)
    if not (repo / ".git").exists():
        raise SystemExit(f"not a git checkout: {repo}")
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
