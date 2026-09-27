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
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")

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

    def sync(self) -> None:
        _run_git(self.repo, "fetch", "origin", self.branch)
        status = _run_git(self.repo, "status", "--porcelain").stdout.strip()
        tracked_dirty = [
            line for line in status.splitlines()
            if line and ".pc-relay/" not in line.replace("\\", "/")
        ]
        if tracked_dirty:
            raise RuntimeError(f"relay checkout has uncommitted tracked changes: {tracked_dirty[:5]}")
        # The remote queue may advance while this checkout creates local result commits.
        # Rebase preserves those local result commits over newly queued remote requests
        # instead of deadlocking forever on an ff-only merge.
        rebased = _run_git(
            self.repo,
            "rebase",
            f"origin/{self.branch}",
            check=False,
        )
        if rebased.returncode != 0:
            _run_git(self.repo, "rebase", "--abort", check=False)
            raise RuntimeError(
                "relay branch rebase failed; manual reconciliation required: "
                + (rebased.stderr.strip() or rebased.stdout.strip())
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
                return
            _run_git(self.repo, "pull", "--rebase", "origin", self.branch)
        raise RuntimeError(f"failed to push relay result {request_id}")

    def _publish_pending_results(self) -> None:
        # Recover results that were produced before a crash or Git commit failure.
        # This is deliberately done before sync so a locally staged/untracked result
        # can be committed and pushed instead of being mistaken for checkout dirt.
        for result_path in sorted(self.results_dir.glob("*.json")):
            result = _load_json(result_path)
            request_id = result.get("id")
            if isinstance(request_id, str) and REQUEST_ID_RE.fullmatch(request_id):
                self.publish_result(result)

    def cycle(self) -> int:
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
                print(f"[relay] cycle error: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
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
    return parser


def main() -> int:
    args = build_parser().parse_args()
    repo = Path(args.repo).resolve()
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
