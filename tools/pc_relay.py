from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from pc_executor.audit import JsonlAuditSink
from pc_executor.executor import Executor
from pc_executor.models import ActionRequest
from pc_executor.outcome_journal import OutcomeJournal
from pc_executor.safety import (
    DEFAULT_SAFE_EXECUTABLES,
    SafetyViolation,
    ensure_argv_allowed,
    ensure_path_allowed,
)
from pc_executor.shell import SafeShellAdapter


REQUEST_VERSION = "pc_relay.request.v2"
RESULT_VERSION = "pc_relay.result.v2"
HEARTBEAT_VERSION = "pc_relay.heartbeat.v1"
STATE_VERSION = "pc_relay.state.v1"
QUEUE_PROTOCOL_VERSION = "pc_relay.queue.v1"
DEFAULT_QUEUE_REF = "agent/pc-relay-queue"

REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_REQUEST_BYTES = 64 * 1024
MAX_RESULT_BYTES = 512 * 1024
SHELL_OUTPUT_LIMIT_BYTES = 64 * 1024
MAX_TIMEOUT_MS = 120_000
DEFAULT_HEARTBEAT_SECONDS = 30.0

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
MAX_ALLOWED_ACTIONS = frozenset(READ_ONLY_ACTIONS | {"shell.run"})
DEFAULT_ALLOWED_ACTIONS = frozenset(MAX_ALLOWED_ACTIONS)

RELAY_SHELL_EXECUTABLES = frozenset(
    set(DEFAULT_SAFE_EXECUTABLES)
    | {
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
        "cmd",
        "cmd.exe",
    }
)

_POWERSHELL_NAMES = {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}
_CMD_NAMES = {"cmd", "cmd.exe"}
_FORBIDDEN_INTERACTIVE_SHELL_TERMS = (
    "get-credential",
    "read-host -assecurestring",
    "convertto-securestring",
    "set-clipboard",
    "sendkeys",
    "captcha",
)
_SENSITIVE_KEY_RE = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|access[_-]?token|token|authorization|credential)",
    re.IGNORECASE,
)
_SENSITIVE_VALUE_RE = re.compile(
    r"(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token|token|authorization|credential)"
    r"\s*[:=]\s*([^\s;,]+)"
)


class RelayError(RuntimeError):
    pass


class RequestValidationError(RelayError):
    pass


class QueueIntegrityError(RelayError):
    pass


class QueueForcePushError(QueueIntegrityError):
    pass


class QueueConflictError(QueueIntegrityError):
    pass


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def request_digest(raw: Mapping[str, Any]) -> str:
    body = {key: value for key, value in raw.items() if key != "request_sha256"}
    return _sha256_json(body)


def result_digest(raw: Mapping[str, Any]) -> str:
    body = {key: value for key, value in raw.items() if key != "result_sha256"}
    return _sha256_json(body)


def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    data = (json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    with tmp.open("wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _load_json_bytes(raw: bytes, *, where: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RequestValidationError(f"{where} is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise RequestValidationError(f"{where} must be a JSON object")
    return value


def _redact_text(value: str) -> str:
    return _SENSITIVE_VALUE_RE.sub(lambda m: f"{m.group(1)}=[REDACTED]", value)


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            if _SENSITIVE_KEY_RE.search(str(key)):
                output[str(key)] = "[REDACTED]"
            else:
                output[str(key)] = _redact_value(item)
        return output
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_value(item) for item in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


def _validate_shell_transport(params: Mapping[str, Any]) -> None:
    argv = params.get("argv")
    if not isinstance(argv, list) or not argv or any(not isinstance(part, str) for part in argv):
        raise RequestValidationError("shell.run argv must be a non-empty array of strings")
    cwd = params.get("cwd")
    if cwd is not None and not isinstance(cwd, str):
        raise RequestValidationError("shell.run cwd must be string or null")

    try:
        args = ensure_argv_allowed(argv, set(RELAY_SHELL_EXECUTABLES))
        ensure_path_allowed(cwd)
    except SafetyViolation as exc:
        raise RequestValidationError(str(exc)) from exc

    executable = Path(args[0].replace("\\", "/")).name.lower()
    lowered = " ".join(args[1:]).casefold()
    if executable in _POWERSHELL_NAMES:
        if "-encodedcommand" in lowered or " -enc " in f" {lowered} ":
            raise RequestValidationError("encoded PowerShell commands are forbidden by relay transport")
        if "-command" not in {part.casefold() for part in args[1:]}:
            raise RequestValidationError("PowerShell relay calls require explicit -Command")
        if "-noprofile" not in {part.casefold() for part in args[1:]}:
            raise RequestValidationError("PowerShell relay calls require -NoProfile")
    if executable in _CMD_NAMES:
        switches = {part.casefold() for part in args[1:]}
        if "/k" in switches:
            raise RequestValidationError("persistent cmd sessions are forbidden by relay transport")
        if "/c" not in switches:
            raise RequestValidationError("cmd relay calls require explicit /c")
    if executable in _POWERSHELL_NAMES | _CMD_NAMES:
        for term in _FORBIDDEN_INTERACTIVE_SHELL_TERMS:
            if term in lowered:
                raise RequestValidationError(
                    f"interactive credential/CAPTCHA transport term is forbidden: {term}"
                )


def validate_request(raw: Mapping[str, Any], allowed_actions: set[str] | frozenset[str]) -> dict[str, Any]:
    allowed_keys = {
        "version",
        "id",
        "action",
        "params",
        "timeout_ms",
        "note",
        "request_sha256",
    }
    required = {"version", "id", "action", "params", "timeout_ms", "request_sha256"}
    unknown = set(raw) - allowed_keys
    missing = required - set(raw)
    if unknown or missing:
        raise RequestValidationError(
            f"request keys mismatch; missing={sorted(missing)}, extra={sorted(unknown)}"
        )
    if raw.get("version") != REQUEST_VERSION:
        raise RequestValidationError(f"unsupported request version: {raw.get('version')!r}")

    request_id = raw.get("id")
    if not isinstance(request_id, str) or not REQUEST_ID_RE.fullmatch(request_id):
        raise RequestValidationError("id must match [A-Za-z0-9._-]{1,80}")

    action = raw.get("action")
    if not isinstance(action, str) or action not in allowed_actions:
        raise RequestValidationError(f"action is not enabled by relay: {action!r}")
    if action not in MAX_ALLOWED_ACTIONS:
        raise RequestValidationError(f"action exceeds relay maximum allowlist: {action!r}")

    params = raw.get("params")
    if not isinstance(params, dict):
        raise RequestValidationError("params must be an object")

    timeout_ms = raw.get("timeout_ms")
    if (
        isinstance(timeout_ms, bool)
        or not isinstance(timeout_ms, int)
        or not 100 <= timeout_ms <= MAX_TIMEOUT_MS
    ):
        raise RequestValidationError(
            f"timeout_ms must be an integer in [100, {MAX_TIMEOUT_MS}]"
        )

    note = raw.get("note")
    if note is not None and (not isinstance(note, str) or len(note) > 512):
        raise RequestValidationError("note must be null or a string of at most 512 characters")

    claimed = raw.get("request_sha256")
    if not isinstance(claimed, str) or not SHA256_RE.fullmatch(claimed):
        raise RequestValidationError("request_sha256 must be lowercase SHA-256")
    actual = request_digest(raw)
    if claimed != actual:
        raise RequestValidationError(
            f"request_sha256 mismatch: claimed={claimed}, actual={actual}"
        )

    if action == "shell.run":
        _validate_shell_transport(params)

    return {
        "version": REQUEST_VERSION,
        "id": request_id,
        "action": action,
        "params": dict(params),
        "timeout_ms": timeout_ms,
        "note": note,
        "request_sha256": claimed,
    }


def validate_result(raw: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "version",
        "id",
        "request_sha256",
        "action",
        "relay_status",
        "live",
        "executor_result",
        "reconciliation",
        "reexecuted",
        "error",
        "implementation_sha",
        "queue_head_at_receive",
        "published_at",
        "result_sha256",
    }
    if set(raw) != required:
        raise QueueConflictError(
            f"result keys mismatch; missing={sorted(required - set(raw))}, "
            f"extra={sorted(set(raw) - required)}"
        )
    if raw["version"] != RESULT_VERSION:
        raise QueueConflictError(f"unsupported result version: {raw['version']!r}")
    if not isinstance(raw["id"], str) or not REQUEST_ID_RE.fullmatch(raw["id"]):
        raise QueueConflictError("result id is invalid")
    if not isinstance(raw["request_sha256"], str) or not SHA256_RE.fullmatch(raw["request_sha256"]):
        raise QueueConflictError("result request_sha256 is invalid")
    if raw["relay_status"] not in {
        "completed",
        "reconciled_completed",
        "reconciliation_required",
        "relay_error",
        "rejected",
    }:
        raise QueueConflictError("result relay_status is invalid")
    if not isinstance(raw["live"], bool) or not isinstance(raw["reexecuted"], bool):
        raise QueueConflictError("result live/reexecuted fields must be booleans")
    for key in ("executor_result", "reconciliation"):
        if raw[key] is not None and not isinstance(raw[key], dict):
            raise QueueConflictError(f"result {key} must be object or null")
    if raw["error"] is not None and not isinstance(raw["error"], str):
        raise QueueConflictError("result error must be string or null")
    if not isinstance(raw["implementation_sha"], str) or not raw["implementation_sha"]:
        raise QueueConflictError("result implementation_sha is invalid")
    if raw["queue_head_at_receive"] is not None and not isinstance(
        raw["queue_head_at_receive"], str
    ):
        raise QueueConflictError("result queue_head_at_receive must be string or null")
    if not isinstance(raw["published_at"], str) or not raw["published_at"]:
        raise QueueConflictError("result published_at is invalid")
    claimed = raw["result_sha256"]
    if not isinstance(claimed, str) or not SHA256_RE.fullmatch(claimed):
        raise QueueConflictError("result_sha256 is invalid")
    actual = result_digest(raw)
    if claimed != actual:
        raise QueueConflictError(f"result_sha256 mismatch: claimed={claimed}, actual={actual}")
    return dict(raw)


def make_result(
    *,
    request: Mapping[str, Any],
    relay_status: str,
    live: bool,
    implementation_sha: str,
    queue_head_at_receive: str | None,
    executor_result: Mapping[str, Any] | None = None,
    reconciliation: Mapping[str, Any] | None = None,
    reexecuted: bool = False,
    error: str | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "version": RESULT_VERSION,
        "id": request["id"],
        "request_sha256": request["request_sha256"],
        "action": request.get("action"),
        "relay_status": relay_status,
        "live": bool(live),
        "executor_result": _redact_value(dict(executor_result)) if executor_result else None,
        "reconciliation": _redact_value(dict(reconciliation)) if reconciliation else None,
        "reexecuted": bool(reexecuted),
        "error": _redact_text(error) if error else None,
        "implementation_sha": implementation_sha,
        "queue_head_at_receive": queue_head_at_receive,
        "published_at": _utc_now_iso(),
    }
    if len(_canonical_json(body).encode("utf-8")) > MAX_RESULT_BYTES:
        body["executor_result"] = {
            "omitted": True,
            "reason": "executor_result_exceeded_transport_limit",
            "limit_bytes": MAX_RESULT_BYTES,
        }
        body["reconciliation"] = None
        body["error"] = "relay result payload exceeded transport limit"
    body["result_sha256"] = result_digest(body)
    return body


def default_state_root() -> Path:
    override = os.environ.get("PC_RELAY_STATE_DIR")
    if override:
        return Path(override)
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA") or Path.home())
        return root / "pc-relay-hardening"
    root = Path(os.environ.get("XDG_STATE_HOME") or (Path.home() / ".local" / "state"))
    return root / "pc-relay-hardening"


def _run_git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        text=True,
        capture_output=True,
        check=check,
    )


class GitQueue:
    def __init__(self, repo: Path, *, queue_ref: str, metadata_path: Path) -> None:
        self.repo = repo.resolve()
        self.queue_ref = queue_ref
        self.remote_tracking_ref = f"refs/remotes/origin/{queue_ref}"
        self.metadata_path = metadata_path
        self.last_remote_sha: str | None = None
        if metadata_path.exists():
            try:
                meta = json.loads(metadata_path.read_text(encoding="utf-8"))
                value = meta.get("last_remote_sha")
                if isinstance(value, str) and value:
                    self.last_remote_sha = value
            except (OSError, json.JSONDecodeError):
                pass

    @property
    def requests_dir(self) -> Path:
        return self.repo / "relay" / "requests"

    @property
    def results_dir(self) -> Path:
        return self.repo / "relay" / "results"

    def head_sha(self) -> str | None:
        result = _run_git(self.repo, "rev-parse", "HEAD", check=False)
        return result.stdout.strip() if result.returncode == 0 else None

    def _remote_sha(self) -> str:
        result = _run_git(self.repo, "rev-parse", "--verify", self.remote_tracking_ref)
        return result.stdout.strip()

    def _is_ancestor(self, older: str, newer: str) -> bool:
        result = _run_git(self.repo, "merge-base", "--is-ancestor", older, newer, check=False)
        return result.returncode == 0

    def _fetch(self) -> str:
        spec = f"+refs/heads/{self.queue_ref}:{self.remote_tracking_ref}"
        result = _run_git(self.repo, "fetch", "--no-tags", "origin", spec, check=False)
        if result.returncode != 0:
            raise QueueIntegrityError(
                f"queue fetch failed: {(result.stderr or result.stdout).strip()}"
            )
        return self._remote_sha()

    def _save_remote(self, sha: str) -> None:
        self.last_remote_sha = sha
        _atomic_json(
            self.metadata_path,
            {
                "version": QUEUE_PROTOCOL_VERSION,
                "queue_ref": self.queue_ref,
                "last_remote_sha": sha,
                "updated_at": _utc_now_iso(),
            },
        )

    def _prepare_clean_checkout(self) -> None:
        status = _run_git(self.repo, "status", "--porcelain").stdout.strip()
        if not status:
            return
        allowed_prefixes = (
            "relay/results/",
            "relay/heartbeat/",
            "relay/quarantine/",
        )
        dirty_paths: list[str] = []
        for line in status.splitlines():
            if len(line) < 4:
                raise QueueConflictError("unparseable queue checkout status")
            raw_path = line[3:].strip().replace("\\", "/")
            if " -> " in raw_path:
                raw_path = raw_path.split(" -> ", 1)[1]
            dirty_paths.append(raw_path)
        if not dirty_paths or not all(
            path.startswith(allowed_prefixes) for path in dirty_paths
        ):
            raise QueueConflictError(
                "queue checkout contains non-transport uncommitted changes"
            )
        _run_git(self.repo, "reset", "--hard", "HEAD")
        _run_git(
            self.repo,
            "clean",
            "-fd",
            "--",
            "relay/results",
            "relay/heartbeat",
            "relay/quarantine",
        )

    def _local_only_paths_are_transport_owned(self, remote: str) -> bool:
        diff = _run_git(
            self.repo,
            "diff",
            "--name-only",
            f"{remote}...HEAD",
            check=False,
        )
        if diff.returncode != 0:
            return False
        allowed_prefixes = (
            "relay/results/",
            "relay/heartbeat/",
            "relay/quarantine/",
        )
        paths = [line.strip().replace("\\", "/") for line in diff.stdout.splitlines() if line.strip()]
        return bool(paths) and all(path.startswith(allowed_prefixes) for path in paths)

    def sync(self) -> str:
        self._prepare_clean_checkout()
        remote = self._fetch()
        if self.last_remote_sha and remote != self.last_remote_sha:
            if not self._is_ancestor(self.last_remote_sha, remote):
                raise QueueForcePushError(
                    f"queue remote no longer descends from last seen SHA {self.last_remote_sha}"
                )

        local = self.head_sha()
        if local is None:
            raise QueueIntegrityError("queue checkout has no HEAD")
        if local == remote:
            self._save_remote(remote)
            return remote

        if self._is_ancestor(local, remote):
            _run_git(self.repo, "merge", "--ff-only", remote)
            self._save_remote(remote)
            return remote

        if self._is_ancestor(remote, local):
            pushed = _run_git(
                self.repo,
                "push",
                "origin",
                f"HEAD:refs/heads/{self.queue_ref}",
                check=False,
            )
            if pushed.returncode == 0:
                remote = self._fetch()
                self._save_remote(remote)
                return remote

        remote = self._fetch()
        if self.last_remote_sha and remote != self.last_remote_sha:
            if not self._is_ancestor(self.last_remote_sha, remote):
                raise QueueForcePushError(
                    f"queue remote was rewritten from last seen SHA {self.last_remote_sha}"
                )
        if not self._local_only_paths_are_transport_owned(remote):
            raise QueueConflictError(
                "queue branch diverged with non-transport local commits; refusing destructive reconciliation"
            )

        _run_git(self.repo, "reset", "--hard", remote)
        self._save_remote(remote)
        return remote

    def _commit_and_push(self, path: Path, message: str, *, mutable: bool) -> None:
        relative = path.relative_to(self.repo).as_posix()
        _run_git(self.repo, "add", relative)
        staged = _run_git(self.repo, "diff", "--cached", "--quiet", check=False)
        if staged.returncode == 0:
            return

        _run_git(
            self.repo,
            "-c",
            "user.name=PC Relay Hardened",
            "-c",
            "user.email=pc-relay@local.invalid",
            "commit",
            "-m",
            message,
        )
        for _ in range(3):
            pushed = _run_git(
                self.repo,
                "push",
                "origin",
                f"HEAD:refs/heads/{self.queue_ref}",
                check=False,
            )
            if pushed.returncode == 0:
                remote = self._fetch()
                self._save_remote(remote)
                return

            remote = self._fetch()
            if self.last_remote_sha and remote != self.last_remote_sha:
                if not self._is_ancestor(self.last_remote_sha, remote):
                    raise QueueForcePushError("queue remote force-push detected during publication")
            if not self._local_only_paths_are_transport_owned(remote):
                raise QueueConflictError("non-transport divergence during queue publication")
            payload = path.read_bytes() if path.exists() else None
            _run_git(self.repo, "reset", "--hard", remote)
            if payload is None:
                raise QueueConflictError("publication payload disappeared during reconciliation")
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                existing = path.read_bytes()
                if not mutable and existing != payload:
                    raise QueueConflictError(f"immutable queue object conflict: {relative}")
                if existing == payload:
                    self._save_remote(remote)
                    return
            path.write_bytes(payload)
            _run_git(self.repo, "add", relative)
            staged = _run_git(self.repo, "diff", "--cached", "--quiet", check=False)
            if staged.returncode == 0:
                self._save_remote(remote)
                return
            _run_git(
                self.repo,
                "-c",
                "user.name=PC Relay Hardened",
                "-c",
                "user.email=pc-relay@local.invalid",
                "commit",
                "-m",
                message,
            )
        raise QueueConflictError(f"failed to publish queue object after bounded retries: {relative}")

    def read_result(self, request_id: str) -> dict[str, Any] | None:
        path = self.results_dir / f"{request_id}.json"
        if not path.exists():
            return None
        if path.stat().st_size > MAX_RESULT_BYTES:
            raise QueueConflictError(f"result {request_id} exceeds transport size limit")
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise QueueConflictError(f"result {request_id} is not an object")
        return validate_result(raw)

    def publish_result(self, result: Mapping[str, Any]) -> None:
        result = validate_result(result)
        path = self.results_dir / f"{result['id']}.json"
        encoded = (json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        if path.exists():
            existing = path.read_bytes()
            if existing == encoded:
                return
            try:
                parsed = validate_result(json.loads(existing.decode("utf-8")))
            except Exception as exc:
                raise QueueConflictError(
                    f"existing result {result['id']} is malformed/conflicting"
                ) from exc
            if parsed["result_sha256"] == result["result_sha256"]:
                return
            raise QueueConflictError(f"result already published with different content: {result['id']}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(encoded)
        self._commit_and_push(path, f"relay result {result['id']}", mutable=False)

    def publish_quarantine(self, metadata: Mapping[str, Any]) -> None:
        digest = str(metadata["raw_sha256"])
        stem = re.sub(r"[^A-Za-z0-9._-]", "_", str(metadata.get("source_name") or "request"))[:80]
        path = self.repo / "relay" / "quarantine" / f"{stem}.{digest[:16]}.json"
        payload = dict(metadata)
        encoded = (json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        if path.exists():
            existing = path.read_bytes()
            if existing == encoded:
                return
            try:
                previous = json.loads(existing.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise QueueConflictError(
                    f"existing quarantine record is malformed: {path.name}"
                ) from exc
            if (
                isinstance(previous, dict)
                and previous.get("raw_sha256") == digest
                and previous.get("source_name") == metadata.get("source_name")
            ):
                return
            raise QueueConflictError(
                f"quarantine identity conflict: {path.name}"
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(encoded)
        self._commit_and_push(path, f"relay quarantine {stem}", mutable=False)

    def publish_heartbeat(self, heartbeat_id: str, payload: Mapping[str, Any]) -> None:
        if not REQUEST_ID_RE.fullmatch(heartbeat_id):
            raise ValueError("heartbeat id must use request-id safe characters")
        path = self.repo / "relay" / "heartbeat" / f"{heartbeat_id}.json"
        _atomic_json(path, payload)
        self._commit_and_push(path, f"relay heartbeat {heartbeat_id}", mutable=True)


class Relay:
    def __init__(
        self,
        *,
        queue: Any,
        state_root: Path,
        executor: Any,
        implementation_sha: str,
        live: bool,
        allowed_actions: set[str] | frozenset[str] = DEFAULT_ALLOWED_ACTIONS,
        heartbeat_id: str = "default",
        heartbeat_seconds: float = DEFAULT_HEARTBEAT_SECONDS,
    ) -> None:
        if not set(allowed_actions).issubset(MAX_ALLOWED_ACTIONS):
            raise ValueError("allowed_actions cannot exceed MAX_ALLOWED_ACTIONS")
        self.queue = queue
        self.state_root = state_root.resolve()
        self.executor = executor
        self.implementation_sha = implementation_sha
        self.live = live
        self.allowed_actions = frozenset(allowed_actions)
        self.heartbeat_id = heartbeat_id
        self.heartbeat_seconds = max(5.0, float(heartbeat_seconds))
        self._last_heartbeat_monotonic: float | None = None
        self.state_dir = self.state_root / "requests"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.last_processed_request: str | None = None
        self.stop_event = threading.Event()
        self.queue_reachable = False
        self.executor_available = executor is not None
        self.queue_integrity = "ok"
        self.queue_remote_sha: str | None = None

    def _state_path(self, request_id: str) -> Path:
        return self.state_dir / f"{request_id}.json"

    def _read_state(self, request_id: str) -> dict[str, Any] | None:
        path = self._state_path(request_id)
        if not path.exists():
            return None
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or raw.get("version") != STATE_VERSION:
            raise RelayError(f"invalid durable state for request {request_id}")
        return raw

    def _write_state(
        self,
        request: Mapping[str, Any],
        *,
        status: str,
        result: Mapping[str, Any] | None = None,
        reexecution_count: int = 0,
    ) -> None:
        _atomic_json(
            self._state_path(str(request["id"])),
            {
                "version": STATE_VERSION,
                "id": request["id"],
                "request_sha256": request["request_sha256"],
                "action": request["action"],
                "status": status,
                "live": self.live,
                "request": dict(request),
                "result": dict(result) if result is not None else None,
                "reexecution_count": reexecution_count,
                "updated_at": _utc_now_iso(),
            },
        )

    def _quarantine(self, request_path: Path, raw: bytes, error: Exception) -> None:
        metadata = {
            "version": "pc_relay.quarantine.v1",
            "source_name": request_path.name,
            "raw_sha256": _sha256_bytes(raw),
            "bytes": len(raw),
            "error_kind": type(error).__name__,
            "error": _redact_text(str(error))[:2048],
            "observed_at": _utc_now_iso(),
            "raw_content_committed": False,
        }
        self.queue.publish_quarantine(metadata)

    def _recover_finished_states(self) -> None:
        for path in sorted(self.state_dir.glob("*.json")):
            try:
                state = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if (
                isinstance(state, dict)
                and state.get("version") == STATE_VERSION
                and state.get("status") == "finished"
                and isinstance(state.get("result"), dict)
            ):
                self.queue.publish_result(state["result"])

    def _lookup_outcome(self, request: Mapping[str, Any]) -> dict[str, Any]:
        return self.executor.read_outcome_evidence(
            request_id=request["id"],
            action=request["action"],
            execution_attempt=None,
        )

    def _execute(self, request: Mapping[str, Any]) -> dict[str, Any]:
        payload = {
            "request_id": request["id"],
            "action": request["action"],
            "params": request["params"],
            "dry_run": not self.live,
            "timeout_ms": request["timeout_ms"],
        }
        result = self.executor.execute(ActionRequest.from_dict(payload))
        if hasattr(result, "to_dict"):
            return result.to_dict()
        if isinstance(result, dict):
            return dict(result)
        raise RelayError("executor returned unsupported result type")

    def process_request_path(self, request_path: Path) -> dict[str, Any] | None:
        raw_bytes = request_path.read_bytes()
        if len(raw_bytes) > MAX_REQUEST_BYTES:
            exc = RequestValidationError(
                f"request exceeds {MAX_REQUEST_BYTES} byte transport limit"
            )
            self._quarantine(request_path, raw_bytes, exc)
            return None

        try:
            raw = _load_json_bytes(raw_bytes, where=request_path.name)
            request = validate_request(raw, self.allowed_actions)
            if request_path.stem != request["id"]:
                raise RequestValidationError("request filename stem must equal immutable request id")
        except Exception as exc:
            self._quarantine(request_path, raw_bytes, exc)
            return None

        state = self._read_state(request["id"])
        if state is not None and state.get("request_sha256") != request["request_sha256"]:
            exc = QueueConflictError(
                f"duplicate request id {request['id']} changed content digest"
            )
            self._quarantine(request_path, raw_bytes, exc)
            return None

        published = self.queue.read_result(request["id"])
        if published is not None:
            if published["request_sha256"] != request["request_sha256"]:
                exc = QueueConflictError(
                    f"published result for {request['id']} belongs to a different request digest"
                )
                self._quarantine(request_path, raw_bytes, exc)
                return None
            if state is None or state.get("status") != "finished":
                self._write_state(request, status="finished", result=published)
            self.last_processed_request = request["id"]
            return published

        reexecution_count = int((state or {}).get("reexecution_count") or 0)
        if state is None:
            self._write_state(request, status="received")
            state = self._read_state(request["id"])

        if state and state.get("status") == "finished" and isinstance(state.get("result"), dict):
            self.queue.publish_result(state["result"])
            self.last_processed_request = request["id"]
            return state["result"]

        reexecuted = False
        if state and state.get("status") == "dispatch_started":
            if request["action"] not in READ_ONLY_ACTIONS:
                reconciliation = self._lookup_outcome(request)
                outcome = reconciliation.get("outcome")
                if outcome == "completed":
                    result = make_result(
                        request=request,
                        relay_status="reconciled_completed",
                        live=self.live,
                        implementation_sha=self.implementation_sha,
                        queue_head_at_receive=self.queue_remote_sha,
                        reconciliation=reconciliation,
                        reexecuted=False,
                    )
                    self._write_state(
                        request,
                        status="finished",
                        result=result,
                        reexecution_count=reexecution_count,
                    )
                    self.queue.publish_result(result)
                    self.last_processed_request = request["id"]
                    return result
                if outcome != "not_started":
                    result = make_result(
                        request=request,
                        relay_status="reconciliation_required",
                        live=self.live,
                        implementation_sha=self.implementation_sha,
                        queue_head_at_receive=self.queue_remote_sha,
                        reconciliation=reconciliation,
                        reexecuted=False,
                        error="side-effect outcome is unknown; relay refused blind replay",
                    )
                    self._write_state(
                        request,
                        status="finished",
                        result=result,
                        reexecution_count=reexecution_count,
                    )
                    self.queue.publish_result(result)
                    self.last_processed_request = request["id"]
                    return result
                reexecution_count += 1
                reexecuted = True

        self._write_state(
            request,
            status="dispatch_started",
            reexecution_count=reexecution_count,
        )
        try:
            executor_result = self._execute(request)
            result = make_result(
                request=request,
                relay_status="completed",
                live=self.live,
                implementation_sha=self.implementation_sha,
                queue_head_at_receive=self.queue_remote_sha,
                executor_result=executor_result,
                reexecuted=reexecuted,
            )
        except Exception as exc:
            reconciliation: dict[str, Any] | None = None
            status = "relay_error"
            if request["action"] not in READ_ONLY_ACTIONS:
                try:
                    reconciliation = self._lookup_outcome(request)
                    if reconciliation.get("outcome") in {"completed", "unknown"}:
                        status = (
                            "reconciled_completed"
                            if reconciliation.get("outcome") == "completed"
                            else "reconciliation_required"
                        )
                except Exception as lookup_exc:
                    reconciliation = {
                        "outcome": "unknown",
                        "reason": f"outcome lookup failed: {type(lookup_exc).__name__}",
                        "replay_authorized": False,
                    }
                    status = "reconciliation_required"
            result = make_result(
                request=request,
                relay_status=status,
                live=self.live,
                implementation_sha=self.implementation_sha,
                queue_head_at_receive=self.queue_remote_sha,
                reconciliation=reconciliation,
                reexecuted=reexecuted,
                error=f"{type(exc).__name__}: {exc}",
            )

        self._write_state(
            request,
            status="finished",
            result=result,
            reexecution_count=reexecution_count,
        )
        self.queue.publish_result(result)
        self.last_processed_request = request["id"]
        return result

    def heartbeat(self, *, alive: bool = True) -> dict[str, Any]:
        return {
            "version": HEARTBEAT_VERSION,
            "relay_alive": bool(alive),
            "queue_reachable": bool(self.queue_reachable),
            "executor_available": bool(self.executor_available),
            "queue_integrity": self.queue_integrity,
            "last_processed_request": self.last_processed_request,
            "implementation_sha": self.implementation_sha,
            "queue_ref": self.queue.queue_ref,
            "queue_remote_sha": self.queue_remote_sha,
            "generated_at": _utc_now_iso(),
        }

    def _maybe_publish_heartbeat(
        self,
        *,
        alive: bool = True,
        force: bool = False,
    ) -> None:
        now = time.monotonic()
        due = (
            self._last_heartbeat_monotonic is None
            or now - self._last_heartbeat_monotonic >= self.heartbeat_seconds
        )
        if not force and not due:
            return
        self.queue.publish_heartbeat(
            self.heartbeat_id,
            self.heartbeat(alive=alive),
        )
        self._last_heartbeat_monotonic = now

    def health_cycle(self) -> None:
        """Sync queue state and publish health without processing any request."""
        try:
            self.queue_remote_sha = self.queue.sync()
            self.queue_reachable = True
            self.queue_integrity = "ok"
        except QueueForcePushError:
            self.queue_reachable = True
            self.queue_integrity = "force_push_detected"
            raise
        except QueueIntegrityError:
            self.queue_reachable = False
            self.queue_integrity = "degraded"
            raise
        self._maybe_publish_heartbeat(alive=True, force=True)

    def cycle(self) -> int:
        try:
            self.queue_remote_sha = self.queue.sync()
            self.queue_reachable = True
            self.queue_integrity = "ok"
        except QueueForcePushError:
            self.queue_reachable = True
            self.queue_integrity = "force_push_detected"
            raise
        except QueueIntegrityError:
            self.queue_reachable = False
            self.queue_integrity = "degraded"
            raise

        self._recover_finished_states()
        processed = 0
        self.queue.requests_dir.mkdir(parents=True, exist_ok=True)
        for path in sorted(self.queue.requests_dir.glob("*.json")):
            before = self.last_processed_request
            self.process_request_path(path)
            if self.last_processed_request != before:
                processed += 1
        self._maybe_publish_heartbeat(alive=True)
        return processed

    def stop(self) -> None:
        self.stop_event.set()

    def run_forever(self, poll_seconds: float) -> None:
        while not self.stop_event.is_set():
            try:
                self.cycle()
            except Exception as exc:
                print(
                    f"[pc-relay] cycle error: {type(exc).__name__}: {exc}",
                    file=sys.stderr,
                    flush=True,
                )
            self.stop_event.wait(max(0.5, poll_seconds))
        try:
            if self.queue_reachable:
                self._maybe_publish_heartbeat(alive=False, force=True)
        except Exception:
            pass


def _implementation_sha(repo: Path) -> str:
    result = _run_git(repo, "rev-parse", "HEAD")
    return result.stdout.strip()


def build_executor(state_root: Path, *, live: bool) -> Executor:
    state_root.mkdir(parents=True, exist_ok=True)
    shell = SafeShellAdapter(
        allow_executables=set(RELAY_SHELL_EXECUTABLES),
        timeout_seconds=MAX_TIMEOUT_MS / 1000.0,
        output_limit_bytes=SHELL_OUTPUT_LIMIT_BYTES,
    )
    return Executor(
        shell=shell,
        audit=JsonlAuditSink(str(state_root / "audit.jsonl")),
        outcome_journal=OutcomeJournal(str(state_root / "outcome-journal-v1.jsonl")),
        dry_run=not live,
        allow_coordinate_fallback=False,
        operation_timeout_seconds=MAX_TIMEOUT_MS / 1000.0,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Production Git-backed transport for pc_executor.Executor"
    )
    parser.add_argument("--implementation-repo", default=".")
    parser.add_argument("--queue-repo", required=True)
    parser.add_argument("--queue-ref", default=DEFAULT_QUEUE_REF)
    parser.add_argument("--state-dir")
    parser.add_argument("--heartbeat-id", default="default")
    parser.add_argument("--poll-seconds", type=float, default=3.0)
    parser.add_argument(
        "--heartbeat-seconds",
        type=float,
        default=DEFAULT_HEARTBEAT_SECONDS,
    )
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument(
        "--health-only",
        action="store_true",
        help="with --once, sync and publish heartbeat without processing requests",
    )
    parser.add_argument(
        "--disable-action",
        action="append",
        default=[],
        help="reduce the fixed relay action allowlist; this option cannot add actions",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.health_only and (not args.once or args.live):
        raise SystemExit("--health-only requires --once and cannot be combined with --live")
    implementation_repo = Path(args.implementation_repo).resolve()
    queue_repo = Path(args.queue_repo).resolve()
    if implementation_repo == queue_repo:
        raise SystemExit("implementation and queue repositories must be separate checkouts")
    if not (implementation_repo / ".git").exists():
        raise SystemExit(f"not a Git implementation checkout: {implementation_repo}")
    if not (queue_repo / ".git").exists():
        raise SystemExit(f"not a Git queue checkout: {queue_repo}")

    disabled = set(args.disable_action)
    unknown_disabled = disabled - MAX_ALLOWED_ACTIONS
    if unknown_disabled:
        raise SystemExit(f"unknown actions in --disable-action: {sorted(unknown_disabled)}")
    allowed = set(DEFAULT_ALLOWED_ACTIONS) - disabled

    state_root = Path(args.state_dir).resolve() if args.state_dir else default_state_root()
    implementation_sha = _implementation_sha(implementation_repo)
    queue = GitQueue(
        queue_repo,
        queue_ref=args.queue_ref,
        metadata_path=state_root / "queue-history.json",
    )
    executor = build_executor(state_root, live=args.live)
    relay = Relay(
        queue=queue,
        state_root=state_root,
        executor=executor,
        implementation_sha=implementation_sha,
        live=args.live,
        allowed_actions=allowed,
        heartbeat_id=args.heartbeat_id,
        heartbeat_seconds=max(5.0, args.heartbeat_seconds),
    )

    def _stop(_signum: int, _frame: Any) -> None:
        relay.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _stop)
        except (ValueError, OSError):
            pass

    if args.once:
        if args.health_only:
            relay.health_cycle()
        else:
            relay.cycle()
        return 0
    relay.run_forever(args.poll_seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
