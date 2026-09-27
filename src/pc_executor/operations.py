from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence
from uuid import uuid4

from .cancellation import CancellationToken
from .errors import OperationCancelledError, OperationTimeoutError, PolicyBlockedError
from .safety import SafetyViolation, ensure_path_allowed, ensure_resolved_path_allowed
from .shell import SafeShellAdapter


OPS_CONTRACT_VERSION = "pc_executor.ops.v1"
CURSOR_VERSION = "pc_executor.stream_cursor.v1"
LOG_CURSOR_VERSION = "pc_executor.log_cursor.v1"
PROCESS_HANDLE_VERSION = "pc_executor.process_handle.v1"

MAX_TEXT_READ_BYTES = 1024 * 1024
MAX_BINARY_READ_BYTES = 1024 * 1024
MAX_HASH_BYTES = 1024 * 1024 * 1024
MAX_COPY_BYTES = 256 * 1024 * 1024
MAX_LIST_RESULTS = 500
MAX_FIND_DEPTH = 32
MAX_LOG_LINES = 2000
MAX_LOG_BYTES = 1024 * 1024
MAX_LOG_MATCHES = 500
MAX_PROCESS_RESULTS = 500
MAX_PROCESS_OUTPUT_BYTES = 256 * 1024
MAX_READ_OUTPUT_BYTES = 64 * 1024
MAX_SESSION_INPUT_BYTES = 64 * 1024
MAX_ENV_ENTRIES = 128
MAX_ENV_VALUE_BYTES = 16 * 1024

FS_READ_ACTIONS = frozenset(
    {
        "fs.list",
        "fs.stat",
        "fs.read_text",
        "fs.read_bytes",
        "fs.hash",
        "fs.find",
        "fs.glob",
    }
)
FS_WRITE_ACTIONS = frozenset(
    {
        "fs.write_text",
        "fs.append_text",
        "fs.mkdir",
        "fs.copy",
        "fs.move",
        "fs.delete",
    }
)
LOG_ACTIONS = frozenset({"log.tail", "log.read_since", "log.search"})
PROCESS_READ_ACTIONS = frozenset(
    {"process.list", "process.inspect", "process.status", "process.read_output"}
)
PROCESS_WRITE_ACTIONS = frozenset({"process.start", "process.terminate"})
SESSION_READ_ACTIONS = frozenset({"shell.session.read"})
SESSION_WRITE_ACTIONS = frozenset(
    {
        "shell.session.start",
        "shell.session.write_stdin",
        "shell.session.terminate",
    }
)
SYSTEM_ACTIONS = frozenset({"system.info", "system.resources", "system.paths"})
OPS_READ_ONLY_ACTIONS = frozenset(
    FS_READ_ACTIONS | LOG_ACTIONS | PROCESS_READ_ACTIONS | SESSION_READ_ACTIONS | SYSTEM_ACTIONS
)
OPS_SIDE_EFFECT_ACTIONS = frozenset(
    FS_WRITE_ACTIONS | PROCESS_WRITE_ACTIONS | SESSION_WRITE_ACTIONS
)
OPS_ACTIONS = frozenset(OPS_READ_ONLY_ACTIONS | OPS_SIDE_EFFECT_ACTIONS)

_SENSITIVE_PATH_NAMES = {
    ".env",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    "credentials.json",
    "secrets.json",
    "id_rsa",
    "id_ed25519",
}
_SENSITIVE_ENV_RE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|credential|private[_-]?key)"
)
_SENSITIVE_STDIN_RE = re.compile(
    r"(?i)(captcha|password\s*[:=]|passwd\s*[:=]|secret\s*[:=]|"
    r"token\s*[:=]|api[_-]?key\s*[:=]|credential\s*[:=])"
)
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


def _utc_now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _sha256_file(path: Path, *, max_bytes: int, token: CancellationToken | None = None) -> str:
    size = path.stat().st_size
    if size > max_bytes:
        raise SafetyViolation(
            f"file exceeds hash bound: {size} bytes > {max_bytes} bytes"
        )
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            if token is not None:
                token.raise_if_cancelled()
            chunk = handle.read(64 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _path_digest(path: Path) -> str:
    normalized = os.path.normcase(os.path.normpath(str(path)))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _file_identity(path: Path) -> tuple[int | None, int | None]:
    try:
        stat = path.stat()
    except OSError:
        return None, None
    return int(stat.st_dev), int(stat.st_ino)


def _assert_nonsensitive_path(path: Path) -> None:
    name = path.name.casefold()
    if name in _SENSITIVE_PATH_NAMES or name.startswith("secrets."):
        raise SafetyViolation(
            f"sensitive credential/config path is not readable through structured ops: {path.name}"
        )


def _ensure_file(path: Path) -> None:
    if not path.exists():
        raise SafetyViolation(f"path does not exist: {path}")
    if not path.is_file():
        raise SafetyViolation(f"path is not a regular file: {path}")


def _ensure_dir(path: Path) -> None:
    if not path.exists():
        raise SafetyViolation(f"path does not exist: {path}")
    if not path.is_dir():
        raise SafetyViolation(f"path is not a directory: {path}")


def _text(value: Any, where: str, *, max_length: int = 32768) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{where} must be a string")
    if len(value) > max_length:
        raise ValueError(f"{where} exceeds maximum length {max_length}")
    return value


def _nonempty(value: Any, where: str, *, max_length: int = 32768) -> str:
    result = _text(value, where, max_length=max_length)
    if not result:
        raise ValueError(f"{where} must not be empty")
    return result


def _integer(
    value: Any,
    where: str,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{where} must be an integer")
    if minimum is not None and value < minimum:
        raise ValueError(f"{where} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{where} must be <= {maximum}")
    return value


def _boolean(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{where} must be a boolean")
    return value


def _optional_bool(value: Any, where: str, default: bool = False) -> bool:
    return default if value is None else _boolean(value, where)


def _exact_params(
    action: str,
    params: Mapping[str, Any],
    allowed: set[str],
    required: set[str],
) -> None:
    unknown = set(params) - allowed
    missing = required - set(params)
    if unknown or missing:
        raise ValueError(
            f"{action} params mismatch; missing={sorted(missing)}, extra={sorted(unknown)}"
        )


def _encoding(params: Mapping[str, Any]) -> str:
    value = params.get("encoding", "utf-8")
    value = _nonempty(value, "encoding", max_length=40)
    try:
        "".encode(value)
    except LookupError as exc:
        raise ValueError(f"unknown text encoding: {value}") from exc
    return value


def validate_ops_params(action: str, params: Mapping[str, Any]) -> None:
    if action not in OPS_ACTIONS:
        raise ValueError(f"unsupported structured operation: {action}")
    if not isinstance(params, Mapping):
        raise ValueError(f"{action} params must be an object")

    schemas: dict[str, tuple[set[str], set[str]]] = {
        "fs.list": ({"path", "max_entries", "include_hidden"}, {"path"}),
        "fs.stat": ({"path"}, {"path"}),
        "fs.read_text": (
            {"path", "encoding", "start_line", "end_line", "max_bytes"},
            {"path"},
        ),
        "fs.read_bytes": ({"path", "offset", "max_bytes"}, {"path"}),
        "fs.hash": ({"path", "max_bytes"}, {"path"}),
        "fs.find": (
            {"path", "name_contains", "max_results", "max_depth"},
            {"path"},
        ),
        "fs.glob": ({"path", "pattern", "max_results"}, {"path", "pattern"}),
        "fs.write_text": (
            {
                "path",
                "text",
                "encoding",
                "expected_current_hash",
                "create_only",
                "overwrite",
            },
            {"path", "text"},
        ),
        "fs.append_text": (
            {"path", "text", "encoding", "expected_current_hash", "create"},
            {"path", "text"},
        ),
        "fs.mkdir": ({"path", "parents", "exist_ok"}, {"path"}),
        "fs.copy": (
            {"source", "destination", "overwrite", "expected_source_hash"},
            {"source", "destination"},
        ),
        "fs.move": (
            {"source", "destination", "overwrite", "expected_source_hash"},
            {"source", "destination"},
        ),
        "fs.delete": (
            {"path", "classification", "expected_current_hash"},
            {"path", "classification"},
        ),
        "log.tail": ({"path", "encoding", "max_lines", "max_bytes"}, {"path"}),
        "log.read_since": (
            {"path", "encoding", "cursor", "max_bytes"},
            {"path"},
        ),
        "log.search": (
            {
                "path",
                "pattern",
                "regex",
                "case_sensitive",
                "encoding",
                "max_matches",
                "max_bytes",
            },
            {"path", "pattern"},
        ),
        "process.list": ({"pid", "name_contains", "max_results"}, set()),
        "process.inspect": ({"pid"}, {"pid"}),
        "process.start": (
            {"argv", "cwd", "env", "inherit_env", "output_limit_bytes"},
            {"argv"},
        ),
        "process.status": ({"handle_id"}, {"handle_id"}),
        "process.read_output": (
            {"handle_id", "cursor", "max_bytes", "wait_ms"},
            {"handle_id"},
        ),
        "process.terminate": ({"handle_id", "grace_ms"}, {"handle_id"}),
        "shell.session.start": (
            {"argv", "cwd", "env", "inherit_env", "output_limit_bytes"},
            {"argv"},
        ),
        "shell.session.read": (
            {"session_id", "cursor", "max_bytes", "wait_ms"},
            {"session_id"},
        ),
        "shell.session.write_stdin": (
            {"session_id", "text", "append_newline", "sensitive"},
            {"session_id", "text"},
        ),
        "shell.session.terminate": (
            {"session_id", "grace_ms"},
            {"session_id"},
        ),
        "system.info": (set(), set()),
        "system.resources": ({"path"}, set()),
        "system.paths": ({"path"}, set()),
    }
    allowed, required = schemas[action]
    _exact_params(action, params, allowed, required)

    for key in ("path", "source", "destination", "cwd"):
        if key in params and params[key] is not None:
            _nonempty(params[key], f"{action} {key}", max_length=4096)

    if action == "fs.list":
        _integer(params.get("max_entries", 200), "fs.list max_entries", minimum=1, maximum=MAX_LIST_RESULTS)
        _optional_bool(params.get("include_hidden"), "fs.list include_hidden")
    elif action == "fs.read_text":
        start = _integer(params.get("start_line", 1), "fs.read_text start_line", minimum=1)
        end = params.get("end_line")
        if end is not None and _integer(end, "fs.read_text end_line", minimum=start) < start:
            raise ValueError("fs.read_text end_line must be >= start_line")
        _integer(params.get("max_bytes", 256 * 1024), "fs.read_text max_bytes", minimum=1, maximum=MAX_TEXT_READ_BYTES)
        _encoding(params)
    elif action == "fs.read_bytes":
        _integer(params.get("offset", 0), "fs.read_bytes offset", minimum=0)
        _integer(params.get("max_bytes", 256 * 1024), "fs.read_bytes max_bytes", minimum=1, maximum=MAX_BINARY_READ_BYTES)
    elif action == "fs.hash":
        _integer(params.get("max_bytes", MAX_HASH_BYTES), "fs.hash max_bytes", minimum=1, maximum=MAX_HASH_BYTES)
    elif action == "fs.find":
        if params.get("name_contains") is not None:
            _text(params["name_contains"], "fs.find name_contains", max_length=512)
        _integer(params.get("max_results", 200), "fs.find max_results", minimum=1, maximum=MAX_LIST_RESULTS)
        _integer(params.get("max_depth", 8), "fs.find max_depth", minimum=0, maximum=MAX_FIND_DEPTH)
    elif action == "fs.glob":
        pattern = _nonempty(params["pattern"], "fs.glob pattern", max_length=512)
        if Path(pattern).is_absolute() or ".." in Path(pattern).parts:
            raise ValueError("fs.glob pattern must be relative and must not contain parent traversal")
        _integer(params.get("max_results", 200), "fs.glob max_results", minimum=1, maximum=MAX_LIST_RESULTS)
    elif action == "fs.write_text":
        _text(params["text"], "fs.write_text text", max_length=MAX_TEXT_READ_BYTES)
        _encoding(params)
        expected = params.get("expected_current_hash")
        if expected is not None and (not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected)):
            raise ValueError("fs.write_text expected_current_hash must be lowercase SHA-256 or null")
        create_only = _optional_bool(params.get("create_only"), "fs.write_text create_only")
        overwrite = _optional_bool(params.get("overwrite"), "fs.write_text overwrite")
        if create_only and overwrite:
            raise ValueError("fs.write_text create_only and overwrite are mutually exclusive")
    elif action == "fs.append_text":
        _text(params["text"], "fs.append_text text", max_length=MAX_TEXT_READ_BYTES)
        _encoding(params)
        expected = params.get("expected_current_hash")
        if expected is not None and (not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected)):
            raise ValueError("fs.append_text expected_current_hash must be lowercase SHA-256 or null")
        _optional_bool(params.get("create"), "fs.append_text create")
    elif action == "fs.mkdir":
        _optional_bool(params.get("parents"), "fs.mkdir parents")
        _optional_bool(params.get("exist_ok"), "fs.mkdir exist_ok")
    elif action in {"fs.copy", "fs.move"}:
        _optional_bool(params.get("overwrite"), f"{action} overwrite")
        expected = params.get("expected_source_hash")
        if expected is not None and (not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected)):
            raise ValueError(f"{action} expected_source_hash must be lowercase SHA-256 or null")
    elif action == "fs.delete":
        if params["classification"] not in {"file", "empty_directory"}:
            raise ValueError("fs.delete classification must be file or empty_directory")
        expected = params.get("expected_current_hash")
        if expected is not None and (not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected)):
            raise ValueError("fs.delete expected_current_hash must be lowercase SHA-256 or null")
        if params["classification"] == "file" and expected is None:
            raise ValueError("fs.delete file classification requires expected_current_hash")
    elif action in {"log.tail", "log.read_since"}:
        _encoding(params)
        if action == "log.tail":
            _integer(params.get("max_lines", 200), "log.tail max_lines", minimum=1, maximum=MAX_LOG_LINES)
        _integer(params.get("max_bytes", 256 * 1024), f"{action} max_bytes", minimum=1, maximum=MAX_LOG_BYTES)
        if action == "log.read_since" and params.get("cursor") is not None:
            _validate_log_cursor(params["cursor"])
    elif action == "log.search":
        _nonempty(params["pattern"], "log.search pattern", max_length=512)
        _optional_bool(params.get("regex"), "log.search regex")
        _optional_bool(params.get("case_sensitive"), "log.search case_sensitive", default=True)
        _encoding(params)
        _integer(params.get("max_matches", 100), "log.search max_matches", minimum=1, maximum=MAX_LOG_MATCHES)
        _integer(params.get("max_bytes", 512 * 1024), "log.search max_bytes", minimum=1, maximum=MAX_LOG_BYTES)
        if params.get("regex"):
            try:
                re.compile(params["pattern"])
            except re.error as exc:
                raise ValueError(f"invalid log.search regex: {exc}") from exc
    elif action == "process.list":
        if params.get("pid") is not None:
            _integer(params["pid"], "process.list pid", minimum=1)
        if params.get("name_contains") is not None:
            _text(params["name_contains"], "process.list name_contains", max_length=256)
        _integer(params.get("max_results", 200), "process.list max_results", minimum=1, maximum=MAX_PROCESS_RESULTS)
    elif action == "process.inspect":
        _integer(params["pid"], "process.inspect pid", minimum=1)
    elif action in {"process.start", "shell.session.start"}:
        _validate_start_params(action, params)
    elif action in {"process.status", "process.read_output", "process.terminate"}:
        _nonempty(params["handle_id"], f"{action} handle_id", max_length=128)
        if action == "process.read_output":
            if params.get("cursor") is not None:
                _validate_stream_cursor(params["cursor"], params["handle_id"])
            _integer(params.get("max_bytes", MAX_READ_OUTPUT_BYTES), "process.read_output max_bytes", minimum=1, maximum=MAX_READ_OUTPUT_BYTES)
            _integer(params.get("wait_ms", 0), "process.read_output wait_ms", minimum=0, maximum=2000)
        if action == "process.terminate":
            _integer(params.get("grace_ms", 1000), "process.terminate grace_ms", minimum=0, maximum=5000)
    elif action in {"shell.session.read", "shell.session.write_stdin", "shell.session.terminate"}:
        session_id = _nonempty(params["session_id"], f"{action} session_id", max_length=128)
        if action == "shell.session.read":
            if params.get("cursor") is not None:
                _validate_stream_cursor(params["cursor"], session_id)
            _integer(params.get("max_bytes", MAX_READ_OUTPUT_BYTES), "shell.session.read max_bytes", minimum=1, maximum=MAX_READ_OUTPUT_BYTES)
            _integer(params.get("wait_ms", 0), "shell.session.read wait_ms", minimum=0, maximum=2000)
        elif action == "shell.session.write_stdin":
            value = _text(params["text"], "shell.session.write_stdin text", max_length=MAX_SESSION_INPUT_BYTES)
            if len(value.encode("utf-8")) > MAX_SESSION_INPUT_BYTES:
                raise ValueError("shell.session.write_stdin text exceeds byte bound")
            _optional_bool(params.get("append_newline"), "shell.session.write_stdin append_newline")
            sensitive = _optional_bool(params.get("sensitive"), "shell.session.write_stdin sensitive")
            if sensitive or _SENSITIVE_STDIN_RE.search(value):
                raise SafetyViolation("credential/CAPTCHA session input is forbidden")
        else:
            _integer(params.get("grace_ms", 1000), "shell.session.terminate grace_ms", minimum=0, maximum=5000)


def _validate_start_params(action: str, params: Mapping[str, Any]) -> None:
    argv = params["argv"]
    if not isinstance(argv, list) or not argv or any(not isinstance(item, str) or not item for item in argv):
        raise ValueError(f"{action} argv must be a non-empty array of non-empty strings")
    if len(argv) > 128 or sum(len(item) for item in argv) > 32768:
        raise ValueError(f"{action} argv exceeds transport bounds")
    env = params.get("env")
    if env is not None:
        if not isinstance(env, Mapping) or len(env) > MAX_ENV_ENTRIES:
            raise ValueError(f"{action} env must be an object with at most {MAX_ENV_ENTRIES} entries")
        for key, value in env.items():
            if not isinstance(key, str) or not _ENV_NAME_RE.fullmatch(key):
                raise ValueError(f"{action} env key is invalid")
            if _SENSITIVE_ENV_RE.search(key):
                raise SafetyViolation(f"{action} sensitive environment key is forbidden: {key}")
            if not isinstance(value, str) or len(value.encode("utf-8")) > MAX_ENV_VALUE_BYTES:
                raise ValueError(f"{action} env value is invalid or too large")
    _optional_bool(params.get("inherit_env"), f"{action} inherit_env", default=True)
    _integer(params.get("output_limit_bytes", MAX_PROCESS_OUTPUT_BYTES), f"{action} output_limit_bytes", minimum=1024, maximum=MAX_PROCESS_OUTPUT_BYTES)


def _validate_stream_cursor(value: Any, handle_id: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("stream cursor must be an object")
    expected = {"version", "handle_id", "stdout_offset", "stderr_offset"}
    if set(value) != expected:
        raise ValueError("stream cursor keys mismatch")
    if value["version"] != CURSOR_VERSION or value["handle_id"] != handle_id:
        raise ValueError("stream cursor version/handle mismatch")
    _integer(value["stdout_offset"], "stream cursor stdout_offset", minimum=0)
    _integer(value["stderr_offset"], "stream cursor stderr_offset", minimum=0)
    return dict(value)


def _validate_log_cursor(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("log cursor must be an object")
    expected = {"version", "path_sha256", "device", "inode", "offset"}
    if set(value) != expected or value["version"] != LOG_CURSOR_VERSION:
        raise ValueError("log cursor schema/version mismatch")
    path_sha = value["path_sha256"]
    if not isinstance(path_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", path_sha):
        raise ValueError("log cursor path_sha256 is invalid")
    for key in ("device", "inode"):
        if value[key] is not None:
            _integer(value[key], f"log cursor {key}", minimum=0)
    _integer(value["offset"], "log cursor offset", minimum=0)
    return dict(value)


@dataclass
class _ByteWindow:
    limit: int
    buffer: bytearray = field(default_factory=bytearray)
    base_offset: int = 0
    total_offset: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def append(self, data: bytes) -> None:
        if not data:
            return
        with self.lock:
            self.buffer.extend(data)
            self.total_offset += len(data)
            if len(self.buffer) > self.limit:
                excess = len(self.buffer) - self.limit
                del self.buffer[:excess]
                self.base_offset += excess

    def read(self, offset: int, max_bytes: int) -> tuple[bytes, int, bool]:
        with self.lock:
            truncated = offset < self.base_offset
            start = max(offset, self.base_offset) - self.base_offset
            data = bytes(self.buffer[start : start + max_bytes])
            next_offset = max(offset, self.base_offset) + len(data)
            return data, next_offset, truncated


@dataclass
class _ManagedProcess:
    handle_id: str
    kind: str
    process: subprocess.Popen[bytes]
    executable: str
    started_at: str
    generation_id: str
    stdout: _ByteWindow
    stderr: _ByteWindow


class ManagedProcessRegistry:
    def __init__(self, state_path: Path, *, generation_id: str) -> None:
        self.state_path = state_path
        self.generation_id = generation_id
        self.live: dict[str, _ManagedProcess] = {}
        self.stale: dict[str, dict[str, Any]] = {}
        self.lock = threading.Lock()
        self._load_stale()

    def _load_stale(self) -> None:
        if not self.state_path.exists():
            return
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        records = raw.get("handles") if isinstance(raw, dict) else None
        if not isinstance(records, list):
            return
        for item in records:
            if isinstance(item, dict) and isinstance(item.get("handle_id"), str):
                self.stale[item["handle_id"]] = dict(item)

    def _persist(self) -> None:
        records: list[dict[str, Any]] = []
        for handle in self.live.values():
            records.append(
                {
                    "version": PROCESS_HANDLE_VERSION,
                    "handle_id": handle.handle_id,
                    "kind": handle.kind,
                    "pid": int(handle.process.pid),
                    "executable": handle.executable,
                    "started_at": handle.started_at,
                    "generation_id": handle.generation_id,
                }
            )
        records.extend(self.stale.values())
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        with temp.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(
                {"version": PROCESS_HANDLE_VERSION, "handles": records},
                handle,
                sort_keys=True,
                indent=2,
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, self.state_path)

    def register(
        self,
        process: subprocess.Popen[bytes],
        *,
        kind: str,
        executable: str,
        output_limit: int,
    ) -> _ManagedProcess:
        handle_id = f"{kind}:{uuid4()}"
        item = _ManagedProcess(
            handle_id=handle_id,
            kind=kind,
            process=process,
            executable=executable,
            started_at=_utc_now_iso(),
            generation_id=self.generation_id,
            stdout=_ByteWindow(output_limit),
            stderr=_ByteWindow(output_limit),
        )
        with self.lock:
            self.live[handle_id] = item
            self._persist()
        self._reader(item, process.stdout, item.stdout, "stdout")
        self._reader(item, process.stderr, item.stderr, "stderr")
        return item

    def _reader(
        self,
        item: _ManagedProcess,
        stream: io.BufferedReader | None,
        target: _ByteWindow,
        name: str,
    ) -> None:
        if stream is None:
            return

        def worker() -> None:
            try:
                while True:
                    chunk = stream.read(4096)
                    if not chunk:
                        return
                    target.append(chunk)
            finally:
                try:
                    stream.close()
                except OSError:
                    pass

        threading.Thread(
            target=worker,
            name=f"pc-executor-{name}-{item.handle_id[-8:]}",
            daemon=True,
        ).start()

    def get(self, handle_id: str, *, kind: str | None = None) -> _ManagedProcess:
        with self.lock:
            item = self.live.get(handle_id)
            if item is not None:
                if kind is not None and item.kind != kind:
                    raise SafetyViolation("managed handle kind mismatch")
                return item
            stale = self.stale.get(handle_id)
        if stale is not None:
            raise SafetyViolation(
                "managed handle belongs to a previous gateway generation; "
                "restart semantics forbid stdin/output/termination"
            )
        raise SafetyViolation(f"unknown managed handle: {handle_id}")

    def status(self, handle_id: str) -> dict[str, Any]:
        with self.lock:
            item = self.live.get(handle_id)
            stale = self.stale.get(handle_id)
        if item is None:
            if stale is None:
                raise SafetyViolation(f"unknown managed handle: {handle_id}")
            return {
                "handle_id": handle_id,
                "kind": stale.get("kind"),
                "pid": stale.get("pid"),
                "status": "stale_after_restart",
                "owned_by_current_gateway": False,
                "returncode": None,
            }
        code = item.process.poll()
        return {
            "handle_id": handle_id,
            "kind": item.kind,
            "pid": int(item.process.pid),
            "status": "running" if code is None else "exited",
            "owned_by_current_gateway": True,
            "returncode": code,
        }


class LocalOperations:
    def __init__(
        self,
        *,
        shell: SafeShellAdapter,
        state_root: str | Path | None = None,
    ) -> None:
        self.shell = shell
        root = Path(state_root) if state_root is not None else self.default_state_root()
        self.state_root = root
        self.generation_id = str(uuid4())
        self.registry = ManagedProcessRegistry(
            root / "managed-processes.v1.json",
            generation_id=self.generation_id,
        )

    @staticmethod
    def default_state_root() -> Path:
        if os.name == "nt":
            root = Path(os.environ.get("LOCALAPPDATA") or Path.home())
        else:
            root = Path(
                os.environ.get("XDG_STATE_HOME")
                or Path.home() / ".local" / "state"
            )
        return root / "pc-executor" / "operations"

    def preflight(self, action: str, params: Mapping[str, Any]) -> None:
        validate_ops_params(action, params)
        if action.startswith("fs.") or action.startswith("log."):
            self._preflight_path_action(action, params)
        elif action in {"process.start", "shell.session.start"}:
            self.shell.validate(params["argv"], cwd=params.get("cwd"))
            if params.get("cwd") is not None:
                ensure_resolved_path_allowed(params["cwd"])
        elif action in {
            "process.status",
            "process.read_output",
            "process.terminate",
        }:
            if action == "process.status":
                self.registry.status(params["handle_id"])
            else:
                self.registry.get(params["handle_id"], kind="process")
        elif action.startswith("shell.session.") and action != "shell.session.start":
            self.registry.get(params["session_id"], kind="session")
        elif action == "system.paths" and params.get("path") is not None:
            ensure_resolved_path_allowed(params["path"])
        elif action == "system.resources" and params.get("path") is not None:
            ensure_resolved_path_allowed(params["path"])

    def _preflight_path_action(self, action: str, params: Mapping[str, Any]) -> None:
        if action in {"fs.copy", "fs.move"}:
            source = ensure_resolved_path_allowed(params["source"])
            destination = ensure_resolved_path_allowed(
                params["destination"], for_creation=True
            )
            _ensure_file(source)
            _assert_nonsensitive_path(source)
            if source.stat().st_size > MAX_COPY_BYTES:
                raise SafetyViolation(
                    f"source exceeds structured copy/move bound: {source.stat().st_size} bytes"
                )
            if destination.exists() and not params.get("overwrite", False):
                raise SafetyViolation(f"destination exists and overwrite=false: {destination}")
            expected = params.get("expected_source_hash")
            if expected is not None and _sha256_file(source, max_bytes=MAX_HASH_BYTES) != expected:
                raise SafetyViolation("source changed: expected_source_hash mismatch")
            return

        path = ensure_resolved_path_allowed(
            params["path"],
            for_creation=action in {"fs.write_text", "fs.append_text", "fs.mkdir"},
        )
        if action in FS_READ_ACTIONS or action in LOG_ACTIONS:
            if action in {"fs.list", "fs.find", "fs.glob"}:
                _ensure_dir(path)
            else:
                _ensure_file(path)
                _assert_nonsensitive_path(path)
            return
        if action == "fs.write_text":
            create_only = bool(params.get("create_only", False))
            overwrite = bool(params.get("overwrite", False))
            expected = params.get("expected_current_hash")
            if path.exists():
                _ensure_file(path)
                if create_only:
                    raise SafetyViolation("fs.write_text create_only target already exists")
                if expected is not None:
                    actual = _sha256_file(path, max_bytes=MAX_HASH_BYTES)
                    if actual != expected:
                        raise SafetyViolation("fs.write_text expected_current_hash mismatch")
                elif not overwrite:
                    raise SafetyViolation(
                        "fs.write_text existing target requires expected_current_hash or overwrite=true"
                    )
            elif expected is not None:
                raise SafetyViolation("fs.write_text expected_current_hash requires existing target")
            return
        if action == "fs.append_text":
            if path.exists():
                _ensure_file(path)
                if path.stat().st_size > MAX_COPY_BYTES:
                    raise SafetyViolation(
                        f"append target exceeds structured append bound: {path.stat().st_size} bytes"
                    )
                expected = params.get("expected_current_hash")
                if expected is not None:
                    actual = _sha256_file(path, max_bytes=MAX_HASH_BYTES)
                    if actual != expected:
                        raise SafetyViolation("fs.append_text expected_current_hash mismatch")
            elif not params.get("create", False):
                raise SafetyViolation("fs.append_text target missing and create=false")
            return
        if action == "fs.mkdir":
            if path.exists() and not params.get("exist_ok", False):
                raise SafetyViolation("fs.mkdir target exists and exist_ok=false")
            return
        if action == "fs.delete":
            _ensure_file(path) if params["classification"] == "file" else _ensure_dir(path)
            if path.is_symlink():
                raise SafetyViolation("fs.delete refuses symbolic-link targets")
            if params["classification"] == "file":
                actual = _sha256_file(path, max_bytes=MAX_HASH_BYTES)
                if actual != params["expected_current_hash"]:
                    raise SafetyViolation("fs.delete expected_current_hash mismatch")

    def execute(
        self,
        action: str,
        params: Mapping[str, Any],
        *,
        cancellation: CancellationToken | None = None,
    ) -> dict[str, Any]:
        token = cancellation or CancellationToken()
        token.raise_if_cancelled()
        self.preflight(action, params)

        if action == "fs.list":
            return self._fs_list(params, token)
        if action == "fs.stat":
            return self._fs_stat(params)
        if action == "fs.read_text":
            return self._fs_read_text(params, token)
        if action == "fs.read_bytes":
            return self._fs_read_bytes(params)
        if action == "fs.hash":
            return self._fs_hash(params, token)
        if action == "fs.find":
            return self._fs_find(params, token)
        if action == "fs.glob":
            return self._fs_glob(params, token)
        if action == "fs.write_text":
            return self._fs_write_text(params, token)
        if action == "fs.append_text":
            return self._fs_append_text(params, token)
        if action == "fs.mkdir":
            return self._fs_mkdir(params)
        if action == "fs.copy":
            return self._fs_copy(params, token)
        if action == "fs.move":
            return self._fs_move(params, token)
        if action == "fs.delete":
            return self._fs_delete(params)
        if action == "log.tail":
            return self._log_tail(params)
        if action == "log.read_since":
            return self._log_read_since(params)
        if action == "log.search":
            return self._log_search(params, token)
        if action == "process.list":
            return self._process_list(params)
        if action == "process.inspect":
            return self._process_inspect(params["pid"])
        if action == "process.start":
            return self._start(params, kind="process")
        if action == "process.status":
            return self.registry.status(params["handle_id"])
        if action == "process.read_output":
            return self._read_output(
                params["handle_id"], params, kind="process"
            )
        if action == "process.terminate":
            return self._terminate(
                params["handle_id"], params, kind="process", token=token
            )
        if action == "shell.session.start":
            return self._start(params, kind="session")
        if action == "shell.session.read":
            return self._read_output(
                params["session_id"], params, kind="session"
            )
        if action == "shell.session.write_stdin":
            return self._write_stdin(params)
        if action == "shell.session.terminate":
            return self._terminate(
                params["session_id"], params, kind="session", token=token
            )
        if action == "system.info":
            return self._system_info()
        if action == "system.resources":
            return self._system_resources(params)
        if action == "system.paths":
            return self._system_paths(params)
        raise ValueError(f"unsupported structured operation: {action}")

    def _fs_list(self, params: Mapping[str, Any], token: CancellationToken) -> dict[str, Any]:
        path = ensure_resolved_path_allowed(params["path"])
        limit = int(params.get("max_entries", 200))
        include_hidden = bool(params.get("include_hidden", False))
        entries = []
        for child in sorted(path.iterdir(), key=lambda p: p.name.casefold()):
            token.raise_if_cancelled()
            if not include_hidden and child.name.startswith("."):
                continue
            try:
                resolved = ensure_resolved_path_allowed(child)
            except SafetyViolation:
                continue
            stat = resolved.stat()
            entries.append(
                {
                    "name": child.name,
                    "path": str(resolved),
                    "kind": "directory" if resolved.is_dir() else "file" if resolved.is_file() else "other",
                    "bytes": int(stat.st_size),
                    "modified_ns": int(stat.st_mtime_ns),
                    "symlink": child.is_symlink(),
                }
            )
            if len(entries) >= limit:
                break
        return {"path": str(path), "entries": entries, "count": len(entries), "limit": limit}

    def _fs_stat(self, params: Mapping[str, Any]) -> dict[str, Any]:
        raw = Path(params["path"])
        symlink = raw.is_symlink()
        path = ensure_resolved_path_allowed(params["path"])
        stat = path.stat()
        return {
            "path": str(path),
            "exists": True,
            "kind": "directory" if path.is_dir() else "file" if path.is_file() else "other",
            "bytes": int(stat.st_size),
            "modified_ns": int(stat.st_mtime_ns),
            "device": int(stat.st_dev),
            "inode": int(stat.st_ino),
            "symlink": symlink,
        }

    def _fs_read_text(self, params: Mapping[str, Any], token: CancellationToken) -> dict[str, Any]:
        path = ensure_resolved_path_allowed(params["path"])
        _assert_nonsensitive_path(path)
        encoding = _encoding(params)
        start = int(params.get("start_line", 1))
        end = params.get("end_line")
        max_bytes = int(params.get("max_bytes", 256 * 1024))
        lines: list[str] = []
        used = 0
        truncated = False
        next_line = start
        with path.open("r", encoding=encoding, errors="strict", newline="") as handle:
            for number, line in enumerate(handle, start=1):
                token.raise_if_cancelled()
                if number < start:
                    continue
                if end is not None and number > int(end):
                    break
                encoded = line.encode(encoding)
                if used + len(encoded) > max_bytes:
                    truncated = True
                    break
                lines.append(line)
                used += len(encoded)
                next_line = number + 1
        return {
            "path": str(path),
            "encoding": encoding,
            "start_line": start,
            "next_line": next_line,
            "text": "".join(lines),
            "returned_bytes": used,
            "truncated": truncated,
            "sha256": _sha256_file(path, max_bytes=MAX_HASH_BYTES, token=token),
        }

    def _fs_read_bytes(self, params: Mapping[str, Any]) -> dict[str, Any]:
        path = ensure_resolved_path_allowed(params["path"])
        _assert_nonsensitive_path(path)
        offset = int(params.get("offset", 0))
        max_bytes = int(params.get("max_bytes", 256 * 1024))
        size = path.stat().st_size
        if offset > size:
            offset = size
        with path.open("rb") as handle:
            handle.seek(offset)
            raw = handle.read(max_bytes)
        return {
            "path": str(path),
            "offset": offset,
            "next_offset": offset + len(raw),
            "data_base64": base64.b64encode(raw).decode("ascii"),
            "returned_bytes": len(raw),
            "file_bytes": int(size),
            "truncated": offset + len(raw) < size,
        }

    def _fs_hash(self, params: Mapping[str, Any], token: CancellationToken) -> dict[str, Any]:
        path = ensure_resolved_path_allowed(params["path"])
        _assert_nonsensitive_path(path)
        maximum = int(params.get("max_bytes", MAX_HASH_BYTES))
        return {
            "path": str(path),
            "algorithm": "sha256",
            "sha256": _sha256_file(path, max_bytes=maximum, token=token),
            "bytes": int(path.stat().st_size),
        }

    def _fs_find(self, params: Mapping[str, Any], token: CancellationToken) -> dict[str, Any]:
        root = ensure_resolved_path_allowed(params["path"])
        needle = str(params.get("name_contains") or "").casefold()
        limit = int(params.get("max_results", 200))
        max_depth = int(params.get("max_depth", 8))
        results: list[str] = []
        root_parts = len(root.parts)
        for current, dirs, files in os.walk(root, followlinks=False):
            token.raise_if_cancelled()
            current_path = Path(current)
            depth = len(current_path.parts) - root_parts
            if depth >= max_depth:
                dirs[:] = []
            safe_dirs = []
            for name in dirs:
                candidate = current_path / name
                if candidate.is_symlink():
                    continue
                try:
                    ensure_resolved_path_allowed(candidate)
                except SafetyViolation:
                    continue
                safe_dirs.append(name)
            dirs[:] = safe_dirs
            for name in sorted([*dirs, *files], key=str.casefold):
                if needle and needle not in name.casefold():
                    continue
                candidate = current_path / name
                try:
                    resolved = ensure_resolved_path_allowed(candidate)
                except SafetyViolation:
                    continue
                results.append(str(resolved))
                if len(results) >= limit:
                    return {"path": str(root), "results": results, "count": len(results), "truncated": True}
        return {"path": str(root), "results": results, "count": len(results), "truncated": False}

    def _fs_glob(self, params: Mapping[str, Any], token: CancellationToken) -> dict[str, Any]:
        root = ensure_resolved_path_allowed(params["path"])
        pattern = params["pattern"]
        limit = int(params.get("max_results", 200))
        results: list[str] = []
        for candidate in sorted(root.glob(pattern), key=lambda p: str(p).casefold()):
            token.raise_if_cancelled()
            if candidate.is_symlink():
                continue
            try:
                resolved = ensure_resolved_path_allowed(candidate)
            except SafetyViolation:
                continue
            results.append(str(resolved))
            if len(results) >= limit:
                return {"path": str(root), "pattern": pattern, "results": results, "count": len(results), "truncated": True}
        return {"path": str(root), "pattern": pattern, "results": results, "count": len(results), "truncated": False}

    def _atomic_replace(self, path: Path, payload: bytes, token: CancellationToken) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        ensure_resolved_path_allowed(path.parent)
        fd, temp_name = tempfile.mkstemp(prefix=".pc-executor-", dir=str(path.parent))
        temp = Path(temp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                for offset in range(0, len(payload), 64 * 1024):
                    token.raise_if_cancelled()
                    handle.write(payload[offset : offset + 64 * 1024])
                handle.flush()
                os.fsync(handle.fileno())
            token.raise_if_cancelled()
            os.replace(temp, path)
        finally:
            try:
                if temp.exists():
                    temp.unlink()
            except OSError:
                pass

    def _atomic_copy_with_suffix(
        self,
        source: Path | None,
        destination: Path,
        suffix: bytes,
        token: CancellationToken,
    ) -> int:
        destination.parent.mkdir(parents=True, exist_ok=True)
        ensure_resolved_path_allowed(destination.parent)
        fd, temp_name = tempfile.mkstemp(prefix=".pc-executor-", dir=str(destination.parent))
        temp = Path(temp_name)
        total = 0
        try:
            with os.fdopen(fd, "wb") as output:
                if source is not None:
                    with source.open("rb") as input_handle:
                        while True:
                            token.raise_if_cancelled()
                            chunk = input_handle.read(64 * 1024)
                            if not chunk:
                                break
                            total += len(chunk)
                            if total > MAX_COPY_BYTES:
                                raise SafetyViolation("structured copy/append bound exceeded")
                            output.write(chunk)
                if suffix:
                    token.raise_if_cancelled()
                    output.write(suffix)
                    total += len(suffix)
                output.flush()
                os.fsync(output.fileno())
            token.raise_if_cancelled()
            os.replace(temp, destination)
            return total
        finally:
            try:
                if temp.exists():
                    temp.unlink()
            except OSError:
                pass

    def _fs_write_text(self, params: Mapping[str, Any], token: CancellationToken) -> dict[str, Any]:
        path = ensure_resolved_path_allowed(params["path"], for_creation=True)
        self._preflight_path_action("fs.write_text", params)
        payload = params["text"].encode(_encoding(params))
        if len(payload) > MAX_TEXT_READ_BYTES:
            raise SafetyViolation("fs.write_text encoded payload exceeds byte bound")
        self._atomic_replace(path, payload, token)
        return {
            "path": str(path),
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "atomic_replace": True,
        }

    def _fs_append_text(self, params: Mapping[str, Any], token: CancellationToken) -> dict[str, Any]:
        path = ensure_resolved_path_allowed(params["path"], for_creation=True)
        self._preflight_path_action("fs.append_text", params)
        encoding = _encoding(params)
        expected = params.get("expected_current_hash")
        if expected is not None and path.exists():
            actual = _sha256_file(path, max_bytes=MAX_COPY_BYTES, token=token)
            if actual != expected:
                raise SafetyViolation("fs.append_text expected_current_hash mismatch")
        addition = params["text"].encode(encoding)
        if len(addition) > MAX_TEXT_READ_BYTES:
            raise SafetyViolation("fs.append_text encoded payload exceeds byte bound")
        total = self._atomic_copy_with_suffix(
            path if path.exists() else None,
            path,
            addition,
            token,
        )
        digest = _sha256_file(path, max_bytes=MAX_COPY_BYTES, token=token)
        return {
            "path": str(path),
            "appended_bytes": len(addition),
            "bytes": total,
            "sha256": digest,
            "atomic_replace": True,
        }

    def _fs_mkdir(self, params: Mapping[str, Any]) -> dict[str, Any]:
        path = ensure_resolved_path_allowed(params["path"], for_creation=True)
        path.mkdir(
            parents=bool(params.get("parents", False)),
            exist_ok=bool(params.get("exist_ok", False)),
        )
        return {"path": str(path), "created": True}

    def _fs_copy(self, params: Mapping[str, Any], token: CancellationToken) -> dict[str, Any]:
        source = ensure_resolved_path_allowed(params["source"])
        destination = ensure_resolved_path_allowed(params["destination"], for_creation=True)
        self._preflight_path_action("fs.copy", params)
        total = self._atomic_copy_with_suffix(source, destination, b"", token)
        return {
            "source": str(source),
            "destination": str(destination),
            "bytes": total,
            "sha256": _sha256_file(destination, max_bytes=MAX_COPY_BYTES, token=token),
            "atomic_replace": True,
        }

    def _fs_move(self, params: Mapping[str, Any], token: CancellationToken) -> dict[str, Any]:
        source = ensure_resolved_path_allowed(params["source"])
        destination = ensure_resolved_path_allowed(params["destination"], for_creation=True)
        self._preflight_path_action("fs.move", params)
        token.raise_if_cancelled()
        try:
            source_device = source.stat().st_dev
            destination_device = destination.parent.stat().st_dev
        except OSError as exc:
            raise SafetyViolation(f"fs.move identity check failed: {exc}") from exc
        if source_device != destination_device:
            raise SafetyViolation("fs.move requires source/destination on the same filesystem")
        os.replace(source, destination)
        return {"source": str(source), "destination": str(destination), "atomic_move": True}

    def _fs_delete(self, params: Mapping[str, Any]) -> dict[str, Any]:
        path = ensure_resolved_path_allowed(params["path"])
        self._preflight_path_action("fs.delete", params)
        if params["classification"] == "file":
            path.unlink()
        else:
            path.rmdir()
        return {"path": str(path), "classification": params["classification"], "deleted": True}

    def _log_tail(self, params: Mapping[str, Any]) -> dict[str, Any]:
        path = ensure_resolved_path_allowed(params["path"])
        _assert_nonsensitive_path(path)
        max_bytes = int(params.get("max_bytes", 256 * 1024))
        max_lines = int(params.get("max_lines", 200))
        size = path.stat().st_size
        start = max(0, size - max_bytes)
        with path.open("rb") as handle:
            handle.seek(start)
            raw = handle.read(max_bytes)
        text = raw.decode(_encoding(params), errors="strict")
        lines = text.splitlines(keepends=True)[-max_lines:]
        return {
            "path": str(path),
            "lines": lines,
            "returned_lines": len(lines),
            "returned_bytes": len("".join(lines).encode(_encoding(params))),
            "file_bytes": int(size),
            "truncated": start > 0,
        }

    def _log_read_since(self, params: Mapping[str, Any]) -> dict[str, Any]:
        path = ensure_resolved_path_allowed(params["path"])
        _assert_nonsensitive_path(path)
        stat = path.stat()
        device, inode = int(stat.st_dev), int(stat.st_ino)
        path_sha = _path_digest(path)
        cursor = params.get("cursor")
        offset = 0
        if cursor is not None:
            cursor = _validate_log_cursor(cursor)
            if cursor["path_sha256"] != path_sha or cursor["device"] != device or cursor["inode"] != inode:
                raise SafetyViolation("log cursor is stale because file identity changed")
            offset = int(cursor["offset"])
        if offset > stat.st_size:
            raise SafetyViolation("log cursor offset exceeds current file size")
        max_bytes = int(params.get("max_bytes", 256 * 1024))
        with path.open("rb") as handle:
            handle.seek(offset)
            raw = handle.read(max_bytes)
        text = raw.decode(_encoding(params), errors="strict")
        next_offset = offset + len(raw)
        next_cursor = {
            "version": LOG_CURSOR_VERSION,
            "path_sha256": path_sha,
            "device": device,
            "inode": inode,
            "offset": next_offset,
        }
        return {
            "path": str(path),
            "text": text,
            "returned_bytes": len(raw),
            "cursor": next_cursor,
            "has_more": next_offset < stat.st_size,
        }

    def _log_search(self, params: Mapping[str, Any], token: CancellationToken) -> dict[str, Any]:
        path = ensure_resolved_path_allowed(params["path"])
        _assert_nonsensitive_path(path)
        max_bytes = int(params.get("max_bytes", 512 * 1024))
        max_matches = int(params.get("max_matches", 100))
        pattern = params["pattern"]
        flags = 0 if params.get("case_sensitive", True) else re.IGNORECASE
        regex = re.compile(pattern, flags) if params.get("regex", False) else None
        matches = []
        consumed = 0
        encoding = _encoding(params)
        with path.open("r", encoding=encoding, errors="strict", newline="") as handle:
            for line_number, line in enumerate(handle, start=1):
                token.raise_if_cancelled()
                encoded = line.encode(encoding)
                if consumed + len(encoded) > max_bytes:
                    break
                consumed += len(encoded)
                haystack = line if params.get("case_sensitive", True) else line.casefold()
                needle = pattern if params.get("case_sensitive", True) else pattern.casefold()
                matched = bool(regex.search(line)) if regex else needle in haystack
                if matched:
                    matches.append(
                        {
                            "line_number": line_number,
                            "text": line[:4096],
                        }
                    )
                    if len(matches) >= max_matches:
                        break
        return {
            "path": str(path),
            "matches": matches,
            "match_count": len(matches),
            "scanned_bytes": consumed,
            "bounded": True,
        }

    def _build_env(self, params: Mapping[str, Any]) -> dict[str, str] | None:
        supplied = params.get("env")
        inherit = bool(params.get("inherit_env", True))
        if supplied is None and inherit:
            return None
        env = dict(os.environ) if inherit else {}
        if supplied:
            env.update({str(key): str(value) for key, value in supplied.items()})
        return env

    def _start(self, params: Mapping[str, Any], *, kind: str) -> dict[str, Any]:
        argv = self.shell.validate(params["argv"], cwd=params.get("cwd"))
        output_limit = int(params.get("output_limit_bytes", MAX_PROCESS_OUTPUT_BYTES))
        process = subprocess.Popen(
            argv,
            cwd=params.get("cwd"),
            env=self._build_env(params),
            shell=False,
            stdin=subprocess.PIPE if kind == "session" else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        item = self.registry.register(
            process,
            kind=kind,
            executable=Path(str(argv[0]).replace("\\", "/")).name.lower(),
            output_limit=output_limit,
        )
        return {
            "version": PROCESS_HANDLE_VERSION,
            "handle_id": item.handle_id,
            "session_id": item.handle_id if kind == "session" else None,
            "pid": int(process.pid),
            "kind": kind,
            "executable": item.executable,
            "started_at": item.started_at,
            "output_limit_bytes": output_limit,
        }

    def _read_output(
        self,
        handle_id: str,
        params: Mapping[str, Any],
        *,
        kind: str,
    ) -> dict[str, Any]:
        item = self.registry.get(handle_id, kind=kind)
        cursor = params.get("cursor")
        if cursor is None:
            out_offset = err_offset = 0
        else:
            parsed = _validate_stream_cursor(cursor, handle_id)
            out_offset = int(parsed["stdout_offset"])
            err_offset = int(parsed["stderr_offset"])
        max_bytes = int(params.get("max_bytes", MAX_READ_OUTPUT_BYTES))
        wait_ms = int(params.get("wait_ms", 0))
        deadline = time.monotonic() + wait_ms / 1000.0
        while wait_ms and time.monotonic() < deadline:
            out, _, _ = item.stdout.read(out_offset, 1)
            err, _, _ = item.stderr.read(err_offset, 1)
            if out or err or item.process.poll() is not None:
                break
            time.sleep(0.02)
        stdout, next_out, out_truncated = item.stdout.read(out_offset, max_bytes)
        stderr, next_err, err_truncated = item.stderr.read(err_offset, max_bytes)
        next_cursor = {
            "version": CURSOR_VERSION,
            "handle_id": handle_id,
            "stdout_offset": next_out,
            "stderr_offset": next_err,
        }
        return {
            "handle_id": handle_id,
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
            "stdout_bytes": len(stdout),
            "stderr_bytes": len(stderr),
            "stdout_truncated_before_cursor": out_truncated,
            "stderr_truncated_before_cursor": err_truncated,
            "cursor": next_cursor,
            "running": item.process.poll() is None,
            "returncode": item.process.poll(),
        }

    def _write_stdin(self, params: Mapping[str, Any]) -> dict[str, Any]:
        session_id = params["session_id"]
        item = self.registry.get(session_id, kind="session")
        if item.process.poll() is not None:
            raise SafetyViolation("session already exited")
        if item.process.stdin is None:
            raise SafetyViolation("session stdin is unavailable")
        text = params["text"] + ("\n" if params.get("append_newline", False) else "")
        if params.get("sensitive", False) or _SENSITIVE_STDIN_RE.search(text):
            raise SafetyViolation("credential/CAPTCHA session input is forbidden")
        raw = text.encode("utf-8")
        item.process.stdin.write(raw)
        item.process.stdin.flush()
        return {"session_id": session_id, "written_bytes": len(raw)}

    def _terminate(
        self,
        handle_id: str,
        params: Mapping[str, Any],
        *,
        kind: str,
        token: CancellationToken,
    ) -> dict[str, Any]:
        item = self.registry.get(handle_id, kind=kind)
        before = item.process.poll()
        if before is not None:
            return {
                "handle_id": handle_id,
                "already_exited": True,
                "returncode": before,
            }
        item.process.terminate()
        grace = int(params.get("grace_ms", 1000)) / 1000.0
        deadline = time.monotonic() + grace
        while item.process.poll() is None and time.monotonic() < deadline:
            token.raise_if_cancelled()
            time.sleep(0.02)
        if item.process.poll() is None:
            item.process.kill()
        return {
            "handle_id": handle_id,
            "already_exited": False,
            "returncode": item.process.wait(timeout=2),
        }

    def _process_list(self, params: Mapping[str, Any]) -> dict[str, Any]:
        limit = int(params.get("max_results", 200))
        pid_filter = params.get("pid")
        name_filter = str(params.get("name_contains") or "").casefold()
        entries: list[dict[str, Any]] = []
        if os.name == "nt":
            output = subprocess.run(
                ["tasklist.exe", "/FO", "CSV", "/NH"],
                text=True,
                capture_output=True,
                check=False,
            ).stdout
            for row in csv.reader(io.StringIO(output)):
                if len(row) < 2:
                    continue
                try:
                    pid = int(row[1])
                except ValueError:
                    continue
                name = row[0]
                if pid_filter is not None and pid != pid_filter:
                    continue
                if name_filter and name_filter not in name.casefold():
                    continue
                entries.append({"pid": pid, "name": name})
                if len(entries) >= limit:
                    break
        else:
            output = subprocess.run(
                ["ps", "-eo", "pid=,ppid=,comm="],
                text=True,
                capture_output=True,
                check=False,
            ).stdout
            for line in output.splitlines():
                parts = line.strip().split(None, 2)
                if len(parts) != 3:
                    continue
                try:
                    pid, ppid = int(parts[0]), int(parts[1])
                except ValueError:
                    continue
                name = parts[2]
                if pid_filter is not None and pid != pid_filter:
                    continue
                if name_filter and name_filter not in name.casefold():
                    continue
                entries.append({"pid": pid, "ppid": ppid, "name": name})
                if len(entries) >= limit:
                    break
        return {"processes": entries, "count": len(entries), "limit": limit}

    def _process_inspect(self, pid: int) -> dict[str, Any]:
        listed = self._process_list({"pid": pid, "max_results": 1})["processes"]
        if not listed:
            raise SafetyViolation(f"process not found: {pid}")
        return listed[0]

    def _system_info(self) -> dict[str, Any]:
        return {
            "platform_system": platform.system() or "unknown",
            "platform_release": platform.release(),
            "platform_machine": platform.machine() or "unknown",
            "os_family": os.name,
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "cpu_count": os.cpu_count(),
        }

    def _system_resources(self, params: Mapping[str, Any]) -> dict[str, Any]:
        target = ensure_resolved_path_allowed(params.get("path") or os.getcwd())
        disk = shutil.disk_usage(target if target.exists() else target.parent)
        load = None
        try:
            load = list(os.getloadavg())
        except (AttributeError, OSError):
            pass
        memory = self._memory_info()
        return {
            "cpu_count": os.cpu_count(),
            "load_average": load,
            "memory": memory,
            "disk": {
                "path": str(target),
                "total_bytes": int(disk.total),
                "used_bytes": int(disk.used),
                "free_bytes": int(disk.free),
            },
            "gpu": None,
        }

    def _memory_info(self) -> dict[str, int] | None:
        if os.name == "nt":
            try:
                import ctypes

                class MemoryStatus(ctypes.Structure):
                    _fields_ = [
                        ("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                    ]

                status = MemoryStatus()
                status.dwLength = ctypes.sizeof(MemoryStatus)
                if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                    return {
                        "total_bytes": int(status.ullTotalPhys),
                        "available_bytes": int(status.ullAvailPhys),
                    }
            except Exception:
                return None
        try:
            page = os.sysconf("SC_PAGE_SIZE")
            total = os.sysconf("SC_PHYS_PAGES")
            available = os.sysconf("SC_AVPHYS_PAGES")
            return {
                "total_bytes": int(page * total),
                "available_bytes": int(page * available),
            }
        except (AttributeError, OSError, ValueError):
            return None

    def _system_paths(self, params: Mapping[str, Any]) -> dict[str, Any]:
        cwd = ensure_resolved_path_allowed(os.getcwd())
        requested = params.get("path")
        result: dict[str, Any] = {
            "cwd": str(cwd),
            "separator": os.sep,
            "path_separator": os.pathsep,
        }
        if requested is not None:
            resolved = ensure_resolved_path_allowed(requested, for_creation=True)
            result["requested"] = {
                "path": str(resolved),
                "exists": resolved.exists(),
                "parent_exists": resolved.parent.exists(),
            }
        return result
