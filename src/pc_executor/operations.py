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
import stat as stat_module
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from uuid import uuid4

from .admin_config import (
    MAX_READ_MANY_BYTES,
    MUTABLE_CONFIG_KEYS,
    AdminConfigStore,
)
from .cancellation import CancellationToken
from .errors import OperationCancelledError, OperationTimeoutError, PolicyBlockedError
from .safety import (
    PROTECTED_WINDOWS_ROOTS,
    SafetyViolation,
    ensure_path_allowed,
    ensure_resolved_path_allowed,
)
from .shell import SafeShellAdapter
from .search_sessions import (
    DEFAULT_SEARCH_RETENTION_SECONDS,
    DEFAULT_SEARCH_TIMEOUT_MS,
    DEFAULT_SEARCH_WORKERS,
    MAX_SEARCH_CONTEXT_CHARS,
    MAX_SEARCH_CONTEXT_LINES,
    MAX_RETAINED_SEARCH_SESSIONS,
    MAX_SEARCH_PAGE_LENGTH,
    MAX_SEARCH_RESULTS,
    MAX_SEARCH_TIMEOUT_MS,
    SEARCH_SESSION_VERSION,
    SearchSession,
    SearchSessionManager,
)


OPS_CONTRACT_VERSION = "pc_executor.ops.v1"
NATIVE_TOOL_PARITY_VERSION = "pc_executor.native_tool_parity.v1"
NATIVE_REQUEST_VERSION = "pc_executor.native_tool_request.v1"
NATIVE_RESULT_VERSION = "pc_executor.native_tool_result.v1"
NATIVE_CAPABILITIES_VERSION = "pc_executor.native_tool_capabilities.v1"
OPS_CAPABILITIES_VERSION = "pc_executor.ops_capabilities.v1"
OPS_PREFLIGHT_VERSION = "pc_executor.ops_preflight.v1"
OPS_CONTEXT_VERSION = "pc_executor.ops_context_binding.v1"
CURSOR_VERSION = "pc_executor.stream_cursor.v1"
LOG_CURSOR_VERSION = "pc_executor.log_cursor.v1"
SEARCH_CURSOR_VERSION = "pc_executor.search_cursor.v1"
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
MAX_READ_MANY_FILES = 64
MAX_AUDIT_HISTORY_RESULTS = 200

FS_READ_ACTIONS = frozenset(
    {
        "fs.list",
        "fs.stat",
        "fs.read_text",
        "fs.read_many",
        "fs.read_bytes",
        "fs.hash",
        "fs.find",
        "fs.glob",
        "fs.search",
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
        "fs.edit_text",
    }
)
LOG_ACTIONS = frozenset({"log.tail", "log.read_since", "log.search"})
SEARCH_READ_ACTIONS = frozenset({"search.read", "search.list"})
SEARCH_SIDE_EFFECT_ACTIONS = frozenset({"search.start", "search.stop"})
PROCESS_READ_ACTIONS = frozenset(
    {
        "process.list",
        "process.inspect",
        "process.status",
        "process.read_output",
        "process.managed.list",
    }
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
SYSTEM_ACTIONS = frozenset(
    {
        "device.info",
        "health.get",
        "config.get",
        "identity.get",
        "audit.history",
        "metrics.get",
        "system.info",
        "system.resources",
        "system.paths",
    }
)
SYSTEM_SIDE_EFFECT_ACTIONS = frozenset({"system.process.kill", "config.set", "device.shutdown"})
OPS_READ_ONLY_ACTIONS = frozenset(
    FS_READ_ACTIONS
    | LOG_ACTIONS
    | SEARCH_READ_ACTIONS
    | PROCESS_READ_ACTIONS
    | SESSION_READ_ACTIONS
    | SYSTEM_ACTIONS
    | {"ops.capabilities.get", "ops.preflight"}
)
OPS_SIDE_EFFECT_ACTIONS = frozenset(
    FS_WRITE_ACTIONS
    | SEARCH_SIDE_EFFECT_ACTIONS
    | PROCESS_WRITE_ACTIONS
    | SESSION_WRITE_ACTIONS
    | SYSTEM_SIDE_EFFECT_ACTIONS
)
OPS_ACTIONS = frozenset(OPS_READ_ONLY_ACTIONS | OPS_SIDE_EFFECT_ACTIONS)


def register_native_outcome_actions() -> frozenset[str]:
    """Extend the frozen action-outcome validator for native actions at runtime."""
    from . import outcome as outcome_contract

    registered = frozenset(
        set(outcome_contract.SIDE_EFFECTING_ACTIONS)
        | set(OPS_SIDE_EFFECT_ACTIONS)
    )
    outcome_contract.SIDE_EFFECTING_ACTIONS = registered
    return registered


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
_SENSITIVE_ARG_RE = re.compile(
    r"(?i)(captcha|--?(?:password|passwd|secret|token|api[_-]?key|credential)(?:=|$))"
)
_POWERSHELL_NAMES = {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}
_CMD_NAMES = {"cmd", "cmd.exe"}
_FORBIDDEN_SHELL_TERMS = (
    "get-credential",
    "read-host -assecurestring",
    "convertto-securestring",
    "set-clipboard",
    "sendkeys",
    "captcha",
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


def _absolute_requested_path(value: str | os.PathLike[str]) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    return path


def _assert_mutation_leaf_not_reparse(value: str | os.PathLike[str]) -> None:
    path = _absolute_requested_path(value)
    try:
        stat = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise SafetyViolation(f"mutation path identity check failed: {path}: {exc}") from exc
    reparse_flag = getattr(stat_module, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = int(getattr(stat, "st_file_attributes", 0) or 0)
    if stat_module.S_ISLNK(stat.st_mode) or attributes & reparse_flag:
        raise SafetyViolation(
            "structured mutations refuse symbolic-link/junction/reparse leaf targets"
        )


def _validate_structured_command(action: str, argv: Sequence[str]) -> None:
    executable = Path(str(argv[0]).replace("\\", "/")).name.lower()
    lowered_args = [str(part).casefold() for part in argv[1:]]
    joined = " ".join(lowered_args)
    for part in argv[1:]:
        if _SENSITIVE_ARG_RE.search(str(part)):
            raise SafetyViolation(
                f"{action} credential/CAPTCHA command arguments are forbidden"
            )
    if executable in _POWERSHELL_NAMES:
        switches = set(lowered_args)
        if "-noprofile" not in switches:
            raise SafetyViolation(
                f"{action} PowerShell requires explicit -NoProfile"
            )
        if "-encodedcommand" in switches or "-enc" in switches:
            raise SafetyViolation(
                f"{action} encoded PowerShell commands are forbidden"
            )
        if action == "process.start" and "-command" not in switches:
            raise SafetyViolation(
                "process.start PowerShell requires explicit -Command"
            )
        for term in _FORBIDDEN_SHELL_TERMS:
            if term in joined:
                raise SafetyViolation(
                    f"{action} interactive credential/CAPTCHA shell term is forbidden: {term}"
                )
    if executable in _CMD_NAMES:
        switches = set(lowered_args)
        if action == "process.start" and "/k" in switches:
            raise SafetyViolation(
                "process.start persistent cmd sessions are forbidden; use shell.session.start"
            )
        for term in _FORBIDDEN_SHELL_TERMS:
            if term in joined:
                raise SafetyViolation(
                    f"{action} interactive credential/CAPTCHA shell term is forbidden: {term}"
                )


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
    if action == "ops.capabilities.get":
        _exact_params(action, params, set(), set())
        return
    if action == "ops.preflight":
        _validate_ops_preflight_payload(params)
        return

    schemas: dict[str, tuple[set[str], set[str]]] = {
        "fs.list": ({"path", "offset", "max_entries", "include_hidden"}, {"path"}),
        "fs.stat": ({"path"}, {"path"}),
        "fs.read_text": (
            {
                "path",
                "encoding",
                "start_line",
                "end_line",
                "tail_lines",
                "max_bytes",
            },
            {"path"},
        ),
        "fs.read_many": (
            {"paths", "encoding", "max_bytes_per_file", "max_total_bytes"},
            {"paths"},
        ),
        "fs.read_bytes": ({"path", "offset", "max_bytes"}, {"path"}),
        "fs.hash": ({"path", "max_bytes"}, {"path"}),
        "fs.find": (
            {"path", "name_contains", "max_results", "max_depth"},
            {"path"},
        ),
        "fs.glob": ({"path", "pattern", "max_results"}, {"path", "pattern"}),
        "fs.search": (
            {
                "path",
                "query",
                "content",
                "case_sensitive",
                "max_results",
                "max_depth",
                "cursor",
            },
            {"path", "query"},
        ),
        "search.start": (
            {
                "path",
                "search_type",
                "pattern",
                "literal_search",
                "ignore_case",
                "context_lines",
                "include_hidden",
                "max_results",
                "timeout_ms",
            },
            {"path", "pattern"},
        ),
        "search.read": ({"search_id", "offset", "length"}, {"search_id"}),
        "search.list": (set(), set()),
        "search.stop": ({"search_id"}, {"search_id"}),
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
        "fs.edit_text": (
            {
                "path",
                "old_text",
                "new_text",
                "expected_replacements",
                "expected_current_hash",
                "encoding",
            },
            {"path", "old_text", "new_text", "expected_current_hash"},
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
        "process.list": ({"pid", "name_contains", "offset", "max_results"}, set()),
        "process.inspect": ({"pid"}, {"pid"}),
        "process.managed.list": ({"kind", "include_stale", "offset", "max_results"}, set()),
        "process.start": (
            {"argv", "cwd", "env", "inherit_env", "output_limit_bytes", "context_binding"},
            {"argv"},
        ),
        "process.status": ({"handle_id"}, {"handle_id"}),
        "process.read_output": (
            {"handle_id", "cursor", "tail_bytes", "max_bytes", "wait_ms"},
            {"handle_id"},
        ),
        "process.terminate": ({"handle_id", "grace_ms"}, {"handle_id"}),
        "shell.session.start": (
            {"argv", "cwd", "env", "inherit_env", "output_limit_bytes"},
            {"argv"},
        ),
        "shell.session.read": (
            {"session_id", "cursor", "tail_bytes", "max_bytes", "wait_ms"},
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
        "device.info": (set(), set()),
        "health.get": (set(), set()),
        "config.get": (set(), set()),
        "config.set": ({"key", "value", "expected_revision"}, {"key", "value"}),
        "device.shutdown": ({"device_id", "session_epoch"}, {"device_id", "session_epoch"}),
        "identity.get": ({"device_id", "session_epoch"}, set()),
        "audit.history": ({"limit"}, set()),
        "metrics.get": (set(), set()),
        "system.info": (set(), set()),
        "system.resources": ({"path"}, set()),
        "system.paths": ({"path"}, set()),
        "system.process.kill": (
            {"pid", "expected_name", "exit_code"},
            {"pid", "expected_name"},
        ),
    }
    allowed, required = schemas[action]
    _exact_params(action, params, allowed, required)

    for key in ("path", "source", "destination", "cwd"):
        if key in params and params[key] is not None:
            _nonempty(params[key], f"{action} {key}", max_length=4096)

    if action == "fs.list":
        _integer(params.get("offset", 0), "fs.list offset", minimum=0, maximum=1000000)
        _integer(params.get("max_entries", 200), "fs.list max_entries", minimum=1, maximum=MAX_LIST_RESULTS)
        _optional_bool(params.get("include_hidden"), "fs.list include_hidden")
    elif action == "fs.read_text":
        start = _integer(params.get("start_line", 1), "fs.read_text start_line", minimum=1)
        end = params.get("end_line")
        tail = params.get("tail_lines")
        if tail is not None:
            _integer(tail, "fs.read_text tail_lines", minimum=1, maximum=MAX_LOG_LINES)
            if "start_line" in params or end is not None:
                raise ValueError(
                    "fs.read_text tail_lines is mutually exclusive with start_line/end_line"
                )
        if end is not None and _integer(end, "fs.read_text end_line", minimum=start) < start:
            raise ValueError("fs.read_text end_line must be >= start_line")
        _integer(params.get("max_bytes", 256 * 1024), "fs.read_text max_bytes", minimum=1, maximum=MAX_TEXT_READ_BYTES)
        _encoding(params)
    elif action == "fs.read_many":
        paths = params["paths"]
        if not isinstance(paths, list) or not (1 <= len(paths) <= MAX_READ_MANY_FILES):
            raise ValueError(f"fs.read_many paths must contain 1..{MAX_READ_MANY_FILES} entries")
        for index, value in enumerate(paths):
            _nonempty(value, f"fs.read_many paths[{index}]", max_length=4096)
        _encoding(params)
        _integer(
            params.get("max_bytes_per_file", 256 * 1024),
            "fs.read_many max_bytes_per_file",
            minimum=1,
            maximum=MAX_TEXT_READ_BYTES,
        )
        _integer(
            params.get("max_total_bytes", 4 * 1024 * 1024),
            "fs.read_many max_total_bytes",
            minimum=1,
            maximum=MAX_READ_MANY_BYTES,
        )
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
    elif action == "fs.search":
        _nonempty(params["query"], "fs.search query", max_length=512)
        _optional_bool(params.get("content"), "fs.search content")
        _optional_bool(params.get("case_sensitive"), "fs.search case_sensitive")
        _integer(params.get("max_results", 100), "fs.search max_results", minimum=1, maximum=MAX_LIST_RESULTS)
        _integer(params.get("max_depth", 8), "fs.search max_depth", minimum=0, maximum=MAX_FIND_DEPTH)
        if params.get("cursor") is not None:
            _validate_search_cursor(params["cursor"])
    elif action == "search.start":
        search_type = params.get("search_type", "files")
        if search_type not in {"files", "content"}:
            raise ValueError("search.start search_type must be files or content")
        pattern = _nonempty(params["pattern"], "search.start pattern", max_length=512)
        literal = _optional_bool(params.get("literal_search"), "search.start literal_search")
        ignore_case = _optional_bool(params.get("ignore_case"), "search.start ignore_case", default=True)
        _optional_bool(params.get("include_hidden"), "search.start include_hidden")
        _integer(params.get("context_lines", 5), "search.start context_lines", minimum=0, maximum=MAX_SEARCH_CONTEXT_LINES)
        _integer(params.get("max_results", 100), "search.start max_results", minimum=1, maximum=MAX_SEARCH_RESULTS)
        _integer(params.get("timeout_ms", DEFAULT_SEARCH_TIMEOUT_MS), "search.start timeout_ms", minimum=1, maximum=MAX_SEARCH_TIMEOUT_MS)
        if not literal:
            try:
                re.compile(pattern, re.IGNORECASE if ignore_case else 0)
            except re.error as exc:
                raise ValueError(f"search.start invalid regular expression: {exc}") from exc
    elif action == "search.read":
        _nonempty(params["search_id"], "search.read search_id", max_length=128)
        _integer(params.get("offset", 0), "search.read offset", minimum=-1000000, maximum=1000000)
        _integer(params.get("length", 100), "search.read length", minimum=1, maximum=MAX_SEARCH_PAGE_LENGTH)
    elif action == "search.stop":
        _nonempty(params["search_id"], "search.stop search_id", max_length=128)
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
    elif action == "fs.edit_text":
        old = _nonempty(params["old_text"], "fs.edit_text old_text", max_length=MAX_TEXT_READ_BYTES)
        new = _text(params["new_text"], "fs.edit_text new_text", max_length=MAX_TEXT_READ_BYTES)
        if len(old.encode(_encoding(params))) > MAX_TEXT_READ_BYTES or len(new.encode(_encoding(params))) > MAX_TEXT_READ_BYTES:
            raise ValueError("fs.edit_text replacement exceeds byte bound")
        _integer(params.get("expected_replacements", 1), "fs.edit_text expected_replacements", minimum=1, maximum=10000)
        expected = params["expected_current_hash"]
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError("fs.edit_text expected_current_hash must be lowercase SHA-256")
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
    elif action == "config.set":
        key = _nonempty(params["key"], "config.set key", max_length=128)
        if key not in MUTABLE_CONFIG_KEYS:
            raise ValueError(f"config key is not mutable: {key}")
        revision = params.get("expected_revision")
        if revision is not None and (
            not isinstance(revision, str)
            or not re.fullmatch(r"[0-9a-f]{64}", revision)
        ):
            raise ValueError("config.set expected_revision must be lowercase SHA-256 or null")
        value = params["value"]
        if key == "allowed_roots":
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                raise ValueError("config.set allowed_roots must be a string array")
            if len(value) > 32:
                raise ValueError("config.set allowed_roots contains too many entries")
        elif isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("config.set read_many_max_bytes must be an integer")
    elif action == "device.shutdown":
        _nonempty(params["device_id"], "device.shutdown device_id", max_length=128)
        _nonempty(params["session_epoch"], "device.shutdown session_epoch", max_length=128)
    elif action == "identity.get":
        if params.get("device_id") is not None:
            _nonempty(params["device_id"], "identity.get device_id", max_length=128)
        if params.get("session_epoch") is not None:
            _nonempty(params["session_epoch"], "identity.get session_epoch", max_length=128)
    elif action == "audit.history":
        _integer(
            params.get("limit", 50),
            "audit.history limit",
            minimum=1,
            maximum=MAX_AUDIT_HISTORY_RESULTS,
        )
    elif action == "process.list":
        if params.get("pid") is not None:
            _integer(params["pid"], "process.list pid", minimum=1)
        if params.get("name_contains") is not None:
            _text(params["name_contains"], "process.list name_contains", max_length=256)
        _integer(params.get("offset", 0), "process.list offset", minimum=0, maximum=1000000)
        _integer(params.get("max_results", 200), "process.list max_results", minimum=1, maximum=MAX_PROCESS_RESULTS)
    elif action == "process.inspect":
        _integer(params["pid"], "process.inspect pid", minimum=1)
    elif action == "process.managed.list":
        if params.get("kind") not in {None, "process", "session"}:
            raise ValueError("process.managed.list kind must be process, session, or null")
        _optional_bool(params.get("include_stale"), "process.managed.list include_stale")
        _integer(params.get("offset", 0), "process.managed.list offset", minimum=0, maximum=1000000)
        _integer(params.get("max_results", 200), "process.managed.list max_results", minimum=1, maximum=MAX_PROCESS_RESULTS)
    elif action in {"process.start", "shell.session.start"}:
        _validate_start_params(action, params)
    elif action in {"process.status", "process.read_output", "process.terminate"}:
        _nonempty(params["handle_id"], f"{action} handle_id", max_length=128)
        if action == "process.read_output":
            if params.get("cursor") is not None:
                _validate_stream_cursor(params["cursor"], params["handle_id"])
            if params.get("tail_bytes") is not None:
                _integer(params["tail_bytes"], "process.read_output tail_bytes", minimum=1, maximum=MAX_READ_OUTPUT_BYTES)
                if params.get("cursor") is not None:
                    raise ValueError("process.read_output tail_bytes and cursor are mutually exclusive")
            _integer(params.get("max_bytes", MAX_READ_OUTPUT_BYTES), "process.read_output max_bytes", minimum=1, maximum=MAX_READ_OUTPUT_BYTES)
            _integer(params.get("wait_ms", 0), "process.read_output wait_ms", minimum=0, maximum=2000)
        if action == "process.terminate":
            _integer(params.get("grace_ms", 1000), "process.terminate grace_ms", minimum=0, maximum=5000)
    elif action in {"shell.session.read", "shell.session.write_stdin", "shell.session.terminate"}:
        session_id = _nonempty(params["session_id"], f"{action} session_id", max_length=128)
        if action == "shell.session.read":
            if params.get("cursor") is not None:
                _validate_stream_cursor(params["cursor"], session_id)
            if params.get("tail_bytes") is not None:
                _integer(params["tail_bytes"], "shell.session.read tail_bytes", minimum=1, maximum=MAX_READ_OUTPUT_BYTES)
                if params.get("cursor") is not None:
                    raise ValueError("shell.session.read tail_bytes and cursor are mutually exclusive")
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
    elif action == "system.process.kill":
        pid = _integer(params["pid"], "system.process.kill pid", minimum=1)
        if pid == os.getpid():
            raise SafetyViolation("system.process.kill refuses to terminate the executor process")
        _nonempty(params["expected_name"], "system.process.kill expected_name", max_length=512)
        _integer(params.get("exit_code", 1), "system.process.kill exit_code", minimum=0, maximum=255)


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
    if params.get("context_binding") is not None:
        _validate_ops_context_binding(params["context_binding"], action)


def _validate_ops_preflight_payload(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("ops.preflight payload must be an object")
    if set(value) != {"contract_version", "request"}:
        raise ValueError("ops.preflight payload keys mismatch")
    if value["contract_version"] != OPS_PREFLIGHT_VERSION:
        raise ValueError("unsupported ops.preflight contract_version")
    request = value["request"]
    if not isinstance(request, Mapping):
        raise ValueError("ops.preflight request must be an object")
    allowed = {"request_id", "action", "params", "dry_run", "timeout_ms"}
    required = {"request_id", "action", "params"}
    if set(request) - allowed or required - set(request):
        raise ValueError("ops.preflight request keys mismatch")
    _nonempty(request["request_id"], "ops.preflight request_id", max_length=128)
    action = _nonempty(request["action"], "ops.preflight action", max_length=128)
    if action in {"ops.preflight", "ops.capabilities.get"}:
        raise ValueError("ops.preflight cannot target ops meta-actions")
    if action not in OPS_ACTIONS:
        raise ValueError(f"unsupported structured operation: {action}")
    if not isinstance(request["params"], Mapping):
        raise ValueError("ops.preflight params must be an object")
    dry_run = request.get("dry_run")
    if dry_run is not None and not isinstance(dry_run, bool):
        raise ValueError("ops.preflight dry_run must be boolean or null")
    timeout = request.get("timeout_ms")
    if timeout is not None:
        _integer(timeout, "ops.preflight timeout_ms", minimum=1, maximum=120000)
    return {
        "request_id": request["request_id"],
        "action": action,
        "params": dict(request["params"]),
        "dry_run": dry_run,
        "timeout_ms": timeout,
    }


def _validate_ops_context_binding(value: Any, action: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("ops context_binding must be an object")
    expected = {
        "contract_version",
        "action",
        "executable",
        "cwd_path_sha256",
        "cwd_device",
        "cwd_inode",
        "context_digest",
    }
    if set(value) != expected:
        raise ValueError("ops context_binding keys mismatch")
    if value["contract_version"] != OPS_CONTEXT_VERSION or value["action"] != action:
        raise ValueError("ops context_binding version/action mismatch")
    for key in ("executable", "cwd_path_sha256", "context_digest"):
        if not isinstance(value[key], str) or not value[key]:
            raise ValueError(f"ops context_binding {key} is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", value["cwd_path_sha256"]):
        raise ValueError("ops context_binding cwd_path_sha256 is invalid")
    for key in ("cwd_device", "cwd_inode"):
        if value[key] is not None:
            _integer(value[key], f"ops context_binding {key}", minimum=0)
    body = dict(value)
    claimed = body.pop("context_digest")
    actual = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    if claimed != actual:
        raise ValueError("ops context_binding digest mismatch")
    return dict(value)


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


def _validate_search_cursor(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("search cursor must be an object")
    expected = {"version", "root_sha256", "query_sha256", "offset"}
    if set(value) != expected or value["version"] != SEARCH_CURSOR_VERSION:
        raise ValueError("search cursor schema/version mismatch")
    for key in ("root_sha256", "query_sha256"):
        digest = value[key]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"search cursor {key} is invalid")
    _integer(value["offset"], "search cursor offset", minimum=0)
    return dict(value)


def _is_reparse_or_symlink(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        stat = os.lstat(path)
    except OSError:
        return True
    reparse_flag = getattr(stat_module, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(stat, "st_file_attributes", 0) & reparse_flag)


def _is_hidden_entry(path: Path) -> bool:
    if path.name.startswith("."):
        return True
    if os.name != "nt":
        return False
    try:
        stat = os.stat(path, follow_symlinks=False)
    except OSError:
        return True
    hidden_flag = getattr(stat_module, "FILE_ATTRIBUTE_HIDDEN", 0x2)
    return bool(getattr(stat, "st_file_attributes", 0) & hidden_flag)


def _walk_safe_tree(
    root: Path,
    *,
    max_depth: int,
    include_hidden: bool,
    token: CancellationToken,
    checkpoint: Callable[[], None] | None = None,
):
    root_parts = len(root.parts)

    def onerror(_error: OSError) -> None:
        return None

    for current, dirs, files in os.walk(
        root,
        topdown=True,
        followlinks=False,
        onerror=onerror,
    ):
        token.raise_if_cancelled()
        if checkpoint is not None:
            checkpoint()
        current_path = Path(current)
        depth = len(current_path.parts) - root_parts
        resolved_dirs: list[Path] = []
        safe_dir_names: list[str] = []
        if depth < max_depth:
            for name in sorted(dirs, key=lambda value: (value.casefold(), value)):
                candidate = current_path / name
                if not include_hidden and _is_hidden_entry(candidate):
                    continue
                if _is_reparse_or_symlink(candidate):
                    continue
                try:
                    resolved = ensure_resolved_path_allowed(candidate)
                    if not resolved.is_dir():
                        continue
                except (OSError, SafetyViolation):
                    continue
                safe_dir_names.append(name)
                resolved_dirs.append(resolved)
        dirs[:] = safe_dir_names
        resolved_files: list[Path] = []
        for name in sorted(files, key=lambda value: (value.casefold(), value)):
            candidate = current_path / name
            if not include_hidden and _is_hidden_entry(candidate):
                continue
            if _is_reparse_or_symlink(candidate):
                continue
            try:
                resolved = ensure_resolved_path_allowed(candidate)
                if not resolved.is_file():
                    continue
            except (OSError, SafetyViolation):
                continue
            resolved_files.append(resolved)
        yield current_path, resolved_dirs, resolved_files


def _compile_search_matcher(
    pattern: str,
    *,
    literal: bool,
    ignore_case: bool,
) -> Callable[[str], bool]:
    if literal:
        needle = pattern.casefold() if ignore_case else pattern

        def literal_match(value: str) -> bool:
            haystack = value.casefold() if ignore_case else value
            return needle in haystack

        return literal_match
    expression = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
    return lambda value: expression.search(value) is not None


def _bounded_search_line(value: str) -> str:
    return value.rstrip("\r\n")[:MAX_SEARCH_CONTEXT_CHARS]


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

    def tail_offset(self, max_bytes: int) -> int:
        with self.lock:
            return max(self.base_offset, self.total_offset - max_bytes)

    def bounds(self) -> tuple[int, int]:
        with self.lock:
            return self.base_offset, self.total_offset


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

    def list_handles(
        self,
        *,
        kind: str | None = None,
        include_stale: bool = False,
        offset: int = 0,
        max_results: int = 200,
    ) -> tuple[list[dict[str, Any]], bool]:
        with self.lock:
            live_ids = sorted(self.live)
            stale_items = [
                dict(value) for _, value in sorted(self.stale.items())
            ]
        all_results: list[dict[str, Any]] = []
        for handle_id in live_ids:
            status = self.status(handle_id)
            if kind is None or status["kind"] == kind:
                all_results.append(status)
        if include_stale:
            for value in stale_items:
                if kind is not None and value.get("kind") != kind:
                    continue
                all_results.append(
                    {
                        "handle_id": value.get("handle_id"),
                        "kind": value.get("kind"),
                        "pid": value.get("pid"),
                        "status": "stale_after_restart",
                        "owned_by_current_gateway": False,
                        "returncode": None,
                    }
                )
        page = all_results[offset : offset + max_results]
        return page, offset + len(page) < len(all_results)


class LocalOperations:
    def __init__(
        self,
        *,
        shell: SafeShellAdapter,
        state_root: str | Path | None = None,
        search_retention_seconds: float = DEFAULT_SEARCH_RETENTION_SECONDS,
        search_max_workers: int = DEFAULT_SEARCH_WORKERS,
    ) -> None:
        self.shell = shell
        root = Path(state_root) if state_root is not None else self.default_state_root()
        self.state_root = root
        self.generation_id = str(uuid4())
        self.admin_config = AdminConfigStore(root)
        self.audit_provider: Any | None = None
        self.registry = ManagedProcessRegistry(
            root / "managed-processes.v1.json",
            generation_id=self.generation_id,
        )
        self.searches = SearchSessionManager(
            root / "search-sessions.v1.json",
            generation_id=self.generation_id,
            retention_seconds=search_retention_seconds,
            max_workers=search_max_workers,
        )

    def set_audit_provider(self, provider: Any) -> None:
        self.audit_provider = provider

    def _resolve_path(
        self,
        value: str | os.PathLike[str],
        *,
        for_creation: bool = False,
    ) -> Path:
        resolved = ensure_resolved_path_allowed(value, for_creation=for_creation)
        self.admin_config.assert_allowed(resolved)
        return resolved

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

    def capabilities_snapshot(self) -> dict[str, Any]:
        actions = {
            action: {
                "side_effecting": action in OPS_SIDE_EFFECT_ACTIONS,
                "supported": True,
                "tool_contract_version": NATIVE_TOOL_PARITY_VERSION,
            }
            for action in sorted(OPS_ACTIONS)
        }
        body = {
            "contract_version": OPS_CAPABILITIES_VERSION,
            "operations_contract_version": OPS_CONTRACT_VERSION,
            "native_tool_parity_version": NATIVE_TOOL_PARITY_VERSION,
            "schema_versions": {
                "request": NATIVE_REQUEST_VERSION,
                "result": NATIVE_RESULT_VERSION,
                "capabilities": NATIVE_CAPABILITIES_VERSION,
                "preflight": OPS_PREFLIGHT_VERSION,
                "execution_context": OPS_CONTEXT_VERSION,
                "stream_cursor": CURSOR_VERSION,
                "log_cursor": LOG_CURSOR_VERSION,
                "search_cursor": SEARCH_CURSOR_VERSION,
                "search_session": SEARCH_SESSION_VERSION,
                "process_handle": PROCESS_HANDLE_VERSION,
            },
            "actions": actions,
            "safety": {
                "protected_path_policy": "lexical_plus_resolved_target_and_existing_ancestors",
                "credential_entry_allowed": False,
                "captcha_entry_allowed": False,
                "process_termination_scope": "gateway_owned_current_generation_only",
                "system_process_kill_policy": "pid_plus_expected_name_direct_os_handle",
                "max_text_read_bytes": MAX_TEXT_READ_BYTES,
                "max_binary_read_bytes": MAX_BINARY_READ_BYTES,
                "max_log_bytes": MAX_LOG_BYTES,
                "max_process_output_bytes": MAX_PROCESS_OUTPUT_BYTES,
                "max_search_results": MAX_SEARCH_RESULTS,
                "max_search_timeout_ms": MAX_SEARCH_TIMEOUT_MS,
                "max_retained_search_sessions": MAX_RETAINED_SEARCH_SESSIONS,
                "search_retention_seconds": self.searches.retention_seconds,
                "max_read_many_files": MAX_READ_MANY_FILES,
                "max_read_many_bytes": MAX_READ_MANY_BYTES,
                "mutable_config_keys": sorted(MUTABLE_CONFIG_KEYS),
                "allowed_roots_policy": (
                    "protected_only"
                    if self.admin_config.load().allowed_roots is None
                    else "deny_all"
                    if not self.admin_config.load().allowed_roots
                    else "explicit_allowlist"
                ),
            },
        }
        digest = hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        return {**body, "attestation": {"algorithm": "sha256", "digest": digest}}

    def preflight_contract(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        try:
            parsed = _validate_ops_preflight_payload(payload)
            self.preflight(parsed["action"], parsed["params"])
            context = None
            if parsed["action"] in {"process.start", "shell.session.start"}:
                context = self._start_context(parsed["action"], parsed["params"])
            return {
                "contract_version": OPS_PREFLIGHT_VERSION,
                "request_id": parsed["request_id"],
                "action": parsed["action"],
                "status": "ready",
                "executable": True,
                "side_effecting": parsed["action"] in OPS_SIDE_EFFECT_ACTIONS,
                "reason": "ready",
                "context_binding": context,
            }
        except SafetyViolation as exc:
            request = payload.get("request") if isinstance(payload, Mapping) else None
            return {
                "contract_version": OPS_PREFLIGHT_VERSION,
                "request_id": request.get("request_id") if isinstance(request, Mapping) else None,
                "action": request.get("action") if isinstance(request, Mapping) else None,
                "status": "blocked",
                "executable": False,
                "side_effecting": (
                    isinstance(request, Mapping)
                    and request.get("action") in OPS_SIDE_EFFECT_ACTIONS
                ),
                "reason": str(exc),
                "context_binding": None,
            }
        except (KeyError, TypeError, ValueError) as exc:
            request = payload.get("request") if isinstance(payload, Mapping) else None
            return {
                "contract_version": OPS_PREFLIGHT_VERSION,
                "request_id": request.get("request_id") if isinstance(request, Mapping) else None,
                "action": request.get("action") if isinstance(request, Mapping) else None,
                "status": "invalid_request",
                "executable": False,
                "side_effecting": False,
                "reason": str(exc),
                "context_binding": None,
            }

    def _start_context(self, action: str, params: Mapping[str, Any]) -> dict[str, Any]:
        argv = self.shell.validate(params["argv"], cwd=params.get("cwd"))
        cwd = self._resolve_path(params.get("cwd") or os.getcwd())
        device, inode = _file_identity(cwd)
        body: dict[str, Any] = {
            "contract_version": OPS_CONTEXT_VERSION,
            "action": action,
            "executable": Path(str(argv[0]).replace("\\", "/")).name.lower(),
            "cwd_path_sha256": _path_digest(cwd),
            "cwd_device": device,
            "cwd_inode": inode,
        }
        body["context_digest"] = hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        return body

    def preflight(self, action: str, params: Mapping[str, Any]) -> None:
        validate_ops_params(action, params)
        if action in {"ops.capabilities.get", "ops.preflight"}:
            return
        if action == "fs.read_many":
            configured = self.admin_config.load().read_many_max_bytes
            requested = int(params.get("max_total_bytes", configured))
            if requested > configured:
                raise SafetyViolation(
                    f"fs.read_many aggregate bound exceeds configured limit: {requested} > {configured}"
                )
            return
        if action.startswith("fs.") or action.startswith("log."):
            self._preflight_path_action(action, params)
        elif action == "search.start":
            root = self._resolve_path(params["path"])
            _ensure_dir(root)
        elif action in {"search.read", "search.stop"}:
            self.searches.assert_current(params["search_id"])
        elif action == "search.list":
            return
        elif action in {"process.start", "shell.session.start"}:
            validated = self.shell.validate(params["argv"], cwd=params.get("cwd"))
            _validate_structured_command(action, validated)
            current = self._start_context(action, params)
            supplied = params.get("context_binding")
            if supplied is not None and _validate_ops_context_binding(supplied, action) != current:
                raise SafetyViolation("structured operation context changed since preflight")
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
            self._resolve_path(params["path"])
        elif action == "system.resources" and params.get("path") is not None:
            self._resolve_path(params["path"])
        elif action == "config.set":
            self.admin_config.validate_update(
                key=params["key"],
                value=params["value"],
                expected_revision=params.get("expected_revision"),
            )
        elif action == "system.process.kill":
            self._assert_system_kill_target(
                params["pid"],
                params["expected_name"],
            )

    def _preflight_path_action(self, action: str, params: Mapping[str, Any]) -> None:
        if action in {"fs.copy", "fs.move"}:
            source = self._resolve_path(params["source"])
            destination = self._resolve_path(
                params["destination"], for_creation=True
            )
            _assert_mutation_leaf_not_reparse(params["source"])
            _assert_mutation_leaf_not_reparse(params["destination"])
            _ensure_file(source)
            _assert_nonsensitive_path(source)
            if source.stat().st_size > MAX_COPY_BYTES:
                raise SafetyViolation(
                    f"source exceeds structured copy/move bound: {source.stat().st_size} bytes"
                )
            if destination.exists():
                if not destination.is_file():
                    raise SafetyViolation(
                        f"destination must be a regular file when it exists: {destination}"
                    )
                if not params.get("overwrite", False):
                    raise SafetyViolation(
                        f"destination exists and overwrite=false: {destination}"
                    )
            expected = params.get("expected_source_hash")
            if expected is not None and _sha256_file(source, max_bytes=MAX_HASH_BYTES) != expected:
                raise SafetyViolation("source changed: expected_source_hash mismatch")
            return

        path = self._resolve_path(
            params["path"],
            for_creation=action in {"fs.write_text", "fs.append_text", "fs.mkdir"},
        )
        if action in FS_WRITE_ACTIONS:
            _assert_mutation_leaf_not_reparse(params["path"])
        if action in FS_READ_ACTIONS or action in LOG_ACTIONS:
            if action in {"fs.list", "fs.find", "fs.glob", "fs.search"}:
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
            return
        if action == "fs.edit_text":
            _ensure_file(path)
            _assert_nonsensitive_path(path)
            if path.stat().st_size > MAX_TEXT_READ_BYTES:
                raise SafetyViolation("fs.edit_text target exceeds text edit bound")
            actual = _sha256_file(path, max_bytes=MAX_TEXT_READ_BYTES)
            if actual != params["expected_current_hash"]:
                raise SafetyViolation("fs.edit_text expected_current_hash mismatch")

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

        if action == "ops.capabilities.get":
            return {"capabilities": self.capabilities_snapshot()}
        if action == "ops.preflight":
            return {"preflight": self.preflight_contract(params)}
        if action == "search.start":
            return self._search_start(params)
        if action == "search.read":
            return self.searches.read(
                params["search_id"],
                offset=int(params.get("offset", 0)),
                length=int(params.get("length", 100)),
            )
        if action == "search.list":
            return self.searches.list()
        if action == "search.stop":
            return self.searches.stop(params["search_id"])
        if action == "fs.list":
            return self._fs_list(params, token)
        if action == "fs.stat":
            return self._fs_stat(params)
        if action == "fs.read_text":
            return self._fs_read_text(params, token)
        if action == "fs.read_many":
            return self._fs_read_many(params, token)
        if action == "fs.read_bytes":
            return self._fs_read_bytes(params)
        if action == "fs.hash":
            return self._fs_hash(params, token)
        if action == "fs.find":
            return self._fs_find(params, token)
        if action == "fs.glob":
            return self._fs_glob(params, token)
        if action == "fs.search":
            return self._fs_search(params, token)
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
        if action == "fs.edit_text":
            return self._fs_edit_text(params, token)
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
        if action == "process.managed.list":
            offset = int(params.get("offset", 0))
            handles, has_more = self.registry.list_handles(
                kind=params.get("kind"),
                include_stale=bool(params.get("include_stale", False)),
                offset=offset,
                max_results=int(params.get("max_results", 200)),
            )
            return {
                "handles": handles,
                "count": len(handles),
                "offset": offset,
                "next_offset": offset + len(handles),
                "has_more": has_more,
                "generation_id": self.generation_id,
            }
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
        if action == "device.info":
            return self._device_info()
        if action == "health.get":
            return self._health()
        if action == "config.get":
            return self._config()
        if action == "config.set":
            return self._config_set(params)
        if action == "device.shutdown":
            return self._device_shutdown(params)
        if action == "identity.get":
            return self._identity(params)
        if action == "audit.history":
            return self._audit_history(params)
        if action == "metrics.get":
            return self._metrics()
        if action == "system.info":
            return self._system_info()
        if action == "system.resources":
            return self._system_resources(params)
        if action == "system.paths":
            return self._system_paths(params)
        if action == "system.process.kill":
            return self._system_process_kill(
                params["pid"],
                params["expected_name"],
                exit_code=int(params.get("exit_code", 1)),
            )
        raise ValueError(f"unsupported structured operation: {action}")

    def _search_start(self, params: Mapping[str, Any]) -> dict[str, Any]:
        root = self._resolve_path(params["path"])
        _ensure_dir(root)
        return self.searches.start(
            search_type=str(params.get("search_type", "files")),
            pattern=str(params["pattern"]),
            path=str(root),
            literal_search=bool(params.get("literal_search", False)),
            ignore_case=bool(params.get("ignore_case", True)),
            context_lines=int(params.get("context_lines", 5)),
            include_hidden=bool(params.get("include_hidden", False)),
            max_results=int(params.get("max_results", 100)),
            timeout_ms=int(params.get("timeout_ms", DEFAULT_SEARCH_TIMEOUT_MS)),
            runner=self._run_search_session,
        )

    def _run_search_session(
        self,
        session: SearchSession,
        emit: Callable[[dict[str, Any]], bool],
    ) -> str:
        root = self._resolve_path(session.path)
        _ensure_dir(root)
        matcher = _compile_search_matcher(
            session.pattern,
            literal=session.literal_search,
            ignore_case=session.ignore_case,
        )
        for _current, _dirs, files in _walk_safe_tree(
            root,
            max_depth=MAX_FIND_DEPTH,
            include_hidden=session.include_hidden,
            token=session.cancellation,
            checkpoint=session.checkpoint,
        ):
            for candidate in files:
                session.checkpoint()
                try:
                    _assert_nonsensitive_path(candidate)
                except SafetyViolation:
                    continue
                if session.search_type == "files":
                    if not matcher(candidate.name):
                        continue
                    if not emit(
                        {
                            "path": str(candidate),
                            "name": candidate.name,
                            "kind": "file",
                        }
                    ):
                        return "max_results"
                    continue

                try:
                    size = candidate.stat().st_size
                    if size > MAX_TEXT_READ_BYTES:
                        continue
                    with candidate.open(
                        "r",
                        encoding="utf-8",
                        errors="strict",
                        newline=None,
                    ) as handle:
                        lines = handle.readlines()
                except (OSError, UnicodeError):
                    continue
                for index, line in enumerate(lines):
                    session.checkpoint()
                    if not matcher(line):
                        continue
                    start = max(0, index - session.context_lines)
                    end = min(len(lines), index + session.context_lines + 1)
                    before = [
                        _bounded_search_line(value)
                        for value in lines[start:index]
                    ]
                    after = [
                        _bounded_search_line(value)
                        for value in lines[index + 1 : end]
                    ]
                    if not emit(
                        {
                            "path": str(candidate),
                            "name": candidate.name,
                            "kind": "content",
                            "line_number": index + 1,
                            "text": _bounded_search_line(line),
                            "context_before": before,
                            "context_after": after,
                        }
                    ):
                        return "max_results"
        return "completed"

    def _fs_list(self, params: Mapping[str, Any], token: CancellationToken) -> dict[str, Any]:
        path = self._resolve_path(params["path"])
        offset = int(params.get("offset", 0))
        limit = int(params.get("max_entries", 200))
        include_hidden = bool(params.get("include_hidden", False))
        entries = []
        eligible = 0
        has_more = False
        for child in sorted(path.iterdir(), key=lambda p: p.name.casefold()):
            token.raise_if_cancelled()
            if not include_hidden and child.name.startswith("."):
                continue
            try:
                resolved = self._resolve_path(child)
            except SafetyViolation:
                continue
            if eligible < offset:
                eligible += 1
                continue
            if len(entries) >= limit:
                has_more = True
                break
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
            eligible += 1
        return {
            "path": str(path),
            "entries": entries,
            "count": len(entries),
            "offset": offset,
            "next_offset": offset + len(entries),
            "limit": limit,
            "has_more": has_more,
        }

    def _fs_stat(self, params: Mapping[str, Any]) -> dict[str, Any]:
        raw = Path(params["path"])
        symlink = raw.is_symlink()
        path = self._resolve_path(params["path"])
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

    def _fs_read_many(
        self,
        params: Mapping[str, Any],
        token: CancellationToken,
    ) -> dict[str, Any]:
        config = self.admin_config.load()
        aggregate_limit = int(params.get("max_total_bytes", config.read_many_max_bytes))
        if aggregate_limit > config.read_many_max_bytes:
            raise SafetyViolation(
                f"fs.read_many aggregate bound exceeds configured limit: "
                f"{aggregate_limit} > {config.read_many_max_bytes}"
            )
        per_file = int(params.get("max_bytes_per_file", 256 * 1024))
        encoding = _encoding(params)
        results: list[dict[str, Any]] = []
        total = 0
        for raw_path in params["paths"]:
            token.raise_if_cancelled()
            remaining = aggregate_limit - total
            if remaining <= 0:
                results.append(
                    {
                        "path": raw_path,
                        "ok": False,
                        "error": {"code": "AGGREGATE_LIMIT_EXHAUSTED"},
                    }
                )
                continue
            try:
                item = self._fs_read_text(
                    {
                        "path": raw_path,
                        "encoding": encoding,
                        "max_bytes": min(per_file, remaining),
                    },
                    token,
                )
                returned = int(item.get("returned_bytes", 0))
                if returned < 0 or returned > remaining:
                    raise SafetyViolation("fs.read_many provider exceeded aggregate bound")
                total += returned
                results.append(
                    {
                        "path": raw_path,
                        "ok": True,
                        "text": item["text"],
                        "encoding": item["encoding"],
                        "returned_bytes": returned,
                        "file_bytes": item["file_bytes"],
                        "truncated": bool(item["truncated"]),
                        "sha256": item["sha256"],
                    }
                )
            except SafetyViolation:
                results.append(
                    {
                        "path": raw_path,
                        "ok": False,
                        "error": {"code": "POLICY_BLOCKED"},
                    }
                )
            except FileNotFoundError:
                results.append(
                    {
                        "path": raw_path,
                        "ok": False,
                        "error": {"code": "NOT_FOUND"},
                    }
                )
            except (IsADirectoryError, NotADirectoryError):
                results.append(
                    {
                        "path": raw_path,
                        "ok": False,
                        "error": {"code": "INVALID_TYPE"},
                    }
                )
            except UnicodeError:
                results.append(
                    {
                        "path": raw_path,
                        "ok": False,
                        "error": {"code": "DECODE_ERROR"},
                    }
                )
            except OSError:
                results.append(
                    {
                        "path": raw_path,
                        "ok": False,
                        "error": {"code": "IO_ERROR"},
                    }
                )
        return {
            "results": results,
            "count": len(results),
            "returned_bytes": total,
            "max_total_bytes": aggregate_limit,
            "max_bytes_per_file": per_file,
        }

    def _fs_read_text(self, params: Mapping[str, Any], token: CancellationToken) -> dict[str, Any]:
        path = self._resolve_path(params["path"])
        _assert_nonsensitive_path(path)
        encoding = _encoding(params)
        max_bytes = int(params.get("max_bytes", 256 * 1024))
        tail_lines = params.get("tail_lines")
        if tail_lines is not None:
            size = path.stat().st_size
            start_byte = max(0, size - max_bytes)
            with path.open("rb") as handle:
                handle.seek(start_byte)
                raw = handle.read(max_bytes)
            text = raw.decode(encoding, errors="strict")
            normalized = text.replace("\r\n", "\n").replace("\r", "\n")
            lines = normalized.splitlines(keepends=True)
            selected = lines[-int(tail_lines) :]
            payload = "".join(selected)
            return {
                "path": str(path),
                "encoding": encoding,
                "start_line": None,
                "next_line": None,
                "tail_lines": int(tail_lines),
                "text": payload,
                "returned_bytes": len(payload.encode(encoding)),
                "truncated": start_byte > 0 or len(lines) > int(tail_lines),
                "file_bytes": int(size),
                "sha256": _sha256_file(path, max_bytes=MAX_HASH_BYTES, token=token),
            }

        start = int(params.get("start_line", 1))
        end = params.get("end_line")
        lines: list[str] = []
        used = 0
        truncated = False
        next_line = start
        with path.open("r", encoding=encoding, errors="strict", newline=None) as handle:
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
            "tail_lines": None,
            "text": "".join(lines),
            "returned_bytes": used,
            "truncated": truncated,
            "file_bytes": int(path.stat().st_size),
            "sha256": _sha256_file(path, max_bytes=MAX_HASH_BYTES, token=token),
        }

    def _fs_read_bytes(self, params: Mapping[str, Any]) -> dict[str, Any]:
        path = self._resolve_path(params["path"])
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
        path = self._resolve_path(params["path"])
        _assert_nonsensitive_path(path)
        maximum = int(params.get("max_bytes", MAX_HASH_BYTES))
        return {
            "path": str(path),
            "algorithm": "sha256",
            "sha256": _sha256_file(path, max_bytes=maximum, token=token),
            "bytes": int(path.stat().st_size),
        }

    def _fs_find(self, params: Mapping[str, Any], token: CancellationToken) -> dict[str, Any]:
        root = self._resolve_path(params["path"])
        needle = str(params.get("name_contains") or "").casefold()
        limit = int(params.get("max_results", 200))
        max_depth = int(params.get("max_depth", 8))
        results: list[str] = []
        for _current, dirs, files in _walk_safe_tree(
            root,
            max_depth=max_depth,
            include_hidden=True,
            token=token,
        ):
            for candidate in sorted(
                [*dirs, *files],
                key=lambda path: (path.name.casefold(), path.name),
            ):
                if needle and needle not in candidate.name.casefold():
                    continue
                results.append(str(candidate))
                if len(results) >= limit:
                    return {
                        "path": str(root),
                        "results": results,
                        "count": len(results),
                        "truncated": True,
                    }
        return {
            "path": str(root),
            "results": results,
            "count": len(results),
            "truncated": False,
        }

    def _fs_glob(self, params: Mapping[str, Any], token: CancellationToken) -> dict[str, Any]:
        root = self._resolve_path(params["path"])
        pattern = params["pattern"]
        limit = int(params.get("max_results", 200))
        results: list[str] = []
        for candidate in sorted(root.glob(pattern), key=lambda p: str(p).casefold()):
            token.raise_if_cancelled()
            if candidate.is_symlink():
                continue
            try:
                resolved = self._resolve_path(candidate)
            except SafetyViolation:
                continue
            results.append(str(resolved))
            if len(results) >= limit:
                return {"path": str(root), "pattern": pattern, "results": results, "count": len(results), "truncated": True}
        return {"path": str(root), "pattern": pattern, "results": results, "count": len(results), "truncated": False}

    def _fs_search(
        self,
        params: Mapping[str, Any],
        token: CancellationToken,
    ) -> dict[str, Any]:
        root = self._resolve_path(params["path"])
        query = params["query"]
        case_sensitive = bool(params.get("case_sensitive", False))
        content = bool(params.get("content", False))
        max_results = int(params.get("max_results", 100))
        max_depth = int(params.get("max_depth", 8))
        root_sha = _path_digest(root)
        query_body = {
            "query": query,
            "content": content,
            "case_sensitive": case_sensitive,
            "max_depth": max_depth,
        }
        query_sha = hashlib.sha256(
            json.dumps(
                query_body,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        cursor = params.get("cursor")
        offset = 0
        if cursor is not None:
            parsed = _validate_search_cursor(cursor)
            if (
                parsed["root_sha256"] != root_sha
                or parsed["query_sha256"] != query_sha
            ):
                raise SafetyViolation("search cursor does not match this search")
            offset = int(parsed["offset"])

        needle = query if case_sensitive else query.casefold()
        results: list[dict[str, Any]] = []
        matched = 0
        scanned_files = 0
        scanned_bytes = 0
        bounded = False
        for _current, dirs, files in _walk_safe_tree(
            root,
            max_depth=max_depth,
            include_hidden=True,
            token=token,
        ):
            candidates = (
                files
                if content
                else sorted(
                    [*dirs, *files],
                    key=lambda path: (path.name.casefold(), path.name),
                )
            )
            for resolved in candidates:
                token.raise_if_cancelled()
                name = resolved.name
                line_number = None
                matched_text = None
                if content:
                    try:
                        _assert_nonsensitive_path(resolved)
                        size = resolved.stat().st_size
                    except (OSError, SafetyViolation):
                        continue
                    scanned_files += 1
                    if size > MAX_TEXT_READ_BYTES:
                        continue
                    if scanned_bytes + size > 8 * 1024 * 1024:
                        bounded = True
                        break
                    scanned_bytes += size
                    try:
                        with resolved.open(
                            "r", encoding="utf-8", errors="strict"
                        ) as handle:
                            for number, line in enumerate(handle, start=1):
                                haystack = line if case_sensitive else line.casefold()
                                if needle in haystack:
                                    line_number = number
                                    matched_text = line[:4096]
                                    break
                    except (OSError, UnicodeError):
                        continue
                    is_match = line_number is not None
                else:
                    haystack = name if case_sensitive else name.casefold()
                    is_match = needle in haystack

                if not is_match:
                    continue
                if matched >= offset and len(results) < max_results:
                    item = {
                        "path": str(resolved),
                        "kind": "directory" if resolved.is_dir() else "file",
                    }
                    if line_number is not None:
                        item["line_number"] = line_number
                        item["text"] = matched_text
                    results.append(item)
                matched += 1
                if matched > offset + max_results:
                    bounded = True
                    break
            if bounded:
                break

        next_offset = offset + len(results)
        has_more = matched > next_offset or bounded
        next_cursor = (
            {
                "version": SEARCH_CURSOR_VERSION,
                "root_sha256": root_sha,
                "query_sha256": query_sha,
                "offset": next_offset,
            }
            if has_more
            else None
        )
        return {
            "path": str(root),
            "query": query,
            "content": content,
            "results": results,
            "count": len(results),
            "cursor": next_cursor,
            "has_more": has_more,
            "scanned_files": scanned_files,
            "scanned_bytes": scanned_bytes,
            "bounded": True,
        }

    def _atomic_replace(
        self,
        path: Path,
        payload: bytes,
        token: CancellationToken,
        *,
        before_replace: Callable[[], None] | None = None,
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._resolve_path(path.parent)
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
            if before_replace is not None:
                before_replace()
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
        *,
        before_replace: Callable[[], None] | None = None,
    ) -> int:
        destination.parent.mkdir(parents=True, exist_ok=True)
        self._resolve_path(destination.parent)
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
            if before_replace is not None:
                before_replace()
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
        path = self._resolve_path(params["path"], for_creation=True)
        self._preflight_path_action("fs.write_text", params)
        payload = params["text"].encode(_encoding(params))
        if len(payload) > MAX_TEXT_READ_BYTES:
            raise SafetyViolation("fs.write_text encoded payload exceeds byte bound")
        self._atomic_replace(
            path,
            payload,
            token,
            before_replace=lambda: self._preflight_path_action(
                "fs.write_text", params
            ),
        )
        return {
            "path": str(path),
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "atomic_replace": True,
        }

    def _fs_append_text(self, params: Mapping[str, Any], token: CancellationToken) -> dict[str, Any]:
        path = self._resolve_path(params["path"], for_creation=True)
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
            before_replace=lambda: self._preflight_path_action(
                "fs.append_text", params
            ),
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
        path = self._resolve_path(params["path"], for_creation=True)
        self._preflight_path_action("fs.mkdir", params)
        path.mkdir(
            parents=bool(params.get("parents", False)),
            exist_ok=bool(params.get("exist_ok", False)),
        )
        return {"path": str(path), "created": True}

    def _fs_copy(self, params: Mapping[str, Any], token: CancellationToken) -> dict[str, Any]:
        source = self._resolve_path(params["source"])
        destination = self._resolve_path(params["destination"], for_creation=True)
        self._preflight_path_action("fs.copy", params)
        total = self._atomic_copy_with_suffix(
            source,
            destination,
            b"",
            token,
            before_replace=lambda: self._preflight_path_action(
                "fs.copy", params
            ),
        )
        return {
            "source": str(source),
            "destination": str(destination),
            "bytes": total,
            "sha256": _sha256_file(destination, max_bytes=MAX_COPY_BYTES, token=token),
            "atomic_replace": True,
        }

    def _fs_move(self, params: Mapping[str, Any], token: CancellationToken) -> dict[str, Any]:
        source = self._resolve_path(params["source"])
        destination = self._resolve_path(params["destination"], for_creation=True)
        self._preflight_path_action("fs.move", params)
        token.raise_if_cancelled()
        try:
            source_device = source.stat().st_dev
            destination_device = destination.parent.stat().st_dev
        except OSError as exc:
            raise SafetyViolation(f"fs.move identity check failed: {exc}") from exc
        if source_device != destination_device:
            raise SafetyViolation("fs.move requires source/destination on the same filesystem")
        self._preflight_path_action("fs.move", params)
        token.raise_if_cancelled()
        os.replace(source, destination)
        return {"source": str(source), "destination": str(destination), "atomic_move": True}

    def _fs_delete(self, params: Mapping[str, Any]) -> dict[str, Any]:
        path = self._resolve_path(params["path"])
        self._preflight_path_action("fs.delete", params)
        if params["classification"] == "file":
            path.unlink()
        else:
            path.rmdir()
        return {"path": str(path), "classification": params["classification"], "deleted": True}

    def _fs_edit_text(
        self,
        params: Mapping[str, Any],
        token: CancellationToken,
    ) -> dict[str, Any]:
        path = self._resolve_path(params["path"])
        self._preflight_path_action("fs.edit_text", params)
        encoding = _encoding(params)
        raw = path.read_bytes()
        if len(raw) > MAX_TEXT_READ_BYTES:
            raise SafetyViolation("fs.edit_text target exceeds text edit bound")
        text = raw.decode(encoding, errors="strict")
        old_text = params["old_text"]
        new_text = params["new_text"]
        expected_replacements = int(params.get("expected_replacements", 1))
        actual_replacements = text.count(old_text)
        if actual_replacements != expected_replacements:
            raise SafetyViolation(
                "fs.edit_text replacement count mismatch: "
                f"expected {expected_replacements}, observed {actual_replacements}"
            )
        payload = text.replace(
            old_text,
            new_text,
            expected_replacements,
        ).encode(encoding)
        if len(payload) > MAX_TEXT_READ_BYTES:
            raise SafetyViolation("fs.edit_text result exceeds text edit bound")
        self._atomic_replace(
            path,
            payload,
            token,
            before_replace=lambda: self._preflight_path_action(
                "fs.edit_text", params
            ),
        )
        return {
            "path": str(path),
            "replacements": actual_replacements,
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "atomic_replace": True,
        }

    def _log_tail(self, params: Mapping[str, Any]) -> dict[str, Any]:
        path = self._resolve_path(params["path"])
        _assert_nonsensitive_path(path)
        max_bytes = int(params.get("max_bytes", 256 * 1024))
        max_lines = int(params.get("max_lines", 200))
        size = path.stat().st_size
        start = max(0, size - max_bytes)
        with path.open("rb") as handle:
            handle.seek(start)
            raw = handle.read(max_bytes)
        text = raw.decode(_encoding(params), errors="strict")
        text = text.replace("\r\n", "\n").replace("\r", "\n")
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
        path = self._resolve_path(params["path"])
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
        path = self._resolve_path(params["path"])
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
        env = (
            {
                key: value
                for key, value in os.environ.items()
                if not _SENSITIVE_ENV_RE.search(key)
            }
            if inherit
            else {}
        )
        if supplied:
            env.update({str(key): str(value) for key, value in supplied.items()})
        return env

    def _start(self, params: Mapping[str, Any], *, kind: str) -> dict[str, Any]:
        argv = self.shell.validate(params["argv"], cwd=params.get("cwd"))
        _validate_structured_command(
            "shell.session.start" if kind == "session" else "process.start",
            argv,
        )
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
        try:
            item = self.registry.register(
                process,
                kind=kind,
                executable=Path(str(argv[0]).replace("\\", "/")).name.lower(),
                output_limit=output_limit,
            )
        except Exception:
            try:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=1.0)
            except Exception:
                try:
                    if process.poll() is None:
                        process.kill()
                except Exception:
                    pass
            raise
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
        tail_bytes = params.get("tail_bytes")
        max_bytes = int(params.get("max_bytes", MAX_READ_OUTPUT_BYTES))
        if cursor is None:
            if tail_bytes is None:
                out_offset = err_offset = 0
            else:
                tail_limit = min(int(tail_bytes), max_bytes)
                out_offset = item.stdout.tail_offset(tail_limit)
                err_offset = item.stderr.tail_offset(tail_limit)
        else:
            parsed = _validate_stream_cursor(cursor, handle_id)
            out_offset = int(parsed["stdout_offset"])
            err_offset = int(parsed["stderr_offset"])
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
        stdout_base, stdout_total = item.stdout.bounds()
        stderr_base, stderr_total = item.stderr.bounds()
        return {
            "handle_id": handle_id,
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
            "stdout_bytes": len(stdout),
            "stderr_bytes": len(stderr),
            "stdout_available_from": stdout_base,
            "stderr_available_from": stderr_base,
            "stdout_total_bytes": stdout_total,
            "stderr_total_bytes": stderr_total,
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

    def _windows_process_entries(self) -> list[dict[str, Any]]:
        import ctypes
        from ctypes import wintypes

        TH32CS_SNAPPROCESS = 0x00000002
        INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

        class ProcessEntry32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", wintypes.WCHAR * 260),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateToolhelp32Snapshot.argtypes = [
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        kernel32.Process32FirstW.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(ProcessEntry32W),
        ]
        kernel32.Process32FirstW.restype = wintypes.BOOL
        kernel32.Process32NextW.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(ProcessEntry32W),
        ]
        kernel32.Process32NextW.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snapshot == INVALID_HANDLE_VALUE:
            raise OSError(ctypes.get_last_error(), "CreateToolhelp32Snapshot failed")
        entries: list[dict[str, Any]] = []
        try:
            entry = ProcessEntry32W()
            entry.dwSize = ctypes.sizeof(entry)
            ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
            while ok:
                entries.append(
                    {
                        "pid": int(entry.th32ProcessID),
                        "ppid": int(entry.th32ParentProcessID),
                        "name": str(entry.szExeFile),
                    }
                )
                ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
        finally:
            kernel32.CloseHandle(snapshot)
        return entries

    def _process_list(self, params: Mapping[str, Any]) -> dict[str, Any]:
        limit = int(params.get("max_results", 200))
        pid_filter = params.get("pid")
        name_filter = str(params.get("name_contains") or "").casefold()
        entries: list[dict[str, Any]] = []
        if os.name == "nt":
            raw_entries = self._windows_process_entries()
        else:
            output = subprocess.run(
                ["ps", "-eo", "pid=,ppid=,comm="],
                text=True,
                capture_output=True,
                check=False,
            ).stdout
            raw_entries = []
            for line in output.splitlines():
                parts = line.strip().split(None, 2)
                if len(parts) != 3:
                    continue
                try:
                    pid, ppid = int(parts[0]), int(parts[1])
                except ValueError:
                    continue
                raw_entries.append(
                    {"pid": pid, "ppid": ppid, "name": parts[2]}
                )

        offset = int(params.get("offset", 0))
        eligible = 0
        has_more = False
        for entry in sorted(raw_entries, key=lambda item: int(item["pid"])):
            pid = int(entry["pid"])
            name = str(entry["name"])
            if pid_filter is not None and pid != pid_filter:
                continue
            if name_filter and name_filter not in name.casefold():
                continue
            if eligible < offset:
                eligible += 1
                continue
            if len(entries) >= limit:
                has_more = True
                break
            entries.append(entry)
            eligible += 1
        return {
            "processes": entries,
            "count": len(entries),
            "offset": offset,
            "next_offset": offset + len(entries),
            "limit": limit,
            "has_more": has_more,
        }

    def _process_inspect(self, pid: int) -> dict[str, Any]:
        listed = self._process_list({"pid": pid, "max_results": 1})["processes"]
        if not listed:
            raise SafetyViolation(f"process not found: {pid}")
        return listed[0]

    def _device_info(self) -> dict[str, Any]:
        return {
            "contract_version": OPS_CONTRACT_VERSION,
            "device_id": "local",
            "transport": "native_local",
            "platform": platform.system() or "unknown",
            "architecture": platform.machine() or "unknown",
            "generation_id": self.generation_id,
        }

    def _health(self) -> dict[str, Any]:
        handles, _ = self.registry.list_handles(
            include_stale=True,
            max_results=MAX_PROCESS_RESULTS,
        )
        live = sum(
            1 for item in handles if item["owned_by_current_gateway"]
        )
        stale = sum(
            1 for item in handles if not item["owned_by_current_gateway"]
        )
        searches = self.searches.list()["searches"]
        running_searches = sum(
            1 for item in searches if item["status"] == "running"
        )
        return {
            "contract_version": OPS_CONTRACT_VERSION,
            "status": "ok",
            "generation_id": self.generation_id,
            "managed_processes_live": live,
            "managed_processes_stale": stale,
            "managed_searches_running": running_searches,
            "managed_searches_recent": len(searches),
            "state_root": str(self.state_root),
        }

    def _config(self) -> dict[str, Any]:
        admin = self.admin_config.load()
        return {
            "contract_version": OPS_CONTRACT_VERSION,
            "native_tool_parity_version": NATIVE_TOOL_PARITY_VERSION,
            "request_schema_version": NATIVE_REQUEST_VERSION,
            "result_schema_version": NATIVE_RESULT_VERSION,
            "capabilities_schema_version": NATIVE_CAPABILITIES_VERSION,
            "capabilities_version": OPS_CAPABILITIES_VERSION,
            "preflight_version": OPS_PREFLIGHT_VERSION,
            "execution_context_version": OPS_CONTEXT_VERSION,
            "stream_cursor_version": CURSOR_VERSION,
            "log_cursor_version": LOG_CURSOR_VERSION,
            "search_cursor_version": SEARCH_CURSOR_VERSION,
            "search_session_version": SEARCH_SESSION_VERSION,
            "process_handle_version": PROCESS_HANDLE_VERSION,
            "protected_windows_roots": list(PROTECTED_WINDOWS_ROOTS),
            "limits": {
                "max_text_read_bytes": MAX_TEXT_READ_BYTES,
                "max_binary_read_bytes": MAX_BINARY_READ_BYTES,
                "max_list_results": MAX_LIST_RESULTS,
                "max_process_output_bytes": MAX_PROCESS_OUTPUT_BYTES,
                "max_read_output_bytes": MAX_READ_OUTPUT_BYTES,
                "max_search_results": MAX_SEARCH_RESULTS,
                "max_search_timeout_ms": MAX_SEARCH_TIMEOUT_MS,
                "max_search_page_length": MAX_SEARCH_PAGE_LENGTH,
                "max_retained_search_sessions": MAX_RETAINED_SEARCH_SESSIONS,
                "search_retention_seconds": self.searches.retention_seconds,
                "max_read_many_files": MAX_READ_MANY_FILES,
                "max_read_many_bytes": MAX_READ_MANY_BYTES,
            },
            "mutable": True,
            "mutable_keys": sorted(MUTABLE_CONFIG_KEYS),
            "admin_config": admin.to_dict(),
            "admin_config_revision": self.admin_config.revision(admin),
        }

    def _config_set(self, params: Mapping[str, Any]) -> dict[str, Any]:
        updated = self.admin_config.update_key(
            key=params["key"],
            value=params["value"],
            expected_revision=params.get("expected_revision"),
        )
        return {
            "contract_version": updated.contract_version,
            "key": params["key"],
            "config": updated.to_dict(),
            "revision": self.admin_config.revision(updated),
        }

    def _device_shutdown(self, params: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "contract_version": OPS_CONTRACT_VERSION,
            "shutdown_requested": True,
            "device_id": params["device_id"],
            "session_epoch": params["session_epoch"],
            "scope": "current_device_agent",
        }

    def _identity(self, params: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "contract_version": OPS_CONTRACT_VERSION,
            "controller": "pc_executor",
            "device_id": params.get("device_id") or "local",
            "session_epoch": params.get("session_epoch"),
            "transport": "native_remote" if params.get("device_id") else "native_local",
            "platform": platform.system() or "unknown",
            "architecture": platform.machine() or "unknown",
            "generation_id": self.generation_id,
        }

    def _audit_history(self, params: Mapping[str, Any]) -> dict[str, Any]:
        provider = self.audit_provider
        reader = getattr(provider, "recent_sanitized", None)
        if not callable(reader):
            return {
                "contract_version": "pc_executor.audit_history.v1",
                "available": False,
                "events": [],
            }
        events = reader(limit=int(params.get("limit", 50)))
        return {
            "contract_version": "pc_executor.audit_history.v1",
            "available": True,
            "events": events,
            "count": len(events),
            "sanitized": True,
        }

    def _metrics(self) -> dict[str, Any]:
        provider = self.audit_provider
        reader = getattr(provider, "usage_metrics", None)
        if not callable(reader):
            return {
                "contract_version": "pc_executor.usage_metrics.v1",
                "available": False,
                "window_events": 0,
                "completed_calls": 0,
                "actions": {},
                "outcomes": {},
            }
        payload = dict(reader())
        payload["available"] = True
        payload["sanitized"] = True
        return payload

    def _assert_system_kill_target(

        self,
        pid: int,
        expected_name: str,
    ) -> dict[str, Any]:
        target = self._process_inspect(pid)
        actual_name = str(target["name"])
        if actual_name.casefold() != expected_name.casefold():
            raise SafetyViolation(
                "system.process.kill expected_name mismatch: "
                f"expected {expected_name!r}, observed {actual_name!r}"
            )
        if actual_name.casefold() in {
            "system",
            "system idle process",
            "csrss.exe",
            "wininit.exe",
            "services.exe",
            "lsass.exe",
        }:
            raise SafetyViolation(
                "system.process.kill refuses protected system process"
            )
        return target

    def _system_process_kill(
        self,
        pid: int,
        expected_name: str,
        *,
        exit_code: int,
    ) -> dict[str, Any]:
        target = self._assert_system_kill_target(pid, expected_name)
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes

            PROCESS_TERMINATE = 0x0001
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.argtypes = [
                wintypes.DWORD,
                wintypes.BOOL,
                wintypes.DWORD,
            ]
            kernel32.OpenProcess.restype = wintypes.HANDLE
            kernel32.QueryFullProcessImageNameW.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
                wintypes.LPWSTR,
                ctypes.POINTER(wintypes.DWORD),
            ]
            kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
            kernel32.TerminateProcess.argtypes = [
                wintypes.HANDLE,
                wintypes.UINT,
            ]
            kernel32.TerminateProcess.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL
            handle = kernel32.OpenProcess(
                PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                False,
                int(pid),
            )
            if not handle:
                raise OSError(
                    ctypes.get_last_error(),
                    "OpenProcess failed",
                )
            try:
                size = ctypes.c_ulong(32768)
                buffer = ctypes.create_unicode_buffer(size.value)
                if not kernel32.QueryFullProcessImageNameW(
                    handle,
                    0,
                    buffer,
                    ctypes.byref(size),
                ):
                    raise OSError(
                        ctypes.get_last_error(),
                        "QueryFullProcessImageNameW failed",
                    )
                opened_name = Path(buffer.value).name
                if opened_name.casefold() != expected_name.casefold():
                    raise SafetyViolation(
                        "system.process.kill process identity changed before termination"
                    )
                if not kernel32.TerminateProcess(handle, int(exit_code)):
                    raise OSError(
                        ctypes.get_last_error(),
                        "TerminateProcess failed",
                    )
            finally:
                kernel32.CloseHandle(handle)
        else:
            import signal

            os.kill(int(pid), signal.SIGTERM)
        return {
            "pid": int(pid),
            "name": target["name"],
            "terminated": True,
            "exit_code": int(exit_code),
        }

    def _system_info(self) -> dict[str, Any]:
        return {
            "platform_system": platform.system() or "unknown",
            "platform_release": platform.release(),
            "platform_machine": platform.machine() or "unknown",
            "os_family": os.name,
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "cpu_count": os.cpu_count(),
        }

    def _cpu_times_sample(self) -> tuple[int, int] | None:
        if os.name == "nt":
            try:
                import ctypes

                class FileTime(ctypes.Structure):
                    _fields_ = [
                        ("dwLowDateTime", ctypes.c_ulong),
                        ("dwHighDateTime", ctypes.c_ulong),
                    ]

                idle = FileTime()
                kernel = FileTime()
                user = FileTime()
                if not ctypes.windll.kernel32.GetSystemTimes(
                    ctypes.byref(idle),
                    ctypes.byref(kernel),
                    ctypes.byref(user),
                ):
                    return None

                def value(item: FileTime) -> int:
                    return int(item.dwLowDateTime) | (
                        int(item.dwHighDateTime) << 32
                    )

                idle_ticks = value(idle)
                total_ticks = value(kernel) + value(user)
                return idle_ticks, total_ticks
            except Exception:
                return None

        proc_stat = Path("/proc/stat")
        if proc_stat.exists():
            try:
                first = proc_stat.read_text(encoding="ascii").splitlines()[0]
                parts = first.split()
                if not parts or parts[0] != "cpu":
                    return None
                values = [int(value) for value in parts[1:9]]
                if len(values) < 4:
                    return None
                idle_ticks = values[3] + (values[4] if len(values) > 4 else 0)
                return idle_ticks, sum(values)
            except (OSError, UnicodeError, ValueError, IndexError):
                return None
        return None

    def _cpu_usage_percent(self) -> float | None:
        first = self._cpu_times_sample()
        if first is None:
            return None
        time.sleep(0.05)
        second = self._cpu_times_sample()
        if second is None:
            return None
        idle_delta = second[0] - first[0]
        total_delta = second[1] - first[1]
        if total_delta <= 0:
            return None
        busy = max(0, total_delta - max(0, idle_delta))
        return round(min(100.0, max(0.0, busy * 100.0 / total_delta)), 2)

    def _system_resources(self, params: Mapping[str, Any]) -> dict[str, Any]:
        target = self._resolve_path(params.get("path") or os.getcwd())
        disk = shutil.disk_usage(target if target.exists() else target.parent)
        load = None
        try:
            load = list(os.getloadavg())
        except (AttributeError, OSError):
            pass
        memory = self._memory_info()
        return {
            "cpu_count": os.cpu_count(),
            "cpu_usage_percent": self._cpu_usage_percent(),
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
        cwd = self._resolve_path(os.getcwd())
        requested = params.get("path")
        result: dict[str, Any] = {
            "cwd": str(cwd),
            "separator": os.sep,
            "path_separator": os.pathsep,
        }
        if requested is not None:
            resolved = self._resolve_path(requested, for_creation=True)
            result["requested"] = {
                "path": str(resolved),
                "exists": resolved.exists(),
                "parent_exists": resolved.parent.exists(),
            }
        return result
