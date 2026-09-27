from __future__ import annotations

import json
import os
import string
import threading
from pathlib import Path
from typing import Any, Mapping

from .safety import SafetyViolation, ensure_path_allowed


SETTINGS_CONTRACT_VERSION = "pc_executor.native_settings.v1"
MAX_ALLOWED_ROOTS = 32
MAX_BATCH_AGGREGATE_BYTES = 4 * 1024 * 1024
MAX_PDF_INPUT_BYTES = 8 * 1024 * 1024
MAX_PDF_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_RECENT_TOOL_CALLS = 1000

MUTABLE_SETTING_KEYS = frozenset(
    {
        "filesystem.allowed_roots",
        "batch_read.max_aggregate_bytes",
        "pdf.max_input_bytes",
        "pdf.max_output_bytes",
        "diagnostics.max_recent_calls",
    }
)


def _default_allowed_roots() -> list[str]:
    if os.name == "nt":
        # Preserve the pre-settings drive-letter scope without probing drives.
        # Protected roots are still denied before this allowlist is considered.
        return [f"{letter}:{os.sep}" for letter in string.ascii_uppercase]
    return [os.path.abspath(os.sep)]


def _default_values() -> dict[str, Any]:
    return {
        "filesystem.allowed_roots": _default_allowed_roots(),
        "batch_read.max_aggregate_bytes": 1024 * 1024,
        "pdf.max_input_bytes": 2 * 1024 * 1024,
        "pdf.max_output_bytes": 8 * 1024 * 1024,
        "diagnostics.max_recent_calls": 200,
    }


def _integer(value: Any, key: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{key} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{key} must be between {minimum} and {maximum}")
    return value


def _validate_roots(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError("filesystem.allowed_roots must be a non-empty array")
    if len(value) > MAX_ALLOWED_ROOTS:
        raise ValueError(f"filesystem.allowed_roots supports at most {MAX_ALLOWED_ROOTS} entries")
    validated: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError("filesystem.allowed_roots entries must be non-empty strings")
        if "*" in item or "?" in item:
            raise ValueError("filesystem.allowed_roots entries must not contain wildcards")
        ensure_path_allowed(item)
        path = Path(item).expanduser()
        if not path.is_absolute():
            raise ValueError("filesystem.allowed_roots entries must be absolute")
        normalized = os.path.normcase(os.path.normpath(str(path)))
        if normalized not in seen:
            seen.add(normalized)
            validated.append(str(path))
    if not validated:
        raise ValueError("filesystem.allowed_roots must contain at least one valid root")
    return validated


def validate_setting_value(key: str, value: Any) -> Any:
    if key not in MUTABLE_SETTING_KEYS:
        raise ValueError(f"unsupported mutable native setting: {key}")
    if key == "filesystem.allowed_roots":
        return _validate_roots(value)
    if key == "batch_read.max_aggregate_bytes":
        return _integer(value, key, 1024, MAX_BATCH_AGGREGATE_BYTES)
    if key == "pdf.max_input_bytes":
        return _integer(value, key, 1024, MAX_PDF_INPUT_BYTES)
    if key == "pdf.max_output_bytes":
        return _integer(value, key, 16 * 1024, MAX_PDF_OUTPUT_BYTES)
    if key == "diagnostics.max_recent_calls":
        return _integer(value, key, 1, MAX_RECENT_TOOL_CALLS)
    raise AssertionError(key)


class NativeSettingsStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        self._values = _default_values()
        self._load()
    def _load(self) -> None:
        if not self.path.exists():
            return
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, Mapping):
            raise ValueError("native settings file must contain an object")
        if raw.get("contract_version") != SETTINGS_CONTRACT_VERSION:
            raise ValueError("native settings contract_version mismatch")
        values = raw.get("values")
        if not isinstance(values, Mapping):
            raise ValueError("native settings values must be an object")
        candidate = _default_values()
        for key, value in values.items():
            candidate[key] = validate_setting_value(str(key), value)
        self._values = candidate

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "contract_version": SETTINGS_CONTRACT_VERSION,
                "mutable_keys": sorted(MUTABLE_SETTING_KEYS),
                "values": json.loads(json.dumps(self._values)),
            }

    def value(self, key: str) -> Any:
        with self._lock:
            value = self._values[key]
            return json.loads(json.dumps(value))

    def set_value(self, key: str, value: Any) -> dict[str, Any]:
        validated = validate_setting_value(key, value)
        with self._lock:
            candidate = dict(self._values)
            candidate[key] = validated
            roots = candidate.get("filesystem.allowed_roots")
            if not isinstance(roots, list) or not roots:
                raise ValueError("filesystem.allowed_roots must never be empty")
            payload = {
                "contract_version": SETTINGS_CONTRACT_VERSION,
                "values": candidate,
            }
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temp = self.path.with_suffix(self.path.suffix + ".tmp")
            temp.write_text(
                json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            os.replace(temp, self.path)
            self._values = candidate
            return self.snapshot()

    def assert_allowed_path(self, path: str | Path) -> None:
        ensure_path_allowed(path)
        candidate = Path(path).expanduser().absolute()
        candidate_norm = os.path.normcase(os.path.normpath(str(candidate)))
        roots = self.value("filesystem.allowed_roots")
        for raw_root in roots:
            root_norm = os.path.normcase(os.path.normpath(str(Path(raw_root).expanduser().absolute())))
            try:
                common = os.path.commonpath([candidate_norm, root_norm])
            except ValueError:
                continue
            if common == root_norm:
                return
        raise SafetyViolation("path is outside configured filesystem.allowed_roots")
