from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable

from .safety import SafetyViolation, ensure_path_allowed

ADMIN_CONFIG_VERSION = "pc_executor.admin_config.v1"
MAX_CONFIGURED_ROOTS = 32
MAX_READ_MANY_BYTES = 8 * 1024 * 1024
DEFAULT_READ_MANY_BYTES = 4 * 1024 * 1024
MIN_READ_MANY_BYTES = 1024
MUTABLE_CONFIG_KEYS = frozenset({"allowed_roots", "read_many_max_bytes"})


def _canonical(payload: dict[str, Any]) -> bytes:
    return (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    tmp = Path(raw_tmp)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def _normalize_root(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("allowed root must be a non-empty string")
    ensure_path_allowed(value)
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ValueError("allowed root must be absolute")
    resolved = path.resolve(strict=False)
    ensure_path_allowed(str(resolved))
    return str(resolved)


@dataclass(frozen=True)
class AdminConfig:
    contract_version: str = ADMIN_CONFIG_VERSION
    allowed_roots: tuple[str, ...] | None = None
    read_many_max_bytes: int = DEFAULT_READ_MANY_BYTES

    def validate(self) -> "AdminConfig":
        if self.contract_version != ADMIN_CONFIG_VERSION:
            raise ValueError("unsupported admin config version")
        roots = self.allowed_roots
        if roots is not None:
            if not isinstance(roots, tuple):
                raise ValueError("allowed_roots must be an array")
            if len(roots) > MAX_CONFIGURED_ROOTS:
                raise ValueError("too many allowed_roots")
            normalized = tuple(_normalize_root(root) for root in roots)
            if len(set(os.path.normcase(root) for root in normalized)) != len(normalized):
                raise ValueError("allowed_roots contains duplicates")
            if normalized != roots:
                return replace(self, allowed_roots=normalized).validate()
        value = self.read_many_max_bytes
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("read_many_max_bytes must be an integer")
        if not MIN_READ_MANY_BYTES <= value <= MAX_READ_MANY_BYTES:
            raise ValueError(
                f"read_many_max_bytes must be {MIN_READ_MANY_BYTES}..{MAX_READ_MANY_BYTES}"
            )
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "allowed_roots": None if self.allowed_roots is None else list(self.allowed_roots),
            "read_many_max_bytes": self.read_many_max_bytes,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "AdminConfig":
        if not isinstance(raw, dict):
            raise ValueError("admin config must be an object")
        if set(raw) != {"contract_version", "allowed_roots", "read_many_max_bytes"}:
            raise ValueError("admin config keys mismatch")
        roots = raw["allowed_roots"]
        if roots is not None:
            if not isinstance(roots, list) or any(not isinstance(item, str) for item in roots):
                raise ValueError("allowed_roots must be a string array or null")
            roots = tuple(roots)
        return cls(
            contract_version=raw["contract_version"],
            allowed_roots=roots,
            read_many_max_bytes=raw["read_many_max_bytes"],
        ).validate()


class AdminConfigStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.path = self.root / "admin-config.v1.json"
        self.backup_path = self.root / "admin-config.backup.v1.json"

    def load(self) -> AdminConfig:
        if not self.path.exists():
            return AdminConfig().validate()
        return AdminConfig.from_dict(json.loads(self.path.read_text(encoding="utf-8")))

    def revision(self, config: AdminConfig | None = None) -> str:
        current = config or self.load()
        return hashlib.sha256(_canonical(current.to_dict())).hexdigest()

    def validate_update(
        self,
        *,
        key: str,
        value: Any,
        expected_revision: str | None = None,
    ) -> AdminConfig:
        if key not in MUTABLE_CONFIG_KEYS:
            raise ValueError(f"config key is not mutable: {key}")
        current = self.load()
        if expected_revision is not None and expected_revision != self.revision(current):
            raise SafetyViolation("config revision conflict")
        if key == "allowed_roots":
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                raise ValueError("allowed_roots value must be a string array")
            return replace(current, allowed_roots=tuple(value)).validate()
        return replace(current, read_many_max_bytes=value).validate()

    def update_key(
        self,
        *,
        key: str,
        value: Any,
        expected_revision: str | None = None,
    ) -> AdminConfig:
        candidate = self.validate_update(
            key=key,
            value=value,
            expected_revision=expected_revision,
        )
        previous = self.path.read_bytes() if self.path.exists() else None
        if previous is not None:
            _atomic_write(self.backup_path, previous)
        try:
            _atomic_write(self.path, _canonical(candidate.to_dict()))
            loaded = self.load()
            if loaded != candidate:
                raise RuntimeError("persisted admin config verification failed")
            return loaded
        except Exception:
            if previous is None:
                try:
                    self.path.unlink()
                except FileNotFoundError:
                    pass
            else:
                _atomic_write(self.path, previous)
            raise

    def assert_allowed(self, resolved: Path) -> None:
        config = self.load()
        roots = config.allowed_roots
        if roots is None:
            return
        if not roots:
            raise SafetyViolation("configured allowed_roots denies all filesystem access")
        target = os.path.normcase(str(resolved.resolve(strict=False)))
        for root in roots:
            root_norm = os.path.normcase(str(Path(root).resolve(strict=False)))
            try:
                common = os.path.commonpath([target, root_norm])
            except ValueError:
                continue
            if os.path.normcase(common) == root_norm:
                return
        raise SafetyViolation("path is outside configured allowed_roots")
