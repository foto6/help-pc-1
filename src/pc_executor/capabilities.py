from __future__ import annotations

import hashlib
import importlib.util
import os
import platform
import sys
from typing import Any

from .capture import PillowScreenCapture
from .input import WindowsInputAdapter
from .models import canonical_json
from .safety import DEFAULT_SAFE_EXECUTABLES, PROTECTED_WINDOWS_ROOTS
from .shell import SafeShellAdapter
from .uia import WindowsUIAutomationAdapter
from .windows import Win32WindowEnumerator


CONTRACT_VERSION = "pc_executor.capabilities.v1"
EXECUTOR_VERSION = "0.1.0"

READ_ONLY_ACTIONS = frozenset(
    {
        "capabilities.get",
        "action.preflight",
        "outcome.lookup",
        "screenshot.capture",
        "windows.list",
        "uia.snapshot",
        "uia.inspect",
        "clipboard.get",
    }
)
SIDE_EFFECT_ACTIONS = frozenset(
    {
        "vision.target.invoke",
        "uia.invoke",
        "uia.focus",
        "uia.set_value",
        "mouse.click",
        "keyboard.press",
        "keyboard.type_text",
        "clipboard.set",
        "shell.run",
    }
)
SUPPORTED_ACTIONS = tuple(sorted(READ_ONLY_ACTIONS | SIDE_EFFECT_ACTIONS))


def _has_methods(value: object, *methods: str) -> bool:
    return all(callable(getattr(value, method, None)) for method in methods)


def _dependency_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _availability(
    *,
    configured: object,
    methods: tuple[str, ...],
    native_type: type | None = None,
    windows_only: bool = False,
    dependencies: tuple[str, ...] = (),
) -> dict[str, Any]:
    if configured is None or not _has_methods(configured, *methods):
        return {
            "available": False,
            "provider": "missing",
            "unsupported_reason": "adapter_missing",
        }

    native = native_type is not None and isinstance(configured, native_type)
    if native and windows_only and os.name != "nt":
        return {
            "available": False,
            "provider": "native",
            "unsupported_reason": "platform_not_windows",
        }

    if native:
        missing = sorted(name for name in dependencies if not _dependency_available(name))
        if missing:
            return {
                "available": False,
                "provider": "native",
                "unsupported_reason": "dependency_missing:" + ",".join(missing),
            }

    return {
        "available": True,
        "provider": "native" if native else "injected",
        "unsupported_reason": None,
    }


def _action_capability(
    *,
    adapter: str | None,
    adapters: dict[str, dict[str, Any]],
    side_effecting: bool,
    safety_gate: str | None = None,
) -> dict[str, Any]:
    if adapter is None:
        available = True
        reason = None
    else:
        entry = adapters[adapter]
        available = bool(entry["available"])
        reason = entry["unsupported_reason"]
    return {
        "supported": available,
        "adapter": adapter,
        "side_effecting": side_effecting,
        "safety_gate": safety_gate,
        "unsupported_reason": reason,
    }

def build_capabilities(
    *,
    screenshot: object,
    windows: object,
    accessibility: object,
    input_adapter: object,
    shell: object,
    outcome_journal_configured: bool,
    dry_run_default: bool,
    allow_coordinate_fallback: bool,
    operation_timeout_seconds: float,
) -> dict[str, Any]:
    adapters = {
        "screenshot": _availability(
            configured=screenshot,
            methods=("capture_png",),
            native_type=PillowScreenCapture,
            windows_only=True,
        ),
        "windows": _availability(
            configured=windows,
            methods=("list_windows",),
            native_type=Win32WindowEnumerator,
            windows_only=True,
        ),
        "uia": _availability(
            configured=accessibility,
            methods=("inspect", "snapshot", "invoke", "focus", "set_value"),
            native_type=WindowsUIAutomationAdapter,
            windows_only=True,
            dependencies=("uiautomation",),
        ),
        "input": _availability(
            configured=input_adapter,
            methods=("click", "press", "type_text"),
            native_type=WindowsInputAdapter,
            windows_only=True,
            dependencies=("pyautogui",),
        ),
        "clipboard": _availability(
            configured=input_adapter,
            methods=("clipboard_get", "clipboard_set"),
            native_type=WindowsInputAdapter,
            windows_only=True,
            dependencies=("pyperclip",),
        ),
        "shell": _availability(
            configured=shell,
            methods=("validate", "run"),
            native_type=SafeShellAdapter,
        ),
    }

    action_adapters = {
        "capabilities.get": None,
        "action.preflight": None,
        "outcome.lookup": None,
        "screenshot.capture": "screenshot",
        "windows.list": "windows",
        "uia.snapshot": "uia",
        "uia.inspect": "uia",
        "vision.target.invoke": "uia",
        "uia.invoke": "uia",
        "uia.focus": "uia",
        "uia.set_value": "uia",
        "mouse.click": "input",
        "keyboard.press": "input",
        "keyboard.type_text": "input",
        "clipboard.get": "clipboard",
        "clipboard.set": "clipboard",
        "shell.run": "shell",
    }
    actions: dict[str, dict[str, Any]] = {}
    for action in SUPPORTED_ACTIONS:
        actions[action] = _action_capability(
            adapter=action_adapters[action],
            adapters=adapters,
            side_effecting=action in SIDE_EFFECT_ACTIONS,
            safety_gate="coordinate_fallback" if action == "mouse.click" else None,
        )

    shell_allowlist = sorted(
        str(value).lower()
        for value in getattr(shell, "allow_executables", DEFAULT_SAFE_EXECUTABLES)
    )
    output_limit = getattr(shell, "output_limit_bytes", None)
    if isinstance(output_limit, bool) or not isinstance(output_limit, int):
        output_limit = None

    body = {
        "contract_version": CONTRACT_VERSION,
        "runtime": {
            "executor_version": EXECUTOR_VERSION,
            "python_implementation": sys.implementation.name,
            "python_major_minor": f"{sys.version_info.major}.{sys.version_info.minor}",
            "platform_system": platform.system() or "unknown",
            "platform_machine": platform.machine() or "unknown",
            "os_family": os.name,
        },
        "adapters": adapters,
        "actions": actions,
        "safety": {
            "dry_run_default": bool(dry_run_default),
            "coordinate_fallback_enabled": bool(allow_coordinate_fallback),
            "credential_entry_allowed": False,
            "captcha_entry_allowed": False,
            "protected_windows_roots": list(PROTECTED_WINDOWS_ROOTS),
            "shell_allowlist": shell_allowlist,
            "shell_output_limit_bytes": output_limit,
            "operation_timeout_ms": int(max(0.0, operation_timeout_seconds) * 1000),
            "outcome_journal_configured": bool(outcome_journal_configured),
        },
    }
    digest = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
    return {
        **body,
        "attestation": {
            "algorithm": "sha256",
            "digest": digest,
        },
    }


def validate_capabilities(payload: Any) -> None:
    if not isinstance(payload, dict):
        raise ValueError("capabilities must be an object")
    expected = {
        "contract_version",
        "runtime",
        "adapters",
        "actions",
        "safety",
        "attestation",
    }
    if set(payload) != expected:
        raise ValueError("capabilities keys mismatch")
    if payload["contract_version"] != CONTRACT_VERSION:
        raise ValueError("unsupported capabilities contract_version")

    runtime = payload["runtime"]
    runtime_keys = {
        "executor_version",
        "python_implementation",
        "python_major_minor",
        "platform_system",
        "platform_machine",
        "os_family",
    }
    if not isinstance(runtime, dict) or set(runtime) != runtime_keys:
        raise ValueError("invalid capabilities runtime")
    if any(not isinstance(value, str) or not value for value in runtime.values()):
        raise ValueError("capabilities runtime values must be non-empty strings")

    adapters = payload["adapters"]
    adapter_names = {"screenshot", "windows", "uia", "input", "clipboard", "shell"}
    if not isinstance(adapters, dict) or set(adapters) != adapter_names:
        raise ValueError("invalid capabilities adapters")
    for name, entry in adapters.items():
        if not isinstance(entry, dict) or set(entry) != {
            "available",
            "provider",
            "unsupported_reason",
        }:
            raise ValueError(f"invalid adapter capability: {name}")
        if not isinstance(entry["available"], bool):
            raise ValueError(f"adapter available must be boolean: {name}")
        if entry["provider"] not in {"native", "injected", "missing"}:
            raise ValueError(f"invalid adapter provider: {name}")
        reason = entry["unsupported_reason"]
        if reason is not None and (not isinstance(reason, str) or not reason):
            raise ValueError(f"invalid adapter unsupported_reason: {name}")
        if entry["available"] and reason is not None:
            raise ValueError(f"available adapter cannot have unsupported_reason: {name}")
        if not entry["available"] and reason is None:
            raise ValueError(f"unavailable adapter requires unsupported_reason: {name}")

    actions = payload["actions"]
    if not isinstance(actions, dict) or tuple(sorted(actions)) != SUPPORTED_ACTIONS:
        raise ValueError("invalid capabilities actions")
    for name, entry in actions.items():
        if not isinstance(entry, dict) or set(entry) != {
            "supported",
            "adapter",
            "side_effecting",
            "safety_gate",
            "unsupported_reason",
        }:
            raise ValueError(f"invalid action capability: {name}")
        if not isinstance(entry["supported"], bool):
            raise ValueError(f"action supported must be boolean: {name}")
        if not isinstance(entry["side_effecting"], bool):
            raise ValueError(f"action side_effecting must be boolean: {name}")
        if entry["adapter"] is not None and entry["adapter"] not in adapter_names:
            raise ValueError(f"invalid action adapter: {name}")
        if entry["safety_gate"] is not None and not isinstance(
            entry["safety_gate"], str
        ):
            raise ValueError(f"invalid action safety_gate: {name}")
        reason = entry["unsupported_reason"]
        if reason is not None and (not isinstance(reason, str) or not reason):
            raise ValueError(f"invalid action unsupported_reason: {name}")
        if entry["supported"] and reason is not None:
            raise ValueError(f"supported action cannot have unsupported_reason: {name}")

    safety = payload["safety"]
    safety_keys = {
        "dry_run_default",
        "coordinate_fallback_enabled",
        "credential_entry_allowed",
        "captcha_entry_allowed",
        "protected_windows_roots",
        "shell_allowlist",
        "shell_output_limit_bytes",
        "operation_timeout_ms",
        "outcome_journal_configured",
    }
    if not isinstance(safety, dict) or set(safety) != safety_keys:
        raise ValueError("invalid capabilities safety")
    for key in (
        "dry_run_default",
        "coordinate_fallback_enabled",
        "credential_entry_allowed",
        "captcha_entry_allowed",
        "outcome_journal_configured",
    ):
        if not isinstance(safety[key], bool):
            raise ValueError(f"capabilities safety {key} must be boolean")
    for key in ("protected_windows_roots", "shell_allowlist"):
        value = safety[key]
        if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
            raise ValueError(f"capabilities safety {key} must be string array")
    output_limit = safety["shell_output_limit_bytes"]
    if output_limit is not None and (
        isinstance(output_limit, bool)
        or not isinstance(output_limit, int)
        or output_limit <= 0
    ):
        raise ValueError("invalid shell_output_limit_bytes")
    timeout = safety["operation_timeout_ms"]
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout < 0:
        raise ValueError("invalid operation_timeout_ms")

    attestation = payload["attestation"]
    if not isinstance(attestation, dict) or set(attestation) != {"algorithm", "digest"}:
        raise ValueError("invalid capabilities attestation")
    if attestation["algorithm"] != "sha256":
        raise ValueError("unsupported capabilities attestation algorithm")
    digest = attestation["digest"]
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(ch not in "0123456789abcdef" for ch in digest)
    ):
        raise ValueError("invalid capabilities digest")
    body = dict(payload)
    body.pop("attestation")
    expected_digest = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
    if digest != expected_digest:
        raise ValueError("capabilities attestation digest mismatch")
