from __future__ import annotations

import base64
import hashlib
import ntpath
from dataclasses import dataclass
from typing import Any, Mapping

from pc_executor.context_binding import BOUND_ACTIONS
from pc_executor.models import ActionRequest, canonical_json
from pc_executor.operations import (
    CURSOR_VERSION,
    LOG_CURSOR_VERSION,
    NATIVE_CAPABILITIES_VERSION,
    NATIVE_REQUEST_VERSION,
    NATIVE_RESULT_VERSION,
    NATIVE_TOOL_PARITY_VERSION,
    OPS_ACTIONS,
    OPS_CONTEXT_VERSION,
    OPS_PREFLIGHT_VERSION,
    OPS_SIDE_EFFECT_ACTIONS,
    PROCESS_HANDLE_VERSION,
    SEARCH_CURSOR_VERSION,
)
from pc_executor.search_sessions import SEARCH_SESSION_VERSION
from pc_executor.preflight import CONTRACT_VERSION as PREFLIGHT_CONTRACT_VERSION

from .agent import DispatchResult, TransportDispatchContext, UnknownDispatchOutcome
from .protocol import DEFAULT_MAX_STREAM_BYTES, ProtocolError

NATIVE_CONTROL_PROTOCOL_V1 = "pc.native.control.v1"
NATIVE_TOOL_REGISTRY_V1 = "pc.native.tool_registry.v1"
PARITY_TOOL_REGISTRY_V1 = "pc.native.parity_tool_registry.v1"
NATIVE_RESPONSE_V1 = "pc.native.response.v1"
MAX_PAGE_SIZE = 200
PROTECTED_ROOT = r"e:\manhwa"


@dataclass(frozen=True)
class NativeTool:
    name: str
    executor_action: str
    effect: str
    streaming: bool = False
    handle_mode: str | None = None
    destructive: bool = False

    def registry_digest_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "executorAction": self.executor_action,
            "effect": self.effect,
            "streaming": self.streaming,
            "handleMode": self.handle_mode,
            "destructive": self.destructive,
        }

    def manifest_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "executor_action": self.executor_action,
            "effect": self.effect,
            "streaming": self.streaming,
            "process_handle": self.handle_mode,
            "destructive": self.destructive,
        }


_COMPAT_TOOLS_V1 = (
    NativeTool("device.health", "system.health", "read_only"),
    NativeTool("device.get_config", "system.config.get", "read_only"),
    NativeTool("device.set_config", "system.config.set", "side_effect"),
    NativeTool("file.list", "fs.list", "read_only", True),
    NativeTool("file.info", "fs.stat", "read_only"),
    NativeTool("file.read", "fs.read_text", "read_only", True),
    NativeTool("file.read_bytes", "fs.read_bytes", "read_only", True),
    NativeTool("file.hash", "fs.hash", "read_only"),
    NativeTool("file.search", "fs.find", "read_only", True),
    NativeTool("content.search", "fs.search_text", "read_only", True),
    NativeTool("file.write", "fs.write_text", "side_effect"),
    NativeTool("file.append", "fs.append_text", "side_effect"),
    NativeTool("file.edit", "fs.edit_text", "side_effect"),
    NativeTool("file.create_dir", "fs.mkdir", "side_effect"),
    NativeTool("file.copy", "fs.copy", "side_effect"),
    NativeTool("file.move", "fs.move", "side_effect"),
    NativeTool("file.delete", "fs.delete", "side_effect", destructive=True),
    NativeTool("process.start", "process.start", "side_effect", handle_mode="create"),
    NativeTool("process.read", "process.read", "read_only", True, "use"),
    NativeTool("process.interact", "process.interact", "side_effect", handle_mode="use"),
    NativeTool("process.list", "process.list", "read_only", True),
    NativeTool("process.terminate", "process.terminate", "side_effect", handle_mode="close"),
    NativeTool("system.process.list", "system.process.list", "read_only", True),
    NativeTool("system.process.kill", "system.process.kill", "side_effect", destructive=True),
    NativeTool("shell.session.open", "shell.session.open", "side_effect", handle_mode="create"),
    NativeTool("shell.session.read", "shell.session.read", "read_only", True, "use"),
    NativeTool("shell.session.write", "shell.session.write", "side_effect", handle_mode="use"),
    NativeTool("shell.session.close", "shell.session.close", "side_effect", handle_mode="close"),
    NativeTool("shell.run", "shell.run", "side_effect"),
    NativeTool("window.list", "window.list", "read_only", True),
    NativeTool("screenshot.capture", "screenshot.capture", "read_only"),
    NativeTool("uia.find", "uia.find", "read_only", True),
    NativeTool("uia.invoke", "uia.invoke", "side_effect"),
    NativeTool("input.click", "input.click", "side_effect"),
    NativeTool("input.type", "input.type", "side_effect"),
    NativeTool("clipboard.read", "clipboard.read", "read_only"),
    NativeTool("clipboard.write", "clipboard.write", "side_effect"),
)
TOOL_REGISTRY = {tool.name: tool for tool in _COMPAT_TOOLS_V1}
TOOL_REGISTRY_LIST = tuple(sorted(_COMPAT_TOOLS_V1, key=lambda tool: tool.name))
TOOL_REGISTRY_DIGEST = hashlib.sha256(
    canonical_json(
        {
            "contract_version": NATIVE_TOOL_REGISTRY_V1,
            "tools": [tool.registry_digest_dict() for tool in TOOL_REGISTRY_LIST],
        }
    ).encode("utf-8")
).hexdigest()

# Compatibility v1 is the frozen A/control-facing registry. Its digest must
# never change as parity actions evolve; newer/native actions are exposed only
# through the separate parity registry below.
EXPECTED_COMPAT_TOOL_REGISTRY_V1_DIGEST = (
    "58b2bde8c6a49825747dcd7010f105dad0b6d548c7e8341cdafb32d2319f6dcd"
)
if TOOL_REGISTRY_DIGEST != EXPECTED_COMPAT_TOOL_REGISTRY_V1_DIGEST:
    raise RuntimeError("pc.native.tool_registry.v1 compatibility digest drifted")

_PARITY_TOOLS = (
    NativeTool("device.info", "device.info", "read_only"),
    NativeTool("device.health", "health.get", "read_only"),
    NativeTool("device.get_config", "config.get", "read_only"),
    NativeTool("device.set_config", "config.set", "side_effect"),
    NativeTool("identity.who_am_i", "identity.who_am_i", "read_only"),
    NativeTool("agent.shutdown", "agent.shutdown", "side_effect"),
    NativeTool("file.list", "fs.list", "read_only", True),
    NativeTool("file.info", "fs.stat", "read_only"),
    NativeTool("file.read", "fs.read_text", "read_only", True),
    NativeTool("file.read_multiple", "fs.read_multiple", "read_only"),
    NativeTool("file.read_bytes", "fs.read_bytes", "read_only", True),
    NativeTool("file.hash", "fs.hash", "read_only"),
    NativeTool("file.search", "fs.find", "read_only", True),
    NativeTool("file.glob", "fs.glob", "read_only", True),
    NativeTool("content.search", "fs.search", "read_only", True),
    NativeTool("file.write", "fs.write_text", "side_effect"),
    NativeTool("file.append", "fs.append_text", "side_effect"),
    NativeTool("file.edit", "fs.edit_text", "side_effect"),
    NativeTool("file.create_dir", "fs.mkdir", "side_effect"),
    NativeTool("file.copy", "fs.copy", "side_effect"),
    NativeTool("file.move", "fs.move", "side_effect"),
    NativeTool("file.delete", "fs.delete", "side_effect", destructive=True),
    NativeTool("log.tail", "log.tail", "read_only", True),
    NativeTool("log.read_since", "log.read_since", "read_only", True),
    NativeTool("log.search", "log.search", "read_only", True),
    NativeTool("search.start", "search.start", "side_effect", handle_mode="create"),
    NativeTool("search.read", "search.read", "read_only", True, "use"),
    NativeTool("search.list", "search.list", "read_only"),
    NativeTool("search.stop", "search.stop", "side_effect", handle_mode="use"),
    NativeTool("process.start", "process.start", "side_effect", handle_mode="create"),
    NativeTool("process.read", "process.read_output", "read_only", True, "use"),
    NativeTool("process.status", "process.status", "read_only", handle_mode="use"),
    NativeTool("process.list", "process.managed.list", "read_only", True),
    NativeTool("process.terminate", "process.terminate", "side_effect", handle_mode="close"),
    NativeTool("system.process.list", "process.list", "read_only", True),
    NativeTool("system.process.inspect", "process.inspect", "read_only"),
    NativeTool("system.process.kill", "system.process.kill", "side_effect", destructive=True),
    NativeTool("shell.session.open", "shell.session.start", "side_effect", handle_mode="create"),
    NativeTool("shell.session.read", "shell.session.read", "read_only", True, "use"),
    NativeTool("shell.session.write", "shell.session.write_stdin", "side_effect", handle_mode="use"),
    NativeTool("shell.session.close", "shell.session.terminate", "side_effect", handle_mode="close"),
    NativeTool("diagnostics.usage_stats", "diagnostics.usage_stats", "read_only"),
    NativeTool("diagnostics.recent_tool_calls", "diagnostics.recent_tool_calls", "read_only"),
    NativeTool("pdf.write", "pdf.write", "side_effect"),
    NativeTool("system.info", "system.info", "read_only"),
    NativeTool("system.resources", "system.resources", "read_only"),
    NativeTool("system.paths", "system.paths", "read_only"),
)
PARITY_TOOL_REGISTRY = {tool.name: tool for tool in _PARITY_TOOLS}
PARITY_TOOL_REGISTRY_LIST = tuple(sorted(_PARITY_TOOLS, key=lambda tool: tool.name))
PARITY_TOOL_REGISTRY_DIGEST = hashlib.sha256(
    canonical_json(
        {
            "contract_version": PARITY_TOOL_REGISTRY_V1,
            "tools": [tool.registry_digest_dict() for tool in PARITY_TOOL_REGISTRY_LIST],
        }
    ).encode("utf-8")
).hexdigest()

if not {tool.executor_action for tool in PARITY_TOOL_REGISTRY_LIST} <= set(OPS_ACTIONS):
    raise RuntimeError("remote parity registry contains non-parity actions")
if any(
    (tool.effect == "side_effect") != (tool.executor_action in OPS_SIDE_EFFECT_ACTIONS)
    for tool in PARITY_TOOL_REGISTRY_LIST
):
    raise RuntimeError("remote parity registry effect classification drifted")

_COMPAT_PARITY_ACTION_BY_TOOL = {
    "device.health": "health.get",
    "device.get_config": "config.get",
    "device.set_config": "config.set",
    "file.list": "fs.list",
    "file.info": "fs.stat",
    "file.read": "fs.read_text",
    "file.read_bytes": "fs.read_bytes",
    "file.hash": "fs.hash",
    "file.search": "fs.find",
    "content.search": "fs.search",
    "file.write": "fs.write_text",
    "file.append": "fs.append_text",
    "file.edit": "fs.edit_text",
    "file.create_dir": "fs.mkdir",
    "file.copy": "fs.copy",
    "file.move": "fs.move",
    "file.delete": "fs.delete",
    "process.start": "process.start",
    "process.read": "process.read_output",
    "process.interact": "shell.session.write_stdin",
    "process.list": "process.managed.list",
    "process.terminate": "process.terminate",
    "system.process.list": "process.list",
    "system.process.kill": "system.process.kill",
    "shell.session.open": "shell.session.start",
    "shell.session.read": "shell.session.read",
    "shell.session.write": "shell.session.write_stdin",
    "shell.session.close": "shell.session.terminate",
}
_COMPAT_LEGACY_ACTION_BY_TOOL = {
    "shell.run": "shell.run",
    "window.list": "windows.list",
    "screenshot.capture": "screenshot.capture",
    "uia.invoke": "uia.invoke",
    "input.click": "mouse.click",
    "input.type": "keyboard.type_text",
    "clipboard.read": "clipboard.get",
    "clipboard.write": "clipboard.set",
}
_COMPAT_UNAVAILABLE = {
    "uia.find": "No current parity or legacy Executor action provides uia.find semantics."
}
if (
    set(_COMPAT_PARITY_ACTION_BY_TOOL)
    | set(_COMPAT_LEGACY_ACTION_BY_TOOL)
    | set(_COMPAT_UNAVAILABLE)
) != set(TOOL_REGISTRY):
    raise RuntimeError("compatibility registry route coverage drifted")
if not set(_COMPAT_PARITY_ACTION_BY_TOOL.values()) <= set(OPS_ACTIONS):
    raise RuntimeError("compatibility parity routes contain non-parity actions")

_EXPECTED_PARITY_SCHEMA_VERSIONS = {
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
}


class NativeAdapterError(ValueError):
    def __init__(
        self,
        message: str,
        *,
        code: str,
        category: str,
        retryable: bool = False,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.category = category
        self.retryable = retryable
        self.details = details


@dataclass
class _HandleRecord:
    handle: str
    session_id: str
    device_id: str
    session_epoch: str
    capabilities_digest: str
    tool: str
    open: bool = True


def _response(
    *,
    request_id: str,
    session_id: str,
    status: str,
    data: Any = None,
    error: dict[str, Any] | None = None,
    stream: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "contract_version": NATIVE_RESPONSE_V1,
        "request_id": request_id,
        "session_id": session_id,
        "status": status,
        "data": data,
        "error": error,
        "stream": stream,
    }


def _error_response(
    error: NativeAdapterError,
    *,
    request_id: str,
    session_id: str,
) -> dict[str, Any]:
    return _response(
        request_id=request_id,
        session_id=session_id,
        status="error",
        error={
            "code": error.code,
            "category": error.category,
            "message": str(error),
            "retryable": error.retryable,
            "details": error.details,
        },
    )


def _mapping(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise NativeAdapterError(
            f"{where} must be an object",
            code="INVALID_ARGUMENT",
            category="schema",
        )
    return dict(value)


def _text(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise NativeAdapterError(
            f"{where} must be a non-empty string",
            code="INVALID_ARGUMENT",
            category="schema",
        )
    return value


def _has_protected_path(value: Any) -> bool:
    if isinstance(value, str):
        candidate = value.replace("/", "\\")
        while "\\\\" in candidate:
            candidate = candidate.replace("\\\\", "\\")
        candidate = ntpath.normcase(ntpath.normpath(candidate))
        return candidate == PROTECTED_ROOT or candidate.startswith(PROTECTED_ROOT + "\\")
    if isinstance(value, list):
        return any(_has_protected_path(item) for item in value)
    if isinstance(value, Mapping):
        return any(_has_protected_path(item) for item in value.values())
    return False


def _input_handle(arguments: Mapping[str, Any]) -> str | None:
    for key in (
        "process_handle",
        "session_handle",
        "search_id",
        "handle",
        "handle_id",
        "session_id",
    ):
        value = arguments.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _result_handle(data: Mapping[str, Any]) -> str | None:
    return _input_handle(data)


def _as_dict(value: Any) -> dict[str, Any]:
    if hasattr(value, "to_dict") and callable(value.to_dict):
        value = value.to_dict()
    if not isinstance(value, dict):
        raise NativeAdapterError(
            "Executor returned a non-object result",
            code="PROVIDER_PROTOCOL_ERROR",
            category="provider",
        )
    return value


def _outcome_dict(raw: Mapping[str, Any]) -> dict[str, Any] | None:
    value = raw.get("outcome_evidence")
    return dict(value) if isinstance(value, Mapping) else None


def _stream_projection(
    tool: NativeTool,
    data: Mapping[str, Any],
    *,
    executor_action: str,
) -> tuple[bytes, str, str] | None:
    if not tool.streaming:
        return None

    if executor_action == "fs.read_text":
        for key in ("text", "content"):
            value = data.get(key)
            if isinstance(value, str):
                return value.encode("utf-8"), "file_read", "utf-8"

    if executor_action == "fs.read_bytes":
        for key in ("data_b64", "bytes_b64", "content_b64"):
            value = data.get(key)
            if isinstance(value, str):
                try:
                    return base64.b64decode(value.encode("ascii"), validate=True), "file_read", "binary"
                except Exception as exc:
                    raise NativeAdapterError(
                        "Executor returned invalid base64 file bytes",
                        code="PROVIDER_PROTOCOL_ERROR",
                        category="provider",
                    ) from exc

    kind = "process_output" if executor_action in {
        "process.read_output",
        "process.managed.list",
        "process.list",
        "shell.session.read",
    } else "file_read" if executor_action.startswith("fs.") else "provider_stream"
    return canonical_json(dict(data)).encode("utf-8"), kind, "json"


class ExecutorRemoteDispatcher:
    """Maps pc.native.control.v1 envelopes into the existing Executor boundary only."""

    def __init__(
        self,
        executor: Any,
        *,
        max_stream_bytes: int = DEFAULT_MAX_STREAM_BYTES,
        max_page_size: int = MAX_PAGE_SIZE,
    ) -> None:
        self.executor = executor
        self.max_stream_bytes = max_stream_bytes
        self.max_page_size = max_page_size
        self._handles: dict[str, _HandleRecord] = {}
        self._session_devices: dict[str, str] = {}

    @property
    def shutdown_requested(self) -> bool:
        operations = getattr(self.executor, "operations", None)
        return bool(getattr(operations, "shutdown_requested", False))

    @staticmethod
    def _snapshot_actions(snapshot: Mapping[str, Any], where: str) -> dict[str, Any]:
        actions = snapshot.get("actions")
        if not isinstance(actions, Mapping):
            raise NativeAdapterError(
                f"{where} actions must be an object",
                code="PROVIDER_PROTOCOL_ERROR",
                category="provider",
            )
        return dict(actions)

    @staticmethod
    def _snapshot_digest(snapshot: Mapping[str, Any], where: str) -> str:
        attestation = _mapping(snapshot.get("attestation"), f"{where} attestation")
        return _text(attestation.get("digest"), f"{where} capabilities digest")

    def _legacy_capabilities(self) -> dict[str, Any]:
        capabilities = _as_dict(self.executor.capabilities_snapshot())
        self._snapshot_actions(capabilities, "Executor capabilities")
        self._snapshot_digest(capabilities, "Executor")
        return capabilities

    def _parity_capabilities(self) -> dict[str, Any]:
        operations = getattr(self.executor, "operations", None)
        provider = getattr(operations, "capabilities_snapshot", None)
        if not callable(provider):
            raise NativeAdapterError(
                "Executor native tool-parity capabilities are unavailable",
                code="PROVIDER_PROTOCOL_ERROR",
                category="provider",
            )
        capabilities = _as_dict(provider())
        if capabilities.get("native_tool_parity_version") != NATIVE_TOOL_PARITY_VERSION:
            raise NativeAdapterError(
                "Executor native tool-parity contract mismatch",
                code="SCHEMA_VERSION_MISMATCH",
                category="capability_mismatch",
            )
        schema_versions = _mapping(
            capabilities.get("schema_versions"),
            "native tool-parity schema_versions",
        )
        if schema_versions != _EXPECTED_PARITY_SCHEMA_VERSIONS:
            raise NativeAdapterError(
                "Executor native tool-parity schema versions drifted",
                code="SCHEMA_VERSION_MISMATCH",
                category="capability_mismatch",
                details={
                    "expected": dict(_EXPECTED_PARITY_SCHEMA_VERSIONS),
                    "actual": schema_versions,
                },
            )
        actions = self._snapshot_actions(capabilities, "native tool-parity capabilities")
        if set(actions) != set(OPS_ACTIONS):
            raise NativeAdapterError(
                "Executor native tool-parity action inventory drifted",
                code="CAPABILITY_DRIFT",
                category="capability_mismatch",
                details={
                    "missing": sorted(set(OPS_ACTIONS) - set(actions)),
                    "extra": sorted(set(actions) - set(OPS_ACTIONS)),
                },
            )
        for action in OPS_ACTIONS:
            entry = actions[action]
            if not isinstance(entry, Mapping) or entry.get("supported") is not True:
                raise NativeAdapterError(
                    f"Executor parity action {action!r} is not supported",
                    code="CAPABILITY_DRIFT",
                    category="capability_mismatch",
                )
            if entry.get("tool_contract_version") != NATIVE_TOOL_PARITY_VERSION:
                raise NativeAdapterError(
                    f"Executor parity action {action!r} contract version drifted",
                    code="SCHEMA_VERSION_MISMATCH",
                    category="capability_mismatch",
                )
            if entry.get("side_effecting") is not (action in OPS_SIDE_EFFECT_ACTIONS):
                raise NativeAdapterError(
                    f"Executor parity action {action!r} effect classification drifted",
                    code="CAPABILITY_SEMANTICS_MISMATCH",
                    category="capability_mismatch",
                )
        self._snapshot_digest(capabilities, "native tool-parity")
        return capabilities

    def _manifest_from_snapshots(
        self,
        legacy_capabilities: dict[str, Any],
        parity_capabilities: dict[str, Any],
    ) -> dict[str, Any]:
        legacy_actions = self._snapshot_actions(
            legacy_capabilities,
            "Executor capabilities",
        )
        parity_actions = self._snapshot_actions(
            parity_capabilities,
            "native tool-parity capabilities",
        )
        legacy_supported = sorted(
            name
            for name, entry in legacy_actions.items()
            if isinstance(entry, Mapping) and entry.get("supported") is True
        )
        parity_supported = sorted(
            name
            for name, entry in parity_actions.items()
            if isinstance(entry, Mapping) and entry.get("supported") is True
        )
        compatibility_routes = {
            name: {
                "status": (
                    "capability_unavailable"
                    if name in _COMPAT_UNAVAILABLE
                    else "translated"
                ),
                "surface": (
                    "unavailable"
                    if name in _COMPAT_UNAVAILABLE
                    else "parity"
                    if name in _COMPAT_PARITY_ACTION_BY_TOOL
                    else "legacy_executor"
                ),
                "target_action": (
                    None
                    if name in _COMPAT_UNAVAILABLE
                    else _COMPAT_PARITY_ACTION_BY_TOOL.get(name)
                    or _COMPAT_LEGACY_ACTION_BY_TOOL.get(name)
                ),
            }
            for name in sorted(TOOL_REGISTRY)
        }
        parity_digest = self._snapshot_digest(
            parity_capabilities,
            "native tool-parity",
        )
        return {
            "contract_version": NATIVE_TOOL_REGISTRY_V1,
            "protocol_version": NATIVE_CONTROL_PROTOCOL_V1,
            "registry_digest": TOOL_REGISTRY_DIGEST,
            "limits": {
                "max_page_size": self.max_page_size,
                "max_body_bytes": 1024 * 1024,
            },
            "executor": {
                "contract_version": _text(
                    parity_capabilities.get("contract_version"),
                    "native tool-parity contract_version",
                ),
                "digest": parity_digest,
                "actions": parity_supported,
                "native_tool_parity_version": NATIVE_TOOL_PARITY_VERSION,
                "schema_versions": dict(_EXPECTED_PARITY_SCHEMA_VERSIONS),
            },
            "tool_parity": parity_capabilities,
            "internal_registry": {
                "contract_version": PARITY_TOOL_REGISTRY_V1,
                "registry_digest": PARITY_TOOL_REGISTRY_DIGEST,
                "tools": [
                    tool.manifest_dict()
                    for tool in PARITY_TOOL_REGISTRY_LIST
                ],
            },
            "compatibility": {
                "contract_version": NATIVE_TOOL_REGISTRY_V1,
                "registry_digest": TOOL_REGISTRY_DIGEST,
                "default_for_unversioned_requests": True,
                "routes": compatibility_routes,
                "legacy_executor": {
                    "contract_version": _text(
                        legacy_capabilities.get("contract_version"),
                        "Executor capabilities contract_version",
                    ),
                    "digest": self._snapshot_digest(
                        legacy_capabilities,
                        "Executor",
                    ),
                    "actions": legacy_supported,
                },
            },
            "tools": [tool.manifest_dict() for tool in TOOL_REGISTRY_LIST],
        }

    def capability_manifest(self) -> dict[str, Any]:
        legacy_capabilities = self._legacy_capabilities()
        parity_capabilities = self._parity_capabilities()
        return self._manifest_from_snapshots(
            legacy_capabilities,
            parity_capabilities,
        )

    def _validate_envelope(
        self,
        request_version: str,
        request_id: str,
        body: dict[str, Any],
        context: TransportDispatchContext,
    ) -> tuple[dict[str, Any], NativeTool, dict[str, Any], str, str]:
        if request_version != NATIVE_CONTROL_PROTOCOL_V1:
            raise NativeAdapterError(
                "Unsupported transport request_version",
                code="SCHEMA_VERSION_MISMATCH",
                category="capability_mismatch",
            )
        envelope = _mapping(body, "native request envelope")
        allowed = {
            "contract_version",
            "registry_version",
            "session_id",
            "request_id",
            "tool",
            "arguments",
            "page",
            "execution_context",
        }
        required = {"contract_version", "session_id", "request_id", "tool"}
        missing = required - set(envelope)
        extra = set(envelope) - allowed
        if missing or extra:
            raise NativeAdapterError(
                f"Request envelope keys mismatch; missing={sorted(missing)}, extra={sorted(extra)}",
                code="INVALID_ARGUMENT",
                category="schema",
            )
        if envelope["contract_version"] != NATIVE_CONTROL_PROTOCOL_V1:
            raise NativeAdapterError(
                "Unsupported request envelope version",
                code="SCHEMA_VERSION_MISMATCH",
                category="capability_mismatch",
            )
        if _text(envelope["request_id"], "request_id") != request_id:
            raise NativeAdapterError(
                "Transport and control request_id differ",
                code="REQUEST_ID_MISMATCH",
                category="idempotency",
            )
        registry_version = envelope.get("registry_version", NATIVE_TOOL_REGISTRY_V1)
        if registry_version not in {
            NATIVE_TOOL_REGISTRY_V1,
            PARITY_TOOL_REGISTRY_V1,
        }:
            raise NativeAdapterError(
                "Unsupported native tool registry version",
                code="SCHEMA_VERSION_MISMATCH",
                category="capability_mismatch",
                details={"registry_version": registry_version},
            )
        session_id = _text(envelope["session_id"], "session_id")
        owner = self._session_devices.get(session_id)
        if owner is None:
            self._session_devices[session_id] = context.device_id
        elif owner != context.device_id:
            raise NativeAdapterError(
                "Control session belongs to another device",
                code="STALE_SESSION",
                category="session",
            )
        operations = getattr(self.executor, "operations", None)
        binder = getattr(operations, "bind_agent_session", None)
        if callable(binder):
            binder(
                device_id=context.device_id,
                session_id=session_id,
                session_epoch=context.session_epoch,
            )
        tool_name = _text(envelope["tool"], "tool")
        registry = (
            TOOL_REGISTRY
            if registry_version == NATIVE_TOOL_REGISTRY_V1
            else PARITY_TOOL_REGISTRY
        )
        tool = registry.get(tool_name)
        if tool is None:
            raise NativeAdapterError(
                f"Unknown native tool {tool_name!r} for {registry_version}",
                code="TOOL_NOT_FOUND",
                category="tool",
                details={"registry_version": registry_version},
            )
        if (
            registry_version == NATIVE_TOOL_REGISTRY_V1
            and tool.name in _COMPAT_UNAVAILABLE
        ):
            raise NativeAdapterError(
                _COMPAT_UNAVAILABLE[tool.name],
                code="CAPABILITY_UNAVAILABLE",
                category="capability_mismatch",
                details={
                    "registry_version": registry_version,
                    "tool": tool.name,
                },
            )
        arguments = _mapping(envelope.get("arguments", {}), "arguments")
        if _has_protected_path(arguments):
            raise NativeAdapterError(
                "Protected path is outside native remote dispatch scope",
                code="PROTECTED_PATH_BLOCKED",
                category="policy",
            )
        self._validate_page(envelope.get("page"), tool, arguments)
        self._validate_execution_context_envelope(envelope.get("execution_context"), context)
        return envelope, tool, arguments, session_id, registry_version

    def _validate_page(self, page: Any, tool: NativeTool, arguments: dict[str, Any]) -> None:
        if page is None:
            return
        if not tool.streaming:
            raise NativeAdapterError(
                "page is only valid for streaming tools",
                code="INVALID_ARGUMENT",
                category="bounds",
            )
        page = _mapping(page, "page")
        if set(page) - {"limit", "cursor"}:
            raise NativeAdapterError(
                "page contains unsupported keys",
                code="INVALID_ARGUMENT",
                category="bounds",
            )
        limit = page.get("limit", self.max_page_size)
        if isinstance(limit, bool) or not isinstance(limit, int) or not (1 <= limit <= self.max_page_size):
            raise NativeAdapterError(
                f"page.limit must be 1..{self.max_page_size}",
                code="PAGE_LIMIT_EXCEEDED",
                category="bounds",
            )
        arguments["limit"] = limit
        cursor = page.get("cursor")
        if cursor is not None:
            arguments["cursor"] = _text(cursor, "page.cursor")

    def _validate_execution_context_envelope(
        self,
        value: Any,
        context: TransportDispatchContext,
    ) -> None:
        if value is None:
            return
        raw = _mapping(value, "execution_context")
        if set(raw) != {"device_id", "session_epoch", "binding"}:
            raise NativeAdapterError(
                "execution_context keys mismatch",
                code="INVALID_ARGUMENT",
                category="execution_context",
            )
        if raw["device_id"] != context.device_id or raw["session_epoch"] != context.session_epoch:
            raise NativeAdapterError(
                "Execution context belongs to a stale device/session epoch",
                code="STALE_EXECUTION_CONTEXT",
                category="execution_context",
            )
        _mapping(raw["binding"], "execution_context.binding")

    def _assert_capability_stability(
        self,
        context: TransportDispatchContext,
        tool: NativeTool,
        registry_version: str,
    ) -> tuple[str, str, str]:
        legacy_capabilities = self._legacy_capabilities()
        parity_capabilities = self._parity_capabilities()
        manifest = self._manifest_from_snapshots(
            legacy_capabilities,
            parity_capabilities,
        )
        manifest_digest = hashlib.sha256(
            canonical_json(manifest).encode("utf-8")
        ).hexdigest()
        if manifest_digest != context.session_capabilities_digest:
            raise NativeAdapterError(
                "Executor/native capability manifest drifted after device hello",
                code="CAPABILITY_DRIFT",
                category="capability_mismatch",
                details={
                    "hello_manifest_digest": context.session_capabilities_digest,
                    "current_manifest_digest": manifest_digest,
                },
            )

        if registry_version == PARITY_TOOL_REGISTRY_V1:
            resolved_action = tool.executor_action
            surface = "parity"
            snapshot = parity_capabilities
            where = "native tool-parity"
        elif tool.name in _COMPAT_PARITY_ACTION_BY_TOOL:
            resolved_action = _COMPAT_PARITY_ACTION_BY_TOOL[tool.name]
            surface = "parity"
            snapshot = parity_capabilities
            where = "native tool-parity"
        elif tool.name in _COMPAT_LEGACY_ACTION_BY_TOOL:
            resolved_action = _COMPAT_LEGACY_ACTION_BY_TOOL[tool.name]
            surface = "legacy_executor"
            snapshot = legacy_capabilities
            where = "Executor"
        else:
            raise NativeAdapterError(
                _COMPAT_UNAVAILABLE.get(
                    tool.name,
                    f"No compatibility route for {tool.name!r}",
                ),
                code="CAPABILITY_UNAVAILABLE",
                category="capability_mismatch",
                details={
                    "registry_version": registry_version,
                    "tool": tool.name,
                },
            )

        actions = self._snapshot_actions(snapshot, f"{where} capabilities")
        action_capability = actions.get(resolved_action)
        if (
            not isinstance(action_capability, Mapping)
            or action_capability.get("supported") is not True
        ):
            raise NativeAdapterError(
                f"Executor does not advertise action {resolved_action!r}",
                code="CAPABILITY_UNAVAILABLE",
                category="capability_mismatch",
                details={
                    "registry_version": registry_version,
                    "tool": tool.name,
                    "target_action": resolved_action,
                    "surface": surface,
                },
            )
        expected_side_effect = tool.effect == "side_effect"
        if action_capability.get("side_effecting") is not expected_side_effect:
            raise NativeAdapterError(
                "Executor action effect classification disagrees with native registry",
                code="CAPABILITY_SEMANTICS_MISMATCH",
                category="capability_mismatch",
                details={
                    "tool": tool.name,
                    "target_action": resolved_action,
                    "surface": surface,
                },
            )
        return resolved_action, self._snapshot_digest(snapshot, where), surface

    @staticmethod
    def _translated_arguments(
        tool: NativeTool,
        executor_action: str,
        arguments: Mapping[str, Any],
    ) -> dict[str, Any]:
        params = dict(arguments)
        if executor_action in {"process.read_output", "process.terminate", "process.status"}:
            handle = _input_handle(params)
            for key in ("process_handle", "session_handle", "handle"):
                params.pop(key, None)
            if handle is not None:
                params["handle_id"] = handle
        elif executor_action in {
            "shell.session.read",
            "shell.session.write_stdin",
            "shell.session.terminate",
        }:
            handle = _input_handle(params)
            for key in ("process_handle", "session_handle", "handle", "handle_id"):
                params.pop(key, None)
            if handle is not None:
                params["session_id"] = handle
            if (
                executor_action == "shell.session.write_stdin"
                and "input" in params
                and "text" not in params
            ):
                params["text"] = params.pop("input")

        if executor_action in {"fs.list", "fs.find", "fs.search", "process.list", "process.managed.list"}:
            limit = params.pop("limit", None)
            if limit is not None:
                target = "max_entries" if executor_action == "fs.list" else "max_results"
                params.setdefault(target, limit)
        if executor_action == "process.read_output":
            limit = params.pop("limit", None)
            if limit is not None:
                params.setdefault("max_bytes", limit)
        if executor_action == "search.read":
            limit = params.pop("limit", None)
            if limit is not None:
                params.setdefault("length", limit)
            cursor = params.pop("cursor", None)
            if cursor is not None and "offset" not in params:
                try:
                    params["offset"] = int(cursor)
                except (TypeError, ValueError) as exc:
                    raise NativeAdapterError(
                        "search.read page.cursor must be an integer offset",
                        code="INVALID_ARGUMENT",
                        category="bounds",
                    ) from exc
        if executor_action == "fs.search" and "pattern" in params and "query" not in params:
            params["query"] = params.pop("pattern")
        return params

    def _assert_handle(
        self,
        tool: NativeTool,
        arguments: Mapping[str, Any],
        *,
        session_id: str,
        context: TransportDispatchContext,
    ) -> None:
        if tool.handle_mode not in {"use", "close"}:
            return
        handle = _input_handle(arguments)
        record = self._handles.get(handle or "")
        if (
            record is None
            or not record.open
            or record.session_id != session_id
            or record.device_id != context.device_id
            or record.session_epoch != context.session_epoch
            or record.capabilities_digest != context.session_capabilities_digest
        ):
            search_handle = tool.name.startswith("search.")
            raise NativeAdapterError(
                (
                    "Search handle is stale for this device/session epoch or capability digest"
                    if search_handle
                    else "Process/session handle is stale for this device/session epoch"
                ),
                code="STALE_SEARCH_HANDLE" if search_handle else "STALE_PROCESS_HANDLE",
                category="search_handle" if search_handle else "process_handle",
            )

    def _assert_compat_handle_semantics(
        self,
        tool: NativeTool,
        registry_version: str,
        arguments: Mapping[str, Any],
    ) -> None:
        if (
            registry_version != NATIVE_TOOL_REGISTRY_V1
            or tool.name != "process.interact"
        ):
            return
        handle = _input_handle(arguments)
        record = self._handles.get(handle or "")
        if record is None or record.tool != "shell.session.open":
            raise NativeAdapterError(
                "process.interact compatibility requires a handle created by shell.session.open",
                code="CAPABILITY_UNAVAILABLE",
                category="capability_mismatch",
                details={
                    "tool": tool.name,
                    "required_handle_tool": "shell.session.open",
                },
            )

    def _register_or_close_handle(
        self,
        tool: NativeTool,
        arguments: Mapping[str, Any],
        data: Mapping[str, Any],
        *,
        session_id: str,
        context: TransportDispatchContext,
    ) -> None:
        if tool.handle_mode == "create":
            handle = _result_handle(data)
            if handle:
                self._handles[handle] = _HandleRecord(
                    handle=handle,
                    session_id=session_id,
                    device_id=context.device_id,
                    session_epoch=context.session_epoch,
                    capabilities_digest=context.session_capabilities_digest,
                    tool=tool.name,
                )
        elif tool.handle_mode == "close":
            handle = _input_handle(arguments)
            record = self._handles.get(handle or "")
            if record is not None:
                record.open = False

    def _filter_search_list(
        self,
        data: Mapping[str, Any],
        *,
        session_id: str,
        context: TransportDispatchContext,
    ) -> dict[str, Any]:
        raw = dict(data)
        searches = raw.get("searches")
        if not isinstance(searches, list):
            return raw
        visible: list[dict[str, Any]] = []
        for item in searches:
            if not isinstance(item, Mapping):
                continue
            search_id = item.get("search_id")
            record = self._handles.get(search_id) if isinstance(search_id, str) else None
            if (
                record is not None
                and record.open
                and record.tool == "search.start"
                and record.session_id == session_id
                and record.device_id == context.device_id
                and record.session_epoch == context.session_epoch
                and record.capabilities_digest == context.session_capabilities_digest
            ):
                visible.append(dict(item))
        raw["searches"] = visible
        raw["count"] = len(visible)
        return raw

    def _preflight(
        self,
        *,
        request_id: str,
        action: str,
        arguments: dict[str, Any],
        executor_digest: str,
    ) -> dict[str, Any]:
        result = self.executor.preflight(
            {
                "contract_version": PREFLIGHT_CONTRACT_VERSION,
                "request": {
                    "request_id": request_id,
                    "action": action,
                    "params": arguments,
                    "dry_run": None,
                    "timeout_ms": None,
                },
            }
        )
        raw = _as_dict(result)
        if raw.get("capabilities_digest") != executor_digest:
            raise NativeAdapterError(
                "Executor capability digest changed during preflight",
                code="CAPABILITY_DRIFT",
                category="capability_mismatch",
            )
        if raw.get("status") != "ready" or raw.get("executable") is not True:
            raise NativeAdapterError(
                "Executor preflight rejected request",
                code="EXECUTOR_PREFLIGHT_REJECTED",
                category="policy",
                details={"preflight": raw},
            )
        return raw

    def _assert_side_effect_replay_safe(
        self,
        *,
        request_id: str,
        action: str,
    ) -> None:
        if getattr(self.executor, "outcome_journal", None) is None:
            raise NativeAdapterError(
                "Side effects require the Executor durable outcome journal",
                code="OUTCOME_JOURNAL_REQUIRED",
                category="idempotency",
            )
        lookup = _as_dict(
            self.executor.read_outcome_evidence(
                request_id=request_id,
                action=action,
            )
        )
        if lookup.get("reason") == "journal_not_configured":
            raise NativeAdapterError(
                "Side effects require the Executor durable outcome journal",
                code="OUTCOME_JOURNAL_REQUIRED",
                category="idempotency",
            )
        provenance = lookup.get("provenance")
        matched = provenance.get("matched_records", 0) if isinstance(provenance, Mapping) else 0
        if matched or lookup.get("latest_valid_record") is not None:
            raise UnknownDispatchOutcome(
                "Executor already has outcome evidence for this side-effect request; reconciliation is required"
            )

    def _execution_binding(
        self,
        envelope: Mapping[str, Any],
        request: ActionRequest,
        tool: NativeTool,
        executor_action: str,
    ) -> dict[str, Any] | None:
        wrapped = envelope.get("execution_context")
        if wrapped is not None:
            return dict(_mapping(wrapped, "execution_context")["binding"])
        if tool.effect == "side_effect" and executor_action in BOUND_ACTIONS:
            try:
                return dict(self.executor.bind_execution_context(request))
            except Exception as exc:
                raise NativeAdapterError(
                    "Unable to derive Executor execution-context binding",
                    code="EXECUTION_CONTEXT_BIND_FAILED",
                    category="execution_context",
                    details={"error": f"{type(exc).__name__}: {exc}"},
                ) from exc
        return None

    async def dispatch(
        self,
        *,
        request_version: str,
        request_id: str,
        body: dict[str, Any],
        transport_context: TransportDispatchContext | None = None,
    ) -> DispatchResult:
        session_id = ""
        try:
            if transport_context is None:
                raise NativeAdapterError(
                    "Transport dispatch context is required",
                    code="TRANSPORT_CONTEXT_REQUIRED",
                    category="transport",
                )
            (
                envelope,
                tool,
                arguments,
                session_id,
                registry_version,
            ) = self._validate_envelope(
                request_version,
                request_id,
                body,
                transport_context,
            )
            (
                executor_action,
                executor_digest,
                action_surface,
            ) = self._assert_capability_stability(
                transport_context,
                tool,
                registry_version,
            )
            self._assert_handle(
                tool,
                arguments,
                session_id=session_id,
                context=transport_context,
            )
            self._assert_compat_handle_semantics(
                tool,
                registry_version,
                arguments,
            )
            executor_arguments = self._translated_arguments(
                tool,
                executor_action,
                arguments,
            )
            if tool.effect == "side_effect":
                self._assert_side_effect_replay_safe(
                    request_id=request_id,
                    action=executor_action,
                )
            self._preflight(
                request_id=request_id,
                action=executor_action,
                arguments=executor_arguments,
                executor_digest=executor_digest,
            )
            action_request = ActionRequest.from_dict(
                {
                    "request_id": request_id,
                    "action": executor_action,
                    "params": executor_arguments,
                    "dry_run": None,
                    "timeout_ms": None,
                }
            )
            binding = self._execution_binding(
                envelope,
                action_request,
                tool,
                executor_action,
            )
            if binding is not None:
                action_request.execution_context_binding = binding

            result = self.executor.execute(action_request)
            raw = _as_dict(result)
            if raw.get("request_id") != request_id or raw.get("action") != executor_action:
                if tool.effect == "side_effect":
                    raise UnknownDispatchOutcome("Executor result identity mismatch after side-effect dispatch")
                raise NativeAdapterError(
                    "Executor result identity mismatch",
                    code="PROVIDER_PROTOCOL_ERROR",
                    category="provider",
                )

            outcome = _outcome_dict(raw)
            if tool.effect == "side_effect":
                if outcome is None:
                    raise UnknownDispatchOutcome("Executor side-effect result lacks durable outcome evidence")
                if outcome.get("reconciliation_required") is True or outcome.get("effect_state") == "unknown":
                    raise UnknownDispatchOutcome("Executor side-effect outcome is unknown")
                if raw.get("ok") is True and outcome.get("effect_state") != "completed" and raw.get("dry_run") is not True:
                    raise UnknownDispatchOutcome("Executor did not prove side-effect completion")

            data = raw.get("data")
            if not isinstance(data, Mapping):
                data = {}
            data = dict(data)
            if executor_action == "search.list":
                data = self._filter_search_list(
                    data,
                    session_id=session_id,
                    context=transport_context,
                )
            if raw.get("ok") is not True:
                raise NativeAdapterError(
                    str(raw.get("error") or "Executor rejected request"),
                    code="EXECUTOR_BLOCKED" if raw.get("status") == "blocked" else "EXECUTION_FAILED",
                    category="execution",
                    details={
                        "executor_status": raw.get("status"),
                        "error_kind": raw.get("error_kind"),
                        "data": data,
                        "outcome_evidence": outcome,
                    },
                )

            self._register_or_close_handle(
                tool,
                arguments,
                data,
                session_id=session_id,
                context=transport_context,
            )
            projection = _stream_projection(
                tool,
                data,
                executor_action=executor_action,
            )
            stream_data = stream_kind = encoding = None
            if projection is not None:
                stream_data, stream_kind, encoding = projection
                if len(stream_data) > self.max_stream_bytes:
                    raise NativeAdapterError(
                        "Executor streaming result exceeds native transport bound",
                        code="PROVIDER_BOUNDS_VIOLATION",
                        category="bounds",
                    )
            response = _response(
                request_id=request_id,
                session_id=session_id,
                status="completed",
                data=data,
                stream=None
                if stream_data is None
                else {
                    "bounded": True,
                    "encoding": encoding,
                    "transport": "pc_remote_transport.frame.v1",
                },
            )
            return DispatchResult(
                payload=response,
                stream_data=stream_data,
                stream_kind=stream_kind,
            )
        except UnknownDispatchOutcome:
            raise
        except NativeAdapterError as exc:
            return DispatchResult(
                payload=_error_response(
                    exc,
                    request_id=request_id,
                    session_id=session_id,
                )
            )
        except ProtocolError as exc:
            return DispatchResult(
                payload=_error_response(
                    NativeAdapterError(
                        str(exc),
                        code="TRANSPORT_PROTOCOL_ERROR",
                        category="transport",
                    ),
                    request_id=request_id,
                    session_id=session_id,
                )
            )
        except Exception as exc:
            if transport_context is not None:
                tool_name = body.get("tool") if isinstance(body, Mapping) else None
                registry_version = (
                    body.get("registry_version", NATIVE_TOOL_REGISTRY_V1)
                    if isinstance(body, Mapping)
                    else NATIVE_TOOL_REGISTRY_V1
                )
                registry = (
                    PARITY_TOOL_REGISTRY
                    if registry_version == PARITY_TOOL_REGISTRY_V1
                    else TOOL_REGISTRY
                )
                tool = registry.get(tool_name)
                if tool is not None and tool.effect == "side_effect":
                    raise UnknownDispatchOutcome(
                        f"Unexpected adapter failure with side-effect outcome not provable: {type(exc).__name__}: {exc}"
                    ) from exc
            return DispatchResult(
                payload=_error_response(
                    NativeAdapterError(
                        f"{type(exc).__name__}: {exc}",
                        code="ADAPTER_FAILURE",
                        category="adapter",
                    ),
                    request_id=request_id,
                    session_id=session_id,
                )
            )
