from __future__ import annotations

import hashlib
import ntpath
import os
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from .errors import AmbiguousTargetError, PolicyBlockedError, StaleTargetError
from .models import ElementInfo, ElementQuery, canonical_json
from .vision_target import GroundedTargetContractError, parse_grounded_target_v1
from .windows import display_for_point, foreground_window_info


CONTRACT_VERSION = "pc_executor.execution_context_binding.v1"
VALIDATION_CONTRACT_VERSION = "pc_executor.execution_context_validation.v1"

UIA_ACTIONS = frozenset(
    {"vision.target.invoke", "uia.invoke", "uia.focus", "uia.set_value"}
)
FOREGROUND_ACTIONS = frozenset(
    {"mouse.click", "keyboard.press", "keyboard.type_text", "clipboard.set"}
)
SHELL_ACTIONS = frozenset({"shell.run"})
BOUND_ACTIONS = UIA_ACTIONS | FOREGROUND_ACTIONS | SHELL_ACTIONS

AUTHORITY_BY_KIND = {
    "uia": frozenset(
        {
            "request.identity",
            "process.process_id",
            "process.start_epoch_ms",
            "window.window_handle",
            "target.identity_digest",
        }
    ),
    "foreground": frozenset(
        {
            "request.identity",
            "process.process_id",
            "process.start_epoch_ms",
            "window.window_handle",
            "display.display_id",
        }
    ),
    "shell": frozenset(
        {
            "request.identity",
            "shell.executable",
            "shell.cwd_path_digest",
            "shell.cwd_file_identity",
        }
    ),
}


class ExecutionContextBindingError(ValueError):
    pass


class ContextMismatchBlockedError(PolicyBlockedError):
    def __init__(self, *, binding_digest: str, mismatches: list[str]) -> None:
        self.validation_evidence = {
            "contract_version": VALIDATION_CONTRACT_VERSION,
            "status": "blocked",
            "reason": "context_mismatch",
            "binding_digest": binding_digest,
            "reexecution_safe": True,
            "adapter_dispatch_started": False,
            "mismatches": list(mismatches),
        }
        super().__init__("context_mismatch: " + ", ".join(mismatches))


@dataclass(slots=True, frozen=True)
class ForegroundContext:
    process_id: int | None
    process_start_epoch_ms: int | None
    window_handle: int | None
    display_id: str | None


@dataclass(slots=True, frozen=True)
class CwdIdentity:
    path_digest: str
    device: int | None
    inode: int | None


class ExecutionContextObserver(Protocol):
    def foreground(self) -> ForegroundContext | None: ...
    def display_at(self, x: int, y: int) -> str | None: ...
    def cwd_identity(self, cwd: str | None) -> CwdIdentity: ...


class SystemExecutionContextObserver:
    """Read-only operating-system provenance used before side-effect dispatch."""

    def foreground(self) -> ForegroundContext | None:
        info = foreground_window_info()
        if info is None:
            return None
        return ForegroundContext(
            process_id=info.pid,
            process_start_epoch_ms=info.process_start_epoch_ms,
            window_handle=info.hwnd,
            display_id=info.display_id,
        )

    def display_at(self, x: int, y: int) -> str | None:
        return display_for_point(x, y)

    def cwd_identity(self, cwd: str | None) -> CwdIdentity:
        raw = cwd if cwd is not None else os.getcwd()
        resolved = os.path.abspath(raw)
        normalized = ntpath.normcase(
            ntpath.normpath(resolved.replace("/", "\\"))
        )
        digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        try:
            stat = os.stat(raw)
        except OSError:
            device = inode = None
        else:
            device, inode = int(stat.st_dev), int(stat.st_ino)
        return CwdIdentity(digest, device, inode)


@dataclass(slots=True, frozen=True)
class ExecutionContextBinding:
    request_id: str
    action: str
    context_kind: str
    authoritative_fields: tuple[str, ...]
    process: dict[str, Any] | None
    window: dict[str, Any] | None
    target: dict[str, Any] | None
    display: dict[str, Any] | None
    shell: dict[str, Any] | None
    context_digest: str
    contract_version: str = CONTRACT_VERSION

    @classmethod
    def create(
        cls,
        *,
        request_id: str,
        action: str,
        context_kind: str,
        authoritative_fields: list[str] | tuple[str, ...],
        process: dict[str, Any] | None = None,
        window: dict[str, Any] | None = None,
        target: dict[str, Any] | None = None,
        display: dict[str, Any] | None = None,
        shell: dict[str, Any] | None = None,
    ) -> "ExecutionContextBinding":
        authority = tuple(sorted(set(authoritative_fields)))
        body = {
            "contract_version": CONTRACT_VERSION,
            "request_id": request_id,
            "action": action,
            "context_kind": context_kind,
            "authoritative_fields": list(authority),
            "process": process,
            "window": window,
            "target": target,
            "display": display,
            "shell": shell,
        }
        digest = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        value = cls(
            request_id=request_id,
            action=action,
            context_kind=context_kind,
            authoritative_fields=authority,
            process=process,
            window=window,
            target=target,
            display=display,
            shell=shell,
            context_digest=digest,
        )
        return cls.from_dict(value.to_dict())

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ExecutionContextBinding":
        raw = _object(payload, "binding")
        _keys(
            raw,
            {
                "contract_version",
                "request_id",
                "action",
                "context_kind",
                "authoritative_fields",
                "process",
                "window",
                "target",
                "display",
                "shell",
                "context_digest",
            },
            "binding",
        )
        version = _text(raw["contract_version"], "contract_version")
        if version != CONTRACT_VERSION:
            raise ExecutionContextBindingError(
                f"unsupported contract_version: {version!r}"
            )
        authority_raw = raw["authoritative_fields"]
        if not isinstance(authority_raw, list):
            raise ExecutionContextBindingError(
                "authoritative_fields must be an array"
            )
        authority = tuple(_text(x, "authoritative_fields[]") for x in authority_raw)
        if authority != tuple(sorted(set(authority))):
            raise ExecutionContextBindingError(
                "authoritative_fields must be sorted and unique"
            )
        value = cls(
            request_id=_text(raw["request_id"], "request_id"),
            action=_text(raw["action"], "action"),
            context_kind=_text(raw["context_kind"], "context_kind"),
            authoritative_fields=authority,
            process=_parse_process(raw["process"]),
            window=_parse_window(raw["window"]),
            target=_parse_target(raw["target"]),
            display=_parse_display(raw["display"]),
            shell=_parse_shell(raw["shell"]),
            context_digest=_sha(raw["context_digest"], "context_digest"),
        )
        _semantics(value)
        body = value.to_dict()
        body.pop("context_digest")
        expected = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        if value.context_digest != expected:
            raise ExecutionContextBindingError("context_digest mismatch")
        return value

    def to_dict(self) -> dict[str, Any]:
        target = None if self.target is None else dict(self.target)
        if target is not None and target.get("runtime_id") is not None:
            target["runtime_id"] = list(target["runtime_id"])
        return {
            "contract_version": self.contract_version,
            "request_id": self.request_id,
            "action": self.action,
            "context_kind": self.context_kind,
            "authoritative_fields": list(self.authoritative_fields),
            "process": None if self.process is None else dict(self.process),
            "window": None if self.window is None else dict(self.window),
            "target": target,
            "display": None if self.display is None else dict(self.display),
            "shell": None if self.shell is None else dict(self.shell),
            "context_digest": self.context_digest,
        }


def parse_execution_context_binding(
    payload: Mapping[str, Any],
) -> ExecutionContextBinding:
    return ExecutionContextBinding.from_dict(payload)


def validate_execution_context_binding(payload: Mapping[str, Any]) -> None:
    ExecutionContextBinding.from_dict(payload)


def target_identity(element: ElementInfo) -> dict[str, Any]:
    body = {
        "automation_id": element.automation_id,
        "control_type": element.control_type,
        "class_name": element.class_name,
        "native_handle": element.native_handle,
        "runtime_id": (
            list(element.runtime_id) if element.runtime_id is not None else None
        ),
    }
    return {
        **body,
        "identity_digest": hashlib.sha256(
            canonical_json(body).encode()
        ).hexdigest(),
    }


def binding_from_uia_element(
    *,
    request_id: str,
    action: str,
    element: ElementInfo,
    capture_id: str | None = None,
) -> ExecutionContextBinding:
    if action not in UIA_ACTIONS:
        raise ExecutionContextBindingError("action does not use UIA context")
    process = _process_values(
        element.process_id, element.process_start_epoch_ms
    )
    window = (
        {"window_handle": element.window_handle}
        if element.window_handle is not None
        else None
    )
    display = (
        {"display_id": element.display_id, "capture_id": capture_id}
        if element.display_id is not None or capture_id is not None
        else None
    )
    authority = ["request.identity", "target.identity_digest"]
    if process is not None:
        authority.append("process.process_id")
        if process["start_epoch_ms"] is not None:
            authority.append("process.start_epoch_ms")
    if window is not None:
        authority.append("window.window_handle")
    return ExecutionContextBinding.create(
        request_id=request_id,
        action=action,
        context_kind="uia",
        authoritative_fields=authority,
        process=process,
        window=window,
        target=target_identity(element),
        display=display,
    )


def binding_from_foreground(
    *,
    request_id: str,
    action: str,
    foreground: ForegroundContext,
    capture_id: str | None = None,
    display_id: str | None = None,
) -> ExecutionContextBinding:
    if action not in FOREGROUND_ACTIONS:
        raise ExecutionContextBindingError("action does not use foreground context")
    process = _process_values(
        foreground.process_id, foreground.process_start_epoch_ms
    )
    window = (
        {"window_handle": foreground.window_handle}
        if foreground.window_handle is not None
        else None
    )
    bound_display = display_id if display_id is not None else foreground.display_id
    display = (
        {"display_id": bound_display, "capture_id": capture_id}
        if bound_display is not None or capture_id is not None
        else None
    )
    authority = ["request.identity"]
    if process is not None:
        authority.append("process.process_id")
        if process["start_epoch_ms"] is not None:
            authority.append("process.start_epoch_ms")
    if window is not None:
        authority.append("window.window_handle")
    if action == "mouse.click" and bound_display is not None:
        authority.append("display.display_id")
    return ExecutionContextBinding.create(
        request_id=request_id,
        action=action,
        context_kind="foreground",
        authoritative_fields=authority,
        process=process,
        window=window,
        target=None,
        display=display,
    )


def binding_from_shell(
    *,
    request_id: str,
    action: str,
    executable: str,
    cwd: CwdIdentity,
) -> ExecutionContextBinding:
    if action not in SHELL_ACTIONS:
        raise ExecutionContextBindingError("action does not use shell context")
    shell = {
        "executable": ntpath.basename(executable).lower(),
        "cwd_path_digest": cwd.path_digest,
        "cwd_device": cwd.device,
        "cwd_inode": cwd.inode,
    }
    authority = [
        "request.identity",
        "shell.executable",
        "shell.cwd_path_digest",
    ]
    if cwd.device is not None and cwd.inode is not None:
        authority.append("shell.cwd_file_identity")
    return ExecutionContextBinding.create(
        request_id=request_id,
        action=action,
        context_kind="shell",
        authoritative_fields=authority,
        process=None,
        window=None,
        target=None,
        display=None,
        shell=shell,
    )


def derive_execution_context_binding(
    *,
    request_id: str,
    action: str,
    params: Mapping[str, Any],
    accessibility: Any,
    shell_adapter: Any,
    observer: ExecutionContextObserver,
    capture_id: str | None = None,
    display_id: str | None = None,
) -> ExecutionContextBinding:
    if action in UIA_ACTIONS:
        element = accessibility.inspect(_uia_query(action, params))
        return binding_from_uia_element(
            request_id=request_id,
            action=action,
            element=element,
            capture_id=capture_id,
        )
    if action in FOREGROUND_ACTIONS:
        current = observer.foreground()
        if current is None:
            raise ExecutionContextBindingError("foreground context unavailable")
        if action == "mouse.click" and display_id is None:
            display_id = observer.display_at(
                _integer(params.get("x"), "mouse.click x"),
                _integer(params.get("y"), "mouse.click y"),
            )
        return binding_from_foreground(
            request_id=request_id,
            action=action,
            foreground=current,
            capture_id=capture_id,
            display_id=display_id,
        )
    if action in SHELL_ACTIONS:
        argv = params.get("argv")
        if not isinstance(argv, list) or not argv:
            raise ExecutionContextBindingError(
                "shell.run argv must be a non-empty array"
            )
        cwd = params.get("cwd")
        validated = shell_adapter.validate(argv, cwd=cwd)
        return binding_from_shell(
            request_id=request_id,
            action=action,
            executable=str(validated[0]),
            cwd=observer.cwd_identity(cwd),
        )
    raise ExecutionContextBindingError(
        f"action does not support execution context binding: {action!r}"
    )


def validate_bound_execution_context(
    *,
    request_id: str,
    action: str,
    params: Mapping[str, Any],
    binding_payload: Mapping[str, Any],
    accessibility: Any,
    shell_adapter: Any,
    observer: ExecutionContextObserver,
) -> dict[str, Any]:
    binding = parse_execution_context_binding(binding_payload)
    mismatches = []
    if binding.request_id != request_id:
        mismatches.append("request_id_changed")
    if binding.action != action:
        mismatches.append("action_changed")
    if mismatches:
        raise ContextMismatchBlockedError(
            binding_digest=binding.context_digest,
            mismatches=mismatches,
        )

    if binding.context_kind == "uia":
        try:
            element = accessibility.inspect(_uia_query(action, params))
        except (StaleTargetError, AmbiguousTargetError):
            raise ContextMismatchBlockedError(
                binding_digest=binding.context_digest,
                mismatches=["target_resolution_changed"],
            )
        current = binding_from_uia_element(
            request_id=request_id,
            action=action,
            element=element,
            capture_id=_capture_id(binding),
        )
    elif binding.context_kind == "foreground":
        observed = observer.foreground()
        if observed is None:
            raise ContextMismatchBlockedError(
                binding_digest=binding.context_digest,
                mismatches=["foreground_context_unavailable"],
            )
        display_id = None
        if "display.display_id" in binding.authoritative_fields:
            display_id = observer.display_at(
                _integer(params.get("x"), "mouse.click x"),
                _integer(params.get("y"), "mouse.click y"),
            )
        current = binding_from_foreground(
            request_id=request_id,
            action=action,
            foreground=observed,
            capture_id=_capture_id(binding),
            display_id=display_id,
        )
    else:
        argv, cwd = params.get("argv"), params.get("cwd")
        validated = shell_adapter.validate(argv, cwd=cwd)
        current = binding_from_shell(
            request_id=request_id,
            action=action,
            executable=str(validated[0]),
            cwd=observer.cwd_identity(cwd),
        )

    mismatches = [
        field
        for field in binding.authoritative_fields
        if field != "request.identity"
        and _field(binding, field) != _field(current, field)
    ]
    if mismatches:
        raise ContextMismatchBlockedError(
            binding_digest=binding.context_digest,
            mismatches=mismatches,
        )
    return {
        "contract_version": VALIDATION_CONTRACT_VERSION,
        "status": "matched",
        "reason": "context_match",
        "binding_digest": binding.context_digest,
        "reexecution_safe": False,
        "adapter_dispatch_started": False,
        "mismatches": [],
    }


def _capture_id(binding: ExecutionContextBinding) -> str | None:
    if binding.display is None:
        return None
    return binding.display.get("capture_id")


def _field(binding: ExecutionContextBinding, field: str) -> Any:
    section_name, key = field.split(".", 1)
    section = getattr(binding, section_name)
    if section is None:
        return None
    if field == "shell.cwd_file_identity":
        return section.get("cwd_device"), section.get("cwd_inode")
    return section.get(key)


def _uia_query(action: str, params: Mapping[str, Any]) -> ElementQuery:
    if action == "vision.target.invoke":
        try:
            target = parse_grounded_target_v1(params.get("target"))
        except GroundedTargetContractError as exc:
            raise ExecutionContextBindingError(
                f"invalid vision target contract: {exc}"
            ) from exc
        automation_id = target.automation_id
        if (
            "uia" not in target.sources
            or not automation_id
            or not automation_id.strip()
        ):
            raise ExecutionContextBindingError(
                "vision target requires non-empty UIA automation_id"
            )
        return ElementQuery(automation_id=automation_id)
    try:
        return ElementQuery.from_dict(dict(params.get("query") or {}))
    except (TypeError, ValueError) as exc:
        raise ExecutionContextBindingError(
            f"invalid UIA query: {exc}"
        ) from exc


def _semantics(value: ExecutionContextBinding) -> None:
    if value.action not in BOUND_ACTIONS:
        raise ExecutionContextBindingError("unsupported bound action")
    expected_kind = (
        "uia"
        if value.action in UIA_ACTIONS
        else "foreground"
        if value.action in FOREGROUND_ACTIONS
        else "shell"
    )
    if value.context_kind != expected_kind:
        raise ExecutionContextBindingError(
            f"{value.action!r} requires context_kind {expected_kind!r}"
        )
    authority = set(value.authoritative_fields)
    if "request.identity" not in authority:
        raise ExecutionContextBindingError("request.identity must be authoritative")
    invalid = authority - AUTHORITY_BY_KIND[value.context_kind]
    if invalid:
        raise ExecutionContextBindingError(
            f"invalid authoritative fields: {sorted(invalid)}"
        )
    if (
        value.context_kind == "foreground"
        and "display.display_id" in authority
        and value.action != "mouse.click"
    ):
        raise ExecutionContextBindingError(
            "display authority is only valid for mouse.click"
        )

    if value.context_kind == "uia":
        if value.target is None or "target.identity_digest" not in authority:
            raise ExecutionContextBindingError(
                "UIA binding requires authoritative target identity"
            )
        if value.shell is not None:
            raise ExecutionContextBindingError(
                "UIA binding cannot carry shell context"
            )
    elif value.context_kind == "foreground":
        if value.target is not None or value.shell is not None:
            raise ExecutionContextBindingError(
                "foreground binding cannot carry target/shell context"
            )
        if value.process is None and value.window is None:
            raise ExecutionContextBindingError(
                "foreground binding requires process or window identity"
            )
    else:
        if any(
            item is not None
            for item in (value.process, value.window, value.target, value.display)
        ):
            raise ExecutionContextBindingError(
                "shell binding cannot carry GUI context"
            )
        if value.shell is None:
            raise ExecutionContextBindingError("shell context is required")
        required = {"shell.executable", "shell.cwd_path_digest"}
        if not required.issubset(authority):
            raise ExecutionContextBindingError(
                "shell executable and cwd must be authoritative"
            )

    if "process.process_id" in authority and value.process is None:
        raise ExecutionContextBindingError("process section required")
    if "process.start_epoch_ms" in authority and (
        value.process is None or value.process["start_epoch_ms"] is None
    ):
        raise ExecutionContextBindingError("process start epoch required")
    if "window.window_handle" in authority and value.window is None:
        raise ExecutionContextBindingError("window section required")
    if "display.display_id" in authority and (
        value.display is None or value.display["display_id"] is None
    ):
        raise ExecutionContextBindingError("display_id required")
    if "shell.cwd_file_identity" in authority and (
        value.shell is None
        or value.shell["cwd_device"] is None
        or value.shell["cwd_inode"] is None
    ):
        raise ExecutionContextBindingError("cwd file identity required")


def _process_values(pid: int | None, start: int | None) -> dict[str, Any] | None:
    if pid is None:
        return None
    return {
        "process_id": int(pid),
        "start_epoch_ms": int(start) if start is not None else None,
    }


def _parse_process(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    raw = _object(value, "process")
    _keys(raw, {"process_id", "start_epoch_ms"}, "process")
    start = raw["start_epoch_ms"]
    return {
        "process_id": _positive(raw["process_id"], "process_id"),
        "start_epoch_ms": (
            None if start is None else _nonnegative(start, "start_epoch_ms")
        ),
    }


def _parse_window(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    raw = _object(value, "window")
    _keys(raw, {"window_handle"}, "window")
    return {"window_handle": _positive(raw["window_handle"], "window_handle")}


def _parse_target(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    raw = _object(value, "target")
    keys = {
        "automation_id",
        "control_type",
        "class_name",
        "native_handle",
        "runtime_id",
        "identity_digest",
    }
    _keys(raw, keys, "target")
    runtime = raw["runtime_id"]
    if runtime is not None and (
        not isinstance(runtime, list)
        or any(isinstance(x, bool) or not isinstance(x, int) for x in runtime)
    ):
        raise ExecutionContextBindingError(
            "runtime_id must be an integer array or null"
        )
    native = raw["native_handle"]
    if native is not None:
        native = _positive(native, "native_handle")
    body = {
        "automation_id": _nullable_text(raw["automation_id"], "automation_id"),
        "control_type": _nullable_text(raw["control_type"], "control_type"),
        "class_name": _nullable_text(raw["class_name"], "class_name"),
        "native_handle": native,
        "runtime_id": None if runtime is None else list(runtime),
    }
    digest = _sha(raw["identity_digest"], "identity_digest")
    expected = hashlib.sha256(canonical_json(body).encode()).hexdigest()
    if digest != expected:
        raise ExecutionContextBindingError("target identity_digest mismatch")
    return {**body, "identity_digest": digest}


def _parse_display(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    raw = _object(value, "display")
    _keys(raw, {"display_id", "capture_id"}, "display")
    return {
        "display_id": _nullable_text(raw["display_id"], "display_id"),
        "capture_id": _nullable_text(raw["capture_id"], "capture_id"),
    }


def _parse_shell(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    raw = _object(value, "shell")
    _keys(
        raw,
        {"executable", "cwd_path_digest", "cwd_device", "cwd_inode"},
        "shell",
    )
    device, inode = raw["cwd_device"], raw["cwd_inode"]
    if device is not None:
        device = _nonnegative(device, "cwd_device")
    if inode is not None:
        inode = _nonnegative(inode, "cwd_inode")
    if (device is None) != (inode is None):
        raise ExecutionContextBindingError(
            "cwd_device and cwd_inode must both be null or integers"
        )
    return {
        "executable": _text(raw["executable"], "executable").lower(),
        "cwd_path_digest": _sha(raw["cwd_path_digest"], "cwd_path_digest"),
        "cwd_device": device,
        "cwd_inode": inode,
    }


def _object(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ExecutionContextBindingError(f"{where} must be an object")
    return value


def _keys(value: Mapping[str, Any], expected: set[str], where: str) -> None:
    if set(value) != expected:
        raise ExecutionContextBindingError(f"{where} keys mismatch")


def _text(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise ExecutionContextBindingError(f"{where} must be a non-empty string")
    return value


def _nullable_text(value: Any, where: str) -> str | None:
    return None if value is None else _text(value, where)


def _integer(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ExecutionContextBindingError(f"{where} must be an integer")
    return value


def _positive(value: Any, where: str) -> int:
    result = _integer(value, where)
    if result <= 0:
        raise ExecutionContextBindingError(f"{where} must be positive")
    return result


def _nonnegative(value: Any, where: str) -> int:
    result = _integer(value, where)
    if result < 0:
        raise ExecutionContextBindingError(f"{where} must be non-negative")
    return result


def _sha(value: Any, where: str) -> str:
    result = _text(value, where)
    if len(result) != 64 or any(c not in "0123456789abcdef" for c in result):
        raise ExecutionContextBindingError(f"{where} must be lowercase SHA-256")
    return result
