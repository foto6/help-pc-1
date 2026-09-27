from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .errors import AmbiguousTargetError, PolicyBlockedError, StaleTargetError
from .models import ElementInfo, ElementQuery
from .safety import SafetyViolation, ensure_not_sensitive_text
from .vision_target import GroundedTargetContractError, parse_grounded_target_v1


CONTRACT_VERSION = "pc_executor.action_preflight.v1"
STATUSES = {
    "ready",
    "blocked",
    "unsupported",
    "stale_observation",
    "ambiguous_target",
    "invalid_request",
}


class PreflightValidationError(ValueError):
    pass


@dataclass(slots=True, frozen=True)
class PreflightRequest:
    request_id: str
    action: str
    params: dict[str, Any]
    dry_run: bool | None
    timeout_ms: int | None
    contract_version: str = CONTRACT_VERSION

    @classmethod
    def from_dict(cls, payload: Any) -> "PreflightRequest":
        raw = _mapping(payload, "preflight")
        _exact_keys(raw, {"contract_version", "request"}, "preflight")
        if raw["contract_version"] != CONTRACT_VERSION:
            raise PreflightValidationError("unsupported preflight contract_version")
        request = _mapping(raw["request"], "preflight.request")
        allowed = {"request_id", "action", "params", "dry_run", "timeout_ms"}
        required = {"request_id", "action", "params"}
        unknown = set(request) - allowed
        missing = required - set(request)
        if unknown or missing:
            raise PreflightValidationError(
                f"preflight.request keys mismatch; missing={sorted(missing)}, "
                f"extra={sorted(unknown)}"
            )
        request_id = _string(request["request_id"], "preflight.request.request_id")
        action = _string(request["action"], "preflight.request.action")
        params = _mapping(request["params"], "preflight.request.params")
        dry_run = request.get("dry_run")
        if dry_run is not None and not isinstance(dry_run, bool):
            raise PreflightValidationError(
                "preflight.request.dry_run must be a boolean or null"
            )
        timeout_ms = request.get("timeout_ms")
        if timeout_ms is not None and (
            isinstance(timeout_ms, bool)
            or not isinstance(timeout_ms, int)
            or timeout_ms <= 0
        ):
            raise PreflightValidationError(
                "preflight.request.timeout_ms must be a positive integer or null"
            )
        return cls(
            request_id=request_id,
            action=action,
            params=dict(params),
            dry_run=dry_run,
            timeout_ms=timeout_ms,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "request": {
                "request_id": self.request_id,
                "action": self.action,
                "params": self.params,
                "dry_run": self.dry_run,
                "timeout_ms": self.timeout_ms,
            },
        }


@dataclass(slots=True, frozen=True)
class PreflightResult:
    request_id: str | None
    action: str | None
    status: str
    executable: bool
    capabilities_digest: str
    deadline_budget_ms: int
    reasons: tuple[dict[str, str], ...]
    target: dict[str, Any] | None = None
    contract_version: str = CONTRACT_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "request_id": self.request_id,
            "action": self.action,
            "status": self.status,
            "executable": self.executable,
            "capabilities_digest": self.capabilities_digest,
            "deadline_budget_ms": self.deadline_budget_ms,
            "reasons": [dict(reason) for reason in self.reasons],
            "target": dict(self.target) if self.target is not None else None,
        }

    @classmethod
    def from_dict(cls, payload: Any) -> "PreflightResult":
        raw = _mapping(payload, "preflight_result")
        expected = {
            "contract_version",
            "request_id",
            "action",
            "status",
            "executable",
            "capabilities_digest",
            "deadline_budget_ms",
            "reasons",
            "target",
        }
        _exact_keys(raw, expected, "preflight_result")
        if raw["contract_version"] != CONTRACT_VERSION:
            raise PreflightValidationError("unsupported preflight result contract_version")
        request_id = _optional_string(raw["request_id"], "preflight_result.request_id")
        action = _optional_string(raw["action"], "preflight_result.action")
        status = _string(raw["status"], "preflight_result.status")
        if status not in STATUSES:
            raise PreflightValidationError("unsupported preflight result status")
        executable = raw["executable"]
        if not isinstance(executable, bool) or executable != (status == "ready"):
            raise PreflightValidationError("preflight executable/status mismatch")
        digest = _string(raw["capabilities_digest"], "preflight_result.capabilities_digest")
        if len(digest) != 64:
            raise PreflightValidationError("invalid preflight capabilities digest")
        deadline = raw["deadline_budget_ms"]
        if isinstance(deadline, bool) or not isinstance(deadline, int) or deadline <= 0:
            raise PreflightValidationError("invalid preflight deadline_budget_ms")
        reasons_raw = raw["reasons"]
        if not isinstance(reasons_raw, list):
            raise PreflightValidationError("preflight reasons must be an array")
        reasons: list[dict[str, str]] = []
        for value in reasons_raw:
            reason = _mapping(value, "preflight reason")
            _exact_keys(reason, {"code", "message"}, "preflight reason")
            reasons.append(
                {
                    "code": _string(reason["code"], "preflight reason.code"),
                    "message": _string(reason["message"], "preflight reason.message"),
                }
            )
        target = raw["target"]
        if target is not None and not isinstance(target, dict):
            raise PreflightValidationError("preflight target must be an object or null")
        return cls(
            request_id=request_id,
            action=action,
            status=status,
            executable=executable,
            capabilities_digest=digest,
            deadline_budget_ms=deadline,
            reasons=tuple(reasons),
            target=dict(target) if target is not None else None,
        )

def invalid_result(
    payload: Any,
    *,
    capabilities_digest: str,
    default_deadline_ms: int,
    message: str,
) -> PreflightResult:
    request_id = None
    action = None
    if isinstance(payload, Mapping):
        request = payload.get("request")
        if isinstance(request, Mapping):
            if isinstance(request.get("request_id"), str):
                request_id = request["request_id"]
            if isinstance(request.get("action"), str):
                action = request["action"]
    return _result(
        request_id=request_id,
        action=action,
        status="invalid_request",
        capabilities_digest=capabilities_digest,
        deadline_budget_ms=max(1, default_deadline_ms),
        code="invalid_request",
        message=message,
    )


def evaluate_preflight(
    preflight: PreflightRequest,
    *,
    capabilities: dict[str, Any],
    accessibility: object,
    input_adapter: object,
    shell: object,
    default_timeout_ms: int,
    allow_coordinate_fallback: bool,
) -> PreflightResult:
    digest = capabilities["attestation"]["digest"]
    deadline = preflight.timeout_ms or max(1, default_timeout_ms)
    action = preflight.action
    params = preflight.params

    action_capability = capabilities["actions"].get(action)
    if action_capability is None:
        return _result(
            preflight,
            status="unsupported",
            digest=digest,
            deadline=deadline,
            code="unsupported_action",
            message="action kind is not supported by this executor contract",
        )
    if not action_capability["supported"]:
        reason = action_capability["unsupported_reason"] or "adapter_unavailable"
        return _result(
            preflight,
            status="unsupported",
            digest=digest,
            deadline=deadline,
            code="adapter_unavailable",
            message=reason,
        )

    try:
        _validate_params(action, params)
    except PreflightValidationError as exc:
        return _result(
            preflight,
            status="invalid_request",
            digest=digest,
            deadline=deadline,
            code="invalid_action_params",
            message=str(exc),
        )

    if action == "mouse.click" and not allow_coordinate_fallback:
        return _result(
            preflight,
            status="blocked",
            digest=digest,
            deadline=deadline,
            code="coordinate_fallback_disabled",
            message="raw coordinate fallback is disabled; use UI Automation first",
        )

    if action in {"keyboard.type_text", "clipboard.set", "uia.set_value"}:
        sensitive = params.get("sensitive", False)
        if sensitive is True:
            return _result(
                preflight,
                status="blocked",
                digest=digest,
                deadline=deadline,
                code="sensitive_entry_blocked",
                message="credential/sensitive entry is not supported",
            )

    if action == "shell.run":
        try:
            shell.validate(params["argv"], cwd=params.get("cwd"))
        except SafetyViolation as exc:
            return _result(
                preflight,
                status="blocked",
                digest=digest,
                deadline=deadline,
                code="shell_policy_blocked",
                message=str(exc),
            )
        except Exception:
            return _result(
                preflight,
                status="unsupported",
                digest=digest,
                deadline=deadline,
                code="shell_validation_unavailable",
                message="shell validation adapter is unavailable",
            )
        return _ready(preflight, digest=digest, deadline=deadline)

    if action == "vision.target.invoke":
        try:
            target = parse_grounded_target_v1(params["target"])
        except GroundedTargetContractError as exc:
            return _result(
                preflight,
                status="invalid_request",
                digest=digest,
                deadline=deadline,
                code="invalid_vision_target",
                message=str(exc),
            )
        automation_id = target.automation_id
        if "uia" not in target.sources or not automation_id or not automation_id.strip():
            return _result(
                preflight,
                status="blocked",
                digest=digest,
                deadline=deadline,
                code="vision_target_not_uia_actionable",
                message="non-empty UIA automation_id is required",
            )
        return _preflight_uia(
            preflight,
            ElementQuery(automation_id=automation_id),
            accessibility=accessibility,
            digest=digest,
            deadline=deadline,
            mode="invoke",
        )

    if action.startswith("uia."):
        if action == "uia.snapshot":
            window_title = params.get("window_title")
            if window_title:
                try:
                    accessibility.snapshot(window_title=window_title)
                except StaleTargetError:
                    return _result(
                        preflight,
                        status="stale_observation",
                        digest=digest,
                        deadline=deadline,
                        code="stale_observation",
                        message="requested UIA window is no longer observable",
                    )
                except AmbiguousTargetError:
                    return _result(
                        preflight,
                        status="ambiguous_target",
                        digest=digest,
                        deadline=deadline,
                        code="ambiguous_target",
                        message="requested UIA window is ambiguous",
                    )
                except Exception:
                    return _result(
                        preflight,
                        status="unsupported",
                        digest=digest,
                        deadline=deadline,
                        code="uia_observation_unavailable",
                        message="UIA snapshot observation is unavailable",
                    )
            return _ready(preflight, digest=digest, deadline=deadline)

        try:
            query = ElementQuery.from_dict(params["query"])
        except (TypeError, ValueError) as exc:
            return _result(
                preflight,
                status="invalid_request",
                digest=digest,
                deadline=deadline,
                code="invalid_uia_query",
                message=str(exc),
            )
        mode = {
            "uia.inspect": "inspect",
            "uia.invoke": "invoke",
            "uia.focus": "focus",
            "uia.set_value": "set_value",
        }[action]
        return _preflight_uia(
            preflight,
            query,
            accessibility=accessibility,
            digest=digest,
            deadline=deadline,
            mode=mode,
        )

    return _ready(preflight, digest=digest, deadline=deadline)

def _preflight_uia(
    preflight: PreflightRequest,
    query: ElementQuery,
    *,
    accessibility: object,
    digest: str,
    deadline: int,
    mode: str,
) -> PreflightResult:
    try:
        element = accessibility.inspect(query)
    except StaleTargetError:
        return _result(
            preflight,
            status="stale_observation",
            digest=digest,
            deadline=deadline,
            code="stale_observation",
            message="UIA selector no longer resolves",
        )
    except AmbiguousTargetError:
        return _result(
            preflight,
            status="ambiguous_target",
            digest=digest,
            deadline=deadline,
            code="ambiguous_target",
            message="UIA selector resolves ambiguously",
        )
    except PolicyBlockedError as exc:
        return _result(
            preflight,
            status="blocked",
            digest=digest,
            deadline=deadline,
            code="uia_policy_blocked",
            message=str(exc),
        )
    except Exception:
        return _result(
            preflight,
            status="unsupported",
            digest=digest,
            deadline=deadline,
            code="uia_observation_unavailable",
            message="UIA read-only observation is unavailable",
        )

    target = _target_summary(element)
    if mode == "inspect":
        return _ready(preflight, digest=digest, deadline=deadline, target=target)

    if not element.is_enabled or element.is_offscreen:
        return _result(
            preflight,
            status="blocked",
            digest=digest,
            deadline=deadline,
            code="uia_target_not_actionable",
            message="UIA target is disabled or offscreen",
            target=target,
        )
    if mode == "invoke" and not element.supports_invoke:
        return _result(
            preflight,
            status="blocked",
            digest=digest,
            deadline=deadline,
            code="uia_invoke_unsupported",
            message="UIA target does not expose invoke capability",
            target=target,
        )
    if mode == "set_value":
        try:
            ensure_not_sensitive_text(
                is_password=element.is_password,
                sensitive=bool(preflight.params.get("sensitive", False)),
            )
        except SafetyViolation as exc:
            return _result(
                preflight,
                status="blocked",
                digest=digest,
                deadline=deadline,
                code="sensitive_entry_blocked",
                message=str(exc),
                target=target,
            )
        if not element.supports_value:
            return _result(
                preflight,
                status="blocked",
                digest=digest,
                deadline=deadline,
                code="uia_value_unsupported",
                message="UIA target does not expose value capability",
                target=target,
            )
    return _ready(preflight, digest=digest, deadline=deadline, target=target)


def _target_summary(element: ElementInfo) -> dict[str, Any]:
    return {
        "resolved": True,
        "automation_id_present": bool(element.automation_id),
        "enabled": bool(element.is_enabled),
        "offscreen": bool(element.is_offscreen),
        "password": bool(element.is_password),
        "supports_invoke": bool(element.supports_invoke),
        "supports_value": bool(element.supports_value),
    }

def _validate_params(action: str, params: dict[str, Any]) -> None:
    schemas: dict[str, tuple[set[str], set[str]]] = {
        "capabilities.get": (set(), set()),
        "action.preflight": (
            {"contract_version", "request"},
            {"contract_version", "request"},
        ),
        "outcome.lookup": (
            {"request_id", "action", "execution_attempt"},
            {"request_id", "action"},
        ),
        "screenshot.capture": (set(), set()),
        "windows.list": (set(), set()),
        "uia.snapshot": ({"window_title"}, set()),
        "uia.inspect": ({"query"}, {"query"}),
        "uia.invoke": ({"query"}, {"query"}),
        "uia.focus": ({"query"}, {"query"}),
        "uia.set_value": ({"query", "value", "sensitive"}, {"query"}),
        "vision.target.invoke": ({"target"}, {"target"}),
        "mouse.click": ({"x", "y", "button"}, {"x", "y"}),
        "keyboard.press": ({"key"}, {"key"}),
        "keyboard.type_text": ({"text", "sensitive"}, set()),
        "clipboard.get": (set(), set()),
        "clipboard.set": ({"text", "sensitive"}, set()),
        "shell.run": ({"argv", "cwd"}, {"argv"}),
    }
    allowed, required = schemas[action]
    unknown = set(params) - allowed
    missing = required - set(params)
    if unknown or missing:
        raise PreflightValidationError(
            f"{action} params mismatch; missing={sorted(missing)}, extra={sorted(unknown)}"
        )

    if action == "action.preflight":
        PreflightRequest.from_dict(params)
    if action == "outcome.lookup":
        _string(params["request_id"], "outcome.lookup request_id")
        _string(params["action"], "outcome.lookup action")
        attempt = params.get("execution_attempt")
        if attempt is not None and (
            isinstance(attempt, bool) or not isinstance(attempt, int) or attempt <= 0
        ):
            raise PreflightValidationError(
                "outcome.lookup execution_attempt must be a positive integer"
            )
    if action == "uia.snapshot":
        window = params.get("window_title")
        if window is not None and not isinstance(window, str):
            raise PreflightValidationError("uia.snapshot window_title must be string or null")
    if action.startswith("uia.") and action != "uia.snapshot":
        if not isinstance(params.get("query"), dict):
            raise PreflightValidationError(f"{action} query must be an object")
    if action == "uia.set_value":
        if "value" in params and not isinstance(params["value"], str):
            raise PreflightValidationError("uia.set_value value must be a string")
        _optional_bool(params.get("sensitive"), "uia.set_value sensitive")
    if action == "mouse.click":
        for key in ("x", "y"):
            value = params[key]
            if isinstance(value, bool) or not isinstance(value, int):
                raise PreflightValidationError(f"mouse.click {key} must be an integer")
        button = params.get("button", "left")
        if button not in {"left", "right", "middle"}:
            raise PreflightValidationError("mouse.click button is unsupported")
    if action == "keyboard.press":
        key = params["key"]
        if not isinstance(key, str) or not key or len(key) > 64:
            raise PreflightValidationError(
                "keyboard.press key must be a short non-empty string"
            )
    if action == "keyboard.type_text":
        if "text" in params and not isinstance(params["text"], str):
            raise PreflightValidationError("keyboard.type_text text must be a string")
        _optional_bool(params.get("sensitive"), "keyboard.type_text sensitive")
    if action == "clipboard.set":
        if "text" in params and not isinstance(params["text"], str):
            raise PreflightValidationError("clipboard.set text must be a string")
        _optional_bool(params.get("sensitive"), "clipboard.set sensitive")
    if action == "shell.run":
        argv = params["argv"]
        if not isinstance(argv, list) or not argv or any(
            not isinstance(part, str) for part in argv
        ):
            raise PreflightValidationError(
                "shell.run argv must be a non-empty array of strings"
            )
        cwd = params.get("cwd")
        if cwd is not None and not isinstance(cwd, str):
            raise PreflightValidationError("shell.run cwd must be string or null")


def _optional_bool(value: Any, where: str) -> None:
    if value is not None and not isinstance(value, bool):
        raise PreflightValidationError(f"{where} must be a boolean")


def _ready(
    preflight: PreflightRequest,
    *,
    digest: str,
    deadline: int,
    target: dict[str, Any] | None = None,
) -> PreflightResult:
    return _result(
        preflight,
        status="ready",
        digest=digest,
        deadline=deadline,
        code="ready",
        message="preflight checks passed; execution success is not guaranteed",
        target=target,
    )


def _result(
    preflight: PreflightRequest | None = None,
    *,
    request_id: str | None = None,
    action: str | None = None,
    status: str,
    digest: str | None = None,
    capabilities_digest: str | None = None,
    deadline: int | None = None,
    deadline_budget_ms: int | None = None,
    code: str,
    message: str,
    target: dict[str, Any] | None = None,
) -> PreflightResult:
    if status not in STATUSES:
        raise ValueError(f"unsupported preflight status: {status}")
    if preflight is not None:
        request_id = preflight.request_id
        action = preflight.action
    resolved_digest = digest or capabilities_digest
    resolved_deadline = deadline if deadline is not None else deadline_budget_ms
    if resolved_digest is None or resolved_deadline is None:
        raise ValueError("preflight result requires digest and deadline")
    return PreflightResult(
        request_id=request_id,
        action=action,
        status=status,
        executable=status == "ready",
        capabilities_digest=resolved_digest,
        deadline_budget_ms=max(1, int(resolved_deadline)),
        reasons=({"code": code, "message": message},),
        target=target,
    )


def _mapping(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PreflightValidationError(f"{where} must be an object")
    return value


def _exact_keys(value: Mapping[str, Any], expected: set[str], where: str) -> None:
    actual = set(value)
    if actual != expected:
        raise PreflightValidationError(
            f"{where} keys mismatch; missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )


def _string(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PreflightValidationError(f"{where} must be a non-empty string")
    return value


def _optional_string(value: Any, where: str) -> str | None:
    if value is None:
        return None
    return _string(value, where)
