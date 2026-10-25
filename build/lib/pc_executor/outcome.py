from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Mapping


CONTRACT_VERSION = "pc_executor.action_outcome.v1"
EFFECT_STATES = {"not_started", "completed", "unknown"}
SIDE_EFFECTING_ACTIONS = frozenset(
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
_ALLOWED_REASONS = {
    "dispatch_started",
    "completed",
    "dry_run",
    "stale_target",
    "ambiguous_target",
    "policy_blocked",
    "timeout",
    "cancelled",
    "transient",
    "executor_failure",
}


class ActionOutcomeValidationError(ValueError):
    """Raised when an action-outcome evidence payload violates v1."""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

@dataclass(slots=True, frozen=True)
class ActionOutcomeEvidence:
    request_id: str
    action: str
    effect_state: str
    dispatch_started: bool
    completion_observed: bool
    reexecution_safe: bool
    reconciliation_required: bool
    observed_at: str
    reason: str
    contract_version: str = CONTRACT_VERSION

    @classmethod
    def create(
        cls,
        *,
        request_id: str,
        action: str,
        effect_state: str,
        dispatch_started: bool,
        reason: str,
        observed_at: str | None = None,
    ) -> "ActionOutcomeEvidence":
        if effect_state == "not_started":
            completion_observed = False
            reexecution_safe = True
            reconciliation_required = False
        elif effect_state == "completed":
            completion_observed = True
            reexecution_safe = False
            reconciliation_required = False
        elif effect_state == "unknown":
            completion_observed = False
            reexecution_safe = False
            reconciliation_required = True
        else:
            raise ActionOutcomeValidationError(
                f"unsupported effect_state: {effect_state!r}"
            )

        value = cls(
            request_id=request_id,
            action=action,
            effect_state=effect_state,
            dispatch_started=dispatch_started,
            completion_observed=completion_observed,
            reexecution_safe=reexecution_safe,
            reconciliation_required=reconciliation_required,
            observed_at=observed_at or _utc_now_iso(),
            reason=reason,
        )
        validate_action_outcome(value.to_dict())
        return value

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ActionOutcomeEvidence":
        raw = _mapping(payload, "payload")
        expected = {
            "contract_version",
            "request_id",
            "action",
            "effect_state",
            "dispatch_started",
            "completion_observed",
            "reexecution_safe",
            "reconciliation_required",
            "observed_at",
            "reason",
        }
        _exact_keys(raw, expected, "payload")

        version = _string(raw["contract_version"], "contract_version")
        if version != CONTRACT_VERSION:
            raise ActionOutcomeValidationError(
                f"unsupported contract_version: {version!r}"
            )

        value = cls(
            request_id=_string(raw["request_id"], "request_id"),
            action=_string(raw["action"], "action"),
            effect_state=_string(raw["effect_state"], "effect_state"),
            dispatch_started=_boolean(raw["dispatch_started"], "dispatch_started"),
            completion_observed=_boolean(
                raw["completion_observed"], "completion_observed"
            ),
            reexecution_safe=_boolean(raw["reexecution_safe"], "reexecution_safe"),
            reconciliation_required=_boolean(
                raw["reconciliation_required"], "reconciliation_required"
            ),
            observed_at=_string(raw["observed_at"], "observed_at"),
            reason=_string(raw["reason"], "reason"),
        )
        _validate_semantics(value)
        return value

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_action_outcome(payload: Mapping[str, Any]) -> ActionOutcomeEvidence:
    return ActionOutcomeEvidence.from_dict(payload)


def validate_action_outcome(payload: Mapping[str, Any]) -> None:
    ActionOutcomeEvidence.from_dict(payload)

def _validate_semantics(value: ActionOutcomeEvidence) -> None:
    if value.action not in SIDE_EFFECTING_ACTIONS:
        raise ActionOutcomeValidationError(
            f"action is not side-effecting in v1: {value.action!r}"
        )
    if value.effect_state not in EFFECT_STATES:
        raise ActionOutcomeValidationError(
            f"unsupported effect_state: {value.effect_state!r}"
        )
    if value.reason not in _ALLOWED_REASONS:
        raise ActionOutcomeValidationError(f"unsupported reason: {value.reason!r}")

    if value.effect_state == "not_started":
        expected = (False, True, False)
    elif value.effect_state == "completed":
        if not value.dispatch_started:
            raise ActionOutcomeValidationError(
                "completed outcome requires dispatch_started=true"
            )
        expected = (True, False, False)
    else:
        if not value.dispatch_started:
            raise ActionOutcomeValidationError(
                "unknown outcome requires dispatch_started=true"
            )
        expected = (False, False, True)

    observed = (
        value.completion_observed,
        value.reexecution_safe,
        value.reconciliation_required,
    )
    if observed != expected:
        raise ActionOutcomeValidationError(
            "outcome flags are inconsistent with effect_state"
        )


def _mapping(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ActionOutcomeValidationError(f"{where} must be an object")
    return value

def _exact_keys(value: Mapping[str, Any], expected: set[str], where: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ActionOutcomeValidationError(
            f"{where} keys mismatch; missing={missing}, extra={extra}"
        )


def _string(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise ActionOutcomeValidationError(f"{where} must be a non-empty string")
    return value


def _boolean(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise ActionOutcomeValidationError(f"{where} must be a boolean")
    return value
