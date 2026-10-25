from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from typing import Any, Mapping


CONTRACT_VERSION = "vision.grounded_target.v1"
_ALLOWED_SOURCES = {"uia", "vision", "ocr"}


class GroundedTargetContractError(ValueError):
    """Raised when a Vision grounded-target payload violates the frozen v1 transport."""


@dataclass(frozen=True, slots=True)
class ValidatedVisionTarget:
    automation_id: str | None
    sources: tuple[str, ...]


def parse_grounded_target_v1(payload: Any) -> ValidatedVisionTarget:
    root = _mapping(payload, "payload")
    _exact_keys(root, {"contract_version", "frame", "target"}, "payload")

    version = _string(root["contract_version"], "contract_version")
    if version != CONTRACT_VERSION:
        raise GroundedTargetContractError(f"unsupported contract_version: {version!r}")

    frame = _mapping(root["frame"], "frame")
    _exact_keys(
        frame,
        {"frame_id", "sequence", "captured_at_ms", "image_digest", "display_id"},
        "frame",
    )
    _string(frame["frame_id"], "frame.frame_id")
    _integer(frame["sequence"], "frame.sequence", minimum=0)
    _integer(frame["captured_at_ms"], "frame.captured_at_ms", minimum=0)
    _string(frame["image_digest"], "frame.image_digest")
    _string(frame["display_id"], "frame.display_id")

    target = _mapping(root["target"], "target")
    _exact_keys(
        target,
        {
            "element_id",
            "node_id",
            "automation_id",
            "role",
            "name",
            "confidence",
            "sources",
            "bounds_screen",
            "click_point_screen",
        },
        "target",
    )
    sources_raw = target["sources"]
    if not isinstance(sources_raw, list) or not sources_raw:
        raise GroundedTargetContractError("target.sources must be a non-empty JSON array")
    sources = tuple(_string(value, "target.sources[]") for value in sources_raw)
    if any(source not in _ALLOWED_SOURCES for source in sources):
        raise GroundedTargetContractError("target.sources contains an unsupported source")

    _string(target["element_id"], "target.element_id")
    _optional_string(target["node_id"], "target.node_id")
    automation_id = _optional_string(target["automation_id"], "target.automation_id")
    _string(target["role"], "target.role")
    _string(target["name"], "target.name", allow_empty=True)
    _number(target["confidence"], "target.confidence", minimum=0.0, maximum=1.0)

    x, y, width, height = _parse_rect(target["bounds_screen"], "target.bounds_screen")
    click_x, click_y = _parse_point(target["click_point_screen"], "target.click_point_screen")
    if (click_x, click_y) != (x + width / 2.0, y + height / 2.0):
        raise GroundedTargetContractError(
            "target.click_point_screen must equal bounds_screen center"
        )
    if "uia" not in sources and automation_id:
        raise GroundedTargetContractError(
            "non-UIA targets cannot carry actionable automation_id"
        )

    return ValidatedVisionTarget(automation_id=automation_id, sources=sources)


def _mapping(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise GroundedTargetContractError(f"{where} must be an object")
    return value

def _exact_keys(value: Mapping[str, Any], expected: set[str], where: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise GroundedTargetContractError(
            f"{where} keys mismatch; missing={missing}, extra={extra}"
        )


def _string(value: Any, where: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise GroundedTargetContractError(f"{where} must be a non-empty string")
    return value


def _optional_string(value: Any, where: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise GroundedTargetContractError(f"{where} must be a string or null")
    return value


def _integer(value: Any, where: str, *, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise GroundedTargetContractError(f"{where} must be an integer >= {minimum}")
    return value

def _number(
    value: Any,
    where: str,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not isfinite(value):
        raise GroundedTargetContractError(f"{where} must be a finite number")
    if minimum is not None and value < minimum:
        raise GroundedTargetContractError(f"{where} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise GroundedTargetContractError(f"{where} must be <= {maximum}")
    return float(value)


def _parse_rect(value: Any, where: str) -> tuple[float, float, float, float]:
    raw = _mapping(value, where)
    _exact_keys(raw, {"x", "y", "width", "height"}, where)
    return (
        _number(raw["x"], f"{where}.x"),
        _number(raw["y"], f"{where}.y"),
        _number(raw["width"], f"{where}.width", minimum=0.0),
        _number(raw["height"], f"{where}.height", minimum=0.0),
    )


def _parse_point(value: Any, where: str) -> tuple[float, float]:
    raw = _mapping(value, where)
    _exact_keys(raw, {"x", "y"}, where)
    return (
        _number(raw["x"], f"{where}.x"),
        _number(raw["y"], f"{where}.y"),
    )
