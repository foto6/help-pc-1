from __future__ import annotations

import hashlib
import json
import math
import re
import time
from pathlib import Path
from typing import Any, Iterable

from .progress import (
    DEFAULT_STALL_SECONDS,
    LIVENESS_VERSION,
    PROGRESS_VERSION,
    SOURCE_REPOSITORY,
    liveness_probe,
    validate_progress,
)


EVIDENCE_VERSION = "pc_relay.progress_evidence.v1"
DELIVERY_MECHANISM = "bounded_local_file_stdio"
DEFAULT_MAX_SNAPSHOT_BYTES = 64 * 1024
DEFAULT_MAX_AGE_SECONDS = 30.0
MAX_MAX_AGE_SECONDS = 300.0
MAX_CLOCK_SKEW_SECONDS = 5.0

_ERROR_CLASSIFICATIONS = {
    "missing_snapshot",
    "oversized_snapshot",
    "invalid_json",
    "unknown_version",
    "schema_invalid",
    "source_identity_invalid",
    "stale_snapshot",
    "future_snapshot",
    "atomic_binding_invalid",
    "read_error",
}
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class EvidenceReadError(RuntimeError):
    def __init__(self, classification: str, reason: str) -> None:
        if classification not in _ERROR_CLASSIFICATIONS:
            classification = "read_error"
        self.classification = classification
        self.reason = reason[:256]
        super().__init__(f"{classification}: {self.reason}")


def _canonical(payload: Any) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(payload: Any) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


def _finite_number(value: object) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(float(value))
    )


def _delivery_semantics() -> dict[str, bool]:
    return {
        "read_only": True,
        "queue_acknowledged": False,
        "lease_created": False,
        "retry_triggered": False,
        "replay_triggered": False,
    }


def _delivery_source(
    *,
    reader_script_sha256: str,
    evidence_module_sha256: str,
) -> dict[str, Any]:
    if not _HEX64.fullmatch(reader_script_sha256):
        raise ValueError("reader_script_sha256 must be lowercase sha256")
    if not _HEX64.fullmatch(evidence_module_sha256):
        raise ValueError("evidence_module_sha256 must be lowercase sha256")
    return {
        "repository": SOURCE_REPOSITORY,
        "mechanism": DELIVERY_MECHANISM,
        "reader_script_sha256": reader_script_sha256,
        "evidence_module_sha256": evidence_module_sha256,
    }


def _empty_envelope(
    *,
    observed_at_unix: float,
    delivery_source: dict[str, Any],
    classification: str,
    reason: str,
) -> dict[str, Any]:
    envelope = {
        "contract_version": EVIDENCE_VERSION,
        "status": "blocked",
        "observed_at_unix": observed_at_unix,
        "delivery_source": delivery_source,
        "delivery_semantics": _delivery_semantics(),
        "binding": None,
        "progress_sha256": None,
        "progress": None,
        "liveness": None,
        "error": {
            "classification": classification,
            "reason": reason[:256],
            "retryable": False,
        },
        "evidence_sha256": "",
    }
    envelope["evidence_sha256"] = _sha256(
        {key: value for key, value in envelope.items() if key != "evidence_sha256"}
    )
    return envelope


def _validate_source_identity(progress: dict[str, Any]) -> None:
    source = progress["source"]
    startup_head = source.get("startup_head")
    relay_script_sha256 = source.get("relay_script_sha256")
    process = progress["process"]

    if not isinstance(startup_head, str) or not _HEX40.fullmatch(startup_head):
        raise EvidenceReadError(
            "source_identity_invalid",
            "relay startup HEAD is unavailable or malformed",
        )
    if (
        not isinstance(relay_script_sha256, str)
        or not _HEX64.fullmatch(relay_script_sha256)
    ):
        raise EvidenceReadError(
            "source_identity_invalid",
            "relay script sha256 is unavailable or malformed",
        )
    if (
        not isinstance(process.get("instance_id"), str)
        or not process["instance_id"]
        or len(process["instance_id"]) > 128
    ):
        raise EvidenceReadError(
            "source_identity_invalid",
            "relay process instance identity is invalid",
        )


def _freshness_deadline(
    progress: dict[str, Any],
    *,
    max_age_seconds: float,
) -> float:
    recorded_at = float(progress["recorded_at_unix"])
    deadline = recorded_at + max_age_seconds
    cycle = progress["current_cycle"]
    execution_deadline = cycle.get("deadline_at_unix")
    if (
        cycle.get("state") == "executing"
        and _finite_number(execution_deadline)
    ):
        deadline = max(
            deadline,
            float(execution_deadline)
            + max(1.0, float(progress["limits"]["poll_seconds"])),
        )
    return deadline


def _read_one_progress_snapshot(
    path: Path,
    *,
    max_snapshot_bytes: int,
) -> tuple[dict[str, Any], bytes]:
    if (
        isinstance(max_snapshot_bytes, bool)
        or not isinstance(max_snapshot_bytes, int)
        or max_snapshot_bytes <= 0
        or max_snapshot_bytes > 1024 * 1024
    ):
        raise ValueError("max_snapshot_bytes must be an integer in [1, 1048576]")
    try:
        with path.open("rb") as fh:
            raw = fh.read(max_snapshot_bytes + 1)
    except FileNotFoundError as exc:
        raise EvidenceReadError(
            "missing_snapshot",
            "relay progress snapshot does not exist",
        ) from exc
    except OSError as exc:
        raise EvidenceReadError(
            "read_error",
            f"bounded snapshot read failed: {type(exc).__name__}",
        ) from exc

    if len(raw) > max_snapshot_bytes:
        raise EvidenceReadError(
            "oversized_snapshot",
            "relay progress snapshot exceeds bounded read limit",
        )
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceReadError(
            "invalid_json",
            "relay progress snapshot is torn, partial, or invalid JSON",
        ) from exc
    if not isinstance(decoded, dict):
        raise EvidenceReadError(
            "schema_invalid",
            "relay progress snapshot must be a JSON object",
        )
    version = decoded.get("contract_version")
    if version != PROGRESS_VERSION:
        raise EvidenceReadError(
            "unknown_version",
            "relay progress snapshot contract version is unsupported",
        )
    try:
        validate_progress(decoded)
    except Exception as exc:
        raise EvidenceReadError(
            "schema_invalid",
            f"relay progress snapshot failed strict validation: {type(exc).__name__}",
        ) from exc
    _validate_source_identity(decoded)
    return decoded, raw


def read_progress_evidence(
    progress_path: Path,
    *,
    reader_script_sha256: str,
    evidence_module_sha256: str,
    observed_pids: Iterable[int] | None = None,
    expected_pid: int | None = None,
    now: float | None = None,
    max_age_seconds: float = DEFAULT_MAX_AGE_SECONDS,
    stall_seconds: float = DEFAULT_STALL_SECONDS,
    max_snapshot_bytes: int = DEFAULT_MAX_SNAPSHOT_BYTES,
) -> dict[str, Any]:
    observed_at = time.time() if now is None else float(now)
    if not math.isfinite(observed_at) or observed_at < 0:
        raise ValueError("observed time must be a finite nonnegative value")
    max_age = float(max_age_seconds)
    if (
        not math.isfinite(max_age)
        or max_age < 1.0
        or max_age > MAX_MAX_AGE_SECONDS
    ):
        raise ValueError("max_age_seconds must be in [1, 300]")
    source = _delivery_source(
        reader_script_sha256=reader_script_sha256,
        evidence_module_sha256=evidence_module_sha256,
    )

    try:
        progress, _raw = _read_one_progress_snapshot(
            Path(progress_path),
            max_snapshot_bytes=max_snapshot_bytes,
        )
        recorded_at = float(progress["recorded_at_unix"])
        if recorded_at > observed_at + MAX_CLOCK_SKEW_SECONDS:
            raise EvidenceReadError(
                "future_snapshot",
                "relay progress snapshot timestamp is ahead of observation bound",
            )
        if observed_at > _freshness_deadline(
            progress,
            max_age_seconds=max_age,
        ):
            raise EvidenceReadError(
                "stale_snapshot",
                "relay progress snapshot exceeded the delivery freshness bound",
            )

        liveness = liveness_probe(
            progress,
            observed_pids=observed_pids,
            expected_pid=expected_pid,
            now=observed_at,
            stall_seconds=stall_seconds,
        )
        if liveness.get("contract_version") != LIVENESS_VERSION:
            raise EvidenceReadError(
                "atomic_binding_invalid",
                "derived liveness contract version mismatch",
            )
        if (
            liveness.get("loop_generation_id") != progress["loop_generation_id"]
            or liveness.get("loop_epoch") != progress["loop_epoch"]
            or liveness.get("process_pid") != progress["process"]["pid"]
        ):
            raise EvidenceReadError(
                "atomic_binding_invalid",
                "progress and liveness generation binding mismatch",
            )

        binding = {
            "relay_startup_head": progress["source"]["startup_head"],
            "relay_script_sha256": progress["source"]["relay_script_sha256"],
            "process_pid": progress["process"]["pid"],
            "process_started_at_unix": progress["process"]["started_at_unix"],
            "process_instance_id": progress["process"]["instance_id"],
            "loop_generation_id": progress["loop_generation_id"],
            "loop_epoch": progress["loop_epoch"],
            "progress_recorded_at_unix": progress["recorded_at_unix"],
        }
        envelope = {
            "contract_version": EVIDENCE_VERSION,
            "status": "ok",
            "observed_at_unix": observed_at,
            "delivery_source": source,
            "delivery_semantics": _delivery_semantics(),
            "binding": binding,
            "progress_sha256": _sha256(progress),
            "progress": progress,
            "liveness": liveness,
            "error": None,
            "evidence_sha256": "",
        }
        envelope["evidence_sha256"] = _sha256(
            {
                key: value
                for key, value in envelope.items()
                if key != "evidence_sha256"
            }
        )
        validate_evidence_envelope(envelope)
        return envelope
    except EvidenceReadError as exc:
        return _empty_envelope(
            observed_at_unix=observed_at,
            delivery_source=source,
            classification=exc.classification,
            reason=exc.reason,
        )


def validate_evidence_envelope(payload: Any) -> None:
    if not isinstance(payload, dict):
        raise ValueError("relay progress evidence must be an object")
    required = {
        "contract_version",
        "status",
        "observed_at_unix",
        "delivery_source",
        "delivery_semantics",
        "binding",
        "progress_sha256",
        "progress",
        "liveness",
        "error",
        "evidence_sha256",
    }
    if set(payload) != required:
        raise ValueError("relay progress evidence top-level keys mismatch")
    if payload["contract_version"] != EVIDENCE_VERSION:
        raise ValueError("relay progress evidence version mismatch")
    if payload["status"] not in {"ok", "blocked"}:
        raise ValueError("relay progress evidence status invalid")
    if not _finite_number(payload["observed_at_unix"]):
        raise ValueError("relay progress evidence observed_at invalid")
    source = payload["delivery_source"]
    if not isinstance(source, dict) or set(source) != {
        "repository",
        "mechanism",
        "reader_script_sha256",
        "evidence_module_sha256",
    }:
        raise ValueError("relay progress evidence delivery source invalid")
    if source["repository"] != SOURCE_REPOSITORY:
        raise ValueError("relay progress evidence repository mismatch")
    if source["mechanism"] != DELIVERY_MECHANISM:
        raise ValueError("relay progress evidence mechanism mismatch")
    semantics = payload["delivery_semantics"]
    if semantics != _delivery_semantics():
        raise ValueError("relay progress evidence delivery semantics mismatch")
    if not _HEX64.fullmatch(str(source["reader_script_sha256"])):
        raise ValueError("relay progress reader script digest invalid")
    if not _HEX64.fullmatch(str(source["evidence_module_sha256"])):
        raise ValueError("relay progress evidence module digest invalid")

    if payload["status"] == "ok":
        if payload["error"] is not None:
            raise ValueError("successful relay progress evidence cannot have error")
        progress = payload["progress"]
        liveness = payload["liveness"]
        binding = payload["binding"]
        validate_progress(progress)
        if (
            not isinstance(liveness, dict)
            or liveness.get("contract_version") != LIVENESS_VERSION
        ):
            raise ValueError("relay progress evidence liveness invalid")
        if not isinstance(binding, dict) or set(binding) != {
            "relay_startup_head",
            "relay_script_sha256",
            "process_pid",
            "process_started_at_unix",
            "process_instance_id",
            "loop_generation_id",
            "loop_epoch",
            "progress_recorded_at_unix",
        }:
            raise ValueError("relay progress evidence binding invalid")
        if binding["relay_startup_head"] != progress["source"]["startup_head"]:
            raise ValueError("relay startup HEAD binding mismatch")
        if binding["relay_script_sha256"] != progress["source"]["relay_script_sha256"]:
            raise ValueError("relay script digest binding mismatch")
        if binding["process_pid"] != progress["process"]["pid"]:
            raise ValueError("relay process binding mismatch")
        if binding["process_instance_id"] != progress["process"]["instance_id"]:
            raise ValueError("relay process instance binding mismatch")
        if binding["loop_generation_id"] != progress["loop_generation_id"]:
            raise ValueError("relay generation binding mismatch")
        if binding["loop_epoch"] != progress["loop_epoch"]:
            raise ValueError("relay epoch binding mismatch")
        if liveness.get("loop_generation_id") != binding["loop_generation_id"]:
            raise ValueError("relay liveness generation mismatch")
        if liveness.get("loop_epoch") != binding["loop_epoch"]:
            raise ValueError("relay liveness epoch mismatch")
        if liveness.get("process_pid") != binding["process_pid"]:
            raise ValueError("relay liveness process mismatch")
        if payload["progress_sha256"] != _sha256(progress):
            raise ValueError("relay progress canonical digest mismatch")
    else:
        if any(
            payload[key] is not None
            for key in ("binding", "progress_sha256", "progress", "liveness")
        ):
            raise ValueError("blocked relay evidence must not expose partial snapshot")
        error = payload["error"]
        if (
            not isinstance(error, dict)
            or set(error) != {"classification", "reason", "retryable"}
            or error["classification"] not in _ERROR_CLASSIFICATIONS
            or error["retryable"] is not False
            or not isinstance(error["reason"], str)
            or len(error["reason"]) > 256
        ):
            raise ValueError("blocked relay evidence error invalid")

    expected = _sha256(
        {
            key: value
            for key, value in payload.items()
            if key != "evidence_sha256"
        }
    )
    if payload["evidence_sha256"] != expected:
        raise ValueError("relay progress evidence digest mismatch")
