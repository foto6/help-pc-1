from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .operations import OPS_SIDE_EFFECT_ACTIONS
from .outcome_journal import ExecutionCorrelation


EVIDENCE_VERSION = "pc_executor.ops_action_outcome.v1"
RECORD_VERSION = "pc_executor.ops_outcome_journal.record.v1"
LOOKUP_VERSION = "pc_executor.ops_outcome_journal.lookup.v1"
SOURCE = "help-pc-1.ops-outcome-journal"
EFFECT_STATES = {"not_started", "completed", "unknown"}
REASONS = {
    "dispatch_started",
    "completed",
    "dry_run",
    "policy_blocked",
    "timeout",
    "cancelled",
    "transient",
    "executor_failure",
}

_LOCKS_GUARD = threading.Lock()
_LOCKS: dict[str, threading.RLock] = {}


class OpsOutcomeError(RuntimeError):
    pass


class OpsOutcomeIntegrityError(OpsOutcomeError):
    pass


class OpsOutcomeReplayUnsafeError(OpsOutcomeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _lock(path: Path) -> threading.RLock:
    key = str(path.resolve())
    with _LOCKS_GUARD:
        value = _LOCKS.get(key)
        if value is None:
            value = threading.RLock()
            _LOCKS[key] = value
        return value


@dataclass(slots=True, frozen=True)
class OpsActionOutcomeEvidence:
    request_id: str
    action: str
    effect_state: str
    dispatch_started: bool
    completion_observed: bool
    reexecution_safe: bool
    reconciliation_required: bool
    observed_at: str
    reason: str
    contract_version: str = EVIDENCE_VERSION

    @classmethod
    def create(
        cls,
        *,
        request_id: str,
        action: str,
        effect_state: str,
        dispatch_started: bool,
        reason: str,
    ) -> "OpsActionOutcomeEvidence":
        if action not in OPS_SIDE_EFFECT_ACTIONS:
            raise OpsOutcomeIntegrityError(f"not a structured side-effect action: {action}")
        if effect_state not in EFFECT_STATES or reason not in REASONS:
            raise OpsOutcomeIntegrityError("invalid structured outcome state/reason")
        completion = effect_state == "completed"
        safe = effect_state == "not_started"
        reconcile = effect_state == "unknown"
        if effect_state in {"completed", "unknown"} and not dispatch_started:
            raise OpsOutcomeIntegrityError(
                f"{effect_state} outcome requires dispatch_started=true"
            )
        return cls(
            request_id=request_id,
            action=action,
            effect_state=effect_state,
            dispatch_started=dispatch_started,
            completion_observed=completion,
            reexecution_safe=safe,
            reconciliation_required=reconcile,
            observed_at=_now(),
            reason=reason,
        )

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "OpsActionOutcomeEvidence":
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
        if not isinstance(raw, Mapping) or set(raw) != expected:
            raise OpsOutcomeIntegrityError("ops outcome evidence keys mismatch")
        if raw["contract_version"] != EVIDENCE_VERSION:
            raise OpsOutcomeIntegrityError("unsupported ops outcome evidence version")
        value = cls.create(
            request_id=_string(raw["request_id"], "request_id"),
            action=_string(raw["action"], "action"),
            effect_state=_string(raw["effect_state"], "effect_state"),
            dispatch_started=_bool(raw["dispatch_started"], "dispatch_started"),
            reason=_string(raw["reason"], "reason"),
        )
        if (
            raw["completion_observed"] != value.completion_observed
            or raw["reexecution_safe"] != value.reexecution_safe
            or raw["reconciliation_required"] != value.reconciliation_required
        ):
            raise OpsOutcomeIntegrityError("ops outcome evidence semantics mismatch")
        return cls(
            request_id=value.request_id,
            action=value.action,
            effect_state=value.effect_state,
            dispatch_started=value.dispatch_started,
            completion_observed=value.completion_observed,
            reexecution_safe=value.reexecution_safe,
            reconciliation_required=value.reconciliation_required,
            observed_at=_string(raw["observed_at"], "observed_at"),
            reason=value.reason,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class OpsOutcomeJournal:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = _lock(self.path)

    @staticmethod
    def default_path() -> Path:
        override = os.environ.get("PC_EXECUTOR_OPS_OUTCOME_JOURNAL")
        if override:
            return Path(override)
        if os.name == "nt":
            root = Path(os.environ.get("LOCALAPPDATA") or Path.home())
        else:
            root = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
        return root / "pc-executor" / "ops-outcome-journal-v1.jsonl"

    def preflight_new_attempt(self, *, request_id: str, action: str) -> None:
        with self._lock:
            records, corruption = self._scan()
            if corruption:
                raise OpsOutcomeIntegrityError(corruption)
            matching = [r for r in records if r["request_id"] == request_id]
            actions = {r["action"] for r in matching}
            if actions and actions != {action}:
                raise OpsOutcomeIntegrityError(
                    f"request_id {request_id!r} already belongs to {sorted(actions)!r}"
                )
            prior = [r for r in matching if r["action"] == action]
            if prior:
                state = prior[-1]["evidence"]["effect_state"]
                if state in {"completed", "unknown"}:
                    raise OpsOutcomeReplayUnsafeError(
                        f"request {request_id!r} has {state} outcome; structured replay refused"
                    )

    def start_dispatch(
        self, evidence: OpsActionOutcomeEvidence
    ) -> ExecutionCorrelation:
        if (
            evidence.effect_state != "unknown"
            or not evidence.dispatch_started
            or evidence.reason != "dispatch_started"
        ):
            raise OpsOutcomeIntegrityError("dispatch evidence must be unknown/dispatch_started")
        with self._lock:
            self.preflight_new_attempt(
                request_id=evidence.request_id,
                action=evidence.action,
            )
            records, corruption = self._scan()
            if corruption:
                raise OpsOutcomeIntegrityError(corruption)
            attempts = [
                int(r["execution_attempt"])
                for r in records
                if r["request_id"] == evidence.request_id
                and r["action"] == evidence.action
            ]
            attempt = max(attempts, default=0) + 1
            execution_id = "ops-exec:" + hashlib.sha256(
                f"{evidence.request_id}\0{evidence.action}\0{attempt}".encode("utf-8")
            ).hexdigest()
            correlation = ExecutionCorrelation(execution_id, attempt)
            self._append(
                records,
                evidence=evidence,
                correlation=correlation,
                transition="dispatch_started",
            )
            return correlation

    def append_terminal(
        self,
        evidence: OpsActionOutcomeEvidence,
        *,
        correlation: ExecutionCorrelation | None = None,
    ) -> dict[str, Any]:
        if evidence.reason == "dispatch_started":
            raise OpsOutcomeIntegrityError("terminal evidence cannot use dispatch_started")
        with self._lock:
            records, corruption = self._scan()
            if corruption:
                raise OpsOutcomeIntegrityError(corruption)
            if correlation is None:
                self.preflight_new_attempt(
                    request_id=evidence.request_id,
                    action=evidence.action,
                )
                attempts = [
                    int(r["execution_attempt"])
                    for r in records
                    if r["request_id"] == evidence.request_id
                    and r["action"] == evidence.action
                ]
                attempt = max(attempts, default=0) + 1
                correlation = ExecutionCorrelation(
                    "ops-exec:"
                    + hashlib.sha256(
                        f"{evidence.request_id}\0{evidence.action}\0{attempt}".encode(
                            "utf-8"
                        )
                    ).hexdigest(),
                    attempt,
                )
            else:
                dispatches = [
                    r
                    for r in records
                    if r["execution_id"] == correlation.execution_id
                    and r["transition"] == "dispatch_started"
                ]
                if not dispatches:
                    raise OpsOutcomeIntegrityError(
                        "terminal correlation has no durable dispatch record"
                    )
            terminals = [
                r
                for r in records
                if r["execution_id"] == correlation.execution_id
                and r["transition"] == "terminal"
            ]
            if terminals:
                if terminals[-1]["evidence"] == evidence.to_dict():
                    return terminals[-1]
                raise OpsOutcomeIntegrityError("conflicting structured terminal evidence")
            return self._append(
                records,
                evidence=evidence,
                correlation=correlation,
                transition="terminal",
            )

    def lookup(
        self,
        *,
        request_id: str,
        action: str,
        execution_attempt: int | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            records, corruption = self._scan()
        matching = [
            r
            for r in records
            if r["request_id"] == request_id
            and r["action"] == action
            and (
                execution_attempt is None
                or r["execution_attempt"] == execution_attempt
            )
        ]
        latest = matching[-1] if matching else None
        if corruption:
            outcome, reason = "unknown", "journal_corrupt"
        elif latest is None:
            outcome, reason = "unknown", "no_evidence"
        else:
            evidence = latest["evidence"]
            outcome = evidence["effect_state"]
            reason = evidence["reason"]
        return {
            "contract_version": LOOKUP_VERSION,
            "source": SOURCE,
            "request_id": request_id,
            "requestId": request_id,
            "action": action,
            "execution_attempt": execution_attempt,
            "outcome": outcome,
            "reason": reason,
            "replay_authorized": False,
            "latest_valid_evidence": latest["evidence"] if latest else None,
            "latest_valid_record": latest,
            "history": matching,
            "provenance": {
                "record_contract_version": RECORD_VERSION,
                "total_valid_records": len(records),
                "matched_records": len(matching),
                "journal_sha256": hashlib.sha256(
                    self.path.read_bytes() if self.path.exists() else b""
                ).hexdigest(),
                "integrity": "corrupt" if corruption else "clean",
                "corruption": corruption,
            },
        }

    def _append(
        self,
        records: list[dict[str, Any]],
        *,
        evidence: OpsActionOutcomeEvidence,
        correlation: ExecutionCorrelation,
        transition: str,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "contract_version": RECORD_VERSION,
            "journal_sequence": len(records) + 1,
            "recorded_at": _now(),
            "request_id": evidence.request_id,
            "action": evidence.action,
            "execution_id": correlation.execution_id,
            "execution_attempt": correlation.execution_attempt,
            "transition": transition,
            "evidence": evidence.to_dict(),
            "previous_record_sha256": (
                records[-1]["record_sha256"] if records else None
            ),
        }
        body["record_sha256"] = _digest(body)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = (_canonical(body) + "\n").encode("utf-8")
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        fd = os.open(self.path, flags, 0o600)
        try:
            if os.write(fd, payload) != len(payload):
                raise OpsOutcomeIntegrityError("short structured outcome journal append")
            os.fsync(fd)
        finally:
            os.close(fd)
        return body

    def _scan(self) -> tuple[list[dict[str, Any]], str | None]:
        if not self.path.exists():
            return [], None
        raw = self.path.read_bytes()
        records: list[dict[str, Any]] = []
        previous: str | None = None
        for number, line in enumerate(raw.splitlines(keepends=True), start=1):
            if not line.endswith(b"\n"):
                return records, f"truncated_tail_line_{number}"
            try:
                value = json.loads(line[:-1].decode("utf-8"))
                self._validate_record(value, len(records) + 1, previous)
            except Exception as exc:
                return records, f"malformed_record_line_{number}:{type(exc).__name__}"
            records.append(value)
            previous = value["record_sha256"]
        return records, None

    @staticmethod
    def _validate_record(
        value: Mapping[str, Any],
        sequence: int,
        previous: str | None,
    ) -> None:
        expected = {
            "contract_version",
            "journal_sequence",
            "recorded_at",
            "request_id",
            "action",
            "execution_id",
            "execution_attempt",
            "transition",
            "evidence",
            "previous_record_sha256",
            "record_sha256",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise OpsOutcomeIntegrityError("record keys mismatch")
        if value["contract_version"] != RECORD_VERSION:
            raise OpsOutcomeIntegrityError("record version mismatch")
        if value["journal_sequence"] != sequence:
            raise OpsOutcomeIntegrityError("record sequence mismatch")
        if value["previous_record_sha256"] != previous:
            raise OpsOutcomeIntegrityError("record hash chain mismatch")
        body = dict(value)
        claimed = body.pop("record_sha256")
        if claimed != _digest(body):
            raise OpsOutcomeIntegrityError("record digest mismatch")
        evidence = OpsActionOutcomeEvidence.from_dict(value["evidence"])
        if evidence.request_id != value["request_id"] or evidence.action != value["action"]:
            raise OpsOutcomeIntegrityError("record/evidence identity mismatch")
        if value["transition"] not in {"dispatch_started", "terminal"}:
            raise OpsOutcomeIntegrityError("record transition mismatch")


def _string(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise OpsOutcomeIntegrityError(f"{where} must be non-empty string")
    return value


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise OpsOutcomeIntegrityError(f"{where} must be boolean")
    return value
