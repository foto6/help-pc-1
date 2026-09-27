from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol

from .outcome import ActionOutcomeEvidence, parse_action_outcome


RECORD_CONTRACT_VERSION = "pc_executor.outcome_journal.record.v1"
LOOKUP_CONTRACT_VERSION = "pc_executor.outcome_journal.lookup.v1"
SOURCE = "help-pc-1.outcome-journal"
_TRANSITIONS = {"dispatch_started", "terminal"}

_LOCKS_GUARD = threading.Lock()
_PATH_LOCKS: dict[str, threading.RLock] = {}


class OutcomeJournalError(RuntimeError):
    pass


class OutcomeJournalIntegrityError(OutcomeJournalError):
    pass


class OutcomeJournalConflictError(OutcomeJournalError):
    pass


class OutcomeJournalReplayUnsafeError(OutcomeJournalError):
    pass


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _record_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def canonical_journal_bytes(raw: bytes) -> bytes:
    """Normalize transport newlines for cross-platform hashing only."""
    without_crlf = raw.replace(b"\r\n", b"\n")
    if b"\r" in without_crlf:
        raise OutcomeJournalIntegrityError("journal contains unsupported bare CR bytes")
    return without_crlf


def canonical_journal_sha256(raw: bytes) -> str:
    return hashlib.sha256(canonical_journal_bytes(raw)).hexdigest()


def _path_lock(path: Path) -> threading.RLock:
    key = str(path.resolve())
    with _LOCKS_GUARD:
        lock = _PATH_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _PATH_LOCKS[key] = lock
        return lock


class JournalStorage(Protocol):
    def read_bytes(self) -> bytes: ...

    def append_durable(self, payload: bytes) -> None: ...


class FileJournalStorage:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def read_bytes(self) -> bytes:
        try:
            return self.path.read_bytes()
        except FileNotFoundError:
            return b""

    def append_durable(self, payload: bytes) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        existed = self.path.exists()
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        fd = os.open(self.path, flags, 0o600)
        try:
            written = os.write(fd, payload)
            if written != len(payload):
                raise OutcomeJournalIntegrityError(
                    f"short journal append: {written}/{len(payload)} bytes"
                )
            os.fsync(fd)
        finally:
            os.close(fd)
        if not existed and os.name != "nt":
            directory_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)


@dataclass(slots=True, frozen=True)
class ExecutionCorrelation:
    execution_id: str
    execution_attempt: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True, frozen=True)
class JournalCorruption:
    kind: str
    line_number: int
    byte_offset: int
    detail: str
    safe_prefix_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass(slots=True, frozen=True)
class OutcomeJournalRecord:
    journal_sequence: int
    recorded_at: str
    request_id: str
    action: str
    execution_id: str
    execution_attempt: int
    transition: str
    evidence: ActionOutcomeEvidence
    previous_record_sha256: str | None
    record_sha256: str
    contract_version: str = RECORD_CONTRACT_VERSION

    @classmethod
    def create(
        cls,
        *,
        journal_sequence: int,
        request_id: str,
        action: str,
        correlation: ExecutionCorrelation,
        transition: str,
        evidence: ActionOutcomeEvidence,
        previous_record_sha256: str | None,
        recorded_at: str | None = None,
    ) -> "OutcomeJournalRecord":
        recorded = recorded_at or _utc_now_iso()
        body = {
            "contract_version": RECORD_CONTRACT_VERSION,
            "journal_sequence": journal_sequence,
            "recorded_at": recorded,
            "request_id": request_id,
            "action": action,
            "execution_id": correlation.execution_id,
            "execution_attempt": correlation.execution_attempt,
            "transition": transition,
            "evidence": evidence.to_dict(),
            "previous_record_sha256": previous_record_sha256,
        }
        record = cls(
            journal_sequence=journal_sequence,
            recorded_at=recorded,
            request_id=request_id,
            action=action,
            execution_id=correlation.execution_id,
            execution_attempt=correlation.execution_attempt,
            transition=transition,
            evidence=evidence,
            previous_record_sha256=previous_record_sha256,
            record_sha256=_record_digest(body),
        )
        _validate_record(record)
        return record

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "OutcomeJournalRecord":
        value = _mapping(raw, "record")
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
        _exact_keys(value, expected, "record")
        if _string(value["contract_version"], "contract_version") != RECORD_CONTRACT_VERSION:
            raise OutcomeJournalIntegrityError(
                f"unsupported journal contract_version: {value['contract_version']!r}"
            )
        evidence = parse_action_outcome(_mapping(value["evidence"], "evidence"))
        record = cls(
            journal_sequence=_positive_int(value["journal_sequence"], "journal_sequence"),
            recorded_at=_string(value["recorded_at"], "recorded_at"),
            request_id=_string(value["request_id"], "request_id"),
            action=_string(value["action"], "action"),
            execution_id=_string(value["execution_id"], "execution_id"),
            execution_attempt=_positive_int(value["execution_attempt"], "execution_attempt"),
            transition=_string(value["transition"], "transition"),
            evidence=evidence,
            previous_record_sha256=_optional_digest(
                value["previous_record_sha256"], "previous_record_sha256"
            ),
            record_sha256=_digest(value["record_sha256"], "record_sha256"),
        )
        body = record.to_dict()
        body.pop("record_sha256")
        if _record_digest(body) != record.record_sha256:
            raise OutcomeJournalIntegrityError("record_sha256 mismatch")
        _validate_record(record)
        return record

    def to_dict(self) -> dict[str, Any]:
        raw = asdict(self)
        raw["evidence"] = self.evidence.to_dict()
        return raw

@dataclass(slots=True, frozen=True)
class OutcomeJournalLookup:
    request_id: str
    action: str
    execution_attempt: int | None
    outcome: str
    reason: str
    latest_valid_record: OutcomeJournalRecord | None
    history: tuple[OutcomeJournalRecord, ...]
    corruption: JournalCorruption | None
    total_valid_records: int
    journal_sha256: str
    contract_version: str = LOOKUP_CONTRACT_VERSION
    source: str = SOURCE
    replay_authorized: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "source": self.source,
            "request_id": self.request_id,
            "requestId": self.request_id,
            "action": self.action,
            "execution_attempt": self.execution_attempt,
            "outcome": self.outcome,
            "reason": self.reason,
            "replay_authorized": False,
            "latest_valid_evidence": (
                self.latest_valid_record.evidence.to_dict()
                if self.latest_valid_record is not None
                else None
            ),
            "latest_valid_record": (
                self.latest_valid_record.to_dict()
                if self.latest_valid_record is not None
                else None
            ),
            "history": [record.to_dict() for record in self.history],
            "provenance": {
                "record_contract_version": RECORD_CONTRACT_VERSION,
                "total_valid_records": self.total_valid_records,
                "matched_records": len(self.history),
                "journal_sha256": self.journal_sha256,
                "integrity": "corrupt" if self.corruption else "clean",
                "corruption": self.corruption.to_dict() if self.corruption else None,
            },
        }


@dataclass(slots=True, frozen=True)
class _ScanResult:
    records: tuple[OutcomeJournalRecord, ...]
    corruption: JournalCorruption | None
    journal_sha256: str


class OutcomeJournal:
    def __init__(
        self,
        path: str | Path,
        *,
        storage: JournalStorage | None = None,
    ) -> None:
        self.path = Path(path)
        self._storage = storage or FileJournalStorage(self.path)
        self._lock = _path_lock(self.path)

    @staticmethod
    def default_path() -> Path:
        override = os.environ.get("PC_EXECUTOR_OUTCOME_JOURNAL")
        if override:
            return Path(override)
        if os.name == "nt":
            root = Path(os.environ.get("LOCALAPPDATA") or Path.home())
            return root / "pc-executor" / "outcome-journal-v1.jsonl"
        state = Path(os.environ.get("XDG_STATE_HOME") or (Path.home() / ".local" / "state"))
        return state / "pc-executor" / "outcome-journal-v1.jsonl"

    def preflight_new_attempt(self, *, request_id: str, action: str) -> None:
        request_id = _string(request_id, "request_id")
        action = _string(action, "action")
        with self._lock:
            scan = self._scan_locked()
            self._require_clean(scan)
            self._require_identity(scan.records, request_id, action)
            self._require_replay_safe_prefix(scan.records, request_id, action)

    def start_dispatch(self, evidence: ActionOutcomeEvidence) -> ExecutionCorrelation:
        if (
            evidence.effect_state != "unknown"
            or not evidence.dispatch_started
            or evidence.reason != "dispatch_started"
        ):
            raise OutcomeJournalConflictError(
                "dispatch record requires provisional unknown/dispatch_started evidence"
            )
        with self._lock:
            scan = self._scan_locked()
            self._require_clean(scan)
            self._require_identity(scan.records, evidence.request_id, evidence.action)
            self._require_replay_safe_prefix(scan.records, evidence.request_id, evidence.action)
            attempt = self._next_attempt(scan.records, evidence.request_id, evidence.action)
            correlation = self._correlation(evidence.request_id, evidence.action, attempt)
            record = self._make_record(
                scan,
                evidence=evidence,
                correlation=correlation,
                transition="dispatch_started",
            )
            self._append_record_locked(record)
            return correlation

    def append_terminal(
        self,
        evidence: ActionOutcomeEvidence,
        *,
        correlation: ExecutionCorrelation | None = None,
    ) -> OutcomeJournalRecord:
        if evidence.reason == "dispatch_started":
            raise OutcomeJournalConflictError("terminal evidence cannot use dispatch_started reason")
        with self._lock:
            scan = self._scan_locked()
            self._require_clean(scan)
            self._require_identity(scan.records, evidence.request_id, evidence.action)

            if correlation is None:
                if evidence.dispatch_started:
                    raise OutcomeJournalConflictError(
                        "dispatched terminal evidence requires execution correlation"
                    )
                self._require_replay_safe_prefix(
                    scan.records, evidence.request_id, evidence.action
                )
                attempt = self._next_attempt(
                    scan.records, evidence.request_id, evidence.action
                )
                correlation = self._correlation(
                    evidence.request_id, evidence.action, attempt
                )
            else:
                if not evidence.dispatch_started:
                    raise OutcomeJournalConflictError(
                        "terminal evidence for a dispatched execution must preserve "
                        "dispatch_started=true"
                    )
                self._validate_correlation(
                    scan.records,
                    evidence.request_id,
                    evidence.action,
                    correlation,
                )

            terminals = [
                record
                for record in scan.records
                if record.execution_id == correlation.execution_id
                and record.transition == "terminal"
            ]
            if terminals:
                existing = terminals[-1]
                if existing.evidence.to_dict() == evidence.to_dict():
                    return existing
                raise OutcomeJournalConflictError(
                    "conflicting terminal evidence already exists for execution_id"
                )

            record = self._make_record(
                scan,
                evidence=evidence,
                correlation=correlation,
                transition="terminal",
            )
            self._append_record_locked(record)
            return record

    def lookup(
        self,
        *,
        request_id: str,
        action: str,
        execution_attempt: int | None = None,
    ) -> OutcomeJournalLookup:
        request_id = _string(request_id, "request_id")
        action = _string(action, "action")
        if execution_attempt is not None:
            execution_attempt = _positive_int(execution_attempt, "execution_attempt")
        with self._lock:
            scan = self._scan_locked()

        matching_request = [
            record for record in scan.records if record.request_id == request_id
        ]
        identity_conflict = any(record.action != action for record in matching_request)
        history = tuple(
            record
            for record in matching_request
            if record.action == action
            and (
                execution_attempt is None
                or record.execution_attempt == execution_attempt
            )
        )
        latest = history[-1] if history else None

        corruption = scan.corruption
        if identity_conflict and corruption is None:
            corruption = JournalCorruption(
                kind="request_action_conflict",
                line_number=0,
                byte_offset=0,
                detail="request_id is associated with multiple actions",
                safe_prefix_bytes=0,
            )

        outcome, reason = _reconciliation_outcome(latest, corruption)
        return OutcomeJournalLookup(
            request_id=request_id,
            action=action,
            execution_attempt=execution_attempt,
            outcome=outcome,
            reason=reason,
            latest_valid_record=latest,
            history=history,
            corruption=corruption,
            total_valid_records=len(scan.records),
            journal_sha256=scan.journal_sha256,
        )

    def read_evidence(self, request: Mapping[str, Any]) -> dict[str, Any]:
        raw = _mapping(request, "request")
        request_id = raw.get("request_id", raw.get("requestId"))
        action = raw.get("action")
        attempt = raw.get("execution_attempt", raw.get("executionAttempt"))
        return self.lookup(
            request_id=_string(request_id, "request_id"),
            action=_string(action, "action"),
            execution_attempt=(
                None if attempt is None else _positive_int(attempt, "execution_attempt")
            ),
        ).to_dict()

    def _make_record(
        self,
        scan: _ScanResult,
        *,
        evidence: ActionOutcomeEvidence,
        correlation: ExecutionCorrelation,
        transition: str,
    ) -> OutcomeJournalRecord:
        previous = scan.records[-1].record_sha256 if scan.records else None
        return OutcomeJournalRecord.create(
            journal_sequence=len(scan.records) + 1,
            request_id=evidence.request_id,
            action=evidence.action,
            correlation=correlation,
            transition=transition,
            evidence=evidence,
            previous_record_sha256=previous,
        )

    def _append_record_locked(self, record: OutcomeJournalRecord) -> None:
        payload = (_canonical_json(record.to_dict()) + "\n").encode("utf-8")
        try:
            self._storage.append_durable(payload)
        except OutcomeJournalError:
            raise
        except OSError as exc:
            raise OutcomeJournalIntegrityError(
                f"journal durable append failed: {type(exc).__name__}: {exc}"
            ) from exc

    def _scan_locked(self) -> _ScanResult:
        try:
            raw = self._storage.read_bytes()
        except OSError as exc:
            raise OutcomeJournalIntegrityError(
                f"journal read failed: {type(exc).__name__}: {exc}"
            ) from exc
        if not raw:
            return _ScanResult(
                records=(),
                corruption=None,
                journal_sha256=hashlib.sha256(b"").hexdigest(),
            )
        digest = hashlib.sha256(raw).hexdigest()
        records: list[OutcomeJournalRecord] = []
        previous_hash: str | None = None
        offset = 0

        for line_number, line in enumerate(raw.splitlines(keepends=True), start=1):
            line_start = offset
            offset += len(line)
            if not line.endswith(b"\n"):
                return _ScanResult(
                    records=tuple(records),
                    corruption=JournalCorruption(
                        kind="truncated_tail",
                        line_number=line_number,
                        byte_offset=line_start,
                        detail="final journal record is not newline-terminated",
                        safe_prefix_bytes=line_start,
                    ),
                    journal_sha256=digest,
                )
            payload = line[:-1]
            try:
                decoded = json.loads(payload.decode("utf-8"))
                record = OutcomeJournalRecord.from_dict(decoded)
                if record.journal_sequence != len(records) + 1:
                    raise OutcomeJournalIntegrityError(
                        "journal_sequence is not contiguous"
                    )
                if record.previous_record_sha256 != previous_hash:
                    raise OutcomeJournalIntegrityError(
                        "previous_record_sha256 chain mismatch"
                    )
            except Exception as exc:
                return _ScanResult(
                    records=tuple(records),
                    corruption=JournalCorruption(
                        kind=(
                            "malformed_tail"
                            if offset == len(raw)
                            else "malformed_record"
                        ),
                        line_number=line_number,
                        byte_offset=line_start,
                        detail=f"{type(exc).__name__}: {exc}",
                        safe_prefix_bytes=line_start,
                    ),
                    journal_sha256=digest,
                )
            records.append(record)
            previous_hash = record.record_sha256

        return _ScanResult(
            records=tuple(records),
            corruption=None,
            journal_sha256=digest,
        )

    @staticmethod
    def _require_clean(scan: _ScanResult) -> None:
        if scan.corruption is not None:
            raise OutcomeJournalIntegrityError(
                f"journal integrity failure: {scan.corruption.kind} at line "
                f"{scan.corruption.line_number}"
            )

    @staticmethod
    def _require_identity(
        records: tuple[OutcomeJournalRecord, ...],
        request_id: str,
        action: str,
    ) -> None:
        actions = {record.action for record in records if record.request_id == request_id}
        if actions and actions != {action}:
            raise OutcomeJournalConflictError(
                f"request_id {request_id!r} is already bound to action(s) {sorted(actions)!r}"
            )

    @staticmethod
    def _require_replay_safe_prefix(
        records: tuple[OutcomeJournalRecord, ...],
        request_id: str,
        action: str,
    ) -> None:
        prior = [
            record
            for record in records
            if record.request_id == request_id and record.action == action
        ]
        if not prior:
            return
        latest = prior[-1].evidence
        if latest.effect_state in {"unknown", "completed"}:
            raise OutcomeJournalReplayUnsafeError(
                f"request {request_id!r} has {latest.effect_state} outcome; "
                "journal never authorizes side-effect replay"
            )

    @staticmethod
    def _next_attempt(
        records: tuple[OutcomeJournalRecord, ...],
        request_id: str,
        action: str,
    ) -> int:
        attempts = [
            record.execution_attempt
            for record in records
            if record.request_id == request_id and record.action == action
        ]
        return max(attempts, default=0) + 1

    @staticmethod
    def _correlation(
        request_id: str,
        action: str,
        execution_attempt: int,
    ) -> ExecutionCorrelation:
        digest = hashlib.sha256(
            f"{request_id}\0{action}\0{execution_attempt}".encode("utf-8")
        ).hexdigest()
        return ExecutionCorrelation(
            execution_id=f"exec:{digest}",
            execution_attempt=execution_attempt,
        )

    @staticmethod
    def _validate_correlation(
        records: tuple[OutcomeJournalRecord, ...],
        request_id: str,
        action: str,
        correlation: ExecutionCorrelation,
    ) -> None:
        matching = [
            record
            for record in records
            if record.execution_id == correlation.execution_id
        ]
        if not matching:
            raise OutcomeJournalConflictError(
                "execution correlation has no durable dispatch record"
            )
        for record in matching:
            if (
                record.request_id != request_id
                or record.action != action
                or record.execution_attempt != correlation.execution_attempt
            ):
                raise OutcomeJournalConflictError(
                    "execution correlation does not match request/action/attempt"
                )
        if not any(record.transition == "dispatch_started" for record in matching):
            raise OutcomeJournalConflictError(
                "execution correlation is missing dispatch_started record"
            )


def _reconciliation_outcome(
    latest: OutcomeJournalRecord | None,
    corruption: JournalCorruption | None,
) -> tuple[str, str]:
    if corruption is not None:
        return "unknown", f"journal_{corruption.kind}"
    if latest is None:
        return "unknown", "no_evidence"

    evidence = latest.evidence
    if evidence.effect_state == "completed":
        return "succeeded", evidence.reason
    if evidence.effect_state == "unknown":
        return "unknown", evidence.reason
    if evidence.reason == "policy_blocked":
        return "blocked", evidence.reason
    if evidence.reason == "cancelled":
        return "cancelled", evidence.reason
    return "not_dispatched", evidence.reason

def _validate_record(record: OutcomeJournalRecord) -> None:
    if record.transition not in _TRANSITIONS:
        raise OutcomeJournalIntegrityError(
            f"unsupported transition: {record.transition!r}"
        )
    if record.evidence.request_id != record.request_id:
        raise OutcomeJournalIntegrityError("record/evidence request_id mismatch")
    if record.evidence.action != record.action:
        raise OutcomeJournalIntegrityError("record/evidence action mismatch")
    if record.transition == "dispatch_started":
        if (
            record.evidence.effect_state != "unknown"
            or not record.evidence.dispatch_started
            or record.evidence.reason != "dispatch_started"
        ):
            raise OutcomeJournalIntegrityError(
                "dispatch_started record requires provisional unknown evidence"
            )
    elif record.evidence.reason == "dispatch_started":
        raise OutcomeJournalIntegrityError(
            "terminal record cannot carry dispatch_started reason"
        )


def _mapping(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise OutcomeJournalIntegrityError(f"{where} must be an object")
    return value


def _exact_keys(value: Mapping[str, Any], expected: set[str], where: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise OutcomeJournalIntegrityError(
            f"{where} keys mismatch; missing={missing}, extra={extra}"
        )


def _string(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise OutcomeJournalIntegrityError(f"{where} must be a non-empty string")
    return value


def _positive_int(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise OutcomeJournalIntegrityError(f"{where} must be a positive integer")
    return value


def _digest(value: Any, where: str) -> str:
    value = _string(value, where)
    if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise OutcomeJournalIntegrityError(f"{where} must be lowercase sha256 hex")
    return value


def _optional_digest(value: Any, where: str) -> str | None:
    if value is None:
        return None
    return _digest(value, where)
