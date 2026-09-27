from __future__ import annotations

import argparse
import hashlib
import json
import platform
import time
from pathlib import Path
from typing import Any

from pc_executor.outcome import ActionOutcomeEvidence, SIDE_EFFECTING_ACTIONS
from pc_executor.outcome_journal import (
    ExecutionCorrelation,
    OutcomeJournal,
    OutcomeJournalConflictError,
    OutcomeJournalIntegrityError,
    OutcomeJournalRecord,
    canonical_journal_sha256,
)

REPORT_SCHEMA = "pc_executor.outcome_journal.reliability_report.v1"
SEED = 0x5A17C0DE
DEFAULT_RECORD_COUNT = 10_002
DEFAULT_REOPEN_COUNT = 12
ACTIONS = tuple(sorted(SIDE_EFFECTING_ACTIONS))
OBSERVED_AT = "2026-09-27T10:00:00.000Z"
RECORDED_AT = "2026-09-27T10:00:00.000Z"


def _json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _correlation(request_id: str, action: str, attempt: int) -> ExecutionCorrelation:
    digest = hashlib.sha256(
        f"{request_id}\0{action}\0{attempt}".encode("utf-8")
    ).hexdigest()
    return ExecutionCorrelation(
        execution_id=f"exec:{digest}",
        execution_attempt=attempt,
    )


def _evidence(
    request_id: str,
    action: str,
    state: str,
    *,
    dispatched: bool,
    reason: str,
) -> ActionOutcomeEvidence:
    return ActionOutcomeEvidence.create(
        request_id=request_id,
        action=action,
        effect_state=state,
        dispatch_started=dispatched,
        reason=reason,
        observed_at=OBSERVED_AT,
    )


def build_large_journal(path: Path, record_count: int = DEFAULT_RECORD_COUNT) -> dict[str, Any]:
    if record_count < 10_000 or record_count % 3:
        raise ValueError("record_count must be >=10000 and divisible by 3")

    previous: str | None = None
    payloads: list[bytes] = []
    sequence = 0
    request_count = record_count // 3

    for request_index in range(request_count):
        request_id = f"chaos-{request_index:06d}"
        action = ACTIONS[request_index % len(ACTIONS)]
        attempt1 = _correlation(request_id, action, 1)
        attempt2 = _correlation(request_id, action, 2)
        specs = (
            ("terminal", attempt1, _evidence(
                request_id, action, "not_started", dispatched=False, reason="dry_run"
            )),
            ("dispatch_started", attempt2, _evidence(
                request_id, action, "unknown", dispatched=True, reason="dispatch_started"
            )),
            ("terminal", attempt2, _evidence(
                request_id, action, "completed", dispatched=True, reason="completed"
            )),
        )
        for transition, correlation, evidence in specs:
            sequence += 1
            record = OutcomeJournalRecord.create(
                journal_sequence=sequence,
                request_id=request_id,
                action=action,
                correlation=correlation,
                transition=transition,
                evidence=evidence,
                previous_record_sha256=previous,
                recorded_at=RECORDED_AT,
            )
            previous = record.record_sha256
            payloads.append(_json_bytes(record.to_dict()) + b"\n")

    raw = b"".join(payloads)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return {
        "record_count": record_count,
        "request_count": request_count,
        "bytes": len(raw),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "canonical_sha256": canonical_journal_sha256(raw),
        "last_record_sha256": previous,
    }


class MemoryFaultStorage:
    def __init__(self, raw: bytes = b"") -> None:
        self.raw = bytearray(raw)
        self.cut: int | None = None
        self.disk_full = False
        self.fail_after_write = False
        self.read_count = 0
        self.append_count = 0

    def read_bytes(self) -> bytes:
        self.read_count += 1
        return bytes(self.raw)

    def append_durable(self, payload: bytes) -> None:
        self.append_count += 1
        if self.disk_full:
            raise OSError(28, "simulated disk full")
        if self.cut is not None:
            cut = max(0, min(self.cut, len(payload)))
            self.raw.extend(payload[:cut])
            if cut != len(payload):
                raise OSError(5, f"simulated partial write at {cut}")
        else:
            self.raw.extend(payload)
        if self.fail_after_write:
            raise OSError(5, "simulated crash before durable flush")


def _boundary_classes(length: int) -> dict[str, int]:
    return {
        "zero": 0,
        "first_byte": 1,
        "first_quarter": max(2, length // 4),
        "half": max(2, length // 2),
        "penultimate": max(2, length - 2),
        "before_lf": max(2, length - 1),
    }


def exercise_fault_matrix() -> dict[str, Any]:
    request_id = "fault-dispatch"
    action = "keyboard.press"
    template = MemoryFaultStorage()
    OutcomeJournal("memory-template-dispatch", storage=template).start_dispatch(
        _evidence(
            request_id,
            action,
            "unknown",
            dispatched=True,
            reason="dispatch_started",
        )
    )
    dispatch_payload = bytes(template.raw)
    dispatch_cases = _boundary_classes(len(dispatch_payload))

    dispatch_unknown = 0
    for name, cut in dispatch_cases.items():
        storage = MemoryFaultStorage()
        storage.cut = cut
        journal = OutcomeJournal(f"memory-dispatch-{name}", storage=storage)
        try:
            journal.start_dispatch(
                _evidence(
                    request_id,
                    action,
                    "unknown",
                    dispatched=True,
                    reason="dispatch_started",
                )
            )
        except OutcomeJournalIntegrityError:
            pass
        else:
            raise AssertionError(f"partial dispatch {name} unexpectedly succeeded")
        lookup = journal.lookup(request_id=request_id, action=action).to_dict()
        if lookup["outcome"] != "unknown":
            raise AssertionError(f"partial dispatch {name} upgraded outcome")
        dispatch_unknown += 1

    base = MemoryFaultStorage()
    base_journal = OutcomeJournal("memory-terminal-template", storage=base)
    correlation = base_journal.start_dispatch(
        _evidence(
            "fault-terminal",
            action,
            "unknown",
            dispatched=True,
            reason="dispatch_started",
        )
    )
    provisional_raw = bytes(base.raw)
    base_journal.append_terminal(
        _evidence(
            "fault-terminal",
            action,
            "completed",
            dispatched=True,
            reason="completed",
        ),
        correlation=correlation,
    )
    terminal_payload = bytes(base.raw)[len(provisional_raw):]
    terminal_cases = _boundary_classes(len(terminal_payload))

    terminal_unknown = 0
    for name, cut in terminal_cases.items():
        storage = MemoryFaultStorage(provisional_raw)
        storage.cut = cut
        journal = OutcomeJournal(f"memory-terminal-{name}", storage=storage)
        try:
            journal.append_terminal(
                _evidence(
                    "fault-terminal",
                    action,
                    "completed",
                    dispatched=True,
                    reason="completed",
                ),
                correlation=correlation,
            )
        except OutcomeJournalIntegrityError:
            pass
        else:
            raise AssertionError(f"partial terminal {name} unexpectedly succeeded")
        lookup = journal.lookup(
            request_id="fault-terminal",
            action=action,
        ).to_dict()
        if lookup["outcome"] != "unknown":
            raise AssertionError(f"partial terminal {name} upgraded unknown")
        terminal_unknown += 1

    disk_full = MemoryFaultStorage()
    disk_full.disk_full = True
    try:
        OutcomeJournal("memory-disk-full", storage=disk_full).start_dispatch(
            _evidence(
                "disk-full",
                action,
                "unknown",
                dispatched=True,
                reason="dispatch_started",
            )
        )
    except OutcomeJournalIntegrityError:
        pass
    else:
        raise AssertionError("disk-full append unexpectedly succeeded")

    crash_storage = MemoryFaultStorage()
    crash_storage.fail_after_write = True
    crash_journal = OutcomeJournal("memory-crash-after-write", storage=crash_storage)
    try:
        crash_journal.start_dispatch(
            _evidence(
                "crash-after-write",
                action,
                "unknown",
                dispatched=True,
                reason="dispatch_started",
            )
        )
    except OutcomeJournalIntegrityError:
        pass
    else:
        raise AssertionError("crash-after-write unexpectedly returned success")
    crash_lookup = crash_journal.lookup(
        request_id="crash-after-write",
        action=action,
    ).to_dict()
    if crash_lookup["outcome"] != "unknown":
        raise AssertionError("crash-after-write did not remain unknown")

    duplicate_storage = MemoryFaultStorage()
    duplicate_journal = OutcomeJournal("memory-duplicate", storage=duplicate_storage)
    duplicate_correlation = duplicate_journal.start_dispatch(
        _evidence("duplicate", action, "unknown", dispatched=True, reason="dispatch_started")
    )
    duplicate_terminal = _evidence(
        "duplicate", action, "completed", dispatched=True, reason="completed"
    )
    duplicate_journal.append_terminal(
        duplicate_terminal,
        correlation=duplicate_correlation,
    )
    duplicate_size = len(duplicate_storage.raw)
    duplicate_journal.append_terminal(
        duplicate_terminal,
        correlation=duplicate_correlation,
    )
    if len(duplicate_storage.raw) != duplicate_size:
        raise AssertionError("idempotent terminal duplicate appended bytes")

    duplicate_lines = bytes(duplicate_storage.raw).splitlines(keepends=True)
    duplicate_storage.raw.extend(duplicate_lines[-1])
    duplicate_lookup = duplicate_journal.lookup(
        request_id="duplicate",
        action=action,
    ).to_dict()
    if duplicate_lookup["outcome"] != "unknown":
        raise AssertionError("raw duplicate terminal record did not fail closed")

    identity_storage = MemoryFaultStorage()
    identity_journal = OutcomeJournal("memory-identity", storage=identity_storage)
    identity_journal.append_terminal(
        _evidence("identity", action, "not_started", dispatched=False, reason="dry_run")
    )
    try:
        identity_journal.append_terminal(
            _evidence("identity", "mouse.click", "not_started", dispatched=False, reason="dry_run")
        )
    except OutcomeJournalConflictError:
        pass
    else:
        raise AssertionError("request/action identity conflict unexpectedly succeeded")

    try:
        OutcomeJournal("memory-reordered", storage=MemoryFaultStorage()).append_terminal(
            _evidence("reordered", action, "completed", dispatched=True, reason="completed"),
            correlation=ExecutionCorrelation("exec:" + "0" * 64, 99),
        )
    except OutcomeJournalConflictError:
        pass
    else:
        raise AssertionError("terminal-before-dispatch unexpectedly succeeded")

    truncated_storage = MemoryFaultStorage(provisional_raw[:-1])
    truncated_lookup = OutcomeJournal(
        "memory-truncated", storage=truncated_storage
    ).lookup(request_id="fault-terminal", action=action).to_dict()
    if truncated_lookup["outcome"] != "unknown":
        raise AssertionError("truncated tail did not fail closed")

    return {
        "dispatch_partial_boundary_cases": len(dispatch_cases),
        "dispatch_partial_unknown": dispatch_unknown,
        "terminal_partial_boundary_cases": len(terminal_cases),
        "terminal_partial_unknown": terminal_unknown,
        "disk_full_cases": 1,
        "crash_between_write_and_flush_cases": 1,
        "idempotent_duplicate_terminal_cases": 1,
        "raw_duplicate_terminal_corruption_cases": 1,
        "request_action_conflict_cases": 1,
        "reordered_append_cases": 1,
        "truncated_tail_cases": 1,
    }


def benchmark_recovery(
    path: Path,
    *,
    request_count: int,
    reopen_count: int = DEFAULT_REOPEN_COUNT,
) -> dict[str, Any]:
    before = path.read_bytes()
    before_sha = hashlib.sha256(before).hexdigest()

    target_index = request_count - 1
    target_id = f"chaos-{target_index:06d}"
    target_action = ACTIONS[target_index % len(ACTIONS)]

    started = time.perf_counter()
    first = OutcomeJournal(path).lookup(
        request_id=target_id,
        action=target_action,
        execution_attempt=2,
    ).to_dict()
    first_lookup_ms = (time.perf_counter() - started) * 1000.0
    if first["outcome"] != "succeeded":
        raise AssertionError("large-journal terminal evidence was not recovered")

    started = time.perf_counter()
    for reopen_index in range(reopen_count):
        index = (reopen_index * 271) % request_count
        request_id = f"chaos-{index:06d}"
        action = ACTIONS[index % len(ACTIONS)]
        lookup = OutcomeJournal(path).lookup(
            request_id=request_id,
            action=action,
        ).to_dict()
        if lookup["outcome"] != "succeeded":
            raise AssertionError(f"reopen recovery failed for {request_id}")
    reopen_total_ms = (time.perf_counter() - started) * 1000.0

    after = path.read_bytes()
    after_sha = hashlib.sha256(after).hexdigest()
    if after_sha != before_sha or after != before:
        raise AssertionError("lookup/recovery mutated journal bytes")

    return {
        "first_lookup_ms": round(first_lookup_ms, 3),
        "reopen_count": reopen_count,
        "reopen_total_ms": round(reopen_total_ms, 3),
        "first_lookup_bound_ms": 15_000,
        "reopen_total_bound_ms": 60_000,
        "lookup_read_only": True,
    }


def frozen_outcome_hashes(fixtures_root: Path) -> dict[str, str]:
    names = (
        "action_outcome_v1.json",
        "action_outcome_v1_not_started.json",
        "action_outcome_v1_unknown.json",
    )
    return {
        name: hashlib.sha256((fixtures_root / name).read_bytes()).hexdigest()
        for name in names
    }


def build_report(
    work_dir: Path,
    fixtures_root: Path,
    *,
    record_count: int = DEFAULT_RECORD_COUNT,
    reopen_count: int = DEFAULT_REOPEN_COUNT,
) -> dict[str, Any]:
    journal_path = work_dir / "outcome-journal-chaos-10002.jsonl"
    journal = build_large_journal(journal_path, record_count)
    faults = exercise_fault_matrix()
    performance = benchmark_recovery(
        journal_path,
        request_count=journal["request_count"],
        reopen_count=reopen_count,
    )
    stable = {
        "schema": REPORT_SCHEMA,
        "seed": SEED,
        "journal": journal,
        "faults": faults,
        "frozen_action_outcome_sha256": frozen_outcome_hashes(fixtures_root),
    }
    stable_sha = hashlib.sha256(_json_bytes(stable)).hexdigest()
    return {
        **stable,
        "stable_report_sha256": stable_sha,
        "performance": performance,
        "runtime": {
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--fixtures-root", type=Path, default=Path("tests/fixtures"))
    parser.add_argument("--records", type=int, default=DEFAULT_RECORD_COUNT)
    parser.add_argument("--reopens", type=int, default=DEFAULT_REOPEN_COUNT)
    args = parser.parse_args()

    report = build_report(
        args.work_dir,
        args.fixtures_root,
        record_count=args.records,
        reopen_count=args.reopens,
    )
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
