from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from pc_executor.executor import Executor
from pc_executor.models import ActionRequest
from pc_executor.outcome import ActionOutcomeEvidence
from pc_executor.outcome_journal import (
    ExecutionCorrelation,
    OutcomeJournal,
    OutcomeJournalConflictError,
    OutcomeJournalIntegrityError,
    canonical_journal_bytes,
    canonical_journal_sha256,
)
from tools.outcome_journal_chaos import (
    DEFAULT_RECORD_COUNT,
    SEED,
    MemoryFaultStorage,
    build_large_journal,
    build_report,
    exercise_fault_matrix,
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
        observed_at="2026-09-27T10:00:00.000Z",
    )


def test_seeded_10002_record_reopen_stress_and_machine_report(tmp_path):
    report = build_report(
        tmp_path / "work",
        Path(__file__).parent / "fixtures",
        record_count=DEFAULT_RECORD_COUNT,
        reopen_count=12,
    )

    assert report["seed"] == SEED
    assert report["journal"]["record_count"] == 10_002
    assert report["journal"]["request_count"] == 3_334
    assert report["journal"]["raw_sha256"] == report["journal"]["canonical_sha256"]
    assert report["faults"]["dispatch_partial_unknown"] == 6
    assert report["faults"]["terminal_partial_unknown"] == 6
    assert report["performance"]["lookup_read_only"] is True
    assert (
        report["performance"]["first_lookup_ms"]
        < report["performance"]["first_lookup_bound_ms"]
    )
    assert (
        report["performance"]["reopen_total_ms"]
        < report["performance"]["reopen_total_bound_ms"]
    )

    report2 = build_report(
        tmp_path / "work2",
        Path(__file__).parent / "fixtures",
        record_count=DEFAULT_RECORD_COUNT,
        reopen_count=1,
    )
    assert report2["stable_report_sha256"] == report["stable_report_sha256"]
    assert report2["journal"]["raw_sha256"] == report["journal"]["raw_sha256"]


def test_fault_matrix_never_upgrades_partial_unknown_to_completed():
    faults = exercise_fault_matrix()
    assert faults == {
        "dispatch_partial_boundary_cases": 6,
        "dispatch_partial_unknown": 6,
        "terminal_partial_boundary_cases": 6,
        "terminal_partial_unknown": 6,
        "disk_full_cases": 1,
        "crash_between_write_and_flush_cases": 1,
        "idempotent_duplicate_terminal_cases": 1,
        "raw_duplicate_terminal_corruption_cases": 1,
        "request_action_conflict_cases": 1,
        "reordered_append_cases": 1,
        "truncated_tail_cases": 1,
    }


def test_crash_after_complete_write_before_flush_recovers_only_written_evidence():
    storage = MemoryFaultStorage()
    storage.fail_after_write = True
    journal = OutcomeJournal("memory-crash-boundary", storage=storage)

    with pytest.raises(OutcomeJournalIntegrityError):
        journal.start_dispatch(
            _evidence(
                "crash-boundary",
                "keyboard.press",
                "unknown",
                dispatched=True,
                reason="dispatch_started",
            )
        )

    lookup = journal.lookup(
        request_id="crash-boundary",
        action="keyboard.press",
    ).to_dict()
    assert lookup["outcome"] == "unknown"
    assert lookup["latest_valid_evidence"]["effect_state"] == "unknown"
    assert lookup["replay_authorized"] is False


def test_disk_full_before_write_leaves_no_false_evidence():
    storage = MemoryFaultStorage()
    storage.disk_full = True
    journal = OutcomeJournal("memory-disk-full-test", storage=storage)
    with pytest.raises(OutcomeJournalIntegrityError):
        journal.start_dispatch(
            _evidence(
                "disk-full-test",
                "keyboard.press",
                "unknown",
                dispatched=True,
                reason="dispatch_started",
            )
        )

    assert storage.read_bytes() == b""
    lookup = journal.lookup(
        request_id="disk-full-test",
        action="keyboard.press",
    ).to_dict()
    assert lookup["outcome"] == "unknown"
    assert lookup["latest_valid_evidence"] is None


def test_duplicate_terminal_is_idempotent_but_conflict_and_reorder_fail_closed(tmp_path):
    path = tmp_path / "duplicates.jsonl"
    journal = OutcomeJournal(path)
    provisional = _evidence(
        "dup",
        "keyboard.press",
        "unknown",
        dispatched=True,
        reason="dispatch_started",
    )
    correlation = journal.start_dispatch(provisional)
    terminal = _evidence(
        "dup",
        "keyboard.press",
        "completed",
        dispatched=True,
        reason="completed",
    )
    first = journal.append_terminal(terminal, correlation=correlation)
    before = path.read_bytes()
    second = journal.append_terminal(terminal, correlation=correlation)
    assert second.record_sha256 == first.record_sha256
    assert path.read_bytes() == before

    conflicting = _evidence(
        "dup",
        "keyboard.press",
        "unknown",
        dispatched=True,
        reason="timeout",
    )
    with pytest.raises(OutcomeJournalConflictError):
        journal.append_terminal(conflicting, correlation=correlation)

    fabricated = ExecutionCorrelation(
        execution_id="exec:" + "0" * 64,
        execution_attempt=99,
    )
    with pytest.raises(OutcomeJournalConflictError):
        OutcomeJournal(tmp_path / "reordered.jsonl").append_terminal(
            _evidence(
                "reordered",
                "keyboard.press",
                "completed",
                dispatched=True,
                reason="completed",
            ),
            correlation=fabricated,
        )


def test_conflicting_request_action_reuse_fails_closed(tmp_path):
    journal = OutcomeJournal(tmp_path / "identity.jsonl")
    journal.append_terminal(
        _evidence(
            "same-id",
            "keyboard.press",
            "not_started",
            dispatched=False,
            reason="dry_run",
        )
    )
    with pytest.raises(OutcomeJournalConflictError):
        journal.append_terminal(
            _evidence(
                "same-id",
                "mouse.click",
                "not_started",
                dispatched=False,
                reason="dry_run",
            )
        )


def test_lf_crlf_policy_and_canonical_hash_are_cross_platform(tmp_path):
    fixture = (
        Path(__file__).parent
        / "fixtures"
        / "outcome_journal_v1"
        / "completed.jsonl"
    )
    raw_lf = fixture.read_bytes()
    assert b"\r\n" not in raw_lf
    raw_crlf = raw_lf.replace(b"\n", b"\r\n")
    assert hashlib.sha256(raw_lf).hexdigest() != hashlib.sha256(raw_crlf).hexdigest()
    assert canonical_journal_bytes(raw_crlf) == raw_lf
    assert canonical_journal_sha256(raw_crlf) == canonical_journal_sha256(raw_lf)

    crlf_path = tmp_path / "completed-crlf.jsonl"
    crlf_path.write_bytes(raw_crlf)
    lookup = OutcomeJournal(crlf_path).lookup(
        request_id="fixture-completed",
        action="keyboard.press",
        execution_attempt=1,
    ).to_dict()
    assert lookup["outcome"] == "succeeded"
    assert fixture.read_bytes() == raw_lf

    with pytest.raises(OutcomeJournalIntegrityError):
        canonical_journal_bytes(b"{}\r")


def test_frozen_action_outcome_v1_bytes_remain_exact():
    fixtures = Path(__file__).parent / "fixtures"
    expected = {
        "action_outcome_v1_not_started.json":
            "06278df0fd016093d67420f9e33b0504d7f72bc5da8ecbece063c649d9d2c913",
        "action_outcome_v1.json":
            "e73488314215a43768710247ee199aa878442d93f20025e35da567bb20757f10",
        "action_outcome_v1_unknown.json":
            "c4585b7b2ccd0788ee4d22be2dfee8f43c28e2f46555bbe731157b272d321951",
    }
    for name, digest in expected.items():
        assert hashlib.sha256((fixtures / name).read_bytes()).hexdigest() == digest


def test_process_local_concurrent_writers_serialize_without_corruption(tmp_path):
    path = tmp_path / "concurrent.jsonl"

    def append(index: int) -> None:
        OutcomeJournal(path).append_terminal(
            _evidence(
                f"thread-{index:04d}",
                "keyboard.press",
                "not_started",
                dispatched=False,
                reason="dry_run",
            )
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(append, range(256)))

    lookup = OutcomeJournal(path).lookup(
        request_id="thread-0255",
        action="keyboard.press",
    ).to_dict()
    assert lookup["provenance"]["integrity"] == "clean"
    assert lookup["provenance"]["total_valid_records"] == 256
    assert lookup["outcome"] == "not_dispatched"
    assert len(path.read_bytes().splitlines()) == 256


class _BombAdapter:
    def __getattr__(self, name):
        raise AssertionError(f"recovery must not call adapter method {name}")


def test_large_journal_recovery_is_read_only_and_never_calls_side_effect_adapters(tmp_path):
    path = tmp_path / "large.jsonl"
    metadata = build_large_journal(path)
    before = path.read_bytes()
    before_hash = hashlib.sha256(before).hexdigest()
    index = metadata["request_count"] - 1
    request_id = f"chaos-{index:06d}"
    action = tuple(sorted({
        "vision.target.invoke", "uia.invoke", "uia.focus", "uia.set_value",
        "mouse.click", "keyboard.press", "keyboard.type_text", "clipboard.set",
        "shell.run",
    }))[index % 9]

    executor = Executor(
        input_adapter=_BombAdapter(),
        accessibility=_BombAdapter(),
        shell=_BombAdapter(),
        outcome_journal=OutcomeJournal(path),
        dry_run=False,
    )
    result = executor.execute(
        ActionRequest(
            "outcome.lookup",
            {
                "request_id": request_id,
                "action": action,
                "execution_attempt": 2,
            },
            request_id="recovery-query",
        )
    )

    assert result.ok is True
    assert result.data["outcome_evidence"]["outcome"] == "succeeded"
    after = path.read_bytes()
    assert after == before
    assert hashlib.sha256(after).hexdigest() == before_hash
    assert b"SENSITIVE-TEXT-DO-NOT-PERSIST" not in after
