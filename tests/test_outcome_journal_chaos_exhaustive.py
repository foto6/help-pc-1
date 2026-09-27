from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from pc_executor.outcome import ActionOutcomeEvidence
from pc_executor.outcome_journal import (
    OutcomeJournal,
    OutcomeJournalIntegrityError,
)
from tools.outcome_journal_chaos import (
    ACTIONS,
    DEFAULT_RECORD_COUNT,
    MemoryFaultStorage,
    build_large_journal,
)


def _provisional(request_id: str) -> ActionOutcomeEvidence:
    return ActionOutcomeEvidence.create(
        request_id=request_id,
        action="keyboard.press",
        effect_state="unknown",
        dispatch_started=True,
        reason="dispatch_started",
        observed_at="2026-09-27T10:00:00.000Z",
    )


def _completed(request_id: str) -> ActionOutcomeEvidence:
    return ActionOutcomeEvidence.create(
        request_id=request_id,
        action="keyboard.press",
        effect_state="completed",
        dispatch_started=True,
        reason="completed",
        observed_at="2026-09-27T10:00:01.000Z",
    )


def test_every_dispatch_partial_byte_offset_fails_closed():
    template = MemoryFaultStorage()
    OutcomeJournal("memory-exhaustive-dispatch-template", storage=template).start_dispatch(
        _provisional("byte-cut")
    )
    payload = bytes(template.raw)
    assert len(payload) > 100

    for cut in range(len(payload)):
        storage = MemoryFaultStorage()
        storage.cut = cut
        journal = OutcomeJournal(
            f"memory-exhaustive-dispatch-{cut}",
            storage=storage,
        )
        with pytest.raises(OutcomeJournalIntegrityError):
            journal.start_dispatch(_provisional("byte-cut"))

        lookup = journal.lookup(
            request_id="byte-cut",
            action="keyboard.press",
        ).to_dict()
        assert lookup["outcome"] == "unknown", f"cut={cut}"
        assert lookup["replay_authorized"] is False, f"cut={cut}"
        latest = lookup["latest_valid_evidence"]
        assert latest is None or latest["effect_state"] != "completed", f"cut={cut}"


def test_every_terminal_partial_byte_offset_preserves_provisional_unknown():
    prefix_storage = MemoryFaultStorage()
    prefix_journal = OutcomeJournal(
        "memory-exhaustive-terminal-prefix",
        storage=prefix_storage,
    )
    correlation = prefix_journal.start_dispatch(_provisional("terminal-byte-cut"))
    prefix = bytes(prefix_storage.raw)

    complete_storage = MemoryFaultStorage(prefix)
    OutcomeJournal(
        "memory-exhaustive-terminal-template",
        storage=complete_storage,
    ).append_terminal(
        _completed("terminal-byte-cut"),
        correlation=correlation,
    )
    terminal_payload = bytes(complete_storage.raw)[len(prefix):]
    assert len(terminal_payload) > 100

    for cut in range(len(terminal_payload)):
        storage = MemoryFaultStorage(prefix)
        storage.cut = cut
        journal = OutcomeJournal(
            f"memory-exhaustive-terminal-{cut}",
            storage=storage,
        )
        with pytest.raises(OutcomeJournalIntegrityError):
            journal.append_terminal(
                _completed("terminal-byte-cut"),
                correlation=correlation,
            )

        lookup = journal.lookup(
            request_id="terminal-byte-cut",
            action="keyboard.press",
        ).to_dict()
        assert lookup["outcome"] == "unknown", f"cut={cut}"
        assert lookup["latest_valid_evidence"]["effect_state"] == "unknown", f"cut={cut}"
        assert lookup["replay_authorized"] is False, f"cut={cut}"


def test_large_journal_recovers_across_fresh_executor_processes(tmp_path):
    path = tmp_path / "fresh-process-recovery.jsonl"
    stats = build_large_journal(path, DEFAULT_RECORD_COUNT)
    before = path.read_bytes()
    before_sha = hashlib.sha256(before).hexdigest()

    request_count = stats["request_count"]
    indices = (0, request_count // 3, (request_count * 2) // 3, request_count - 1)
    timings: list[float] = []

    for index in indices:
        request_id = f"chaos-{index:06d}"
        action = ACTIONS[index % len(ACTIONS)]
        request = {
            "request_id": f"recovery-probe-{index}",
            "action": "outcome.lookup",
            "params": {
                "request_id": request_id,
                "action": action,
                "execution_attempt": 2,
            },
        }
        started = time.perf_counter()
        process = subprocess.run(
            [
                sys.executable,
                "-m",
                "pc_executor",
                "--outcome-journal",
                str(path),
            ],
            input=json.dumps(request) + "\n",
            text=True,
            capture_output=True,
            check=False,
        )
        timings.append(time.perf_counter() - started)

        assert process.returncode == 0, process.stderr
        response = json.loads(process.stdout.strip())
        evidence = response["data"]["outcome_evidence"]
        assert evidence["outcome"] == "succeeded"
        assert evidence["replay_authorized"] is False
        assert evidence["provenance"]["integrity"] == "clean"

    after = path.read_bytes()
    assert after == before
    assert hashlib.sha256(after).hexdigest() == before_sha
    assert max(timings) < 15.0
    assert sum(timings) < 60.0
