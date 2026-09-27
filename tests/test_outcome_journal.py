from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from pc_executor.executor import Executor
from pc_executor.fakes import ReplayInputAdapter, ReplayShellAdapter, ReplayUIAAdapter
from pc_executor.models import ActionRequest, ElementInfo
from pc_executor.outcome import ActionOutcomeEvidence
from pc_executor.outcome_journal import (
    OutcomeJournal,
    OutcomeJournalConflictError,
    OutcomeJournalIntegrityError,
    OutcomeJournalReplayUnsafeError,
)
from pc_executor.shell import ShellResult


def provisional(request_id: str, action: str) -> ActionOutcomeEvidence:
    return ActionOutcomeEvidence.create(
        request_id=request_id,
        action=action,
        effect_state="unknown",
        dispatch_started=True,
        reason="dispatch_started",
        observed_at="2026-09-27T09:00:00.000Z",
    )


def completed(request_id: str, action: str) -> ActionOutcomeEvidence:
    return ActionOutcomeEvidence.create(
        request_id=request_id,
        action=action,
        effect_state="completed",
        dispatch_started=True,
        reason="completed",
        observed_at="2026-09-27T09:00:01.000Z",
    )


def not_started(request_id: str, action: str, *, reason: str = "dry_run") -> ActionOutcomeEvidence:
    return ActionOutcomeEvidence.create(
        request_id=request_id,
        action=action,
        effect_state="not_started",
        dispatch_started=False,
        reason=reason,
        observed_at="2026-09-27T09:00:01.000Z",
    )


def actionable(*, automation_id: str = "save", value: bool = False) -> ElementInfo:
    return ElementInfo(
        name="Save",
        automation_id=automation_id,
        control_type="EditControl" if value else "ButtonControl",
        is_enabled=True,
        is_password=False,
        native_handle=7,
        process_id=70,
        supports_invoke=not value,
        supports_value=value,
    )


def test_live_side_effect_persists_provisional_then_terminal(tmp_path):
    path = tmp_path / "outcomes.jsonl"
    journal = OutcomeJournal(path)
    raw_input = ReplayInputAdapter()
    executor = Executor(
        input_adapter=raw_input,
        outcome_journal=journal,
        dry_run=False,
    )

    result = executor.execute(
        ActionRequest("keyboard.press", {"key": "enter"}, request_id="req-1")
    )

    assert result.ok is True
    assert raw_input.events == [("press", "enter")]
    lookup = journal.lookup(request_id="req-1", action="keyboard.press").to_dict()
    assert lookup["outcome"] == "succeeded"
    assert lookup["replay_authorized"] is False
    assert [entry["transition"] for entry in lookup["history"]] == [
        "dispatch_started",
        "terminal",
    ]
    assert lookup["history"][0]["evidence"]["effect_state"] == "unknown"
    assert lookup["history"][1]["evidence"]["effect_state"] == "completed"
    assert lookup["history"][0]["execution_id"] == lookup["history"][1]["execution_id"]
    assert lookup["history"][0]["execution_attempt"] == 1
    assert lookup["provenance"]["integrity"] == "clean"

class CrashAfterProvisionalJournal(OutcomeJournal):
    def start_dispatch(self, evidence):
        super().start_dispatch(evidence)
        raise SystemExit("simulated crash after provisional fsync")


def test_crash_after_provisional_fsync_before_adapter_call_is_recoverable_unknown(tmp_path):
    path = tmp_path / "crash-before-adapter.jsonl"
    journal = CrashAfterProvisionalJournal(path)
    raw_input = ReplayInputAdapter()
    executor = Executor(
        input_adapter=raw_input,
        outcome_journal=journal,
        dry_run=False,
    )

    with pytest.raises(SystemExit):
        executor.execute(
            ActionRequest("keyboard.press", {"key": "enter"}, request_id="req-crash-a")
        )

    assert raw_input.events == []
    restarted = OutcomeJournal(path)
    lookup = restarted.lookup(
        request_id="req-crash-a",
        action="keyboard.press",
    ).to_dict()
    assert lookup["outcome"] == "unknown"
    assert lookup["reason"] == "dispatch_started"
    assert lookup["latest_valid_evidence"]["reexecution_safe"] is False
    assert lookup["latest_valid_evidence"]["reconciliation_required"] is True
    assert len(lookup["history"]) == 1
    assert path.read_bytes().endswith(b"\n")


class CrashBeforeTerminalJournal(OutcomeJournal):
    def append_terminal(self, evidence, *, correlation=None):
        if evidence.effect_state == "completed":
            raise SystemExit("simulated crash after adapter effect before terminal fsync")
        return super().append_terminal(evidence, correlation=correlation)


def test_crash_after_adapter_effect_before_terminal_write_stays_unknown(tmp_path):
    path = tmp_path / "crash-after-effect.jsonl"
    journal = CrashBeforeTerminalJournal(path)
    raw_input = ReplayInputAdapter()
    executor = Executor(
        input_adapter=raw_input,
        outcome_journal=journal,
        dry_run=False,
    )

    with pytest.raises(SystemExit):
        executor.execute(
            ActionRequest("keyboard.press", {"key": "enter"}, request_id="req-crash-b")
        )

    assert raw_input.events == [("press", "enter")]
    lookup = OutcomeJournal(path).lookup(
        request_id="req-crash-b",
        action="keyboard.press",
    ).to_dict()
    assert lookup["outcome"] == "unknown"
    assert lookup["latest_valid_evidence"]["effect_state"] == "unknown"
    assert lookup["replay_authorized"] is False
    with pytest.raises(OutcomeJournalReplayUnsafeError):
        OutcomeJournal(path).preflight_new_attempt(
            request_id="req-crash-b",
            action="keyboard.press",
        )

@pytest.mark.parametrize(
    ("tail", "expected_kind"),
    [
        (b'{"contract_version":"pc_executor.outcome_journal.record.v1"', "truncated_tail"),
        (b'not-json\n', "malformed_tail"),
    ],
)
def test_corrupt_tail_is_explicit_and_forces_unknown_even_after_completed(
    tmp_path, tail, expected_kind
):
    path = tmp_path / "corrupt-tail.jsonl"
    journal = OutcomeJournal(path)
    correlation = journal.start_dispatch(provisional("req-tail", "keyboard.press"))
    journal.append_terminal(
        completed("req-tail", "keyboard.press"),
        correlation=correlation,
    )

    with path.open("ab") as handle:
        handle.write(tail)
        handle.flush()
        os.fsync(handle.fileno())

    lookup = OutcomeJournal(path).lookup(
        request_id="req-tail",
        action="keyboard.press",
    ).to_dict()
    assert lookup["outcome"] == "unknown"
    assert lookup["latest_valid_evidence"]["effect_state"] == "completed"
    assert lookup["provenance"]["integrity"] == "corrupt"
    assert lookup["provenance"]["corruption"]["kind"] == expected_kind
    assert lookup["reason"] == f"journal_{expected_kind}"
    assert lookup["replay_authorized"] is False

    with pytest.raises(OutcomeJournalIntegrityError):
        OutcomeJournal(path).preflight_new_attempt(
            request_id="req-tail",
            action="keyboard.press",
        )


def test_duplicate_terminal_append_is_idempotent(tmp_path):
    path = tmp_path / "duplicate.jsonl"
    journal = OutcomeJournal(path)
    correlation = journal.start_dispatch(provisional("req-dup", "keyboard.press"))
    evidence = completed("req-dup", "keyboard.press")

    first = journal.append_terminal(evidence, correlation=correlation)
    second = journal.append_terminal(evidence, correlation=correlation)

    assert first.record_sha256 == second.record_sha256
    lookup = journal.lookup(request_id="req-dup", action="keyboard.press").to_dict()
    assert len(lookup["history"]) == 2
    assert path.read_bytes().count(b"\n") == 2


def test_conflicting_request_action_reuse_blocks_before_side_effect(tmp_path):
    path = tmp_path / "conflict.jsonl"
    journal = OutcomeJournal(path)
    journal.append_terminal(not_started("same-id", "keyboard.press"))

    with pytest.raises(OutcomeJournalConflictError):
        journal.preflight_new_attempt(
            request_id="same-id",
            action="clipboard.set",
        )

    raw_input = ReplayInputAdapter()
    executor = Executor(
        input_adapter=raw_input,
        outcome_journal=journal,
        dry_run=False,
    )
    result = executor.execute(
        ActionRequest("clipboard.set", {"text": "value"}, request_id="same-id")
    )
    assert result.status == "blocked"
    assert raw_input.events == []

def test_restart_readback_preserves_hash_chain_and_execution_correlation(tmp_path):
    path = tmp_path / "restart.jsonl"
    first = OutcomeJournal(path)
    correlation = first.start_dispatch(provisional("req-restart", "keyboard.press"))
    terminal = first.append_terminal(
        completed("req-restart", "keyboard.press"),
        correlation=correlation,
    )

    second = OutcomeJournal(path)
    lookup = second.lookup(
        request_id="req-restart",
        action="keyboard.press",
        execution_attempt=1,
    ).to_dict()

    assert lookup["outcome"] == "succeeded"
    assert lookup["latest_valid_record"]["record_sha256"] == terminal.record_sha256
    assert lookup["latest_valid_record"]["execution_id"] == correlation.execution_id
    assert lookup["provenance"]["total_valid_records"] == 2
    assert lookup["provenance"]["integrity"] == "clean"


def test_concurrent_different_request_ids_produce_contiguous_valid_journal(tmp_path):
    path = tmp_path / "concurrent.jsonl"

    def write_one(index: int):
        journal = OutcomeJournal(path)
        request_id = f"req-{index:02d}"
        correlation = journal.start_dispatch(
            provisional(request_id, "keyboard.press")
        )
        journal.append_terminal(
            completed(request_id, "keyboard.press"),
            correlation=correlation,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(write_one, range(20)))

    raw_lines = path.read_text(encoding="utf-8").splitlines()
    assert len(raw_lines) == 40
    sequences = [json.loads(line)["journal_sequence"] for line in raw_lines]
    assert sequences == list(range(1, 41))
    for index in range(20):
        lookup = OutcomeJournal(path).lookup(
            request_id=f"req-{index:02d}",
            action="keyboard.press",
        ).to_dict()
        assert lookup["outcome"] == "succeeded"
        assert lookup["provenance"]["integrity"] == "clean"


def test_unknown_never_becomes_reexecution_safe_or_replay_authorized(tmp_path):
    path = tmp_path / "unknown.jsonl"
    journal = OutcomeJournal(path)
    journal.start_dispatch(provisional("req-unknown", "keyboard.press"))

    lookup = journal.lookup(
        request_id="req-unknown",
        action="keyboard.press",
    ).to_dict()
    assert lookup["outcome"] == "unknown"
    assert lookup["replay_authorized"] is False
    assert lookup["latest_valid_evidence"]["reexecution_safe"] is False
    assert lookup["latest_valid_evidence"]["reconciliation_required"] is True

    with pytest.raises(OutcomeJournalReplayUnsafeError):
        journal.preflight_new_attempt(
            request_id="req-unknown",
            action="keyboard.press",
        )

    raw_input = ReplayInputAdapter()
    result = Executor(
        input_adapter=raw_input,
        outcome_journal=journal,
        dry_run=False,
    ).execute(
        ActionRequest("keyboard.press", {"key": "enter"}, request_id="req-unknown")
    )
    assert result.status == "blocked"
    assert raw_input.events == []

class BombInput:
    def click(self, *args, **kwargs):
        raise AssertionError("input adapter must not be called")

    def press(self, *args, **kwargs):
        raise AssertionError("input adapter must not be called")

    def type_text(self, *args, **kwargs):
        raise AssertionError("input adapter must not be called")

    def clipboard_get(self):
        raise AssertionError("input adapter must not be called")

    def clipboard_set(self, *args, **kwargs):
        raise AssertionError("input adapter must not be called")


class BombUIA:
    def inspect(self, *args, **kwargs):
        raise AssertionError("UIA adapter must not be called")

    def invoke(self, *args, **kwargs):
        raise AssertionError("UIA adapter must not be called")

    def focus(self, *args, **kwargs):
        raise AssertionError("UIA adapter must not be called")

    def set_value(self, *args, **kwargs):
        raise AssertionError("UIA adapter must not be called")

    def snapshot(self, *args, **kwargs):
        raise AssertionError("UIA adapter must not be called")


class BombShell:
    def validate(self, *args, **kwargs):
        raise AssertionError("shell adapter must not be called")

    def run(self, *args, **kwargs):
        raise AssertionError("shell adapter must not be called")


def test_outcome_lookup_action_is_read_only_and_never_calls_adapters(tmp_path):
    path = tmp_path / "lookup.jsonl"
    journal = OutcomeJournal(path)
    correlation = journal.start_dispatch(provisional("target-id", "keyboard.press"))
    journal.append_terminal(
        completed("target-id", "keyboard.press"),
        correlation=correlation,
    )
    executor = Executor(
        input_adapter=BombInput(),
        accessibility=BombUIA(),
        shell=BombShell(),
        outcome_journal=journal,
        dry_run=False,
    )

    result = executor.execute(
        ActionRequest(
            "outcome.lookup",
            {
                "request_id": "target-id",
                "action": "keyboard.press",
                "execution_attempt": 1,
            },
            request_id="lookup-call",
        )
    )

    assert result.ok is True
    assert result.status == "completed"
    evidence = result.data["outcome_evidence"]
    assert evidence["outcome"] == "succeeded"
    assert evidence["replay_authorized"] is False
    assert result.outcome_evidence is None

def test_attempt_correlation_advances_only_after_proven_not_started(tmp_path):
    path = tmp_path / "attempts.jsonl"
    journal = OutcomeJournal(path)
    raw_input = ReplayInputAdapter()

    dry = Executor(
        input_adapter=raw_input,
        outcome_journal=journal,
        dry_run=True,
    ).execute(
        ActionRequest("keyboard.press", {"key": "enter"}, request_id="same-request")
    )
    assert dry.outcome_evidence.effect_state == "not_started"

    live = Executor(
        input_adapter=raw_input,
        outcome_journal=journal,
        dry_run=False,
    ).execute(
        ActionRequest("keyboard.press", {"key": "enter"}, request_id="same-request")
    )
    assert live.ok is True

    attempt1 = journal.lookup(
        request_id="same-request",
        action="keyboard.press",
        execution_attempt=1,
    ).to_dict()
    attempt2 = journal.lookup(
        request_id="same-request",
        action="keyboard.press",
        execution_attempt=2,
    ).to_dict()
    assert attempt1["outcome"] == "not_dispatched"
    assert attempt2["outcome"] == "succeeded"
    assert attempt2["history"][0]["execution_attempt"] == 2


def test_unknown_record_version_fails_closed(tmp_path):
    path = tmp_path / "version.jsonl"
    journal = OutcomeJournal(path)
    journal.append_terminal(not_started("req-version", "keyboard.press"))
    raw = json.loads(path.read_text(encoding="utf-8").strip())
    raw["contract_version"] = "pc_executor.outcome_journal.record.v2"
    path.write_text(json.dumps(raw, separators=(",", ":")) + "\n", encoding="utf-8")

    lookup = OutcomeJournal(path).lookup(
        request_id="req-version",
        action="keyboard.press",
    ).to_dict()
    assert lookup["outcome"] == "unknown"
    assert lookup["provenance"]["integrity"] == "corrupt"
    assert lookup["latest_valid_evidence"] is None
    assert lookup["replay_authorized"] is False

def test_sensitive_payloads_and_coordinates_never_enter_journal(tmp_path):
    path = tmp_path / "redaction.jsonl"
    journal = OutcomeJournal(path)
    raw_input = ReplayInputAdapter()
    executor = Executor(
        input_adapter=raw_input,
        outcome_journal=journal,
        dry_run=False,
        allow_coordinate_fallback=True,
    )

    secret = "SENSITIVE-TEXT-DO-NOT-PERSIST"
    result = executor.execute(
        ActionRequest(
            "keyboard.type_text",
            {"text": secret},
            request_id="secret-request",
        )
    )
    assert result.ok is True

    coordinate_result = Executor(
        input_adapter=raw_input,
        outcome_journal=journal,
        dry_run=False,
        allow_coordinate_fallback=True,
    ).execute(
        ActionRequest(
            "mouse.click",
            {"x": 123456789, "y": -987654321},
            request_id="coordinate-request",
        )
    )
    assert coordinate_result.ok is True

    serialized = path.read_text(encoding="utf-8")
    assert secret not in serialized
    assert "123456789" not in serialized
    assert "-987654321" not in serialized


def test_uia_value_and_shell_output_do_not_enter_journal(tmp_path):
    path = tmp_path / "payloads.jsonl"
    journal = OutcomeJournal(path)
    secret_value = "VALUE-BODY-SECRET"
    shell_secret = "SHELL-STDOUT-SECRET"

    uia = ReplayUIAAdapter([actionable(automation_id="field", value=True)])
    set_result = Executor(
        accessibility=uia,
        outcome_journal=journal,
        dry_run=False,
    ).execute(
        ActionRequest(
            "uia.set_value",
            {
                "query": {"automation_id": "field"},
                "value": secret_value,
            },
            request_id="uia-secret",
        )
    )
    assert set_result.ok is True

    shell = ReplayShellAdapter(
        [
            ShellResult(
                argv=["python", "-V"],
                returncode=0,
                stdout=shell_secret,
                stderr="STDERR-SECRET",
                stdout_bytes=len(shell_secret),
                stderr_bytes=len("STDERR-SECRET"),
                stdout_truncated=False,
                stderr_truncated=False,
                output_limit_bytes=1024,
            )
        ]
    )
    shell_result = Executor(
        shell=shell,
        outcome_journal=journal,
        dry_run=False,
    ).execute(
        ActionRequest(
            "shell.run",
            {"argv": ["python", "-V"]},
            request_id="shell-secret",
        )
    )
    assert shell_result.ok is True

    serialized = path.read_text(encoding="utf-8")
    assert secret_value not in serialized
    assert shell_secret not in serialized
    assert "STDERR-SECRET" not in serialized


def test_provisional_fsync_happens_before_adapter_invocation(tmp_path, monkeypatch):
    path = tmp_path / "fsync-order.jsonl"
    journal = OutcomeJournal(path)
    fsync_seen = threading.Event()
    real_fsync = os.fsync

    def tracking_fsync(fd):
        real_fsync(fd)
        fsync_seen.set()

    monkeypatch.setattr(os, "fsync", tracking_fsync)

    class OrderingInput(ReplayInputAdapter):
        def press(self, key):
            assert fsync_seen.is_set(), "side effect started before provisional fsync"
            super().press(key)

    result = Executor(
        input_adapter=OrderingInput(),
        outcome_journal=journal,
        dry_run=False,
    ).execute(
        ActionRequest("keyboard.press", {"key": "enter"}, request_id="fsync-order")
    )
    assert result.ok is True


def test_clipboard_and_blocked_sensitive_values_never_enter_journal(tmp_path):
    path = tmp_path / "clipboard-redaction.jsonl"
    journal = OutcomeJournal(path)
    raw_input = ReplayInputAdapter()
    clipboard_secret = "CLIPBOARD-BODY-SECRET"
    blocked_secret = "BLOCKED-CREDENTIAL-SECRET"

    clipboard_result = Executor(
        input_adapter=raw_input,
        outcome_journal=journal,
        dry_run=False,
    ).execute(
        ActionRequest(
            "clipboard.set",
            {"text": clipboard_secret},
            request_id="clipboard-secret",
        )
    )
    assert clipboard_result.ok is True

    blocked = Executor(
        input_adapter=raw_input,
        outcome_journal=journal,
        dry_run=False,
    ).execute(
        ActionRequest(
            "keyboard.type_text",
            {"text": blocked_secret, "sensitive": True},
            request_id="blocked-secret",
        )
    )
    assert blocked.status == "blocked"

    serialized = path.read_text(encoding="utf-8")
    assert clipboard_secret not in serialized
    assert blocked_secret not in serialized


def test_transport_neutral_fixture_manifest_and_frozen_outcome_hashes():
    root = Path(__file__).parent / "fixtures" / "outcome_journal_v1"
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    sidecar = (root / "manifest.sha256").read_text(encoding="ascii").strip()
    expected_manifest_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()

    assert sidecar == f"{expected_manifest_hash}  manifest.json"
    assert manifest["contract_version"] == "pc_executor.outcome_journal.fixture_manifest.v1"
    assert manifest["record_contract_version"] == "pc_executor.outcome_journal.record.v1"
    assert manifest["lookup_contract_version"] == "pc_executor.outcome_journal.lookup.v1"
    assert manifest["action_outcome_contract_version"] == "pc_executor.action_outcome.v1"
    assert manifest["producer_base_head"] == "606074456ca00681fac30a40ee28f7bb0f67c79c"
    assert manifest["consumer_compatibility_head"] == "27ac92f38892605cdac0ca6cdc968757b1c9cb66"

    for name, metadata in manifest["files"].items():
        path = root / name
        assert len(path.read_bytes()) == metadata["bytes"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == metadata["sha256"]

    frozen = manifest["frozen_action_outcome_fixture_sha256"]
    assert frozen == {
        "action_outcome_v1_not_started.json": "06278df0fd016093d67420f9e33b0504d7f72bc5da8ecbece063c649d9d2c913",
        "action_outcome_v1.json": "e73488314215a43768710247ee199aa878442d93f20025e35da567bb20757f10",
        "action_outcome_v1_unknown.json": "c4585b7b2ccd0788ee4d22be2dfee8f43c28e2f46555bbe731157b272d321951",
    }
    fixtures = Path(__file__).parent / "fixtures"
    for name, expected_hash in frozen.items():
        assert hashlib.sha256((fixtures / name).read_bytes()).hexdigest() == expected_hash


@pytest.mark.parametrize(
    ("lookup_name", "outcome", "integrity"),
    [
        ("completed.lookup.json", "succeeded", "clean"),
        ("unknown.lookup.json", "unknown", "clean"),
        ("not_started.lookup.json", "not_dispatched", "clean"),
        ("truncated_tail.lookup.json", "unknown", "corrupt"),
    ],
)
def test_transport_lookup_fixtures_have_help_pc2_consumable_outcome(
    lookup_name, outcome, integrity
):
    root = Path(__file__).parent / "fixtures" / "outcome_journal_v1"
    payload = json.loads((root / lookup_name).read_text(encoding="utf-8"))
    assert payload["contract_version"] == "pc_executor.outcome_journal.lookup.v1"
    assert payload["source"] == "help-pc-1.outcome-journal"
    assert payload["outcome"] == outcome
    assert payload["replay_authorized"] is False
    assert payload["provenance"]["integrity"] == integrity


def test_jsonl_outcome_lookup_reads_journal_without_execution(tmp_path):
    path = tmp_path / "cli-lookup.jsonl"
    journal = OutcomeJournal(path)
    correlation = journal.start_dispatch(provisional("cli-target", "keyboard.press"))
    journal.append_terminal(
        completed("cli-target", "keyboard.press"),
        correlation=correlation,
    )

    request = {
        "request_id": "lookup-request",
        "action": "outcome.lookup",
        "params": {
            "request_id": "cli-target",
            "action": "keyboard.press",
            "execution_attempt": 1,
        },
    }
    completed_process = subprocess.run(
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

    assert completed_process.returncode == 0
    response = json.loads(completed_process.stdout.strip())
    assert response["ok"] is True
    assert response["status"] == "dry_run"
    evidence = response["data"]["outcome_evidence"]
    assert evidence["outcome"] == "succeeded"
    assert evidence["replay_authorized"] is False
    assert evidence["provenance"]["integrity"] == "clean"


def test_read_evidence_accepts_current_help_pc2_request_shape(tmp_path):
    path = tmp_path / "adapter-shape.jsonl"
    journal = OutcomeJournal(path)
    correlation = journal.start_dispatch(
        provisional("adapter-target", "keyboard.press")
    )
    journal.append_terminal(
        completed("adapter-target", "keyboard.press"),
        correlation=correlation,
    )

    payload = journal.read_evidence(
        {
            "request_id": "adapter-target",
            "action": "keyboard.press",
            "execution_attempt": 1,
        }
    )
    assert payload["outcome"] == "succeeded"
    assert payload["execution_attempt"] == 1
    assert payload["replay_authorized"] is False


def test_tampered_hash_chain_is_explicit_unknown_and_blocks_append(tmp_path):
    path = tmp_path / "tampered.jsonl"
    journal = OutcomeJournal(path)
    correlation = journal.start_dispatch(provisional("tamper", "keyboard.press"))
    journal.append_terminal(
        completed("tamper", "keyboard.press"),
        correlation=correlation,
    )

    lines = path.read_text(encoding="utf-8").splitlines()
    second = json.loads(lines[1])
    second["previous_record_sha256"] = "0" * 64
    path.write_text(
        lines[0] + "\n" + json.dumps(second, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    lookup = OutcomeJournal(path).lookup(
        request_id="tamper",
        action="keyboard.press",
    ).to_dict()
    assert lookup["outcome"] == "unknown"
    assert lookup["provenance"]["integrity"] == "corrupt"
    assert lookup["provenance"]["corruption"]["kind"] == "malformed_tail"
    assert lookup["latest_valid_evidence"]["effect_state"] == "unknown"

    with pytest.raises(OutcomeJournalIntegrityError):
        OutcomeJournal(path).start_dispatch(provisional("other", "keyboard.press"))


@pytest.mark.parametrize(
    ("journal_name", "request_id", "lookup_name"),
    [
        ("completed.jsonl", "fixture-completed", "completed.lookup.json"),
        ("unknown.jsonl", "fixture-unknown", "unknown.lookup.json"),
        ("not_started.jsonl", "fixture-not-started", "not_started.lookup.json"),
        ("truncated_tail.jsonl", "fixture-completed", "truncated_tail.lookup.json"),
    ],
)
def test_fixture_lookup_outputs_are_reproducible(
    journal_name, request_id, lookup_name
):
    root = Path(__file__).parent / "fixtures" / "outcome_journal_v1"
    actual = OutcomeJournal(root / journal_name).lookup(
        request_id=request_id,
        action="keyboard.press",
        execution_attempt=1,
    ).to_dict()
    expected = json.loads((root / lookup_name).read_text(encoding="utf-8"))
    assert actual == expected


def test_cli_dry_run_default_does_not_create_outcome_journal(tmp_path):
    path = tmp_path / "should-not-exist.jsonl"
    env = os.environ.copy()
    env["PC_EXECUTOR_OUTCOME_JOURNAL"] = str(path)
    request = {
        "request_id": "dry-default",
        "action": "keyboard.press",
        "params": {"key": "enter"},
    }

    process = subprocess.run(
        [sys.executable, "-m", "pc_executor"],
        input=json.dumps(request) + "\n",
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )

    assert process.returncode == 0
    response = json.loads(process.stdout.strip())
    assert response["status"] == "dry_run"
    assert path.exists() is False


def test_cli_live_uses_default_outcome_journal_for_safe_policy_block(tmp_path):
    path = tmp_path / "live-default.jsonl"
    env = os.environ.copy()
    env["PC_EXECUTOR_OUTCOME_JOURNAL"] = str(path)
    request = {
        "request_id": "live-blocked",
        "action": "mouse.click",
        "params": {"x": 5, "y": 9},
    }

    process = subprocess.run(
        [sys.executable, "-m", "pc_executor", "--live"],
        input=json.dumps(request) + "\n",
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )

    assert process.returncode == 1
    response = json.loads(process.stdout.strip())
    assert response["status"] == "blocked"
    assert path.exists() is True

    lookup = OutcomeJournal(path).lookup(
        request_id="live-blocked",
        action="mouse.click",
    ).to_dict()
    assert lookup["outcome"] == "blocked"
    assert lookup["latest_valid_evidence"]["effect_state"] == "not_started"
    assert lookup["latest_valid_evidence"]["reason"] == "policy_blocked"
