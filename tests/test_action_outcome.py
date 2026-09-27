from __future__ import annotations

import copy
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from pc_executor.audit import InMemoryAuditSink
from pc_executor.cancellation import CancellationToken
from pc_executor.executor import Executor
from pc_executor.fakes import ReplayInputAdapter, ReplayUIAAdapter
from pc_executor.models import ActionRequest, ElementInfo
from pc_executor.outcome import (
    ActionOutcomeEvidence,
    ActionOutcomeValidationError,
    parse_action_outcome,
)
from pc_executor.shell import SafeShellAdapter


FIXTURE = Path(__file__).parent / "fixtures" / "action_outcome_v1.json"


def actionable() -> ElementInfo:
    return ElementInfo(
        name="Save",
        automation_id="save",
        control_type="ButtonControl",
        is_enabled=True,
        is_password=False,
        native_handle=7,
        process_id=70,
        supports_invoke=True,
    )


def load_fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))

def test_canonical_outcome_fixture_round_trips_strictly():
    payload = load_fixture()
    parsed = parse_action_outcome(payload)

    assert parsed.to_dict() == payload
    assert parsed.effect_state == "completed"
    assert parsed.reexecution_safe is False
    assert parsed.reconciliation_required is False


@pytest.mark.parametrize(
    "mutator",
    [
        lambda p: p.__setitem__("contract_version", "pc_executor.action_outcome.v2"),
        lambda p: p.__setitem__("extra", True),
        lambda p: p.__setitem__("effect_state", "maybe"),
        lambda p: p.__setitem__("completion_observed", False),
        lambda p: p.__setitem__("reexecution_safe", True),
        lambda p: p.__setitem__("reconciliation_required", True),
        lambda p: p.__setitem__("action", "screenshot.capture"),
    ],
)
def test_outcome_contract_rejects_unknown_or_inconsistent_payloads(mutator):
    payload = copy.deepcopy(load_fixture())
    mutator(payload)

    with pytest.raises(ActionOutcomeValidationError):
        parse_action_outcome(payload)


def test_successful_side_effect_emits_completed_evidence_and_dispatch_marker():
    audit = InMemoryAuditSink()
    adapter = ReplayUIAAdapter([actionable()])
    executor = Executor(accessibility=adapter, audit=audit, dry_run=False)

    result = executor.execute(
        ActionRequest("uia.invoke", {"query": {"automation_id": "save"}}, request_id="r-complete")
    )

    assert result.ok is True
    assert result.outcome_evidence is not None
    assert result.outcome_evidence.effect_state == "completed"
    assert result.outcome_evidence.dispatch_started is True
    assert result.outcome_evidence.completion_observed is True
    assert result.outcome_evidence.reexecution_safe is False
    assert result.outcome_evidence.reconciliation_required is False
    assert adapter.events == [("invoke", "save")]
    assert [event.phase for event in audit.events] == [
        "start",
        "effect_dispatch",
        "finish",
    ]
    provisional = audit.events[1].details["outcome_evidence"]
    assert provisional["effect_state"] == "unknown"
    assert provisional["reexecution_safe"] is False
    assert provisional["reconciliation_required"] is True
    assert audit.events[-1].details["outcome_evidence"]["effect_state"] == "completed"


def test_dry_run_side_effect_is_not_started_and_safe_to_reexecute():
    audit = InMemoryAuditSink()
    raw_input = ReplayInputAdapter()
    executor = Executor(input_adapter=raw_input, audit=audit, dry_run=True)

    result = executor.execute(
        ActionRequest("keyboard.press", {"key": "enter"}, request_id="r-dry")
    )

    evidence = result.outcome_evidence
    assert evidence is not None
    assert evidence.effect_state == "not_started"
    assert evidence.dispatch_started is False
    assert evidence.reexecution_safe is True
    assert evidence.reconciliation_required is False
    assert evidence.reason == "dry_run"
    assert raw_input.events == []
    assert [event.phase for event in audit.events] == ["start", "finish"]


def test_structured_stale_target_proves_not_started_even_after_adapter_dispatch():
    audit = InMemoryAuditSink()
    adapter = ReplayUIAAdapter([])
    executor = Executor(accessibility=adapter, audit=audit, dry_run=False)

    result = executor.execute(
        ActionRequest("uia.invoke", {"query": {"automation_id": "missing"}})
    )

    evidence = result.outcome_evidence
    assert result.error_kind == "stale_target"
    assert evidence is not None
    assert evidence.effect_state == "not_started"
    assert evidence.dispatch_started is True
    assert evidence.reexecution_safe is True
    assert evidence.reconciliation_required is False
    assert evidence.reason == "stale_target"

class SlowInput(ReplayInputAdapter):
    def press(self, key):
        self.events.append(("press_started", key))
        time.sleep(0.08)
        self.events.append(("press_finished", key))


def test_post_dispatch_timeout_is_unknown_and_requires_reconciliation():
    raw_input = SlowInput()
    executor = Executor(input_adapter=raw_input, dry_run=False)

    result = executor.execute(
        ActionRequest(
            "keyboard.press",
            {"key": "enter"},
            request_id="r-timeout",
            timeout_ms=10,
        )
    )

    evidence = result.outcome_evidence
    assert result.status == "timeout"
    assert result.error_kind == "timeout"
    assert evidence is not None
    assert evidence.effect_state == "unknown"
    assert evidence.dispatch_started is True
    assert evidence.completion_observed is False
    assert evidence.reexecution_safe is False
    assert evidence.reconciliation_required is True
    assert evidence.reason == "timeout"
    time.sleep(0.1)


def test_precancelled_side_effect_is_not_started():
    token = CancellationToken()
    token.cancel()
    raw_input = ReplayInputAdapter()
    executor = Executor(input_adapter=raw_input, dry_run=False)

    result = executor.execute(
        ActionRequest("keyboard.press", {"key": "enter"}, request_id="r-cancel"),
        cancellation=token,
    )

    evidence = result.outcome_evidence
    assert result.status == "cancelled"
    assert evidence is not None
    assert evidence.effect_state == "not_started"
    assert evidence.dispatch_started is False
    assert evidence.reexecution_safe is True
    assert evidence.reconciliation_required is False
    assert raw_input.events == []

class CrashLikeInput(ReplayInputAdapter):
    def press(self, key):
        self.events.append(("press_started", key))
        raise SystemExit("simulated process loss after dispatch")


def test_crash_like_interruption_leaves_provisional_unknown_audit_evidence():
    audit = InMemoryAuditSink()
    raw_input = CrashLikeInput()
    executor = Executor(input_adapter=raw_input, audit=audit, dry_run=False)

    with pytest.raises(SystemExit):
        executor.execute(
            ActionRequest("keyboard.press", {"key": "enter"}, request_id="r-crash")
        )

    assert [event.phase for event in audit.events] == ["start", "effect_dispatch"]
    evidence = audit.events[-1].details["outcome_evidence"]
    assert evidence["effect_state"] == "unknown"
    assert evidence["dispatch_started"] is True
    assert evidence["reexecution_safe"] is False
    assert evidence["reconciliation_required"] is True


def test_read_only_result_preserves_legacy_shape_without_outcome_evidence():
    class Windows:
        def list_windows(self):
            return []

    executor = Executor(windows=Windows(), dry_run=False)
    result = executor.execute(ActionRequest("windows.list"))

    assert result.outcome_evidence is None
    assert "outcome_evidence" not in result.to_dict()


def test_outcome_and_audit_never_persist_typed_text():
    secret = "do-not-persist-this-value"
    audit = InMemoryAuditSink()
    raw_input = ReplayInputAdapter()
    executor = Executor(input_adapter=raw_input, audit=audit, dry_run=False)

    result = executor.execute(
        ActionRequest(
            "keyboard.type_text",
            {"text": secret},
            request_id="r-sensitive-evidence",
        )
    )

    assert result.outcome_evidence is not None
    serialized = json.dumps(
        [event.to_dict() for event in audit.events],
        sort_keys=True,
    )
    assert secret not in serialized
    assert result.data == {"text_length": len(secret)}


def test_factory_enforces_unknown_as_non_reexecutable_reconciliation_state():
    evidence = ActionOutcomeEvidence.create(
        request_id="r1",
        action="shell.run",
        effect_state="unknown",
        dispatch_started=True,
        reason="executor_failure",
        observed_at="2026-09-27T08:00:00.000Z",
    )
    assert evidence.reexecution_safe is False
    assert evidence.reconciliation_required is True


class FailingInput(ReplayInputAdapter):
    def press(self, key):
        self.events.append(("press_started", key))
        raise RuntimeError("input driver lost after dispatch")


def test_unexpected_post_dispatch_failure_is_unknown_not_retry_safe():
    raw_input = FailingInput()
    executor = Executor(input_adapter=raw_input, dry_run=False)

    result = executor.execute(
        ActionRequest("keyboard.press", {"key": "enter"}, request_id="r-driver")
    )

    evidence = result.outcome_evidence
    assert result.status == "error"
    assert result.error_kind == "executor_failure"
    assert evidence is not None
    assert evidence.effect_state == "unknown"
    assert evidence.reexecution_safe is False
    assert evidence.reconciliation_required is True


def test_policy_block_before_dispatch_is_not_started():
    executor = Executor(dry_run=False, allow_coordinate_fallback=False)

    result = executor.execute(
        ActionRequest("mouse.click", {"x": 10, "y": 20}, request_id="r-blocked")
    )

    evidence = result.outcome_evidence
    assert result.status == "blocked"
    assert evidence is not None
    assert evidence.effect_state == "not_started"
    assert evidence.dispatch_started is False
    assert evidence.reexecution_safe is True
    assert evidence.reconciliation_required is False


def test_jsonl_transport_emits_outcome_evidence_for_side_effecting_dry_run():
    request = {
        "request_id": "cli-outcome",
        "action": "keyboard.press",
        "params": {"key": "enter"},
    }

    completed = subprocess.run(
        [sys.executable, "-m", "pc_executor"],
        input=json.dumps(request) + "\n",
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0
    response = json.loads(completed.stdout.strip())
    evidence = response["outcome_evidence"]
    assert evidence["contract_version"] == "pc_executor.action_outcome.v1"
    assert evidence["request_id"] == "cli-outcome"
    assert evidence["action"] == "keyboard.press"
    assert evidence["effect_state"] == "not_started"
    assert evidence["dispatch_started"] is False
    assert evidence["reexecution_safe"] is True
    assert evidence["reconciliation_required"] is False
    assert evidence["reason"] == "dry_run"


@pytest.mark.parametrize(
    ("name", "state"),
    [
        ("action_outcome_v1_not_started.json", "not_started"),
        ("action_outcome_v1.json", "completed"),
        ("action_outcome_v1_unknown.json", "unknown"),
    ],
)
def test_canonical_state_corpus_parses(name, state):
    payload = json.loads((FIXTURE.parent / name).read_text(encoding="utf-8"))
    parsed = parse_action_outcome(payload)
    assert parsed.effect_state == state
    assert parsed.to_dict() == payload


def test_post_dispatch_cancellation_is_unknown_and_requires_reconciliation():
    token = CancellationToken()
    started = threading.Event()

    class CancellableInput(ReplayInputAdapter):
        def press(self, key):
            self.events.append(("press_started", key))
            started.set()
            time.sleep(0.08)
            self.events.append(("press_finished", key))

    raw_input = CancellableInput()
    executor = Executor(input_adapter=raw_input, dry_run=False)

    def cancel_after_dispatch():
        assert started.wait(timeout=1)
        token.cancel()

    canceller = threading.Thread(target=cancel_after_dispatch, daemon=True)
    canceller.start()
    result = executor.execute(
        ActionRequest("keyboard.press", {"key": "enter"}, request_id="r-cancel-late"),
        cancellation=token,
    )
    canceller.join(timeout=1)

    evidence = result.outcome_evidence
    assert result.status == "cancelled"
    assert evidence is not None
    assert evidence.effect_state == "unknown"
    assert evidence.dispatch_started is True
    assert evidence.reexecution_safe is False
    assert evidence.reconciliation_required is True
    assert evidence.reason == "cancelled"
    time.sleep(0.1)


def test_shell_timeout_after_process_dispatch_is_unknown():
    executable = Path(sys.executable).name
    shell = SafeShellAdapter(allow_executables={executable})
    executor = Executor(shell=shell, dry_run=False)

    result = executor.execute(
        ActionRequest(
            "shell.run",
            {"argv": [sys.executable, "-c", "import time; time.sleep(0.2)"]},
            request_id="r-shell-timeout",
            timeout_ms=20,
        )
    )

    evidence = result.outcome_evidence
    assert result.status == "timeout"
    assert evidence is not None
    assert evidence.effect_state == "unknown"
    assert evidence.dispatch_started is True
    assert evidence.reexecution_safe is False
    assert evidence.reconciliation_required is True
