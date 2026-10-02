from __future__ import annotations

import json
import subprocess
from pathlib import Path

from tools.github_relay import (
    HEALTH_VERSION,
    classify_health_snapshot,
)


def _root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_real_incident_fixture_classifies_stale_healthy_and_reconciliation() -> None:
    fixture = json.loads(
        (
            _root()
            / "tests"
            / "fixtures"
            / "pc_relay_cutover_candidate"
            / "incident_2026-10-01.json"
        ).read_text(encoding="utf-8")
    )

    incident = fixture["recorded_incident"]
    assert incident["process_chain"] == [
        {"image": "py.exe", "pid": 4612, "parent_pid": 1000},
        {"image": "python3.13.exe", "pid": 15056, "parent_pid": 4612},
    ]
    assert incident["local_head"] == "be374169e51309bbc943f68e7965f23f53c85380"
    assert incident["observed_remote_head"] == (
        "e29d3746d2fbdc35b26e4b0725a63b78100a07c6"
    )
    assert incident["missing_result_backlog"] == 22
    assert incident["manual_fetch_succeeded"] is True
    assert incident["recovery_reused_existing_request_ids"] is True

    observed: dict[str, str] = {}
    for scenario in fixture["scenarios"]:
        snapshot = scenario["snapshot"]
        assert snapshot["health_version"] == HEALTH_VERSION
        state = classify_health_snapshot(
            snapshot,
            now_unix=scenario["now_unix"],
            process_exists=scenario["process_exists"],
            logical_process_count=scenario["logical_process_count"],
            health_pid_observed=scenario["health_pid_observed"],
            head_relation=scenario["head_relation"],
            observed_remote_head=scenario["observed_remote_head"],
            observed_remote_backlog_count=scenario[
                "observed_remote_backlog_count"
            ],
            stale_after_seconds=30,
        )
        observed[scenario["name"]] = state
        assert state == scenario["expected_state"]

    assert observed == {
        "recorded_stale_sync": "STALE",
        "healthy_after_forward_progress": "HEALTHY",
        "unknown_side_effect_after_reboot": "RECONCILIATION_REQUIRED",
    }


def test_launcher_bounds_logs_without_changing_reconciliation_semantics() -> None:
    text = (
        _root() / "tools" / "start_pc_control_relay.ps1"
    ).read_text(encoding="utf-8")
    folded = text.casefold()

    assert "[long]$LogMaxBytes = 5242880" in text
    assert "[int]$LogBackupCount = 3" in text
    assert "function Rotate-BoundedLog" in text
    assert "Rotate-BoundedLog -Path $Stdout" in text
    assert "Rotate-BoundedLog -Path $Stderr" in text
    assert "outcome.lookup" in text
    assert "liveness recovery never authorizes replay" in folded
    assert text.count("$RelayScript,") >= 2
    assert "'tools\\github_relay.py'," not in text
    assert "Stop-Process" not in text
    assert "taskkill" not in folded


def test_autostart_installer_is_exact_head_guarded_plan_only_by_default() -> None:
    text = (
        _root() / "tools" / "install_pc_relay_autostart.ps1"
    ).read_text(encoding="utf-8")
    folded = text.casefold()

    assert "[switch]$Apply" in text
    assert "expected_head = $ExpectedHead" in text
    assert "expected_branch = $ExpectedBranch" in text
    assert "if (-not $Apply)" in text
    assert "Register-ScheduledTask" in text
    assert "New-ScheduledTaskTrigger -AtLogOn" in text
    assert "$trigger.Delay" in text
    assert "MultipleInstances IgnoreNew" in text
    assert "LogonType Interactive" in text
    assert "RunLevel Limited" in text
    assert "starts_task_immediately = $false" in text
    assert "Start-ScheduledTask" not in text
    assert "Stop-Process" not in text
    assert "taskkill" not in folded
    assert "automatic_replay = $false" in text


def test_autostart_uninstall_preserves_state_and_refuses_running_relay() -> None:
    text = (
        _root() / "tools" / "uninstall_pc_relay_autostart.ps1"
    ).read_text(encoding="utf-8")
    folded = text.casefold()

    assert "[switch]$Apply" in text
    assert "if (-not $Apply)" in text
    assert "Unregister-ScheduledTask" in text
    assert "requires_relay_absent = $true" in text
    assert "deletes_runtime_state = $false" in text
    assert "deletes_outcome_journal = $false" in text
    assert "Stop-Process" not in text
    assert "taskkill" not in folded


def test_rollback_is_exact_detached_head_and_never_moves_live_branch() -> None:
    text = (
        _root() / "tools" / "rollback_pc_relay_cutover.ps1"
    ).read_text(encoding="utf-8")
    folded = text.casefold()

    assert "[switch]$Apply" in text
    assert "PreviousBranch = 'agent/pc-github-relay'" in text
    assert "refs/remotes/origin/$PreviousBranch" in text
    assert "checkout_mode = 'detached_exact_head'" in text
    assert "Invoke-Git -Arguments @('checkout', '--detach', $PreviousHead)" in text
    assert "starts_relay = $false" in text
    assert "automatic_process_kill = $false" in text
    assert "automatic_replay = $false" in text
    assert r".pc-relay\state" in text
    assert r".pc-relay\outcomes.jsonl" in text
    assert "git reset --hard" not in folded
    assert "Stop-Process" not in text
    assert "taskkill" not in folded


def test_cutover_candidate_manifest_keeps_no_live_cutover_and_reboot_safety() -> None:
    manifest = json.loads(
        (
            _root()
            / "conformance"
            / "pc_relay.cutover_candidate.v1"
            / "manifest.json"
        ).read_text(encoding="utf-8")
    )

    assert manifest["contract"] == "pc_relay.cutover_candidate.v1"
    assert manifest["exact_start_sha"] == (
        "33d063dffa507833a23c642d3e3e06bfa5d02b76"
    )
    assert manifest["live_branch"]["name"] == "agent/pc-github-relay"
    assert manifest["live_branch"]["modified_by_milestone"] is False
    assert manifest["reboot_recovery"]["state_preserved"] is True
    assert manifest["reboot_recovery"]["outcome_journal_preserved"] is True
    assert manifest["reboot_recovery"]["unknown_effect_replay_authorized"] is False
    assert manifest["autostart"]["registration_requires_explicit_apply"] is True
    assert manifest["autostart"]["registration_performed_by_ci"] is False
    assert manifest["release_gate"] == "NO_LIVE_CUTOVER"


def _git_blob_sha(relative: str) -> str:
    return subprocess.check_output(
        ["git", "rev-parse", f"HEAD:{relative}"],
        cwd=_root(),
        text=True,
    ).strip()


def test_cutover_manifest_source_blobs_and_schema_are_exact() -> None:
    root = _root()
    manifest = json.loads(
        (
            root
            / "conformance"
            / "pc_relay.cutover_candidate.v1"
            / "manifest.json"
        ).read_text(encoding="utf-8")
    )
    schema = json.loads(
        (
            root
            / "conformance"
            / "pc_relay.cutover_candidate.v1"
            / "schema.json"
        ).read_text(encoding="utf-8")
    )

    assert schema["$id"] == "pc_relay.cutover_candidate.v1"
    assert set(schema["required"]) == {
        "contract",
        "repository",
        "branch",
        "exact_start_sha",
        "source_blobs",
        "live_branch",
        "health_contract",
        "watchdog_contract",
        "incident_fixture",
        "autostart",
        "reboot_recovery",
        "rollback",
        "logs",
        "release_gate",
    }
    for item in manifest["source_blobs"].values():
        assert _git_blob_sha(item["path"]) == item["git_blob_sha1"], item["path"]


def test_incident_fixture_is_bound_to_recorded_incident_document() -> None:
    fixture = json.loads(
        (
            _root()
            / "tests"
            / "fixtures"
            / "pc_relay_cutover_candidate"
            / "incident_2026-10-01.json"
        ).read_text(encoding="utf-8")
    )
    assert fixture["source_document"] == (
        "docs/PC_RELAY_STALE_SYNC_INCIDENT_2026-10-01.md"
    )
    incident_doc = (
        _root() / "docs" / "PC_RELAY_STALE_SYNC_INCIDENT_2026-10-01.md"
    ).read_text(encoding="utf-8")
    assert "py.exe PID 4612" in incident_doc
    assert "python3.13.exe PID 15056" in incident_doc
    assert "22 request files lacked result files" in incident_doc
    assert "be374169e51309bbc943f68e7965f23f53c85380" in incident_doc
