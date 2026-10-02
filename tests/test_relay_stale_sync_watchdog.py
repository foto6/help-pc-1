from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

import pytest

import tools.github_relay as relay_module
from tools.github_relay import (
    DEFAULT_ALLOWED_ACTIONS,
    HEALTH_VERSION,
    REQUEST_VERSION,
    Relay,
    _bounded_error,
    _parse_observed_processes,
    build_watchdog_status,
    classify_health_snapshot,
)


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=repo,
        text=True,
        capture_output=True,
        check=True,
    )
    return proc.stdout.strip()


def _git_fixture(tmp_path: Path) -> tuple[Path, str, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.name", "R27 Watchdog Test")
    _git(repo, "config", "user.email", "watchdog@test.invalid")
    (repo / "README.md").write_text("base\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-m", "base")
    base = _git(repo, "rev-parse", "HEAD")

    request_dir = repo / "relay" / "requests"
    request_dir.mkdir(parents=True)
    (request_dir / "queued-001.json").write_text(
        '{"version":"pc_relay.request.v1","id":"queued-001","action":"capabilities.get","params":{},"timeout_ms":5000}\n',
        encoding="utf-8",
    )
    _git(repo, "add", "relay/requests/queued-001.json")
    _git(repo, "commit", "-m", "remote queue advanced")
    remote = _git(repo, "rev-parse", "HEAD")
    _git(
        repo,
        "update-ref",
        "refs/remotes/origin/agent/pc-github-relay",
        remote,
    )
    _git(repo, "reset", "--hard", base)
    return repo, base, remote


def _health(
    *,
    now: float,
    pid: int = 15056,
    local_head: str = "a" * 40,
    remote_head: str = "a" * 40,
    backlog_count: int = 0,
    updated_age: float = 1.0,
    sync_age: float = 1.0,
    cycle_age: float = 1.0,
    reconciliation_required: bool = False,
) -> dict:
    return {
        "health_version": HEALTH_VERSION,
        "pid": pid,
        "branch": "agent/pc-github-relay",
        "live": True,
        "status": "healthy",
        "phase": "idle",
        "updated_at_unix": now - updated_age,
        "started_at_unix": now - 500.0,
        "last_fetch_success_at_unix": now - sync_age,
        "last_sync_at_unix": now - sync_age,
        "last_cycle_completed_at_unix": now - cycle_age,
        "last_request_processed_at_unix": now - cycle_age,
        "last_request_processed_id": "previous-001",
        "last_result_published_at_unix": now - cycle_age,
        "last_result_published_id": "previous-001",
        "local_head": local_head,
        "remote_head": remote_head,
        "remote_head_observed_at_unix": now - sync_age,
        "request_count": 10,
        "result_count": 10 - backlog_count,
        "backlog_count": backlog_count,
        "last_backlog_change_at_unix": now - cycle_age,
        "backlog_high_watermark": max(backlog_count, 1),
        "current_request_id": None,
        "last_error": None,
        "last_reconciliation_request_id": (
            "unknown-side-effect" if reconciliation_required else None
        ),
        "reconciliation_required": reconciliation_required,
    }


def test_alive_process_with_stale_local_head_and_remote_queue_advance_is_stale(
    tmp_path: Path,
) -> None:
    repo, base, remote = _git_fixture(tmp_path)
    now = 10_000.0
    snapshot = _health(
        now=now,
        local_head=base,
        remote_head=base,
        backlog_count=0,
        updated_age=60,
        sync_age=60,
        cycle_age=60,
    )

    status = build_watchdog_status(
        repo,
        snapshot=snapshot,
        observed_processes=["4612:100", "15056:4612"],
        now_unix=now,
        stale_after_seconds=30,
    )

    assert status["state"] == "STALE"
    assert status["process"]["logical_process_count"] == 1
    assert status["process"]["logical_roots"] == [4612]
    assert status["process"]["health_pid_observed"] is True
    assert status["observations"]["local_head"] == base
    assert status["observations"]["remote_tracking_head"] == remote
    assert status["observations"]["head_relation"] == "local_behind_remote"
    assert status["observations"]["remote_tracking_queue"]["backlog_count"] == 1
    assert "local_head_behind_remote_tracking_head" in status["stale_reasons"]
    assert "remote_tracking_head_advanced_since_last_relay_sync" in status["stale_reasons"]
    assert "remote_backlog_advanced_without_completed_cycle" in status["stale_reasons"]


def test_manual_fetch_success_but_no_relay_cycle_progress_is_stale() -> None:
    now = 20_000.0
    snapshot = _health(
        now=now,
        updated_age=1,
        sync_age=90,
        cycle_age=90,
    )
    assert classify_health_snapshot(
        snapshot,
        now_unix=now,
        process_exists=True,
        stale_after_seconds=30,
        logical_process_count=1,
        health_pid_observed=True,
        head_relation="local_behind_remote",
        observed_remote_head="b" * 40,
        observed_remote_backlog_count=1,
    ) == "STALE"


def test_backlog_growth_without_completed_cycle_is_stale_even_with_live_process() -> None:
    now = 30_000.0
    snapshot = _health(
        now=now,
        backlog_count=2,
        updated_age=1,
        sync_age=1,
        cycle_age=75,
    )
    assert classify_health_snapshot(
        snapshot,
        now_unix=now,
        process_exists=True,
        stale_after_seconds=30,
        logical_process_count=1,
        health_pid_observed=True,
        head_relation="equal",
        observed_remote_head=snapshot["remote_head"],
        observed_remote_backlog_count=22,
    ) == "STALE"


def test_normal_py_parent_python_child_chain_is_one_logical_relay() -> None:
    parsed = _parse_observed_processes(
        ["4612:1000", "15056:4612"]
    )
    assert parsed == {
        "matching_pids": [4612, 15056],
        "logical_roots": [4612],
        "logical_process_count": 1,
    }


def test_two_independent_relay_roots_are_duplicate_ambiguous() -> None:
    now = 40_000.0
    snapshot = _health(now=now, pid=15056)
    assert classify_health_snapshot(
        snapshot,
        now_unix=now,
        process_exists=True,
        stale_after_seconds=30,
        logical_process_count=2,
        health_pid_observed=True,
    ) == "DUPLICATE_AMBIGUOUS"


def test_healthy_active_processing_remains_healthy() -> None:
    now = 50_000.0
    snapshot = _health(
        now=now,
        backlog_count=3,
        updated_age=1,
        sync_age=2,
        cycle_age=2,
    )
    assert classify_health_snapshot(
        snapshot,
        now_unix=now,
        process_exists=True,
        stale_after_seconds=30,
        logical_process_count=1,
        health_pid_observed=True,
        head_relation="equal",
        observed_remote_head=snapshot["remote_head"],
        observed_remote_backlog_count=3,
    ) == "HEALTHY"


class _FakeResult:
    def to_dict(self) -> dict:
        return {
            "request_id": "unknown-side-effect.relay-reconcile",
            "action": "outcome.lookup",
            "ok": True,
            "status": "ok",
            "data": {
                "outcome_evidence": {
                    "effect_state": "unknown",
                    "replay_authorized": False,
                }
            },
        }


class _ReconcileOnlyExecutor:
    def __init__(self) -> None:
        self.actions: list[str] = []

    def execute(self, request):
        self.actions.append(request.action)
        assert request.action == "outcome.lookup"
        return _FakeResult()


def test_interrupted_side_effect_stays_reconciliation_required_and_never_replays(
    tmp_path: Path,
) -> None:
    request_path = tmp_path / "relay" / "requests" / "unknown-side-effect.json"
    state_dir = tmp_path / ".pc-relay" / "state"
    results_dir = tmp_path / "relay" / "results"
    state_dir.mkdir(parents=True)
    results_dir.mkdir(parents=True)
    request_path.parent.mkdir(parents=True)
    request = {
        "version": REQUEST_VERSION,
        "id": "unknown-side-effect",
        "action": "shell.run",
        "params": {"argv": ["python", "-c", "print('synthetic')"]},
        "timeout_ms": 1000,
    }
    request_path.write_text(json.dumps(request) + "\n", encoding="utf-8")
    (state_dir / "unknown-side-effect.json").write_text(
        json.dumps(
            {
                "status": "started",
                "request": request,
                "live": True,
                "started_at_unix": 1.0,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    relay = Relay.__new__(Relay)
    relay.live = True
    relay.allowed_actions = set(DEFAULT_ALLOWED_ACTIONS)
    relay.state_dir = state_dir
    relay.results_dir = results_dir
    relay.health_path = tmp_path / ".pc-relay" / "health.json"
    relay._health = _health(now=time.time())
    relay.executor = _ReconcileOnlyExecutor()
    published: list[dict] = []
    relay.publish_result = lambda result: published.append(result)

    result = relay.execute_one(request_path)

    assert relay.executor.actions == ["outcome.lookup"]
    assert result["relay_status"] == "interrupted_requires_reconciliation"
    assert result["reexecuted"] is False
    assert result["replay_authorized"] is False
    assert relay._health["reconciliation_required"] is True
    assert published == [result]


def test_safe_relay_reinitialization_preserves_state_and_outcome_journal(
    tmp_path: Path,
    monkeypatch,
) -> None:
    class DummyShell:
        def __init__(self, *args, **kwargs):
            pass

    class DummyAudit:
        def __init__(self, *args, **kwargs):
            pass

    class DummyJournal:
        def __init__(self, path):
            self.path = path

    class DummyExecutor:
        def __init__(self, *args, **kwargs):
            pass

    monkeypatch.setattr(relay_module, "SafeShellAdapter", DummyShell)
    monkeypatch.setattr(relay_module, "JsonlAuditSink", DummyAudit)
    monkeypatch.setattr(relay_module, "OutcomeJournal", DummyJournal)
    monkeypatch.setattr(relay_module, "Executor", DummyExecutor)
    monkeypatch.setattr(relay_module, "_git_head", lambda *args, **kwargs: "a" * 40)

    first = Relay(
        tmp_path,
        branch="agent/pc-github-relay",
        live=True,
        poll_seconds=3,
        allowed_actions=set(DEFAULT_ALLOWED_ACTIONS),
    )
    state_path = first.state_dir / "pending-side-effect.json"
    state_path.write_bytes(b'{"status":"started"}\n')
    first.journal_path.write_bytes(b'journal-preserved\n')

    second = Relay(
        tmp_path,
        branch="agent/pc-github-relay",
        live=True,
        poll_seconds=3,
        allowed_actions=set(DEFAULT_ALLOWED_ACTIONS),
    )

    assert second.state_dir == first.state_dir
    assert second.journal_path == first.journal_path
    assert state_path.read_bytes() == b'{"status":"started"}\n'
    assert second.journal_path.read_bytes() == b'journal-preserved\n'


def test_status_artifact_sanitizes_secret_like_error_and_preserves_recovery_invariants(
    monkeypatch,
    tmp_path: Path,
) -> None:
    now = 60_000.0
    snapshot = _health(now=now)
    snapshot["last_error"] = (
        "fatal https://super-secret@github.com/repo "
        "authorization=never-show"
    )
    monkeypatch.setattr(relay_module, "_git_head", lambda *args, **kwargs: "a" * 40)
    monkeypatch.setattr(relay_module, "_git_head_relation", lambda *args, **kwargs: "equal")
    monkeypatch.setattr(
        relay_module,
        "_tree_queue_counts",
        lambda *args, **kwargs: {"request_count": 1, "result_count": 1, "backlog_count": 0},
    )

    status = build_watchdog_status(
        tmp_path,
        snapshot=snapshot,
        observed_processes=["15056:4612", "4612:1000"],
        now_unix=now,
    )
    rendered = json.dumps(status, sort_keys=True).casefold()

    assert "super-secret" not in rendered
    assert "never-show" not in rendered
    assert status["recovery"]["automatic_restart"] is False
    assert status["recovery"]["automatic_kill"] is False
    assert status["recovery"]["automatic_side_effect_replay"] is False
    assert status["recovery"]["unknown_side_effect_requires_outcome_lookup"] is True


def test_bounded_error_redacts_url_userinfo_and_auth_values() -> None:
    rendered = _bounded_error(
        "fatal https://abc123@github.com/repo authorization=xyz password=hunter2"
    )
    assert "abc123" not in rendered
    assert "xyz" not in rendered
    assert "hunter2" not in rendered
    assert "<redacted>" in rendered


def test_launcher_has_no_automatic_stale_process_termination() -> None:
    root = Path(__file__).resolve().parents[1]
    text = (root / "tools" / "start_pc_control_relay.ps1").read_text(
        encoding="utf-8"
    )
    folded = text.casefold()
    assert "--observed-process" in text
    assert "ParentProcessId" in text
    assert "Stop-Process" not in text
    assert "taskkill" not in folded
    assert "outcome.lookup" in text
    assert "No process was killed or restarted automatically." in text


def test_watchdog_conformance_persists_future_attachment_handoff_safety_rule() -> None:
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads(
        (
            root
            / "conformance"
            / "pc_relay.watchdog_status.v1"
            / "manifest.json"
        ).read_text(encoding="utf-8")
    )
    attachment = manifest["future_attachment_handoff"]
    assert attachment["bounded_and_journaled_required"] is True
    assert attachment["unknown_upload_requires_reconciliation"] is True
    assert attachment["blind_large_upload_retry_allowed"] is False
    assert attachment["direct_chat_single_file_max_bytes"] == 500_000_000
    assert manifest["release_gate"] == "NO_LIVE_CUTOVER"


def _git_blob_sha(root: Path, relative: str) -> str:
    return subprocess.check_output(
        ["git", "rev-parse", f"HEAD:{relative}"],
        cwd=root,
        text=True,
    ).strip()


def test_watchdog_and_health_schemas_expose_required_progress_fields() -> None:
    root = Path(__file__).resolve().parents[1]
    health = json.loads(
        (root / "conformance" / "pc_relay.health.v1" / "schema.json")
        .read_text(encoding="utf-8")
    )
    watchdog = json.loads(
        (root / "conformance" / "pc_relay.watchdog_status.v1" / "schema.json")
        .read_text(encoding="utf-8")
    )

    assert health["$id"] == HEALTH_VERSION
    assert {
        "last_fetch_success_at_unix",
        "last_sync_at_unix",
        "last_cycle_completed_at_unix",
        "last_request_processed_at_unix",
        "last_request_processed_id",
        "last_result_published_at_unix",
        "last_result_published_id",
        "local_head",
        "remote_head",
        "remote_head_observed_at_unix",
        "backlog_count",
        "last_backlog_change_at_unix",
        "backlog_high_watermark",
        "reconciliation_required",
    } <= set(health["required"])
    assert "request_processed" in health["properties"]["phase"]["enum"]
    assert watchdog["$id"] == "pc_relay.watchdog_status.v1"
    assert {
        "PROCESS_MISSING",
        "PROCESS_EXISTS",
        "HEALTHY",
        "STALE",
        "RECONCILIATION_REQUIRED",
        "DUPLICATE_AMBIGUOUS",
    } == set(watchdog["properties"]["state"]["enum"])


def test_conformance_manifests_pin_current_producer_blobs() -> None:
    root = Path(__file__).resolve().parents[1]
    manifests = [
        json.loads(
            (root / "conformance" / "pc_relay.health.v1" / "manifest.json")
            .read_text(encoding="utf-8")
        ),
        json.loads(
            (root / "conformance" / "pc_relay.watchdog_status.v1" / "manifest.json")
            .read_text(encoding="utf-8")
        ),
    ]

    for manifest in manifests:
        blobs = manifest["producer_blobs"]
        for item in blobs.values():
            assert _git_blob_sha(root, item["path"]) == item["git_blob_sha1"], item["path"]


def test_status_probe_does_not_perform_network_fetch_or_queue_mutation(
    monkeypatch,
    tmp_path: Path,
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run_git(repo, *args, check=True):
        calls.append(tuple(args))
        if args[:2] == ("rev-parse", "HEAD"):
            return subprocess.CompletedProcess([], 0, "a" * 40 + "\n", "")
        if args[:2] == ("rev-parse", "origin/agent/pc-github-relay"):
            return subprocess.CompletedProcess([], 0, "a" * 40 + "\n", "")
        if args[:2] == ("ls-tree", "-r"):
            return subprocess.CompletedProcess([], 0, "", "")
        raise AssertionError(f"unexpected git operation from status: {args}")

    monkeypatch.setattr(relay_module, "_run_git", fake_run_git)
    snapshot = _health(now=70_000.0)
    status = build_watchdog_status(
        tmp_path,
        snapshot=snapshot,
        observed_processes=["15056:4612", "4612:1000"],
        now_unix=70_000.0,
    )

    assert status["state"] == "HEALTHY"
    assert all(call[0] not in {"fetch", "pull", "push", "reset", "checkout", "rebase"} for call in calls)
    assert status["observations"]["remote_observation_source"] == (
        "local_remote_tracking_ref_no_network"
    )
