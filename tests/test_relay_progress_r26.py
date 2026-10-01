from __future__ import annotations

import argparse
import json
import subprocess
import time
from collections import Counter
from pathlib import Path

import pytest

import pc_relay.progress as progress_module
import tools.github_relay as relay_module
from pc_executor.models import ActionRequest
from pc_relay.progress import (
    LIVENESS_VERSION,
    MAX_BATCH_PER_CYCLE,
    PROGRESS_VERSION,
    RelayProgress,
    classify_error,
    liveness_probe,
    load_progress,
)
from tools.github_relay import (
    DEFAULT_ALLOWED_ACTIONS,
    READ_ONLY_ACTIONS,
    REQUEST_VERSION,
    RESULT_VERSION,
    Relay,
    RelayTransportError,
    _abort_stale_rebase,
    _git_retry,
)


class FakeResult:
    def __init__(self, payload: dict) -> None:
        self.payload = payload

    def to_dict(self) -> dict:
        return json.loads(json.dumps(self.payload))


class CountingExecutor:
    def __init__(self) -> None:
        self.calls: Counter[str] = Counter()
        self.side_effects: Counter[str] = Counter()
        self.lookups = 0

    def execute(self, request: ActionRequest) -> FakeResult:
        if request.action == "outcome.lookup":
            self.lookups += 1
            return FakeResult(
                {
                    "request_id": request.request_id,
                    "action": request.action,
                    "ok": True,
                    "status": "ok",
                    "data": {
                        "outcome_evidence": {
                            "effect_state": "unknown",
                            "replay_authorized": False,
                        }
                    },
                }
            )
        self.calls[request.request_id] += 1
        if request.action not in READ_ONLY_ACTIONS:
            self.side_effects[request.request_id] += 1
        return FakeResult(
            {
                "request_id": request.request_id,
                "action": request.action,
                "ok": True,
                "status": "ok",
                "data": {"synthetic": True},
            }
        )


class IsolatedRelay(Relay):
    """No network/Git mutation: deterministic queue semantics only."""

    def __init__(
        self,
        repo: Path,
        *,
        executor: CountingExecutor,
        fail_sync_epochs: set[int] | None = None,
        fail_publish_once: set[str] | None = None,
    ) -> None:
        self.commit_counts: Counter[str] = Counter()
        self._committed: set[str] = set()
        self._uncommitted: set[str] = set()
        self._failed_publish: set[str] = set()
        self._fail_sync_epochs = set(fail_sync_epochs or set())
        self._failed_sync_epochs: set[int] = set()
        self._fail_publish_once = set(fail_publish_once or set())
        super().__init__(
            repo,
            branch="agent/r26-isolated-test",
            live=True,
            poll_seconds=0.5,
            allowed_actions=set(DEFAULT_ALLOWED_ACTIONS),
            executor=executor,
            sleep_fn=lambda _value: None,
        )

    def sync(self) -> None:
        epoch = self.progress.snapshot()["loop_epoch"]
        self.progress.state("fetching")
        if epoch in self._fail_sync_epochs and epoch not in self._failed_sync_epochs:
            self._failed_sync_epochs.add(epoch)
            raise RelayTransportError(
                {
                    "classification": "transient_network",
                    "retryable": True,
                    "operation": "fetch",
                    "returncode": 128,
                    "message": "synthetic temporary network failure",
                }
            )
        self.progress.fetch_success(remote_head="f" * 40)
        self.progress.state("rebasing")

    def _publish_pending_results(self) -> None:
        self.progress.state("publishing_pending")
        for request_id in sorted(tuple(self._uncommitted)):
            result = json.loads(
                self._result_path(request_id).read_text(encoding="utf-8")
            )
            self.publish_result(result)

    def publish_result(self, result: dict) -> None:
        request_id = result["id"]
        result_path = self._result_path(request_id)
        if not result_path.exists():
            result_path.parent.mkdir(parents=True, exist_ok=True)
            result_path.write_text(
                json.dumps(result, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        self.progress.state("publishing")
        if (
            request_id in self._fail_publish_once
            and request_id not in self._failed_publish
        ):
            self._failed_publish.add(request_id)
            self._uncommitted.add(request_id)
            raise RelayTransportError(
                {
                    "classification": "transient_network",
                    "retryable": True,
                    "operation": "push",
                    "returncode": 128,
                    "message": "synthetic temporary push failure",
                }
            )
        if request_id not in self._committed:
            self._committed.add(request_id)
            self._uncommitted.discard(request_id)
            self.commit_counts[request_id] += 1
            self.progress.result_committed(
                request_id,
                commit_sha=f"{len(self._committed):040x}",
            )


def _request_file(repo: Path, request_id: str, *, action: str = "shell.run") -> Path:
    path = repo / "relay" / "requests" / f"{request_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    params = (
        {"argv": ["python", "-c", "print('synthetic')"]}
        if action == "shell.run"
        else {}
    )
    path.write_text(
        json.dumps(
            {
                "version": REQUEST_VERSION,
                "id": request_id,
                "action": action,
                "params": params,
                "timeout_ms": 1000,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _fast_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")


def test_progress_contract_has_source_process_loop_queue_and_bounded_errors(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(progress_module, "_atomic_json", _fast_atomic)
    now = [1000.0]
    progress = RelayProgress(
        tmp_path / "progress.json",
        branch="agent/test",
        startup_head="a" * 40,
        relay_script_sha256="b" * 64,
        poll_seconds=3.0,
        clock=lambda: now[0],
        pid=4321,
        instance_id="instance",
        generation_id="generation",
    )
    progress.start_cycle()
    now[0] += 1
    progress.fetch_success(remote_head="c" * 40)
    progress.queue_metrics(
        pending_count=2,
        oldest_pending_request_id="req-1",
        oldest_pending_age_seconds=8.0,
    )
    progress.request_observed("req-1", action="shell.run", timeout_ms=5000)
    progress.result_committed("req-1", commit_sha="d" * 40)
    progress.cycle_success()

    record = load_progress(tmp_path / "progress.json")
    assert record is not None
    assert record["contract_version"] == PROGRESS_VERSION
    assert record["source"]["repository"] == "foto6/help-pc-1"
    assert record["process"]["pid"] == 4321
    assert record["loop_generation_id"] == "generation"
    assert record["loop_epoch"] == 1
    assert record["last_fetch_success"]["remote_head"] == "c" * 40
    assert record["last_request_observed"]["id"] == "req-1"
    assert record["last_result_committed"]["id"] == "req-1"
    assert record["last_successful_cycle_at_unix"] == now[0]
    assert record["queue"]["pending_count"] == 2
    assert record["current_cycle"]["state"] == "sleeping"

    error = classify_error(
        "fatal: unable to access https://secret-token@github.com/repo: connection timed out",
        operation="fetch",
        returncode=128,
    )
    progress.cycle_failure(error)
    failed = progress.snapshot()
    assert failed["last_error"]["classification"] == "transient_network"
    assert "secret-token" not in failed["last_error"]["message"]
    assert len(failed["last_error"]["message"]) <= 512


def test_alive_process_with_no_queue_progress_is_stalled_not_healthy(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(progress_module, "_atomic_json", _fast_atomic)
    now = [2000.0]
    store = RelayProgress(
        tmp_path / "progress.json",
        branch="agent/test",
        startup_head="a" * 40,
        relay_script_sha256="b" * 64,
        poll_seconds=3,
        clock=lambda: now[0],
        pid=700,
        generation_id="gen-stall",
    )
    store.start_cycle()
    store.queue_metrics(
        pending_count=1,
        oldest_pending_request_id="pending-1",
        oldest_pending_age_seconds=0,
    )
    store.cycle_success()
    now[0] += 20
    # The process is still actively cycling/heartbeating, but no pending
    # request has produced a committed result during the stall window.
    store.start_cycle()
    store.queue_metrics(
        pending_count=1,
        oldest_pending_request_id="pending-1",
        oldest_pending_age_seconds=20,
    )
    store.cycle_success()

    probe = liveness_probe(
        store.snapshot(),
        observed_pids=[700],
        expected_pid=700,
        now=now[0],
        stall_seconds=15,
    )

    assert probe["contract_version"] == LIVENESS_VERSION
    assert probe["state"] == "alive_stalled"
    assert probe["reason"] == "pending_queue_has_no_result_progress"
    assert probe["pending_count"] == 1


def test_repeated_fetch_failures_eventually_classify_alive_stalled(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(progress_module, "_atomic_json", _fast_atomic)
    now = [3000.0]
    store = RelayProgress(
        tmp_path / "progress.json",
        branch="agent/test",
        startup_head="a" * 40,
        relay_script_sha256="b" * 64,
        poll_seconds=3,
        clock=lambda: now[0],
        pid=701,
    )
    store.start_cycle()
    store.cycle_success()
    for _ in range(3):
        now[0] += 6
        store.start_cycle()
        store.cycle_failure(
            {
                "classification": "transient_network",
                "retryable": True,
                "operation": "fetch",
                "message": "temporary network",
                "returncode": 128,
            }
        )

    probe = liveness_probe(
        store.snapshot(),
        observed_pids=[701],
        now=now[0],
        stall_seconds=15,
    )
    assert probe["state"] == "alive_stalled"
    assert probe["reason"] == "no_successful_cycle_with_repeated_failures"
    assert probe["consecutive_cycle_failures"] == 3


@pytest.mark.parametrize(
    ("observed", "expected", "state"),
    [
        ([800], 800, "healthy_progressing"),
        ([800, 801], None, "duplicate_processes_ambiguous"),
        ([999], 999, "alive_ambiguous_identity"),
        ([], None, "stale_record_no_process"),
    ],
)
def test_launcher_liveness_distinguishes_progress_duplicate_and_stale_identity(
    tmp_path: Path,
    monkeypatch,
    observed,
    expected,
    state,
) -> None:
    monkeypatch.setattr(progress_module, "_atomic_json", _fast_atomic)
    now = [4000.0]
    store = RelayProgress(
        tmp_path / "progress.json",
        branch="agent/test",
        startup_head="a" * 40,
        relay_script_sha256="b" * 64,
        poll_seconds=3,
        clock=lambda: now[0],
        pid=800,
    )
    store.start_cycle()
    store.cycle_success()
    probe = liveness_probe(
        store.snapshot(),
        observed_pids=observed,
        expected_pid=expected,
        now=now[0] + 1,
        stall_seconds=15,
    )
    assert probe["state"] == state


def test_git_fetch_retries_are_bounded_and_eventually_recover(
    monkeypatch,
    tmp_path: Path,
) -> None:
    calls: list[tuple[str, ...]] = []
    responses = [
        subprocess.CompletedProcess([], 128, "", "fatal: connection timed out"),
        subprocess.CompletedProcess([], 128, "", "fatal: connection reset"),
        subprocess.CompletedProcess([], 0, "ok", ""),
    ]

    def fake_run_git(repo, *args, check=True):
        calls.append(args)
        return responses.pop(0)

    sleeps: list[float] = []
    monkeypatch.setattr(relay_module, "_run_git", fake_run_git)
    result = _git_retry(
        tmp_path,
        "fetch",
        "origin",
        "branch",
        operation="fetch",
        attempts=3,
        sleep_fn=sleeps.append,
    )

    assert result.returncode == 0
    assert len(calls) == 3
    assert sleeps == [0.25, 0.5]


def test_git_fetch_retry_exhaustion_is_explicit_and_bounded(
    monkeypatch,
    tmp_path: Path,
) -> None:
    calls = 0

    def fake_run_git(repo, *args, check=True):
        nonlocal calls
        calls += 1
        return subprocess.CompletedProcess(
            [], 128, "", "fatal: network is unreachable"
        )

    monkeypatch.setattr(relay_module, "_run_git", fake_run_git)
    with pytest.raises(RelayTransportError) as caught:
        _git_retry(
            tmp_path,
            "fetch",
            "origin",
            "branch",
            operation="fetch",
            attempts=3,
            sleep_fn=lambda _value: None,
        )
    assert calls == 3
    assert caught.value.error["classification"] == "transient_network"
    assert caught.value.error["retryable"] is True


def test_recover_local_ahead_commit_pushes_without_duplicate_commit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(progress_module, "_atomic_json", _fast_atomic)
    progress = RelayProgress(
        tmp_path / "progress.json",
        branch="agent/test",
        startup_head="a" * 40,
        relay_script_sha256="b" * 64,
        poll_seconds=3,
        pid=900,
    )
    relay = Relay.__new__(Relay)
    relay.repo = tmp_path
    relay.branch = "agent/test"
    relay.progress = progress
    relay.sleep_fn = lambda _value: None

    pushes = 0
    commits = 0

    def fake_run_git(repo, *args, check=True):
        nonlocal pushes, commits
        if args[:2] == ("rev-list", "--count"):
            return subprocess.CompletedProcess([], 0, "1\n", "")
        if args[:2] == ("log", "-1"):
            return subprocess.CompletedProcess(
                [], 0, f"{'c' * 40}\x00relay result ahead-result\n", ""
            )
        if args and args[0] == "push":
            pushes += 1
            if pushes == 1:
                return subprocess.CompletedProcess(
                    [], 128, "", "fatal: connection timed out"
                )
            return subprocess.CompletedProcess([], 0, "", "")
        if "commit" in args:
            commits += 1
        raise AssertionError(f"unexpected git call: {args}")

    monkeypatch.setattr(relay_module, "_run_git", fake_run_git)

    relay._recover_local_ahead_commits()

    assert pushes == 2
    assert commits == 0
    assert progress.snapshot()["last_result_committed"]["id"] == "ahead-result"


def test_rebase_conflict_is_bounded_and_requires_manual_reconciliation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run_git(repo, *args, check=True):
        calls.append(args)
        if args[:2] == ("rev-parse", "--git-path"):
            return subprocess.CompletedProcess([], 0, str(tmp_path / args[-1]), "")
        if args and args[0] == "fetch":
            return subprocess.CompletedProcess([], 0, "", "")
        if args[:2] == ("rev-parse", "origin/branch"):
            return subprocess.CompletedProcess([], 0, "d" * 40 + "\n", "")
        if args and args[0] == "rebase" and args[1:] == ("origin/branch",):
            return subprocess.CompletedProcess([], 1, "", "CONFLICT content")
        if args and args[0] == "rebase" and args[1:] == ("--abort",):
            return subprocess.CompletedProcess([], 0, "", "")
        raise AssertionError(f"unexpected git call: {args}")

    monkeypatch.setattr(relay_module, "_run_git", fake_run_git)

    with pytest.raises(RelayTransportError) as caught:
        relay_module._rebase_onto_remote(
            tmp_path,
            "branch",
            sleep_fn=lambda _value: None,
        )

    assert caught.value.error["classification"] == "rebase_conflict"
    assert caught.value.error["retryable"] is False
    assert ("rebase", "--abort") in calls


def test_stale_rebase_marker_is_aborted_in_isolated_git_fixture(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    marker = repo / ".git" / "rebase-merge"
    marker.mkdir(parents=True)

    assert _abort_stale_rebase(repo) is True


def test_queue_scan_keeps_only_bounded_batch_while_reporting_full_lag(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(progress_module, "_atomic_json", _fast_atomic)
    monkeypatch.setattr(relay_module, "_atomic_json", _fast_atomic)
    executor = CountingExecutor()
    relay = IsolatedRelay(tmp_path, executor=executor)
    for index in range(1000):
        _request_file(tmp_path, f"bounded-{index:04d}")

    paths, metrics = relay._queue_snapshot()

    assert len(paths) == MAX_BATCH_PER_CYCLE == 64
    assert metrics["pending_count"] == 1000
    assert paths[0].name == "bounded-0000.json"
    assert paths[-1].name == "bounded-0063.json"


def test_1000_request_cycle_chaos_soak_has_no_loss_duplicate_commit_or_effect(
    tmp_path: Path,
    monkeypatch,
) -> None:
    # Synthetic soak intentionally replaces fsync with bounded fixture writes;
    # production atomicity is exercised by the normal relay implementation.
    monkeypatch.setattr(progress_module, "_atomic_json", _fast_atomic)
    monkeypatch.setattr(relay_module, "_atomic_json", _fast_atomic)
    executor = CountingExecutor()
    relay = IsolatedRelay(
        tmp_path,
        executor=executor,
        fail_sync_epochs={17, 251, 509, 777},
        fail_publish_once={
            "soak-0123",
            "soak-0456",
            "soak-0789",
        },
    )

    logical_requests = 1000
    cycle_attempts = 0
    for index in range(logical_requests):
        request_id = f"soak-{index:04d}"
        path = _request_file(tmp_path, request_id)
        completed = False
        while not completed:
            cycle_attempts += 1
            try:
                relay.cycle()
                completed = relay._result_path(request_id).exists() and (
                    request_id in relay._committed
                )
            except RelayTransportError:
                pass
        path.unlink()

    assert cycle_attempts >= logical_requests
    assert len(list((tmp_path / "relay" / "results").glob("*.json"))) == logical_requests
    assert len(relay._committed) == logical_requests
    assert set(relay.commit_counts.values()) == {1}
    assert len(executor.side_effects) == logical_requests
    assert set(executor.side_effects.values()) == {1}
    assert sum(executor.calls.values()) == logical_requests
    assert relay.progress.snapshot()["consecutive_cycle_failures"] == 0
    assert relay.progress.snapshot()["loop_epoch"] == cycle_attempts
    assert (tmp_path / ".pc-relay" / "progress.v1.json").stat().st_size < 64 * 1024


def test_pending_request_survives_restart_with_new_generation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(progress_module, "_atomic_json", _fast_atomic)
    monkeypatch.setattr(relay_module, "_atomic_json", _fast_atomic)
    executor = CountingExecutor()
    path = _request_file(tmp_path, "restart-pending", action="windows.list")

    first = IsolatedRelay(tmp_path, executor=executor)
    generation_one = first.progress.snapshot()["loop_generation_id"]
    second = IsolatedRelay(tmp_path, executor=executor)
    generation_two = second.progress.snapshot()["loop_generation_id"]

    assert generation_one != generation_two
    assert not second._result_path("restart-pending").exists()
    assert second.cycle() == 1
    assert second._result_path("restart-pending").exists()
    assert executor.calls["restart-pending"] == 1
    path.unlink()


def test_interrupted_side_effect_after_restart_remains_reconciliation_only(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(progress_module, "_atomic_json", _fast_atomic)
    monkeypatch.setattr(relay_module, "_atomic_json", _fast_atomic)
    executor = CountingExecutor()
    relay = IsolatedRelay(tmp_path, executor=executor)
    request_path = _request_file(tmp_path, "unknown-side-effect", action="shell.run")
    req = json.loads(request_path.read_text(encoding="utf-8"))
    _fast_atomic(
        relay._state_path("unknown-side-effect"),
        {
            "status": "started",
            "request": req,
            "live": True,
            "started_at_unix": 1.0,
        },
    )

    result = relay.execute_one(request_path)

    assert result["relay_status"] == "interrupted_requires_reconciliation"
    assert result["reexecuted"] is False
    assert result["replay_authorized"] is False
    assert executor.side_effects["unknown-side-effect"] == 0
    assert executor.lookups == 1
    assert relay.commit_counts["unknown-side-effect"] == 1


def test_publish_failure_after_effect_recovers_result_without_reexecution(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(progress_module, "_atomic_json", _fast_atomic)
    monkeypatch.setattr(relay_module, "_atomic_json", _fast_atomic)
    executor = CountingExecutor()
    relay = IsolatedRelay(
        tmp_path,
        executor=executor,
        fail_publish_once={"publish-once"},
    )
    _request_file(tmp_path, "publish-once", action="shell.run")

    with pytest.raises(RelayTransportError):
        relay.cycle()
    assert executor.side_effects["publish-once"] == 1
    assert relay._result_path("publish-once").exists()
    assert relay._state_path("publish-once").exists()

    relay.cycle()

    assert executor.side_effects["publish-once"] == 1
    assert relay.commit_counts["publish-once"] == 1
    assert "publish-once" in relay._committed


def test_launcher_script_uses_progress_health_and_never_auto_kills_ambiguous_process() -> None:
    text = (
        Path(__file__).resolve().parents[1]
        / "tools"
        / "start_pc_control_relay.ps1"
    ).read_text(encoding="utf-8")

    assert "--health" in text
    assert "healthy_progressing" in text
    assert "alive_stalled" in text
    assert "multiple" in text or "ambiguous" in text
    assert "No process was killed or restarted" in text
    assert "Stop-Process" not in text
    assert "taskkill" not in text.casefold()


def test_health_probe_payload_contains_no_request_params_or_environment(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(progress_module, "_atomic_json", _fast_atomic)
    store = RelayProgress(
        tmp_path / ".pc-relay" / "progress.v1.json",
        branch="agent/test",
        startup_head="a" * 40,
        relay_script_sha256="b" * 64,
        poll_seconds=3,
        pid=1234,
    )
    store.start_cycle()
    store.request_observed("safe-id", action="shell.run", timeout_ms=1000)
    store.cycle_success()

    args = argparse.Namespace(
        observed_pid=[1234],
        expected_pid=1234,
        stall_seconds=15.0,
    )
    assert relay_module._health_probe(args, tmp_path) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["probe"]["state"] == "healthy_progressing"
    rendered = json.dumps(payload, sort_keys=True).casefold()
    assert "params" not in rendered
    assert "environment" not in rendered
    assert "authorization" not in rendered
    assert "credential" not in rendered
