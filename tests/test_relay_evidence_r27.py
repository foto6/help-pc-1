from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

import pc_relay.progress as progress_module
from pc_relay.evidence import (
    EVIDENCE_VERSION,
    EvidenceReadError,
    read_progress_evidence,
    validate_evidence_envelope,
)
from pc_relay.progress import RelayProgress


READER_SHA = "a" * 64
MODULE_SHA = "b" * 64
STARTUP_HEAD = "c" * 40
RELAY_SHA = "d" * 64


def _fast_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(
        f".{path.name}.test.{os.getpid()}.{threading.get_ident()}.{time.time_ns()}"
    )
    tmp.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(tmp, path)


def _progress(
    path: Path,
    *,
    clock,
    pid: int = 4100,
    instance_id: str = "instance-a",
    generation_id: str = "generation-a",
) -> RelayProgress:
    return RelayProgress(
        path,
        branch="agent/pc-github-relay",
        startup_head=STARTUP_HEAD,
        relay_script_sha256=RELAY_SHA,
        poll_seconds=3.0,
        clock=clock,
        pid=pid,
        instance_id=instance_id,
        generation_id=generation_id,
    )


def _read(
    path: Path,
    *,
    now: float,
    observed_pids=None,
    expected_pid=None,
    max_age_seconds: float = 30.0,
):
    return read_progress_evidence(
        path,
        reader_script_sha256=READER_SHA,
        evidence_module_sha256=MODULE_SHA,
        observed_pids=observed_pids,
        expected_pid=expected_pid,
        now=now,
        max_age_seconds=max_age_seconds,
        stall_seconds=15.0,
    )


def test_exact_atomic_envelope_binds_source_process_generation_epoch_and_observed_at(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(progress_module, "_atomic_json", _fast_atomic)
    now = [1000.0]
    path = tmp_path / ".pc-relay" / "progress.v1.json"
    writer = _progress(path, clock=lambda: now[0])
    writer.start_cycle()
    now[0] = 1001.0
    writer.fetch_success(remote_head="e" * 40)
    writer.queue_metrics(
        pending_count=1,
        oldest_pending_request_id="pending-001",
        oldest_pending_age_seconds=1.0,
    )
    writer.cycle_success()

    envelope = _read(
        path,
        now=1002.0,
        observed_pids=[4100],
        expected_pid=4100,
    )

    validate_evidence_envelope(envelope)
    assert envelope["contract_version"] == EVIDENCE_VERSION
    assert envelope["status"] == "ok"
    assert envelope["observed_at_unix"] == 1002.0
    assert envelope["binding"] == {
        "relay_startup_head": STARTUP_HEAD,
        "relay_script_sha256": RELAY_SHA,
        "process_pid": 4100,
        "process_started_at_unix": 1000.0,
        "process_instance_id": "instance-a",
        "loop_generation_id": "generation-a",
        "loop_epoch": 1,
        "progress_recorded_at_unix": 1001.0,
    }
    assert envelope["liveness"]["loop_generation_id"] == "generation-a"
    assert envelope["liveness"]["loop_epoch"] == 1
    assert envelope["liveness"]["process_pid"] == 4100
    assert envelope["delivery_semantics"] == {
        "read_only": True,
        "queue_acknowledged": False,
        "lease_created": False,
        "retry_triggered": False,
        "replay_triggered": False,
    }
    assert envelope["progress_sha256"] == hashlib.sha256(
        json.dumps(
            envelope["progress"],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def test_duplicate_process_ambiguity_is_delivered_without_guessing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(progress_module, "_atomic_json", _fast_atomic)
    now = [2000.0]
    path = tmp_path / ".pc-relay" / "progress.v1.json"
    writer = _progress(path, clock=lambda: now[0], pid=5100)
    writer.start_cycle()
    writer.cycle_success()

    envelope = _read(
        path,
        now=2001.0,
        observed_pids=[5100, 5101],
    )

    assert envelope["status"] == "ok"
    assert envelope["liveness"]["state"] == "duplicate_processes_ambiguous"
    assert envelope["liveness"]["reason"] == "multiple_matching_relay_processes"
    assert envelope["binding"]["process_pid"] == 5100


def test_restart_changes_process_instance_and_loop_generation_atomically(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(progress_module, "_atomic_json", _fast_atomic)
    now = [3000.0]
    path = tmp_path / ".pc-relay" / "progress.v1.json"

    first = _progress(
        path,
        clock=lambda: now[0],
        pid=6100,
        instance_id="instance-one",
        generation_id="generation-one",
    )
    first.start_cycle()
    first.cycle_success()
    before = _read(path, now=3001.0, observed_pids=[6100])

    now[0] = 3010.0
    second = _progress(
        path,
        clock=lambda: now[0],
        pid=6200,
        instance_id="instance-two",
        generation_id="generation-two",
    )
    second.start_cycle()
    second.cycle_success()
    after = _read(path, now=3011.0, observed_pids=[6200])

    assert before["binding"]["process_instance_id"] == "instance-one"
    assert before["binding"]["loop_generation_id"] == "generation-one"
    assert after["binding"]["process_instance_id"] == "instance-two"
    assert after["binding"]["loop_generation_id"] == "generation-two"
    assert after["liveness"]["loop_generation_id"] == "generation-two"
    assert after["liveness"]["loop_epoch"] == after["binding"]["loop_epoch"]
    assert before["evidence_sha256"] != after["evidence_sha256"]


@pytest.mark.parametrize(
    ("raw", "classification"),
    [
        (b'{"contract_version":"pc_relay.progress.v1"', "invalid_json"),
        (
            json.dumps(
                {
                    "contract_version": "pc_relay.progress.v999",
                    "source": {},
                }
            ).encode("utf-8"),
            "unknown_version",
        ),
        (
            json.dumps(
                {
                    "contract_version": "pc_relay.progress.v1",
                    "schema_drift": True,
                }
            ).encode("utf-8"),
            "schema_invalid",
        ),
    ],
)
def test_torn_unknown_version_and_schema_drift_fail_closed(
    tmp_path: Path,
    raw: bytes,
    classification: str,
) -> None:
    path = tmp_path / ".pc-relay" / "progress.v1.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(raw)

    envelope = _read(path, now=4000.0)

    validate_evidence_envelope(envelope)
    assert envelope["status"] == "blocked"
    assert envelope["error"]["classification"] == classification
    assert envelope["progress"] is None
    assert envelope["liveness"] is None
    assert envelope["binding"] is None


def test_missing_and_oversized_snapshot_fail_closed_with_bounded_errors(
    tmp_path: Path,
) -> None:
    missing = _read(tmp_path / "missing.json", now=5000.0)
    assert missing["status"] == "blocked"
    assert missing["error"]["classification"] == "missing_snapshot"

    path = tmp_path / ".pc-relay" / "progress.v1.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"x" * (64 * 1024 + 1))
    oversized = _read(path, now=5000.0)
    assert oversized["status"] == "blocked"
    assert oversized["error"]["classification"] == "oversized_snapshot"
    assert len(oversized["error"]["reason"]) <= 256


def test_stale_and_future_snapshots_fail_closed_but_bounded_execution_deadline_is_valid(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(progress_module, "_atomic_json", _fast_atomic)
    now = [6000.0]
    path = tmp_path / ".pc-relay" / "progress.v1.json"
    writer = _progress(path, clock=lambda: now[0])
    writer.start_cycle()
    writer.cycle_success()

    stale = _read(path, now=6040.0, max_age_seconds=30.0)
    assert stale["status"] == "blocked"
    assert stale["error"]["classification"] == "stale_snapshot"

    future = _read(path, now=5990.0, max_age_seconds=30.0)
    assert future["status"] == "blocked"
    assert future["error"]["classification"] == "future_snapshot"

    now[0] = 6100.0
    executing = _progress(
        path,
        clock=lambda: now[0],
        pid=4100,
        instance_id="exec-instance",
        generation_id="exec-generation",
    )
    executing.start_cycle()
    executing.request_observed(
        "long-readonly",
        action="uia.snapshot",
        timeout_ms=120_000,
    )
    bounded = _read(path, now=6160.0, max_age_seconds=30.0)
    assert bounded["status"] == "ok"
    assert bounded["progress"]["current_cycle"]["state"] == "executing"


def test_source_identity_unknown_startup_head_fails_closed(
    tmp_path: Path,
) -> None:
    path = tmp_path / ".pc-relay" / "progress.v1.json"
    path.parent.mkdir(parents=True)
    payload = {
        "contract_version": "pc_relay.progress.v1",
        "source": {
            "repository": "foto6/help-pc-1",
            "branch": "agent/test",
            "startup_head": "unknown",
            "relay_script_sha256": RELAY_SHA,
        },
        "process": {
            "pid": 7000,
            "started_at_unix": 7000.0,
            "instance_id": "i",
        },
        "loop_generation_id": "g",
        "loop_epoch": 1,
        "last_fetch_success": None,
        "last_request_observed": None,
        "last_result_committed": None,
        "last_successful_cycle_at_unix": 7000.0,
        "consecutive_cycle_failures": 0,
        "queue": {
            "pending_count": 0,
            "oldest_pending_request_id": None,
            "oldest_pending_age_seconds": None,
            "last_progress_at_unix": 7000.0,
        },
        "current_cycle": {
            "state": "sleeping",
            "started_at_unix": 7000.0,
            "updated_at_unix": 7000.0,
            "deadline_at_unix": None,
        },
        "last_error": None,
        "limits": {
            "max_batch_per_cycle": 64,
            "max_error_chars": 512,
            "poll_seconds": 3.0,
        },
        "recorded_at_unix": 7000.0,
    }
    path.write_text(json.dumps(payload), encoding="utf-8")

    envelope = _read(path, now=7001.0)

    assert envelope["status"] == "blocked"
    assert envelope["error"]["classification"] == "source_identity_invalid"


def test_pending_unknown_effect_state_is_not_read_acknowledged_retried_or_replayed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(progress_module, "_atomic_json", _fast_atomic)
    now = [8000.0]
    runtime = tmp_path / ".pc-relay"
    path = runtime / "progress.v1.json"
    writer = _progress(path, clock=lambda: now[0])
    writer.start_cycle()
    writer.request_observed(
        "unknown-effect-001",
        action="shell.run",
        timeout_ms=120_000,
    )

    state_path = runtime / "state" / "unknown-effect-001.json"
    state_path.parent.mkdir(parents=True)
    secret_marker = "DO-NOT-EXPOSE-RAW-COMMAND"
    state_payload = {
        "status": "started",
        "request": {
            "id": "unknown-effect-001",
            "action": "shell.run",
            "params": {"argv": ["powershell.exe", "-Command", secret_marker]},
        },
        "live": True,
    }
    state_path.write_text(
        json.dumps(state_payload, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    before = state_path.read_bytes()
    progress_before = path.read_bytes()

    envelope = _read(
        path,
        now=8001.0,
        observed_pids=[4100],
        expected_pid=4100,
    )

    assert envelope["status"] == "ok"
    assert envelope["progress"]["last_request_observed"] == {
        "id": "unknown-effect-001",
        "action": "shell.run",
        "at_unix": 8000.0,
    }
    assert envelope["delivery_semantics"]["queue_acknowledged"] is False
    assert envelope["delivery_semantics"]["lease_created"] is False
    assert envelope["delivery_semantics"]["retry_triggered"] is False
    assert envelope["delivery_semantics"]["replay_triggered"] is False
    assert state_path.read_bytes() == before
    assert path.read_bytes() == progress_before
    assert secret_marker not in json.dumps(envelope)


def test_concurrent_atomic_writer_reader_never_mixes_generation_or_epoch(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(progress_module, "_atomic_json", _fast_atomic)
    path = tmp_path / ".pc-relay" / "progress.v1.json"
    writer = _progress(
        path,
        clock=time.time,
        pid=8100,
        instance_id="concurrent-instance",
        generation_id="concurrent-generation",
    )
    stop = threading.Event()
    errors: list[BaseException] = []

    def mutate() -> None:
        try:
            for index in range(200):
                writer.start_cycle()
                writer.queue_metrics(
                    pending_count=index % 7,
                    oldest_pending_request_id=(
                        None if index % 7 == 0 else f"p-{index:04d}"
                    ),
                    oldest_pending_age_seconds=float(index % 11),
                )
                writer.cycle_success()
        except BaseException as exc:
            errors.append(exc)
        finally:
            stop.set()

    thread = threading.Thread(target=mutate, daemon=True)
    thread.start()
    reads = 0
    while reads < 1000 or not stop.is_set():
        envelope = read_progress_evidence(
            path,
            reader_script_sha256=READER_SHA,
            evidence_module_sha256=MODULE_SHA,
            observed_pids=[8100],
            expected_pid=8100,
            max_age_seconds=30.0,
        )
        assert envelope["status"] == "ok", envelope
        validate_evidence_envelope(envelope)
        assert (
            envelope["progress"]["loop_generation_id"]
            == envelope["liveness"]["loop_generation_id"]
            == envelope["binding"]["loop_generation_id"]
        )
        assert (
            envelope["progress"]["loop_epoch"]
            == envelope["liveness"]["loop_epoch"]
            == envelope["binding"]["loop_epoch"]
        )
        reads += 1
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert errors == []
    assert reads >= 1000


def test_1000_read_soak_is_side_effect_free_and_bounded(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(progress_module, "_atomic_json", _fast_atomic)
    now = [9000.0]
    runtime = tmp_path / ".pc-relay"
    path = runtime / "progress.v1.json"
    writer = _progress(path, clock=lambda: now[0], pid=9100)
    writer.start_cycle()
    writer.queue_metrics(
        pending_count=3,
        oldest_pending_request_id="soak-pending",
        oldest_pending_age_seconds=2.0,
    )
    writer.cycle_success()

    requests = tmp_path / "relay" / "requests"
    results = tmp_path / "relay" / "results"
    state = runtime / "state"
    for directory in (requests, results, state):
        directory.mkdir(parents=True, exist_ok=True)
    sentinel_paths = [
        requests / "pending.json",
        results / "existing.json",
        state / "unknown.json",
    ]
    for index, sentinel in enumerate(sentinel_paths):
        sentinel.write_bytes(f"sentinel-{index}".encode("ascii"))
    before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in sentinel_paths}
    progress_before = (path.read_bytes(), path.stat().st_mtime_ns)

    max_encoded = 0
    for _index in range(1000):
        envelope = _read(
            path,
            now=9001.0,
            observed_pids=[9100],
            expected_pid=9100,
        )
        assert envelope["status"] == "ok"
        validate_evidence_envelope(envelope)
        max_encoded = max(
            max_encoded,
            len(json.dumps(envelope, sort_keys=True).encode("utf-8")),
        )

    after = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in sentinel_paths}
    assert after == before
    assert (path.read_bytes(), path.stat().st_mtime_ns) == progress_before
    assert max_encoded < 128 * 1024


def test_stdio_reader_emits_one_strict_envelope_and_no_queue_mutation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(progress_module, "_atomic_json", _fast_atomic)
    now = [time.time()]
    path = tmp_path / ".pc-relay" / "progress.v1.json"
    writer = _progress(path, clock=lambda: now[0], pid=10100)
    writer.start_cycle()
    writer.cycle_success()
    progress_before = path.read_bytes()

    root = Path(__file__).resolve().parents[1]
    proc = subprocess.run(
        [
            sys.executable,
            str(root / "tools" / "read_relay_progress_evidence.py"),
            "--repo",
            str(tmp_path),
            "--observed-pid",
            "10100",
            "--expected-pid",
            "10100",
        ],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == ""
    assert len(proc.stdout.splitlines()) == 1
    envelope = json.loads(proc.stdout)
    validate_evidence_envelope(envelope)
    assert envelope["status"] == "ok"
    assert envelope["liveness"]["state"] == "healthy_progressing"
    assert path.read_bytes() == progress_before


def test_stdio_reader_blocked_exit_is_explicit_and_does_not_echo_corrupt_content(
    tmp_path: Path,
) -> None:
    progress_path = tmp_path / ".pc-relay" / "progress.v1.json"
    progress_path.parent.mkdir(parents=True)
    secret = "AUTHORIZATION=super-secret-never-echo"
    progress_path.write_text(
        '{"contract_version":"pc_relay.progress.v1","x":"' + secret,
        encoding="utf-8",
    )
    root = Path(__file__).resolve().parents[1]
    proc = subprocess.run(
        [
            sys.executable,
            str(root / "tools" / "read_relay_progress_evidence.py"),
            "--repo",
            str(tmp_path),
        ],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )

    assert proc.returncode == 2
    assert proc.stderr == ""
    envelope = json.loads(proc.stdout)
    assert envelope["status"] == "blocked"
    assert envelope["error"]["classification"] == "invalid_json"
    assert secret not in proc.stdout
