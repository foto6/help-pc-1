from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from pc_executor.safety import DEFAULT_SAFE_EXECUTABLES, SafetyViolation
from pc_executor.shell import SafeShellAdapter
from tools.pc_relay import (
    DEFAULT_ALLOWED_ACTIONS,
    HEARTBEAT_VERSION,
    MAX_REQUEST_BYTES,
    QUEUE_PROTOCOL_VERSION,
    RELAY_SHELL_EXECUTABLES,
    REQUEST_VERSION,
    RESULT_VERSION,
    SHELL_OUTPUT_LIMIT_BYTES,
    GitQueue,
    QueueConflictError,
    QueueForcePushError,
    Relay,
    RequestValidationError,
    STATE_VERSION,
    make_result,
    request_digest,
    validate_request,
)


class FakeExecutor:
    def __init__(self, *, outcome: str = "not_started") -> None:
        self.execute_calls = 0
        self.lookup_calls = 0
        self.outcome = outcome

    def execute(self, request):
        self.execute_calls += 1
        return {
            "request_id": request.request_id,
            "action": request.action,
            "ok": True,
            "status": "ok",
            "data": {"stdout": "ok", "stderr": ""},
        }

    def read_outcome_evidence(self, *, request_id, action, execution_attempt=None):
        self.lookup_calls += 1
        return {
            "contract_version": "pc_executor.outcome_journal.lookup.v1",
            "request_id": request_id,
            "action": action,
            "execution_attempt": execution_attempt,
            "outcome": self.outcome,
            "reason": f"fixture_{self.outcome}",
            "replay_authorized": False,
        }


class FakeQueue:
    queue_ref = "agent/pc-relay-queue"

    def __init__(self, root: Path) -> None:
        self.repo = root
        self.requests_dir = root / "relay" / "requests"
        self.results_dir = root / "relay" / "results"
        self.requests_dir.mkdir(parents=True)
        self.results_dir.mkdir(parents=True)
        self.results: dict[str, dict] = {}
        self.quarantine: list[dict] = []
        self.heartbeats: list[dict] = []
        self.publish_failures = 0
        self.sync_shas = ["a" * 40]

    def sync(self) -> str:
        if len(self.sync_shas) > 1:
            return self.sync_shas.pop(0)
        return self.sync_shas[0]

    def read_result(self, request_id: str):
        return self.results.get(request_id)

    def publish_result(self, result):
        if self.publish_failures:
            self.publish_failures -= 1
            raise QueueConflictError("fixture publication failure")
        existing = self.results.get(result["id"])
        if existing is not None and existing != dict(result):
            raise QueueConflictError("fixture conflicting result")
        self.results[result["id"]] = dict(result)

    def publish_quarantine(self, metadata):
        self.quarantine.append(dict(metadata))

    def publish_heartbeat(self, heartbeat_id, payload):
        assert heartbeat_id == "fixture"
        self.heartbeats.append(dict(payload))


def _request(
    request_id: str = "req-001",
    *,
    action: str = "shell.run",
    params: dict | None = None,
    timeout_ms: int = 5000,
    note: str | None = None,
) -> dict:
    if params is None:
        params = {
            "argv": [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                "Write-Output ok",
            ],
            "cwd": "C:\\",
        }
    raw = {
        "version": REQUEST_VERSION,
        "id": request_id,
        "action": action,
        "params": params,
        "timeout_ms": timeout_ms,
        "note": note,
    }
    raw["request_sha256"] = request_digest(raw)
    return raw


def _write_request(queue: FakeQueue, raw: dict) -> Path:
    path = queue.requests_dir / f"{raw['id']}.json"
    path.write_text(json.dumps(raw, sort_keys=True), encoding="utf-8")
    return path


def _relay(tmp_path: Path, *, outcome: str = "not_started"):
    queue = FakeQueue(tmp_path / "queue")
    executor = FakeExecutor(outcome=outcome)
    relay = Relay(
        queue=queue,
        state_root=tmp_path / "state",
        executor=executor,
        implementation_sha="f" * 40,
        live=True,
        heartbeat_id="fixture",
    )
    relay.queue_remote_sha = "a" * 40
    return relay, queue, executor


def test_request_schema_and_digest_are_strict() -> None:
    raw = _request()
    parsed = validate_request(raw, DEFAULT_ALLOWED_ACTIONS)
    assert parsed["request_sha256"] == request_digest(raw)

    bad = dict(raw)
    bad["timeout_ms"] = 5001
    with pytest.raises(RequestValidationError, match="request_sha256 mismatch"):
        validate_request(bad, DEFAULT_ALLOWED_ACTIONS)

    bad = dict(raw)
    bad["version"] = "pc_relay.request.v1"
    bad["request_sha256"] = request_digest(bad)
    with pytest.raises(RequestValidationError, match="unsupported request version"):
        validate_request(bad, DEFAULT_ALLOWED_ACTIONS)


def test_transport_allowlist_does_not_widen_executor_global_defaults() -> None:
    assert "powershell.exe" in RELAY_SHELL_EXECUTABLES
    assert "cmd.exe" in RELAY_SHELL_EXECUTABLES
    assert "powershell.exe" not in DEFAULT_SAFE_EXECUTABLES
    assert "cmd.exe" not in DEFAULT_SAFE_EXECUTABLES
    assert "mouse.click" not in DEFAULT_ALLOWED_ACTIONS
    assert "keyboard.type_text" not in DEFAULT_ALLOWED_ACTIONS
    assert "uia.set_value" not in DEFAULT_ALLOWED_ACTIONS


def test_transport_rejects_protected_path_and_credential_captcha_shell_forms() -> None:
    protected = _request(
        params={
            "argv": [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                r"Get-ChildItem E:\manhwa",
            ],
            "cwd": "C:\\",
        }
    )
    with pytest.raises(RequestValidationError, match="protected path"):
        validate_request(protected, DEFAULT_ALLOWED_ACTIONS)

    for command in (
        "Get-Credential",
        "Read-Host -AsSecureString",
        "Write-Output captcha",
    ):
        raw = _request(
            request_id="blocked-" + str(abs(hash(command))),
            params={
                "argv": ["powershell.exe", "-NoProfile", "-Command", command],
                "cwd": "C:\\",
            },
        )
        with pytest.raises(RequestValidationError, match="forbidden"):
            validate_request(raw, DEFAULT_ALLOWED_ACTIONS)


def test_transport_rejects_encoded_or_persistent_windows_shells() -> None:
    encoded = _request(
        params={
            "argv": ["powershell.exe", "-NoProfile", "-EncodedCommand", "QQA="],
            "cwd": "C:\\",
        }
    )
    with pytest.raises(RequestValidationError, match="encoded PowerShell"):
        validate_request(encoded, DEFAULT_ALLOWED_ACTIONS)

    cmd = _request(
        params={"argv": ["cmd.exe", "/k", "echo", "ok"], "cwd": "C:\\"}
    )
    with pytest.raises(RequestValidationError, match="persistent cmd"):
        validate_request(cmd, DEFAULT_ALLOWED_ACTIONS)


def test_fault_crash_before_dispatch_resumes_once(tmp_path: Path) -> None:
    relay, queue, executor = _relay(tmp_path)
    raw = _request("crash-before-dispatch")
    path = _write_request(queue, raw)
    relay._write_state(raw, status="received")

    result = relay.process_request_path(path)

    assert result["relay_status"] == "completed"
    assert executor.execute_calls == 1
    assert queue.results[raw["id"]]["result_sha256"] == result["result_sha256"]


@pytest.mark.parametrize("outcome", ["unknown", "completed"])
def test_fault_crash_after_dispatch_never_blind_replays(tmp_path: Path, outcome: str) -> None:
    relay, queue, executor = _relay(tmp_path, outcome=outcome)
    raw = _request(f"crash-after-dispatch-{outcome}")
    path = _write_request(queue, raw)
    relay._write_state(raw, status="dispatch_started")

    result = relay.process_request_path(path)

    assert executor.execute_calls == 0
    assert executor.lookup_calls == 1
    assert result["reexecuted"] is False
    assert result["relay_status"] in {"reconciliation_required", "reconciled_completed"}


def test_fault_dispatch_terminal_not_started_allows_bounded_reexecution(tmp_path: Path) -> None:
    relay, queue, executor = _relay(tmp_path, outcome="not_started")
    raw = _request("safe-reexecution")
    path = _write_request(queue, raw)
    relay._write_state(raw, status="dispatch_started")

    result = relay.process_request_path(path)

    assert executor.lookup_calls == 1
    assert executor.execute_calls == 1
    assert result["reexecuted"] is True


def test_fault_executor_completed_before_queue_push_recovers_from_local_state(tmp_path: Path) -> None:
    relay, queue, executor = _relay(tmp_path)
    raw = _request("completed-before-push")
    result = make_result(
        request=raw,
        relay_status="completed",
        live=True,
        implementation_sha="f" * 40,
        queue_head_at_receive="a" * 40,
        executor_result={"ok": True},
    )
    relay._write_state(raw, status="finished", result=result)

    relay.cycle()

    assert executor.execute_calls == 0
    assert queue.results[raw["id"]]["result_sha256"] == result["result_sha256"]


@pytest.mark.parametrize("failure_kind", ["git_commit_failure", "git_push_rejection"])
def test_fault_publication_failure_does_not_reexecute(
    tmp_path: Path, failure_kind: str
) -> None:
    relay, queue, executor = _relay(tmp_path)
    raw = _request(failure_kind)
    path = _write_request(queue, raw)
    queue.publish_failures = 1

    with pytest.raises(QueueConflictError):
        relay.process_request_path(path)

    assert executor.execute_calls == 1
    state = json.loads(relay._state_path(raw["id"]).read_text(encoding="utf-8"))
    assert state["status"] == "finished"

    recovered = relay.process_request_path(path)
    assert executor.execute_calls == 1
    assert recovered["result_sha256"] == queue.results[raw["id"]]["result_sha256"]


def test_fault_concurrent_queue_update_records_new_head_without_reexecution(tmp_path: Path) -> None:
    relay, queue, executor = _relay(tmp_path)
    queue.sync_shas = ["1" * 40, "2" * 40]
    raw = _request("concurrent-update")
    _write_request(queue, raw)

    relay.cycle()
    relay.cycle()

    assert executor.execute_calls == 1
    assert relay.queue_remote_sha == "2" * 40
    assert queue.heartbeats[-1]["version"] == HEARTBEAT_VERSION


def test_fault_force_push_detection_fails_closed(monkeypatch, tmp_path: Path) -> None:
    metadata = tmp_path / "queue-history.json"
    metadata.write_text(
        json.dumps(
            {
                "version": QUEUE_PROTOCOL_VERSION,
                "queue_ref": "agent/pc-relay-queue",
                "last_remote_sha": "1" * 40,
            }
        ),
        encoding="utf-8",
    )
    queue = GitQueue(tmp_path, queue_ref="agent/pc-relay-queue", metadata_path=metadata)
    monkeypatch.setattr(queue, "_prepare_clean_checkout", lambda: None)
    monkeypatch.setattr(queue, "_fetch", lambda: "2" * 40)
    monkeypatch.setattr(queue, "_is_ancestor", lambda older, newer: False)

    with pytest.raises(QueueForcePushError):
        queue.sync()


@pytest.mark.parametrize(
    "payload",
    [
        b"{not-json",
        json.dumps({"version": REQUEST_VERSION}).encode(),
        json.dumps({**_request("wrong-version"), "version": "wrong"}).encode(),
    ],
)
def test_fault_malformed_json_schema_or_version_is_quarantined(
    tmp_path: Path, payload: bytes
) -> None:
    relay, queue, executor = _relay(tmp_path)
    path = queue.requests_dir / "malformed.json"
    path.write_bytes(payload)

    assert relay.process_request_path(path) is None
    assert executor.execute_calls == 0
    assert queue.quarantine
    assert queue.quarantine[-1]["raw_content_committed"] is False


def test_fault_oversized_request_is_quarantined_without_copying_content(tmp_path: Path) -> None:
    relay, queue, executor = _relay(tmp_path)
    path = queue.requests_dir / "oversized.json"
    path.write_bytes(b"x" * (MAX_REQUEST_BYTES + 1))

    relay.process_request_path(path)

    assert executor.execute_calls == 0
    assert queue.quarantine[-1]["bytes"] == MAX_REQUEST_BYTES + 1
    assert "content" not in queue.quarantine[-1]


def test_fault_duplicate_id_with_different_content_is_quarantined(tmp_path: Path) -> None:
    relay, queue, executor = _relay(tmp_path)
    first = _request("duplicate-id", note="first")
    path = _write_request(queue, first)
    relay.process_request_path(path)
    assert executor.execute_calls == 1

    queue.results.clear()
    second = _request("duplicate-id", note="different")
    path.write_text(json.dumps(second), encoding="utf-8")
    assert relay.process_request_path(path) is None

    assert executor.execute_calls == 1
    assert "changed content digest" in queue.quarantine[-1]["error"]


def test_fault_result_already_published_skips_executor(tmp_path: Path) -> None:
    relay, queue, executor = _relay(tmp_path)
    raw = _request("already-published")
    path = _write_request(queue, raw)
    published = make_result(
        request=raw,
        relay_status="completed",
        live=True,
        implementation_sha="e" * 40,
        queue_head_at_receive="d" * 40,
        executor_result={"ok": True},
    )
    queue.results[raw["id"]] = published

    result = relay.process_request_path(path)

    assert result["result_sha256"] == published["result_sha256"]
    assert executor.execute_calls == 0


def test_duplicate_result_with_different_content_fails_closed(tmp_path: Path) -> None:
    relay, queue, executor = _relay(tmp_path)
    raw = _request("result-conflict")
    path = _write_request(queue, raw)
    published = make_result(
        request=raw,
        relay_status="completed",
        live=True,
        implementation_sha="e" * 40,
        queue_head_at_receive="d" * 40,
        executor_result={"ok": True},
    )
    queue.results[raw["id"]] = published
    conflicting = dict(published)
    conflicting["implementation_sha"] = "c" * 40

    with pytest.raises(QueueConflictError):
        queue.publish_result(conflicting)

    assert executor.execute_calls == 0


def test_quarantine_publication_is_idempotent(monkeypatch, tmp_path: Path) -> None:
    queue = GitQueue(
        tmp_path,
        queue_ref="agent/pc-relay-queue",
        metadata_path=tmp_path / "queue-history.json",
    )
    commits: list[str] = []
    monkeypatch.setattr(
        queue,
        "_commit_and_push",
        lambda path, message, mutable: commits.append(path.name),
    )
    metadata = {
        "version": "pc_relay.quarantine.v1",
        "source_name": "bad.json",
        "raw_sha256": "a" * 64,
        "bytes": 9,
        "error_kind": "RequestValidationError",
        "error": "bad request",
        "observed_at": "2026-09-27T00:00:00.000Z",
        "raw_content_committed": False,
    }

    queue.publish_quarantine(metadata)
    repeated = dict(metadata)
    repeated["observed_at"] = "2026-09-27T00:01:00.000Z"
    queue.publish_quarantine(repeated)

    assert commits == ["bad.json.aaaaaaaaaaaaaaaa.json"]


def test_heartbeat_publication_is_cadence_bounded(tmp_path: Path) -> None:
    relay, queue, _executor = _relay(tmp_path)
    relay.heartbeat_seconds = 3600.0

    relay._maybe_publish_heartbeat()
    relay._maybe_publish_heartbeat()

    assert len(queue.heartbeats) == 1
    relay._maybe_publish_heartbeat(alive=False, force=True)
    assert len(queue.heartbeats) == 2
    assert queue.heartbeats[-1]["relay_alive"] is False


def test_heartbeat_reports_required_health_dimensions(tmp_path: Path) -> None:
    relay, queue, _executor = _relay(tmp_path)
    relay.queue_reachable = True
    relay.queue_remote_sha = "a" * 40
    relay.last_processed_request = "req-9"

    heartbeat = relay.heartbeat()

    assert heartbeat == {
        "version": HEARTBEAT_VERSION,
        "relay_alive": True,
        "queue_reachable": True,
        "executor_available": True,
        "queue_integrity": "ok",
        "last_processed_request": "req-9",
        "implementation_sha": "f" * 40,
        "queue_ref": "agent/pc-relay-queue",
        "queue_remote_sha": "a" * 40,
        "generated_at": heartbeat["generated_at"],
    }


def test_result_redacts_common_secret_fields_and_values() -> None:
    raw = _request("redaction")
    result = make_result(
        request=raw,
        relay_status="completed",
        live=True,
        implementation_sha="f" * 40,
        queue_head_at_receive="a" * 40,
        executor_result={
            "password": "dont-commit-me",
            "stdout": "token=abc123 ordinary-output",
        },
    )
    encoded = json.dumps(result)
    assert "dont-commit-me" not in encoded
    assert "abc123" not in encoded
    assert "[REDACTED]" in encoded


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell live-path test")
def test_windows_powershell_stdout_stderr_are_bounded_and_truncated(tmp_path: Path) -> None:
    adapter = SafeShellAdapter(
        allow_executables=set(RELAY_SHELL_EXECUTABLES),
        timeout_seconds=10.0,
        output_limit_bytes=64,
    )
    result = adapter.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-Command",
            "[Console]::Out.Write(('x' * 256)); [Console]::Error.Write(('y' * 256))",
        ],
        cwd=str(tmp_path),
    )

    assert result.stdout_truncated is True
    assert result.stderr_truncated is True
    assert result.stdout_bytes == 256
    assert result.stderr_bytes == 256
    assert len(result.stdout.encode("utf-8")) <= 64
    assert len(result.stderr.encode("utf-8")) <= 64


def test_shell_adapter_still_rejects_protected_cwd_portably() -> None:
    adapter = SafeShellAdapter(allow_executables=set(RELAY_SHELL_EXECUTABLES))
    with pytest.raises(SafetyViolation, match="protected path"):
        adapter.validate(["powershell.exe", "-NoProfile", "-Command", "Write-Output ok"], cwd=r"E:\manhwa")


def test_health_only_cycle_does_not_process_requests(tmp_path: Path) -> None:
    relay, queue, executor = _relay(tmp_path)
    raw = _request("health-only-do-not-dispatch")
    _write_request(queue, raw)

    relay.health_cycle()

    assert executor.execute_calls == 0
    assert queue.results == {}
    assert queue.heartbeats[-1]["relay_alive"] is True
    assert queue.heartbeats[-1]["queue_reachable"] is True
    assert queue.heartbeats[-1]["queue_integrity"] == "ok"
    assert queue.heartbeats[-1]["last_processed_request"] is None
