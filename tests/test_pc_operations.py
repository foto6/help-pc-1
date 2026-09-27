from __future__ import annotations

import hashlib
import os
import sys
import time
from pathlib import Path

import pytest

import pc_executor.operations as operations_module
import pc_executor.safety as safety_module
from pc_executor.executor import Executor
from pc_executor.models import ActionRequest
from pc_executor.operations import (
    OPS_ACTIONS,
    OPS_READ_ONLY_ACTIONS,
    OPS_SIDE_EFFECT_ACTIONS,
    LocalOperations,
)
from pc_executor.outcome_journal import OutcomeJournal
from pc_executor.preflight import CONTRACT_VERSION as PREFLIGHT_VERSION
from pc_executor.safety import SafetyViolation, ensure_resolved_path_allowed
from pc_executor.shell import SafeShellAdapter


def make_executor(
    tmp_path: Path,
    *,
    live: bool = True,
    journal: OutcomeJournal | None = None,
):
    executable = Path(sys.executable).name.lower()
    shell = SafeShellAdapter(
        allow_executables={"python", "python.exe", executable},
        output_limit_bytes=4096,
    )
    ops = LocalOperations(shell=shell, state_root=tmp_path / "ops-state")
    executor = Executor(
        shell=shell,
        operations=ops,
        outcome_journal=journal,
        dry_run=not live,
        operation_timeout_seconds=5.0,
    )
    return executor, ops


def request(action: str, params: dict, request_id: str = "ops-1") -> ActionRequest:
    return ActionRequest(
        action=action,
        params=params,
        request_id=request_id,
        timeout_ms=5000,
    )


def preflight_payload(action: str, params: dict) -> dict:
    return {
        "contract_version": PREFLIGHT_VERSION,
        "request": {
            "request_id": "preflight-ops",
            "action": action,
            "params": params,
            "dry_run": None,
            "timeout_ms": 5000,
        },
    }


def wait_for_exit(executor: Executor, handle_id: str, timeout: float = 5.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = executor.execute(
            request("process.status", {"handle_id": handle_id}, "status")
        )
        assert result.ok
        if result.data["status"] == "exited":
            return result.data
        time.sleep(0.02)
    raise AssertionError("managed process did not exit")


def test_action_inventory_is_exposed_in_capabilities(tmp_path: Path) -> None:
    executor, _ops = make_executor(tmp_path)
    caps = executor.capabilities_snapshot()

    assert OPS_ACTIONS.issubset(caps["actions"])
    assert all(
        caps["actions"][name]["side_effecting"] is (name in OPS_SIDE_EFFECT_ACTIONS)
        for name in OPS_ACTIONS
    )
    assert caps["safety"]["structured_ops_contract_version"] == "pc_executor.ops.v1"
    assert caps["safety"]["process_termination_scope"] == (
        "gateway_owned_current_generation_only"
    )


def test_filesystem_read_surface_is_bounded(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    root.mkdir()
    target = root / "sample.txt"
    target.write_text("one\ntwo\nthree\n", encoding="utf-8")
    (root / "other.log").write_text("x\n", encoding="utf-8")
    executor, _ops = make_executor(tmp_path)

    listed = executor.execute(
        request("fs.list", {"path": str(root), "max_entries": 10}, "list")
    )
    stat = executor.execute(request("fs.stat", {"path": str(target)}, "stat"))
    text = executor.execute(
        request(
            "fs.read_text",
            {
                "path": str(target),
                "start_line": 2,
                "end_line": 2,
                "max_bytes": 64,
            },
            "read-text",
        )
    )
    raw = executor.execute(
        request(
            "fs.read_bytes",
            {"path": str(target), "offset": 0, "max_bytes": 4},
            "read-bytes",
        )
    )
    hashed = executor.execute(request("fs.hash", {"path": str(target)}, "hash"))
    found = executor.execute(
        request(
            "fs.find",
            {"path": str(root), "name_contains": "sample", "max_results": 5},
            "find",
        )
    )
    globbed = executor.execute(
        request(
            "fs.glob",
            {"path": str(root), "pattern": "*.txt", "max_results": 5},
            "glob",
        )
    )

    assert listed.ok and listed.data["count"] == 2
    assert stat.data["kind"] == "file"
    assert text.data["text"] == "two\n"
    assert raw.data["returned_bytes"] == 4
    assert hashed.data["sha256"] == hashlib.sha256(target.read_bytes()).hexdigest()
    assert found.data["count"] == 1
    assert globbed.data["results"] == [str(target.resolve())]


def test_large_file_and_encoding_error_faults(tmp_path: Path) -> None:
    large = tmp_path / "large.txt"
    large.write_bytes(b"x" * (2 * 1024 * 1024))
    bad = tmp_path / "bad.txt"
    bad.write_bytes(b"\xff")
    executor, _ops = make_executor(tmp_path)

    bounded = executor.execute(
        request(
            "fs.read_bytes",
            {"path": str(large), "max_bytes": 1024},
            "large",
        )
    )
    invalid = executor.execute(
        request(
            "fs.read_text",
            {"path": str(bad), "encoding": "utf-8", "max_bytes": 1024},
            "encoding",
        )
    )

    assert bounded.ok is True
    assert bounded.data["returned_bytes"] == 1024
    assert bounded.data["truncated"] is True
    assert invalid.ok is False
    assert invalid.status == "error"


def test_write_hash_preconditions_and_file_change_between_preflight_write(
    tmp_path: Path,
) -> None:
    target = tmp_path / "write.txt"
    target.write_text("before", encoding="utf-8")
    before = hashlib.sha256(target.read_bytes()).hexdigest()
    executor, _ops = make_executor(tmp_path)
    params = {
        "path": str(target),
        "text": "after",
        "expected_current_hash": before,
    }

    ready = executor.preflight(preflight_payload("fs.write_text", params))
    assert ready.status == "ready"
    target.write_text("changed", encoding="utf-8")

    result = executor.execute(request("fs.write_text", params, "stale-write"))

    assert result.status == "blocked"
    assert result.outcome_evidence.effect_state == "not_started"
    assert target.read_text(encoding="utf-8") == "changed"


def test_write_create_only_and_overwrite_semantics(tmp_path: Path) -> None:
    executor, _ops = make_executor(tmp_path)
    target = tmp_path / "new.txt"

    created = executor.execute(
        request(
            "fs.write_text",
            {"path": str(target), "text": "one", "create_only": True},
            "create",
        )
    )
    refused = executor.execute(
        request(
            "fs.write_text",
            {"path": str(target), "text": "two", "create_only": True},
            "create-again",
        )
    )
    overwritten = executor.execute(
        request(
            "fs.write_text",
            {"path": str(target), "text": "two", "overwrite": True},
            "overwrite",
        )
    )

    assert created.ok is True
    assert refused.status == "blocked"
    assert overwritten.ok is True
    assert target.read_text(encoding="utf-8") == "two"


def test_append_crash_keeps_original_bytes(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "append.txt"
    target.write_text("base", encoding="utf-8")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    executor, _ops = make_executor(tmp_path)

    def crash_replace(_source, _destination):
        raise RuntimeError("fixture replace crash")

    monkeypatch.setattr(operations_module.os, "replace", crash_replace)
    result = executor.execute(
        request(
            "fs.append_text",
            {
                "path": str(target),
                "text": "+new",
                "expected_current_hash": digest,
            },
            "append-crash",
        )
    )

    assert result.ok is False
    assert result.outcome_evidence.effect_state == "unknown"
    assert target.read_text(encoding="utf-8") == "base"


def test_delete_race_and_explicit_classification(tmp_path: Path) -> None:
    target = tmp_path / "delete.txt"
    target.write_text("old", encoding="utf-8")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    executor, _ops = make_executor(tmp_path)
    params = {
        "path": str(target),
        "classification": "file",
        "expected_current_hash": digest,
    }
    assert executor.preflight(preflight_payload("fs.delete", params)).status == "ready"
    target.write_text("new", encoding="utf-8")

    result = executor.execute(request("fs.delete", params, "delete-race"))

    assert result.status == "blocked"
    assert target.exists()
    malformed = executor.execute(
        request(
            "fs.delete",
            {"path": str(target), "classification": "tree"},
            "delete-tree",
        )
    )
    assert malformed.status == "blocked"


def test_copy_move_mkdir_and_hash_guard(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    source.write_text("payload", encoding="utf-8")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    executor, _ops = make_executor(tmp_path)

    directory = executor.execute(
        request(
            "fs.mkdir",
            {"path": str(tmp_path / "a" / "b"), "parents": True},
            "mkdir",
        )
    )
    copied = executor.execute(
        request(
            "fs.copy",
            {
                "source": str(source),
                "destination": str(tmp_path / "copy.txt"),
                "expected_source_hash": digest,
            },
            "copy",
        )
    )
    moved = executor.execute(
        request(
            "fs.move",
            {
                "source": str(tmp_path / "copy.txt"),
                "destination": str(tmp_path / "moved.txt"),
                "expected_source_hash": digest,
            },
            "move",
        )
    )

    assert directory.ok and copied.ok and moved.ok
    assert (tmp_path / "moved.txt").read_text(encoding="utf-8") == "payload"


def test_log_cursor_tail_search_and_malformed_cursor(tmp_path: Path) -> None:
    log = tmp_path / "app.log"
    log.write_text("one\nERROR two\nthree\n", encoding="utf-8")
    executor, _ops = make_executor(tmp_path)

    tail = executor.execute(
        request(
            "log.tail",
            {"path": str(log), "max_lines": 2, "max_bytes": 100},
            "tail",
        )
    )
    first = executor.execute(
        request(
            "log.read_since",
            {"path": str(log), "max_bytes": 4},
            "since-one",
        )
    )
    second = executor.execute(
        request(
            "log.read_since",
            {
                "path": str(log),
                "cursor": first.data["cursor"],
                "max_bytes": 100,
            },
            "since-two",
        )
    )
    searched = executor.execute(
        request(
            "log.search",
            {
                "path": str(log),
                "pattern": "error",
                "regex": False,
                "case_sensitive": False,
            },
            "search",
        )
    )
    malformed = executor.execute(
        request(
            "log.read_since",
            {"path": str(log), "cursor": {"offset": 1}},
            "bad-cursor",
        )
    )

    assert tail.data["lines"][-1] == "three\n"
    assert first.data["returned_bytes"] == 4
    assert second.data["text"]
    assert searched.data["match_count"] == 1
    assert malformed.status == "blocked"


def test_process_exits_before_read_and_output_cursor(tmp_path: Path) -> None:
    executor, _ops = make_executor(tmp_path)
    started = executor.execute(
        request(
            "process.start",
            {
                "argv": [
                    sys.executable,
                    "-u",
                    "-c",
                    "import sys; print('done'); print('err', file=sys.stderr)",
                ],
                "output_limit_bytes": 4096,
            },
            "process-start",
        )
    )
    assert started.ok is True
    handle_id = started.data["handle_id"]
    status = wait_for_exit(executor, handle_id)
    read = executor.execute(
        request(
            "process.read_output",
            {"handle_id": handle_id, "max_bytes": 4096, "wait_ms": 100},
            "process-read",
        )
    )

    assert status["status"] == "exited"
    assert "done" in read.data["stdout"]
    assert "err" in read.data["stderr"]
    assert read.data["running"] is False


def test_process_stdout_stderr_truncation_is_bounded(tmp_path: Path) -> None:
    executor, _ops = make_executor(tmp_path)
    started = executor.execute(
        request(
            "process.start",
            {
                "argv": [
                    sys.executable,
                    "-u",
                    "-c",
                    "import sys;sys.stdout.write('x'*20000);sys.stderr.write('y'*20000)",
                ],
                "output_limit_bytes": 4096,
            },
            "truncate-start",
        )
    )
    handle_id = started.data["handle_id"]
    wait_for_exit(executor, handle_id)
    time.sleep(0.05)
    read = executor.execute(
        request(
            "process.read_output",
            {"handle_id": handle_id, "max_bytes": 4096},
            "truncate-read",
        )
    )

    assert read.data["stdout_bytes"] <= 4096
    assert read.data["stderr_bytes"] <= 4096
    assert read.data["stdout_truncated_before_cursor"] is True
    assert read.data["stderr_truncated_before_cursor"] is True


def test_process_terminate_only_allows_current_gateway_owned_handles(
    tmp_path: Path,
) -> None:
    executor, _ops = make_executor(tmp_path)

    unknown = executor.execute(
        request(
            "process.terminate",
            {"handle_id": "process:not-owned", "grace_ms": 10},
            "terminate-unknown",
        )
    )

    assert unknown.status == "blocked"
    assert unknown.outcome_evidence.effect_state == "not_started"


def test_shell_session_io_and_restart_semantics(tmp_path: Path) -> None:
    executor, ops = make_executor(tmp_path)
    started = executor.execute(
        request(
            "shell.session.start",
            {
                "argv": [
                    sys.executable,
                    "-u",
                    "-c",
                    "import sys; line=sys.stdin.readline(); print('echo:'+line.strip())",
                ],
                "output_limit_bytes": 4096,
            },
            "session-start",
        )
    )
    session_id = started.data["session_id"]
    written = executor.execute(
        request(
            "shell.session.write_stdin",
            {
                "session_id": session_id,
                "text": "hello",
                "append_newline": True,
                "sensitive": False,
            },
            "session-write",
        )
    )
    assert written.ok is True
    deadline = time.monotonic() + 5
    read = None
    while time.monotonic() < deadline:
        read = executor.execute(
            request(
                "shell.session.read",
                {"session_id": session_id, "max_bytes": 4096, "wait_ms": 100},
                "session-read",
            )
        )
        if "echo:hello" in read.data["stdout"]:
            break
    assert read is not None and "echo:hello" in read.data["stdout"]

    restarted = LocalOperations(shell=ops.shell, state_root=ops.state_root)
    restarted_executor = Executor(
        shell=ops.shell,
        operations=restarted,
        dry_run=False,
    )
    stale = restarted_executor.execute(
        request(
            "shell.session.read",
            {"session_id": session_id},
            "session-after-restart",
        )
    )
    assert stale.status == "blocked"
    assert "previous gateway generation" in stale.error


def test_session_blocks_sensitive_or_captcha_stdin(tmp_path: Path) -> None:
    executor, _ops = make_executor(tmp_path)
    result = executor.preflight(
        preflight_payload(
            "shell.session.write_stdin",
            {
                "session_id": "session:any",
                "text": "captcha=1234",
                "sensitive": False,
            },
        )
    )
    assert result.status == "blocked"


def test_process_start_blocks_sensitive_environment(tmp_path: Path) -> None:
    executor, _ops = make_executor(tmp_path)
    result = executor.preflight(
        preflight_payload(
            "process.start",
            {
                "argv": [sys.executable, "-V"],
                "env": {"API_TOKEN": "should-never-enter-transport"},
            },
        )
    )
    assert result.status == "blocked"


def test_duplicate_side_effect_operation_id_is_blocked_by_outcome_journal(
    tmp_path: Path,
) -> None:
    journal = OutcomeJournal(tmp_path / "outcomes.jsonl")
    executor, _ops = make_executor(tmp_path, journal=journal)
    target = tmp_path / "dup-dir"
    first = executor.execute(
        request("fs.mkdir", {"path": str(target)}, "duplicate-operation")
    )
    second = executor.execute(
        request(
            "fs.mkdir",
            {"path": str(tmp_path / "other-dir")},
            "duplicate-operation",
        )
    )

    assert first.ok is True
    assert second.status == "blocked"
    assert not (tmp_path / "other-dir").exists()


def test_symlink_escape_and_protected_path_aliases_fail_closed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    with pytest.raises(SafetyViolation):
        ensure_resolved_path_allowed(r"e:/MANHWA/../manhwa/private.txt")
    with pytest.raises(SafetyViolation):
        ensure_resolved_path_allowed(r"E:\safe\..\manhwa\private.txt")

    protected = tmp_path / "protected"
    protected.mkdir()
    (protected / "secret.txt").write_text("secret", encoding="utf-8")
    link = tmp_path / "link"
    try:
        link.symlink_to(protected, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation unavailable")
    monkeypatch.setattr(
        safety_module,
        "PROTECTED_WINDOWS_ROOTS",
        (str(protected),),
    )
    with pytest.raises(SafetyViolation):
        ensure_resolved_path_allowed(link / "secret.txt")


@pytest.mark.skipif(os.name != "nt", reason="Windows protected-path alias test")
def test_windows_protected_path_aliases_remain_blocked() -> None:
    for value in (
        r"e:\MANHWA\x.txt",
        r"E:/manhwa/x.txt",
        r"E:\safe\..\manhwa\x.txt",
    ):
        with pytest.raises(SafetyViolation):
            ensure_resolved_path_allowed(value)


def test_system_read_only_surface(tmp_path: Path) -> None:
    executor, _ops = make_executor(tmp_path)

    info = executor.execute(request("system.info", {}, "sys-info"))
    resources = executor.execute(
        request("system.resources", {"path": str(tmp_path)}, "sys-res")
    )
    paths = executor.execute(
        request("system.paths", {"path": str(tmp_path / "future")}, "sys-paths")
    )

    assert info.ok and resources.ok and paths.ok
    assert "cpu_count" in info.data
    assert resources.data["disk"]["total_bytes"] > 0
    assert paths.data["requested"]["parent_exists"] is True


def test_audit_redacts_file_and_process_payloads(tmp_path: Path) -> None:
    target = tmp_path / "audit.txt"
    target.write_text("token=abc123 ordinary", encoding="utf-8")
    executor, _ops = make_executor(tmp_path)

    result = executor.execute(
        request("fs.read_text", {"path": str(target)}, "audit-read")
    )

    assert result.ok
    events = executor.audit.events
    serialized = repr([event.to_dict() for event in events])
    assert "abc123" not in serialized
    assert "text_redacted_bytes" in serialized
