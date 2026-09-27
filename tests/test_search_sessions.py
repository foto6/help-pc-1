import os
import sys
import time
from pathlib import Path

import pytest

import pc_executor.operations as operations_module
from pc_executor.executor import Executor
from pc_executor.models import ActionRequest
from pc_executor.operations import (
    OPS_SIDE_EFFECT_ACTIONS,
    LocalOperations,
)
from pc_executor.outcome_journal import OutcomeJournal
from pc_executor.safety import SafetyViolation
from pc_executor.search_sessions import SEARCH_SESSION_VERSION
from pc_executor.shell import SafeShellAdapter


def _shell() -> SafeShellAdapter:
    executable = Path(sys.executable).name.lower()
    return SafeShellAdapter(
        allow_executables={"python", "python.exe", executable},
        output_limit_bytes=4096,
    )


def _executor(
    tmp_path: Path,
    *,
    state_root: Path | None = None,
    retention_seconds: float = 300.0,
) -> tuple[Executor, LocalOperations]:
    shell = _shell()
    root = state_root or (tmp_path / "ops-state")
    ops = LocalOperations(
        shell=shell,
        state_root=root,
        search_retention_seconds=retention_seconds,
        search_max_workers=2,
    )
    executor = Executor(
        shell=shell,
        operations=ops,
        outcome_journal=OutcomeJournal(tmp_path / f"outcomes-{time.time_ns()}.jsonl"),
        dry_run=False,
        operation_timeout_seconds=5.0,
    )
    return executor, ops


def _request(action: str, params: dict, request_id: str) -> ActionRequest:
    return ActionRequest(
        action=action,
        params=params,
        request_id=request_id,
        timeout_ms=5000,
    )


def _start(executor: Executor, root: Path, pattern: str, **kwargs) -> str:
    params = {"path": str(root), "pattern": pattern, **kwargs}
    result = executor.execute(
        _request("search.start", params, f"start-{time.time_ns()}")
    )
    assert result.ok, result.error
    return result.data["search_id"]


def _read(
    executor: Executor,
    search_id: str,
    *,
    offset: int = 0,
    length: int = 100,
):
    return executor.execute(
        _request(
            "search.read",
            {"search_id": search_id, "offset": offset, "length": length},
            f"read-{time.time_ns()}",
        )
    )


def _wait_terminal(
    executor: Executor,
    search_id: str,
    timeout: float = 5.0,
):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = _read(executor, search_id, length=500)
        if result.ok and result.data["status"] != "running":
            return result
        time.sleep(0.01)
    raise AssertionError("search session did not reach terminal state")


def test_search_capabilities_and_state_mutation_classification(tmp_path: Path) -> None:
    executor, _ops = _executor(tmp_path)
    result = executor.execute(
        _request("ops.capabilities.get", {}, "search-caps")
    )
    assert result.ok
    caps = result.data["capabilities"]
    assert caps["schema_versions"]["search_session"] == SEARCH_SESSION_VERSION
    assert caps["actions"]["search.start"]["side_effecting"] is True
    assert caps["actions"]["search.stop"]["side_effecting"] is True
    assert caps["actions"]["search.read"]["side_effecting"] is False
    assert caps["actions"]["search.list"]["side_effecting"] is False
    assert {"search.start", "search.stop"} <= OPS_SIDE_EFFECT_ACTIONS


def test_file_search_regex_literal_ignore_case_hidden_and_pagination(
    tmp_path: Path,
) -> None:
    root = tmp_path / "files"
    root.mkdir()
    for name in [
        "Alpha.TXT",
        "beta.py",
        "item-01.txt",
        "item-02.txt",
        "item-03.txt",
        "literal[abc].txt",
        ".Hidden.TXT",
    ]:
        (root / name).write_text(name, encoding="utf-8")
    executor, _ops = _executor(tmp_path)

    regex_id = _start(
        executor,
        root,
        r"^(alpha|item-[0-9]+)\.txt$",
        search_type="files",
    )
    regex = _wait_terminal(executor, regex_id)
    assert regex.data["status"] == "completed"
    names = [Path(item["path"]).name for item in regex.data["results"]]
    assert names == ["Alpha.TXT", "item-01.txt", "item-02.txt", "item-03.txt"]

    page = _read(executor, regex_id, offset=1, length=2)
    assert [Path(item["path"]).name for item in page.data["results"]] == [
        "item-01.txt",
        "item-02.txt",
    ]
    tail = _read(executor, regex_id, offset=-2, length=1)
    assert tail.data["length"] is None
    assert [Path(item["path"]).name for item in tail.data["results"]] == [
        "item-02.txt",
        "item-03.txt",
    ]

    literal_id = _start(
        executor,
        root,
        "[abc]",
        search_type="files",
        literal_search=True,
        ignore_case=False,
    )
    literal = _wait_terminal(executor, literal_id)
    assert [Path(item["path"]).name for item in literal.data["results"]] == [
        "literal[abc].txt"
    ]

    hidden_default = _start(
        executor,
        root,
        "hidden",
        search_type="files",
        literal_search=True,
    )
    assert _wait_terminal(executor, hidden_default).data["result_count"] == 0

    hidden_included = _start(
        executor,
        root,
        "hidden",
        search_type="files",
        literal_search=True,
        include_hidden=True,
    )
    hidden = _wait_terminal(executor, hidden_included)
    assert [Path(item["path"]).name for item in hidden.data["results"]] == [
        ".Hidden.TXT"
    ]


def test_content_search_context_unicode_and_case_modes(tmp_path: Path) -> None:
    root = tmp_path / "content"
    root.mkdir()
    target = root / "unicode.txt"
    target.write_text(
        "before\nПривет мир\nTARGET Ω\nafter\n",
        encoding="utf-8",
    )
    executor, _ops = _executor(tmp_path)

    search_id = _start(
        executor,
        root,
        r"target\s+Ω",
        search_type="content",
        context_lines=1,
    )
    result = _wait_terminal(executor, search_id)
    assert result.data["result_count"] == 1
    match = result.data["results"][0]
    assert match["line_number"] == 3
    assert match["text"] == "TARGET Ω"
    assert match["context_before"] == ["Привет мир"]
    assert match["context_after"] == ["after"]

    strict_id = _start(
        executor,
        root,
        "target",
        search_type="content",
        literal_search=True,
        ignore_case=False,
        context_lines=0,
    )
    assert _wait_terminal(executor, strict_id).data["result_count"] == 0

    folded_id = _start(
        executor,
        root,
        "target",
        search_type="content",
        literal_search=True,
        ignore_case=True,
        context_lines=0,
    )
    assert _wait_terminal(executor, folded_id).data["result_count"] == 1


def test_max_results_is_terminal_and_bounded(tmp_path: Path) -> None:
    root = tmp_path / "bounded"
    root.mkdir()
    for index in range(20):
        (root / f"match-{index:02d}.txt").write_text("x", encoding="utf-8")
    executor, _ops = _executor(tmp_path)

    search_id = _start(
        executor,
        root,
        r"match-",
        search_type="files",
        max_results=3,
    )
    result = _wait_terminal(executor, search_id)
    assert result.data["status"] == "max_results"
    assert result.data["result_count"] == 3
    assert len(result.data["results"]) == 3


def test_timeout_and_cancel_mid_search_preserve_final_results(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "slow"
    root.mkdir()
    for index in range(12):
        child = root / f"d{index:02d}"
        child.mkdir()
        (child / f"match-{index:02d}.txt").write_text("match", encoding="utf-8")

    original_walk = operations_module.os.walk

    def slow_walk(*args, **kwargs):
        for item in original_walk(*args, **kwargs):
            time.sleep(0.02)
            yield item

    monkeypatch.setattr(operations_module.os, "walk", slow_walk)
    executor, _ops = _executor(tmp_path)

    timed_id = _start(
        executor,
        root,
        "match",
        search_type="files",
        literal_search=True,
        timeout_ms=5,
    )
    timed = _wait_terminal(executor, timed_id)
    assert timed.data["status"] == "timed_out"

    cancel_id = _start(
        executor,
        root,
        "match",
        search_type="files",
        literal_search=True,
        timeout_ms=5000,
    )
    time.sleep(0.035)
    stopped = executor.execute(
        _request(
            "search.stop",
            {"search_id": cancel_id},
            f"stop-{time.time_ns()}",
        )
    )
    assert stopped.ok
    cancelled = _wait_terminal(executor, cancel_id)
    assert cancelled.data["status"] == "cancelled"
    final = _read(executor, cancel_id, offset=-500, length=1)
    assert final.ok
    assert final.data["status"] == "cancelled"


def test_completed_stop_list_reconnect_and_stale_restart(tmp_path: Path) -> None:
    root = tmp_path / "lifecycle"
    root.mkdir()
    (root / "one.txt").write_text("one", encoding="utf-8")
    state_root = tmp_path / "shared-state"
    executor, ops = _executor(tmp_path, state_root=state_root)

    search_id = _start(
        executor,
        root,
        "one",
        search_type="files",
        literal_search=True,
    )
    completed = _wait_terminal(executor, search_id)
    assert completed.data["status"] == "completed"

    listed = executor.execute(_request("search.list", {}, "list-searches"))
    assert listed.ok
    entry = next(
        item for item in listed.data["searches"] if item["search_id"] == search_id
    )
    assert entry["search_type"] == "files"
    assert entry["pattern"] == "one"
    assert entry["result_count"] == 1
    assert entry["runtime_ms"] >= 0

    reconnect_read = _read(executor, search_id)
    assert reconnect_read.ok
    assert reconnect_read.data["result_count"] == 1

    stopped = executor.execute(
        _request(
            "search.stop",
            {"search_id": search_id},
            f"stop-complete-{time.time_ns()}",
        )
    )
    assert stopped.ok
    assert stopped.data["already_finished"] is True

    restarted_executor, _restarted_ops = _executor(
        tmp_path,
        state_root=state_root,
    )
    stale = _read(restarted_executor, search_id)
    assert stale.ok is False
    assert stale.status == "blocked"
    assert "previous executor/device generation" in (stale.error or "")
    assert ops.generation_id != _restarted_ops.generation_id


def test_retention_expiry_gc_removes_handle(tmp_path: Path) -> None:
    root = tmp_path / "expiry"
    root.mkdir()
    (root / "done.txt").write_text("done", encoding="utf-8")
    executor, _ops = _executor(tmp_path, retention_seconds=0.05)

    search_id = _start(
        executor,
        root,
        "done",
        search_type="files",
        literal_search=True,
    )
    _wait_terminal(executor, search_id)
    time.sleep(0.08)

    listed = executor.execute(_request("search.list", {}, "list-after-expiry"))
    assert listed.ok
    assert all(
        item["search_id"] != search_id for item in listed.data["searches"]
    )
    expired = _read(executor, search_id)
    assert expired.ok is False
    assert expired.status == "blocked"
    assert "expired after retention" in (expired.error or "")


def test_permission_error_is_skipped_without_failing_search(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "permission"
    root.mkdir()
    denied = root / "denied.txt"
    denied.write_text("needle", encoding="utf-8")
    allowed = root / "allowed.txt"
    allowed.write_text("needle", encoding="utf-8")
    original_open = Path.open

    def guarded_open(self: Path, *args, **kwargs):
        if self == denied.resolve():
            raise PermissionError("simulated denial")
        return original_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)
    executor, _ops = _executor(tmp_path)
    search_id = _start(
        executor,
        root,
        "needle",
        search_type="content",
        literal_search=True,
        context_lines=0,
    )
    result = _wait_terminal(executor, search_id)
    assert result.data["status"] == "completed"
    assert [Path(item["path"]).name for item in result.data["results"]] == [
        "allowed.txt"
    ]


def test_reparse_escape_is_not_traversed(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "reparse"
    root.mkdir()
    escape = root / "escape"
    escape.mkdir()
    (escape / "secret-match.txt").write_text("x", encoding="utf-8")
    original = operations_module._is_reparse_or_symlink

    def fake_reparse(path: Path) -> bool:
        if path.name == "escape":
            return True
        return original(path)

    monkeypatch.setattr(
        operations_module,
        "_is_reparse_or_symlink",
        fake_reparse,
    )
    executor, _ops = _executor(tmp_path)
    search_id = _start(
        executor,
        root,
        "secret",
        search_type="files",
        literal_search=True,
    )
    result = _wait_terminal(executor, search_id)
    assert result.data["result_count"] == 0


def test_protected_root_rejects_before_traversal_or_probe(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _executor_instance, ops = _executor(tmp_path)
    probes: list[str] = []

    def forbidden_exists(self: Path) -> bool:
        probes.append(str(self))
        raise AssertionError("filesystem probe occurred")

    monkeypatch.setattr(Path, "exists", forbidden_exists)
    with pytest.raises(SafetyViolation):
        ops.preflight(
            "search.start",
            {
                "path": r"E:\manhwa\must-not-touch",
                "pattern": "anything",
            },
        )
    assert probes == []


def test_invalid_regex_fails_before_session_creation(tmp_path: Path) -> None:
    root = tmp_path / "regex"
    root.mkdir()
    executor, _ops = _executor(tmp_path)
    result = executor.execute(
        _request(
            "search.start",
            {"path": str(root), "pattern": "("},
            "bad-regex",
        )
    )
    assert result.ok is False
    listed = executor.execute(_request("search.list", {}, "list-bad-regex"))
    assert listed.ok
    assert listed.data["count"] == 0


def test_stop_request_identity_cannot_cancel_unrelated_search(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "replay"
    root.mkdir()
    for index in range(20):
        child = root / f"d{index:02d}"
        child.mkdir()
        (child / f"match-{index:02d}.txt").write_text("x", encoding="utf-8")

    original_walk = operations_module.os.walk

    def slow_walk(*args, **kwargs):
        for item in original_walk(*args, **kwargs):
            time.sleep(0.01)
            yield item

    monkeypatch.setattr(operations_module.os, "walk", slow_walk)
    executor, _ops = _executor(tmp_path)
    first_id = _start(
        executor,
        root,
        "match",
        search_type="files",
        literal_search=True,
        timeout_ms=5000,
    )
    second_id = _start(
        executor,
        root,
        "match",
        search_type="files",
        literal_search=True,
        timeout_ms=5000,
    )
    stop_once = _request(
        "search.stop",
        {"search_id": first_id},
        "stop-request-once",
    )
    first_stop = executor.execute(stop_once)
    assert first_stop.ok

    replay = executor.execute(
        _request(
            "search.stop",
            {"search_id": second_id},
            "stop-request-once",
        )
    )
    assert replay.ok is False
    assert replay.status == "blocked"

    second_state = _read(executor, second_id)
    assert second_state.ok
    assert second_state.data["status"] in {"running", "completed", "max_results"}

    executor.execute(
        _request(
            "search.stop",
            {"search_id": second_id},
            "stop-request-two",
        )
    )


@pytest.mark.skipif(os.name == "nt", reason="case-distinct fixture requires POSIX")
def test_casefold_ties_have_deterministic_order(tmp_path: Path) -> None:
    root = tmp_path / "case-ties"
    root.mkdir()
    (root / "a.txt").write_text("x", encoding="utf-8")
    (root / "A.txt").write_text("x", encoding="utf-8")
    executor, _ops = _executor(tmp_path)
    search_id = _start(
        executor,
        root,
        r"^[Aa]\.txt$",
        search_type="files",
    )
    result = _wait_terminal(executor, search_id)
    assert [Path(item["path"]).name for item in result.data["results"]] == [
        "A.txt",
        "a.txt",
    ]
