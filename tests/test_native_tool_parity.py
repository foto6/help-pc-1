from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

import pytest

from pc_executor.executor import Executor
from pc_executor.models import ActionRequest
from pc_executor.operations import (
    NATIVE_CAPABILITIES_VERSION,
    NATIVE_REQUEST_VERSION,
    NATIVE_RESULT_VERSION,
    NATIVE_TOOL_PARITY_VERSION,
    OPS_ACTIONS,
    LocalOperations,
)
from pc_executor.outcome_journal import OutcomeJournal
from pc_executor.safety import SafetyViolation, ensure_resolved_path_allowed
from pc_executor.shell import SafeShellAdapter


def _shell() -> SafeShellAdapter:
    executable = Path(sys.executable).name.lower()
    return SafeShellAdapter(
        allow_executables={"python", "python.exe", executable},
        output_limit_bytes=4096,
    )


def _executor(tmp_path: Path, *, journal: bool = True) -> Executor:
    shell = _shell()
    return Executor(
        shell=shell,
        operations=LocalOperations(
            shell=shell,
            state_root=tmp_path / "ops-state",
        ),
        outcome_journal=(
            OutcomeJournal(tmp_path / "outcomes.jsonl") if journal else None
        ),
        dry_run=False,
        operation_timeout_seconds=5.0,
    )


def _request(
    action: str,
    params: dict,
    request_id: str,
    *,
    binding: dict | None = None,
) -> ActionRequest:
    return ActionRequest(
        action=action,
        params=params,
        request_id=request_id,
        timeout_ms=5000,
        execution_context_binding=binding,
    )


def test_capabilities_publish_exact_native_contract_versions(
    tmp_path: Path,
) -> None:
    result = _executor(tmp_path).execute(
        _request("ops.capabilities.get", {}, "caps")
    )
    assert result.ok
    caps = result.data["capabilities"]
    assert caps["native_tool_parity_version"] == NATIVE_TOOL_PARITY_VERSION
    assert caps["schema_versions"]["request"] == NATIVE_REQUEST_VERSION
    assert caps["schema_versions"]["result"] == NATIVE_RESULT_VERSION
    assert (
        caps["schema_versions"]["capabilities"]
        == NATIVE_CAPABILITIES_VERSION
    )
    assert all(
        value["tool_contract_version"] == NATIVE_TOOL_PARITY_VERSION
        for value in caps["actions"].values()
    )
    required = {
        "device.info",
        "health.get",
        "config.get",
        "fs.read_text",
        "fs.write_text",
        "fs.edit_text",
        "fs.list",
        "fs.move",
        "fs.mkdir",
        "fs.stat",
        "fs.search",
        "search.start",
        "search.read",
        "search.list",
        "search.stop",
        "process.start",
        "process.read_output",
        "process.managed.list",
        "process.terminate",
        "shell.session.start",
        "shell.session.read",
        "shell.session.write_stdin",
        "shell.session.terminate",
        "process.list",
        "system.process.kill",
    }
    assert required <= OPS_ACTIONS


def test_protected_root_rejects_before_any_filesystem_probe(
    tmp_path: Path,
    monkeypatch,
) -> None:
    ops = LocalOperations(
        shell=_shell(),
        state_root=tmp_path / "ops-state",
    )
    probes: list[str] = []

    def forbidden_exists(self: Path) -> bool:
        probes.append(str(self))
        raise AssertionError("filesystem probe occurred")

    monkeypatch.setattr(Path, "exists", forbidden_exists)
    with pytest.raises(SafetyViolation):
        ops.preflight(
            "fs.read_text",
            {"path": r"E:\manhwa\must-not-touch.txt"},
        )
    assert probes == []


class _ExplodingOperations:
    def __init__(self) -> None:
        self.calls = 0

    def capabilities_snapshot(self) -> dict:
        return {"attestation": {"digest": "0" * 64}}

    def preflight(self, action: str, params: dict) -> None:
        assert action == "fs.mkdir"

    def execute(self, action: str, params: dict, *, cancellation=None) -> dict:
        self.calls += 1
        raise RuntimeError("simulated adapter uncertainty")


def test_live_native_side_effect_requires_outcome_journal_before_adapter() -> None:
    ops = _ExplodingOperations()
    executor = Executor(
        operations=ops,
        dry_run=False,
    )
    result = executor.execute(
        _request("fs.mkdir", {"path": "C:\\never-probed"}, "no-journal")
    )
    assert result.status == "blocked"
    assert ops.calls == 0
    assert result.outcome_evidence.effect_state == "not_started"


def test_unknown_outcome_blocks_blind_replay(tmp_path: Path) -> None:
    ops = _ExplodingOperations()
    journal = OutcomeJournal(tmp_path / "unknown.jsonl")
    executor = Executor(
        operations=ops,
        outcome_journal=journal,
        dry_run=False,
    )
    request = _request(
        "fs.mkdir",
        {"path": str(tmp_path / "uncertain")},
        "unknown-replay",
    )
    first = executor.execute(request)
    assert first.ok is False
    assert first.outcome_evidence.effect_state == "unknown"
    assert ops.calls == 1

    second = executor.execute(request)
    assert second.status == "blocked"
    assert ops.calls == 1
    lookup = executor.read_outcome_evidence(
        request_id=request.request_id,
        action=request.action,
    )
    assert lookup["outcome"] == "unknown"


def test_edit_text_requires_hash_and_exact_replacement_count(
    tmp_path: Path,
) -> None:
    target = tmp_path / "edit.txt"
    target.write_text("alpha beta alpha\n", encoding="utf-8")
    before = hashlib.sha256(target.read_bytes()).hexdigest()
    executor = _executor(tmp_path)
    result = executor.execute(
        _request(
            "fs.edit_text",
            {
                "path": str(target),
                "old_text": "alpha",
                "new_text": "omega",
                "expected_replacements": 2,
                "expected_current_hash": before,
            },
            "edit-1",
        )
    )
    assert result.ok
    assert target.read_text(encoding="utf-8") == "omega beta omega\n"
    assert result.data["replacements"] == 2

    stale = executor.execute(
        _request(
            "fs.edit_text",
            {
                "path": str(target),
                "old_text": "omega",
                "new_text": "zeta",
                "expected_replacements": 2,
                "expected_current_hash": before,
            },
            "edit-stale",
        )
    )
    assert stale.status == "blocked"
    assert target.read_text(encoding="utf-8") == "omega beta omega\n"


def test_streaming_content_search_has_stable_cursor(tmp_path: Path) -> None:
    root = tmp_path / "search"
    root.mkdir()
    for index in range(5):
        (root / f"f{index}.txt").write_text(
            f"line {index}\nneedle {index}\n",
            encoding="utf-8",
        )
    executor = _executor(tmp_path)
    first = executor.execute(
        _request(
            "fs.search",
            {
                "path": str(root),
                "query": "needle",
                "content": True,
                "max_results": 2,
            },
            "search-1",
        )
    )
    assert first.ok
    assert len(first.data["results"]) == 2
    assert first.data["has_more"] is True
    cursor = first.data["cursor"]

    second = executor.execute(
        _request(
            "fs.search",
            {
                "path": str(root),
                "query": "needle",
                "content": True,
                "max_results": 2,
                "cursor": cursor,
            },
            "search-2",
        )
    )
    assert second.ok
    first_paths = {item["path"] for item in first.data["results"]}
    second_paths = {item["path"] for item in second.data["results"]}
    assert first_paths.isdisjoint(second_paths)


def test_text_tail_is_bounded_and_explicit(tmp_path: Path) -> None:
    target = tmp_path / "tail.txt"
    target.write_text("1\n2\n3\n4\n", encoding="utf-8")
    result = _executor(tmp_path).execute(
        _request(
            "fs.read_text",
            {
                "path": str(target),
                "tail_lines": 2,
                "max_bytes": 32,
            },
            "tail",
        )
    )
    assert result.ok
    assert result.data["text"] == "3\n4\n"
    assert result.data["tail_lines"] == 2
    assert result.data["truncated"] is True
    assert result.data["file_bytes"] == len(target.read_bytes())


def test_managed_process_identity_survives_as_stale_metadata(
    tmp_path: Path,
) -> None:
    executor = _executor(tmp_path)
    start = executor.execute(
        _request(
            "process.start",
            {
                "argv": [
                    sys.executable,
                    "-c",
                    "import time; time.sleep(30)",
                ],
                "cwd": str(tmp_path),
            },
            "proc-start",
        )
    )
    assert start.ok
    handle_id = start.data["handle_id"]
    try:
        shell = _shell()
        restarted = LocalOperations(
            shell=shell,
            state_root=tmp_path / "ops-state",
        )
        listed = restarted.execute(
            "process.managed.list",
            {"include_stale": True},
        )
        stale = next(
            item for item in listed["handles"] if item["handle_id"] == handle_id
        )
        assert stale["status"] == "stale_after_restart"
        with pytest.raises(SafetyViolation):
            restarted.execute(
                "process.read_output",
                {"handle_id": handle_id},
            )
    finally:
        terminated = executor.execute(
            _request(
                "process.terminate",
                {"handle_id": handle_id, "grace_ms": 50},
                "proc-stop",
            )
        )
        assert terminated.ok


def test_process_start_uses_existing_execution_context_binding(
    tmp_path: Path,
) -> None:
    executor = _executor(tmp_path)
    request = _request(
        "process.start",
        {
            "argv": [sys.executable, "-c", "print('bound')"],
            "cwd": str(tmp_path),
        },
        "bound-start",
    )
    binding = executor.bind_execution_context(request)
    bound = _request(
        request.action,
        request.params,
        request.request_id,
        binding=binding,
    )
    result = executor.execute(bound)
    assert result.ok
    handle_id = result.data["handle_id"]
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        status = executor.execute(
            _request(
                "process.status",
                {"handle_id": handle_id},
                f"status-{time.monotonic_ns()}",
            )
        )
        if status.data["status"] == "exited":
            break
        time.sleep(0.02)
    output = executor.execute(
        _request(
            "process.read_output",
            {"handle_id": handle_id, "tail_bytes": 128},
            "bound-read",
        )
    )
    assert "bound" in output.data["stdout"]
    assert output.data["stdout_total_bytes"] >= len("bound\n")


def test_device_health_and_config_are_read_only(tmp_path: Path) -> None:
    executor = _executor(tmp_path)
    device = executor.execute(_request("device.info", {}, "device"))
    health = executor.execute(_request("health.get", {}, "health"))
    config = executor.execute(_request("config.get", {}, "config"))
    assert device.ok and health.ok and config.ok
    assert device.data["transport"] == "native_local"
    assert health.data["status"] == "ok"
    assert config.data["mutable"] is True
    assert config.data["mutable_keys"] == ["allowed_roots", "read_many_max_bytes"]
    assert config.data["admin_config_revision"]
    assert config.data["search_cursor_version"].endswith(".v1")
    assert config.data["search_session_version"].endswith(".v1")


def test_generated_schemas_freeze_exact_action_inventory() -> None:
    root = Path(__file__).resolve().parents[1]
    request_schema = json.loads(
        (
            root
            / "schemas"
            / "pc_executor.native_tool_request.v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    result_schema = json.loads(
        (
            root
            / "schemas"
            / "pc_executor.native_tool_result.v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    capabilities_schema = json.loads(
        (
            root
            / "schemas"
            / "pc_executor.native_tool_capabilities.v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    assert request_schema["$id"] == NATIVE_REQUEST_VERSION
    assert result_schema["$id"] == NATIVE_RESULT_VERSION
    assert capabilities_schema["$id"] == NATIVE_CAPABILITIES_VERSION
    assert (
        request_schema["properties"]["action"]["enum"]
        == sorted(OPS_ACTIONS)
    )
    assert (
        result_schema["properties"]["action"]["enum"]
        == sorted(OPS_ACTIONS)
    )


def test_desktop_commander_mapping_fixture_covers_reference_surface() -> None:
    root = Path(__file__).resolve().parents[1]
    payload = json.loads(
        (
            root
            / "tests"
            / "fixtures"
            / "native_tool_parity_v1"
            / "desktop_commander_mapping.json"
        ).read_text(encoding="utf-8")
    )
    assert payload["contract_version"] == NATIVE_TOOL_PARITY_VERSION
    mapped = {item["reference"]: item for item in payload["mappings"]}
    required = {
        "list_devices",
        "ping",
        "get_config",
        "set_config_value",
        "who_am_i",
        "shutdown",
        "read_file",
        "read_multiple_files",
        "write_file",
        "edit_block",
        "list_directory",
        "move_file",
        "create_directory",
        "get_file_info",
        "start_search",
        "get_more_search_results",
        "stop_search",
        "list_searches",
        "start_process",
        "read_process_output",
        "interact_with_process",
        "list_sessions",
        "force_terminate",
        "list_processes",
        "kill_process",
        "get_usage_stats",
        "get_recent_tool_calls",
        "write_pdf",
    }
    assert required <= set(mapped)
    assert mapped["kill_process"]["candidate"] == ["system.process.kill"]
    assert mapped["edit_block"]["candidate"] == ["fs.edit_text"]
    assert mapped["start_search"]["candidate"] == ["search.start"]
    assert mapped["get_more_search_results"]["candidate"] == ["search.read"]
    assert mapped["stop_search"]["candidate"] == ["search.stop"]
    assert mapped["list_searches"]["candidate"] == ["search.list"]
    assert mapped["read_multiple_files"]["candidate"] == ["fs.read_many"]
    assert mapped["set_config_value"]["candidate"] == ["config.set"]
    assert mapped["who_am_i"]["candidate"] == ["identity.get"]
    assert mapped["shutdown"]["candidate"] == ["device.shutdown"]
    assert mapped["get_usage_stats"]["candidate"] == ["metrics.get"]
    assert mapped["get_recent_tool_calls"]["candidate"] == ["audit.history"]
    assert mapped["write_pdf"]["status"] == "unsupported_hard_gap"
    assert mapped["write_pdf"]["candidate"] == []


def test_directory_listing_pagination_is_explicit(tmp_path: Path) -> None:
    root = tmp_path / "paged"
    root.mkdir()
    for name in ("a.txt", "b.txt", "c.txt"):
        (root / name).write_text(name, encoding="utf-8")
    executor = _executor(tmp_path)
    first = executor.execute(
        _request(
            "fs.list",
            {"path": str(root), "max_entries": 2},
            "list-page-1",
        )
    )
    assert first.ok
    assert first.data["count"] == 2
    assert first.data["has_more"] is True
    second = executor.execute(
        _request(
            "fs.list",
            {
                "path": str(root),
                "offset": first.data["next_offset"],
                "max_entries": 2,
            },
            "list-page-2",
        )
    )
    assert second.ok
    assert second.data["count"] == 1
    assert second.data["has_more"] is False
    names = {
        item["name"]
        for item in first.data["entries"] + second.data["entries"]
    }
    assert names == {"a.txt", "b.txt", "c.txt"}
