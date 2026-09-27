from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from pc_executor.executor import Executor
from pc_executor.operations import OPS_ACTIONS, LocalOperations
from pc_executor.outcome_journal import OutcomeJournal
from pc_executor.shell import SafeShellAdapter
from pc_remote_transport import (
    ExecutorRemoteDispatcher,
    NATIVE_CONTROL_PROTOCOL_V1,
    TransportDispatchContext,
)
from pc_remote_transport.executor_adapter import TOOL_REGISTRY_LIST
from pc_remote_transport.protocol import digest_json


def _executor(tmp_path: Path) -> Executor:
    executable = Path(sys.executable).name.lower()
    shell = SafeShellAdapter(
        allow_executables={"python", "python.exe", "python3", executable},
        output_limit_bytes=65536,
    )
    return Executor(
        shell=shell,
        operations=LocalOperations(
            shell=shell,
            state_root=tmp_path / "ops-state",
        ),
        outcome_journal=OutcomeJournal(tmp_path / "outcomes.jsonl"),
        dry_run=False,
        operation_timeout_seconds=5.0,
    )


def _context(dispatcher: ExecutorRemoteDispatcher) -> TransportDispatchContext:
    return TransportDispatchContext(
        device_id="device-integrated",
        session_epoch="epoch-integrated-0001",
        session_capabilities_digest=digest_json(dispatcher.capability_manifest()),
    )


def _body(request_id: str, tool: str, arguments: dict | None = None) -> dict:
    return {
        "contract_version": NATIVE_CONTROL_PROTOCOL_V1,
        "session_id": "control-integrated",
        "request_id": request_id,
        "tool": tool,
        "arguments": arguments or {},
    }

async def _call(
    dispatcher: ExecutorRemoteDispatcher,
    context: TransportDispatchContext,
    request_id: str,
    tool: str,
    arguments: dict | None = None,
):
    return await dispatcher.dispatch(
        request_version=NATIVE_CONTROL_PROTOCOL_V1,
        request_id=request_id,
        body=_body(request_id, tool, arguments),
        transport_context=context,
    )


def test_remote_manifest_embeds_exact_tool_parity_capabilities(tmp_path: Path) -> None:
    executor = _executor(tmp_path)
    dispatcher = ExecutorRemoteDispatcher(executor)
    parity = executor.operations.capabilities_snapshot()
    manifest = dispatcher.capability_manifest()

    assert manifest["tool_parity"] == parity
    assert manifest["executor"]["digest"] == parity["attestation"]["digest"]
    assert manifest["executor"]["contract_version"] == parity["contract_version"]
    assert manifest["executor"]["schema_versions"] == parity["schema_versions"]
    assert set(manifest["executor"]["actions"]) == set(OPS_ACTIONS)


def test_observed_desktop_commander_operations_remain_registry_backed() -> None:
    root = Path(__file__).resolve().parents[1]
    mapping = json.loads(
        (root / "tests" / "fixtures" / "native_tool_parity_v1"
         / "desktop_commander_mapping.json").read_text(encoding="utf-8")
    )
    by_reference = {item["reference"]: item for item in mapping["mappings"]}
    exposed_actions = {tool.executor_action for tool in TOOL_REGISTRY_LIST}
    required = {
        "read_file",
        "read_multiple_files",
        "write_file",
        "edit_block",
        "start_process",
        "read_process_output",
        "list_sessions",
        "force_terminate",
    }
    for name in required:
        candidates = set(by_reference[name]["candidate"])
        assert candidates, name
        assert candidates <= exposed_actions, (name, candidates - exposed_actions)


@pytest.mark.asyncio
async def test_observed_file_and_process_workflow_through_remote_adapter(
    tmp_path: Path,
) -> None:
    executor = _executor(tmp_path)
    dispatcher = ExecutorRemoteDispatcher(executor)
    context = _context(dispatcher)
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_text("one\n", encoding="utf-8")
    second.write_text("two\n", encoding="utf-8")

    read_one = await _call(
        dispatcher, context, "read-one", "file.read", {"path": str(first)}
    )
    read_two = await _call(
        dispatcher, context, "read-two", "file.read", {"path": str(second)}
    )
    assert read_one.payload["data"]["text"] == "one\n"
    assert read_two.payload["data"]["text"] == "two\n"
    assert read_one.stream_data == b"one\n"
    assert read_two.stream_data == b"two\n"

    target = tmp_path / "written.txt"
    written = await _call(
        dispatcher,
        context,
        "write-one",
        "file.write",
        {"path": str(target), "text": "alpha alpha\n", "overwrite": True},
    )
    assert written.payload["status"] == "completed"
    before = hashlib.sha256(target.read_bytes()).hexdigest()
    edited = await _call(
        dispatcher,
        context,
        "edit-one",
        "file.edit",
        {
            "path": str(target),
            "old_text": "alpha",
            "new_text": "omega",
            "expected_replacements": 2,
            "expected_current_hash": before,
        },
    )
    assert edited.payload["status"] == "completed"
    assert target.read_text(encoding="utf-8") == "omega omega\n"

    started = await _call(
        dispatcher,
        context,
        "proc-start",
        "process.start",
        {
            "argv": [
                sys.executable,
                "-c",
                "import time; print('remote-ok', flush=True); time.sleep(30)",
            ],
            "cwd": str(tmp_path),
        },
    )
    assert started.payload["status"] == "completed"
    handle_id = started.payload["data"]["handle_id"]
    try:
        output = await _call(
            dispatcher,
            context,
            "proc-read",
            "process.read",
            {"handle_id": handle_id, "wait_ms": 1000, "max_bytes": 4096},
        )
        assert output.payload["status"] == "completed"
        assert output.stream_kind == "process_output"
        assert b"remote-ok" in output.stream_data

        sessions = await _call(
            dispatcher,
            context,
            "proc-list",
            "process.list",
            {"include_stale": False, "max_results": 50},
        )
        ids = {item["handle_id"] for item in sessions.payload["data"]["handles"]}
        assert handle_id in ids
    finally:
        terminated = await _call(
            dispatcher,
            context,
            "proc-stop",
            "process.terminate",
            {"handle_id": handle_id, "grace_ms": 100},
        )
        assert terminated.payload["status"] == "completed"
