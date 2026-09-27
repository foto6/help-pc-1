from __future__ import annotations

import sys
from pathlib import Path

import pytest

from pc_executor.executor import Executor
from pc_executor.operations import (
    NATIVE_TOOL_PARITY_VERSION,
    OPS_ACTIONS,
    OPS_SIDE_EFFECT_ACTIONS,
    LocalOperations,
)
from pc_executor.outcome_journal import OutcomeJournal
from pc_executor.shell import SafeShellAdapter
from pc_remote_transport import (
    ExecutorRemoteDispatcher,
    NATIVE_CONTROL_PROTOCOL_V1,
    PARITY_TOOL_REGISTRY_V1,
    TransportDispatchContext,
)
from pc_remote_transport.executor_adapter import (
    PARITY_TOOL_REGISTRY_LIST,
    TOOL_REGISTRY_DIGEST,
)
from pc_remote_transport.protocol import digest_json


EXPECTED_COMPAT_DIGEST = (
    "58b2bde8c6a49825747dcd7010f105dad0b6d548c7e8341cdafb32d2319f6dcd"
)


def _executor(tmp_path: Path) -> Executor:
    executable = Path(sys.executable).name.lower()
    shell = SafeShellAdapter(
        allow_executables={executable, "python", "python.exe", "python3"},
        output_limit_bytes=65536,
    )
    operations = LocalOperations(
        shell=shell,
        state_root=tmp_path / "ops",
    )
    return Executor(
        shell=shell,
        operations=operations,
        outcome_journal=OutcomeJournal(tmp_path / "outcomes.jsonl"),
        dry_run=False,
        operation_timeout_seconds=3.0,
    )
def _context(dispatcher: ExecutorRemoteDispatcher) -> TransportDispatchContext:
    return TransportDispatchContext(
        device_id="device-registry",
        session_epoch="epoch-registry-0001",
        session_capabilities_digest=digest_json(dispatcher.capability_manifest()),
    )


def _body(
    request_id: str,
    tool: str,
    arguments: dict | None = None,
    *,
    registry_version: str | None = None,
) -> dict:
    value = {
        "contract_version": NATIVE_CONTROL_PROTOCOL_V1,
        "session_id": "control-registry",
        "request_id": request_id,
        "tool": tool,
        "arguments": arguments or {},
    }
    if registry_version is not None:
        value["registry_version"] = registry_version
    return value


async def _call(
    dispatcher: ExecutorRemoteDispatcher,
    context: TransportDispatchContext,
    request_id: str,
    tool: str,
    arguments: dict | None = None,
    *,
    registry_version: str | None = None,
):
    return await dispatcher.dispatch(
        request_version=NATIVE_CONTROL_PROTOCOL_V1,
        request_id=request_id,
        body=_body(
            request_id,
            tool,
            arguments,
            registry_version=registry_version,
        ),
        transport_context=context,
    )


def test_registry_policy_keeps_compat_digest_and_direct_parity_invariants(
    tmp_path: Path,
) -> None:
    executor = _executor(tmp_path)
    dispatcher = ExecutorRemoteDispatcher(executor)
    manifest = dispatcher.capability_manifest()

    assert TOOL_REGISTRY_DIGEST == EXPECTED_COMPAT_DIGEST
    assert manifest["registry_digest"] == EXPECTED_COMPAT_DIGEST
    assert manifest["compatibility"]["registry_digest"] == EXPECTED_COMPAT_DIGEST
    assert manifest["compatibility"]["default_for_unversioned_requests"] is True
    assert manifest["internal_registry"]["contract_version"] == PARITY_TOOL_REGISTRY_V1
    assert manifest["tool_parity"]["native_tool_parity_version"] == NATIVE_TOOL_PARITY_VERSION

    direct = {tool.executor_action: tool for tool in PARITY_TOOL_REGISTRY_LIST}
    assert set(direct) <= set(OPS_ACTIONS)
    for action, tool in direct.items():
        assert (tool.effect == "side_effect") == (
            action in OPS_SIDE_EFFECT_ACTIONS
        )
@pytest.mark.asyncio
async def test_compat_set_config_maps_to_current_config_set(tmp_path: Path) -> None:
    executor = _executor(tmp_path)
    dispatcher = ExecutorRemoteDispatcher(executor)
    context = _context(dispatcher)

    result = await _call(
        dispatcher,
        context,
        "compat-config-set-1",
        "device.set_config",
        {
            "key": "diagnostics.max_recent_calls",
            "value": 25,
        },
    )
    assert result.payload["status"] == "completed"
    assert executor.operations.settings.value("diagnostics.max_recent_calls") == 25


@pytest.mark.asyncio
async def test_compat_uia_find_is_explicitly_unavailable(tmp_path: Path) -> None:
    executor = _executor(tmp_path)
    dispatcher = ExecutorRemoteDispatcher(executor)
    context = _context(dispatcher)

    result = await _call(
        dispatcher,
        context,
        "compat-uia-find-1",
        "uia.find",
        {"query": {"automation_id": "never-dispatched"}},
    )
    assert result.payload["status"] == "error"
    assert result.payload["error"]["code"] == "CAPABILITY_UNAVAILABLE"
    route = dispatcher.capability_manifest()["compatibility"]["routes"]["uia.find"]
    assert route["status"] == "capability_unavailable"
    assert route["target_action"] is None


@pytest.mark.asyncio
async def test_compat_process_interact_requires_interactive_session(
    tmp_path: Path,
) -> None:
    executor = _executor(tmp_path)
    dispatcher = ExecutorRemoteDispatcher(executor)
    context = _context(dispatcher)

    process = await _call(
        dispatcher,
        context,
        "compat-process-start-1",
        "process.start",
        {
            "argv": [
                sys.executable,
                "-c",
                "import time; time.sleep(5)",
            ]
        },
    )
    assert process.payload["status"] == "completed"
    process_handle = process.payload["data"]["handle_id"]
    blocked = await _call(
        dispatcher,
        context,
        "compat-process-interact-wrong-kind",
        "process.interact",
        {
            "process_handle": process_handle,
            "input": "hello\n",
        },
    )
    assert blocked.payload["status"] == "error"
    assert blocked.payload["error"]["code"] == "CAPABILITY_UNAVAILABLE"

    terminated = await _call(
        dispatcher,
        context,
        "compat-process-stop-1",
        "process.terminate",
        {"process_handle": process_handle, "grace_ms": 100},
    )
    assert terminated.payload["status"] == "completed"

    session = await _call(
        dispatcher,
        context,
        "compat-session-open-1",
        "shell.session.open",
        {
            "argv": [
                sys.executable,
                "-u",
                "-c",
                (
                    "import sys; "
                    "value=sys.stdin.readline().strip(); "
                    "print('echo:'+value, flush=True)"
                ),
            ]
        },
    )
    assert session.payload["status"] == "completed"
    session_id = session.payload["data"]["session_id"]

    interacted = await _call(
        dispatcher,
        context,
        "compat-process-interact-session",
        "process.interact",
        {
            "process_handle": session_id,
            "input": "hello\n",
        },
    )
    assert interacted.payload["status"] == "completed"
    assert interacted.payload["data"]["written_bytes"] == len("hello\n")

    output = await _call(
        dispatcher,
        context,
        "compat-session-read-1",
        "shell.session.read",
        {
            "session_handle": session_id,
            "wait_ms": 1000,
            "max_bytes": 4096,
        },
    )
    assert output.payload["status"] == "completed"
    assert "echo:hello" in output.payload["data"]["stdout"]
