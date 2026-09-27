from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from pc_executor.executor import Executor
from pc_executor.models import ActionRequest
from pc_executor.operations import OPS_ACTIONS, OPS_SIDE_EFFECT_ACTIONS, LocalOperations
from pc_executor.outcome_journal import OutcomeJournal
from pc_executor.safety import SafetyViolation
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


def _request(action: str, params: dict, request_id: str) -> ActionRequest:
    return ActionRequest(
        action=action,
        params=params,
        request_id=request_id,
        timeout_ms=5000,
    )


def test_gap_actions_are_first_class_capabilities(tmp_path: Path) -> None:
    required = {
        "fs.read_multiple",
        "config.set",
        "agent.shutdown",
        "identity.who_am_i",
        "diagnostics.usage_stats",
        "diagnostics.recent_tool_calls",
        "pdf.write",
    }
    assert required <= OPS_ACTIONS
    assert {"config.set", "agent.shutdown", "pdf.write"} <= OPS_SIDE_EFFECT_ACTIONS
    caps = _executor(tmp_path).operations.capabilities_snapshot()
    assert required <= set(caps["actions"])
    assert caps["actions"]["fs.read_multiple"]["side_effecting"] is False
    assert caps["actions"]["config.set"]["side_effecting"] is True


def test_batch_read_is_ordered_per_file_and_aggregate_bounded(tmp_path: Path) -> None:
    first = tmp_path / "first.txt"
    missing = tmp_path / "missing.txt"
    third = tmp_path / "third.txt"
    first.write_text("alpha", encoding="utf-8")
    third.write_text("charlie", encoding="utf-8")
    result = _executor(tmp_path).execute(
        _request(
            "fs.read_multiple",
            {
                "paths": [str(first), str(missing), str(third)],
                "max_bytes_per_file": 16,
                "max_total_bytes": 16,
            },
            "batch-ordered",
        )
    )
    assert result.ok
    items = result.data["results"]
    assert [Path(item["path"]).name for item in items] == [
        "first.txt",
        "missing.txt",
        "third.txt",
    ]
    assert items[0]["ok"] is True and items[0]["text"] == "alpha"
    assert items[1]["ok"] is False
    assert items[2]["ok"] is True and items[2]["text"] == "charlie"
    assert result.data["returned_bytes"] <= 16

    blocked = _executor(tmp_path).execute(
        _request(
            "fs.read_multiple",
            {"paths": [str(first)], "max_total_bytes": 4 * 1024 * 1024},
            "batch-too-large",
        )
    )
    assert blocked.ok is False
    assert blocked.status == "blocked"


def test_batch_protected_path_is_rejected_before_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ops = LocalOperations(shell=_shell(), state_root=tmp_path / "ops-state")
    probes: list[str] = []

    def forbidden_exists(self: Path) -> bool:
        probes.append(str(self))
        raise AssertionError("filesystem probe occurred")

    monkeypatch.setattr(Path, "exists", forbidden_exists)
    result = ops.execute(
        "fs.read_multiple",
        {"paths": [r"E:\manhwa\must-not-touch.txt"]},
    )
    assert result["results"][0]["ok"] is False
    assert probes == []


def test_config_set_allowlist_is_atomic_and_never_unrestricts(
    tmp_path: Path,
) -> None:
    executor = _executor(tmp_path)
    valid = executor.execute(
        _request(
            "config.set",
            {"key": "batch_read.max_aggregate_bytes", "value": 2048},
            "config-valid",
        )
    )
    assert valid.ok
    assert (
        executor.operations.settings.value("batch_read.max_aggregate_bytes")
        == 2048
    )

    invalid = executor.execute(
        _request(
            "config.set",
            {"key": "batch_read.max_aggregate_bytes", "value": 0},
            "config-invalid",
        )
    )
    assert invalid.ok is False
    assert (
        executor.operations.settings.value("batch_read.max_aggregate_bytes")
        == 2048
    )
    reloaded = LocalOperations(
        shell=_shell(),
        state_root=tmp_path / "ops-state",
    )
    assert reloaded.settings.value("batch_read.max_aggregate_bytes") == 2048

    empty_roots = executor.execute(
        _request(
            "config.set",
            {"key": "filesystem.allowed_roots", "value": []},
            "config-empty-roots",
        )
    )
    assert empty_roots.ok is False
    assert executor.operations.settings.value("filesystem.allowed_roots")

    unknown = executor.execute(
        _request(
            "config.set",
            {"key": "arbitrary.unsafe.setting", "value": True},
            "config-unknown",
        )
    )
    assert unknown.ok is False


def test_config_side_effect_requires_outcome_journal(tmp_path: Path) -> None:
    executor = _executor(tmp_path, journal=False)
    before = executor.operations.settings.value("diagnostics.max_recent_calls")
    result = executor.execute(
        _request(
            "config.set",
            {"key": "diagnostics.max_recent_calls", "value": 10},
            "config-no-journal",
        )
    )
    assert result.status == "blocked"
    assert executor.operations.settings.value("diagnostics.max_recent_calls") == before


def test_shutdown_is_journaled_and_bound_to_active_device_session(
    tmp_path: Path,
) -> None:
    executor = _executor(tmp_path)
    ops = executor.operations
    ops.bind_agent_session(
        device_id="device-a",
        session_id="control-a",
        session_epoch="epoch-a",
    )
    stale = executor.execute(
        _request(
            "agent.shutdown",
            {
                "device_id": "device-a",
                "session_id": "control-a",
                "session_epoch": "epoch-stale",
                "generation_id": ops.generation_id,
            },
            "shutdown-stale",
        )
    )
    assert stale.ok is False
    assert ops.shutdown_requested is False

    current = executor.execute(
        _request(
            "agent.shutdown",
            {
                "device_id": "device-a",
                "session_id": "control-a",
                "session_epoch": "epoch-a",
                "generation_id": ops.generation_id,
            },
            "shutdown-current",
        )
    )
    assert current.ok
    assert current.outcome_evidence.effect_state == "completed"
    assert ops.shutdown_requested is True


def test_shutdown_without_journal_never_sets_event(tmp_path: Path) -> None:
    executor = _executor(tmp_path, journal=False)
    ops = executor.operations
    ops.bind_agent_session(
        device_id="device-a",
        session_id="control-a",
        session_epoch="epoch-a",
    )
    result = executor.execute(
        _request(
            "agent.shutdown",
            {
                "device_id": "device-a",
                "session_id": "control-a",
                "session_epoch": "epoch-a",
                "generation_id": ops.generation_id,
            },
            "shutdown-no-journal",
        )
    )
    assert result.status == "blocked"
    assert ops.shutdown_requested is False


def test_identity_and_diagnostics_are_sanitized(tmp_path: Path) -> None:
    executor = _executor(tmp_path)
    secret = "do-not-leak-this-raw-content"
    target = tmp_path / "diag.txt"
    target.write_text(secret, encoding="utf-8")
    read = executor.execute(
        _request("fs.read_text", {"path": str(target)}, "diagnostic-read")
    )
    assert read.ok and secret in read.data["text"]

    identity = executor.execute(
        _request("identity.who_am_i", {}, "identity")
    )
    assert identity.ok
    assert identity.data["secret_fields_included"] is False
    assert "credentials" not in identity.data
    assert "environment" not in identity.data

    usage = executor.execute(
        _request("diagnostics.usage_stats", {}, "usage")
    )
    recent = executor.execute(
        _request(
            "diagnostics.recent_tool_calls",
            {"max_results": 50},
            "recent",
        )
    )
    assert usage.ok and recent.ok
    serialized = json.dumps(recent.data, sort_keys=True)
    assert secret not in serialized
    assert str(target) not in serialized
    assert any(item["action"] == "fs.read_text" for item in recent.data["calls"])
    assert all(
        set(item)
        == {
            "request_id",
            "action",
            "status",
            "started_at",
            "finished_at",
            "dry_run",
            "effect_state",
        }
        for item in recent.data["calls"]
    )


def test_pdf_create_and_modify_always_write_new_output(tmp_path: Path) -> None:
    executor = _executor(tmp_path)
    source = tmp_path / "source.pdf"
    created = executor.execute(
        _request(
            "pdf.write",
            {"path": str(source), "content": "# Title\n\nBody"},
            "pdf-create",
        )
    )
    assert created.ok
    original = source.read_bytes()
    assert original.startswith(b"%PDF")
    original_hash = hashlib.sha256(original).hexdigest()

    output = tmp_path / "modified.pdf"
    modified = executor.execute(
        _request(
            "pdf.write",
            {
                "path": str(source),
                "output_path": str(output),
                "content": [
                    {"type": "insert", "page_index": 1, "markdown": "# Added"},
                    {"type": "delete", "page_indexes": [0]},
                ],
            },
            "pdf-modify",
        )
    )
    assert modified.ok
    assert output.exists()
    assert output.read_bytes().startswith(b"%PDF")
    assert hashlib.sha256(source.read_bytes()).hexdigest() == original_hash

    overwrite = executor.execute(
        _request(
            "pdf.write",
            {"path": str(source), "content": "# Replacement"},
            "pdf-overwrite",
        )
    )
    assert overwrite.ok is False
    assert hashlib.sha256(source.read_bytes()).hexdigest() == original_hash


def test_pdf_side_effect_requires_journal_before_write(tmp_path: Path) -> None:
    output = tmp_path / "no-journal.pdf"
    result = _executor(tmp_path, journal=False).execute(
        _request(
            "pdf.write",
            {"path": str(output), "content": "# No"},
            "pdf-no-journal",
        )
    )
    assert result.status == "blocked"
    assert not output.exists()


def test_pdf_protected_output_rejects_before_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ops = LocalOperations(shell=_shell(), state_root=tmp_path / "ops-state")
    probes: list[str] = []

    def forbidden_exists(self: Path) -> bool:
        probes.append(str(self))
        raise AssertionError("filesystem probe occurred")

    monkeypatch.setattr(Path, "exists", forbidden_exists)
    with pytest.raises(SafetyViolation):
        ops.preflight(
            "pdf.write",
            {
                "path": r"E:\manhwa\must-not-touch.pdf",
                "content": "# blocked",
            },
        )
    assert probes == []


@pytest.mark.asyncio
async def test_remote_adapter_reuses_frozen_set_config_slot(tmp_path: Path) -> None:
    from pc_executor.models import canonical_json
    from pc_remote_transport.agent import TransportDispatchContext
    from pc_remote_transport.executor_adapter import (
        ExecutorRemoteDispatcher,
        TOOL_REGISTRY_DIGEST,
    )

    executor = _executor(tmp_path)
    dispatcher = ExecutorRemoteDispatcher(executor)
    manifest = dispatcher.capability_manifest()
    manifest_digest = hashlib.sha256(
        canonical_json(manifest).encode("utf-8")
    ).hexdigest()
    result = await dispatcher.dispatch(
        request_version="pc.native.control.v1",
        request_id="remote-config",
        body={
            "contract_version": "pc.native.control.v1",
            "session_id": "session-a",
            "request_id": "remote-config",
            "tool": "device.set_config",
            "arguments": {
                "key": "diagnostics.max_recent_calls",
                "value": 25,
            },
        },
        transport_context=TransportDispatchContext(
            device_id="device-a",
            session_epoch="epoch-a",
            session_capabilities_digest=manifest_digest,
        ),
    )
    assert manifest["registry_digest"] == TOOL_REGISTRY_DIGEST
    assert result.payload["status"] == "completed"
    assert executor.operations.settings.value("diagnostics.max_recent_calls") == 25
