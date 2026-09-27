from __future__ import annotations

import asyncio
import json
import sys
import threading
from pathlib import Path

import pytest

import pc_executor.admin_config as admin_config_module
from pc_executor.admin_config import AdminConfigStore
from pc_executor.executor import Executor
from pc_executor.models import ActionRequest
from pc_executor.operations import LocalOperations
from pc_executor.outcome_journal import OutcomeJournal
from pc_executor.shell import SafeShellAdapter
from pc_remote_transport import (
    DeviceAgent,
    ExecutorRemoteDispatcher,
    RequestLedger,
    TokenRing,
    TransportDispatchContext,
)
from pc_remote_transport.agent import DispatchResult
from pc_remote_transport.protocol import TokenMaterial, digest_json
from pc_remote_transport.service import (
    ConfigStore,
    DeviceServiceHost,
    HealthStore,
    RuntimeBundle,
    ServiceConfig,
)


def _shell() -> SafeShellAdapter:
    executable = Path(sys.executable).name.lower()
    return SafeShellAdapter(
        allow_executables={"python", "python.exe", "python3", executable},
        output_limit_bytes=65536,
    )


def _executor(tmp_path: Path) -> Executor:
    shell = _shell()
    return Executor(
        shell=shell,
        operations=LocalOperations(shell=shell, state_root=tmp_path / "ops"),
        outcome_journal=OutcomeJournal(tmp_path / "outcomes.jsonl"),
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


def _context(dispatcher: ExecutorRemoteDispatcher) -> TransportDispatchContext:
    return TransportDispatchContext(
        device_id="device-dc-parity",
        session_epoch="epoch-dc-parity-0001",
        session_capabilities_digest=digest_json(dispatcher.capability_manifest()),
    )


def _body(request_id: str, tool: str, arguments: dict | None = None) -> dict:
    return {
        "contract_version": "pc.native.control.v1",
        "session_id": "control-dc-parity",
        "request_id": request_id,
        "tool": tool,
        "arguments": arguments or {},
    }


def test_read_many_preserves_order_errors_and_aggregate_bound(tmp_path: Path) -> None:
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_text("a\n", encoding="utf-8")
    second.write_text("b\nc\n", encoding="utf-8")
    missing = tmp_path / "missing.txt"
    executor = _executor(tmp_path)

    result = executor.execute(
        _request(
            "fs.read_many",
            {
                "paths": [str(first), str(missing), str(second)],
                "max_bytes_per_file": 4,
                "max_total_bytes": 4,
            },
            "read-many-1",
        )
    )
    assert result.ok
    rows = result.data["results"]
    assert [row["path"] for row in rows] == [str(first), str(missing), str(second)]
    assert rows[0]["ok"] is True and rows[0]["text"] == "a\n"
    assert rows[1] == {
        "path": str(missing),
        "ok": False,
        "error": {"code": "NOT_FOUND"},
    }
    assert rows[2]["ok"] is True
    assert result.data["returned_bytes"] <= 4
    assert sum(row.get("returned_bytes", 0) for row in rows) == result.data["returned_bytes"]


def test_read_many_protected_path_is_per_file_reject(tmp_path: Path) -> None:
    executor = _executor(tmp_path)
    protected = r"E:\manhwa\never-touch.txt"
    result = executor.execute(
        _request("fs.read_many", {"paths": [protected]}, "read-many-protected")
    )
    assert result.ok
    assert result.data["results"] == [
        {
            "path": protected,
            "ok": False,
            "error": {"code": "POLICY_BLOCKED"},
        }
    ]


def test_mutable_config_allowlist_and_empty_roots_deny_all(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    target = allowed / "file.txt"
    target.write_text("safe\n", encoding="utf-8")
    executor = _executor(tmp_path)

    before = executor.execute(_request("config.get", {}, "cfg-get-1"))
    revision = before.data["admin_config_revision"]
    configured = executor.execute(
        _request(
            "config.set",
            {
                "key": "allowed_roots",
                "value": [str(allowed)],
                "expected_revision": revision,
            },
            "cfg-set-1",
        )
    )
    assert configured.ok
    read = executor.execute(
        _request("fs.read_text", {"path": str(target)}, "cfg-read-1")
    )
    assert read.ok and read.data["text"] == "safe\n"

    denied = executor.execute(
        _request(
            "config.set",
            {
                "key": "allowed_roots",
                "value": [],
                "expected_revision": configured.data["revision"],
            },
            "cfg-set-2",
        )
    )
    assert denied.ok
    blocked = executor.execute(
        _request("fs.read_text", {"path": str(target)}, "cfg-read-2")
    )
    assert blocked.status == "blocked"
    assert "allowed_roots denies all" in (blocked.error or "")


def test_admin_config_atomic_rollback_on_post_write_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = AdminConfigStore(tmp_path / "admin")
    first = store.update_key(key="allowed_roots", value=[str(tmp_path)])
    before = store.path.read_bytes()
    original_write = admin_config_module._atomic_write
    injected = False

    def fail_once(path: Path, payload: bytes) -> None:
        nonlocal injected
        original_write(path, payload)
        if path == store.path and not injected:
            injected = True
            raise RuntimeError("simulated post-write failure")

    monkeypatch.setattr(admin_config_module, "_atomic_write", fail_once)
    with pytest.raises(RuntimeError, match="simulated"):
        store.update_key(
            key="read_many_max_bytes",
            value=first.read_many_max_bytes // 2,
            expected_revision=store.revision(first),
        )
    monkeypatch.setattr(admin_config_module, "_atomic_write", original_write)
    assert store.path.read_bytes() == before
    assert store.load() == first


def test_sanitized_audit_history_and_metrics_never_return_details(tmp_path: Path) -> None:
    executor = _executor(tmp_path)
    target = tmp_path / "audit.txt"
    secret_text = "SECRET-PAYLOAD-MUST-NOT-APPEAR"
    written = executor.execute(
        _request(
            "fs.write_text",
            {"path": str(target), "text": secret_text, "overwrite": True},
            "audit-write",
        )
    )
    assert written.ok

    history = executor.execute(
        _request("audit.history", {"limit": 50}, "audit-history")
    )
    assert history.ok and history.data["sanitized"] is True
    serialized = json.dumps(history.data, sort_keys=True)
    assert secret_text not in serialized
    assert "details" not in serialized
    assert all(
        set(event) == {
            "request_id",
            "action",
            "phase",
            "timestamp",
            "dry_run",
            "outcome",
        }
        for event in history.data["events"]
    )

    metrics = executor.execute(_request("metrics.get", {}, "metrics-get"))
    assert metrics.ok and metrics.data["sanitized"] is True
    assert "fs.write_text" in metrics.data["actions"]
    assert secret_text not in json.dumps(metrics.data, sort_keys=True)


def test_identity_is_non_sensitive_controller_device_metadata(tmp_path: Path) -> None:
    result = _executor(tmp_path).execute(
        _request("identity.get", {}, "identity-local")
    )
    assert result.ok
    assert result.data["controller"] == "pc_executor"
    assert result.data["device_id"] == "local"
    assert result.data["transport"] == "native_local"
    assert "username" not in result.data
    assert "user_id" not in result.data
    assert "token" not in result.data


@pytest.mark.asyncio
async def test_remote_identity_and_shutdown_bind_authenticated_context(
    tmp_path: Path,
) -> None:
    executor = _executor(tmp_path)
    dispatcher = ExecutorRemoteDispatcher(executor)
    context = _context(dispatcher)

    identity = await dispatcher.dispatch(
        request_version="pc.native.control.v1",
        request_id="remote-identity",
        body=_body("remote-identity", "device.identity"),
        transport_context=context,
    )
    assert identity.payload["status"] == "completed"
    assert identity.payload["data"]["device_id"] == context.device_id
    assert identity.payload["data"]["session_epoch"] == context.session_epoch

    stale = await dispatcher.dispatch(
        request_version="pc.native.control.v1",
        request_id="remote-shutdown-stale",
        body=_body(
            "remote-shutdown-stale",
            "device.shutdown",
            {"session_epoch": "epoch-stale-0001"},
        ),
        transport_context=context,
    )
    assert stale.payload["status"] == "error"
    assert stale.payload["error"]["code"] == "STALE_SESSION"

    shutdown = await dispatcher.dispatch(
        request_version="pc.native.control.v1",
        request_id="remote-shutdown",
        body=_body("remote-shutdown", "device.shutdown"),
        transport_context=context,
    )
    assert shutdown.payload["status"] == "completed"
    assert shutdown.shutdown_agent is True
    assert shutdown.payload["data"]["device_id"] == context.device_id
    assert shutdown.payload["data"]["session_epoch"] == context.session_epoch
    lookup = executor.read_outcome_evidence(
        request_id="remote-shutdown",
        action="device.shutdown",
    )
    assert lookup["outcome"] == "succeeded"


class _ShutdownDispatcher:
    async def dispatch(self, **kwargs):
        return DispatchResult(payload={"ok": True}, shutdown_agent=True)


@pytest.mark.asyncio
async def test_device_agent_shutdown_flag_prevents_reconnect(tmp_path: Path) -> None:
    agent = DeviceAgent(
        device_id="device-dc-parity",
        token_ring=TokenRing(1, b"x" * 32),
        capabilities=lambda: {},
        dispatcher=_ShutdownDispatcher(),
        ledger=RequestLedger(tmp_path / "ledger"),
        heartbeat_seconds=0,
    )
    sent: list[tuple[str, dict]] = []

    async def send(kind: str, payload: dict) -> None:
        sent.append((kind, payload))

    await agent._handle_request(
        {
            "request_id": "shutdown-agent",
            "request_version": "pc.native.control.v1",
            "delivery_id": "delivery-shutdown-agent",
            "semantics": "side_effecting",
            "body": {},
        },
        send,
        transport_context=TransportDispatchContext(
            device_id="device-dc-parity",
            session_epoch="epoch-agent-0001",
            session_capabilities_digest="a" * 64,
        ),
    )
    assert agent.shutdown_requested is True
    assert sent and sent[0][0] == "response"

    class Connector:
        def __init__(self):
            self.opens = 0

        async def open(self):
            self.opens += 1
            raise AssertionError("shutdown agent must not reconnect")

    connector = Connector()
    await agent.run_forever(connector)
    assert connector.opens == 0


class _MemorySecrets:
    def __init__(self) -> None:
        self.material = TokenMaterial(1, b"s" * 32)

    def read(self, target: str) -> TokenMaterial:
        return self.material

    def write(self, target: str, material: TokenMaterial) -> None:
        self.material = material

    def delete(self, target: str) -> None:
        pass


class _ImmediateShutdownAgent:
    shutdown_requested = True

    async def run_forever(self, connector, *, enabled, backoff, sleep) -> None:
        return


@pytest.mark.asyncio
async def test_service_remote_shutdown_atomically_disables_transport(tmp_path: Path) -> None:
    store = ConfigStore(tmp_path / "service")
    store.update(
        ServiceConfig(
            enabled=True,
            endpoint="wss://relay.example.test/device",
            device_id="device-dc-parity",
        )
    )
    health = HealthStore(store.root)
    secrets = _MemorySecrets()

    def factory(*args):
        return RuntimeBundle(agent=_ImmediateShutdownAgent(), connector=object())

    host = DeviceServiceHost(
        store,
        health,
        secrets,
        runtime_factory=factory,
        poll_seconds=0.01,
    )
    stop = threading.Event()
    task = asyncio.create_task(host.run(stop))
    for _ in range(100):
        await asyncio.sleep(0.005)
        if not store.load().enabled:
            break
    assert store.load().enabled is False
    snapshot = health.read()
    assert snapshot.enabled is False
    assert snapshot.reason_code == "REMOTE_SHUTDOWN"
    stop.set()
    await asyncio.wait_for(task, timeout=1)


@pytest.mark.asyncio
async def test_remote_read_many_streams_bounded_batch_result(tmp_path: Path) -> None:
    first = tmp_path / "remote-first.txt"
    second = tmp_path / "remote-second.txt"
    first.write_text("first\n", encoding="utf-8")
    second.write_text("second\n", encoding="utf-8")
    executor = _executor(tmp_path)
    dispatcher = ExecutorRemoteDispatcher(executor)
    context = _context(dispatcher)

    result = await dispatcher.dispatch(
        request_version="pc.native.control.v1",
        request_id="remote-read-many",
        body=_body(
            "remote-read-many",
            "file.read_many",
            {
                "paths": [str(first), str(second)],
                "max_bytes_per_file": 64,
                "max_total_bytes": 128,
            },
        ),
        transport_context=context,
    )
    assert result.payload["status"] == "completed"
    assert result.payload["data"]["count"] == 2
    assert result.payload["data"]["stream_contains"] == "full_batch_result_json"
    assert result.stream_kind == "file_read"
    streamed = json.loads(result.stream_data.decode("utf-8"))
    assert [row["path"] for row in streamed["results"]] == [
        str(first),
        str(second),
    ]
    assert [row["text"] for row in streamed["results"]] == [
        "first\n",
        "second\n",
    ]
    assert streamed["returned_bytes"] <= 128
