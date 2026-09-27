from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path

import pytest

from pc_executor.audit import InMemoryAuditSink
from pc_executor.context_binding import CwdIdentity
from pc_executor.executor import Executor
from pc_executor.fakes import (
    ReplayInputAdapter,
    ReplayScreenshotProvider,
    ReplayShellAdapter,
    ReplayUIAAdapter,
    ReplayWindowEnumerator,
)
from pc_executor.outcome_journal import OutcomeJournal
from pc_executor.shell import ShellResult
from pc_remote_transport import (
    DeviceAgent,
    ExecutorRemoteDispatcher,
    NATIVE_CONTROL_PROTOCOL_V1,
    RequestLedger,
    StaleEpochError,
    StreamAssembler,
    TokenMaterial,
    TokenRing,
    TransportDispatchContext,
)
from pc_remote_transport.executor_adapter import TOOL_REGISTRY_DIGEST
from pc_remote_transport.protocol import FRAME_VERSION, decode_frame, digest_json, encode_frame


EXPECTED_HELP_PC_2_REGISTRY_DIGEST = "58b2bde8c6a49825747dcd7010f105dad0b6d548c7e8341cdafb32d2319f6dcd"
_SENTINEL = object()


class StaticContextObserver:
    def __init__(self) -> None:
        self.cwd_calls = 0

    def foreground(self):
        return None

    def display_at(self, x: int, y: int):
        return None

    def cwd_identity(self, cwd: str | None) -> CwdIdentity:
        self.cwd_calls += 1
        return CwdIdentity("1" * 64, 7, 11)


class SpyExecutor:
    def __init__(self, actions: dict[str, bool]) -> None:
        self.actions = dict(actions)
        self.digest = "a" * 64
        self.outcome_journal = object()
        self.preflight_calls = 0
        self.execute_calls = 0
        self.last_request = None
        self.results: dict[str, dict] = {}
        self.unknown_actions: set[str] = set()
        self.prior_requests: set[tuple[str, str]] = set()
        self.binding_calls = 0

    def capabilities_snapshot(self) -> dict:
        return {
            "contract_version": "pc_executor.capabilities.v1",
            "actions": {
                action: {
                    "supported": True,
                    "side_effecting": side_effecting,
                }
                for action, side_effecting in sorted(self.actions.items())
            },
            "attestation": {
                "algorithm": "sha256",
                "digest": self.digest,
            },
        }

    def preflight(self, payload: dict) -> dict:
        self.preflight_calls += 1
        request = payload["request"]
        action = request["action"]
        supported = action in self.actions
        return {
            "contract_version": "pc_executor.action_preflight.v1",
            "request_id": request["request_id"],
            "action": action,
            "status": "ready" if supported else "unsupported",
            "executable": supported,
            "capabilities_digest": self.digest,
            "deadline_budget_ms": 5000,
            "reasons": [],
            "target": None,
        }

    def read_outcome_evidence(
        self,
        *,
        request_id: str,
        action: str,
        execution_attempt: int | None = None,
    ) -> dict:
        prior = (request_id, action) in self.prior_requests
        return {
            "reason": "completed" if prior else "no_evidence",
            "latest_valid_record": {"request_id": request_id} if prior else None,
            "provenance": {"matched_records": 1 if prior else 0},
        }

    def bind_execution_context(self, request) -> dict:
        self.binding_calls += 1
        return {
            "contract_version": "pc_executor.execution_context_binding.v1",
            "request_id": request.request_id,
            "action": request.action,
            "context_kind": "shell",
            "authoritative_fields": ["request.identity"],
            "process": None,
            "window": None,
            "target": None,
            "display": None,
            "shell": None,
            "context_digest": "b" * 64,
        }

    def execute(self, request):
        self.execute_calls += 1
        self.last_request = request
        data = dict(self.results.get(request.action, {"ok": True}))
        side_effect = self.actions.get(request.action, False)
        if side_effect:
            unknown = request.action in self.unknown_actions
            outcome = {
                "effect_state": "unknown" if unknown else "completed",
                "reconciliation_required": unknown,
                "dispatch_started": True,
            }
            if not unknown:
                self.prior_requests.add((request.request_id, request.action))
        else:
            outcome = None
        result = {
            "request_id": request.request_id,
            "action": request.action,
            "ok": True,
            "status": "completed",
            "data": data,
            "error": None,
            "error_kind": None,
            "dry_run": False,
        }
        if outcome is not None:
            result["outcome_evidence"] = outcome
        return result


class QueueConnection:
    def __init__(self) -> None:
        self.incoming: asyncio.Queue[object] = asyncio.Queue()
        self.peer: "QueueConnection | None" = None
        self.closed = False
        self.send_count = 0
        self.fail_send_after: int | None = None

    async def send(self, data: str) -> None:
        self.send_count += 1
        if self.fail_send_after is not None and self.send_count > self.fail_send_after:
            raise ConnectionError("simulated result loss")
        if self.peer is None or self.peer.closed:
            raise ConnectionError("peer closed")
        await self.peer.incoming.put(data)

    async def recv(self) -> str | bytes:
        item = await self.incoming.get()
        if item is _SENTINEL:
            raise ConnectionError("closed")
        assert isinstance(item, (str, bytes))
        return item

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.peer is not None and not self.peer.closed:
            await self.peer.incoming.put(_SENTINEL)


def pair() -> tuple[QueueConnection, QueueConnection]:
    left, right = QueueConnection(), QueueConnection()
    left.peer = right
    right.peer = left
    return left, right


def manifest_context(
    dispatcher: ExecutorRemoteDispatcher,
    *,
    epoch: str = "epoch-adapter-0001",
    device_id: str = "device-1",
) -> TransportDispatchContext:
    return TransportDispatchContext(
        device_id=device_id,
        session_epoch=epoch,
        session_capabilities_digest=digest_json(dispatcher.capability_manifest()),
    )


def envelope(
    request_id: str,
    tool: str,
    arguments: dict | None = None,
    *,
    session_id: str = "control-session-1",
    execution_context: dict | None = None,
    page: dict | None = None,
) -> dict:
    value = {
        "contract_version": NATIVE_CONTROL_PROTOCOL_V1,
        "session_id": session_id,
        "request_id": request_id,
        "tool": tool,
        "arguments": arguments or {},
    }
    if execution_context is not None:
        value["execution_context"] = execution_context
    if page is not None:
        value["page"] = page
    return value


async def relay_handshake(
    relay: QueueConnection,
    *,
    token: TokenMaterial,
    device_id: str,
) -> tuple[str, int, dict]:
    raw = await relay.recv()
    epoch = __import__("json").loads(raw)["session_epoch"]
    hello = decode_frame(
        raw,
        token=token,
        expected_device_id=device_id,
        expected_session_epoch=epoch,
    )
    await relay.send(
        encode_frame(
            device_id=device_id,
            session_epoch=epoch,
            sequence=1,
            frame_type="welcome",
            payload={
                "protocol_version": FRAME_VERSION,
                "hello_nonce": hello["payload"]["hello_nonce"],
                "accepted": True,
            },
            token=token,
        )
    )
    return epoch, 1, hello


def transport_request(
    *,
    epoch: str,
    sequence: int,
    token: TokenMaterial,
    request_id: str,
    body: dict,
    delivery_id: str,
    semantics: str,
) -> str:
    return encode_frame(
        device_id="device-1",
        session_epoch=epoch,
        sequence=sequence,
        frame_type="request",
        payload={
            "request_id": request_id,
            "request_version": NATIVE_CONTROL_PROTOCOL_V1,
            "delivery_id": delivery_id,
            "semantics": semantics,
            "body": body,
        },
        token=token,
    )


def make_real_executor(tmp_path: Path):
    shell = ReplayShellAdapter(
        [
            ShellResult(
                argv=["python", "-V"],
                returncode=0,
                stdout="Python replay",
                stderr="",
                stdout_bytes=13,
                stderr_bytes=0,
                stdout_truncated=False,
                stderr_truncated=False,
                output_limit_bytes=65536,
            )
        ],
        allow_executables={"python"},
    )
    audit = InMemoryAuditSink()
    observer = StaticContextObserver()
    executor = Executor(
        screenshot=ReplayScreenshotProvider([b"png"]),
        windows=ReplayWindowEnumerator([[]]),
        accessibility=ReplayUIAAdapter([]),
        input_adapter=ReplayInputAdapter(),
        shell=shell,
        audit=audit,
        outcome_journal=OutcomeJournal(tmp_path / "outcomes.jsonl"),
        context_observer=observer,
        dry_run=False,
        operation_timeout_seconds=1.0,
    )
    return executor, shell, audit, observer


def test_registry_digest_matches_pc_native_control_v1_reference() -> None:
    assert TOOL_REGISTRY_DIGEST == EXPECTED_HELP_PC_2_REGISTRY_DIGEST


@pytest.mark.asyncio
async def test_real_executor_shell_uses_preflight_context_journal_and_audit(tmp_path) -> None:
    executor, shell, audit, observer = make_real_executor(tmp_path)
    dispatcher = ExecutorRemoteDispatcher(executor)
    context = manifest_context(dispatcher)
    request_id = "real-shell-001"
    result = await dispatcher.dispatch(
        request_version=NATIVE_CONTROL_PROTOCOL_V1,
        request_id=request_id,
        body=envelope(
            request_id,
            "shell.run",
            {"argv": ["python", "-V"]},
        ),
        transport_context=context,
    )

    assert result.payload["status"] == "completed"
    assert result.payload["request_id"] == request_id
    assert shell.calls == [(["python", "-V"], None)]
    assert observer.cwd_calls >= 2
    lookup = executor.read_outcome_evidence(request_id=request_id, action="shell.run")
    assert lookup["outcome"] == "succeeded"
    assert [event.phase for event in audit.events] == ["start", "effect_dispatch", "finish"]


@pytest.mark.asyncio
async def test_protected_target_is_blocked_before_preflight_or_execute() -> None:
    executor = SpyExecutor({"fs.write_text": True})
    dispatcher = ExecutorRemoteDispatcher(executor)
    context = manifest_context(dispatcher)
    executor.preflight_calls = 0
    executor.execute_calls = 0

    result = await dispatcher.dispatch(
        request_version=NATIVE_CONTROL_PROTOCOL_V1,
        request_id="protected-1",
        body=envelope(
            "protected-1",
            "file.write",
            {"path": r"E:\manhwa\never-touch.txt", "text": "x"},
        ),
        transport_context=context,
    )

    assert result.payload["status"] == "error"
    assert result.payload["error"]["code"] == "PROTECTED_PATH_BLOCKED"
    assert executor.preflight_calls == 0
    assert executor.execute_calls == 0


@pytest.mark.asyncio
async def test_stale_execution_context_fails_closed() -> None:
    executor = SpyExecutor({"uia.invoke": True})
    dispatcher = ExecutorRemoteDispatcher(executor)
    context = manifest_context(dispatcher, epoch="epoch-current-1")
    stale = {
        "device_id": "device-1",
        "session_epoch": "epoch-stale-0001",
        "binding": {"contract_version": "pc_executor.execution_context_binding.v1"},
    }

    result = await dispatcher.dispatch(
        request_version=NATIVE_CONTROL_PROTOCOL_V1,
        request_id="ctx-1",
        body=envelope(
            "ctx-1",
            "uia.invoke",
            {"query": {"automation_id": "safe"}},
            execution_context=stale,
        ),
        transport_context=context,
    )

    assert result.payload["status"] == "error"
    assert result.payload["error"]["code"] == "STALE_EXECUTION_CONTEXT"
    assert executor.preflight_calls == 0
    assert executor.execute_calls == 0


@pytest.mark.asyncio
async def test_capability_drift_after_hello_is_rejected_before_preflight() -> None:
    executor = SpyExecutor({"screenshot.capture": False})
    dispatcher = ExecutorRemoteDispatcher(executor)
    context = manifest_context(dispatcher)
    executor.digest = "c" * 64

    result = await dispatcher.dispatch(
        request_version=NATIVE_CONTROL_PROTOCOL_V1,
        request_id="drift-1",
        body=envelope("drift-1", "screenshot.capture"),
        transport_context=context,
    )

    assert result.payload["status"] == "error"
    assert result.payload["error"]["code"] == "CAPABILITY_DRIFT"
    assert executor.preflight_calls == 0
    assert executor.execute_calls == 0


@pytest.mark.asyncio
async def test_process_handle_is_bound_to_transport_epoch_and_process_output_streams() -> None:
    executor = SpyExecutor({"process.start": True, "process.read": False})
    executor.results["process.start"] = {"process_handle": "proc-1"}
    executor.results["process.read"] = {"stdout": "hello", "stderr": ""}
    dispatcher = ExecutorRemoteDispatcher(executor)
    context1 = manifest_context(dispatcher, epoch="epoch-process-1")

    started = await dispatcher.dispatch(
        request_version=NATIVE_CONTROL_PROTOCOL_V1,
        request_id="proc-start-1",
        body=envelope("proc-start-1", "process.start", {"argv": ["fake"]}),
        transport_context=context1,
    )
    assert started.payload["status"] == "completed"

    read = await dispatcher.dispatch(
        request_version=NATIVE_CONTROL_PROTOCOL_V1,
        request_id="proc-read-1",
        body=envelope("proc-read-1", "process.read", {"process_handle": "proc-1"}),
        transport_context=context1,
    )
    assert read.payload["status"] == "completed"
    assert read.stream_kind == "process_output"
    assert b'"stdout":"hello"' in read.stream_data

    context2 = manifest_context(dispatcher, epoch="epoch-process-2")
    stale = await dispatcher.dispatch(
        request_version=NATIVE_CONTROL_PROTOCOL_V1,
        request_id="proc-read-2",
        body=envelope("proc-read-2", "process.read", {"process_handle": "proc-1"}),
        transport_context=context2,
    )
    assert stale.payload["status"] == "error"
    assert stale.payload["error"]["code"] == "STALE_PROCESS_HANDLE"
    assert executor.execute_calls == 2


@pytest.mark.asyncio
async def test_disconnect_result_loss_and_duplicate_request_never_reexecute(tmp_path) -> None:
    token = TokenMaterial(1, b"q" * 32)
    executor = SpyExecutor({"shell.run": True})
    executor.results["shell.run"] = {"returncode": 0}
    dispatcher = ExecutorRemoteDispatcher(executor)
    ledger = RequestLedger(tmp_path / "ledger")
    epochs = iter(["epoch-loss-0001", "epoch-loss-0002"])
    agent = DeviceAgent(
        device_id="device-1",
        token_ring=TokenRing(token.generation, token.secret),
        capabilities=dispatcher.capability_manifest,
        dispatcher=dispatcher,
        ledger=ledger,
        heartbeat_seconds=0,
        session_epoch_factory=lambda: next(epochs),
    )
    body = envelope("dup-side-1", "shell.run", {"argv": ["fake"]})

    device1, relay1 = pair()
    task1 = asyncio.create_task(agent.run_session(device1))
    epoch1, seq1, _ = await relay_handshake(relay1, token=token, device_id="device-1")
    device1.fail_send_after = 1
    await relay1.send(
        transport_request(
            epoch=epoch1,
            sequence=seq1 + 1,
            token=token,
            request_id="dup-side-1",
            body=body,
            delivery_id="delivery-1",
            semantics="side_effecting",
        )
    )
    with pytest.raises(ConnectionError):
        await task1
    assert executor.execute_calls == 1
    assert ledger.load("dup-side-1").status == "completed"

    device2, relay2 = pair()
    task2 = asyncio.create_task(agent.run_session(device2))
    epoch2, seq2, _ = await relay_handshake(relay2, token=token, device_id="device-1")
    await relay2.send(
        transport_request(
            epoch=epoch2,
            sequence=seq2 + 1,
            token=token,
            request_id="dup-side-1",
            body=body,
            delivery_id="delivery-2",
            semantics="side_effecting",
        )
    )
    response = decode_frame(
        await relay2.recv(),
        token=token,
        expected_device_id="device-1",
        expected_session_epoch=epoch2,
    )
    assert response["type"] == "response"
    assert response["payload"]["body"]["status"] == "completed"
    assert executor.execute_calls == 1

    task2.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task2


@pytest.mark.asyncio
async def test_unknown_executor_side_effect_surfaces_reconcile_and_never_reexecutes(tmp_path) -> None:
    token = TokenMaterial(1, b"r" * 32)
    executor = SpyExecutor({"shell.run": True})
    executor.unknown_actions.add("shell.run")
    dispatcher = ExecutorRemoteDispatcher(executor)
    agent = DeviceAgent(
        device_id="device-1",
        token_ring=TokenRing(token.generation, token.secret),
        capabilities=dispatcher.capability_manifest,
        dispatcher=dispatcher,
        ledger=RequestLedger(tmp_path / "ledger"),
        heartbeat_seconds=0,
        session_epoch_factory=lambda: "epoch-unknown-1",
    )
    body = envelope("unknown-side-1", "shell.run", {"argv": ["fake"]})
    device, relay = pair()
    task = asyncio.create_task(agent.run_session(device))
    epoch, seq, _ = await relay_handshake(relay, token=token, device_id="device-1")

    await relay.send(
        transport_request(
            epoch=epoch,
            sequence=seq + 1,
            token=token,
            request_id="unknown-side-1",
            body=body,
            delivery_id="delivery-1",
            semantics="side_effecting",
        )
    )
    first = decode_frame(
        await relay.recv(),
        token=token,
        expected_device_id="device-1",
        expected_session_epoch=epoch,
    )
    assert first["type"] == "reconcile_required"
    assert first["payload"]["status"] == "UNKNOWN_RECONCILE"
    assert first["payload"]["automatic_replay"] is False
    assert executor.execute_calls == 1

    await relay.send(
        transport_request(
            epoch=epoch,
            sequence=seq + 2,
            token=token,
            request_id="unknown-side-1",
            body=body,
            delivery_id="delivery-2",
            semantics="side_effecting",
        )
    )
    second = decode_frame(
        await relay.recv(),
        token=token,
        expected_device_id="device-1",
        expected_session_epoch=epoch,
    )
    assert second["type"] == "reconcile_required"
    assert executor.execute_calls == 1

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_stale_transport_epoch_is_rejected_before_adapter_dispatch(tmp_path) -> None:
    token = TokenMaterial(1, b"s" * 32)
    executor = SpyExecutor({"screenshot.capture": False})
    dispatcher = ExecutorRemoteDispatcher(executor)
    agent = DeviceAgent(
        device_id="device-1",
        token_ring=TokenRing(token.generation, token.secret),
        capabilities=dispatcher.capability_manifest,
        dispatcher=dispatcher,
        ledger=RequestLedger(tmp_path / "ledger"),
        heartbeat_seconds=0,
        session_epoch_factory=lambda: "epoch-current-01",
    )
    device, relay = pair()
    task = asyncio.create_task(agent.run_session(device))
    _, seq, _ = await relay_handshake(relay, token=token, device_id="device-1")

    await relay.send(
        transport_request(
            epoch="epoch-stale-0001",
            sequence=seq + 1,
            token=token,
            request_id="stale-frame-1",
            body=envelope("stale-frame-1", "screenshot.capture"),
            delivery_id="delivery-1",
            semantics="read_only",
        )
    )
    with pytest.raises(StaleEpochError):
        await task
    assert executor.execute_calls == 0


@pytest.mark.asyncio
async def test_file_read_stream_uses_transport_chunk_integrity(tmp_path) -> None:
    token = TokenMaterial(1, b"t" * 32)
    executor = SpyExecutor({"fs.read_text": False})
    expected = "abc123\n" * 20000
    executor.results["fs.read_text"] = {"text": expected}
    dispatcher = ExecutorRemoteDispatcher(executor)
    agent = DeviceAgent(
        device_id="device-1",
        token_ring=TokenRing(token.generation, token.secret),
        capabilities=dispatcher.capability_manifest,
        dispatcher=dispatcher,
        ledger=RequestLedger(tmp_path / "ledger"),
        heartbeat_seconds=0,
        max_chunk_bytes=16384,
        session_epoch_factory=lambda: "epoch-stream-adapter-1",
    )
    device, relay = pair()
    task = asyncio.create_task(agent.run_session(device))
    epoch, seq, _ = await relay_handshake(relay, token=token, device_id="device-1")
    await relay.send(
        transport_request(
            epoch=epoch,
            sequence=seq + 1,
            token=token,
            request_id="file-read-1",
            body=envelope("file-read-1", "file.read", {"path": r"C:\safe\file.txt"}),
            delivery_id="delivery-1",
            semantics="read_only",
        )
    )

    response = decode_frame(
        await relay.recv(),
        token=token,
        expected_device_id="device-1",
        expected_session_epoch=epoch,
    )
    assert response["type"] == "response"
    manifest = response["payload"]["stream"]
    assembler = StreamAssembler(manifest)
    for _ in range(manifest["chunk_count"]):
        chunk = decode_frame(
            await relay.recv(),
            token=token,
            expected_device_id="device-1",
            expected_session_epoch=epoch,
        )
        assert chunk["type"] == "stream_chunk"
        payload = dict(chunk["payload"])
        payload.pop("request_id")
        assembler.accept(payload)
    end = decode_frame(
        await relay.recv(),
        token=token,
        expected_device_id="device-1",
        expected_session_epoch=epoch,
    )
    end_payload = dict(end["payload"])
    end_payload.pop("request_id")
    assert assembler.finish(end_payload) == expected.encode("utf-8")

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
