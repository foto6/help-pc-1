from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from pathlib import Path

import pytest

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
from pc_remote_transport import (
    DeviceAgent,
    ExecutorRemoteDispatcher,
    RequestLedger,
    StreamAssembler,
    TokenMaterial,
    TokenRing,
)
from pc_remote_transport.protocol import (
    FRAME_VERSION,
    decode_frame,
    encode_frame,
)


_SENTINEL = object()


class StaticContextObserver:
    def foreground(self):
        return None

    def display_at(self, x: int, y: int):
        return None

    def cwd_identity(self, cwd: str | None) -> CwdIdentity:
        return CwdIdentity("1" * 64, 7, 11)


class QueueConnection:
    def __init__(self) -> None:
        self.incoming: asyncio.Queue[object] = asyncio.Queue()
        self.peer: "QueueConnection | None" = None
        self.closed = False

    async def send(self, data: str) -> None:
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


def make_executor(tmp_path: Path) -> Executor:
    executable = Path(sys.executable).name.lower()
    shell = ReplayShellAdapter([], allow_executables={executable})
    return Executor(
        screenshot=ReplayScreenshotProvider([b"png"]),
        windows=ReplayWindowEnumerator([[]]),
        accessibility=ReplayUIAAdapter([]),
        input_adapter=ReplayInputAdapter(),
        shell=shell,
        outcome_journal=OutcomeJournal(tmp_path / "outcomes.jsonl"),
        context_observer=StaticContextObserver(),
        operations_state_root=tmp_path / "ops-state",
        dry_run=False,
        operation_timeout_seconds=3.0,
    )


class TransportHarness:
    def __init__(self, executor: Executor, tmp_path: Path) -> None:
        self.token = TokenMaterial(1, b"z" * 32)
        self.dispatcher = ExecutorRemoteDispatcher(executor)
        self.agent = DeviceAgent(
            device_id="device-1",
            token_ring=TokenRing(self.token.generation, self.token.secret),
            capabilities=self.dispatcher.capability_manifest,
            dispatcher=self.dispatcher,
            ledger=RequestLedger(tmp_path / "transport-ledger"),
            heartbeat_seconds=0,
            session_epoch_factory=lambda: "epoch-full-stack-0001",
        )
        self.device: QueueConnection | None = None
        self.relay: QueueConnection | None = None
        self.task: asyncio.Task | None = None
        self.epoch = ""
        self.sequence = 1

    async def start(self) -> None:
        self.device, self.relay = pair()
        self.task = asyncio.create_task(self.agent.run_session(self.device))
        raw = await self.relay.recv()
        self.epoch = json.loads(raw)["session_epoch"]
        hello = decode_frame(
            raw,
            token=self.token,
            expected_device_id="device-1",
            expected_session_epoch=self.epoch,
        )
        await self.relay.send(
            encode_frame(
                device_id="device-1",
                session_epoch=self.epoch,
                sequence=1,
                frame_type="welcome",
                payload={
                    "protocol_version": FRAME_VERSION,
                    "hello_nonce": hello["payload"]["hello_nonce"],
                    "accepted": True,
                },
                token=self.token,
            )
        )

    async def request(
        self,
        request_id: str,
        tool: str,
        arguments: dict | None = None,
        *,
        side_effecting: bool = False,
    ) -> tuple[dict, bytes | None]:
        assert self.relay is not None
        self.sequence += 1
        body = {
            "contract_version": "pc.native.control.v1",
            "session_id": "control-session-full-stack",
            "request_id": request_id,
            "tool": tool,
            "arguments": arguments or {},
        }
        await self.relay.send(
            encode_frame(
                device_id="device-1",
                session_epoch=self.epoch,
                sequence=self.sequence,
                frame_type="request",
                payload={
                    "request_id": request_id,
                    "request_version": "pc.native.control.v1",
                    "delivery_id": f"delivery-{self.sequence}",
                    "semantics": "side_effecting" if side_effecting else "read_only",
                    "body": body,
                },
                token=self.token,
            )
        )
        response = decode_frame(
            await self.relay.recv(),
            token=self.token,
            expected_device_id="device-1",
            expected_session_epoch=self.epoch,
        )
        if response["type"] == "reconcile_required":
            return response["payload"], None
        assert response["type"] == "response"
        payload = response["payload"]
        stream_manifest = payload.get("stream")
        if stream_manifest is None:
            return payload["body"], None
        assembler = StreamAssembler(stream_manifest)
        for _ in range(stream_manifest["chunk_count"]):
            chunk = decode_frame(
                await self.relay.recv(),
                token=self.token,
                expected_device_id="device-1",
                expected_session_epoch=self.epoch,
            )
            chunk_payload = dict(chunk["payload"])
            chunk_payload.pop("request_id")
            assembler.accept(chunk_payload)
        end = decode_frame(
            await self.relay.recv(),
            token=self.token,
            expected_device_id="device-1",
            expected_session_epoch=self.epoch,
        )
        end_payload = dict(end["payload"])
        end_payload.pop("request_id")
        return payload["body"], assembler.finish(end_payload)

    async def close(self) -> None:
        if self.task is not None:
            self.task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await self.task


def test_real_executor_manifest_advertises_parity_operations(tmp_path: Path) -> None:
    executor = make_executor(tmp_path)
    dispatcher = ExecutorRemoteDispatcher(executor)
    manifest = dispatcher.capability_manifest()
    advertised = set(manifest["executor"]["actions"])
    required = {
        "fs.read_text",
        "fs.edit_text",
        "fs.write_text",
        "process.start",
        "process.read_output",
        "process.managed.list",
        "process.terminate",
        "process.list",
        "system.process.kill",
    }
    assert required <= advertised
    assert manifest["executor"]["operations_digest"] == (
        executor.operations.capabilities_snapshot()["attestation"]["digest"]
    )


@pytest.mark.asyncio
async def test_real_file_ops_traverse_transport_adapter_executor(tmp_path: Path) -> None:
    executor = make_executor(tmp_path)
    harness = TransportHarness(executor, tmp_path)
    await harness.start()
    target = tmp_path / "round-trip.txt"
    try:
        written, _ = await harness.request(
            "file-write-real-1",
            "file.write",
            {"path": str(target), "text": "alpha\nbeta\n"},
            side_effecting=True,
        )
        assert written["status"] == "completed"
        assert target.read_text(encoding="utf-8") == "alpha\nbeta\n"

        current_hash = hashlib.sha256(target.read_bytes()).hexdigest()
        edited, _ = await harness.request(
            "file-edit-real-1",
            "file.edit",
            {
                "path": str(target),
                "old_text": "beta",
                "new_text": "gamma",
                "expected_replacements": 1,
                "expected_current_hash": current_hash,
            },
            side_effecting=True,
        )
        assert edited["status"] == "completed"

        read, stream = await harness.request(
            "file-read-real-1",
            "file.read",
            {"path": str(target)},
        )
        assert read["status"] == "completed"
        assert read["data"]["text"] == "alpha\ngamma\n"
        assert stream == b"alpha\ngamma\n"
    finally:
        await harness.close()


@pytest.mark.asyncio
async def test_real_process_lifecycle_traverses_transport_adapter_executor(tmp_path: Path) -> None:
    executor = make_executor(tmp_path)
    harness = TransportHarness(executor, tmp_path)
    await harness.start()
    handle = None
    terminated = False
    try:
        started, _ = await harness.request(
            "process-start-real-1",
            "process.start",
            {
                "argv": [
                    sys.executable,
                    "-c",
                    "import time; print('ready', flush=True); time.sleep(10)",
                ],
                "output_limit_bytes": 65536,
            },
            side_effecting=True,
        )
        assert started["status"] == "completed"
        handle = started["data"]["handle_id"]

        read, _ = await harness.request(
            "process-read-real-1",
            "process.read",
            {"process_handle": handle, "wait_ms": 2000, "max_bytes": 4096},
        )
        assert read["status"] == "completed"
        assert "ready" in read["data"]["stdout"]

        listed, _ = await harness.request(
            "process-list-real-1",
            "process.list",
            {},
        )
        assert listed["status"] == "completed"
        assert any(item["handle_id"] == handle for item in listed["data"]["handles"])

        stopped, _ = await harness.request(
            "process-stop-real-1",
            "process.terminate",
            {"process_handle": handle, "grace_ms": 500},
            side_effecting=True,
        )
        assert stopped["status"] == "completed"
        terminated = True
    finally:
        if handle is not None and not terminated:
            try:
                await harness.request(
                    "process-cleanup-real-1",
                    "process.terminate",
                    {"process_handle": handle, "grace_ms": 100},
                    side_effecting=True,
                )
            except Exception:
                pass
        await harness.close()


@pytest.mark.asyncio
async def test_operations_digest_drift_fails_closed_after_hello(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor = make_executor(tmp_path)
    target = tmp_path / "drift.txt"
    target.write_text("safe", encoding="utf-8")
    harness = TransportHarness(executor, tmp_path)
    await harness.start()
    original = executor.operations.capabilities_snapshot

    def drifted_capabilities() -> dict:
        value = original()
        value["attestation"] = dict(value["attestation"])
        value["attestation"]["digest"] = "f" * 64
        return value

    monkeypatch.setattr(executor.operations, "capabilities_snapshot", drifted_capabilities)
    try:
        result, _ = await harness.request(
            "ops-drift-real-1",
            "file.read",
            {"path": str(target)},
        )
        assert result["status"] == "error"
        assert result["error"]["code"] == "CAPABILITY_DRIFT"
    finally:
        await harness.close()

@pytest.mark.asyncio
async def test_real_system_reads_traverse_transport_adapter_executor(tmp_path: Path) -> None:
    executor = make_executor(tmp_path)
    harness = TransportHarness(executor, tmp_path)
    await harness.start()
    try:
        health, _ = await harness.request(
            "health-real-1",
            "device.health",
            {},
        )
        assert health["status"] == "completed"

        processes, _ = await harness.request(
            "system-process-list-real-1",
            "system.process.list",
            {"max_results": 20},
        )
        assert processes["status"] == "completed"
        assert "processes" in processes["data"]
    finally:
        await harness.close()
