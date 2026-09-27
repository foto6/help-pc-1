from __future__ import annotations

import asyncio
import base64
import json
from dataclasses import dataclass

import pytest

from pc_remote_transport.agent import DeviceAgent, DispatchResult
from pc_remote_transport.ledger import RequestLedger
from pc_remote_transport.protocol import (
    FRAME_VERSION,
    TokenMaterial,
    TokenRing,
    decode_frame,
    encode_frame,
)


_SENTINEL = object()


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
            raise ConnectionError("simulated disconnect after dispatch")
        if self.peer is None or self.peer.closed:
            raise ConnectionError("peer closed")
        await self.peer.incoming.put(data)

    async def recv(self) -> str | bytes:
        item = await self.incoming.get()
        if item is _SENTINEL:
            raise ConnectionError("connection closed")
        assert isinstance(item, (str, bytes))
        return item

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.peer is not None and not self.peer.closed:
            await self.peer.incoming.put(_SENTINEL)


def connection_pair() -> tuple[QueueConnection, QueueConnection]:
    a = QueueConnection()
    b = QueueConnection()
    a.peer = b
    b.peer = a
    return a, b


@dataclass
class CountingDispatcher:
    calls: int = 0
    stream: bytes | None = None

    async def dispatch(self, *, request_version: str, request_id: str, body: dict):
        self.calls += 1
        return DispatchResult(
            payload={"echo": body, "call": self.calls},
            stream_data=self.stream,
            stream_kind="process_output" if self.stream is not None else None,
        )


async def relay_handshake(
    relay: QueueConnection,
    *,
    device_id: str,
    token: TokenMaterial,
) -> tuple[str, int, dict]:
    raw = await relay.recv()
    parsed = json.loads(raw)
    epoch = parsed["session_epoch"]
    hello = decode_frame(
        raw,
        token=token,
        expected_device_id=device_id,
        expected_session_epoch=epoch,
    )
    assert hello["type"] == "hello"
    assert hello["payload"]["protocol_version"] == FRAME_VERSION
    assert hello["payload"]["capabilities_digest"]
    welcome = encode_frame(
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
    await relay.send(welcome)
    return epoch, 1, hello


def make_request(*, epoch: str, sequence: int, token: TokenMaterial, request_id: str = "req-1", delivery_id: str = "delivery-1", semantics: str = "side_effecting", body: dict | None = None) -> str:
    return encode_frame(
        device_id="device-1",
        session_epoch=epoch,
        sequence=sequence,
        frame_type="request",
        payload={
            "request_id": request_id,
            "request_version": "control.request.v1",
            "delivery_id": delivery_id,
            "semantics": semantics,
            "body": body or {"operation": "safe.test"},
        },
        token=token,
    )


@pytest.mark.asyncio
async def test_local_e2e_duplicate_delivery_is_harmless(tmp_path) -> None:
    token = TokenMaterial(1, b"a" * 32)
    dispatcher = CountingDispatcher()
    agent = DeviceAgent(
        device_id="device-1",
        token_ring=TokenRing(token.generation, token.secret),
        capabilities=lambda: {"registry_version": "capabilities.v1", "tools": ["safe.test"]},
        dispatcher=dispatcher,
        ledger=RequestLedger(tmp_path / "ledger"),
        heartbeat_seconds=0,
        session_epoch_factory=lambda: "epoch-e2e-0001",
    )
    device, relay = connection_pair()
    task = asyncio.create_task(agent.run_session(device))
    epoch, relay_seq, _ = await relay_handshake(relay, device_id="device-1", token=token)

    relay_seq += 1
    await relay.send(make_request(epoch=epoch, sequence=relay_seq, token=token))
    response_raw = await relay.recv()
    response = decode_frame(
        response_raw,
        token=token,
        expected_device_id="device-1",
        expected_session_epoch=epoch,
    )
    assert response["type"] == "response"
    assert response["payload"]["body"]["call"] == 1

    relay_seq += 1
    await relay.send(make_request(
        epoch=epoch,
        sequence=relay_seq,
        token=token,
        delivery_id="delivery-2",
    ))
    response2 = decode_frame(
        await relay.recv(),
        token=token,
        expected_device_id="device-1",
        expected_session_epoch=epoch,
    )
    assert response2["type"] == "response"
    assert response2["payload"]["body"]["call"] == 1
    assert dispatcher.calls == 1

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_disconnect_after_dispatch_resends_cached_result_without_reexecution(tmp_path) -> None:
    token = TokenMaterial(1, b"b" * 32)
    dispatcher = CountingDispatcher()
    ledger = RequestLedger(tmp_path / "ledger")
    epochs = iter(["epoch-disc-0001", "epoch-disc-0002"])
    agent = DeviceAgent(
        device_id="device-1",
        token_ring=TokenRing(token.generation, token.secret),
        capabilities=lambda: {"tools": ["safe.test"]},
        dispatcher=dispatcher,
        ledger=ledger,
        heartbeat_seconds=0,
        session_epoch_factory=lambda: next(epochs),
    )

    device1, relay1 = connection_pair()
    task1 = asyncio.create_task(agent.run_session(device1))
    epoch1, seq1, _ = await relay_handshake(relay1, device_id="device-1", token=token)
    device1.fail_send_after = 1
    await relay1.send(make_request(epoch=epoch1, sequence=seq1 + 1, token=token))
    with pytest.raises(ConnectionError):
        await task1
    assert dispatcher.calls == 1
    assert ledger.load("req-1").status == "completed"

    device2, relay2 = connection_pair()
    task2 = asyncio.create_task(agent.run_session(device2))
    epoch2, seq2, _ = await relay_handshake(relay2, device_id="device-1", token=token)
    await relay2.send(make_request(epoch=epoch2, sequence=seq2 + 1, token=token, delivery_id="delivery-retry"))
    response = decode_frame(
        await relay2.recv(),
        token=token,
        expected_device_id="device-1",
        expected_session_epoch=epoch2,
    )
    assert response["type"] == "response"
    assert response["payload"]["body"]["call"] == 1
    assert dispatcher.calls == 1
    task2.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task2


@pytest.mark.asyncio
async def test_unknown_prior_side_effect_requires_reconciliation_never_replays(tmp_path) -> None:
    token = TokenMaterial(1, b"c" * 32)
    ledger = RequestLedger(tmp_path / "ledger")
    dispatcher = CountingDispatcher()
    request_payload = {
        "request_id": "req-unknown",
        "request_version": "control.request.v1",
        "delivery_id": "d-original",
        "semantics": "side_effecting",
        "body": {"operation": "safe.test"},
    }
    from pc_remote_transport.protocol import request_fingerprint
    ledger.mark_dispatch_started(
        request_id="req-unknown",
        request_version="control.request.v1",
        fingerprint=request_fingerprint(request_payload),
        semantics="side_effecting",
    )

    agent = DeviceAgent(
        device_id="device-1",
        token_ring=TokenRing(token.generation, token.secret),
        capabilities=lambda: {},
        dispatcher=dispatcher,
        ledger=ledger,
        heartbeat_seconds=0,
        session_epoch_factory=lambda: "epoch-unknown1",
    )
    device, relay = connection_pair()
    task = asyncio.create_task(agent.run_session(device))
    epoch, seq, _ = await relay_handshake(relay, device_id="device-1", token=token)
    await relay.send(make_request(
        epoch=epoch,
        sequence=seq + 1,
        token=token,
        request_id="req-unknown",
        delivery_id="d-redelivery",
    ))
    raw = await relay.recv()
    frame = decode_frame(raw, token=token, expected_device_id="device-1", expected_session_epoch=epoch)
    assert frame["type"] == "reconcile_required"
    assert frame["payload"]["status"] == "UNKNOWN_RECONCILE"
    assert frame["payload"]["automatic_replay"] is False
    assert dispatcher.calls == 0

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_chunked_stream_has_integrity_metadata(tmp_path) -> None:
    token = TokenMaterial(1, b"d" * 32)
    data = (b"0123456789" * 9000)
    dispatcher = CountingDispatcher(stream=data)
    agent = DeviceAgent(
        device_id="device-1",
        token_ring=TokenRing(token.generation, token.secret),
        capabilities=lambda: {},
        dispatcher=dispatcher,
        ledger=RequestLedger(tmp_path / "ledger"),
        heartbeat_seconds=0,
        max_chunk_bytes=16384,
        session_epoch_factory=lambda: "epoch-stream01",
    )
    device, relay = connection_pair()
    task = asyncio.create_task(agent.run_session(device))
    epoch, seq, _ = await relay_handshake(relay, device_id="device-1", token=token)
    await relay.send(make_request(epoch=epoch, sequence=seq + 1, token=token, semantics="read_only"))
    response = decode_frame(await relay.recv(), token=token, expected_device_id="device-1", expected_session_epoch=epoch)
    assert response["type"] == "response"
    manifest = response["payload"]["stream"]
    assert manifest["total_bytes"] == len(data)
    assert manifest["chunk_count"] > 1

    from pc_remote_transport.protocol import StreamAssembler
    assembler = StreamAssembler(manifest)
    outbound_seq = response["sequence"]
    for _ in range(manifest["chunk_count"]):
        chunk = decode_frame(await relay.recv(), token=token, expected_device_id="device-1", expected_session_epoch=epoch)
        assert chunk["sequence"] > outbound_seq
        outbound_seq = chunk["sequence"]
        assert chunk["type"] == "stream_chunk"
        payload = dict(chunk["payload"])
        payload.pop("request_id")
        assembler.accept(payload)
    end = decode_frame(await relay.recv(), token=token, expected_device_id="device-1", expected_session_epoch=epoch)
    end_payload = dict(end["payload"])
    end_payload.pop("request_id")
    assert assembler.finish(end_payload) == data

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_token_rotation_switches_generation_and_rejects_old_token(tmp_path) -> None:
    old = TokenMaterial(1, b"e" * 32)
    new_secret = b"f" * 32
    ring = TokenRing(old.generation, old.secret)
    agent = DeviceAgent(
        device_id="device-1",
        token_ring=ring,
        capabilities=lambda: {},
        dispatcher=CountingDispatcher(),
        ledger=RequestLedger(tmp_path / "ledger"),
        heartbeat_seconds=0,
        session_epoch_factory=lambda: "epoch-rotate01",
    )
    device, relay = connection_pair()
    task = asyncio.create_task(agent.run_session(device))
    epoch, seq, _ = await relay_handshake(relay, device_id="device-1", token=old)

    rotation = encode_frame(
        device_id="device-1",
        session_epoch=epoch,
        sequence=seq + 1,
        frame_type="token.rotate",
        payload={
            "new_generation": 2,
            "new_token_b64": base64.b64encode(new_secret).decode("ascii"),
        },
        token=old,
    )
    await relay.send(rotation)
    ack_raw = await relay.recv()
    ack = decode_frame(
        ack_raw,
        token=TokenMaterial(2, new_secret),
        expected_device_id="device-1",
        expected_session_epoch=epoch,
    )
    assert ack["type"] == "token.rotated"
    assert ring.current.generation == 2

    old_heartbeat = encode_frame(
        device_id="device-1",
        session_epoch=epoch,
        sequence=seq + 2,
        frame_type="heartbeat",
        payload={},
        token=old,
    )
    await relay.send(old_heartbeat)
    with pytest.raises(Exception):
        await task


def test_backoff_is_bounded_and_deterministic() -> None:
    from pc_remote_transport.agent import BackoffPolicy
    p = BackoffPolicy(initial_seconds=0.5, maximum_seconds=3.0, multiplier=2.0)
    assert [p.delay(i) for i in range(1, 6)] == [0.5, 1.0, 2.0, 3.0, 3.0]


def test_ledger_keys_do_not_collide_after_filename_normalization(tmp_path) -> None:
    from pc_remote_transport.protocol import request_fingerprint
    ledger = RequestLedger(tmp_path / "ledger")
    p1 = {
        "request_id": "a:b",
        "request_version": "control.request.v1",
        "delivery_id": "d1",
        "semantics": "read_only",
        "body": {"n": 1},
    }
    p2 = {
        "request_id": "a_b",
        "request_version": "control.request.v1",
        "delivery_id": "d2",
        "semantics": "read_only",
        "body": {"n": 2},
    }
    ledger.mark_dispatch_started(
        request_id=p1["request_id"],
        request_version=p1["request_version"],
        fingerprint=request_fingerprint(p1),
        semantics=p1["semantics"],
    )
    ledger.mark_dispatch_started(
        request_id=p2["request_id"],
        request_version=p2["request_version"],
        fingerprint=request_fingerprint(p2),
        semantics=p2["semantics"],
    )
    assert ledger.load("a:b").request_id == "a:b"
    assert ledger.load("a_b").request_id == "a_b"
