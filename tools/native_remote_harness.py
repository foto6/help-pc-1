from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

from pc_remote_transport import DeviceAgent, DispatchResult, RequestLedger, TokenMaterial, TokenRing
from pc_remote_transport.protocol import FRAME_VERSION, decode_frame, encode_frame


_SENTINEL = object()


class Endpoint:
    def __init__(self) -> None:
        self.incoming: asyncio.Queue[object] = asyncio.Queue()
        self.peer: "Endpoint | None" = None
        self.closed = False

    async def send(self, data: str) -> None:
        if self.peer is None or self.peer.closed:
            raise ConnectionError("peer closed")
        await self.peer.incoming.put(data)

    async def recv(self) -> str:
        item = await self.incoming.get()
        if item is _SENTINEL:
            raise ConnectionError("closed")
        assert isinstance(item, str)
        return item

    async def close(self) -> None:
        if not self.closed:
            self.closed = True
            if self.peer is not None:
                await self.peer.incoming.put(_SENTINEL)


def pair() -> tuple[Endpoint, Endpoint]:
    a, b = Endpoint(), Endpoint()
    a.peer, b.peer = b, a
    return a, b


class EchoDispatcher:
    def __init__(self) -> None:
        self.calls = 0

    async def dispatch(self, *, request_version: str, request_id: str, body: dict):
        self.calls += 1
        return DispatchResult(
            payload={"request_id": request_id, "echo": body, "calls": self.calls},
            stream_data=b"deterministic process output\n",
            stream_kind="process_output",
        )


async def main_async() -> None:
    token = TokenMaterial(1, b"h" * 32)
    dispatcher = EchoDispatcher()
    with tempfile.TemporaryDirectory(prefix="pc-native-remote-harness-") as tmp:
        agent = DeviceAgent(
            device_id="harness-device",
            token_ring=TokenRing(token.generation, token.secret),
            capabilities=lambda: {"version": "harness.capabilities.v1"},
            dispatcher=dispatcher,
            ledger=RequestLedger(Path(tmp) / "ledger"),
            heartbeat_seconds=0,
            session_epoch_factory=lambda: "harness-epoch-0001",
        )
        device, relay = pair()
        task = asyncio.create_task(agent.run_session(device))

        hello_raw = await relay.recv()
        hello_json = json.loads(hello_raw)
        epoch = hello_json["session_epoch"]
        hello = decode_frame(
            hello_raw,
            token=token,
            expected_device_id="harness-device",
            expected_session_epoch=epoch,
        )
        await relay.send(encode_frame(
            device_id="harness-device",
            session_epoch=epoch,
            sequence=1,
            frame_type="welcome",
            payload={
                "protocol_version": FRAME_VERSION,
                "hello_nonce": hello["payload"]["hello_nonce"],
                "accepted": True,
            },
            token=token,
        ))
        request = {
            "request_id": "harness-request-1",
            "request_version": "harness.request.v1",
            "delivery_id": "delivery-1",
            "semantics": "side_effecting",
            "body": {"operation": "fake.echo"},
        }
        await relay.send(encode_frame(
            device_id="harness-device",
            session_epoch=epoch,
            sequence=2,
            frame_type="request",
            payload=request,
            token=token,
        ))
        response = decode_frame(
            await relay.recv(),
            token=token,
            expected_device_id="harness-device",
            expected_session_epoch=epoch,
        )
        assert response["type"] == "response"
        assert response["payload"]["body"]["calls"] == 1
        chunk_count = response["payload"]["stream"]["chunk_count"]
        for _ in range(chunk_count):
            assert decode_frame(
                await relay.recv(),
                token=token,
                expected_device_id="harness-device",
                expected_session_epoch=epoch,
            )["type"] == "stream_chunk"
        assert decode_frame(
            await relay.recv(),
            token=token,
            expected_device_id="harness-device",
            expected_session_epoch=epoch,
        )["type"] == "stream_end"

        await relay.send(encode_frame(
            device_id="harness-device",
            session_epoch=epoch,
            sequence=3,
            frame_type="request",
            payload={**request, "delivery_id": "delivery-2"},
            token=token,
        ))
        duplicate = decode_frame(
            await relay.recv(),
            token=token,
            expected_device_id="harness-device",
            expected_session_epoch=epoch,
        )
        assert duplicate["type"] == "response"
        assert duplicate["payload"]["body"]["calls"] == 1
        assert dispatcher.calls == 1

        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    print("native remote transport harness: PASS")


def main() -> int:
    asyncio.run(main_async())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
