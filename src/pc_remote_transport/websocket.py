from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from .agent import PersistentConnection
from .protocol import DEFAULT_MAX_FRAME_BYTES, ProtocolError


class _WebSocketConnection:
    def __init__(self, websocket) -> None:
        self.websocket = websocket

    async def send(self, data: str) -> None:
        await self.websocket.send(data)

    async def recv(self) -> str | bytes:
        value = await self.websocket.recv()
        if not isinstance(value, (str, bytes)):
            raise ProtocolError("websocket returned unsupported message type")
        return value

    async def close(self) -> None:
        await self.websocket.close()


@dataclass(frozen=True)
class WebSocketRelayConnector:
    endpoint: str
    max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES
    allow_insecure_loopback: bool = False

    def _validate_endpoint(self) -> None:
        parsed = urlparse(self.endpoint)
        if parsed.scheme == "wss":
            return
        if parsed.scheme == "ws" and self.allow_insecure_loopback and parsed.hostname in {"127.0.0.1", "localhost", "::1"}:
            return
        raise ProtocolError("remote relay must use wss; ws is allowed only for explicit loopback tests")

    async def open(self) -> PersistentConnection:
        self._validate_endpoint()
        try:
            from websockets.asyncio.client import connect
        except ImportError as exc:
            raise RuntimeError("websockets package is required for WebSocketRelayConnector") from exc
        websocket = await connect(
            self.endpoint,
            max_size=self.max_frame_bytes,
            ping_interval=None,
            compression=None,
        )
        return _WebSocketConnection(websocket)
