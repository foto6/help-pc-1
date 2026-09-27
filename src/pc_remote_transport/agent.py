from __future__ import annotations

import asyncio
import inspect
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Protocol

from .ledger import LedgerRecord, RequestLedger
from .protocol import (
    DEFAULT_MAX_CHUNK_BYTES,
    DEFAULT_MAX_FRAME_BYTES,
    DEFAULT_MAX_REQUEST_BYTES,
    DEFAULT_MAX_STREAM_BYTES,
    FRAME_VERSION,
    InboundReplayGuard,
    ProtocolError,
    TokenRing,
    build_stream_manifest,
    decode_frame,
    decode_rotation_secret,
    digest_json,
    encode_frame,
    iter_stream_chunks,
    request_fingerprint,
    validate_request_payload,
)


class PersistentConnection(Protocol):
    async def send(self, data: str) -> None: ...
    async def recv(self) -> str | bytes: ...
    async def close(self) -> None: ...


class RelayConnector(Protocol):
    async def open(self) -> PersistentConnection: ...


class Dispatcher(Protocol):
    async def dispatch(
        self,
        *,
        request_version: str,
        request_id: str,
        body: dict[str, Any],
        transport_context: "TransportDispatchContext | None" = None,
    ) -> "DispatchResult": ...


@dataclass(frozen=True)
class TransportDispatchContext:
    device_id: str
    session_epoch: str
    session_capabilities_digest: str


class UnknownDispatchOutcome(RuntimeError):
    """Dispatcher cannot prove whether a side effect occurred."""


@dataclass(frozen=True)
class DispatchResult:
    payload: dict[str, Any]
    stream_data: bytes | None = None
    stream_kind: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.payload, dict):
            raise TypeError("payload must be an object")
        if self.stream_data is not None and not isinstance(self.stream_data, bytes):
            raise TypeError("stream_data must be bytes or None")
        if self.stream_data is not None:
            if not isinstance(self.stream_kind, str) or not self.stream_kind:
                raise TypeError("stream_kind is required when stream_data is present")
        elif self.stream_kind is not None:
            raise TypeError("stream_kind requires stream_data")


@dataclass(frozen=True)
class BackoffPolicy:
    initial_seconds: float = 0.25
    maximum_seconds: float = 10.0
    multiplier: float = 2.0

    def delay(self, failure_count: int) -> float:
        if failure_count <= 0:
            return 0.0
        return min(self.maximum_seconds, self.initial_seconds * (self.multiplier ** (failure_count - 1)))


class DeviceAgent:
    """Authenticated outbound device transport.

    The transport treats request bodies and capabilities as opaque objects.
    Application-specific action schemas live behind Dispatcher.
    """

    def __init__(
        self,
        *,
        device_id: str,
        token_ring: TokenRing,
        capabilities: Callable[[], dict[str, Any]],
        dispatcher: Dispatcher,
        ledger: RequestLedger,
        heartbeat_seconds: float = 15.0,
        max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
        max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
        max_chunk_bytes: int = DEFAULT_MAX_CHUNK_BYTES,
        max_stream_bytes: int = DEFAULT_MAX_STREAM_BYTES,
        session_epoch_factory: Callable[[], str] | None = None,
    ) -> None:
        self.device_id = device_id
        self.token_ring = token_ring
        self.capabilities = capabilities
        self.dispatcher = dispatcher
        self.ledger = ledger
        self.heartbeat_seconds = heartbeat_seconds
        self.max_frame_bytes = max_frame_bytes
        self.max_request_bytes = max_request_bytes
        self.max_chunk_bytes = max_chunk_bytes
        self.max_stream_bytes = max_stream_bytes
        self.session_epoch_factory = session_epoch_factory or (lambda: uuid.uuid4().hex)

    async def run_session(self, connection: PersistentConnection) -> None:
        epoch = self.session_epoch_factory()
        if len(epoch) < 8:
            raise ProtocolError("session epoch factory returned invalid epoch")
        outbound_sequence = 0
        inbound_guard = InboundReplayGuard()

        async def send(frame_type: str, payload: dict[str, Any]) -> None:
            nonlocal outbound_sequence
            outbound_sequence += 1
            raw = encode_frame(
                device_id=self.device_id,
                session_epoch=epoch,
                sequence=outbound_sequence,
                frame_type=frame_type,
                payload=payload,
                token=self.token_ring.current,
                max_frame_bytes=self.max_frame_bytes,
            )
            await connection.send(raw)

        caps = self.capabilities()
        if not isinstance(caps, dict):
            raise ProtocolError("capabilities provider must return an object")
        session_capabilities_digest = digest_json(caps)
        hello_nonce = uuid.uuid4().hex
        await send("hello", {
            "protocol_version": FRAME_VERSION,
            "hello_nonce": hello_nonce,
            "capabilities": caps,
            "capabilities_digest": session_capabilities_digest,
            "limits": {
                "max_frame_bytes": self.max_frame_bytes,
                "max_request_bytes": self.max_request_bytes,
                "max_chunk_bytes": self.max_chunk_bytes,
                "max_stream_bytes": self.max_stream_bytes,
            },
        })

        first = await connection.recv()
        welcome = decode_frame(
            first,
            token=self.token_ring.current,
            expected_device_id=self.device_id,
            expected_session_epoch=epoch,
            max_frame_bytes=self.max_frame_bytes,
        )
        inbound_guard.accept(welcome["sequence"])
        if welcome["type"] != "welcome":
            raise ProtocolError("first relay frame must be welcome")
        if welcome["payload"] != {
            "protocol_version": FRAME_VERSION,
            "hello_nonce": hello_nonce,
            "accepted": True,
        }:
            raise ProtocolError("invalid welcome payload")

        while True:
            try:
                if self.heartbeat_seconds > 0:
                    raw = await asyncio.wait_for(connection.recv(), timeout=self.heartbeat_seconds)
                else:
                    raw = await connection.recv()
            except asyncio.TimeoutError:
                await send("heartbeat", {"last_inbound_sequence": inbound_guard.last_sequence})
                continue

            frame = decode_frame(
                raw,
                token=self.token_ring.current,
                expected_device_id=self.device_id,
                expected_session_epoch=epoch,
                max_frame_bytes=self.max_frame_bytes,
            )
            inbound_guard.accept(frame["sequence"])
            frame_type = frame["type"]
            payload = frame["payload"]

            if frame_type == "heartbeat":
                await send("heartbeat_ack", {"relay_sequence": frame["sequence"]})
                continue
            if frame_type == "heartbeat_ack":
                continue
            if frame_type == "token.rotate":
                await self._handle_token_rotation(payload, send)
                continue
            if frame_type == "request":
                await self._handle_request(
                    payload,
                    send,
                    transport_context=TransportDispatchContext(
                        device_id=self.device_id,
                        session_epoch=epoch,
                        session_capabilities_digest=session_capabilities_digest,
                    ),
                )
                continue
            if frame_type == "error":
                raise ProtocolError(f"relay error: {payload!r}")
            raise ProtocolError(f"unexpected relay frame type: {frame_type}")

    async def _handle_token_rotation(
        self,
        payload: dict[str, Any],
        send: Callable[[str, dict[str, Any]], Awaitable[None]],
    ) -> None:
        if set(payload) != {"new_generation", "new_token_b64"}:
            raise ProtocolError("invalid token rotation payload")
        generation = payload["new_generation"]
        if isinstance(generation, bool) or not isinstance(generation, int):
            raise ProtocolError("invalid token generation")
        secret = decode_rotation_secret(payload["new_token_b64"])
        self.token_ring.rotate(generation=generation, secret=secret)
        await send("token.rotated", {"generation": generation})

    async def _handle_request(
        self,
        raw_payload: dict[str, Any],
        send: Callable[[str, dict[str, Any]], Awaitable[None]],
        *,
        transport_context: TransportDispatchContext | None = None,
    ) -> None:
        request = validate_request_payload(raw_payload, max_request_bytes=self.max_request_bytes)
        request_id = request["request_id"]
        fingerprint = request_fingerprint(request)
        existing = self.ledger.load(request_id)

        if existing is not None:
            if existing.fingerprint != fingerprint:
                await send("error", {
                    "code": "REQUEST_ID_CONFLICT",
                    "request_id": request_id,
                    "message": "request_id was already used for different content",
                })
                return
            if existing.status == "completed":
                await self._send_completed(existing, send)
                return
            if existing.semantics == "side_effecting":
                reconciled = self.ledger.mark_reconcile_required(existing)
                await self._send_reconcile(reconciled, send, reason="prior_dispatch_outcome_unknown")
                return

        record = self.ledger.mark_dispatch_started(
            request_id=request_id,
            request_version=request["request_version"],
            fingerprint=fingerprint,
            semantics=request["semantics"],
        )

        try:
            dispatch_kwargs: dict[str, Any] = {
                "request_version": request["request_version"],
                "request_id": request_id,
                "body": request["body"],
            }
            parameters = inspect.signature(self.dispatcher.dispatch).parameters
            if (
                "transport_context" in parameters
                or any(
                    parameter.kind is inspect.Parameter.VAR_KEYWORD
                    for parameter in parameters.values()
                )
            ):
                dispatch_kwargs["transport_context"] = transport_context
            result = self.dispatcher.dispatch(**dispatch_kwargs)
            if inspect.isawaitable(result):
                result = await result
            if not isinstance(result, DispatchResult):
                raise TypeError("dispatcher must return DispatchResult")
            if result.stream_data is not None and len(result.stream_data) > self.max_stream_bytes:
                raise ProtocolError("dispatcher stream exceeds maximum size")
            completed = self.ledger.mark_completed(
                request_id=request_id,
                request_version=request["request_version"],
                fingerprint=fingerprint,
                semantics=request["semantics"],
                response_payload=result.payload,
                stream_kind=result.stream_kind,
                stream_data=result.stream_data,
            )
        except UnknownDispatchOutcome:
            if request["semantics"] == "side_effecting":
                reconciled = self.ledger.mark_reconcile_required(record)
                await self._send_reconcile(reconciled, send, reason="dispatcher_reported_unknown_outcome")
                return
            await send("error", {
                "code": "READ_ONLY_DISPATCH_FAILED",
                "request_id": request_id,
                "message": "read-only dispatch outcome was not returned",
            })
            return
        except Exception as exc:
            if request["semantics"] == "side_effecting":
                reconciled = self.ledger.mark_reconcile_required(record)
                await self._send_reconcile(reconciled, send, reason="side_effect_dispatch_failed_unknown")
                return
            await send("error", {
                "code": "READ_ONLY_DISPATCH_FAILED",
                "request_id": request_id,
                "message": f"{type(exc).__name__}: {exc}",
            })
            return

        await self._send_completed(completed, send)

    async def _send_reconcile(
        self,
        record: LedgerRecord,
        send: Callable[[str, dict[str, Any]], Awaitable[None]],
        *,
        reason: str,
    ) -> None:
        await send("reconcile_required", {
            "request_id": record.request_id,
            "request_version": record.request_version,
            "status": "UNKNOWN_RECONCILE",
            "reason": reason,
            "automatic_replay": False,
        })

    async def _send_completed(
        self,
        record: LedgerRecord,
        send: Callable[[str, dict[str, Any]], Awaitable[None]],
    ) -> None:
        stream_manifest = None
        if record.stream_data is not None:
            stream_manifest = build_stream_manifest(
                request_id=record.request_id,
                data=record.stream_data,
                kind=record.stream_kind or "generic",
                chunk_bytes=self.max_chunk_bytes,
                max_stream_bytes=self.max_stream_bytes,
            )
        await send("response", {
            "request_id": record.request_id,
            "request_version": record.request_version,
            "status": "OK",
            "body": record.response_payload or {},
            "stream": None if stream_manifest is None else stream_manifest.to_dict(),
        })
        if stream_manifest is None or record.stream_data is None:
            return
        for chunk in iter_stream_chunks(stream_manifest, record.stream_data):
            await send("stream_chunk", {"request_id": record.request_id, **chunk})
        await send("stream_end", {
            "request_id": record.request_id,
            "stream_id": stream_manifest.stream_id,
            "chunk_count": stream_manifest.chunk_count,
            "total_bytes": stream_manifest.total_bytes,
            "sha256": stream_manifest.sha256,
        })

    async def run_forever(
        self,
        connector: RelayConnector,
        *,
        enabled: Callable[[], bool] = lambda: True,
        backoff: BackoffPolicy = BackoffPolicy(),
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        failure_count = 0
        while enabled():
            connection: PersistentConnection | None = None
            try:
                connection = await connector.open()
                await self.run_session(connection)
                failure_count = 0
            except asyncio.CancelledError:
                raise
            except Exception:
                failure_count += 1
            finally:
                if connection is not None:
                    try:
                        await connection.close()
                    except Exception:
                        pass
            if enabled():
                await sleep(backoff.delay(failure_count))
