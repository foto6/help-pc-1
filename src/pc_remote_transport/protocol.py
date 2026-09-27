from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

FRAME_VERSION = "pc_remote_transport.frame.v1"
REQUEST_VERSION_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,120}$")
DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,120}$")
SESSION_EPOCH_RE = re.compile(r"^[A-Za-z0-9._:-]{8,160}$")

DEFAULT_MAX_FRAME_BYTES = 1_048_576
DEFAULT_MAX_REQUEST_BYTES = 524_288
DEFAULT_MAX_CHUNK_BYTES = 65_536
DEFAULT_MAX_STREAM_BYTES = 8_388_608

FRAME_TYPES = frozenset({
    "hello",
    "welcome",
    "heartbeat",
    "heartbeat_ack",
    "request",
    "response",
    "stream_chunk",
    "stream_end",
    "reconcile_required",
    "error",
    "token.rotate",
    "token.rotated",
})


class ProtocolError(ValueError):
    pass


class AuthenticationError(ProtocolError):
    pass


class ReplayError(ProtocolError):
    pass


class StaleEpochError(ProtocolError):
    pass


@dataclass(frozen=True)
class TokenMaterial:
    generation: int
    secret: bytes

    def __post_init__(self) -> None:
        if isinstance(self.generation, bool) or not isinstance(self.generation, int) or self.generation <= 0:
            raise ValueError("token generation must be a positive integer")
        if not isinstance(self.secret, bytes) or len(self.secret) < 32:
            raise ValueError("token secret must contain at least 32 bytes")


class TokenRing:
    def __init__(self, generation: int, secret: bytes) -> None:
        self._current = TokenMaterial(generation, secret)

    @property
    def current(self) -> TokenMaterial:
        return self._current

    def rotate(self, *, generation: int, secret: bytes) -> None:
        if generation != self._current.generation + 1:
            raise ProtocolError("token generation must advance by exactly one")
        self._current = TokenMaterial(generation, secret)


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_json(value: Any) -> str:
    return sha256_hex(canonical_json(value).encode("utf-8"))


def _signable(frame_without_auth: Mapping[str, Any], generation: int) -> bytes:
    body = dict(frame_without_auth)
    body["token_generation"] = generation
    return canonical_json(body).encode("utf-8")


def _validate_unsigned(frame: Mapping[str, Any]) -> None:
    expected = {"version", "device_id", "session_epoch", "sequence", "type", "payload"}
    if set(frame) != expected:
        raise ProtocolError("frame keys mismatch")
    if frame["version"] != FRAME_VERSION:
        raise ProtocolError("unsupported frame version")
    device_id = frame["device_id"]
    if not isinstance(device_id, str) or not DEVICE_ID_RE.fullmatch(device_id):
        raise ProtocolError("invalid device_id")
    epoch = frame["session_epoch"]
    if not isinstance(epoch, str) or not SESSION_EPOCH_RE.fullmatch(epoch):
        raise ProtocolError("invalid session_epoch")
    sequence = frame["sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
        raise ProtocolError("sequence must be a positive integer")
    frame_type = frame["type"]
    if frame_type not in FRAME_TYPES:
        raise ProtocolError("unsupported frame type")
    if not isinstance(frame["payload"], dict):
        raise ProtocolError("payload must be an object")


def encode_frame(
    *,
    device_id: str,
    session_epoch: str,
    sequence: int,
    frame_type: str,
    payload: dict[str, Any],
    token: TokenMaterial,
    max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
) -> str:
    unsigned = {
        "version": FRAME_VERSION,
        "device_id": device_id,
        "session_epoch": session_epoch,
        "sequence": sequence,
        "type": frame_type,
        "payload": payload,
    }
    _validate_unsigned(unsigned)
    tag = hmac.new(token.secret, _signable(unsigned, token.generation), hashlib.sha256).hexdigest()
    frame = {
        **unsigned,
        "auth": {
            "scheme": "hmac-sha256",
            "token_generation": token.generation,
            "tag": tag,
        },
    }
    raw = canonical_json(frame)
    if len(raw.encode("utf-8")) > max_frame_bytes:
        raise ProtocolError("frame exceeds maximum size")
    return raw


def decode_frame(
    raw: str | bytes,
    *,
    token: TokenMaterial,
    expected_device_id: str,
    expected_session_epoch: str,
    max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
) -> dict[str, Any]:
    raw_bytes = raw.encode("utf-8") if isinstance(raw, str) else raw
    if len(raw_bytes) > max_frame_bytes:
        raise ProtocolError("frame exceeds maximum size")
    try:
        parsed = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid JSON frame") from exc
    if not isinstance(parsed, dict):
        raise ProtocolError("frame must be an object")
    if set(parsed) != {"version", "device_id", "session_epoch", "sequence", "type", "payload", "auth"}:
        raise ProtocolError("frame keys mismatch")
    auth = parsed["auth"]
    if not isinstance(auth, dict) or set(auth) != {"scheme", "token_generation", "tag"}:
        raise AuthenticationError("invalid auth envelope")
    if auth["scheme"] != "hmac-sha256":
        raise AuthenticationError("unsupported auth scheme")
    if auth["token_generation"] != token.generation:
        raise AuthenticationError("token generation mismatch")
    tag = auth["tag"]
    if not isinstance(tag, str) or len(tag) != 64:
        raise AuthenticationError("invalid authentication tag")
    unsigned = {key: parsed[key] for key in ("version", "device_id", "session_epoch", "sequence", "type", "payload")}
    _validate_unsigned(unsigned)
    if parsed["device_id"] != expected_device_id:
        raise AuthenticationError("device identity mismatch")
    if parsed["session_epoch"] != expected_session_epoch:
        raise StaleEpochError("stale or foreign session epoch")
    expected = hmac.new(token.secret, _signable(unsigned, token.generation), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(tag, expected):
        raise AuthenticationError("authentication tag mismatch")
    return unsigned


class InboundReplayGuard:
    def __init__(self) -> None:
        self._last_sequence = 0

    @property
    def last_sequence(self) -> int:
        return self._last_sequence

    def accept(self, sequence: int) -> None:
        if sequence <= self._last_sequence:
            raise ReplayError("replayed or reordered frame sequence")
        self._last_sequence = sequence


def validate_request_payload(
    payload: Any,
    *,
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ProtocolError("request payload must be an object")
    expected = {"request_id", "request_version", "delivery_id", "semantics", "body"}
    if set(payload) != expected:
        raise ProtocolError("request payload keys mismatch")
    request_id = payload["request_id"]
    if not isinstance(request_id, str) or not REQUEST_ID_RE.fullmatch(request_id):
        raise ProtocolError("invalid request_id")
    request_version = payload["request_version"]
    if not isinstance(request_version, str) or not REQUEST_VERSION_RE.fullmatch(request_version):
        raise ProtocolError("invalid request_version")
    delivery_id = payload["delivery_id"]
    if not isinstance(delivery_id, str) or not REQUEST_ID_RE.fullmatch(delivery_id):
        raise ProtocolError("invalid delivery_id")
    semantics = payload["semantics"]
    if semantics not in {"read_only", "side_effecting"}:
        raise ProtocolError("semantics must be read_only or side_effecting")
    body = payload["body"]
    if not isinstance(body, dict):
        raise ProtocolError("request body must be an object")
    if len(canonical_json(body).encode("utf-8")) > max_request_bytes:
        raise ProtocolError("request body exceeds maximum size")
    return {
        "request_id": request_id,
        "request_version": request_version,
        "delivery_id": delivery_id,
        "semantics": semantics,
        "body": body,
    }


def request_fingerprint(payload: Mapping[str, Any]) -> str:
    return digest_json({
        "request_id": payload["request_id"],
        "request_version": payload["request_version"],
        "semantics": payload["semantics"],
        "body": payload["body"],
    })


def decode_rotation_secret(value: Any) -> bytes:
    if not isinstance(value, str):
        raise ProtocolError("new token must be base64 text")
    try:
        secret = base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise ProtocolError("invalid base64 token") from exc
    if len(secret) < 32:
        raise ProtocolError("rotated token must contain at least 32 bytes")
    return secret


@dataclass(frozen=True)
class StreamManifest:
    stream_id: str
    kind: str
    total_bytes: int
    chunk_bytes: int
    chunk_count: int
    sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "stream_id": self.stream_id,
            "kind": self.kind,
            "total_bytes": self.total_bytes,
            "chunk_bytes": self.chunk_bytes,
            "chunk_count": self.chunk_count,
            "sha256": self.sha256,
        }


def build_stream_manifest(
    *,
    request_id: str,
    data: bytes,
    kind: str,
    chunk_bytes: int = DEFAULT_MAX_CHUNK_BYTES,
    max_stream_bytes: int = DEFAULT_MAX_STREAM_BYTES,
) -> StreamManifest:
    if not isinstance(data, bytes):
        raise TypeError("stream data must be bytes")
    if len(data) > max_stream_bytes:
        raise ProtocolError("stream exceeds maximum size")
    if isinstance(chunk_bytes, bool) or not isinstance(chunk_bytes, int) or not (1 <= chunk_bytes <= DEFAULT_MAX_CHUNK_BYTES):
        raise ProtocolError("invalid chunk size")
    digest = sha256_hex(data)
    chunk_count = (len(data) + chunk_bytes - 1) // chunk_bytes if data else 0
    return StreamManifest(
        stream_id=f"{request_id}:{digest[:16]}",
        kind=kind,
        total_bytes=len(data),
        chunk_bytes=chunk_bytes,
        chunk_count=chunk_count,
        sha256=digest,
    )


def iter_stream_chunks(manifest: StreamManifest, data: bytes):
    for index in range(manifest.chunk_count):
        start = index * manifest.chunk_bytes
        chunk = data[start:start + manifest.chunk_bytes]
        yield {
            "stream_id": manifest.stream_id,
            "index": index,
            "chunk_count": manifest.chunk_count,
            "byte_count": len(chunk),
            "sha256": sha256_hex(chunk),
            "data_b64": base64.b64encode(chunk).decode("ascii"),
        }


class StreamAssembler:
    def __init__(self, manifest: Mapping[str, Any], *, max_stream_bytes: int = DEFAULT_MAX_STREAM_BYTES) -> None:
        required = {"stream_id", "kind", "total_bytes", "chunk_bytes", "chunk_count", "sha256"}
        if not isinstance(manifest, Mapping) or set(manifest) != required:
            raise ProtocolError("invalid stream manifest")
        self.stream_id = str(manifest["stream_id"])
        self.total_bytes = int(manifest["total_bytes"])
        self.chunk_bytes = int(manifest["chunk_bytes"])
        self.chunk_count = int(manifest["chunk_count"])
        self.sha256 = str(manifest["sha256"])
        if self.total_bytes < 0 or self.total_bytes > max_stream_bytes:
            raise ProtocolError("stream size out of bounds")
        if not (1 <= self.chunk_bytes <= DEFAULT_MAX_CHUNK_BYTES):
            raise ProtocolError("chunk size out of bounds")
        if self.chunk_count < 0:
            raise ProtocolError("chunk_count out of bounds")
        expected_count = (self.total_bytes + self.chunk_bytes - 1) // self.chunk_bytes if self.total_bytes else 0
        if self.chunk_count != expected_count:
            raise ProtocolError("chunk_count inconsistent with stream size")
        if len(self.sha256) != 64 or any(ch not in "0123456789abcdef" for ch in self.sha256):
            raise ProtocolError("invalid stream digest")
        self._next_index = 0
        self._parts: list[bytes] = []

    def accept(self, payload: Mapping[str, Any]) -> None:
        expected = {"stream_id", "index", "chunk_count", "byte_count", "sha256", "data_b64"}
        if not isinstance(payload, Mapping) or set(payload) != expected:
            raise ProtocolError("invalid stream chunk")
        if payload["stream_id"] != self.stream_id:
            raise ProtocolError("stream_id mismatch")
        if payload["chunk_count"] != self.chunk_count:
            raise ProtocolError("chunk_count mismatch")
        if payload["index"] != self._next_index:
            raise ReplayError("reordered or duplicate stream chunk")
        try:
            chunk = base64.b64decode(str(payload["data_b64"]).encode("ascii"), validate=True)
        except Exception as exc:
            raise ProtocolError("invalid chunk base64") from exc
        if payload["byte_count"] != len(chunk):
            raise ProtocolError("chunk byte count mismatch")
        if payload["sha256"] != sha256_hex(chunk):
            raise ProtocolError("chunk digest mismatch")
        if len(chunk) > self.chunk_bytes:
            raise ProtocolError("chunk exceeds chunk bound")
        self._parts.append(chunk)
        self._next_index += 1

    def finish(self, payload: Mapping[str, Any]) -> bytes:
        expected = {"stream_id", "chunk_count", "total_bytes", "sha256"}
        if not isinstance(payload, Mapping) or set(payload) != expected:
            raise ProtocolError("invalid stream end")
        if payload["stream_id"] != self.stream_id:
            raise ProtocolError("stream_id mismatch")
        if payload["chunk_count"] != self.chunk_count or self._next_index != self.chunk_count:
            raise ProtocolError("stream ended before all chunks")
        data = b"".join(self._parts)
        if payload["total_bytes"] != len(data) or len(data) != self.total_bytes:
            raise ProtocolError("stream total byte count mismatch")
        if payload["sha256"] != self.sha256 or sha256_hex(data) != self.sha256:
            raise ProtocolError("stream digest mismatch")
        return data
