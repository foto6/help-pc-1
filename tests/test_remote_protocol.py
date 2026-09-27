from __future__ import annotations

import base64

import pytest

from pc_remote_transport.protocol import (
    AuthenticationError,
    InboundReplayGuard,
    ProtocolError,
    ReplayError,
    StaleEpochError,
    StreamAssembler,
    TokenMaterial,
    build_stream_manifest,
    encode_frame,
    decode_frame,
    iter_stream_chunks,
    validate_request_payload,
)


def _token(byte: int = 7, generation: int = 1) -> TokenMaterial:
    return TokenMaterial(generation, bytes([byte]) * 32)


def test_authenticated_frame_round_trip() -> None:
    raw = encode_frame(
        device_id="device-1",
        session_epoch="epoch-0001",
        sequence=1,
        frame_type="heartbeat",
        payload={"x": 1},
        token=_token(),
    )
    decoded = decode_frame(
        raw,
        token=_token(),
        expected_device_id="device-1",
        expected_session_epoch="epoch-0001",
    )
    assert decoded["payload"] == {"x": 1}


def test_forged_device_or_token_is_rejected() -> None:
    raw = encode_frame(
        device_id="device-1",
        session_epoch="epoch-0001",
        sequence=1,
        frame_type="heartbeat",
        payload={},
        token=_token(9),
    )
    with pytest.raises(AuthenticationError):
        decode_frame(
            raw,
            token=_token(7),
            expected_device_id="device-1",
            expected_session_epoch="epoch-0001",
        )

    valid = encode_frame(
        device_id="forged-device",
        session_epoch="epoch-0001",
        sequence=1,
        frame_type="heartbeat",
        payload={},
        token=_token(),
    )
    with pytest.raises(AuthenticationError, match="device identity"):
        decode_frame(
            valid,
            token=_token(),
            expected_device_id="device-1",
            expected_session_epoch="epoch-0001",
        )


def test_stale_session_epoch_is_rejected() -> None:
    raw = encode_frame(
        device_id="device-1",
        session_epoch="epoch-old1",
        sequence=1,
        frame_type="heartbeat",
        payload={},
        token=_token(),
    )
    with pytest.raises(StaleEpochError):
        decode_frame(
            raw,
            token=_token(),
            expected_device_id="device-1",
            expected_session_epoch="epoch-new1",
        )


def test_replay_and_reordered_frame_sequence_are_rejected() -> None:
    guard = InboundReplayGuard()
    guard.accept(1)
    guard.accept(3)
    with pytest.raises(ReplayError):
        guard.accept(3)
    with pytest.raises(ReplayError):
        guard.accept(2)


def test_request_body_bound_is_enforced() -> None:
    with pytest.raises(ProtocolError, match="maximum size"):
        validate_request_payload(
            {
                "request_id": "r1",
                "request_version": "control.v1",
                "delivery_id": "d1",
                "semantics": "read_only",
                "body": {"blob": "x" * 500},
            },
            max_request_bytes=100,
        )


def test_oversized_frame_is_rejected_before_parse() -> None:
    with pytest.raises(ProtocolError, match="maximum size"):
        decode_frame(
            b"x" * 101,
            token=_token(),
            expected_device_id="device-1",
            expected_session_epoch="epoch-0001",
            max_frame_bytes=100,
        )


def test_stream_integrity_round_trip_and_reordered_chunk_rejection() -> None:
    data = b"abcdefghij" * 20
    manifest = build_stream_manifest(request_id="r1", data=data, kind="file_read", chunk_bytes=32)
    chunks = list(iter_stream_chunks(manifest, data))

    assembler = StreamAssembler(manifest.to_dict())
    with pytest.raises(ReplayError, match="reordered"):
        assembler.accept(chunks[1])

    assembler = StreamAssembler(manifest.to_dict())
    for chunk in chunks:
        assembler.accept(chunk)
    result = assembler.finish({
        "stream_id": manifest.stream_id,
        "chunk_count": manifest.chunk_count,
        "total_bytes": manifest.total_bytes,
        "sha256": manifest.sha256,
    })
    assert result == data


def test_invalid_stream_digest_is_rejected() -> None:
    data = b"process output"
    manifest = build_stream_manifest(request_id="r2", data=data, kind="process_output", chunk_bytes=8)
    chunks = list(iter_stream_chunks(manifest, data))
    chunks[0]["data_b64"] = base64.b64encode(b"corrupt!").decode("ascii")
    assembler = StreamAssembler(manifest.to_dict())
    with pytest.raises(ProtocolError, match="digest"):
        assembler.accept(chunks[0])
