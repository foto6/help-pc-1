from __future__ import annotations

import asyncio
import json

import pytest

from pc_executor.operations import (
    CURSOR_VERSION,
    LOG_CURSOR_VERSION,
    NATIVE_CAPABILITIES_VERSION,
    NATIVE_REQUEST_VERSION,
    NATIVE_RESULT_VERSION,
    NATIVE_TOOL_PARITY_VERSION,
    OPS_ACTIONS,
    OPS_CAPABILITIES_VERSION,
    OPS_CONTEXT_VERSION,
    OPS_PREFLIGHT_VERSION,
    OPS_SIDE_EFFECT_ACTIONS,
    PROCESS_HANDLE_VERSION,
    SEARCH_CURSOR_VERSION,
)
from pc_executor.search_sessions import SEARCH_SESSION_VERSION
from pc_remote_transport import (
    DeviceAgent,
    ExecutorRemoteDispatcher,
    NATIVE_CONTROL_PROTOCOL_V1,
    RequestLedger,
    TokenMaterial,
    TokenRing,
)
from pc_remote_transport.executor_adapter import TOOL_REGISTRY_DIGEST
from pc_remote_transport.protocol import FRAME_VERSION, decode_frame, digest_json, encode_frame


_SENTINEL = object()


class SpyOperations:
    def __init__(self) -> None:
        self.digest = "p" * 64

    def capabilities_snapshot(self) -> dict:
        return {
            "contract_version": OPS_CAPABILITIES_VERSION,
            "operations_contract_version": "pc_executor.ops.v1",
            "native_tool_parity_version": NATIVE_TOOL_PARITY_VERSION,
            "schema_versions": {
                "request": NATIVE_REQUEST_VERSION,
                "result": NATIVE_RESULT_VERSION,
                "capabilities": NATIVE_CAPABILITIES_VERSION,
                "preflight": OPS_PREFLIGHT_VERSION,
                "execution_context": OPS_CONTEXT_VERSION,
                "stream_cursor": CURSOR_VERSION,
                "log_cursor": LOG_CURSOR_VERSION,
                "search_cursor": SEARCH_CURSOR_VERSION,
                "search_session": SEARCH_SESSION_VERSION,
                "process_handle": PROCESS_HANDLE_VERSION,
            },
            "actions": {
                action: {
                    "supported": True,
                    "side_effecting": action in OPS_SIDE_EFFECT_ACTIONS,
                    "tool_contract_version": NATIVE_TOOL_PARITY_VERSION,
                }
                for action in sorted(OPS_ACTIONS)
            },
            "safety": {},
            "attestation": {
                "algorithm": "sha256",
                "digest": self.digest,
            },
        }


class OutcomeSpyExecutor:
    def __init__(self) -> None:
        self.digest = "d" * 64
        self.outcome_journal = object()
        self.execute_calls = 0
        self.completed_requests: set[tuple[str, str]] = set()
        self.operations = SpyOperations()

    def capabilities_snapshot(self) -> dict:
        return {
            "contract_version": "pc_executor.capabilities.v1",
            "actions": {
                "shell.run": {
                    "supported": True,
                    "side_effecting": True,
                }
            },
            "attestation": {
                "algorithm": "sha256",
                "digest": self.digest,
            },
        }

    def preflight(self, payload: dict) -> dict:
        request = payload["request"]
        return {
            "contract_version": "pc_executor.action_preflight.v1",
            "request_id": request["request_id"],
            "action": request["action"],
            "status": "ready",
            "executable": True,
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
        prior = (request_id, action) in self.completed_requests
        return {
            "reason": "completed" if prior else "no_evidence",
            "latest_valid_record": {"request_id": request_id} if prior else None,
            "provenance": {"matched_records": 1 if prior else 0},
        }

    def bind_execution_context(self, request) -> dict:
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
            "context_digest": "e" * 64,
        }

    def execute(self, request) -> dict:
        self.execute_calls += 1
        self.completed_requests.add((request.request_id, request.action))
        return {
            "request_id": request.request_id,
            "action": request.action,
            "ok": True,
            "status": "completed",
            "data": {"returncode": 0},
            "error": None,
            "error_kind": None,
            "dry_run": False,
            "outcome_evidence": {
                "effect_state": "completed",
                "reconciliation_required": False,
                "dispatch_started": True,
            },
        }


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


async def handshake(relay: QueueConnection, token: TokenMaterial) -> tuple[str, int, dict]:
    raw = await relay.recv()
    epoch = json.loads(raw)["session_epoch"]
    hello = decode_frame(
        raw,
        token=token,
        expected_device_id="device-1",
        expected_session_epoch=epoch,
    )
    await relay.send(
        encode_frame(
            device_id="device-1",
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


def body(request_id: str) -> dict:
    return {
        "contract_version": NATIVE_CONTROL_PROTOCOL_V1,
        "session_id": "stable-control-session",
        "request_id": request_id,
        "tool": "shell.run",
        "arguments": {"argv": ["fake"]},
    }


def request_frame(
    *,
    epoch: str,
    sequence: int,
    token: TokenMaterial,
    request_id: str,
    delivery_id: str,
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
            "semantics": "side_effecting",
            "body": body(request_id),
        },
        token=token,
    )


@pytest.mark.asyncio
async def test_device_hello_contains_exact_executor_digest(tmp_path) -> None:
    token = TokenMaterial(1, b"u" * 32)
    executor = OutcomeSpyExecutor()
    dispatcher = ExecutorRemoteDispatcher(executor)
    agent = DeviceAgent(
        device_id="device-1",
        token_ring=TokenRing(token.generation, token.secret),
        capabilities=dispatcher.capability_manifest,
        dispatcher=dispatcher,
        ledger=RequestLedger(tmp_path / "ledger"),
        heartbeat_seconds=0,
        session_epoch_factory=lambda: "epoch-hello-digest-1",
    )
    device, relay = pair()
    task = asyncio.create_task(agent.run_session(device))
    _, _, hello = await handshake(relay, token)

    advertised = hello["payload"]["capabilities"]
    assert advertised["protocol_version"] == NATIVE_CONTROL_PROTOCOL_V1
    assert advertised["registry_digest"] == TOOL_REGISTRY_DIGEST
    assert advertised["executor"]["contract_version"] == OPS_CAPABILITIES_VERSION
    assert advertised["executor"]["digest"] == executor.operations.digest
    assert advertised["tool_parity"]["native_tool_parity_version"] == NATIVE_TOOL_PARITY_VERSION
    assert advertised["compatibility"]["legacy_executor"]["digest"] == executor.digest
    assert hello["payload"]["capabilities_digest"] == digest_json(advertised)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_missing_transport_ledger_uses_executor_outcome_without_reexecution(tmp_path) -> None:
    token = TokenMaterial(1, b"v" * 32)
    executor = OutcomeSpyExecutor()
    dispatcher = ExecutorRemoteDispatcher(executor)

    agent1 = DeviceAgent(
        device_id="device-1",
        token_ring=TokenRing(token.generation, token.secret),
        capabilities=dispatcher.capability_manifest,
        dispatcher=dispatcher,
        ledger=RequestLedger(tmp_path / "ledger-1"),
        heartbeat_seconds=0,
        session_epoch_factory=lambda: "epoch-journal-0001",
    )
    device1, relay1 = pair()
    task1 = asyncio.create_task(agent1.run_session(device1))
    epoch1, seq1, _ = await handshake(relay1, token)
    await relay1.send(
        request_frame(
            epoch=epoch1,
            sequence=seq1 + 1,
            token=token,
            request_id="journal-recover-1",
            delivery_id="delivery-1",
        )
    )
    first = decode_frame(
        await relay1.recv(),
        token=token,
        expected_device_id="device-1",
        expected_session_epoch=epoch1,
    )
    assert first["type"] == "response"
    assert executor.execute_calls == 1
    task1.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task1

    agent2 = DeviceAgent(
        device_id="device-1",
        token_ring=TokenRing(token.generation, token.secret),
        capabilities=dispatcher.capability_manifest,
        dispatcher=dispatcher,
        ledger=RequestLedger(tmp_path / "ledger-2"),
        heartbeat_seconds=0,
        session_epoch_factory=lambda: "epoch-journal-0002",
    )
    device2, relay2 = pair()
    task2 = asyncio.create_task(agent2.run_session(device2))
    epoch2, seq2, _ = await handshake(relay2, token)
    await relay2.send(
        request_frame(
            epoch=epoch2,
            sequence=seq2 + 1,
            token=token,
            request_id="journal-recover-1",
            delivery_id="delivery-2",
        )
    )
    second = decode_frame(
        await relay2.recv(),
        token=token,
        expected_device_id="device-1",
        expected_session_epoch=epoch2,
    )
    assert second["type"] == "reconcile_required"
    assert second["payload"]["status"] == "UNKNOWN_RECONCILE"
    assert second["payload"]["automatic_replay"] is False
    assert executor.execute_calls == 1

    task2.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task2
