from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .protocol import DEFAULT_MAX_STREAM_BYTES, ProtocolError


@dataclass(frozen=True)
class LedgerRecord:
    request_id: str
    request_version: str
    fingerprint: str
    semantics: str
    status: str
    response_payload: dict[str, Any] | None = None
    stream_kind: str | None = None
    stream_data: bytes | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "version": "pc_remote_transport.request_ledger.v1",
            "request_id": self.request_id,
            "request_version": self.request_version,
            "fingerprint": self.fingerprint,
            "semantics": self.semantics,
            "status": self.status,
            "response_payload": self.response_payload,
            "stream_kind": self.stream_kind,
            "stream_b64": None if self.stream_data is None else base64.b64encode(self.stream_data).decode("ascii"),
        }

    @classmethod
    def from_json(cls, raw: Any, *, max_stream_bytes: int = DEFAULT_MAX_STREAM_BYTES) -> "LedgerRecord":
        if not isinstance(raw, dict):
            raise ProtocolError("ledger record must be an object")
        expected = {
            "version",
            "request_id",
            "request_version",
            "fingerprint",
            "semantics",
            "status",
            "response_payload",
            "stream_kind",
            "stream_b64",
        }
        if set(raw) != expected or raw["version"] != "pc_remote_transport.request_ledger.v1":
            raise ProtocolError("invalid ledger record")
        response = raw["response_payload"]
        if response is not None and not isinstance(response, dict):
            raise ProtocolError("ledger response_payload must be object or null")
        stream_b64 = raw["stream_b64"]
        stream_data = None
        if stream_b64 is not None:
            if not isinstance(stream_b64, str):
                raise ProtocolError("ledger stream_b64 must be text or null")
            try:
                stream_data = base64.b64decode(stream_b64.encode("ascii"), validate=True)
            except Exception as exc:
                raise ProtocolError("ledger stream_b64 invalid") from exc
            if len(stream_data) > max_stream_bytes:
                raise ProtocolError("ledger stream exceeds bound")
        status = raw["status"]
        if status not in {"dispatch_started", "completed", "reconcile_required"}:
            raise ProtocolError("invalid ledger status")
        semantics = raw["semantics"]
        if semantics not in {"read_only", "side_effecting"}:
            raise ProtocolError("invalid ledger semantics")
        return cls(
            request_id=str(raw["request_id"]),
            request_version=str(raw["request_version"]),
            fingerprint=str(raw["fingerprint"]),
            semantics=semantics,
            status=status,
            response_payload=response,
            stream_kind=raw["stream_kind"],
            stream_data=stream_data,
        )


class RequestLedger:
    """Crash-durable request state.

    A side-effecting request is written as dispatch_started before application
    dispatch. If the process dies before completion is durably recorded, a
    later delivery is converted to reconcile_required instead of re-dispatch.
    """

    def __init__(self, directory: str | os.PathLike[str], *, max_stream_bytes: int = DEFAULT_MAX_STREAM_BYTES) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.max_stream_bytes = max_stream_bytes

    def _path(self, request_id: str) -> Path:
        if not request_id:
            raise ProtocolError("invalid empty ledger key")
        key = hashlib.sha256(request_id.encode("utf-8")).hexdigest()
        return self.directory / f"{key}.json"

    def load(self, request_id: str) -> LedgerRecord | None:
        path = self._path(request_id)
        if not path.exists():
            return None
        return LedgerRecord.from_json(json.loads(path.read_text(encoding="utf-8")), max_stream_bytes=self.max_stream_bytes)

    def _write(self, record: LedgerRecord) -> None:
        path = self._path(record.request_id)
        tmp = path.with_suffix(".json.tmp")
        data = json.dumps(record.to_json(), ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        with tmp.open("w", encoding="utf-8", newline="\n") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)

    def mark_dispatch_started(
        self,
        *,
        request_id: str,
        request_version: str,
        fingerprint: str,
        semantics: str,
    ) -> LedgerRecord:
        existing = self.load(request_id)
        if existing is not None:
            if existing.fingerprint != fingerprint:
                raise ProtocolError("request_id reused with different request content")
            return existing
        record = LedgerRecord(
            request_id=request_id,
            request_version=request_version,
            fingerprint=fingerprint,
            semantics=semantics,
            status="dispatch_started",
        )
        self._write(record)
        return record

    def mark_completed(
        self,
        *,
        request_id: str,
        request_version: str,
        fingerprint: str,
        semantics: str,
        response_payload: dict[str, Any],
        stream_kind: str | None,
        stream_data: bytes | None,
    ) -> LedgerRecord:
        if stream_data is not None and len(stream_data) > self.max_stream_bytes:
            raise ProtocolError("stream exceeds ledger bound")
        record = LedgerRecord(
            request_id=request_id,
            request_version=request_version,
            fingerprint=fingerprint,
            semantics=semantics,
            status="completed",
            response_payload=response_payload,
            stream_kind=stream_kind,
            stream_data=stream_data,
        )
        self._write(record)
        return record

    def mark_reconcile_required(self, record: LedgerRecord) -> LedgerRecord:
        updated = LedgerRecord(
            request_id=record.request_id,
            request_version=record.request_version,
            fingerprint=record.fingerprint,
            semantics=record.semantics,
            status="reconcile_required",
        )
        self._write(updated)
        return updated
