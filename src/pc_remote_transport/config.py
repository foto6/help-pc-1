from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from .protocol import ProtocolError, TokenRing


@dataclass(frozen=True)
class RemoteTransportSettings:
    enabled: bool
    endpoint: str
    device_id: str
    token_generation: int
    token_secret: bytes
    state_dir: str

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "RemoteTransportSettings":
        source = os.environ if env is None else env
        enabled = source.get("PC_NATIVE_REMOTE_TRANSPORT", "0").strip().lower() in {"1", "true", "yes", "on"}
        endpoint = source.get("PC_REMOTE_RELAY_URL", "").strip()
        device_id = source.get("PC_REMOTE_DEVICE_ID", "").strip()
        state_dir = source.get("PC_REMOTE_STATE_DIR", ".pc-remote").strip() or ".pc-remote"
        try:
            generation = int(source.get("PC_REMOTE_TOKEN_GENERATION", "1"))
        except ValueError as exc:
            raise ProtocolError("PC_REMOTE_TOKEN_GENERATION must be an integer") from exc
        raw_token = source.get("PC_REMOTE_TOKEN_B64", "").strip()
        try:
            secret = base64.b64decode(raw_token.encode("ascii"), validate=True) if raw_token else b""
        except Exception as exc:
            raise ProtocolError("PC_REMOTE_TOKEN_B64 must be valid base64") from exc
        if enabled:
            if not endpoint:
                raise ProtocolError("PC_REMOTE_RELAY_URL is required when native transport is enabled")
            if not device_id:
                raise ProtocolError("PC_REMOTE_DEVICE_ID is required when native transport is enabled")
            if len(secret) < 32:
                raise ProtocolError("PC_REMOTE_TOKEN_B64 must decode to at least 32 bytes")
            if generation <= 0:
                raise ProtocolError("PC_REMOTE_TOKEN_GENERATION must be positive")
        return cls(
            enabled=enabled,
            endpoint=endpoint,
            device_id=device_id,
            token_generation=generation,
            token_secret=secret,
            state_dir=state_dir,
        )

    def token_ring(self) -> TokenRing:
        return TokenRing(self.token_generation, self.token_secret)
