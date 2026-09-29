from __future__ import annotations

import asyncio
import base64
import hashlib
import inspect
import json
import ntpath
import os
import tempfile
import threading
import uuid
from contextlib import suppress
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Protocol
from urllib.parse import urlparse

from pc_executor.audit import JsonlAuditSink
from pc_executor.executor import Executor
from pc_executor.outcome_journal import OutcomeJournal

from .agent import BackoffPolicy, DeviceAgent
from .executor_adapter import ExecutorRemoteDispatcher
from .ledger import RequestLedger
from .protocol import DEVICE_ID_RE, ProtocolError, TokenMaterial, TokenRing, decode_rotation_secret, digest_json
from .websocket import WebSocketRelayConnector

CONFIG_VERSION = "pc.native.device_service.config.v1"
HEALTH_VERSION = "pc.native.device_service.health.v1"
DEFAULT_SECRET_NAME = "L$OpenAI.PCNativeDeviceService"
POLL_SECONDS = 0.5


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_protected_root(path: str | os.PathLike[str]) -> bool:
    candidate = ntpath.normcase(ntpath.normpath(str(path).replace("/", "\\")))
    protected = ntpath.normcase(ntpath.normpath(r"E:\manhwa"))
    return candidate == protected or candidate.startswith(protected + "\\")


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    tmp = Path(raw_tmp)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        with suppress(FileNotFoundError):
            tmp.unlink()


@dataclass(frozen=True)
class ServiceConfig:
    contract_version: str = CONFIG_VERSION
    enabled: bool = False
    endpoint: str = ""
    device_id: str = ""
    heartbeat_seconds: float = 15.0
    allow_insecure_loopback: bool = False

    def validate(self) -> "ServiceConfig":
        if self.contract_version != CONFIG_VERSION:
            raise ProtocolError("unsupported device service config version")
        if not isinstance(self.enabled, bool) or not isinstance(self.allow_insecure_loopback, bool):
            raise ProtocolError("service enable flags must be booleans")
        if not isinstance(self.heartbeat_seconds, (int, float)) or isinstance(self.heartbeat_seconds, bool):
            raise ProtocolError("heartbeat_seconds must be numeric")
        if not 1.0 <= float(self.heartbeat_seconds) <= 300.0:
            raise ProtocolError("heartbeat_seconds must be between 1 and 300")
        if self.endpoint:
            parsed = urlparse(self.endpoint)
            if parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ProtocolError("endpoint must not contain credentials, query, or fragment")
            secure = parsed.scheme == "wss" and bool(parsed.hostname)
            loopback = (
                parsed.scheme == "ws"
                and self.allow_insecure_loopback
                and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
            )
            if not secure and not loopback:
                raise ProtocolError("endpoint must use wss; ws is allowed only for explicit loopback")
        if self.device_id and DEVICE_ID_RE.fullmatch(self.device_id) is None:
            raise ProtocolError("device_id is invalid")
        if self.enabled:
            if not self.endpoint:
                raise ProtocolError("endpoint is required before enabling the service")
            if not self.device_id:
                raise ProtocolError("device_id is required before enabling the service")
        return self

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ServiceConfig":
        if not isinstance(raw, dict):
            raise ProtocolError("service config must be an object")
        expected = set(cls().__dict__)
        if set(raw) != expected:
            raise ProtocolError("service config keys mismatch")
        return cls(**raw).validate()


class ConfigStore:
    def __init__(self, root: str | os.PathLike[str] | None = None) -> None:
        selected = Path(root) if root is not None else self.default_root()
        if _is_protected_root(selected):
            raise ProtocolError("protected path is forbidden for device service state")
        self.root = selected
        self.path = self.root / "config.json"
        self.backup_path = self.root / "config.backup.json"

    @staticmethod
    def default_root() -> Path:
        override = os.environ.get("PC_NATIVE_DEVICE_SERVICE_HOME")
        if override:
            return Path(override)
        if os.name == "nt":
            base = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
            return Path(base) / "PCNativeDeviceService"
        base = os.environ.get("XDG_STATE_HOME")
        return (Path(base) if base else Path.home() / ".local" / "state") / "pc-native-device-service"

    @staticmethod
    def _bytes(config: ServiceConfig) -> bytes:
        config.validate()
        return (json.dumps(config.to_dict(), sort_keys=True, indent=2) + "\n").encode("utf-8")

    def initialize(self) -> ServiceConfig:
        if not self.path.exists():
            self.update(ServiceConfig())
        return self.load()

    def load(self) -> ServiceConfig:
        return ServiceConfig.from_dict(json.loads(self.path.read_text(encoding="utf-8")))

    def revision(self, config: ServiceConfig | None = None) -> str:
        cfg = config or self.load()
        return hashlib.sha256(self._bytes(cfg)).hexdigest()

    def update(self, config: ServiceConfig) -> ServiceConfig:
        new_bytes = self._bytes(config)
        old_bytes = self.path.read_bytes() if self.path.exists() else None
        if old_bytes is not None:
            _atomic_write(self.backup_path, old_bytes)
        try:
            _atomic_write(self.path, new_bytes)
            loaded = self.load()
            if loaded != config:
                raise ProtocolError("persisted config failed verification")
            return loaded
        except Exception:
            if old_bytes is None:
                with suppress(FileNotFoundError):
                    self.path.unlink()
            else:
                _atomic_write(self.path, old_bytes)
            raise


@dataclass(frozen=True)
class HealthSnapshot:
    contract_version: str = HEALTH_VERSION
    service_state: str = "stopped"
    service_instance_id: str | None = None
    service_pid: int | None = None
    service_started_at: str | None = None
    auth_state: str = "unverified"
    enabled: bool = False
    device_id: str = ""
    session_epoch: str | None = None
    transport_state: str = "stopped"
    last_heartbeat: str | None = None
    capability_digest: str | None = None
    config_revision: str | None = None
    reason_code: str | None = None
    secret_source: str = "<redacted>"
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class HealthStore:
    _allowed = frozenset(HealthSnapshot().__dict__)
    _new_fields = frozenset({
        "service_instance_id", "service_pid", "service_started_at", "auth_state",
    })
    _legacy_required = _allowed - _new_fields

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.path = Path(root) / "health.json"
        self._lock = threading.Lock()

    def read(self) -> HealthSnapshot:
        if not self.path.exists():
            return HealthSnapshot(updated_at=_utc_now())
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if (
            not isinstance(raw, dict)
            or not self._legacy_required <= set(raw)
            or set(raw) - self._allowed
        ):
            raise ProtocolError("health state is invalid")
        # Previous health.json snapshots remain readable, but no pre-R16 file
        # carries current-instance proof and none can attest readiness.
        return HealthSnapshot(**raw)

    def start_new_instance(self) -> HealthSnapshot:
        """Invalidate persisted pre-reboot readiness before config/secret/relay work."""
        return self.update(
            service_instance_id=uuid.uuid4().hex,
            service_pid=os.getpid(),
            service_started_at=_utc_now(),
            service_state="starting",
            auth_state="unverified",
            enabled=False,
            device_id="",
            session_epoch=None,
            transport_state="idle",
            last_heartbeat=None,
            capability_digest=None,
            config_revision=None,
            reason_code="STARTUP_NOT_AUTHENTICATED",
        )

    def update(self, **changes: Any) -> HealthSnapshot:
        forbidden = set(changes) - self._allowed
        if forbidden:
            raise ProtocolError(f"unsafe health fields: {sorted(forbidden)}")
        if any(term in key.lower() for key in changes for term in ("token", "credential", "secret")):
            raise ProtocolError("secret-bearing health fields are forbidden")
        with self._lock:
            current = self.read()
            changes["updated_at"] = _utc_now()
            snapshot = replace(current, **changes)
            _atomic_write(
                self.path,
                (json.dumps(snapshot.to_dict(), sort_keys=True, indent=2) + "\n").encode("utf-8"),
            )
            return snapshot


class SecretStore(Protocol):
    def read(self, target: str) -> TokenMaterial: ...
    def write(self, target: str, material: TokenMaterial) -> None: ...
    def delete(self, target: str) -> None: ...


class MissingSecretError(RuntimeError):
    pass


def encode_token_material(material: TokenMaterial) -> bytes:
    return json.dumps(
        {
            "generation": material.generation,
            "token_b64": base64.b64encode(material.secret).decode("ascii"),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def decode_token_material(raw: bytes | str) -> TokenMaterial:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    try:
        payload = json.loads(raw)
        if set(payload) != {"generation", "token_b64"}:
            raise ValueError
        generation = payload["generation"]
        secret = base64.b64decode(payload["token_b64"].encode("ascii"), validate=True)
        return TokenMaterial(generation, secret)
    except Exception as exc:
        raise ProtocolError("stored service credential is invalid") from exc


def material_fingerprint(material: TokenMaterial) -> str:
    return hashlib.sha256(
        str(material.generation).encode("ascii") + b":" + material.secret
    ).hexdigest()


class ServiceDeviceAgent(DeviceAgent):
    def __init__(
        self,
        *args: Any,
        rotation_persist: Callable[[int, bytes], Awaitable[None] | None],
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._rotation_persist = rotation_persist

    async def _handle_token_rotation(self, payload: dict[str, Any], send: Callable[..., Awaitable[None]]) -> None:
        if set(payload) != {"new_generation", "new_token_b64"}:
            raise ProtocolError("invalid token rotation payload")
        generation = payload["new_generation"]
        if isinstance(generation, bool) or not isinstance(generation, int) or generation <= 0:
            raise ProtocolError("invalid token generation")
        if generation != self.token_ring.current.generation + 1:
            raise ProtocolError("token generation must advance by exactly one")
        secret = decode_rotation_secret(payload["new_token_b64"])
        persisted = self._rotation_persist(generation, secret)
        if inspect.isawaitable(persisted):
            await persisted
        await super()._handle_token_rotation(payload, send)


class _ObservedConnection:
    def __init__(self, inner: Any, health: HealthStore) -> None:
        self.inner = inner
        self.health = health

    # Raw frames are deliberately NOT trusted as liveness/authentication.
    # Only DeviceAgent can report a validated HMAC + welcome nonce + epoch.
    async def send(self, data: str) -> None:
        await self.inner.send(data)

    async def recv(self) -> str | bytes:
        return await self.inner.recv()

    async def close(self) -> None:
        try:
            await self.inner.close()
        finally:
            self.health.update(
                transport_state="disconnected", auth_state="unverified",
                session_epoch=None, last_heartbeat=None,
            )


class _ObservedConnector:
    def __init__(self, inner: WebSocketRelayConnector, health: HealthStore) -> None:
        self.inner = inner
        self.health = health

    async def open(self) -> _ObservedConnection:
        self.health.update(
            transport_state="connecting", auth_state="unverified",
            session_epoch=None, last_heartbeat=None, reason_code=None,
        )
        try:
            connection = await self.inner.open()
        except Exception:
            self.health.update(
                transport_state="backoff", auth_state="unverified",
                session_epoch=None, last_heartbeat=None, reason_code="CONNECT_FAILED",
            )
            raise
        self.health.update(transport_state="handshaking", auth_state="unverified")
        return _ObservedConnection(connection, self.health)


@dataclass(frozen=True)
class RuntimeBundle:
    agent: DeviceAgent
    connector: Any


def build_default_runtime(
    config: ServiceConfig,
    material: TokenMaterial,
    config_store: ConfigStore,
    health: HealthStore,
    secret_store: SecretStore,
) -> RuntimeBundle:
    audit = JsonlAuditSink(str(config_store.root / "audit.jsonl"))
    journal = OutcomeJournal(config_store.root / "outcome-journal.jsonl")
    executor = Executor(dry_run=False, audit=audit, outcome_journal=journal)
    dispatcher = ExecutorRemoteDispatcher(executor)

    def capabilities() -> dict[str, Any]:
        manifest = dispatcher.capability_manifest()
        health.update(capability_digest=digest_json(manifest))
        return manifest

    def new_epoch() -> str:
        # Opaque Control v1 epoch, now includes an immutable per-service-instance
        # prefix so a fresh authenticated relay hello can bind the live process
        # without expanding or changing the frozen tool-registry payload.
        instance = health.read().service_instance_id
        epoch = f"{instance}:{uuid.uuid4().hex}" if instance else uuid.uuid4().hex
        health.update(
            session_epoch=epoch, last_heartbeat=None,
            auth_state="unverified", transport_state="handshaking",
        )
        return epoch

    def session_authenticated(epoch: str) -> None:
        health.update(
            session_epoch=epoch, transport_state="connected",
            auth_state="authenticated", last_heartbeat=_utc_now(),
            reason_code=None,
        )

    def authenticated_frame(epoch: str, frame_type: str) -> None:
        if frame_type in {"heartbeat", "heartbeat_ack"}:
            health.update(last_heartbeat=_utc_now())

    def persist_rotation(generation: int, secret: bytes) -> None:
        secret_store.write(DEFAULT_SECRET_NAME, TokenMaterial(generation, secret))

    agent = ServiceDeviceAgent(
        device_id=config.device_id,
        token_ring=TokenRing(material.generation, material.secret),
        capabilities=capabilities,
        dispatcher=dispatcher,
        ledger=RequestLedger(config_store.root / "request-ledger"),
        heartbeat_seconds=float(config.heartbeat_seconds),
        session_epoch_factory=new_epoch,
        session_authenticated=session_authenticated,
        authenticated_frame=authenticated_frame,
        rotation_persist=persist_rotation,
    )
    connector = _ObservedConnector(
        WebSocketRelayConnector(
            config.endpoint,
            allow_insecure_loopback=config.allow_insecure_loopback,
        ),
        health,
    )
    return RuntimeBundle(agent=agent, connector=connector)


class DeviceServiceHost:
    def __init__(
        self,
        config_store: ConfigStore,
        health: HealthStore,
        secret_store: SecretStore,
        runtime_factory: Callable[[ServiceConfig, TokenMaterial, ConfigStore, HealthStore, SecretStore], RuntimeBundle] = build_default_runtime,
        poll_seconds: float = POLL_SECONDS,
    ) -> None:
        self.config_store = config_store
        self.health = health
        self.secret_store = secret_store
        self.runtime_factory = runtime_factory
        self.poll_seconds = poll_seconds

    def _enabled_now(self) -> bool:
        try:
            return self.config_store.load().enabled
        except Exception:
            return False

    async def _pause(self, stop_event: threading.Event) -> None:
        await asyncio.to_thread(stop_event.wait, self.poll_seconds)

    async def run(self, stop_event: threading.Event) -> None:
        # This write is FIRST: a reboot/SCM restart must revoke historical
        # authenticated-looking health even if later initialization crashes.
        self.health.start_new_instance()
        self.config_store.initialize()
        active: asyncio.Task[Any] | None = None
        try:
            self.health.update(service_state="running")
            while not stop_event.is_set():
                try:
                    config = self.config_store.load()
                    revision = self.config_store.revision(config)
                except Exception:
                    self.health.update(
                        enabled=False,
                        device_id="",
                        session_epoch=None,
                        auth_state="unverified",
                        transport_state="blocked",
                        last_heartbeat=None,
                        capability_digest=None,
                        config_revision=None,
                        reason_code="CONFIG_INVALID",
                    )
                    await self._pause(stop_event)
                    continue

                if not config.enabled:
                    self.health.update(
                        enabled=False,
                        device_id=config.device_id,
                        session_epoch=None,
                        auth_state="unverified",
                        transport_state="disabled",
                        last_heartbeat=None,
                        capability_digest=None,
                        config_revision=revision,
                        reason_code=None,
                    )
                    await self._pause(stop_event)
                    continue

                try:
                    material = self.secret_store.read(DEFAULT_SECRET_NAME)
                except MissingSecretError:
                    self.health.update(
                        enabled=True,
                        device_id=config.device_id,
                        session_epoch=None,
                        auth_state="unverified",
                        transport_state="blocked",
                        last_heartbeat=None,
                        capability_digest=None,
                        config_revision=revision,
                        reason_code="MISSING_SECRET",
                    )
                    await self._pause(stop_event)
                    continue
                except Exception:
                    self.health.update(
                        enabled=True,
                        device_id=config.device_id,
                        session_epoch=None,
                        auth_state="unverified",
                        transport_state="blocked",
                        last_heartbeat=None,
                        capability_digest=None,
                        config_revision=revision,
                        reason_code="SECRET_INVALID",
                    )
                    await self._pause(stop_event)
                    continue

                fingerprint = material_fingerprint(material)
                bundle = self.runtime_factory(
                    config,
                    material,
                    self.config_store,
                    self.health,
                    self.secret_store,
                )

                async def backoff_sleep(delay: float) -> None:
                    self.health.update(
                        transport_state="backoff", auth_state="unverified",
                        session_epoch=None, last_heartbeat=None,
                        reason_code="RELAY_BACKOFF",
                    )
                    await asyncio.sleep(delay)

                self.health.update(
                    enabled=True,
                    device_id=config.device_id,
                    config_revision=revision,
                    auth_state="unverified",
                    last_heartbeat=None,
                    transport_state="starting_transport",
                    reason_code=None,
                )
                active = asyncio.create_task(
                    bundle.agent.run_forever(
                        bundle.connector,
                        enabled=lambda: not stop_event.is_set() and self._enabled_now(),
                        backoff=BackoffPolicy(),
                        sleep=backoff_sleep,
                    )
                )
                while not stop_event.is_set() and not active.done():
                    await self._pause(stop_event)
                    current_enabled = False
                    try:
                        current = self.config_store.load()
                        current_enabled = current.enabled
                        current_material = self.secret_store.read(DEFAULT_SECRET_NAME)
                        changed = (
                            self.config_store.revision(current) != revision
                            or material_fingerprint(current_material) != fingerprint
                        )
                    except Exception:
                        changed = True
                    if changed or not current_enabled:
                        break

                if active is not None and not active.done():
                    active.cancel()
                    with suppress(asyncio.CancelledError):
                        await active
                elif active is not None:
                    with suppress(Exception):
                        await active
                active = None
        finally:
            self.health.update(
                service_state="stopping", transport_state="stopping",
                auth_state="unverified", session_epoch=None, last_heartbeat=None,
            )
            if active is not None and not active.done():
                active.cancel()
                with suppress(asyncio.CancelledError):
                    await active
            self.health.update(
                service_state="stopped", transport_state="stopped",
                auth_state="unverified", session_epoch=None, last_heartbeat=None,
            )
