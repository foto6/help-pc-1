"""Mock-only R16 reboot/autostart matrix. NEVER accesses live Windows SCM."""
from __future__ import annotations

import asyncio
import json
import os
import threading
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from pc_remote_transport.agent import DeviceAgent
from pc_remote_transport.executor_adapter import (
    PARITY_TOOL_REGISTRY_DIGEST, TOOL_REGISTRY_DIGEST,
)
from pc_remote_transport.ledger import RequestLedger
from pc_remote_transport.protocol import (
    FRAME_VERSION, ProtocolError, TokenMaterial, TokenRing, encode_frame,
)
from pc_remote_transport.reboot_readiness import (
    CONTRACT_VERSION, WITNESS_KEYS, evaluate_reboot_readiness,
    status_without_live_witness,
)
from pc_remote_transport.service import (
    ConfigStore, DeviceServiceHost, HealthSnapshot, HealthStore, RuntimeBundle,
    ServiceConfig, _ObservedConnection, _ObservedConnector,
)
from pc_remote_transport.service_cli import _status_payload
from pc_remote_transport.windows_service import WindowsServiceController

INSTANCE_A = "a" * 32
INSTANCE_B = "b" * 32
EPOCH_A = "c" * 32
CAP_DIGEST = "f" * 64


def _healthy(*, instance: str = INSTANCE_B, pid: int = 4100) -> HealthSnapshot:
    return HealthSnapshot(
        service_state="running", service_instance_id=instance,
        service_pid=pid, service_started_at="2026-09-29T09:00:00+00:00",
        auth_state="authenticated", enabled=True,
        device_id="device-r16", session_epoch=f"{instance}:{EPOCH_A}",
        transport_state="connected", last_heartbeat="2026-09-29T09:00:01+00:00",
        capability_digest=CAP_DIGEST, config_revision="r16",
    )


def _witness(health: HealthSnapshot, **overrides):
    result = {
        "contract_version": CONTRACT_VERSION,
        "service_instance_id": health.service_instance_id,
        "service_pid": health.service_pid,
        "service_started_at": health.service_started_at,
        "device_id": health.device_id,
        "session_epoch": health.session_epoch,
        "capability_digest": health.capability_digest,
        "relay_session_epoch": health.session_epoch,
        "control_session_epoch": "control-current-epoch",
        "credential_owner_epoch": "owner-current-epoch",
        "launcher_run_id": "fresh-run-after-reboot",
        "fresh_hello_verified": True,
        "live_listener_verified": True,
        "credential_owner_verified": True,
    }
    result.update(overrides)
    assert set(result) == WITNESS_KEYS
    return result


def _evaluate(health: HealthSnapshot, *, witness=None, pid=None, scm="running"):
    return evaluate_reboot_readiness(
        health, scm_state=scm,
        live_scm_pid=health.service_pid if pid is None else pid,
        live_witness=witness,
    )


def test_frozen_registries_remain_exact_and_distinct():
    assert TOOL_REGISTRY_DIGEST == (
        "58b2bde8c6a49825747dcd7010f105dad0b6d548c7e8341cdafb32d2319f6dcd"
    )
    assert PARITY_TOOL_REGISTRY_DIGEST == (
        "dab7ebd65dd239519c755b0521cd2068f15ae885402e37d4885f64b9c2a08c33"
    )


@pytest.mark.parametrize("scm", ["stopped", "not_installed", "unknown", "stop_pending"])
def test_historical_health_never_becomes_ready_without_live_scm(scm):
    health = _healthy()
    result = _evaluate(health, witness=_witness(health), scm=scm)
    assert not result.ready and result.reason_code == "SCM_NOT_RUNNING"

def test_pid_and_epoch_reuse_cannot_substitute_service_instance():
    old = _healthy(instance=INSTANCE_A)
    current = _healthy(instance=INSTANCE_B)
    # SCM PID and the transport session epoch are deliberately reused.
    stale = _witness(old)
    result = _evaluate(current, witness=stale)
    assert not result.ready
    assert result.reason_code == "SERVICE_INSTANCE_MISMATCH"
    assert _evaluate(current, witness=_witness(current), pid=4101).reason_code == (
        "SCM_PID_UNVERIFIED"
    )
    # Even manually replaying the old opaque epoch inside new persisted health
    # cannot pass the per-process prefix check when PID is recycled.
    forged = replace(current, session_epoch=old.session_epoch)
    assert _evaluate(forged, witness=_witness(forged)).reason_code == (
        "SESSION_INSTANCE_UNBOUND"
    )


@pytest.mark.parametrize(
    ("override", "code"), [
        ({"fresh_hello_verified": False}, "FRESH_AUTHENTICATED_HELLO_REQUIRED"),
        ({"live_listener_verified": False}, "LIVE_RELAY_CONTROL_REQUIRED"),
        ({"credential_owner_verified": False}, "LIVE_CREDENTIAL_OWNER_REQUIRED"),
        ({"relay_session_epoch": "stale-listener"}, "SESSION_OR_CAPABILITY_MISMATCH"),
        ({"capability_digest": "0" * 64}, "SESSION_OR_CAPABILITY_MISMATCH"),
        ({"launcher_run_id": ""}, "LIVE_WITNESS_FIELD_INVALID"),
        ({"credential_owner_epoch": ""}, "LIVE_WITNESS_FIELD_INVALID"),
        ({"control_session_epoch": ""}, "LIVE_WITNESS_FIELD_INVALID"),
    ],
)
def test_reboot_negative_matrix_never_uses_stale_listener_or_owner(override, code):
    health = _healthy()
    result = _evaluate(health, witness=_witness(health, **override))
    assert not result.ready and result.reason_code == code

def test_launcher_crash_between_service_start_and_run_state_blocks_ready(tmp_path):
    health = _healthy()
    # These are synthetic stale records, never used by the readiness evaluator.
    for name in ("ready.json", "run-state.json", "secret-env.json"):
        (tmp_path / name).write_text(
            json.dumps({"status": "READY", "run_id": "old-run", "secret": "fixture"}),
            encoding="utf-8",
        )
    assert _evaluate(health).reason_code == "LIVE_WITNESS_REQUIRED"
    assert not status_without_live_witness(health, "running").ready
    assert not _evaluate(
        health, witness=_witness(health, launcher_run_id="")
    ).ready
    assert all((tmp_path / name).exists() for name in (
        "ready.json", "run-state.json", "secret-env.json",
    ))
    assert _evaluate(health, witness=_witness(health)).ready


def test_missing_or_invalid_witness_never_implies_ready():
    health = _healthy()
    assert _evaluate(health).reason_code == "LIVE_WITNESS_REQUIRED"
    assert _evaluate(health, witness={}).reason_code == "LIVE_WITNESS_SCHEMA_INVALID"
    assert _evaluate(
        health, witness=_witness(health, contract_version="old")
    ).reason_code == "LIVE_WITNESS_VERSION_MISMATCH"


def test_connected_health_without_authenticated_proof_is_not_ready():
    health = replace(_healthy(), auth_state="unverified")
    assert _evaluate(
        health, witness=_witness(health)
    ).reason_code == "TRANSPORT_NOT_AUTHENTICATED"
    health = replace(_healthy(), transport_state="backoff", last_heartbeat=None)
    assert _evaluate(
        health, witness=_witness(health)
    ).reason_code == "TRANSPORT_NOT_AUTHENTICATED"

def test_restart_replaces_persisted_health_before_config_or_secret(tmp_path):
    health_store = HealthStore(tmp_path)
    health_store.update(**{
        key: value for key, value in _healthy(instance=INSTANCE_A).to_dict().items()
        if key not in {"contract_version", "secret_source"}
    })
    original = health_store.read()
    assert original.transport_state == "connected"
    fresh = health_store.start_new_instance()
    assert fresh.service_instance_id != INSTANCE_A
    assert fresh.service_pid == os.getpid()
    assert fresh.service_started_at and fresh.auth_state == "unverified"
    assert fresh.session_epoch is None and fresh.last_heartbeat is None
    assert fresh.capability_digest is None
    assert fresh.reason_code == "STARTUP_NOT_AUTHENTICATED"
    assert not status_without_live_witness(fresh, "running").ready


def test_legacy_health_can_be_read_but_not_attested(tmp_path):
    store = HealthStore(tmp_path)
    prior = _healthy(instance=INSTANCE_A).to_dict()
    for key in ("service_instance_id", "service_pid", "service_started_at", "auth_state"):
        prior.pop(key)
    store.path.write_text(json.dumps(prior), encoding="utf-8")
    health = store.read()
    assert health.service_instance_id is None
    assert health.auth_state == "unverified"
    result = _evaluate(health, witness=None, pid=4100)
    assert not result.ready and result.reason_code == "SCM_PID_UNVERIFIED"


class _FakeTransport:
    def __init__(self, reply: str):
        self.reply = reply
        self.closed = False

    async def send(self, data):
        return None

    async def recv(self):
        return self.reply

    async def close(self):
        self.closed = True

@pytest.mark.asyncio
async def test_raw_welcome_and_heartbeat_cannot_mark_health_authenticated(tmp_path):
    health = HealthStore(tmp_path)
    health.start_new_instance()
    for frame_type in ("welcome", "heartbeat", "heartbeat_ack"):
        conn = _ObservedConnection(
            _FakeTransport(json.dumps({"type": frame_type})), health
        )
        before = health.read().transport_state
        await conn.send(json.dumps({"type": "hello"}))
        await conn.recv()
        assert health.read().auth_state == "unverified"
        assert health.read().transport_state == before
        assert health.read().last_heartbeat is None
        await conn.close()
        assert health.read().transport_state == "disconnected"


class _ScriptedConnection:
    def __init__(self, material, accepted):
        self.material = material
        self.accepted = accepted
        self.hello = None
        self.reads = 0

    async def send(self, raw):
        self.hello = json.loads(raw)

    async def recv(self):
        self.reads += 1
        if self.reads > 1:
            raise asyncio.CancelledError()
        return encode_frame(
            device_id=self.hello["device_id"],
            session_epoch=self.hello["session_epoch"],
            sequence=1, frame_type="welcome",
            payload={
                "protocol_version": FRAME_VERSION,
                "hello_nonce": self.hello["payload"]["hello_nonce"],
                "accepted": self.accepted,
            },
            token=self.material,
        )

    async def close(self):
        pass


@pytest.mark.asyncio
async def test_authentication_callback_requires_valid_welcome_nonce_and_hmac(tmp_path):
    material = TokenMaterial(1, b"k" * 32)
    observed = []
    agent = DeviceAgent(
        device_id="device-r16", token_ring=TokenRing(1, material.secret),
        capabilities=lambda: {"actions": {}},
        dispatcher=SimpleNamespace(),
        ledger=RequestLedger(tmp_path / "ledger"),
        heartbeat_seconds=0,
        session_epoch_factory=lambda: EPOCH_A,
        session_authenticated=observed.append,
    )
    with pytest.raises(ProtocolError):
        await agent.run_session(_ScriptedConnection(material, accepted=False))
    assert observed == []
    with pytest.raises(asyncio.CancelledError):
        await agent.run_session(_ScriptedConnection(material, accepted=True))
    assert observed == [EPOCH_A]

class _FakeSCM:
    """Only in-memory service simulation; no pywin32, UAC, or SCM calls."""
    def __init__(self):
        self.state = "not_installed"
        self.calls = []
        self.stop_fails = False
        self.stop_pending = False

    def install(self, state_root):
        self.calls.append("install")
        self.state = "stopped"

    def start(self):
        self.calls.append("start")
        self.state = "running"

    def stop(self):
        self.calls.append("stop")
        if self.stop_fails:
            raise RuntimeError("mock stop failed")
        self.state = "stop_pending" if self.stop_pending else "stopped"

    def remove(self):
        self.calls.append("remove")
        self.state = "not_installed"

    def restart(self):
        self.calls.append("restart")
        self.state = "running"

    def status(self):
        return self.state

def _controller(tmp_path, api):
    commands = []
    controller = WindowsServiceController(
        ConfigStore(tmp_path), api=api,
        command_runner=lambda argv, **kwargs: commands.append(list(argv)),
    )
    return controller, commands


def test_mock_production_service_auto_recovery_and_idempotent_cleanup(tmp_path):
    api = _FakeSCM()
    controller, commands = _controller(tmp_path, api)
    controller.install()
    assert len(commands) == 2
    assert commands[0][:3] == ["sc.exe", "failure", "PCNativeDeviceService"]
    assert "restart/5000/restart/15000/restart/60000" in commands[0]
    assert commands[1] == ["sc.exe", "failureflag", "PCNativeDeviceService", "1"]
    controller.start()
    assert controller.status() == "running"
    controller.stop()
    controller.stop()
    controller.uninstall()
    controller.uninstall()
    assert api.calls == ["install", "start", "stop", "remove"]
    assert controller.status() == "not_installed"


@pytest.mark.parametrize(("stop_fails", "pending"), [(True, False), (False, True)])
def test_uninstall_refuses_unconfirmed_stop(tmp_path, stop_fails, pending):
    api = _FakeSCM()
    controller, _ = _controller(tmp_path, api)
    controller.install()
    controller.start()
    api.stop_fails, api.stop_pending = stop_fails, pending
    with pytest.raises(RuntimeError):
        controller.uninstall()
    assert "remove" not in api.calls
    assert api.state in {"running", "stop_pending"}

@pytest.mark.asyncio
async def test_no_relay_auto_start_with_surviving_secret_fails_closed(tmp_path):
    from pc_remote_transport.service import DEFAULT_SECRET_NAME

    class MemorySecrets:
        def __init__(self):
            self.material = TokenMaterial(1, b"x" * 32)
            self.reads = 0

        def read(self, name):
            assert name == DEFAULT_SECRET_NAME
            self.reads += 1
            return self.material

    class AbsentRelay:
        def __init__(self):
            self.attempts = 0

        async def open(self):
            self.attempts += 1
            raise ConnectionRefusedError("mock relay/control not running")

    class RetryAgent:
        async def run_forever(self, connector, *, enabled, backoff, sleep):
            while enabled():
                try:
                    await connector.open()
                except ConnectionRefusedError:
                    await sleep(0.01)

    config = ConfigStore(tmp_path)
    config.update(ServiceConfig(
        enabled=True, endpoint="wss://relay.example.test/device",
        device_id="device-r16",
    ))
    health = HealthStore(tmp_path)
    health.update(**{
        key: value for key, value in _healthy(instance=INSTANCE_A).to_dict().items()
        if key not in {"contract_version", "secret_source"}
    })
    secrets = MemorySecrets()
    absent = AbsentRelay()
    def factory(config, material, store, health_store, secret_store):
        assert material == secrets.material
        return RuntimeBundle(
            agent=RetryAgent(), connector=_ObservedConnector(absent, health_store),
        )

    host = DeviceServiceHost(config, health, secrets, runtime_factory=factory,
                             poll_seconds=0.002)
    stop = threading.Event()
    task = asyncio.create_task(host.run(stop))
    try:
        for _ in range(300):
            snapshot = health.read()
            if absent.attempts >= 1 and snapshot.transport_state == "backoff":
                break
            await asyncio.sleep(0.005)
        snapshot = health.read()
        assert absent.attempts >= 1 and secrets.reads >= 1
        assert snapshot.service_instance_id != INSTANCE_A
        assert snapshot.service_state == "running"
        assert snapshot.auth_state == "unverified"
        assert snapshot.transport_state == "backoff"
        assert snapshot.session_epoch is None and snapshot.last_heartbeat is None
        assert not status_without_live_witness(snapshot, "running").ready
    finally:
        stop.set()
        await asyncio.wait_for(task, timeout=2)
    assert health.read().service_state == "stopped"
def test_cli_status_never_promotes_persisted_ready(tmp_path):
    config = ConfigStore(tmp_path)
    config.update(ServiceConfig(
        enabled=True, endpoint="wss://relay.example.test/device",
        device_id="device-r16",
    ))
    health = HealthStore(tmp_path)
    snapshot = _healthy(instance=INSTANCE_A)
    health.update(**{
        key: value for key, value in snapshot.to_dict().items()
        if key not in {"contract_version", "secret_source"}
    })
    for name in ("ready.json", "run-state.json", "secret-env.json"):
        (tmp_path / name).write_text('{"status":"READY"}', encoding="utf-8")
    status = _status_payload(
        SimpleNamespace(status=lambda: "running"), config, health,
    )
    assert status["readiness"]["ready"] is False
    assert status["readiness"]["reason_code"] == "LIVE_WITNESS_REQUIRED"
    assert status["observation_source"] == "persisted_health_unverified"
    assert "secret" not in json.dumps(status).lower().replace(
        '"secret_source": "<redacted>"', ""
    )

def test_versioned_rehearsal_policy_is_plan_only_and_production_remains_auto():
    from pc_remote_transport.windows_service import (
        INSTALL_POLICY_VERSION, planned_install_policy,
    )
    production = planned_install_policy()
    assert production == {
        "contract_version": INSTALL_POLICY_VERSION,
        "kind": "persistent_production_auto",
        "service_name": "PCNativeDeviceService",
        "startup": "auto",
        "recovery": "restart/5000/restart/15000/restart/60000",
        "reset_seconds": 86400,
        "failure_actions_on_non_crash": True,
        "scm_mutation_supported": True,
    }
    rehearsal = planned_install_policy(
        kind="isolated_rehearsal_demand", fixture_id="r16-fixture-0001",
    )
    assert rehearsal["contract_version"] == INSTALL_POLICY_VERSION
    assert rehearsal["startup"] == "demand"
    assert rehearsal["recovery"] == "none"
    assert rehearsal["scm_mutation_supported"] is False
    assert rehearsal["service_name"] != production["service_name"]
    for bad in (None, "", "real-production", "../unsafe", "x"):
        with pytest.raises(ValueError):
            planned_install_policy(
                kind="isolated_rehearsal_demand", fixture_id=bad,
            )
    with pytest.raises(ValueError):
        planned_install_policy(
            kind="persistent_production_auto", fixture_id="r16-fixture-0001",
        )


def test_service_runtime_epoch_binds_current_instance_without_registry_change(tmp_path):
    from pc_remote_transport.service import build_default_runtime

    class MemorySecret:
        def write(self, *args):
            raise AssertionError("no secret rotation in epoch test")

    config = ConfigStore(tmp_path)
    configured = config.update(ServiceConfig(
        enabled=True, endpoint="wss://relay.example.test/device",
        device_id="device-r16",
    ))
    health = HealthStore(tmp_path)
    identity = health.start_new_instance()
    bundle = build_default_runtime(
        configured, TokenMaterial(1, b"m" * 32),
        config, health, MemorySecret(),
    )
    epoch = bundle.agent.session_epoch_factory()
    assert epoch.startswith(identity.service_instance_id + ":")
    assert health.read().session_epoch == epoch
    assert health.read().auth_state == "unverified"
    assert len(epoch) < 160


def test_failed_uninstall_never_deletes_credentials_or_disables_config(
    tmp_path, monkeypatch, capsys,
):
    import pc_remote_transport.service_cli as cli

    store = ConfigStore(tmp_path)
    store.update(ServiceConfig(
        enabled=True, endpoint="wss://relay.example.test/device",
        device_id="device-r16",
    ))
    deleted = []
    class FakeSecrets:
        def delete(self, name):
            deleted.append(name)

    class FailController:
        def uninstall(self):
            raise RuntimeError("SCM_STOP_NOT_CONFIRMED")

    monkeypatch.setattr(cli, "_require_windows", lambda: None)
    monkeypatch.setattr(cli, "ConfigStore", lambda: store)
    monkeypatch.setattr(cli, "WindowsLsaSecretStore", lambda: FakeSecrets())
    monkeypatch.setattr(cli, "WindowsServiceController", lambda _: FailController())
    assert cli.main(["uninstall"]) == 2
    assert deleted == []
    assert store.load().enabled is True
    assert "SCM_STOP_NOT_CONFIRMED" in capsys.readouterr().err

def test_uninstall_unknown_remove_defers_cleanup_and_recovers_idempotently(tmp_path):
    class PendingDeleteSCM(_FakeSCM):
        def remove(self):
            self.calls.append("remove")
            # Mock SCM marked-for-delete but has not proven 1060/not_installed.
            self.state = "stopped"

    api = PendingDeleteSCM()
    controller, _ = _controller(tmp_path, api)
    controller.install()
    with pytest.raises(RuntimeError, match="SCM_REMOVE_NOT_CONFIRMED"):
        controller.uninstall()
    assert api.calls.count("remove") == 1
    api.state = "not_installed"
    controller.uninstall()
    controller.stop()
    assert api.calls.count("remove") == 1
    assert api.state == "not_installed"

def test_disabled_config_and_unbound_instance_fail_even_with_live_witness():
    health = _healthy()
    disabled = replace(health, enabled=False)
    assert _evaluate(
        disabled, witness=_witness(disabled),
    ).reason_code == "SERVICE_CONFIG_NOT_ENABLED"
    no_revision = replace(health, config_revision=None)
    assert _evaluate(
        no_revision, witness=_witness(no_revision),
    ).reason_code == "SERVICE_CONFIG_NOT_ENABLED"
    invalid_instance = replace(
        health, service_instance_id="NOT-A-SERVICE-UUID",
    )
    assert _evaluate(
        invalid_instance, witness=_witness(invalid_instance),
    ).reason_code == "SERVICE_INSTANCE_UNVERIFIED"
