from __future__ import annotations

import asyncio
import base64
import io
import json
import sys
from pathlib import Path
import threading
import types
from dataclasses import replace

import pytest

from pc_executor.executor import Executor
from pc_remote_transport.agent import DeviceAgent, DispatchResult
from pc_remote_transport.executor_adapter import ExecutorRemoteDispatcher
from pc_remote_transport.ledger import RequestLedger
from pc_remote_transport.protocol import (
    ProtocolError,
    StaleEpochError,
    TokenMaterial,
    TokenRing,
    decode_frame,
    encode_frame,
    digest_json,
    request_fingerprint,
)
from pc_remote_transport.service import (
    DEFAULT_SECRET_NAME,
    ConfigStore,
    DeviceServiceHost,
    HealthStore,
    MissingSecretError,
    RuntimeBundle,
    ServiceConfig,
    ServiceDeviceAgent,
    build_default_runtime,
)
import pc_remote_transport.service_cli as service_cli_module
from pc_remote_transport.service_cli import _read_secret_input, _status_payload, main as service_cli_main
from pc_remote_transport.windows_service import (
    WindowsLsaSecretStore,
    WindowsServiceController,
    _Win32ServiceApi,
    _bound_service_store,
    _log_service_event,
    _run_service_host,
    _stage_isolated_service_host,
)


def test_embedded_scm_runner_uses_per_instance_selector_in_a_worker_thread(monkeypatch) -> None:
    """Regression for the R6 event-loop traceback from real SCM EventRecordID 9555."""
    observed: list[tuple[asyncio.AbstractEventLoop, bool]] = []
    errors: list[BaseException] = []
    stop = threading.Event()

    class ProbeHost:
        async def run(self, received_stop: threading.Event) -> None:
            loop = asyncio.get_running_loop()
            observed.append((loop, received_stop is stop))
            await asyncio.sleep(0)

    def forbid_default_factory() -> None:
        raise AssertionError("SCM runner must not construct the default Windows Proactor loop")

    # Runner(loop_factory=SelectorEventLoop) must not rely on the default
    # process-wide event loop policy or asyncio.new_event_loop.
    monkeypatch.setattr(asyncio, "new_event_loop", forbid_default_factory)

    def worker() -> None:
        try:
            _run_service_host(ProbeHost(), stop)
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=worker, name="simulated-pywin32-SvcDoRun")
    thread.start()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert errors == []
    assert len(observed) == 1
    loop, correct_stop = observed[0]
    assert isinstance(loop, asyncio.SelectorEventLoop)
    assert correct_stop is True
    assert loop.is_closed()


@pytest.mark.skipif(sys.platform != "win32", reason="pywin32 service exists on Windows only")
def test_real_windows_svc_do_run_calls_scoped_selector_runner() -> None:
    """Prevent accidental reintroduction of asyncio.run into the SCM thread."""
    import pc_remote_transport.windows_service as module

    code = module.PCNativeDeviceService.SvcDoRun.__code__
    assert "_run_service_host" in code.co_names
    assert "run" not in code.co_names


class MemorySecrets:
    def __init__(self) -> None:
        self.values: dict[str, TokenMaterial] = {}

    def read(self, target: str) -> TokenMaterial:
        if target not in self.values:
            raise MissingSecretError("missing")
        return self.values[target]

    def write(self, target: str, material: TokenMaterial) -> None:
        self.values[target] = material

    def delete(self, target: str) -> None:
        self.values.pop(target, None)


class NoopDispatcher:
    async def dispatch(self, *, request_version: str, request_id: str, body: dict):
        return DispatchResult(payload={"ok": True})


class BlockingAgent:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.cancelled = False
        self.stopped = False

    async def run_forever(self, connector, *, enabled, backoff, sleep) -> None:
        self.started.set()
        try:
            while enabled():
                await asyncio.sleep(0.005)
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        finally:
            self.stopped = True


class FakeApi:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.state = "not_installed"

    def install(self, state_root: Path) -> None:
        self.calls.append("install")
        self.state_root = Path(state_root)
        self.state = "stopped"

    def start(self) -> None:
        self.calls.append("start")
        self.state = "running"

    def stop(self) -> None:
        self.calls.append("stop")
        self.state = "stopped"

    def restart(self) -> None:
        self.calls.append("restart")
        self.state = "running"

    def remove(self) -> None:
        self.calls.append("remove")
        self.state = "not_installed"

    def status(self) -> str:
        return self.state


def enabled_config() -> ServiceConfig:
    return ServiceConfig(
        enabled=True,
        endpoint="wss://relay.example.test/device",
        device_id="device-service-1",
    )


def test_default_config_is_disabled_and_non_secret(tmp_path) -> None:
    store = ConfigStore(tmp_path)
    config = store.initialize()
    assert config.enabled is False
    raw = store.path.read_text(encoding="utf-8")
    assert "token_b64" not in raw
    assert "token_secret" not in raw
    assert DEFAULT_SECRET_NAME not in raw


def test_protected_state_root_is_rejected_without_access() -> None:
    with pytest.raises(ProtocolError, match="protected path"):
        ConfigStore(r"E:\manhwa")
    with pytest.raises(ProtocolError, match="protected path"):
        ConfigStore(r"e:/MANHWA/service")


def test_invalid_endpoint_update_rolls_back_atomically(tmp_path) -> None:
    store = ConfigStore(tmp_path)
    good = store.update(enabled_config())
    before = store.path.read_bytes()
    with pytest.raises(ProtocolError, match="endpoint"):
        store.update(replace(good, endpoint="ws://relay.example.test/device"))
    with pytest.raises(ProtocolError, match="must not contain credentials"):
        store.update(replace(good, endpoint="wss://user:secret@relay.example.test/device?token=x"))
    assert store.path.read_bytes() == before
    assert store.load() == good


def test_loopback_ws_requires_explicit_opt_in(tmp_path) -> None:
    store = ConfigStore(tmp_path)
    with pytest.raises(ProtocolError):
        store.update(
            ServiceConfig(
                enabled=True,
                endpoint="ws://127.0.0.1:8765/device",
                device_id="device-service-1",
            )
        )
    allowed = ServiceConfig(
        enabled=True,
        endpoint="ws://127.0.0.1:8765/device",
        device_id="device-service-1",
        allow_insecure_loopback=True,
    )
    assert store.update(allowed) == allowed


@pytest.mark.asyncio
async def test_missing_secret_blocks_transport_without_crashing_service(tmp_path) -> None:
    store = ConfigStore(tmp_path)
    store.update(enabled_config())
    health = HealthStore(tmp_path)
    secrets = MemorySecrets()
    factory_called = False

    def factory(*args):
        nonlocal factory_called
        factory_called = True
        raise AssertionError("runtime must not be built without a credential")

    stop = threading.Event()
    host = DeviceServiceHost(store, health, secrets, runtime_factory=factory, poll_seconds=0.01)
    task = asyncio.create_task(host.run(stop))
    for _ in range(100):
        await asyncio.sleep(0.005)
        if health.read().reason_code == "MISSING_SECRET":
            break
    snapshot = health.read()
    assert snapshot.service_state == "running"
    assert snapshot.transport_state == "blocked"
    assert snapshot.reason_code == "MISSING_SECRET"
    assert factory_called is False
    stop.set()
    await asyncio.wait_for(task, timeout=1)
    assert health.read().service_state == "stopped"


@pytest.mark.asyncio
async def test_kill_switch_cancels_active_transport_and_leaves_service_idle(tmp_path) -> None:
    store = ConfigStore(tmp_path)
    config = store.update(enabled_config())
    health = HealthStore(tmp_path)
    secrets = MemorySecrets()
    secrets.write(DEFAULT_SECRET_NAME, TokenMaterial(1, b"k" * 32))
    fake_agent = BlockingAgent()

    def factory(*args):
        return RuntimeBundle(agent=fake_agent, connector=object())

    stop = threading.Event()
    host = DeviceServiceHost(store, health, secrets, runtime_factory=factory, poll_seconds=0.01)
    task = asyncio.create_task(host.run(stop))
    await asyncio.wait_for(fake_agent.started.wait(), timeout=1)
    store.update(replace(config, enabled=False))

    for _ in range(100):
        await asyncio.sleep(0.005)
        if health.read().transport_state == "disabled":
            break
    assert health.read().enabled is False
    assert health.read().transport_state == "disabled"
    assert fake_agent.stopped is True

    stop.set()
    await asyncio.wait_for(task, timeout=1)


@pytest.mark.asyncio
async def test_service_restart_replaces_session_epoch(tmp_path) -> None:
    store = ConfigStore(tmp_path)
    config = store.update(enabled_config())
    health = HealthStore(tmp_path)
    secrets = MemorySecrets()
    secrets.write(DEFAULT_SECRET_NAME, TokenMaterial(1, b"r" * 32))
    counter = 0

    def factory(config, material, config_store, health_store, secret_store):
        nonlocal counter
        counter += 1
        health_store.update(session_epoch=f"epoch-restart-{counter:04d}")
        return RuntimeBundle(agent=BlockingAgent(), connector=object())

    async def run_once() -> str:
        stop = threading.Event()
        host = DeviceServiceHost(store, health, secrets, runtime_factory=factory, poll_seconds=0.01)
        task = asyncio.create_task(host.run(stop))
        for _ in range(100):
            await asyncio.sleep(0.005)
            epoch = health.read().session_epoch
            if epoch and epoch.startswith("epoch-restart"):
                break
        epoch = health.read().session_epoch
        stop.set()
        await asyncio.wait_for(task, timeout=1)
        assert epoch is not None
        return epoch

    first = await run_once()
    second = await run_once()
    assert first != second


def test_stale_epoch_is_rejected() -> None:
    token = TokenMaterial(1, b"s" * 32)
    raw = encode_frame(
        device_id="device-service-1",
        session_epoch="epoch-old-0001",
        sequence=1,
        frame_type="heartbeat",
        payload={},
        token=token,
    )
    with pytest.raises(StaleEpochError):
        decode_frame(
            raw,
            token=token,
            expected_device_id="device-service-1",
            expected_session_epoch="epoch-new-0002",
        )


@pytest.mark.asyncio
async def test_token_rotation_is_persisted_before_ack(tmp_path) -> None:
    old = TokenMaterial(1, b"a" * 32)
    new_secret = b"b" * 32
    ring = TokenRing(old.generation, old.secret)
    secrets = MemorySecrets()
    sent = []

    def persist(generation: int, secret: bytes) -> None:
        secrets.write("target", TokenMaterial(generation, secret))

    agent = ServiceDeviceAgent(
        device_id="device-service-1",
        token_ring=ring,
        capabilities=lambda: {},
        dispatcher=NoopDispatcher(),
        ledger=RequestLedger(tmp_path / "ledger"),
        heartbeat_seconds=15,
        rotation_persist=persist,
    )

    async def send(frame_type: str, payload: dict) -> None:
        sent.append((frame_type, payload))

    await agent._handle_token_rotation(
        {
            "new_generation": 2,
            "new_token_b64": base64.b64encode(new_secret).decode("ascii"),
        },
        send,
    )
    assert secrets.read("target") == TokenMaterial(2, new_secret)
    assert ring.current == TokenMaterial(2, new_secret)
    assert sent == [("token.rotated", {"generation": 2})]


def test_restart_and_crash_recovery_are_wired_to_scm(tmp_path) -> None:
    store = ConfigStore(tmp_path)
    api = FakeApi()
    commands = []

    def runner(command, **kwargs):
        commands.append((command, kwargs))
        return object()

    controller = WindowsServiceController(store, api=api, command_runner=runner)
    controller.install()
    assert api.calls == ["install"]
    assert api.state_root == tmp_path
    assert commands[0][0][:3] == ["sc.exe", "failure", "PCNativeDeviceService"]
    assert "restart/5000/restart/15000/restart/60000" in commands[0][0]
    assert commands[1][0] == ["sc.exe", "failureflag", "PCNativeDeviceService", "1"]

    controller.start()
    controller.restart()
    controller.stop()
    assert api.calls[-3:] == ["start", "restart", "stop"]


def test_health_and_status_redact_secret_source(tmp_path) -> None:
    store = ConfigStore(tmp_path)
    config = replace(
        ServiceConfig(),
        endpoint="wss://relay.example.test/device",
        device_id="device-service-1",
    )
    store.update(config)
    health = HealthStore(tmp_path)
    health.update(
        service_state="running",
        enabled=False,
        device_id=config.device_id,
        session_epoch="epoch-redact-0001",
        transport_state="disabled",
        capability_digest="abc123",
    )
    raw_health = health.path.read_text(encoding="utf-8")
    assert DEFAULT_SECRET_NAME not in raw_health

    class FakeController:
        def status(self):
            return "running"

    payload = _status_payload(FakeController(), store, health)
    rendered = json.dumps(payload, sort_keys=True)
    assert DEFAULT_SECRET_NAME not in rendered
    assert payload["secret_source"] == "<redacted>"


class FakeLsaModule:
    POLICY_GET_PRIVATE_INFORMATION = 4
    POLICY_CREATE_SECRET = 32

    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.accesses: list[int] = []

    def LsaOpenPolicy(self, system_name, access):
        assert system_name is None
        self.accesses.append(access)
        return object()

    def LsaRetrievePrivateData(self, policy, name):
        if name not in self.values:
            raise OSError(2, "not found")
        return self.values[name]

    def LsaStorePrivateData(self, policy, name, value):
        if value is None:
            self.values.pop(name, None)
        else:
            self.values[name] = value


def test_lsa_secret_store_round_trip_uses_machine_private_data(monkeypatch) -> None:
    fake = FakeLsaModule()
    secrets = WindowsLsaSecretStore()
    monkeypatch.setattr(secrets, "_module", lambda: fake)
    material = TokenMaterial(7, b"z" * 32)

    secrets.write("L$test-service-secret", material)
    assert secrets.read("L$test-service-secret") == material
    assert fake.accesses == [
        fake.POLICY_CREATE_SECRET,
        fake.POLICY_GET_PRIVATE_INFORMATION,
    ]

    secrets.delete("L$test-service-secret")
    with pytest.raises(MissingSecretError):
        secrets.read("L$test-service-secret")


@pytest.mark.parametrize("missing_code", [2, 1168, 0xC0000034, -1073741772])
def test_lsa_secret_store_accepts_win32_and_ntstatus_missing_codes(monkeypatch, missing_code) -> None:
    class MissingCodeLsa(FakeLsaModule):
        def LsaRetrievePrivateData(self, policy, name):
            raise OSError(missing_code, "not found")

        def LsaStorePrivateData(self, policy, name, value):
            if value is None:
                raise OSError(missing_code, "not found")
            super().LsaStorePrivateData(policy, name, value)

    fake = MissingCodeLsa()
    secrets = WindowsLsaSecretStore()
    monkeypatch.setattr(secrets, "_module", lambda: fake)

    with pytest.raises(MissingSecretError):
        secrets.read("L$test-service-secret")
    secrets.delete("L$test-service-secret")


@pytest.mark.asyncio
async def test_stale_rotation_never_overwrites_persisted_secret(tmp_path) -> None:
    old = TokenMaterial(1, b"m" * 32)
    persisted: list[TokenMaterial] = []
    sent = []

    agent = ServiceDeviceAgent(
        device_id="device-service-1",
        token_ring=TokenRing(old.generation, old.secret),
        capabilities=lambda: {},
        dispatcher=NoopDispatcher(),
        ledger=RequestLedger(tmp_path / "ledger-stale-rotation"),
        rotation_persist=lambda generation, secret: persisted.append(TokenMaterial(generation, secret)),
    )

    async def send(frame_type: str, payload: dict) -> None:
        sent.append((frame_type, payload))

    with pytest.raises(ProtocolError, match="advance by exactly one"):
        await agent._handle_token_rotation(
            {
                "new_generation": 3,
                "new_token_b64": base64.b64encode(b"n" * 32).decode("ascii"),
            },
            send,
        )
    assert persisted == []
    assert sent == []
    assert agent.token_ring.current == old


@pytest.mark.asyncio
async def test_active_transport_config_read_failure_cancels_cleanly(tmp_path) -> None:
    store = ConfigStore(tmp_path)
    config = store.update(enabled_config())
    health = HealthStore(tmp_path)
    secrets = MemorySecrets()
    secrets.write(DEFAULT_SECRET_NAME, TokenMaterial(1, b"q" * 32))
    fake_agent = BlockingAgent()

    def factory(*args):
        return RuntimeBundle(agent=fake_agent, connector=object())

    stop = threading.Event()
    host = DeviceServiceHost(store, health, secrets, runtime_factory=factory, poll_seconds=0.01)
    task = asyncio.create_task(host.run(stop))
    await asyncio.wait_for(fake_agent.started.wait(), timeout=1)

    store.path.write_text("{not valid json", encoding="utf-8")
    for _ in range(100):
        await asyncio.sleep(0.005)
        if fake_agent.stopped and health.read().reason_code == "CONFIG_INVALID":
            break

    assert task.done() is False
    assert fake_agent.stopped is True
    assert health.read().transport_state == "blocked"
    assert health.read().reason_code == "CONFIG_INVALID"
    stop.set()
    await asyncio.wait_for(task, timeout=1)


def test_controller_uninstall_stops_and_removes_running_service(tmp_path) -> None:
    store = ConfigStore(tmp_path)
    api = FakeApi()
    controller = WindowsServiceController(store, api=api, command_runner=lambda *args, **kwargs: object())
    controller.install()
    controller.start()
    controller.uninstall()
    assert api.calls[-2:] == ["stop", "remove"]
    assert controller.status() == "not_installed"


def test_service_event_log_uses_fixed_redacted_messages(monkeypatch) -> None:
    info: list[str] = []
    errors: list[str] = []
    fake = types.SimpleNamespace(
        LogInfoMsg=lambda message: info.append(message),
        LogErrorMsg=lambda message: errors.append(message),
    )
    monkeypatch.setitem(sys.modules, "servicemanager", fake)

    _log_service_event("starting")
    _log_service_event("crashed")
    _log_service_event("stopped")

    rendered = "\n".join(info + errors)
    assert info == [
        "PC native device service starting",
        "PC native device service stopped",
    ]
    assert errors == ["PC native device service crashed"]
    assert "token" not in rendered.lower()
    assert DEFAULT_SECRET_NAME not in rendered


def test_secret_input_uses_redirected_stdin_without_getpass(monkeypatch) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("c2VjcmV0\n"))
    monkeypatch.setattr(service_cli_module.getpass, "getpass", lambda prompt: (_ for _ in ()).throw(AssertionError("getpass must not run for redirected stdin")))
    assert _read_secret_input() == "c2VjcmV0"


def test_secret_input_uses_getpass_for_interactive_tty(monkeypatch) -> None:
    class InteractiveInput(io.StringIO):
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(sys, "stdin", InteractiveInput())
    monkeypatch.setattr(service_cli_module.getpass, "getpass", lambda prompt: "c2VjcmV0")
    assert _read_secret_input() == "c2VjcmV0"


def test_secret_input_rejects_empty_redirected_stdin(monkeypatch) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    with pytest.raises(ProtocolError, match="token input is empty"):
        _read_secret_input()


def test_cli_validation_error_redacts_endpoint_credentials(tmp_path, monkeypatch, capsys) -> None:
    marker = "DO-NOT-LOG-THIS-SECRET"
    monkeypatch.setenv("PC_NATIVE_DEVICE_SERVICE_HOME", str(tmp_path))

    result = service_cli_main(
        [
            "configure",
            "--endpoint",
            f"wss://user:{marker}@relay.example.test/device",
            "--device-id",
            "device-service-1",
        ]
    )

    captured = capsys.readouterr()
    assert result == 2
    assert marker not in captured.out
    assert marker not in captured.err


def test_service_config_cannot_override_device_agent_module_or_executable() -> None:
    base = ServiceConfig().to_dict()
    for key, value in (
        ("device_agent_module", "attacker.module"),
        ("device_agent_executable", r"C:\temp\replacement.exe"),
    ):
        raw = dict(base)
        raw[key] = value
        with pytest.raises(ProtocolError, match="config keys mismatch"):
            ServiceConfig.from_dict(raw)


def test_service_runtime_is_bound_to_current_full_stack(tmp_path) -> None:
    import pc_remote_transport.service as service_module

    assert issubclass(ServiceDeviceAgent, DeviceAgent)
    assert service_module.DeviceAgent is DeviceAgent
    assert service_module.Executor is Executor
    assert service_module.ExecutorRemoteDispatcher is ExecutorRemoteDispatcher

    store = ConfigStore(tmp_path)
    config = store.update(enabled_config())
    health = HealthStore(tmp_path)
    secrets = MemorySecrets()
    material = TokenMaterial(1, b"v" * 32)
    secrets.write(DEFAULT_SECRET_NAME, material)

    bundle = build_default_runtime(config, material, store, health, secrets)

    assert isinstance(bundle.agent, DeviceAgent)
    assert isinstance(bundle.agent.dispatcher, ExecutorRemoteDispatcher)
    assert isinstance(bundle.agent.dispatcher.executor, Executor)
    assert bundle.agent.dispatcher.executor.outcome_journal is not None
    assert bundle.agent.device_id == config.device_id

    manifest = bundle.agent.capabilities()
    snapshot = health.read()
    assert snapshot.capability_digest == digest_json(manifest)

    epoch = bundle.agent.session_epoch_factory()
    snapshot = health.read()
    assert snapshot.session_epoch == epoch
    assert snapshot.last_heartbeat is None


@pytest.mark.asyncio
async def test_service_restart_reconciles_uncertain_side_effect_without_replay(tmp_path) -> None:
    store = ConfigStore(tmp_path)
    config = store.update(enabled_config())
    health = HealthStore(tmp_path)
    secrets = MemorySecrets()
    material = TokenMaterial(1, b"u" * 32)
    secrets.write(DEFAULT_SECRET_NAME, material)

    first = build_default_runtime(config, material, store, health, secrets)
    request = {
        "request_id": "service-uncertain-1",
        "request_version": "pc.native.control.v1",
        "delivery_id": "delivery-original",
        "semantics": "side_effecting",
        "body": {
            "contract_version": "pc.native.control.v1",
            "session_id": "service-session-1",
            "request_id": "service-uncertain-1",
            "tool": "file.write",
            "arguments": {"path": "C:\\Temp\\service-proof.txt", "text": "never-dispatched"},
        },
    }
    first.agent.ledger.mark_dispatch_started(
        request_id=request["request_id"],
        request_version=request["request_version"],
        fingerprint=request_fingerprint(request),
        semantics=request["semantics"],
    )

    restarted = build_default_runtime(config, material, store, health, secrets)
    sent: list[tuple[str, dict]] = []

    async def send(frame_type: str, payload: dict) -> None:
        sent.append((frame_type, payload))

    await restarted.agent._handle_request(request, send)

    assert len(sent) == 1
    frame_type, payload = sent[0]
    assert frame_type == "reconcile_required"
    assert payload["request_id"] == request["request_id"]
    assert payload["status"] == "UNKNOWN_RECONCILE"
    assert payload["automatic_replay"] is False
    record = restarted.agent.ledger.load(request["request_id"])
    assert record is not None
    assert record.status == "reconcile_required"

def _fake_isolated_host_tree(root: Path) -> tuple[Path, Path, Path, dict[str, bytes]]:
    tag = f"{sys.version_info.major}{sys.version_info.minor}"
    base = root / "base"
    venv = root / "venv"
    package_root = venv / "Lib" / "site-packages"
    (package_root / "win32").mkdir(parents=True)
    (package_root / "pywin32_system32").mkdir()
    (base / "Lib" / "encodings").mkdir(parents=True)
    (base / "DLLs").mkdir()
    (base / "Lib" / "encodings" / "__init__.py").write_text("# fixture", encoding="utf-8")
    (package_root / "win32" / "servicemanager.pyd").write_bytes(b"fake-servicemanager")
    (venv / "pyvenv.cfg").write_text("home = isolated-test-base\n", encoding="utf-8")
    binaries = {
        "pythonservice.exe": b"service-host-from-venv",
        f"python{tag}.dll": b"base-interpreter-dll",
        f"pywintypes{tag}.dll": b"venv-pywintypes-dll",
        f"pythoncom{tag}.dll": b"venv-pythoncom-dll",
    }
    (package_root / "win32" / "pythonservice.exe").write_bytes(binaries["pythonservice.exe"])
    (base / f"python{tag}.dll").write_bytes(binaries[f"python{tag}.dll"])
    for name in (f"pywintypes{tag}.dll", f"pythoncom{tag}.dll"):
        (package_root / "pywin32_system32" / name).write_bytes(binaries[name])
    return venv, base, package_root, binaries

def test_isolated_service_host_stages_verified_local_dlls_without_global_mutation(tmp_path) -> None:
    venv, base, packages, binaries = _fake_isolated_host_tree(tmp_path)
    base_before = {p.relative_to(base).as_posix(): p.read_bytes() for p in base.rglob("*") if p.is_file()}
    host = _stage_isolated_service_host(venv, base, packages)
    assert host == venv / "pythonservice.exe"
    assert (venv / "pythonservice._pth").read_text(encoding="utf-8").splitlines() == [
        str(base / "Lib"), str(base / "DLLs"), ".",
        r"Lib\site-packages", r"Lib\site-packages\win32",
        r"Lib\site-packages\win32\lib", r"Lib\site-packages\Pythonwin",
        "import site",
    ]
    for name, expected in binaries.items():
        assert (venv / name).read_bytes() == expected
    assert {p.relative_to(base).as_posix(): p.read_bytes() for p in base.rglob("*") if p.is_file()} == base_before
    assert _stage_isolated_service_host(venv, base, packages) == host
    assert not list(venv.glob("*.native-staging"))


def test_isolated_service_host_fails_closed_on_collisions_and_missing_files(tmp_path) -> None:
    venv, base, packages, binaries = _fake_isolated_host_tree(tmp_path)
    (venv / "pythonservice.exe").write_bytes(b"untrusted")
    with pytest.raises(RuntimeError, match="binary collision"):
        _stage_isolated_service_host(venv, base, packages)
    (venv / "pythonservice.exe").unlink()
    (packages / "pywin32_system32" / f"pythoncom{sys.version_info.major}{sys.version_info.minor}.dll").unlink()
    with pytest.raises(RuntimeError, match="dependency missing"):
        _stage_isolated_service_host(venv, base, packages)
    (venv / "pyvenv.cfg").unlink()
    with pytest.raises(RuntimeError, match="isolated Python venv"):
        _stage_isolated_service_host(venv, base, packages)

def test_bound_scm_state_root_requires_an_explicit_absolute_path(tmp_path) -> None:
    assert _bound_service_store(str(tmp_path)).root == tmp_path
    for bad in (None, "", "relative-state-root"):
        with pytest.raises(RuntimeError, match="state-root binding"):
            _bound_service_store(bad)


def test_scm_install_uses_explicit_venv_host_and_binds_service_state(tmp_path, monkeypatch) -> None:
    venv, base, packages, binaries = _fake_isolated_host_tree(tmp_path)
    calls = []
    fake_service = types.SimpleNamespace(
        __file__=str(packages / "win32" / "win32service.pyd"), SERVICE_AUTO_START=2
    )
    fake_util = types.SimpleNamespace(
        InstallService=lambda **kwargs: calls.append(("install", kwargs)),
        SetServiceCustomOption=lambda *args: calls.append(("state", args)),
        RemoveService=lambda *args: calls.append(("remove", args)),
    )
    monkeypatch.setitem(sys.modules, "win32service", fake_service)
    monkeypatch.setitem(sys.modules, "win32serviceutil", fake_util)
    monkeypatch.setattr(sys, "prefix", str(venv))
    monkeypatch.setattr(sys, "base_prefix", str(base))
    state = tmp_path / "state"
    state.mkdir()
    _Win32ServiceApi().install(state)
    assert calls[0][1]["exeName"] == str(venv / "pythonservice.exe")
    assert calls[1] == ("state", ("PCNativeDeviceService", "StateRoot", str(state)))
    assert all(event[0] != "remove" for event in calls)

def test_scm_state_binding_failure_removes_new_service(tmp_path, monkeypatch) -> None:
    venv, base, packages, _ = _fake_isolated_host_tree(tmp_path)
    calls = []
    fake_service = types.SimpleNamespace(
        __file__=str(packages / "win32" / "win32service.pyd"), SERVICE_AUTO_START=2
    )
    def reject_state(*args):
        raise PermissionError("private registry location")
    fake_util = types.SimpleNamespace(
        InstallService=lambda **kwargs: calls.append("install"),
        SetServiceCustomOption=reject_state,
        RemoveService=lambda *args: calls.append("remove"),
    )
    monkeypatch.setitem(sys.modules, "win32service", fake_service)
    monkeypatch.setitem(sys.modules, "win32serviceutil", fake_util)
    monkeypatch.setattr(sys, "prefix", str(venv))
    monkeypatch.setattr(sys, "base_prefix", str(base))
    with pytest.raises(RuntimeError, match="state-root binding failed"):
        _Win32ServiceApi().install(tmp_path)
    assert calls == ["install", "remove"]


def test_scm_start_failure_reports_only_numeric_error(monkeypatch) -> None:
    def fail_start(name):
        raise OSError(1053, "SENSITIVE-PRIVATE-PATH")
    monkeypatch.setitem(sys.modules, "win32serviceutil",
                        types.SimpleNamespace(StartService=fail_start))
    with pytest.raises(RuntimeError, match="winerror=1053") as exc:
        _Win32ServiceApi().start()
    assert "SENSITIVE-PRIVATE-PATH" not in str(exc.value)

def test_service_host_path_manifest_collisions_fail_before_copy(tmp_path) -> None:
    venv, base, packages, _ = _fake_isolated_host_tree(tmp_path)
    pth = venv / "pythonservice._pth"
    pth.write_text("C:\\untrusted\\modules\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="path manifest collision"):
        _stage_isolated_service_host(venv, base, packages)
    assert not (venv / "pythonservice.exe").exists()
    pth.unlink()
    (packages / "win32" / "servicemanager.pyd").unlink()
    with pytest.raises(RuntimeError, match="servicemanager is unavailable"):
        _stage_isolated_service_host(venv, base, packages)
    assert not (venv / "pythonservice.exe").exists()

@pytest.mark.skipif(sys.platform != "win32", reason="real pywin32 service bootstrap needs Windows")
def test_real_windows_service_host_imports_servicemanager_without_scm_install(tmp_path) -> None:
    import shutil
    import subprocess
    import win32service

    tag = f"{sys.version_info.major}{sys.version_info.minor}"
    source = Path(win32service.__file__).resolve().parent.parent
    venv = tmp_path / "venv"
    site = venv / "Lib" / "site-packages"
    (site / "win32").mkdir(parents=True)
    (site / "pywin32_system32").mkdir()
    (venv / "pyvenv.cfg").write_text(
        f"home = {sys.base_prefix}\n", encoding="utf-8"
    )
    for name in ("pythonservice.exe", "servicemanager.pyd"):
        shutil.copy2(source / "win32" / name, site / "win32" / name)
    for name in (f"pywintypes{tag}.dll", f"pythoncom{tag}.dll"):
        shutil.copy2(source / "pywin32_system32" / name,
                     site / "pywin32_system32" / name)

    host = _stage_isolated_service_host(venv, Path(sys.base_prefix), site)
    assert (venv / "pythonservice._pth").is_file()
    result = subprocess.run(
        [str(host), "-debug", "PCNativeBootstrapProbeNotInstalled"],
        capture_output=True, timeout=10, check=False,
    )
    def decode(raw: bytes) -> str:
        if not raw:
            return ""
        return raw.decode(
            "utf-16-le" if raw.count(b"\x00") > len(raw) // 8 else "utf-8",
            errors="replace",
        )

    output = decode(result.stdout) + "\n" + decode(result.stderr)
    assert "PythonService was unable to locate the service manager" not in output
    assert "0xC00000F4" in output or "PythonClass" in output, output
    assert _stage_isolated_service_host(venv, Path(sys.base_prefix), site) == host
