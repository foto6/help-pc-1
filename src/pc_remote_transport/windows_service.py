from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Callable

from .protocol import TokenMaterial
from .service import (
    ConfigStore,
    DeviceServiceHost,
    HealthStore,
    MissingSecretError,
    decode_token_material,
    encode_token_material,
)

SERVICE_NAME = "PCNativeDeviceService"
SERVICE_DISPLAY_NAME = "PC Native Device Service"
SERVICE_DESCRIPTION = "Authenticated outbound native PC device transport"
INSTALL_POLICY_VERSION = "pc.native.windows_service.install_policy.v1"


def planned_install_policy(
    *, kind: str = "persistent_production_auto", fixture_id: str | None = None,
) -> dict[str, Any]:
    """Pure SCM policy plan; this function never installs or changes a service.

    Rehearsals use a separately named, demand-start fake/isolated fixture.
    The production installer remains AUTO_START and is never switched silently.
    """
    if kind == "persistent_production_auto" and fixture_id is None:
        return {
            "contract_version": INSTALL_POLICY_VERSION,
            "kind": kind,
            "service_name": SERVICE_NAME,
            "startup": "auto",
            "recovery": "restart/5000/restart/15000/restart/60000",
            "reset_seconds": 86400,
            "failure_actions_on_non_crash": True,
            "scm_mutation_supported": True,
        }
    if kind == "isolated_rehearsal_demand":
        if (
            not isinstance(fixture_id, str)
            or re.fullmatch(r"[a-z0-9-]{8,32}", fixture_id) is None
            or "production" in fixture_id
            or fixture_id.startswith("pcnative")
        ):
            raise ValueError("isolated rehearsal requires a valid explicit fixture_id")
        return {
            "contract_version": INSTALL_POLICY_VERSION,
            "kind": kind,
            "service_name": f"PCNativeR16Fixture-{fixture_id}",
            "startup": "demand",
            "recovery": "none",
            "reset_seconds": 0,
            "failure_actions_on_non_crash": False,
            "scm_mutation_supported": False,
        }
    raise ValueError("unsupported or ambiguous Windows service install policy")
_SERVICE_EVENTS = {
    "starting": ("info", "PC native device service starting"),
    "crashed": ("error", "PC native device service crashed"),
    "stopped": ("info", "PC native device service stopped"),
}


def _log_service_event(event: str) -> None:
    level, message = _SERVICE_EVENTS[event]
    import servicemanager

    if level == "error":
        servicemanager.LogErrorMsg(message)
    else:
        servicemanager.LogInfoMsg(message)


class WindowsLsaSecretStore:
    _MISSING_SECRET_CODES = {2, 1168, 0xC0000034, -1073741772}

    def _module(self):
        try:
            import win32security
        except ImportError as exc:
            raise RuntimeError("pywin32 is required for Windows LSA private data") from exc
        return win32security

    @staticmethod
    def _error_code(exc: Exception) -> int | None:
        code = getattr(exc, "winerror", None)
        if code is None and getattr(exc, "args", None):
            code = exc.args[0]
        return code if isinstance(code, int) else None

    def read(self, name: str) -> TokenMaterial:
        win32security = self._module()
        try:
            policy = win32security.LsaOpenPolicy(
                None,
                win32security.POLICY_GET_PRIVATE_INFORMATION,
            )
            payload = win32security.LsaRetrievePrivateData(policy, name)
        except Exception as exc:
            if self._error_code(exc) in self._MISSING_SECRET_CODES:
                raise MissingSecretError("service secret is missing") from None
            raise RuntimeError("machine secret read failed") from exc
        if not isinstance(payload, (bytes, str)) or not payload:
            raise MissingSecretError("service secret is missing")
        return decode_token_material(payload)

    def write(self, name: str, material: TokenMaterial) -> None:
        win32security = self._module()
        payload = encode_token_material(material).decode("utf-8")
        try:
            policy = win32security.LsaOpenPolicy(
                None,
                win32security.POLICY_CREATE_SECRET,
            )
            win32security.LsaStorePrivateData(policy, name, payload)
        except Exception as exc:
            raise RuntimeError("machine secret write failed") from exc

    def delete(self, name: str) -> None:
        win32security = self._module()
        try:
            policy = win32security.LsaOpenPolicy(
                None,
                win32security.POLICY_CREATE_SECRET,
            )
            win32security.LsaStorePrivateData(policy, name, None)
        except Exception as exc:
            if self._error_code(exc) in self._MISSING_SECRET_CODES:
                return
            raise RuntimeError("machine secret delete failed") from exc


def _stage_isolated_service_host(
    venv_root: Path, base_python_root: Path, win32_package_root: Path
) -> Path:
    """Stage a self-contained pywin32 service host without global Python mutations."""
    venv_root = venv_root.resolve()
    base_python_root = base_python_root.resolve()
    win32_package_root = win32_package_root.resolve()
    if venv_root == base_python_root or not (venv_root / "pyvenv.cfg").is_file():
        raise RuntimeError("Windows service host requires an isolated Python venv")
    if not win32_package_root.is_relative_to(venv_root):
        raise RuntimeError("pywin32 service binaries must originate from the selected venv")

    tag = f"{sys.version_info.major}{sys.version_info.minor}"
    sources = {
        "pythonservice.exe": win32_package_root / "win32" / "pythonservice.exe",
        f"python{tag}.dll": base_python_root / f"python{tag}.dll",
        f"pywintypes{tag}.dll": win32_package_root / "pywin32_system32" / f"pywintypes{tag}.dll",
        f"pythoncom{tag}.dll": win32_package_root / "pywin32_system32" / f"pythoncom{tag}.dll",
    }
    optional_abi = base_python_root / "python3.dll"
    if optional_abi.is_file():
        sources["python3.dll"] = optional_abi

    base_lib = base_python_root / "Lib"
    base_dlls = base_python_root / "DLLs"
    manager = win32_package_root / "win32" / "servicemanager.pyd"
    if not (base_lib / "encodings" / "__init__.py").is_file() or not base_dlls.is_dir():
        raise RuntimeError("Windows service host standard library is unavailable")
    if not manager.is_file():
        raise RuntimeError("Windows service host servicemanager is unavailable")
    # pythonservice.exe embeds Python. Unlike Scripts/python.exe, it must
    # explicitly include pywin32's win32 and win32/lib in its import path.
    # The executable-specific ._pth isolates its imports from HKCU/registry
    # and process environment while retaining the selected base stdlib.
    host_path_bytes = ("\n".join((
        str(base_lib), str(base_dlls), ".",
        r"Lib\site-packages", r"Lib\site-packages\win32",
        r"Lib\site-packages\win32\lib", r"Lib\site-packages\Pythonwin",
        "import site", "",
    ))).encode("utf-8")
    host_path = venv_root / "pythonservice._pth"
    if host_path.is_symlink():
        raise RuntimeError("Windows service host path manifest is a symlink")
    if host_path.exists() and (
        not host_path.is_file() or host_path.read_bytes() != host_path_bytes
    ):
        raise RuntimeError("Windows service host path manifest collision")
    host_path_temp = venv_root / "pythonservice._pth.native-staging"
    if host_path_temp.exists() or host_path_temp.is_symlink():
        raise RuntimeError("Windows service host path manifest staging collision")

    for name, source in sources.items():
        if not source.is_file():
            raise RuntimeError(f"Windows service host dependency missing: {name}")
        target = venv_root / name
        if target.is_symlink():
            raise RuntimeError(f"Windows service host target is a symlink: {name}")
        if target.exists():
            if not target.is_file() or hashlib.sha256(target.read_bytes()).digest() != hashlib.sha256(source.read_bytes()).digest():
                raise RuntimeError(f"Windows service host binary collision: {name}")
        temp = venv_root / (name + ".native-staging")
        if temp.exists() or temp.is_symlink():
            raise RuntimeError(f"Windows service host staging collision: {name}")
    for name, source in sources.items():
        target = venv_root / name
        if target.exists():
            continue
        temp = venv_root / (name + ".native-staging")
        try:
            shutil.copy2(source, temp)
            if hashlib.sha256(temp.read_bytes()).digest() != hashlib.sha256(source.read_bytes()).digest():
                raise RuntimeError(f"Windows service host copy verification failed: {name}")
            os.replace(temp, target)
        finally:
            temp.unlink(missing_ok=True)
    if not host_path.exists():
        try:
            with host_path_temp.open("xb") as handle:
                handle.write(host_path_bytes)
                handle.flush()
                os.fsync(handle.fileno())
            if host_path_temp.read_bytes() != host_path_bytes:
                raise RuntimeError("Windows service host path manifest verification failed")
            os.replace(host_path_temp, host_path)
        finally:
            host_path_temp.unlink(missing_ok=True)
    return venv_root / "pythonservice.exe"


def _bound_service_store(registered_root: str | None) -> ConfigStore:
    if not isinstance(registered_root, str) or not registered_root.strip():
        raise RuntimeError("Windows service state-root binding is missing")
    root = Path(registered_root)
    if not root.is_absolute() or registered_root.startswith("\\\\"):
        raise RuntimeError("Windows service state-root binding is invalid")
    return ConfigStore(root)


def _run_service_host(host: DeviceServiceHost, stop_event: threading.Event) -> None:
    """Run asyncio without Windows Proactor signal setup in pywin32's SCM thread.

    pywin32 may initialize embedded Python in a thread which Python considers
    its main thread but Windows does not permit to call signal.set_wakeup_fd.
    Windows' default ProactorEventLoop invokes that API at construction and
    crashes the service (SCM 7024, service-specific 0x20000001). Use a
    per-Runner selector loop; never mutate the process-wide event-loop policy.
    asyncio.Runner(loop_factory=...) is supported by our Python >=3.11 floor.
    """
    import asyncio

    with asyncio.Runner(loop_factory=asyncio.SelectorEventLoop) as runner:
        runner.run(host.run(stop_event))


class _Win32ServiceApi:
    def install(self, state_root: Path) -> None:
        import win32service
        import win32serviceutil

        win32_path = Path(win32service.__file__).resolve().parent.parent
        host_exe = _stage_isolated_service_host(
            Path(sys.prefix), Path(sys.base_prefix), win32_path
        )
        win32serviceutil.InstallService(
            pythonClassString="pc_remote_transport.windows_service.PCNativeDeviceService",
            serviceName=SERVICE_NAME,
            displayName=SERVICE_DISPLAY_NAME,
            startType=win32service.SERVICE_AUTO_START,
            description=SERVICE_DESCRIPTION,
            exeName=str(host_exe),
        )
        try:
            win32serviceutil.SetServiceCustomOption(SERVICE_NAME, "StateRoot", str(state_root.resolve()))
        except Exception:
            win32serviceutil.RemoveService(SERVICE_NAME)
            raise RuntimeError("Windows service state-root binding failed") from None

    def start(self) -> None:
        import win32serviceutil

        try:
            win32serviceutil.StartService(SERVICE_NAME)
        except Exception as exc:
            code = getattr(exc, "winerror", None)
            if code is None and getattr(exc, "args", None):
                code = exc.args[0]
            suffix = f" (winerror={code})" if isinstance(code, int) else ""
            raise RuntimeError("Windows SCM service start failed" + suffix) from None

    def stop(self) -> None:
        import win32serviceutil

        win32serviceutil.StopService(SERVICE_NAME)

    def restart(self) -> None:
        import win32serviceutil

        win32serviceutil.RestartService(SERVICE_NAME)

    def remove(self) -> None:
        import win32serviceutil

        win32serviceutil.RemoveService(SERVICE_NAME)

    def status(self) -> str:
        import win32service
        import win32serviceutil

        try:
            raw = win32serviceutil.QueryServiceStatus(SERVICE_NAME)
        except Exception as exc:
            code = getattr(exc, "winerror", None)
            if code is None and getattr(exc, "args", None):
                code = exc.args[0]
            if code == 1060:
                return "not_installed"
            raise
        state = raw[1]
        names = {
            win32service.SERVICE_STOPPED: "stopped",
            win32service.SERVICE_START_PENDING: "start_pending",
            win32service.SERVICE_STOP_PENDING: "stop_pending",
            win32service.SERVICE_RUNNING: "running",
            win32service.SERVICE_CONTINUE_PENDING: "continue_pending",
            win32service.SERVICE_PAUSE_PENDING: "pause_pending",
            win32service.SERVICE_PAUSED: "paused",
        }
        return names.get(state, f"unknown_{state}")


class WindowsServiceController:
    def __init__(
        self,
        config_store: ConfigStore,
        *,
        api: Any | None = None,
        command_runner: Callable[..., Any] = subprocess.run,
    ) -> None:
        self.config_store = config_store
        self.api = api or _Win32ServiceApi()
        self.command_runner = command_runner

    def install(self) -> None:
        self.config_store.initialize()
        self.api.install(self.config_store.root)
        try:
            self.command_runner(
                [
                    "sc.exe",
                    "failure",
                    SERVICE_NAME,
                    "reset=",
                    "86400",
                    "actions=",
                    "restart/5000/restart/15000/restart/60000",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            self.command_runner(
                ["sc.exe", "failureflag", SERVICE_NAME, "1"],
                check=True,
                capture_output=True,
                text=True,
            )
        except Exception:
            try:
                self.api.remove()
            finally:
                raise

    def start(self) -> None:
        self.api.start()

    def stop(self) -> None:
        # A repeated explicit stop is a no-op. Do not mistake stop_pending for
        # STOPPED when uninstall subsequently needs a proven quiescent service.
        if self.status() in {"not_installed", "stopped"}:
            return
        self.api.stop()

    def restart(self) -> None:
        self.api.restart()

    def status(self) -> str:
        return self.api.status()

    def uninstall(self) -> None:
        # SCM stop may fail or be asynchronous. NEVER swallow an uncertain stop
        # and proceed to removal while the machine service could still run.
        state = self.status()
        if state == "not_installed":
            return
        if state != "stopped":
            self.stop()
            state = self.status()
            if state == "not_installed":
                return
            if state != "stopped":
                raise RuntimeError("SCM_STOP_NOT_CONFIRMED: uninstall refused")
        self.api.remove()
        if self.status() != "not_installed":
            raise RuntimeError("SCM_REMOVE_NOT_CONFIRMED: credential cleanup deferred")


if os.name == "nt":
    import servicemanager
    import win32service
    import win32serviceutil

    class PCNativeDeviceService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION

        def __init__(self, args: list[str]) -> None:
            super().__init__(args)
            self._stop_event = threading.Event()

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._stop_event.set()

        def SvcDoRun(self) -> None:
            _log_service_event("starting")
            try:
                registered_root = win32serviceutil.GetServiceCustomOption(SERVICE_NAME, "StateRoot", None)
                store = _bound_service_store(registered_root)
                health = HealthStore(store.root)
                secrets = WindowsLsaSecretStore()
                host = DeviceServiceHost(store, health, secrets)
                _run_service_host(host, self._stop_event)
            except BaseException:
                _log_service_event("crashed")
                raise
            finally:
                _log_service_event("stopped")
else:
    class PCNativeDeviceService:
        pass
