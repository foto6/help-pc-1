from __future__ import annotations

import os
import subprocess
import threading
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
            if self._error_code(exc) in {2, 1168}:
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
            if self._error_code(exc) in {2, 1168}:
                return
            raise RuntimeError("machine secret delete failed") from exc


class _Win32ServiceApi:
    def install(self) -> None:
        import win32service
        import win32serviceutil

        win32serviceutil.InstallService(
            pythonClassString="pc_remote_transport.windows_service.PCNativeDeviceService",
            serviceName=SERVICE_NAME,
            displayName=SERVICE_DISPLAY_NAME,
            startType=win32service.SERVICE_AUTO_START,
            description=SERVICE_DESCRIPTION,
        )

    def start(self) -> None:
        import win32serviceutil

        win32serviceutil.StartService(SERVICE_NAME)

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
        self.api.install()
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
        self.api.stop()

    def restart(self) -> None:
        self.api.restart()

    def status(self) -> str:
        return self.api.status()

    def uninstall(self) -> None:
        try:
            if self.status() not in {"not_installed", "stopped"}:
                self.stop()
        except Exception:
            pass
        if self.status() != "not_installed":
            self.api.remove()


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
            store = ConfigStore()
            health = HealthStore(store.root)
            secrets = WindowsLsaSecretStore()
            host = DeviceServiceHost(store, health, secrets)
            try:
                import asyncio

                asyncio.run(host.run(self._stop_event))
            except BaseException:
                _log_service_event("crashed")
                raise
            finally:
                _log_service_event("stopped")
else:
    class PCNativeDeviceService:
        pass
