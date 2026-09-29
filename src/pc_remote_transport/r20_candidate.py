"""R20 single-owner shadow Windows SCM service (candidate-only namespace).

No dynamic overrides of the legacy name, registry key, LSA secret or state root.
No automatic deployment/cutover. Installation defaults to DEMAND_START.
"""
from __future__ import annotations

import os
import stat as stat_module
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Callable

from .protocol import TokenMaterial
from .service import (
    DEFAULT_SECRET_NAME,
    ConfigStore,
    DeviceServiceHost,
    HealthStore,
    build_default_runtime,
)
from .windows_service import (
    WindowsLsaSecretStore,
    WindowsServiceController,
    _Win32ServiceApi,
    _run_service_host,
    _stage_isolated_service_host,
)

R20_SERVICE_NAME = "PCNativeCandidateR20"
R20_DISPLAY_NAME = "PC Native Candidate R20"
R20_SERVICE_DESCRIPTION = "Isolated single-owner native PC candidate (manual start)"
R20_SECRET_NAME = "L$OpenAI.PCNativeCandidateR20"
R20_STATE_FOLDER = "PCNativeCandidateR20"
LEGACY_SERVICE_NAME = "PCNativeDeviceService"
LEGACY_SECRET_NAME = "L$OpenAI.PCNativeDeviceService"


def r20_state_root(programdata: str | os.PathLike[str] | None = None) -> Path:
    root = Path(programdata) if programdata is not None else Path(
        os.environ.get("PROGRAMDATA", r"C:\ProgramData")
    )
    if not root.is_absolute():
        raise RuntimeError("candidate ProgramData must be absolute")
    return root / R20_STATE_FOLDER


def _reject_reparse_ancestors(path: Path) -> None:
    """Refuse a symlink/junction along a candidate write/install path."""
    for part in (path, *path.parents):
        try:
            attributes = os.lstat(part)
        except FileNotFoundError:
            continue
        if (
            stat_module.S_ISLNK(attributes.st_mode)
            or int(getattr(attributes, "st_file_attributes", 0) or 0) &
            getattr(stat_module, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        ):
            raise RuntimeError("candidate state path contains a reparse point")


def assert_r20_scope(
    state_root: str | os.PathLike[str],
    *,
    expected_root: str | os.PathLike[str] | None = None,
    legacy_root: str | os.PathLike[str] | None = None,
) -> Path:
    """Never let a candidate share or nest inside the legacy service state."""
    wanted = Path(expected_root) if expected_root is not None else r20_state_root()
    legacy = Path(legacy_root) if legacy_root is not None else ConfigStore.default_root()
    candidate = Path(state_root)
    if not (candidate.is_absolute() and wanted.is_absolute() and legacy.is_absolute()):
        raise RuntimeError("all Windows service state roots must be absolute")
    if any(str(p).startswith("\\\\") for p in (candidate, wanted, legacy)):
        raise RuntimeError("UNC state roots are forbidden")
    _reject_reparse_ancestors(candidate)
    _reject_reparse_ancestors(wanted)
    # Use normcase even for a caller-supplied path variant. Do not treat a
    # directory merely *named* like R20 somewhere else as the approved root.
    from os.path import normcase, normpath
    canon = lambda p: normcase(normpath(str(p.resolve(strict=False))))
    a, b, old = canon(candidate), canon(wanted), canon(legacy)
    if a != b:
        raise RuntimeError("candidate service state root is not its exact scoped root")
    if a == old or a.startswith(old + os.sep) or old.startswith(a + os.sep):
        raise RuntimeError("candidate and legacy state roots overlap")
    if R20_SERVICE_NAME == LEGACY_SERVICE_NAME or R20_SECRET_NAME == LEGACY_SECRET_NAME:
        raise RuntimeError("candidate SCM or secret identity collides with legacy")
    return candidate


class CandidateScopedSecretStore:
    """Only map the historic protocol key into a separate R20 machine secret.

    This adapter allows the UNMODIFIED legacy service runtime to keep using
    DEFAULT_SECRET_NAME internally without ever calling its original LSA key.
    """
    def __init__(self, inner: Any):
        self.inner = inner

    @staticmethod
    def _key(requested: str) -> str:
        if requested != DEFAULT_SECRET_NAME:
            raise RuntimeError("unexpected service secret identifier")
        return R20_SECRET_NAME

    def read(self, requested: str) -> TokenMaterial:
        return self.inner.read(self._key(requested))

    def write(self, requested: str, material: TokenMaterial) -> None:
        self.inner.write(self._key(requested), material)

    def delete(self, requested: str) -> None:
        self.inner.delete(self._key(requested))


def r20_runtime(config, material, config_store, health_store, secret_store):
    assert_r20_scope(config_store.root)
    return build_default_runtime(
        config,
        material,
        config_store,
        health_store,
        secret_store,
        operations_state_root=config_store.root / "operations",
    )


def is_elevated_admin() -> bool:
    """Read-only Windows token check. Never auto-elevate or request UAC."""
    if os.name != "nt":
        return False
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() == 1
    except (AttributeError, OSError):
        return False


class R20CandidateServiceApi(_Win32ServiceApi):
    """Explicitly candidate-only SCM calls. Legacy API remains untouched."""

    def install(self, state_root: Path) -> None:
        approved = assert_r20_scope(state_root)
        if self.status() != "not_installed":
            raise RuntimeError("candidate service already exists; never overwrite")
        if not is_elevated_admin():
            raise RuntimeError("R20 candidate SCM installation requires an elevated Windows token")
        import win32service
        import win32serviceutil

        if Path(sys.prefix).resolve() == Path(sys.base_prefix).resolve():
            raise RuntimeError("R20 installer requires a separate, installed-wheel venv")
        package = Path(__file__).resolve()
        if not package.is_relative_to(Path(sys.prefix).resolve()):
            raise RuntimeError("R20 candidate must be imported from installed venv, not PYTHONPATH")
        win32_path = Path(win32service.__file__).resolve().parent.parent
        host_exe = _stage_isolated_service_host(
            Path(sys.prefix), Path(sys.base_prefix), win32_path
        )
        win32serviceutil.InstallService(
            pythonClassString="pc_remote_transport.r20_candidate.PCNativeCandidateR20Service",
            serviceName=R20_SERVICE_NAME,
            displayName=R20_DISPLAY_NAME,
            startType=win32service.SERVICE_DEMAND_START,
            description=R20_SERVICE_DESCRIPTION,
            exeName=str(host_exe),
        )
        try:
            win32serviceutil.SetServiceCustomOption(
                R20_SERVICE_NAME, "StateRoot", str(approved.resolve())
            )
        except Exception:
            win32serviceutil.RemoveService(R20_SERVICE_NAME)
            raise RuntimeError("candidate state-root binding failed") from None

    def start(self) -> None:
        import win32serviceutil
        win32serviceutil.StartService(R20_SERVICE_NAME)

    def stop(self) -> None:
        import win32serviceutil
        win32serviceutil.StopService(R20_SERVICE_NAME)

    def restart(self) -> None:
        import win32serviceutil
        win32serviceutil.RestartService(R20_SERVICE_NAME)

    def remove(self) -> None:
        import win32serviceutil
        win32serviceutil.RemoveService(R20_SERVICE_NAME)

    def status(self) -> str:
        import win32service
        import win32serviceutil
        try:
            raw = win32serviceutil.QueryServiceStatus(R20_SERVICE_NAME)
        except Exception as exc:
            code = getattr(exc, "winerror", None)
            if code is None and getattr(exc, "args", None):
                code = exc.args[0]
            if code == 1060:
                return "not_installed"
            raise
        names = {
            win32service.SERVICE_STOPPED: "stopped",
            win32service.SERVICE_START_PENDING: "start_pending",
            win32service.SERVICE_STOP_PENDING: "stop_pending",
            win32service.SERVICE_RUNNING: "running",
        }
        return names.get(raw[1], "other")


class R20CandidateController(WindowsServiceController):
    def __init__(
        self, store: ConfigStore, *,
        api: Any | None = None,
        command_runner: Callable[..., Any] = subprocess.run,
    ) -> None:
        self.config_store = store
        self.api = api if api is not None else R20CandidateServiceApi()
        self.command_runner = command_runner

    def install(self) -> None:
        assert_r20_scope(self.config_store.root)
        if self.status() != "not_installed":
            raise RuntimeError("candidate service name is already registered")
        self.config_store.initialize()
        self.api.install(self.config_store.root)
        try:
            for args in (
                ["sc.exe", "failure", R20_SERVICE_NAME, "reset=", "86400",
                 "actions=", "restart/5000/restart/15000/restart/60000"],
                ["sc.exe", "failureflag", R20_SERVICE_NAME, "1"],
            ):
                self.command_runner(args, check=True, capture_output=True, text=True)
        except Exception:
            # Roll back the R20 identity only. Never use inherited R15 name.
            self.api.remove()
            raise

    def uninstall(self) -> None:
        observed = self.status()
        if observed == "not_installed":
            return
        if observed != "stopped":
            raise RuntimeError("stop the candidate and verify STOPPED before removing")
        self.api.remove()


def _bound_candidate_store(registered_root: str | None) -> ConfigStore:
    if not isinstance(registered_root, str) or not registered_root.strip():
        raise RuntimeError("candidate StateRoot registration is missing")
    return ConfigStore(assert_r20_scope(registered_root))


if os.name == "nt":
    import servicemanager
    import win32service
    import win32serviceutil

    class PCNativeCandidateR20Service(win32serviceutil.ServiceFramework):
        _svc_name_ = R20_SERVICE_NAME
        _svc_display_name_ = R20_DISPLAY_NAME
        _svc_description_ = R20_SERVICE_DESCRIPTION

        def __init__(self, args: list[str]) -> None:
            super().__init__(args)
            self._stop_event = threading.Event()

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._stop_event.set()

        def SvcDoRun(self) -> None:
            servicemanager.LogInfoMsg("R20 candidate service starting")
            try:
                raw = win32serviceutil.GetServiceCustomOption(
                    R20_SERVICE_NAME, "StateRoot", None
                )
                store = _bound_candidate_store(raw)
                secrets = CandidateScopedSecretStore(WindowsLsaSecretStore())
                host = DeviceServiceHost(
                    store, HealthStore(store.root), secrets,
                    runtime_factory=r20_runtime,
                )
                _run_service_host(host, self._stop_event)
            except BaseException:
                servicemanager.LogErrorMsg("R20 candidate service stopped with error")
                raise
            finally:
                servicemanager.LogInfoMsg("R20 candidate service stopped")
else:
    class PCNativeCandidateR20Service:
        """Import-only placeholder; SCM functionality is Windows-specific."""
