"""Single-owner R20 shadow service CLI. Never targets the legacy SCM/LSA key.

The native bearer is an INTERNAL device-relay transport credential, not an
interactive account/OAuth system. No command prints secret material.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path
from dataclasses import replace

from .protocol import ProtocolError, TokenMaterial
from .service import DEFAULT_SECRET_NAME, ConfigStore, HealthStore
from .service_cli import _configure, _read_secret_input, _status_payload
from .windows_service import WindowsLsaSecretStore
from .r20_candidate import (
    CandidateScopedSecretStore,
    R20CandidateController,
    R20_SERVICE_NAME,
    R20_SECRET_NAME,
    assert_r20_scope,
    is_elevated_admin,
    r20_state_root,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Isolated PC Native R20 candidate service")
    subs = parser.add_subparsers(dest="command", required=True)
    for name in ("preflight", "install", "start", "stop", "restart",
                 "status", "uninstall"):
        subs.add_parser(name)
    config = subs.add_parser("configure")
    config.add_argument("--endpoint")
    config.add_argument("--device-id")
    config.add_argument("--heartbeat-seconds", type=float)
    config.add_argument("--enable", action="store_true")
    config.add_argument("--disable", action="store_true")
    config.add_argument("--allow-insecure-loopback", action="store_true")
    config.add_argument("--forbid-insecure-loopback", action="store_true")
    secret = subs.add_parser("secret")
    secret_sub = secret.add_subparsers(dest="secret_command", required=True)
    secret_sub.add_parser("delete")
    set_secret = secret_sub.add_parser("set")
    set_secret.add_argument("--generation", type=int, required=True)
    return parser


def _installer_environment() -> dict[str, bool]:
    """Read-only, noninteractive packaging/SCM prerequisites."""
    venv = Path(sys.prefix).resolve()
    requirements = {
        "windows": os.name == "nt",
        "separate_venv": venv != Path(sys.base_prefix).resolve(),
        "installed_wheel": Path(__file__).resolve().is_relative_to(venv),
        "private_pywin32": False,
        "elevated_token": is_elevated_admin(),
    }
    if os.name == "nt":
        try:
            import win32service
            requirements["private_pywin32"] = (
                Path(win32service.__file__).resolve().is_relative_to(venv)
            )
        except ImportError:
            pass
    return requirements


def _preflight(controller: R20CandidateController, store: ConfigStore) -> dict:
    root = assert_r20_scope(store.root)
    status = controller.status()
    requirements = _installer_environment()
    blockers = ([] if status == "not_installed" else ["candidate_service_name_occupied"])
    blockers.extend(name for name, met in requirements.items() if not met)
    return {
        "schema": "pc_native.r20_shadow_scm_preflight.v1",
        "candidate_service": R20_SERVICE_NAME,
        "candidate_state_root": str(root),
        "candidate_scm_state": status,
        "candidate_name_available": status == "not_installed",
        "environment": requirements,
        "blockers": blockers,
        "legacy_service_touched": False,
        "machine_secret_read": False,
        "candidate_install_eligible": not blockers,
    }


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        # Fail before any SCM/LSA operation on scope drift. No global
        # PC_NATIVE_DEVICE_SERVICE_HOME override is ever honored.
        root = assert_r20_scope(r20_state_root())
        store = ConfigStore(root)
        controller = R20CandidateController(store)
        if args.command == "preflight":
            if os.name != "nt":
                raise RuntimeError("Windows SCM preflight requires Windows")
            decision = _preflight(controller, store)
            print(json.dumps(decision, sort_keys=True))
            return 0 if decision["candidate_install_eligible"] else 2
        if args.command == "configure":
            _configure(args, store)
            print("R20 candidate configuration updated")
            return 0
        if os.name != "nt":
            raise RuntimeError("R20 SCM commands require Windows")
        if args.command == "status":
            print(json.dumps(_status_payload(controller, store, HealthStore(root)), sort_keys=True))
            return 0
        if args.command == "install":
            decision = _preflight(controller, store)
            if not decision["candidate_install_eligible"]:
                raise RuntimeError(
                    "R20 installation prerequisites not satisfied: " +
                    ", ".join(decision["blockers"])
                )
            controller.install()
            print("R20 candidate installed in manual-start mode")
            return 0
        if args.command == "secret":
            scoped = CandidateScopedSecretStore(WindowsLsaSecretStore())
            if args.secret_command == "set":
                if args.generation <= 0:
                    raise ProtocolError("generation must be positive")
                encoded = _read_secret_input()
                try:
                    raw = base64.b64decode(encoded.encode("ascii"), validate=True)
                except Exception as exc:
                    raise ProtocolError("invalid token encoding") from exc
                if len(raw) < 32:
                    raise ProtocolError("candidate signed transport secret must be >=32 bytes")
                scoped.write(DEFAULT_SECRET_NAME, TokenMaterial(args.generation, raw))
                print("R20 candidate machine secret updated (redacted)")
            else:
                scoped.delete(DEFAULT_SECRET_NAME)
                print("R20 candidate machine secret deleted")
            return 0
        if args.command == "start":
            controller.start()
            print("R20 candidate start requested")
        elif args.command == "stop":
            controller.stop()
            print("R20 candidate stop requested")
        elif args.command == "restart":
            controller.restart()
            print("R20 candidate restart requested")
        elif args.command == "uninstall":
            controller.uninstall()
            # Removing R20 does not touch any old service, old secret or
            # R20 forensic journal. Delete candidate-only secret explicitly.
            CandidateScopedSecretStore(WindowsLsaSecretStore()).delete(DEFAULT_SECRET_NAME)
            if store.path.exists():
                cfg = store.load()
                store.update(replace(cfg, enabled=False))
            print("R20 candidate-only SCM identity removed; candidate config disabled")
        return 0
    except (RuntimeError, ProtocolError, ValueError) as exc:
        print(f"R20 candidate blocked: {exc}", file=sys.stderr)
        return 2
    except Exception:
        print("R20 candidate command failed (details suppressed)", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
