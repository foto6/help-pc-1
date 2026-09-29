from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import sys
from dataclasses import replace

from .protocol import ProtocolError, TokenMaterial
from .reboot_readiness import status_without_live_witness
from .service import DEFAULT_SECRET_NAME, ConfigStore, HealthSnapshot, HealthStore
from .windows_service import WindowsLsaSecretStore, WindowsServiceController


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Windows native PC device service")
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ("install", "start", "stop", "restart", "status", "uninstall"):
        sub.add_parser(name)

    configure = sub.add_parser("configure")
    configure.add_argument("--endpoint")
    configure.add_argument("--device-id")
    configure.add_argument("--heartbeat-seconds", type=float)
    configure.add_argument("--enable", action="store_true")
    configure.add_argument("--disable", action="store_true")
    configure.add_argument("--allow-insecure-loopback", action="store_true")
    configure.add_argument("--forbid-insecure-loopback", action="store_true")

    secret = sub.add_parser("secret")
    secret_sub = secret.add_subparsers(dest="secret_command", required=True)
    secret_set = secret_sub.add_parser("set")
    secret_set.add_argument("--generation", type=int, required=True)
    secret_sub.add_parser("delete")
    return parser


def _require_windows() -> None:
    if os.name != "nt":
        raise RuntimeError("Windows service commands require Windows")


def _status_payload(
    controller: WindowsServiceController,
    config_store: ConfigStore,
    health_store: HealthStore,
) -> dict:
    config = config_store.initialize()
    try:
        health = health_store.read()
    except Exception:
        health = HealthSnapshot(enabled=config.enabled, device_id=config.device_id)
    try:
        scm_state = controller.status()
    except Exception:
        scm_state = "unknown"
    # This CLI can read persisted health, NOT attest a fresh relay/control
    # handshake. Never infer READY from old ready.json/run-state.json or LSA.
    readiness = status_without_live_witness(health, scm_state)
    return {
        "contract_version": health.contract_version,
        "readiness": readiness.to_dict(),
        "observation_source": "persisted_health_unverified",
        "service_instance_id": health.service_instance_id,
        "service_pid_observed": health.service_pid,
        "service_started_at": health.service_started_at,
        "auth_state": health.auth_state,
        "scm_state": scm_state,
        "service_state": health.service_state,
        "enabled": config.enabled,
        "device_id": config.device_id,
        "session_epoch": health.session_epoch,
        "transport_state": health.transport_state,
        "last_heartbeat": health.last_heartbeat,
        "capability_digest": health.capability_digest,
        "config_revision": config_store.revision(config),
        "reason_code": health.reason_code,
        "secret_source": "<redacted>",
        "updated_at": health.updated_at,
    }


def _configure(args: argparse.Namespace, store: ConfigStore) -> None:
    current = store.initialize()
    updates = {}
    if args.endpoint is not None:
        updates["endpoint"] = args.endpoint.strip()
    if args.device_id is not None:
        updates["device_id"] = args.device_id.strip()
    if args.heartbeat_seconds is not None:
        updates["heartbeat_seconds"] = args.heartbeat_seconds
    if args.enable and args.disable:
        raise ProtocolError("--enable and --disable are mutually exclusive")
    if args.enable:
        updates["enabled"] = True
    if args.disable:
        updates["enabled"] = False
    if args.allow_insecure_loopback and args.forbid_insecure_loopback:
        raise ProtocolError("loopback flags are mutually exclusive")
    if args.allow_insecure_loopback:
        updates["allow_insecure_loopback"] = True
    if args.forbid_insecure_loopback:
        updates["allow_insecure_loopback"] = False
    store.update(replace(current, **updates))


def _read_secret_input() -> str:
    if not sys.stdin.isatty():
        encoded = sys.stdin.readline().strip()
        if not encoded:
            raise ProtocolError("token input is empty")
        return encoded
    return getpass.getpass("Token (base64, input hidden): ").strip()


def _set_secret(args: argparse.Namespace, store: ConfigStore, secrets: WindowsLsaSecretStore) -> None:
    if args.generation <= 0:
        raise ProtocolError("generation must be positive")
    encoded = _read_secret_input()
    try:
        raw = base64.b64decode(encoded.encode("ascii"), validate=True)
    except Exception as exc:
        raise ProtocolError("token must be valid base64") from exc
    material = TokenMaterial(args.generation, raw)
    config = store.initialize()
    secrets.write(DEFAULT_SECRET_NAME, material)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    store = ConfigStore()
    health = HealthStore(store.root)
    secrets = WindowsLsaSecretStore()
    controller = WindowsServiceController(store)

    try:
        if args.command == "configure":
            _configure(args, store)
            print("configuration updated")
            return 0

        _require_windows()

        if args.command == "secret":
            if args.secret_command == "set":
                _set_secret(args, store, secrets)
                print("machine secret updated")
            else:
                config = store.initialize()
                secrets.delete(DEFAULT_SECRET_NAME)
                print("machine secret deleted")
            return 0

        if args.command == "install":
            controller.install()
            print("service installed")
        elif args.command == "start":
            controller.start()
            print("service start requested")
        elif args.command == "stop":
            controller.stop()
            print("service stop requested")
        elif args.command == "restart":
            controller.restart()
            print("service restart requested")
        elif args.command == "status":
            print(json.dumps(_status_payload(controller, store, health), sort_keys=True))
        elif args.command == "uninstall":
            config = store.initialize()
            controller.uninstall()
            secrets.delete(DEFAULT_SECRET_NAME)
            store.update(replace(config, enabled=False))
            print("service uninstalled; machine secret deleted; configuration disabled")
        return 0
    except (ProtocolError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception:
        print("error: service command failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
