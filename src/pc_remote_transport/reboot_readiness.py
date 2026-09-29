"""Fail-closed R16 service/launcher readiness contract; no SCM calls here."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Any, Mapping

CONTRACT_VERSION = "pc.native.device_service.reboot_readiness.v1"
WITNESS_KEYS = frozenset({
    "contract_version", "service_instance_id", "service_pid",
    "service_started_at", "device_id", "session_epoch", "capability_digest",
    "relay_session_epoch", "control_session_epoch", "credential_owner_epoch",
    "launcher_run_id", "fresh_hello_verified", "live_listener_verified",
    "credential_owner_verified",
})


@dataclass(frozen=True)
class ReadinessDecision:
    contract_version: str
    ready: bool
    reason_code: str
    service_instance_id: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _decision(ready: bool, reason: str, instance: str | None) -> ReadinessDecision:
    return ReadinessDecision(CONTRACT_VERSION, ready, reason, instance)

def evaluate_reboot_readiness(
    health: Any, *,
    scm_state: str,
    live_scm_pid: int | None,
    live_witness: Mapping[str, Any] | None = None,
) -> ReadinessDecision:
    """Witness must come from THIS invocation's live authenticated probe, never disk.

    This pure gate cannot fetch SCM, secrets, ready.json or run-state.json.
    Its caller owns verifying the live SCM PID, authenticated hello/relay
    challenge, live Control/listener and current credential owner.
    """
    instance = getattr(health, "service_instance_id", None)
    if scm_state != "running":
        return _decision(False, "SCM_NOT_RUNNING", instance)
    if (
        isinstance(live_scm_pid, bool)
        or not isinstance(live_scm_pid, int)
        or live_scm_pid <= 0
        or live_scm_pid != getattr(health, "service_pid", None)
    ):
        return _decision(False, "SCM_PID_UNVERIFIED", instance)
    if (
        not isinstance(instance, str)
        or re.fullmatch(r"[0-9a-f]{32}", instance) is None
        or not getattr(health, "service_started_at", None)
    ):
        return _decision(False, "SERVICE_INSTANCE_UNVERIFIED", instance)
    if health.enabled is not True or not health.config_revision:
        return _decision(False, "SERVICE_CONFIG_NOT_ENABLED", instance)
    if (
        health.service_state != "running"
        or health.transport_state != "connected"
        or getattr(health, "auth_state", None) != "authenticated"
        or not health.session_epoch
        or not health.capability_digest
        or not health.last_heartbeat
    ):
        return _decision(False, "TRANSPORT_NOT_AUTHENTICATED", instance)
    if not health.session_epoch.startswith(f"{instance}:"):
        return _decision(False, "SESSION_INSTANCE_UNBOUND", instance)
    if live_witness is None:
        return _decision(False, "LIVE_WITNESS_REQUIRED", instance)
    if not isinstance(live_witness, Mapping) or set(live_witness) != WITNESS_KEYS:
        return _decision(False, "LIVE_WITNESS_SCHEMA_INVALID", instance)
    if live_witness["contract_version"] != CONTRACT_VERSION:
        return _decision(False, "LIVE_WITNESS_VERSION_MISMATCH", instance)
    for key in (
        "service_instance_id", "service_started_at", "device_id",
        "session_epoch", "capability_digest", "relay_session_epoch",
        "control_session_epoch", "credential_owner_epoch", "launcher_run_id",
    ):
        value = live_witness[key]
        if not isinstance(value, str) or not value.strip() or len(value) > 256:
            return _decision(False, "LIVE_WITNESS_FIELD_INVALID", instance)
    if (
        isinstance(live_witness["service_pid"], bool)
        or not isinstance(live_witness["service_pid"], int)
        or live_witness["service_pid"] != live_scm_pid
        or live_witness["service_instance_id"] != instance
        or live_witness["service_started_at"] != health.service_started_at
    ):
        return _decision(False, "SERVICE_INSTANCE_MISMATCH", instance)
    if (
        live_witness["device_id"] != health.device_id
        or live_witness["session_epoch"] != health.session_epoch
        or live_witness["relay_session_epoch"] != health.session_epoch
        or live_witness["capability_digest"] != health.capability_digest
    ):
        return _decision(False, "SESSION_OR_CAPABILITY_MISMATCH", instance)
    for key, reason in (
        ("fresh_hello_verified", "FRESH_AUTHENTICATED_HELLO_REQUIRED"),
        ("live_listener_verified", "LIVE_RELAY_CONTROL_REQUIRED"),
        ("credential_owner_verified", "LIVE_CREDENTIAL_OWNER_REQUIRED"),
    ):
        if live_witness[key] is not True:
            return _decision(False, reason, instance)
    return _decision(True, "CURRENT_LIVE_STACK_VERIFIED", instance)


def status_without_live_witness(health: Any, scm_state: str) -> ReadinessDecision:
    """CLI status cannot infer readiness from persisted service/launcher files."""
    instance = getattr(health, "service_instance_id", None)
    if scm_state != "running":
        return _decision(False, "SCM_NOT_RUNNING", instance)
    if getattr(health, "transport_state", None) != "connected":
        return _decision(False, "TRANSPORT_NOT_AUTHENTICATED", instance)
    return _decision(False, "LIVE_WITNESS_REQUIRED", instance)
