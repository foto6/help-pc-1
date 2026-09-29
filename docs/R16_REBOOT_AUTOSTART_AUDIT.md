# R16 reboot/autostart safety: Windows PC Core

Issue: https://github.com/foto6/help-pc-1/issues/1
Producer base: `04f817299b46ecb0ffa8aa908ce84fdb4c3300d0`.
Writable branch: `agent/pc-r16-reboot-service-audit-20260929`.
This is a mock-only safety milestone, not a deployment or service cutover.

## Observed incident and policy

After reboot, the installed `PCNativeDeviceService` started under LocalSystem
with SCM state RUNNING but outbound transport BACKOFF. Relay, Control, and
WebBridge listeners were absent. Historical `ready.json`, `run-state.json`,
and `secret-env.json` survived. Those files are NOT current readiness proof.

Actual production implementation audit:
- `_Win32ServiceApi.install` uses pywin32 `SERVICE_AUTO_START` for the
  installed service. There is no user-account override; the installed service
  runs as the SCM default (LocalSystem).
- `WindowsServiceController.install` configures
  `sc.exe failure ... reset= 86400 actions= restart/5000/restart/15000/restart/60000`
  and `sc.exe failureflag PCNativeDeviceService 1`. This is persistent
  production recovery policy, NOT a rehearsal lifecycle.
- Machine state is bound to the registered StateRoot, normally
  `%ProgramData%\PCNativeDeviceService`. The service config defaults to
  `enabled=false`; previously enabled configuration can survive reboot.
- Machine credentials live in Windows LSA private data and may survive reboot.
  Credential presence does not prove a live credential owner or relay.
- The service creates a fresh instance ID/PID/start timestamp in health before
  reading configuration or secrets. This invalidates old authenticated-looking
  health at the start of every new service process.
## Current service versus historical readiness

`pc.native.device_service.health.v1` now records optional
`service_instance_id`, `service_pid`, `service_started_at`, and
`auth_state`; legacy health files remain readable but have no current
instance proof. At process startup, auth is `unverified`, previous session
epoch/heartbeat/digest are cleared and transport is `idle`.

The production service's opaque Control v1 session epoch takes the form:
`<current-service-instance-id>:<random-UUID-hex>`. It remains a valid
`pc_remote_transport.frame.v1` epoch; the payload and the frozen
`pc.native.tool_registry.v1` / parity registry are not modified.
Boss must compare this instance prefix with current health and a fresh,
authenticated relay hello; PID alone is insufficient because Windows may
reuse it after reboot.

Raw `welcome` or `heartbeat` JSON can no longer set connected/heartbeat
state. `DeviceAgent` invokes observational callbacks only after authenticated
HMAC decoding, current session-epoch validation, inbound replay acceptance and
exact welcome nonce validation. A failed connector enters BACKOFF, revokes
auth/epoch/heartbeat and never emits READY. Disconnect, stop, invalid config,
disabled mode, and missing/invalid machine-secret states also revoke auth.

`pc-native-device-service status` is intentionally diagnostic only. Its
`readiness.ready` remains false without a fresh cross-process witness, even
if SCM reports RUNNING and persisted health looks connected.
`observation_source=persisted_health_unverified` is a deliberate warning:
service-state RUNNING is distinct from fully verified stack readiness.
## Exact downstream Boss launcher contract

Pure evaluation entrypoint:
`pc_remote_transport.reboot_readiness.evaluate_reboot_readiness`
(`health`, `scm_state`, `live_scm_pid`, `live_witness`).
Output contract: `pc.native.device_service.reboot_readiness.v1`,
`ready: bool`, `reason_code: str`, `service_instance_id: str|null`.

Boss launcher MUST create the following in-memory witness from a fresh
authenticated live probe of the current stack, never by copying historical
`ready.json`, `run-state.json`, `secret-env.json`, or health files:

```json
{
  "contract_version": "pc.native.device_service.reboot_readiness.v1",
  "service_instance_id": "<service instance from current health and epoch prefix>",
  "service_pid": 1234,
  "service_started_at": "<current service process start timestamp>",
  "device_id": "<currently authenticated device ID>",
  "session_epoch": "<instance ID>:<fresh authenticated transport epoch>",
  "capability_digest": "<current authenticated capability manifest digest>",
  "relay_session_epoch": "<same epoch observed by live relay>",
  "control_session_epoch": "<current Control listener/session epoch>",
  "credential_owner_epoch": "<current live credential owner epoch>",
  "launcher_run_id": "<freshly created current launcher run ID>",
  "fresh_hello_verified": true,
  "live_listener_verified": true,
  "credential_owner_verified": true
}
```
Boss must obtain `live_scm_pid` from a fresh read-only SCM query and verify
the process identity and start timestamp. The relay hello must have a valid
HMAC and current nonce/epoch. Control/listener and credential-owner flags
may be true ONLY after an independent live check, not after file existence or
a surviving LSA secret. `launcher_run_id` must belong to the current launch
and its run state must have been durably created; failure between service
start and launcher run-state creation remains BLOCKED.

Evaluator requires exact witness keys/version, valid typed nonempty fields,
running SCM, matching live PID, current service ID/start timestamp, current
authenticated transport, matching device/session/capability digest and relay
epoch, instance-bound epoch prefix, and all three live verification flags.
Missing/unknown/stale evidence returns a specific fail-closed reason.
No fallback to historical READY, no guessed replacement epoch, no replay of
side-effect journal entries. Boss owns its separate orchestration/rollback;
this producer changes no boss code.

## Persistent production versus isolated rehearsal policy

Pure planner: `windows_service.planned_install_policy`, contract
`pc.native.windows_service.install_policy.v1`.
`persistent_production_auto` is the unchanged installed policy:
name `PCNativeDeviceService`, startup Auto, crash/non-crash SCM restart
5s/15s/60s with 24-hour reset. The opt-in
`isolated_rehearsal_demand` requires a validated fixture ID, allocates a
distinct `PCNativeR16Fixture-<fixture-id>` name, specifies demand start and
NO recovery, and has `scm_mutation_supported=false`.
It is a planning/simulation contract, not a new executable SCM installer.
Until a separately approved isolated fixture service class exists, use fake
SCM only; never repurpose the installed production SCM identity for rehearsal.
## Deterministic negative matrix

`tests/test_r16_reboot_service_safety.py` runs with fake SCM/connector/LSA
objects, temporary synthetic records, and no real service or protected files.
It asserts:
- Auto-launch without Relay/Control enters BACKOFF even with surviving
  machine credentials; old READY/run-state/secret-env files stay non-authoritative.
- Missing run state after service start, missing live credential owner,
  stale listener, unverified fresh hello, absent witness, and invalid witness
  fields all refuse READY.
- PID reuse, service-instance replacement, session-epoch reuse/forgery,
  digest mismatch, non-running SCM, stale/legacy health and malformed raw
  welcome/heartbeat cannot masquerade as current authenticated readiness.
- Explicit stop and uninstall are idempotent under mock SCM. Stop failure or
  STOP_PENDING fails closed: no service removal until STOPPED is confirmed.
- Frozen primary registry digest
  `58b2bde8c6a49825747dcd7010f105dad0b6d548c7e8341cdafb32d2319f6dcd`
  and separate parity digest
  `dab7ebd65dd239519c755b0521cd2068f15ae885402e37d4885f64b9c2a08c33`
  remain unchanged, as do Control v1, Executor schemas and protected paths.

## Operator-safe rollback (human/elevated owner only)

Do NOT launch another production/rehearsal stack against an auto-started
leftover service. First inspect SCM state, PC service status, relay/Control
listeners, service identity/epoch, and current launcher run state independently.
If a fresh rehearsal requires the production service stopped, an authorized
operator requests the documented elevated explicit stop and confirms STOPPED;
STOP_PENDING, denied stop, unknown outcome and surviving credentials are HOLD,
not permission to install/restart/remove. Preserve outcome journal, request
ledger, service health and incident evidence. Do not wipe user credentials or
guess ownership; do not blind-replay prior effects. A separately authorized
uninstall must verify stop before removing service identity, then explicitly
disable configuration and delete the LSA entry. Keep Desktop Commander
available as fallback. No SCM/UAC operation or production cutover occurred
while developing or testing this branch.
