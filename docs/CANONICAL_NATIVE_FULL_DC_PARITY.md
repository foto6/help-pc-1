# Canonical PC Core Desktop Commander parity milestone

## Lineage and carried provenance

This branch starts exactly from canonical PC Core head
`fec2bc951cef3e4c9f5d31f00503277e7ed5b90b`. That head remains the
authoritative Executor, native tool-parity, remote transport, and remote
Executor adapter lineage.

The Windows device-service implementation was ported file-by-file from proven
candidate `a4596e6f9cef8eed8161425217939282a3b52509`; its older base was not
merged. The service CLI, Windows SCM/LSA implementation, service tests, and
PowerShell installer remain source-identical. `service.py`, its docs,
package metadata, and CI were reconciled narrowly with the current stack.

The stateful-search lifecycle was ported from proven candidate
`603d7a5791d6e0fc145e65e6b14ad031a5b2cf75`; that branch was not merged.
`search_sessions.py` and its focused cross-platform/Windows tests remain
source-identical. The parity operations module, schemas, mapping fixture, docs,
and parity tests were then extended for this milestone's additional actions.
## Newly closed core gaps

`fs.read_many` is a true bounded batch read primitive. It preserves caller
order, returns deterministic per-file success/error records, bounds each file,
and enforces both a configured and hard aggregate-byte ceiling.

`config.set` is a normal Executor side effect restricted to the explicit
mutable-key allowlist: `allowed_roots` and `read_many_max_bytes`. Updates
are revision-aware, atomically replaced, re-read for verification, and rolled
back on failure. `allowed_roots=null` preserves the preexisting
protected-path-only policy; an explicitly configured empty list means
**deny all filesystem access**, never unrestricted access.

`device.shutdown` is a journaled/idempotent Executor side effect. The remote
adapter injects and validates the authenticated device ID and session epoch.
After a completed result is durably recorded, DeviceAgent sends the response,
stops reconnecting, and the Windows service atomically switches its
non-secret config to `enabled=false`.

`audit.history` returns only bounded sanitized audit metadata:
request ID, action, phase, timestamp, dry-run flag, and outcome.
`metrics.get` aggregates bounded action/outcome counts. Neither API returns
raw arguments, results, audit details, credentials, stdin, file contents, or
process output.

`identity.get` exposes controller/device/session/platform metadata only.
It is the non-sensitive PC Core semantic equivalent of `who_am_i`.
## Preserved behavior

The stateful search lifecycle from the proven search candidate is preserved:
`search.start`, `search.read`, `search.list`, and `search.stop`,
including absolute offset reads, negative tail semantics, cancellation,
bounded retention, stale-generation handling, timeout, and deterministic
result ordering.

All existing filesystem/process/session actions, the observed-eight Desktop
Commander workflow, remote transport authentication/stream integrity,
request-ID idempotency, durable outcome reconciliation,
`UNKNOWN_RECONCILE` with `automatic_replay=false`, execution-context
binding, and protected-path reject-before-access policy remain in force.

The device service continues to wrap the existing DeviceAgent and
ExecutorRemoteDispatcher. It does not introduce a second side-effect engine.
Its install/start/stop/restart/status/uninstall lifecycle, atomic non-secret
configuration, LSA private token storage, redacted health, reconnect/backoff,
token rotation, clean stop, and SCM crash recovery are retained.

No implementation or test accesses `E:\manhwa`; tests use path strings or
reject-before-access instrumentation only.
## Desktop Commander 0.2.51 status

Core equivalents now include bounded batch reads, allowlisted config mutation,
agent shutdown, stateful search lifecycle, device-service lifecycle,
sanitized recent-call history, operation metrics, and non-sensitive identity,
in addition to the previously integrated filesystem/process/session surface.

**PDF create/modify remains a hard explicit capability gap.** PC Core does
not advertise or claim full Desktop Commander parity while that action is
absent. No unsafe shell/document bypass was added.

Vendor-specific onboarding/help/feedback operations, including
`give_feedback_to_desktop_commander` and `get_prompts`, are not PC Core
execution actions and are intentionally excluded.

Remote multi-device brokering is also outside this PC Core branch. The current
transport is deliberately scoped to one authenticated device agent/session.

## Verification gates

The CI matrix on Ubuntu and Windows runs the canonical ancestry/provenance
audit, preflight/context-binding tests, native parity and schema reproducibility,
stateful-search tests, native transport/harness, remote adapter tests,
device-service tests, the new full-core parity tests, platform-specific Windows
native/search tests, and the complete suite.
