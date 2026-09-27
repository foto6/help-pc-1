# Canonical PC Core final candidate

This integration-only branch assembles the final `help-pc-1` PC Core candidate. It does not merge or release producer branches.

## Exact provenance

- Primary base: `078de1871d4303db74ffff9d6b74efe1f342c482`.
- Stateful-search source: `c3b86fefb66348e6a78f5f555a59f81154bd357e`.
- Windows-service runtime source: `e8804f116c84b74ae8e04f1c07abc3a01baf79a1`.
- Immutable service-install source: `a906312f49c97ab0ee6ceb6cda00925d5b9ebfca`.
- Strict parity-binding sibling reference: `fec2bc951cef3e4c9f5d31f00503277e7ed5b90b`.
- Lineage review: `foto6/boss` `43718b7b872f47103ea5fad2c54a0ed041b8f1f5`.

The candidate starts exactly from the primary base. Search, service-runtime, immutable-install, and strict-B changes were selectively reapplied or reimplemented; none of those source heads is merged as history. The old GitHub-relay and obsolete transport histories remain non-ancestors.

## Registry and digest policy

Two registries are intentionally distinct.

`pc.native.tool_registry.v1` is the frozen A/control compatibility registry. Its digest remains exactly:

`58b2bde8c6a49825747dcd7010f105dad0b6d548c7e8341cdafb32d2319f6dcd`

Unversioned `pc.native.control.v1` requests continue to use that compatibility registry. Compatibility routes are explicit in the authenticated capability manifest and identify whether each tool resolves to the native parity surface, the legacy Executor UI/shell surface, or is unavailable.

`pc.native.parity_tool_registry.v1` is the direct internal registry. Every advertised internal action is a current `OPS_ACTIONS` member, and every effect classification must exactly match `OPS_SIDE_EFFECT_ACTIONS` at import time. The manifest also embeds the exact `LocalOperations.capabilities_snapshot()`, its parity digest, exact `NATIVE_TOOL_PARITY_VERSION`, and exact request/result/capability/preflight/context/cursor/search/process schema versions. Any drift changes the authenticated device/session manifest and fails dispatch closed.

The compatibility digest is never reinterpreted as the parity-registry digest.
## Lineage-review gap resolution

- `device.set_config` explicitly translates to the current `config.set` action and therefore inherits the parity settings allowlist, atomic validation/rollback, empty-root fail-closed behavior, and outcome journal.
- `process.interact` explicitly translates to `shell.session.write_stdin` only when the supplied handle was created by `shell.session.open`. A normal `process.start` handle returns `CAPABILITY_UNAVAILABLE` instead of being treated as interactive.
- `uia.find` has no current backed action. It remains recognizable only in compatibility v1 and is advertised as `capability_unavailable`; dispatch returns `CAPABILITY_UNAVAILABLE` before Executor preflight or execution. It is not present in the direct parity registry.

## Native parity surface

The candidate retains the parity-gap primitives from the primary base: ordered bounded `fs.read_multiple`, atomic allowlisted `config.set`, journaled `agent.shutdown`, sanitized `identity.who_am_i`, `diagnostics.usage_stats`, `diagnostics.recent_tool_calls`, and bounded/safe `pdf.write`.

Stateful search adds `search.start`, `search.read`, `search.list`, and `search.stop` with generation-scoped retained handles, files/content modes, literal or regex matching, case handling, hidden-file control, bounded context/results/timeouts, absolute/tail pagination, cancellation, and retention cleanup. A terminal search is retained until it has been observed at least once, after which the configured retention window begins; never-observed terminal sessions still have a bounded hard-expiry so GC is eventual. Remote search handles are additionally bound to control session, device, transport epoch, and authenticated capability-manifest digest.

The Desktop Commander acceptance mapping contains 30 reference tools. Twenty-eight have mandatory semantic replacements backed by the direct parity registry. Only `get_prompts` and `give_feedback_to_desktop_commander` are intentional vendor-specific exclusions.

## Transport and side-effect semantics

The authenticated frame transport core remains byte-identical to the primary base for `agent.py`, `config.py`, `ledger.py`, `protocol.py`, and `websocket.py`. `request_id` remains stable through transport, preflight, Executor, journal, audit, and response.

Side-effect requests require durable Executor outcome evidence. Unknown or lost outcomes surface `UNKNOWN_RECONCILE` with automatic replay disabled. Transport response loss or reconnect never authorizes blind re-execution. Device/session epoch drift, capability drift, and stale process/search handles fail closed.

The `E:\\manhwa` protected tree is never used by integration tests. Protection coverage uses literal paths and spies/reject-before-probe assertions only.
## Windows service

The service overlay retains the green Windows service runtime: disabled by default, outbound authenticated relay connection, machine LSA private-data secret storage, redacted health/event logging, token-rotation persistence, bounded reconnect/backoff, configuration kill switch, durable request ledger, and Executor outcome journal.

Production-default `build_default_runtime()` constructs the exact current `Executor` -> `ExecutorRemoteDispatcher` -> `ServiceDeviceAgent` (`DeviceAgent`) path. There is no alternate side-effect engine or module override.

Security W3-B3 is closed by the selectively absorbed immutable-install delta from `a906312f49c97ab0ee6ceb6cda00925d5b9ebfca`. Production bootstrap no longer installs from a mutable checkout: it requires an immutable wheel plus sidecar manifest, independently supplied expected SHA-256/producer/package/protocol/registry metadata, rejects non-canonical or symlink/reparse inputs before mutation, stages and re-hashes the exact approved bytes, then verifies installed package and runtime contract identity before configuration or SCM registration. No local-source production fallback is retained.

## Verification

Two complementary integration proofs are retained:

- A-style authenticated frame -> `DeviceAgent` -> `ExecutorRemoteDispatcher` -> real `Executor` tests cover file write/edit/read, process start/read/list/terminate, system reads, stateful search, streaming, stale capability binding, and transport idempotency/reconciliation.
- B-style direct parity tests prove the exact parity snapshot/digest/schema binding, direct registry subset/effect invariants, all 28 mandatory Desktop Commander mappings, and direct real-Executor file/process workflow.

`tools/audit_native_core_final_candidate.py` verifies exact provenance, selective component blob provenance, byte-stable transport core, complete `src/pc_executor` and `schemas` change tracking, direct-registry invariants, the 30/28/2 mapping rule, absence of old relay ancestry, and `git diff --check`.
