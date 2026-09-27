# Native remote transport → Executor adapter v1

This canonical branch connects the authenticated `pc_remote_transport` device channel to the existing `pc_executor.Executor` action boundary. It does not add a second filesystem, process, shell, UI, clipboard, or input implementation.

## Canonical provenance

The authoritative base is `e47908e2c734984a872f3cc087731f4690d1c82c`, which already contains the current Executor lineage plus the cleanly reapplied native transport.

The adapter implementation is ported from source candidate `30d7cb0f0571c3bd1565fd6b96c069ef64f3d9dd`. That candidate is a nine-commit adapter stack rooted at transport commit `8df29aad32a6cb142dff6721f92fca74a080e441`. The stack's first commit copied Executor context-binding contracts from `2cc1e40f792a3d74560b726a0d246c90b7f077e9`; those files are already present and authoritative on the canonical base, so they are deliberately not re-cherry-picked here.

Carried from the source candidate:

- authenticated `TransportDispatchContext` hook in `pc_remote_transport.agent`;
- adapter exports in `pc_remote_transport.__init__`;
- `pc_remote_transport.executor_adapter`;
- focused adapter and recovery tests.

Not carried:

- old-base copies of `src/pc_executor/**`;
- duplicate execution-context fixtures/docs already on the current Executor line;
- relay queue/history files;
- any `tools/github_relay.py` RPC dependency.

The provider-neutral registry semantics are `pc.native.control.v1` / `pc.native.tool_registry.v1`. The static registry digest remains:

`58b2bde8c6a49825747dcd7010f105dad0b6d548c7e8341cdafb32d2319f6dcd`

## Capability and session binding

`ExecutorRemoteDispatcher.capability_manifest()` advertises the native registry version/digest together with the exact current Executor capability contract, attestation digest, and supported action set. `DeviceAgent` hashes that complete manifest into the authenticated hello.

Each dispatch receives device ID, authenticated session epoch, and hello-time capability-manifest digest. The adapter recomputes the manifest before Executor preflight; drift is rejected as `CAPABILITY_DRIFT`.

Control `request_id` must exactly match the transport logical request ID. It flows unchanged through `ActionRequest`, preflight, outcome journaling, audit, and the response.

Stable control sessions remain device-bound across reconnects. Process/session handles are additionally bound to the authenticated transport epoch, so stale handles fail closed after reconnect.

## Side-effect and idempotency path

For a side-effecting native tool, the adapter validates protocol/schema, request identity, device/session ownership, protected paths, paging/handle state, execution-context epoch, and capability stability before dispatch.

It requires Executor durable outcome evidence, checks prior evidence for the exact request/action, calls existing Executor preflight, preserves current execution-context binding semantics, and invokes `Executor.execute()` exactly once through the authoritative Executor boundary.

Unknown side-effect outcomes raise `UnknownDispatchOutcome`; transport records/surfaces `UNKNOWN_RECONCILE` with automatic replay disabled. Duplicate logical requests never become a new side effect merely because the transport session changed or a response was lost.

## Streaming

Streaming tool results are projected into bounded bytes and handed back to the existing transport stream layer. That layer retains ordered chunk indices, per-chunk SHA-256, whole-stream SHA-256, byte bounds, and final manifest verification.

## Protected-path invariant

Arguments resolving to `E:\\manhwa` or descendants are rejected as `PROTECTED_PATH_BLOCKED` before Executor preflight or execution. Tests use only path strings/spies and do not access that location. This adapter guard is additive; it does not replace Executor policy.

## Canonical topology audit

`tools/audit_canonical_remote_executor_integration.py` runs in both CI matrix jobs. It proves that:

- the canonical base is the sole parent of the integration commit;
- old relay commit `992c66335c9e6c40d150bc10c086e97ea7600d48` and old transport commit `8df29aad32a6cb142dff6721f92fca74a080e441` are not ancestors of the new head;
- no `src/pc_executor/**`, `tools/github_relay.py`, or `relay/**` path is changed;
- the five carried adapter/hook/test blobs are byte-identical to the source candidate;
- the diff passes `git diff --check`.
