# Native remote transport → Executor adapter v1

This branch connects the authenticated `pc_remote_transport` device channel to the existing `pc_executor.Executor` action boundary. It does not add a second filesystem, process, shell, UI, clipboard, or input implementation.

## Provenance

The branch starts from native transport `8df29aad32a6cb142dff6721f92fca74a080e441`.

Because that transport snapshot predated Executor execution-context binding, the branch pins the exact already-published Executor context-binding bytes from `agent/pc-executor@2cc1e40f792a3d74560b726a0d246c90b7f077e9` before adding the adapter. The producer branch itself is not modified.

The provider-neutral registry semantics match `pc.native.control.v1` as published by help-pc-2 `agent/pc-native-mcp@73b2171cdd7c37b51b8ab2d8c4c8d55d70bb67e0`. There is no runtime import or source dependency on help-pc-2. The static registry digest is:

`58b2bde8c6a49825747dcd7010f105dad0b6d548c7e8341cdafb32d2319f6dcd`

## Device hello and capability binding

`ExecutorRemoteDispatcher.capability_manifest()` returns:

- `contract_version=pc.native.tool_registry.v1`
- `protocol_version=pc.native.control.v1`
- the static native tool-registry digest
- the exact current `pc_executor.capabilities.v1` contract version
- the exact current Executor attestation digest
- the exact set of Executor actions currently advertised as supported

`DeviceAgent` hashes this full manifest into the authenticated hello. Each dispatch receives a `TransportDispatchContext` containing the device ID, session epoch, and hello-time manifest digest. The adapter recomputes the current manifest immediately before preflight. Any Executor/schema/capability drift returns `CAPABILITY_DRIFT` before Executor dispatch.

Tools in the provider-neutral registry whose Executor actions are not currently advertised are rejected before preflight/execute. This allows the same adapter to consume later native filesystem/process Executor actions without implementing their side effects in transport.

## Request envelope

The transport `request_version` and envelope `contract_version` must both be `pc.native.control.v1`.

The envelope uses the provider-neutral fields:

```json
{
  "contract_version": "pc.native.control.v1",
  "session_id": "stable-control-session",
  "request_id": "stable-logical-request-id",
  "tool": "shell.run",
  "arguments": {},
  "page": null,
  "execution_context": null
}
```

`request_id` must exactly equal the transport logical request ID. It is copied unchanged into `ActionRequest.request_id`, Executor preflight, the outcome journal, audit records, and the response.

`session_id` is stable across transport reconnects and is bound to one device identity. Transport epochs are intentionally separate: a duplicate logical request can be redelivered after reconnect without changing its fingerprint, while process/session handles remain epoch-scoped.

## Side-effect path

For a side-effecting registry entry the adapter:

1. validates protocol, request identity, device/session ownership, protected-path conformance, and handle/context epoch;
2. checks the hello-time capability manifest has not drifted;
3. requires the Executor durable outcome journal;
4. queries existing Executor outcome evidence for the exact request ID/action and refuses to re-execute if any prior dispatch evidence exists;
5. calls `Executor.preflight()` with the same request ID/action/arguments and requires `ready`;
6. for actions covered by `pc_executor.execution_context_binding.v1`, derives or accepts an epoch-bound binding and passes it unchanged to `ActionRequest`;
7. calls `Executor.execute()` exactly once;
8. requires durable side-effect outcome evidence. An unknown outcome raises `UnknownDispatchOutcome`, which native transport converts to `UNKNOWN_RECONCILE` with `automatic_replay=false`.

Expected policy/schema/capability rejections are returned as completed `pc.native.response.v1` error envelopes. They do not become false unknown-outcome records.

The adapter never calls a shell, filesystem, process, UI, input, clipboard, or system adapter directly.

## Process/session handle lifetime

Handles returned by handle-creating Executor actions are recorded with:

- provider-neutral `session_id`
- authenticated device ID
- current transport session epoch

Handle read/interact/terminate/close requests must match all three and must refer to an open handle. A reconnect creates a new transport epoch, so an old handle fails closed with `STALE_PROCESS_HANDLE`. An agent restart loses the in-memory handle registry, which also fails closed rather than assuming ownership.

Optional supplied execution-context bindings are wrapped with device ID and transport epoch. A stale wrapper is rejected before preflight. Executor still performs its own last-moment binding validation immediately before side-effect dispatch.

## Streaming

Streaming registry entries project Executor results into bounded transport bytes:

- `fs.read_text`: UTF-8 content when present;
- `fs.read_bytes`: validated base64 decoded to raw bytes;
- process/session output and other streaming results: canonical JSON bytes.

The adapter enforces the total stream bound. `DeviceAgent` then applies the existing transport manifest, per-chunk SHA-256, whole-stream SHA-256, ordered chunk indices, chunk bounds, and end-of-stream verification.

## Protected target invariant

Arguments that resolve to `E:\\manhwa` or a descendant are rejected with `PROTECTED_PATH_BLOCKED` before Executor preflight or execution. This is a fail-closed conformance guard and does not replace Executor policy. Tests use only path strings and spies; they do not access the target.

## Failure semantics

The integration suite covers:

- disconnect after Executor dispatch and result loss;
- duplicate logical request after reconnect;
- unknown Executor side-effect outcome;
- stale transport epoch;
- stale execution-context epoch;
- capability drift after hello;
- process output plus stale process handle after reconnect;
- bounded file-read streaming through transport chunk verification;
- protected target reject-before-access;
- real Executor preflight, execution-context binding, outcome journal and audit using replay adapters.

No merge, release, public deployment, or secret material is part of this branch.
