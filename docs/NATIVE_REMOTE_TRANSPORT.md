# Native Remote PC Transport v1

`pc_remote_transport` replaces Git-backed request/result polling with an authenticated,
outbound, persistent device connection. The GitHub relay remains historical break-glass
fallback only; the native transport never reads or writes commits, issues, or repository
files as RPC state.

## Layering

The transport layer owns only delivery concerns:

- device identity and per-device authentication;
- persistent connection lifecycle, heartbeats, reconnect/backoff and session epochs;
- `pc_remote_transport.frame.v1` framing;
- request/delivery IDs, replay defense and crash-durable delivery state;
- bounded byte streams with per-chunk and whole-stream SHA-256 metadata;
- transport errors and `UNKNOWN_RECONCILE` outcomes.

It does **not** define Executor actions, Desktop Commander tools, shell commands, or
control-plane schemas. `DeviceAgent` receives an injected `Dispatcher`. Request `body`
and advertised capability content are opaque objects to the transport. The integration
layer is responsible for validating its own versioned control schema before dispatch.

This separation is deliberate: adding a transport must never create a second policy or
execution path around Executor.

## Connection lifecycle

1. The device opens an outbound `wss://` connection. Plain `ws://` is rejected except
   when explicitly enabled for loopback tests.
2. The device creates a fresh session epoch and sends an HMAC-authenticated `hello`
   containing opaque capabilities, a capabilities digest, and negotiated local bounds.
3. The relay returns an HMAC-authenticated `welcome` echoing the hello nonce and epoch.
4. Each direction uses strictly increasing frame sequence numbers inside the epoch.
5. Idle device sessions send heartbeat frames. Relay heartbeats are acknowledged.
6. Disconnects close the current epoch. `run_forever` reconnects with deterministic
   bounded exponential backoff and a fresh epoch.

The HMAC token must be unique per device. TLS protects confidentiality; the message HMAC
provides device/relay possession proof and message integrity. Secrets are configuration,
never repository content.

## Request and replay rules

A request frame carries:

- `request_id`: stable logical request identity;
- `request_version`: application/control schema version;
- `delivery_id`: delivery-attempt identity;
- `semantics`: `read_only` or `side_effecting`;
- `body`: opaque application request object.

`delivery_id` may change on redelivery; it is intentionally excluded from the logical
request fingerprint. Reusing a `request_id` for different request content is rejected.

Before invoking the injected dispatcher, the device atomically records
`dispatch_started`. On completion it atomically records the exact response and optional
bounded stream bytes. Therefore:

- duplicate delivery after completion returns the cached result without dispatch;
- a read-only request interrupted before completion may be safely dispatched again;
- a side-effecting request found in `dispatch_started`/`reconcile_required` state is
  never automatically dispatched again;
- instead the device returns `UNKNOWN_RECONCILE`, requiring the application/control
  layer to perform its outcome lookup/reconciliation protocol.

A network disconnect after local completion does not cause re-execution: the durable
completed record is replayed on the next delivery. A process/power failure between
durable `dispatch_started` and durable completion becomes `UNKNOWN_RECONCILE`.

## Streaming

`DispatchResult` may include bounded bytes tagged with an application-neutral stream
kind such as `file_read` or `process_output`. The transport sends:

1. a response containing a stream manifest;
2. ordered `stream_chunk` frames;
3. a `stream_end` frame.

The manifest records total bytes, chunk size/count and whole-stream SHA-256. Every chunk
records index, byte count and SHA-256. `StreamAssembler` rejects duplicate/reordered
chunks, corrupt base64, chunk digest mismatch, missing chunks, total-size mismatch and
final digest mismatch.

Defaults:

- frame: 1 MiB;
- request body: 512 KiB;
- chunk: 64 KiB;
- total stream: 8 MiB.

Bounds are intentionally conservative and can be negotiated downward by deployment.

## Token rotation

The relay can send `token.rotate`, authenticated with the current generation. The
generation must increase by exactly one. The device replaces the token in memory and
acknowledges with `token.rotated` authenticated by the new generation. Production
integration should persist the rotated token atomically in a platform secret store
before acknowledging; the transport core intentionally accepts a `TokenRing` abstraction
rather than choosing a secret-storage backend.

## Kill switch

`RemoteTransportSettings.from_env()` defaults `PC_NATIVE_REMOTE_TRANSPORT=0`. Operators
must explicitly enable native transport. Removing/disabling that flag stops reconnect
attempts when it is used as the `DeviceAgent.run_forever(enabled=...)` predicate.

The kill switch disables only transport. It does not bypass or change Executor safety.
