# Migration: `github_relay.py` to Native Remote Transport

The existing GitHub relay is retained unchanged as historical break-glass fallback.
Native transport is a new lane; Git commits/issues/files are not used as RPC.

## Phase 1 — shadow connectivity

Keep `PC_NATIVE_REMOTE_TRANSPORT=0` by default. Provision a per-device token outside the
repository, configure a `wss://` relay endpoint, and connect a `DeviceAgent` with a
read-only dispatcher/capability provider. Verify:

- authenticated hello/welcome and heartbeat behavior;
- capability digest/version agreement;
- reconnect creates a fresh epoch;
- replay/stale-epoch rejection;
- stream bounds and digest validation.

Do not dual-submit side-effecting requests to native and GitHub transports.

## Phase 2 — request parity

Bind the provider-neutral control/MCP facade to `DeviceAgent.Dispatcher`. The binding
owns control-schema validation and maps accepted requests to Executor. The transport
must remain unaware of shell commands, filesystem policy, UI policy, or Executor action
names.

Run the same request IDs through deterministic read-only fixtures and compare normalized
control-layer results. For side-effecting tests, use fake/injected Executor adapters and
verify at-most-once behavior through both the transport ledger and Executor outcome
journal.

## Phase 3 — cutover

1. Stop producing new GitHub relay requests.
2. Let the GitHub relay drain already accepted requests.
3. Reconcile every side-effecting request whose result is not durably known.
4. Start native relay routing and enable the device kill switch:
   `PC_NATIVE_REMOTE_TRANSPORT=1`.
5. Observe heartbeats, capability negotiation and request completion.
6. Leave `tools/github_relay.py` stopped. It is not a secondary live consumer.

Native cutover is complete only when the coordinator/control plane addresses devices
through the relay endpoint and no RPC request/result state is being written to Git.

## Kill switch and fallback

If native transport must be disabled, set `PC_NATIVE_REMOTE_TRANSPORT=0` (or make the
runtime `enabled` predicate false), close the persistent connection, and stop native
routing. Before activating the historical GitHub relay:

1. quiesce native submissions;
2. enumerate requests accepted by native transport;
3. for any side-effecting request without a durable completed result, perform
   application/Executor outcome lookup;
4. carry forward only reconciled terminal results or new logical request IDs for actions
   proven not dispatched;
5. start the GitHub fallback lane manually.

Never run native and GitHub transports as competing consumers for the same side-effecting
request. Never convert `UNKNOWN_RECONCILE` into a retry.

## Removal criteria for historical fallback

The GitHub relay can be archived after native transport has demonstrated:

- capability/schema parity with the control facade;
- restart/reconnect durability;
- token rotation/revocation operations;
- bounded stream behavior under sustained process/file output;
- reconciliation after injected crash windows;
- production relay observability and incident runbooks.

Archival/removal is a separate change; this branch does not merge or release it.
