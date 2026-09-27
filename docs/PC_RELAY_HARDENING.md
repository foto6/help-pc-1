# PC Relay Hardening

This branch contains immutable relay implementation, tests, schemas, and operating documentation only. It must never carry request/result traffic.

The hardened topology is:

`ChatGPT/coordinator -> dedicated queue ref/worktree -> tools/pc_relay.py -> pc_executor.Executor -> outcome journal -> queue result`

The relay reuses Executor policy and adapters. It does not duplicate or weaken Executor's preflight, protected-path, sensitive-entry, context-binding, timeout, or outcome-journal decisions.

## Immutable implementation vs mutable queue

Implementation branch: `agent/pc-relay-hardening`.

Dedicated queue ref: `agent/pc-relay-queue` (recommended name; create it only during the migration procedure below).

Run the relay code from a clean implementation checkout and point `--queue-repo` at a **different** dedicated queue checkout. The CLI refuses to use one checkout for both roles.

Queue-owned paths are limited to:

- `relay/requests/<id>.json` — immutable producer request.
- `relay/results/<id>.json` — immutable relay result.
- `relay/quarantine/<name>.<digest>.json` — metadata only; malformed raw content is not copied.
- `relay/heartbeat/<relay-id>.json` — mutable read-only health observation.

Durable machine state is deliberately outside Git. By default it is under `%LOCALAPPDATA%\pc-relay-hardening` on Windows or the platform state directory elsewhere. It contains request state, queue ancestry history, Executor audit, and the Executor outcome journal.

## Protocol

Request contract: `pc_relay.request.v2`.

Result contract: `pc_relay.result.v2`.

Heartbeat contract: `pc_relay.heartbeat.v1`.

Queue ancestry metadata: `pc_relay.queue.v1`.

A request ID is immutable. A request must carry `request_sha256`, the SHA-256 of canonical JSON (sorted keys, compact separators, UTF-8) after removing only the `request_sha256` field. The filename stem must equal the ID.

Results carry the request digest and a self-digest `result_sha256` computed the same way after removing only `result_sha256`. An existing result with different content is a hard conflict and is never overwritten.

Schema files:

- `schemas/pc_relay.request.v2.schema.json`
- `schemas/pc_relay.result.v2.schema.json`
- `schemas/pc_relay.heartbeat.v1.schema.json`

## At-most-once and reconciliation

The relay writes durable local state before dispatch. Side-effecting requests that are found in `dispatch_started` state after a restart are reconciled against Executor's outcome journal before any new dispatch.

- `completed`: publish `reconciled_completed`; never replay.
- `unknown`: publish `reconciliation_required`; never replay.
- `not_started`: one bounded re-execution is allowed and is recorded as `reexecuted=true`.
- Read-only actions may be repeated because they do not cross a side-effect boundary.

If Executor completes but Git commit/push later fails, the finished local result remains durable. Subsequent cycles publish that result without calling Executor again.

## Transport safety

The relay's maximum action surface is fixed in code. It includes the prototype read-only actions plus `shell.run`; flags can only reduce this set.

Raw coordinate fallback is always disabled.

Credential-bearing UI actions such as `keyboard.type_text`, `clipboard.set`, and `uia.set_value` are not exposed by the relay allowlist. Obvious interactive credential/CAPTCHA PowerShell/cmd forms and encoded PowerShell commands are rejected at the transport boundary.

PowerShell and cmd are added only to the relay-local `SafeShellAdapter`. `pc_executor.safety.DEFAULT_SAFE_EXECUTABLES` is unchanged.

Executor's `E:\manhwa` protected-path checks remain authoritative for argv and cwd. The relay invokes those same checks before a shell request is accepted.

Request size is capped at 64 KiB, request timeout at 120 seconds, result transport payload at 512 KiB, and shell stdout/stderr at 64 KiB each. Common secret-bearing keys and key/value output forms are redacted before result publication. Do not intentionally print credentials or tokens into shell output.

## Queue integrity and restart behavior

Each successful sync persists the last-seen remote queue SHA outside Git. If a later remote SHA no longer descends from it, the relay fails closed with force-push detection.

Normal fast-forward queue updates are accepted. If a local transport publication races with a concurrent remote update, only relay-owned local traffic commits may be discarded and regenerated from durable state. Non-transport local divergence is rejected.

SIGINT/SIGTERM requests clean shutdown. The final heartbeat is published with `relay_alive=false` when the queue is still reachable.

Heartbeat fields let a coordinator distinguish relay process state, queue reachability, Executor availability, queue-history integrity, last processed request, current implementation SHA, queue ref, and queue remote SHA. Heartbeat publication is cadence-bounded to 30 seconds by default (`--heartbeat-seconds`) so the queue does not advance on every poll.

## Windows runbook after migration

Install and test the immutable implementation checkout:

~~~powershell
cd E:\pc-relay-hardening
py -m pip install -e ".[test]"
py -m pytest tests\test_pc_relay.py
~~~

Start dry-run first:

~~~powershell
py tools\pc_relay.py --implementation-repo E:\pc-relay-hardening --queue-repo E:\pc-relay-queue --queue-ref agent/pc-relay-queue --once
~~~

Persistent live mode is explicit:

~~~powershell
py tools\pc_relay.py --implementation-repo E:\pc-relay-hardening --queue-repo E:\pc-relay-queue --queue-ref agent/pc-relay-queue --live
~~~

## Fault matrix

The focused suite covers:

1. crash before dispatch;
2. crash after dispatch-start before result, including unknown/completed no-replay;
3. crash after Executor completion before queue push;
4. Git commit failure;
5. Git push rejection;
6. concurrent queue update;
7. malformed JSON/schema/version quarantine;
8. duplicate request ID with different content;
9. result already published / result conflict;
10. protected path attempt;
11. Windows PowerShell stdout/stderr truncation;
12. force-push detection and credential/CAPTCHA transport blocking.

All eleven requested operational fault categories are covered. The suite also includes separate force-push, result-conflict, redaction, allowlist, heartbeat, request-size, and transport-policy checks.

## Migration checklist — instructions only

Do **not** switch the running prototype in place. Perform this checklist during a controlled migration window:

- [ ] Record the exact current `agent/pc-github-relay` remote SHA.
- [ ] Stop only the prototype relay process so no new result commit can race the snapshot; do not alter its branch history.
- [ ] Fetch the prototype ref and verify its working tree is clean.
- [ ] Inventory every `relay/results/*.json` ID and SHA-256 and every queued request ID.
- [ ] Verify every already-published result has a unique request ID; preserve those result bytes as historical evidence.
- [ ] Create `agent/pc-relay-queue` as the dedicated mutable queue ref from the frozen prototype snapshot or from a filtered queue-only snapshot that preserves all published request/result bytes. Do not base it on the hardening implementation history merely to obtain code.
- [ ] Clone/worktree that queue ref into a path separate from the implementation checkout.
- [ ] Keep `agent/pc-relay-hardening` checked out separately at its CI-proven exact SHA.
- [ ] For legacy v1 requests that already have results, leave them historical and do not replay them.
- [ ] For any legacy v1 request without a result, explicitly convert it to v2 with the same semantic action/params and a new migration-recorded v2 digest before enabling live dispatch; never silently reinterpret v1 bytes.
- [ ] Compare the queue result inventory against the prototype inventory and require exact preservation of every already-published result before proceeding.
- [ ] Start the hardened relay in dry-run/`--once` mode and verify heartbeat: queue reachable, Executor available, expected implementation SHA, no force-push warning.
- [ ] Verify no request is dispatched merely because local relay state is empty; already-published result IDs must be skipped.
- [ ] Enable `--live` only after the inventory and heartbeat checks pass.
- [ ] Keep the old prototype branch unchanged as audit history until the hardened queue has processed a bounded validation request and its result is verified.
- [ ] Never merge or release as part of this migration.

This migration intentionally separates implementation CI provenance from mutable queue traffic while preserving all already-published results.
