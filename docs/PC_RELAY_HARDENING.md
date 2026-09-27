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

## Automated zero-loss migration

The safe migration steps are automated by `tools/pc_relay_migrate.py`. The helper never starts the live relay, never deletes the prototype checkout or history, never force-pushes, and refuses protected paths such as `E:\manhwa`.

Before running the mutating migration command, stop only the currently-running prototype relay process during a controlled migration window. This freezes the local/remote prototype SHA while the helper inventories the queue. The helper itself does not stop that process.

The Windows-first defaults are:

- prototype checkout: `E:\pc-github-relay`
- implementation checkout: `E:\pc-relay-hardening`
- queue checkout: `E:\pc-relay-queue`
- repository: `https://github.com/foto6/help-pc-1.git`
- prototype ref: `agent/pc-github-relay`
- implementation ref: `agent/pc-relay-hardening`
- queue ref: `agent/pc-relay-queue`

Always pin the exact CI-proven implementation SHA. First run the no-mutation plan:

~~~powershell
py tools\pc_relay_migrate.py --expected-implementation-sha <EXACT_GREEN_SHA> --plan
~~~

Then run the safe migration checks:

~~~powershell
py tools\pc_relay_migrate.py --expected-implementation-sha <EXACT_GREEN_SHA>
~~~

Repository URL, remote name, refs, checkout paths, and report path all have explicit CLI overrides. `--dry-run` is an alias for `--plan`.

The helper performs these operations fail-closed:

1. verifies the prototype is a clean dedicated checkout with the expected remote;
2. fetches the prototype ref and requires local HEAD to equal the exact remote SHA;
3. records every request/result path, byte length, SHA-256, logical id, version, and action;
4. detects duplicate logical IDs;
5. verifies the requested implementation SHA is exactly the current implementation-ref SHA and clones/reuses a separate clean implementation checkout;
6. creates `agent/pc-relay-queue` from the frozen prototype SHA with a normal non-force push, or verifies/reuses an existing descendant queue ref;
7. creates/reuses a separate clean queue checkout and allows only fast-forward reconciliation;
8. verifies request and result inventories byte-for-byte against the prototype snapshot;
9. records unresolved legacy `pc_relay.request.v1` requests without results as a conversion plan; it never rewrites or silently converts those requests;
10. runs `pc_relay.py --once --health-only` in dry-run mode, so queue/executor health is checked without dispatching queued requests;
11. validates heartbeat schema, queue reachability, executor availability, queue-integrity state, queue ref, and exact implementation SHA;
12. re-verifies published result bytes after the health check and writes the durable migration report outside all three worktrees.

The migration report defaults to `%LOCALAPPDATA%\pc-relay-hardening\migration-report.json` on Windows. Reruns are idempotent only when the frozen prototype snapshot, refs, expected implementation SHA, existing checkouts, and report identity still match. Any mismatch fails closed.

If unresolved legacy v1 requests remain, the helper prints a conversion plan and exits with live cutover blocked. The operator must manually create reviewed v2 requests with new request digests, then rerun the helper. No live-start command is emitted while that blocker exists.

When every check passes, the helper prints exactly one final live-start command. It does not execute it. The command format is:

~~~powershell
py E:\pc-relay-hardening\tools\pc_relay.py --implementation-repo E:\pc-relay-hardening --queue-repo E:\pc-relay-queue --queue-ref agent/pc-relay-queue --live
~~~

### Rollback

Before live cutover, rollback is simply to leave the hardened relay stopped. The prototype checkout, prototype ref, historical request/result bytes, and queue ref are retained unchanged; do not delete or rewrite them.

After a live validation run, stop the hardened relay before changing transport ownership. Preserve the dedicated queue ref and its results as audit evidence. Reconcile all results produced since the frozen prototype snapshot before directing any producer back to the prototype transport. Never reset or force-push either history as a rollback mechanism.

No merge or release is part of migration.
