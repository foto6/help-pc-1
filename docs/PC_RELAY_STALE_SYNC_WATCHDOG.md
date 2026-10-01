# PC Relay stale-sync watchdog

This milestone addresses the 2026-10-01 stale-sync incident recorded in
`docs/PC_RELAY_STALE_SYNC_INCIDENT_2026-10-01.md`.

The incident proved that a live Python process is not sufficient evidence that
the GitHub-backed relay is consuming queue work. The watchdog therefore separates
process existence from forward progress.

## Machine-readable states

The read-only status command emits `pc_relay.watchdog_status.v1`:

~~~text
py tools\github_relay.py --repo <dedicated-relay-checkout> --status \
  --observed-process <pid>:<parent-pid> [...]
~~~

States:

- `PROCESS_MISSING`: no matching relay process was supplied by the caller.
- `PROCESS_EXISTS`: a matching process exists, but health/identity is
  insufficient to prove forward progress.
- `HEALTHY`: one logical relay tree is observed and health/sync/cycle evidence
  is fresh.
- `STALE`: the relay is alive but freshness or queue/Git forward progress has
  exceeded the configured bound.
- `RECONCILIATION_REQUIRED`: an interrupted side effect remains unresolved.
- `DUPLICATE_AMBIGUOUS`: more than one independent logical relay root matches.

A normal Windows `py.exe -> python.exe` parent/child chain is one logical relay,
not a duplicate.

## Durable producer health

`.pc-relay/health.json` uses `pc_relay.health.v1` and records:

- relay PID, start time and current phase;
- last successful fetch/sync;
- last completed cycle;
- last request processed and request ID;
- last result published and result ID;
- local HEAD;
- observed remote-tracking HEAD and observation time;
- request/result/backlog counts;
- last backlog-change time and backlog high-water mark;
- bounded/redacted last error;
- reconciliation-required state.

Long-running request/reconciliation phases use a bounded extended freshness
window; they are not treated as indefinitely healthy.

## Stale-sync evidence

The status reader performs no network fetch. It uses only read-only local Git
observations:

- `git rev-parse HEAD`;
- `git rev-parse origin/<relay-branch>`;
- `git merge-base --is-ancestor` to classify local-vs-remote relation;
- `git ls-tree` on the remote-tracking ref to count queued requests/results.

This means a successful manual `git fetch` that advances the local
remote-tracking ref immediately becomes evidence available to the watchdog,
without the watchdog mutating Git itself.

A stale determination can include:

- health record age exceeded;
- local HEAD still behind the remote-tracking HEAD;
- remote-tracking HEAD advanced since the relay's last sync;
- remote backlog increased while completed-cycle progress remained stale.

## Launcher behavior

`tools/start_pc_control_relay.ps1` enumerates only matching relay command lines,
passes PID/parent-PID identities to the Python status command, and consumes the
same status contract.

If a matching process tree exists:

- `HEALTHY` returns idempotent success;
- any other state is surfaced to the operator;
- no process is killed;
- no process is automatically restarted.

If no matching process exists, an explicit operator launch may start a new relay,
after which the launcher requires fresh watchdog evidence.

## Safe recovery

For `STALE`, `PROCESS_EXISTS`, `DUPLICATE_AMBIGUOUS`, or
`RECONCILIATION_REQUIRED`:

1. Preserve `.pc-relay/state`.
2. Preserve `.pc-relay/outcomes.jsonl`.
3. Do not submit replacement side-effect request IDs.
4. Verify ownership of the stale logical process tree.
5. If an operator chooses to stop/restart it, do so only after ownership is
   confirmed and only after the old tree is absent.
6. Restart through the launcher.
7. Existing started side effects must reconcile through `outcome.lookup`.
8. Recovery of liveness never authorizes replay.

The watchdog itself contains no automatic production restart or kill path.

## Secret boundary

Health/status output contains no environment dump, auth token, request
parameters, or raw shell command line. Error text is bounded and redacts
credential-like URL userinfo and token/password/authorization assignments.

## Future browser attachment handoff invariant

Direct video files may be supplied to ChatGPT for semantic/editorial review, up
to the current working constraint of 500 MB per attached file.

For a future PC Executor/relay browser-bridge attachment handoff:

- upload must be bounded and journaled;
- upload request identity must remain stable;
- an unknown upload outcome must reconcile before retry;
- a large upload must never be blindly duplicated;
- attachment handoff must not weaken existing at-most-once side-effect semantics.

This milestone records that invariant only. It does not implement browser upload.

## Conformance

Authoritative contracts:

- `conformance/pc_relay.health.v1/schema.json`
- `conformance/pc_relay.health.v1/manifest.json`
- `conformance/pc_relay.watchdog_status.v1/schema.json`
- `conformance/pc_relay.watchdog_status.v1/manifest.json`

**NO_LIVE_CUTOVER.**
