# R26 PC Control Relay Queue Progress / Liveness

Repository: `foto6/help-pc-1`  
Branch: `agent/pc-relay-r26-progress-health-20261001`  
Exact base: `4ce8901221ad994ae5b44299d6601e1c9cc6a047`

R26 is an isolated producer hardening change. It does not deploy, restart, repoint,
replace, or inspect the currently running production relay checkout. The live
relay/launcher remains read-only during this work.

## Progress contract

The relay writes a local-only `.pc-relay/progress.v1.json` record using
`pc_relay.progress.v1`. The path is already ignored by Git, so queue health
does not create background repository commits.

The record binds runtime observations to:

- repository and configured branch;
- startup Git HEAD;
- SHA-256 of the loaded relay script;
- process PID, process-instance token and start time;
- loop generation ID and monotonically increasing loop epoch.

It reports the last successful fetch, last request observed, last result commit,
last successful complete cycle, consecutive cycle failures, queue pending count,
oldest pending request and age, queue-result progress timestamp, current cycle
state/deadline, and one bounded/redacted error classification.

Request parameters, environment variables, credentials, raw shell arguments,
and broad process inventory are not present in the health record.

## Read-only health probe

The following command reads only the local bounded progress record:

~~~text
python tools/github_relay.py --repo <dedicated-checkout> --health
~~~

It does not fetch, rebase, push, execute a queue request, enumerate processes,
read environment secrets, or mutate the relay. An external launcher may add
`--observed-pid` values that it already obtained from its narrowly scoped
relay-process match.

Normal liveness output is `pc_relay.liveness_probe.v1`.

Important classifications:

- `healthy_progressing`: observed process identity matches and cycle/queue
  progress is within the configured bound;
- `alive_stalled`: the process still exists but the progress record, successful
  cycles, or pending-result progress exceeded the stall bound;
- `duplicate_processes_ambiguous`: more than one matching relay process;
- `alive_ambiguous_identity`: the progress PID and observed process disagree;
- `stale_record_no_process`: a progress record remains but no matching process
  exists.

PID existence by itself is never sufficient for `healthy_progressing`.

## Launcher behavior

`tools/start_pc_control_relay.ps1` now queries the same read-only liveness
contract before treating an existing process as healthy.

- One matching + progressing process: idempotent success.
- One matching but stalled/ambiguous process: fail closed; no automatic restart.
- Multiple matching processes: ambiguous duplicate state; no automatic kill.
- No matching process: the launcher may start a new relay, then requires a
  current progress record for the new PID.

The launcher contains no `Stop-Process` or `taskkill` recovery path for
ambiguous ownership.

## Bounded Git recovery

Fetch uses at most three attempts with bounded backoff for classified transient
network/Git-lock failures. A failed push is retried at most three times.

A non-fast-forward push performs the existing fetch/rebase reconciliation before
retrying. Rebase conflicts are bounded, aborted, classified
`rebase_conflict`, and require explicit reconciliation.

Two durable recovery forms are preserved without request replay:

1. a result file written but not committed is recovered from the bounded dirty
   result scan;
2. a clean local result commit left ahead of origin after process interruption
   is pushed directly after restart. No second result commit and no Executor
   request execution are needed.

Stale relay-owned rebase markers are aborted before a new rebase attempt.

## At-most-once side effects

The request ID remains the logical operation identity. Existing local
`.pc-relay/state/<id>.json` and Executor outcome-journal semantics are
preserved.

If a side-effect request is found in `started` state after interruption, R26
does not execute it again. It performs `outcome.lookup` and emits
`interrupted_requires_reconciliation`, `reexecuted=false`, and
`replay_authorized=false`.

Liveness recovery never changes that rule.

Read-only operations may retain the pre-existing safe retry behavior.

## Bounded queue work

Only 64 pending request paths are retained for one processing batch even when
the queue is larger. Queue health still reports the full streaming pending
count and oldest pending age. Dirty result recovery is also capped at 64 files
per cycle.

The synthetic chaos suite exercises 1000 logical side-effect request
lifecycles, injected fetch failures, injected post-effect push failures,
restart, stale rebase markers, duplicate/stale process classification and
pending requests across restart. It verifies:

- every logical request receives a result;
- one result commit per request;
- one side effect per logical request;
- no request loss after recoverable transport faults;
- eventual resumption;
- bounded batch memory and bounded progress-record size.

## Consumer artifacts

- `schemas/pc_relay.progress.v1.schema.json`
- `schemas/pc_relay.liveness_probe.v1.schema.json`
- `tests/fixtures/relay_progress_v1/progress.example.json`
- `tests/fixtures/relay_progress_v1/manifest.json`

The manifest pins the exact producer Git blobs and the base SHA so consumers do
not need to guess field names or source provenance.

## Scope limit

R26 proves isolated relay logic and cross-platform deterministic tests. It does
not prove the currently installed production relay is running this code, and it
does not authorize replacement of the live checkout.

**NO_LIVE_CUTOVER.**
