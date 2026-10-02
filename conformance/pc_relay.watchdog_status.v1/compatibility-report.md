# Stale-sync watchdog compatibility report

Producer repository: `foto6/help-pc-1`
Development branch: `agent/pc-relay-stale-sync-watchdog-20261001`
Exact development base: `85877d46e2d51f5d0b1c1b35abc23f032bfedbee`

## Incident compatibility

The watchdog directly covers the recorded incident shape:

| Incident evidence | Watchdog evidence |
| --- | --- |
| Python process alive | caller-supplied PID/parent-PID tree |
| `py.exe -> python3.13.exe` | collapsed to one logical relay root |
| local checkout stuck | local `HEAD` observation |
| manual fetch advanced origin ref | remote-tracking HEAD observation |
| no completed cycle | durable `last_cycle_completed_at_unix` |
| new request not consumed | remote-tracking backlog versus durable backlog |
| stderr empty | health does not depend on stderr |
| 22 missing results | bounded remote-tracking queue counts |

The status command does not fetch from the network, so it cannot accidentally
refresh or mutate the evidence it is judging.

## At-most-once compatibility

Existing `.pc-relay/state/<request-id>.json` and
`.pc-relay/outcomes.jsonl` locations are preserved across relay
reinitialization.

A side-effect request found in `started` state is never dispatched again by
the relay. It enters `RECONCILIATION_REQUIRED`, performs `outcome.lookup`,
and returns `reexecuted=false` and `replay_authorized=false`.

A healthy process after restart does not change that rule.

## Process compatibility

Launcher health is based on logical roots, not raw matching PID count. A
launcher parent and Python child are one logical relay when the child
`ParentProcessId` points at the matching parent. Independent matching roots
are `DUPLICATE_AMBIGUOUS`.

## Recovery compatibility

The launcher does not issue `Stop-Process`, `taskkill`, or an automatic
restart when a matching relay tree exists. It reports the machine-readable state
and prints the preservation/reconciliation sequence for an operator.

## Future attachment compatibility

Future browser attachment handoff is constrained to bounded, journaled,
at-most-once semantics. Unknown upload outcomes require reconciliation before
retry, and blind duplication of a large upload is forbidden. The current
working direct-chat file limit recorded by this contract is 500,000,000 bytes.

## Release boundary

This report is development/conformance evidence only.

**NO_LIVE_CUTOVER.**
