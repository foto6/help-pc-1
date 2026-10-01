# R27 relay progress-evidence binding report

Authority: `foto6/help-pc-1` branch
`agent/pc-relay-r27-evidence-delivery-20261001`, exact start
`96d453bcdc866bfd26c06ad88e2ec0c033fbccdd`.

## Delivery contract

R27 adds one read-only delivery mechanism:

```
python tools/read_relay_progress_evidence.py --repo <dedicated-relay-checkout>
```

The reader opens only `.pc-relay/progress.v1.json` with a bounded single-file
read, validates the frozen R26 `pc_relay.progress.v1` record, derives
`pc_relay.liveness_probe.v1` from that exact in-memory object, and emits one
`pc_relay.progress_evidence.v1` JSON line to stdout.

It performs no Git operation, queue scan, request acknowledgement, lease,
retry, replay, Executor call, outcome-journal lookup, environment read, process
enumeration, relay restart, or launcher action.

## Atomic binding

A successful envelope contains one binding tuple:

- relay startup HEAD;
- relay script SHA-256;
- relay PID and process start time;
- relay process-instance ID;
- loop generation ID;
- loop epoch;
- progress-record timestamp;
- consumer observation timestamp;
- canonical progress SHA-256;
- canonical envelope SHA-256.

The liveness generation, epoch and PID must match that same progress record.
There is no second progress-file read during derivation, so a consumer cannot
receive progress from one generation and liveness from another.

The R26 writer already commits `progress.v1.json` by atomic replacement. R27
does not alter that producer or any R26 request/result behavior.

## Fail-closed delivery

No partial progress/liveness object is emitted on failure. The envelope uses
`status=blocked` and one bounded classification:

`missing_snapshot`, `oversized_snapshot`, `invalid_json`,
`unknown_version`, `schema_invalid`, `source_identity_invalid`,
`stale_snapshot`, `future_snapshot`, `atomic_binding_invalid`, or
`read_error`.

Default snapshot bound: 64 KiB; hard caller-selectable bound: 1 MiB.
Default freshness: 30 seconds; hard maximum: 300 seconds. A currently executing
bounded request may remain fresh through its declared request deadline plus one
poll interval. Evidence more than five seconds in the future is rejected.

A relay startup HEAD of `unknown` is rejected for source-bound delivery.

## UNKNOWN / at-most-once preservation

Reading the evidence does not inspect `.pc-relay/state`, queue request files,
result files or the Executor outcome journal. Therefore a pending side-effect
whose outcome is UNKNOWN remains UNKNOWN. R27 cannot acknowledge it, create a
lease, retry it, authorize replay, or transform reconciliation-required state.

Duplicate process evidence remains
`duplicate_processes_ambiguous`; the reader does not resolve ownership.

## Secret boundary

The envelope contains only fields already committed by the strict R26 progress
and liveness schemas plus delivery source/binding/digest fields. It never
includes request parameters, environment variables, auth headers/tokens,
credentials, raw shell command lines, state-file bodies, result-file bodies or
broad process inventory.

## Native MCP pin set

Future Native MCP R27 should pin the exact Git blob IDs in
`conformance/pc_relay.progress_evidence.v1/manifest.json`, validate
`schemas/pc_relay.progress_evidence.v1.schema.json`, and reject any runtime
reader/module SHA-256 that is not associated with its approved source build.

The authoritative example is
`tests/fixtures/relay_progress_evidence_v1/evidence.example.json`.

**NO_LIVE_CUTOVER.** R27 is a read-only delivery implementation and does not
authorize replacing or repointing the installed relay.
