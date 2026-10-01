# R27 exact relay progress-evidence delivery

R27 adds a local read-only stdio reader for the R26 relay health producer. It
does not modify the relay loop, launcher, queue semantics, at-most-once
behavior, or UNKNOWN/reconciliation behavior.

## Consumer command

~~~text
python tools/read_relay_progress_evidence.py --repo <dedicated-relay-checkout>
~~~

Optional `--observed-pid` values are caller-supplied observations. The reader
does not enumerate processes itself.

Success emits one `pc_relay.progress_evidence.v1` JSON object with:
`pc_relay.progress.v1`, a liveness object derived from that exact same parsed
snapshot, source/process/generation binding fields, observation time, and
canonical SHA-256 digests.

Blocked reads emit the same envelope version with no partial progress or
liveness content.

## Read-only guarantees

The delivery path reads only the fixed
`.pc-relay/progress.v1.json` file. It does not:

- enumerate or consume relay request files;
- acknowledge requests or create leases;
- invoke retry/replay or Executor operations;
- inspect outcome state/journal files;
- fetch, rebase, commit or push Git;
- read environment variables or credentials;
- read raw shell commands or request parameters;
- start, stop or restart the relay.

A pending side-effect remains reconciliation-required exactly as R26 defined
it. Recovery of relay liveness never authorizes replay.

## Conformance

Authoritative files:

- `schemas/pc_relay.progress_evidence.v1.schema.json`
- `conformance/pc_relay.progress_evidence.v1/manifest.json`
- `conformance/pc_relay.progress_evidence.v1/binding-report.md`
- `tests/fixtures/relay_progress_evidence_v1/evidence.example.json`

The conformance manifest pins the exact source blobs for the reader, evidence
module, frozen R26 progress implementation, and all three schemas.

## Freshness and corruption

Default maximum snapshot age is 30 seconds and default read bound is 64 KiB.
Torn JSON, unknown versions, strict-schema drift, invalid source identity,
staleness, future timestamps and atomic-binding mismatches fail closed with
bounded classifications and no partial evidence.

## Isolation

No live relay checkout is required to build or test R27. CI uses only temporary
synthetic fixtures. There is no deployment or cutover operation in this
milestone.

**NO_LIVE_CUTOVER.**
