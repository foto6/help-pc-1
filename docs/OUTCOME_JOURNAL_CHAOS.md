# Outcome Journal Chaos Reliability

This milestone stress-tests the frozen `pc_executor.action_outcome.v1` evidence contract and
the hash-chained `pc_executor.outcome_journal.record.v1` journal. It does not change action
assignment or execution semantics.

## Deterministic stress profile

The harness at `tools/outcome_journal_chaos.py` uses seed `0x5A17C0DE` and emits 10,002
records for 3,334 request IDs. Every logical request has a proven-not-started attempt followed
by a dispatched/completed attempt, covering multiple side-effecting action names while preserving
the production record hash chain.

The harness reopens the journal 12 times from cold `OutcomeJournal` instances. Lookup bytes are
hashed before and after recovery and must remain byte-identical. Recovery only parses journal
evidence; it has no adapter execution path.

## Fault model

Fake storage injects disk-full before write, partial writes at six boundary classes (zero, first
byte, first quarter, half, penultimate byte, and before LF), and a failure after a complete append
but before the simulated durable-flush boundary. Partial provisional and partial terminal records
must resolve to `unknown`; they may never create `completed` evidence. Duplicate identical terminal
evidence is idempotent, while a physically duplicated terminal record makes the journal corrupt and
therefore `unknown`. Conflicting terminal evidence, request/action reuse, truncated tails, and
terminal-before-dispatch correlation fail closed.

Process-local concurrent writers are supported through the existing per-path re-entrant lock and are
covered with eight threads. Cross-process multi-writer serialization is not claimed by this journal;
deployments must keep one journal writer process per path.

## LF / CRLF policy

Production writes are binary and explicitly LF terminated. Frozen fixtures remain byte-for-byte LF
files. Raw SHA-256 therefore continues to describe exact stored bytes.

`canonical_journal_sha256()` is a transport-comparison utility only: it maps CRLF to LF before
hashing and rejects bare CR bytes. It does not rewrite files, alter record hashes, or change frozen
contract semantics. Equivalent LF and CRLF copies therefore compare canonically across Windows and
Linux while their raw byte hashes remain distinct.

## Performance gate and report

The checked-in `docs/outcome_journal_reliability_report.json` records seed, counts, raw/canonical
journal hashes, frozen outcome hashes, fault-case counts, runtime identity, and measured replay
latency. The stress test enforces a generous 15-second bound for one 10k-record lookup and a
60-second bound for 12 cold reopens so CI catches pathological replay regressions without depending
on workstation-specific microbenchmarks.

Reproduce the report with:

`python tools/outcome_journal_chaos.py --report docs/outcome_journal_reliability_report.json --work-dir .reliability-work --records 10002 --reopens 12`

The generated work journal is disposable and must not be committed.
