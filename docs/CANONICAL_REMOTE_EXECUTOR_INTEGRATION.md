# Canonical Remote Executor Integration

## Inputs

- Repository: `foto6/help-pc-1`
- Branch: `agent/pc-native-executor-integration-final`
- Exact canonical base: `e47908e2c734984a872f3cc087731f4690d1c82c`
- Source adapter candidate: `30d7cb0f0571c3bd1565fd6b96c069ef64f3d9dd`
- Adapter stack root: `8df29aad32a6cb142dff6721f92fca74a080e441`
- Historical relay line: `992c66335c9e6c40d150bc10c086e97ea7600d48`
- Historical relay/current-Executor merge-base: `d0ccb0f390474fc3fc091e51c25f7ef8771b0f09`

## Port decision

The source candidate contains nine commits after the old transport snapshot. Its first commit pins Executor execution-context files from the current Executor producer. Those files are already authoritative on the canonical base and are excluded from this port.

Only the adapter delta is reapplied: transport session context, adapter module/exports, adapter tests including recovery coverage, adapter documentation, and CI wiring.

No merge commit is used. The resulting integration commit has `e47908e2c734984a872f3cc087731f4690d1c82c` as its only parent.

## Executor invariants

Every tracked `src/pc_executor/**` blob is inherited byte-for-byte from the canonical base. No preflight, context-binding, outcome-journal, capability, policy, or audit implementation is replaced.

The adapter calls the existing Executor boundary; it does not implement direct filesystem, process, shell, UI, input, clipboard, or system side effects.

There is no `github_relay` runtime dependency.

## Required behavior covered

Focused adapter/recovery tests cover the provider-neutral registry digest, exact Executor capability digest in device hello, request-ID preservation, durable idempotency/recovery, session epoch and stale-context rejection, `UNKNOWN_RECONCILE`, response-loss duplicate delivery, process/file streaming, and protected-path reject-before-dispatch behavior.

The existing native transport tests/harness remain enabled, as do current preflight and execution-context focused suites.

## CI matrix

Both `ubuntu-latest` and `windows-latest` run:

1. canonical ancestry/diff audit;
2. focused preflight;
3. focused execution-context binding;
4. focused native transport tests;
5. native transport harness;
6. focused native remote Executor adapter + recovery tests;
7. full suite.

The audit additionally verifies exact source-candidate blob provenance and `git diff --check`.
