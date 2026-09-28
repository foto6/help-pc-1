# R16 — independent Executor chaos / contract conformance

- Repository: `foto6/help-pc-1`
- Isolated branch: `agent/pc-r16-executor-chaos-contracts-20260928`
- Pinned producer base: `04f817299b46ecb0ffa8aa908ce84fdb4c3300d0`
- Scope: validation/tests/CI only. No modifications to production Executor, Control, relay, transport, installer, service, or user files.

## Frozen registry evidence

`tests/fixtures/r16_executor_chaos/matrix.v1.json` freezes two **distinct** manifests:

| Contract | Expected canonical SHA-256 |
| --- | --- |
| `pc.native.tool_registry.v1` (unchanged compatibility/default) | `58b2bde8c6a49825747dcd7010f105dad0b6d548c7e8341cdafb32d2319f6dcd` |
| `pc.native.parity_tool_registry.v1` (explicit parity opt-in) | `dab7ebd65dd239519c755b0521cd2068f15ae885402e37d4885f64b9c2a08c33` |

The test recomputes canonical hashes from the actual two registry lists, compares each with its frozen independent constant and the advertised manifest, and checks exact supported action resolution and read-only/side-effect classification. Legacy operations that the OS does not advertise are required to fail `CAPABILITY_UNAVAILABLE`, not to claim parity.

## Error/evidence matrix

The 11 versioned scenarios `R16-01` through `R16-11` specify both the expected error/outcome and the required absence of unsafe dispatch. The tests exercise:

- exact compatibility versus parity action resolution;
- last-moment UIA context verification after synthetic process epoch, window handle and runtime-ID drift; zero UIA invocation and `not_started` outcome;
- completed duplicate request IDs, including a changed-payload attempt, rejected before reapplying isolated settings;
- isolated settings effect followed by injected result loss; durable journal records `unknown` and disallows replay;
- new Executor/operations/dispatcher with the same **temp-only** journal and settings to model restart/reconnect; duplicate logical identity remains reconciliation-only;
- synthetic (never spawned) managed-process handles rejected on changed transport epoch and after dispatcher restart before preflight/execute;
- protected path represented **only as a literal argument** to the remote lexical guard; spy preflight, Executor dispatch and LocalOperations dispatch all remain at zero calls.

No test calls a real Windows Service Controller, UAC, persistent OS process, arbitrary user-directory scan, or the protected filesystem path. Only `pytest.tmp_path` is writable by synthetic test operations.

## Commands

```powershell
python -m pip install -e ".[test]"
python -m pytest tests/test_r16_executor_chaos_contracts.py -v
python -m pytest
```

The existing exact-head cross-platform workflow runs on pushes to the isolated R16 branch. Because `tools/audit_native_core_final_candidate.py` correctly audits a frozen **producer** changed-file set, CI runs that unchanged audit inside a detached worktree at the pinned PC Core SHA. A separate fail-closed delta assertion permits only this R16 validation document, fixture, test and workflow change against the pinned base. This keeps the producer provenance gate authoritative instead of weakening its allowlist for test-branch additions.

## Scope limitations / blockers

This is Executor-side synthetic and deterministic contract evidence, **not** a live Windows service/Control/relay cutover. It does not prove the actual operator UI, OS process lifetime, end-to-end live-device reconnection, or production dual-backend operation. Those still require independent isolated live adapter evidence and current exact-head cross-stack gates. A green R16 CI cannot independently authorize a merge, release, service installation, or Desktop Commander removal.
