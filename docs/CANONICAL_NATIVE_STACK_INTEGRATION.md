# Canonical help-pc-1 native stack integration

## Inputs and topology

- Repository: `foto6/help-pc-1`
- Integration branch: `agent/pc-native-stack-integrated`
- Exact authoritative tool-parity base:
  `18a6496b24520bade8246dae0759306a00a5a372`
- Authoritative Executor base behind parity:
  `2cc1e40f792a3d74560b726a0d246c90b7f077e9`
- Clean native transport source:
  `e47908e2c734984a872f3cc087731f4690d1c82c`
- Adapter source candidate:
  `30d7cb0f0571c3bd1565fd6b96c069ef64f3d9dd`
- Historical old relay line:
  `992c66335c9e6c40d150bc10c086e97ea7600d48`

The integration starts exactly at the tool-parity head. Neither source candidate is
merged or cherry-picked wholesale.
## Carried unchanged from the clean transport

The following are byte-identical to `e47908e2c734984a872f3cc087731f4690d1c82c`:

- `src/pc_remote_transport/config.py`
- `src/pc_remote_transport/ledger.py`
- `src/pc_remote_transport/protocol.py`
- `src/pc_remote_transport/websocket.py`
- `tests/test_native_remote_transport.py`
- `tests/test_remote_protocol.py`
- `tools/native_remote_harness.py`
- `docs/NATIVE_REMOTE_TRANSPORT.md`
- `docs/NATIVE_REMOTE_THREAT_MODEL.md`
- `docs/NATIVE_REMOTE_MIGRATION.md`

`pyproject.toml` is reconciled manually against the parity base and adds only the
transport runtime/test dependencies.
## Adapter provenance and rebase

From `30d7cb0f0571c3bd1565fd6b96c069ef64f3d9dd`, the authenticated
`TransportDispatchContext` hook in `agent.py` and the adapter exports in
`__init__.py` are carried byte-for-byte.

The candidate `executor_adapter.py` and its adapter/recovery tests are intentionally
rebased rather than copied unchanged. The stale source expected legacy Executor
capabilities and several pre-parity action names. The integrated adapter instead:

- reads the exact current `LocalOperations` parity capabilities and digest;
- maps the remote control registry only to current `OPS_ACTIONS`;
- binds current `handle_id` / `session_id` values to authenticated epochs;
- maps current process output/session/action names;
- preserves request-ID, durable outcome, and `UNKNOWN_RECONCILE` semantics.

## Intentionally excluded

The integration does not carry any stale source-candidate copies of:

- `src/pc_executor/**`;
- execution-context binding fixtures already authoritative on the current line;
- old relay queue/result history;
- `tools/github_relay.py`;
- stale workflow or package metadata.

Every tracked `src/pc_executor/**` and `schemas/**` blob remains byte-identical to
the `18a6496...` base.
## Desktop Commander observed surface

The integrated remote registry continues to back the current parity primitives for:

- `read_file` and composed `read_multiple_files`;
- `write_file`;
- `edit_block`;
- `start_process`;
- `read_process_output`;
- `list_sessions`;
- `force_terminate`.

The canonical mapping fixture remains unchanged. A focused integration test executes
bounded file reads, write/edit, process start/output/list/terminate through
`ExecutorRemoteDispatcher` while using the current Executor outcome journal and
preflight path.

## Safety and failure invariants

All remote side effects enter through `Executor.execute()`. Current preflight,
protected-path policy, execution-context binding, idempotency/outcome journal, bounded
execution, and audit behavior remain authoritative.

Uncertain side-effect completion is never retried automatically:
`UNKNOWN_RECONCILE` is returned with `automatic_replay=false`.

No test or integration step accesses `E:\manhwa`; protected-path coverage uses
reject-before-access strings/spies only.
## CI gate

Both Ubuntu and Windows execute:

1. canonical lineage/diff/provenance audit;
2. focused preflight and execution-context suites;
3. current native parity tests and schema reproducibility;
4. native transport protocol/tests and harness;
5. remote Executor adapter/recovery/integrated-stack tests;
6. Windows-native parity tests on Windows;
7. the full suite.

The lineage audit requires the parity base to be the sole parent, rejects the stale
transport/adapter/relay commits as ancestors, verifies exact carried blobs, verifies no
`src/pc_executor/**` or `schemas/**` drift, rejects relay-path changes, and runs
`git diff --check`.
