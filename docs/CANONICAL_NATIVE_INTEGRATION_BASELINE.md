# Canonical Native Integration Baseline

## Scope

This branch establishes the canonical native transport baseline on the current Executor producer without merging the obsolete relay line.

- Repository: `foto6/help-pc-1`
- Canonical branch: `agent/pc-native-integration-canonical`
- Authoritative Executor base: `2cc1e40f792a3d74560b726a0d246c90b7f077e9`
- Native transport source commit: `8df29aad32a6cb142dff6721f92fca74a080e441`
- Transport source base: `992c66335c9e6c40d150bc10c086e97ea7600d48`
- Known merge-base between the old relay line and current Executor: `d0ccb0f390474fc3fc091e51c25f7ef8771b0f09`

The integration is a reapplication of the intended transport delta, not a merge of the old relay history. The resulting commit has the current Executor producer as its only parent.

## Carried transport provenance

The intended delta from `8df29aad32a6cb142dff6721f92fca74a080e441` was reviewed as the single commit immediately after `992c66335c9e6c40d150bc10c086e97ea7600d48`.

Carried unchanged from that commit:

- `src/pc_remote_transport/**`
- `tests/test_native_remote_transport.py`
- `tests/test_remote_protocol.py`
- `tools/native_remote_harness.py`
- `docs/NATIVE_REMOTE_TRANSPORT.md`
- `docs/NATIVE_REMOTE_THREAT_MODEL.md`
- `docs/NATIVE_REMOTE_MIGRATION.md`

Explicitly not carried:

- no `tools/github_relay.py` change;
- no old relay queue/runtime history;
- no old-base copy of any `src/pc_executor/**` file.

## Shared-file reconciliation

### `pyproject.toml`

Current Executor metadata from `2cc1e40f792a3d74560b726a0d246c90b7f077e9` remains authoritative. Only the transport dependencies are added:

- runtime: `websockets>=13,<16`
- tests: `pytest-asyncio>=0.23`

### `.github/workflows/tests.yml`

The current producer workflow is retained, including both focused Executor checks:

- Wave 6 preflight
- Wave 7 execution-context binding

The native transport adds:

- focused remote-transport tests;
- the deterministic native transport harness;
- the `agent/pc-native-integration-canonical` push trigger.

The obsolete transport branch trigger is not copied.

## Conflict and regression resolution

There were no content conflicts in the transport-only files because they are new relative to the current Executor producer. The only divergent shared files were `pyproject.toml` and `.github/workflows/tests.yml`; both were reconciled manually against `2cc1e40f792a3d74560b726a0d246c90b7f077e9` rather than accepting the old-base versions.

The integration does not modify current Executor implementation or frozen contracts. In particular, the current capability, preflight, execution-context binding, outcome journal, and audit paths remain inherited from `2cc1e40f792a3d74560b726a0d246c90b7f077e9`.

## Resulting capability state

The branch contains two layers with a strict boundary:

1. Current `pc_executor` from `2cc1e40f792a3d74560b726a0d246c90b7f077e9`, authoritative for policy, preflight, context binding, side effects, outcome durability, and audit.
2. Provider-neutral `pc_remote_transport` delivery primitives from `8df29aad32a6cb142dff6721f92fca74a080e441`, responsible for authenticated persistent transport, replay defense, crash-durable delivery state, bounded streaming, token rotation primitives, and reconciliation signaling.

The transport does not add a parallel shell/filesystem/UI execution engine. Application dispatch remains injected behind `Dispatcher`; Executor remains the required side-effect authority.

Native transport remains disabled by default through `PC_NATIVE_REMOTE_TRANSPORT=0`.

## Test state

The canonical CI workflow runs on both `ubuntu-latest` and `windows-latest` with Python 3.11 and executes:

1. `python -m pytest tests/test_preflight.py`
2. `python -m pytest tests/test_execution_context_binding.py`
3. `python -m pytest tests/test_native_remote_transport.py tests/test_remote_protocol.py`
4. `python tools/native_remote_harness.py`
5. `python -m pytest`

Exact-head workflow run IDs and conclusions are produced after the commit is pushed; the exact branch head is the evidence anchor for those runs.

## Safety invariant

This integration neither references nor requires access to `E:\\manhwa`. Protected-path behavior remains owned by the current Executor producer and is not weakened by the transport layer.
