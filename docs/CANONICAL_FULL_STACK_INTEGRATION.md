# Canonical native full-stack integration

This branch is the integration-only `help-pc-1` lineage that combines the current native Desktop tool parity Executor with the canonical native remote transport and remote Executor adapter. It does not merge or release any producer branch.

## Exact provenance

- Primary authoritative base: `18a6496b24520bade8246dae0759306a00a5a372` (`agent/pc-native-tool-parity`).
- Remote transport + adapter source: `9254fe113f474a1108cacff97f5bccfd5107f06c`.
- Exact common base of those heads: `2cc1e40f792a3d74560b726a0d246c90b7f077e9`.
- Source-only commits ported without merging source history:
  - `e47908e2c734984a872f3cc087731f4690d1c82c` — canonical native transport.
  - `9254fe113f474a1108cacff97f5bccfd5107f06c` — canonical remote Executor adapter.

The old GitHub-relay branch/history is not merged. `8df29aad32a6cb142dff6721f92fca74a080e441` and `992c66335c9e6c40d150bc10c086e97ea7600d48` remain non-ancestors.

## Conflict resolution

`.github/workflows/tests.yml` was the only cherry-pick conflict. The parity workflow stayed authoritative: parity focused tests, schema reproducibility, and the Windows native adapter job were retained. Remote transport and adapter focused jobs were added, and the integration branch trigger is `agent/pc-native-full-stack`; obsolete producer-branch trigger names were not carried.
No file under `src/pc_executor/**` is changed relative to the parity base. Its Executor, LocalOperations, safety, outcome, and native capability contracts remain authoritative.

`src/pc_remote_transport/executor_adapter.py` is the only carried source implementation intentionally changed after the selective port. The external `pc.native.tool_registry.v1` registry and digest remain unchanged. Transport glue now:

- advertises the union of the legacy Executor action map and `LocalOperations.capabilities_snapshot()` actions;
- includes the native operations capability digest in the authenticated hello manifest, so operations-contract drift changes the session capability digest;
- resolves stable native tool names to parity actions such as `fs.search`, `process.read_output`, `process.managed.list`, `process.list`, and the parity shell-session action names;
- translates stable process/session handle arguments to parity `handle_id` / `session_id` fields;
- uses the capability digest belonging to the resolved action for preflight and preserves the resolved action identity through outcome lookup, preflight, execution, audit, and result validation.

## Integration evidence

`tests/test_native_full_stack_integration.py` uses the authenticated frame transport and `DeviceAgent`, not a mock dispatcher shortcut. With a real parity `Executor` and `LocalOperations`, it proves:

- `fs.write_text` through `file.write`;
- `fs.edit_text` through `file.edit`;
- `fs.read_text` through `file.read`, including the transport stream;
- `process.start`, `process.read_output`, `process.managed.list`, and `process.terminate` through the stable process tools;
- parity native actions and the operations digest are present in the advertised manifest;
- operations capability-digest drift after hello fails closed as `CAPABILITY_DRIFT`.

Existing adapter tests continue to cover durable request IDs, result-loss replay behavior, `UNKNOWN_RECONCILE`, stale transport epochs, and stale process handles. The protected `E:\\manhwa` test remains spy-only and verifies rejection before Executor preflight or execution.
## Deterministic diff audit

`tools/audit_full_stack_integration.py` compares the integration head against both exact source heads. It verifies the exact common base, parity-base ancestry, non-ancestry of the remote source and obsolete relay history, byte identity for every carried remote-source path except the documented workflow and adapter divergences, zero `src/pc_executor/**` drift, no relay path/import, and `git diff --check`.

CI runs the full-stack audit and real integration suite on both Ubuntu and Windows, in addition to parity focused tests, remote transport/adapter focused tests, Windows native tests, and the complete test suite.
