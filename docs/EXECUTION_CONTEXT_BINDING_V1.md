# Execution context binding v1

\`pc_executor.execution_context_binding.v1\` is an optional, transport-neutral guard against preflight-to-execution TOCTOU. It is separate from and does not modify \`pc_executor.capabilities.v1\`, \`pc_executor.action_preflight.v1\`, \`pc_executor.action_outcome.v1\`, or the durable outcome-journal contracts.

## Contract

A binding carries the logical \`request_id\` and \`action\`, a context kind, sorted authoritative field names, available read-only provenance sections, and \`context_digest\`. The digest is SHA-256 over canonical JSON excluding the digest field.

The available sections are:

- \`process\`: process id and process start epoch when observable;
- \`window\`: top-level window handle;
- \`target\`: automation id/control type/class/native handle/runtime id plus a target identity digest;
- \`display\`: display id and optional capture id;
- \`shell\`: executable basename, cwd path digest and cwd filesystem identity when available.

Bindings never contain typed text, clipboard/value bodies, shell arguments beyond the executable identity, credentials/CAPTCHA data, or raw mouse coordinates.

## Authority by action path

| path | authoritative context | advisory provenance |
| --- | --- | --- |
| UIA / Vision invoke | request identity, process id/start epoch when available, top-level window, automation target identity | display id, capture id |
| mouse.click | request identity, foreground process id/start epoch, foreground window, display at bound point when available | capture id |
| keyboard / clipboard write | request identity, foreground process id/start epoch, foreground window | display/capture provenance |
| shell.run | request identity, executable identity, cwd path digest and cwd filesystem identity when available | none; shell never invents GUI context |

UIA bounds and window geometry are intentionally excluded from target identity, so moving or resizing the same window does not by itself invalidate a binding.

## Last-moment validation

When a side-effecting request includes a binding, Executor re-reads only the minimum read-only context immediately before dispatch:

- UIA uses \`inspect()\`;
- foreground input/clipboard uses foreground window/process observation and display lookup for mouse;
- shell uses allowlist/path validation plus cwd metadata.

Validation itself never invokes/focuses/sets a UIA value, clicks, types, presses a key, reads/writes the clipboard, captures a screenshot, or starts a process.

A material change blocks before the adapter dispatch boundary. The response includes:

~~~json
{
  "execution_context_validation": {
    "contract_version": "pc_executor.execution_context_validation.v1",
    "status": "blocked",
    "reason": "context_mismatch",
    "binding_digest": "...",
    "reexecution_safe": true,
    "adapter_dispatch_started": false,
    "mismatches": ["process.start_epoch_ms"]
  }
}
~~~

Mismatch values are not returned; only field names are disclosed.

## Outcome semantics

\`pc_executor.action_outcome.v1\` is frozen. Context mismatch occurs before dispatch, so the existing outcome remains:

- \`effect_state="not_started"\`;
- \`dispatch_started=false\`;
- \`reason="policy_blocked"\`;
- \`reexecution_safe=true\`.

The explicit \`context_mismatch\` reason lives in the new validation record. After adapter dispatch starts, existing outcome/journal semantics dominate: crashes, timeouts, or transport loss remain \`unknown\` when completion cannot be proven, and the binding cannot authorize replay.

## Derivation

Embedding callers may use \`Executor.bind_execution_context()\` or the contract helpers to derive a binding from read-only UIA/foreground/shell provenance. The binding is optional for compatibility; when omitted, existing execution behavior is unchanged.

Consumer fixtures for Control live in \`tests/fixtures/execution_context_binding_v1/\`.
