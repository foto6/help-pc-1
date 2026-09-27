# Side-effect-free capabilities and action preflight v1

Wave 6 adds two read-only contracts without changing `pc_executor.action_outcome.v1` or the outcome-journal contracts:

- `pc_executor.capabilities.v1`
- `pc_executor.action_preflight.v1`

They let Control determine whether an action is currently admissible and plausibly executable before dispatch. A `ready` result is not a promise that later execution will succeed; UI state, cancellation, deadlines, and the environment can still change.

## Capabilities attestation

`capabilities.get` returns a deterministic `pc_executor.capabilities.v1` snapshot containing:

- supported action kinds and whether each is side-effecting;
- adapter availability for UIA, screenshot, window enumeration, input, clipboard, and shell;
- explicit unsupported reasons for unavailable native adapters;
- active safety gates: default dry-run, coordinate fallback, credential/CAPTCHA prohibition, protected roots, shell allowlist/output bound, default operation deadline, and outcome-journal configuration;
- compatibility-only runtime identity: executor version, Python implementation/major-minor, operating-system family/system, and architecture.

The snapshot intentionally excludes hostname, username, home directory, MAC address, machine identifiers, credentials, tokens, UI content, and other machine-unique sensitive values.

`attestation.digest` is SHA-256 over the canonical snapshot body excluding the attestation field. Identical runtime/configuration snapshots produce the same digest across repeated calls and process restart.

## Action preflight request

The strict transport is:

~~~json
{
  "contract_version": "pc_executor.action_preflight.v1",
  "request": {
    "request_id": "logical-action-id",
    "action": "uia.invoke",
    "params": {"query": {"automation_id": "save"}},
    "dry_run": null,
    "timeout_ms": 5000
  }
}
~~~

Unknown outer/request fields, unknown contract versions, invalid types, non-positive deadlines, and action-specific malformed parameters produce `invalid_request`.

The JSONL executor exposes the same transport as `action.preflight`, with the contract object supplied directly as `params`. `capabilities.get` and `action.preflight` are read-only actions and do not require live mode.

## Result statuses

| status | meaning |
| --- | --- |
| `ready` | current checks passed; later execution is still not guaranteed |
| `blocked` | current safety/policy gate forbids the action |
| `unsupported` | action kind or required adapter/environment capability is unavailable |
| `stale_observation` | the requested UIA target/window no longer resolves |
| `ambiguous_target` | the selector/window does not identify exactly one target |
| `invalid_request` | contract or action-specific request schema is malformed |

Every result includes the current capability attestation digest and effective positive deadline budget. UIA target summaries contain only actionability booleans; native handles, process ids, coordinates, names, values, and typed bodies are not copied into preflight results.

## Side-effect-free boundary

Preflight may perform only UIA `inspect()`/requested-window `snapshot()` and shell `validate()`. It never calls UIA `invoke`, `focus`, or `set_value`; never clicks, types, presses keys, reads/writes the clipboard, captures a screenshot, enumerates windows, or starts a process.

For `vision.target.invoke`, preflight strictly parses frozen `vision.grounded_target.v1`, requires UIA-backed non-empty `automation_id`, and then uses only UIA `inspect()`. Vision screen coordinates never gain input authority.

## Safety and retry meaning

Preflight preserves credential/sensitive-entry rejection, CAPTCHA non-support, coordinate authority rules, `E:\\manhwa` protection, shell allowlisting/bounded output, and the default dry-run mode.

Preflight does not create outcome evidence and does not authorize retries or replay. Outcome/reconciliation authority remains exclusively with `pc_executor.action_outcome.v1` and the durable outcome journal.

## Cross-repository fixtures

`tests/fixtures/preflight_v1/` contains transport-neutral capability, request, and result fixtures plus `manifest.json` and `manifest.sha256`.

The final manifest pins producer repository/branch and source commit, exact source paths and SHA-256 hashes, the compatible `foto6/help-pc-2 agent/pc-control-plane` head, every fixture byte length/hash, frozen `pc_executor.action_outcome.v1` fixture hashes, and the existing outcome-journal manifest hash.
