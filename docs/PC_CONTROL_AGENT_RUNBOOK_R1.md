# PC Control — agent runbook for Plus relay mode

## Scope

Use this runbook when the current ChatGPT session does **not** expose a genuine callable Native R22 MCP namespace.

Transport:

`ChatGPT -> private GitHub repo -> github_relay.py -> pc_executor.Executor -> Windows -> durable result -> GitHub -> ChatGPT`

Repository: `foto6/help-pc-1`  
Branch: `agent/pc-github-relay`  
Requests: `relay/requests/`  
Results: `relay/results/`  
Request schema: `pc_relay.request.v1`  
Result schema: `pc_relay.result.v1`

## Human bootstrap

Preferred human action after reboot:

`E:\pc-github-relay\START_PC_CONTROL.cmd`

The launcher starts the relay detached and refuses to create a duplicate process.

Do not ask the user to type the raw Python command unless the launcher itself is missing or broken.

## Before the first action

1. Check for a genuine Native R22 namespace first. If it exists, follow the Native R22 runbook instead.
2. Otherwise use this relay lane.
3. Prefer a harmless read-only probe such as `capabilities.get`.
4. If no result appears, distinguish request sync, relay process state, Executor failure, and result publication failure.
5. Do not equate a missing GitHub result with “the action did not run”.

## Request rules

Create exactly one immutable JSON file per logical action:

```json
{
  "version": "pc_relay.request.v1",
  "id": "globally-unique-descriptive-id",
  "action": "capabilities.get",
  "params": {},
  "timeout_ms": 10000,
  "note": "brief purpose"
}
```

Never reuse an ID for a different action.

For `shell.run`, pass argv arrays, for example:

```json
{
  "argv": ["powershell.exe", "-NoProfile", "-Command", "Get-Process | Select-Object -First 5"]
}
```

## Result acceptance

Do not claim completion until the durable result is read and validated.

For normal success require:

- `version == "pc_relay.result.v1"`
- result `id` equals request `id`
- result `action` equals request `action`
- `relay_status == "completed"`
- `executor_result.ok == true`
- `executor_result.status == "completed"`
- `reexecuted == false` unless a contract explicitly proves replay safety

For side effects also inspect `outcome_evidence` when present.

## Missing or uncertain result

A timeout is not retry permission.

For side-effecting requests:

1. Never create a replacement side-effect request just because the result is absent.
2. Inspect the original result/state or issue a separate read-only `outcome.lookup`.
3. If `effect_state == completed`, treat it as already executed.
4. If `effect_state == unknown`, reconcile; do not replay.

## Default exposed actions

Expect the relay baseline to include:

- `capabilities.get`
- `action.preflight`
- `outcome.lookup`
- `windows.list`
- `uia.snapshot`
- `uia.inspect`
- `screenshot.capture`
- `clipboard.get`
- `shell.run`

Never assume write/input actions are enabled merely because Executor supports them. Check the current relay allow-actions/capabilities.

## Safety invariants

- Never access, enumerate, modify, or route around `E:\manhwa`.
- Never request, read, echo, log, or commit credentials, API keys, passwords, session tokens, recovery codes, or CAPTCHA answers.
- Never disable Executor safety, preflight, execution-context binding, or outcome journaling to force an action through.
- Never blindly repeat a side effect.
- Inspect Git branch/worktree state before modifying repositories.
- Agent completion means concrete evidence: result JSON, changed files, tests, commit SHA, CI, or an explicit blocker. “Ready” and “starting” are not completion.

## Multi-agent work

Use GitHub directly for remote repository/CI state. Use PC Control for state that only exists on the Windows machine: processes, local files, browsers, UIA, local builds, GPU/runtime state, and machine-side commands.

Batch related read-only checks when practical. Avoid dozens of tiny relay requests.

## Native R22 boundary

Do not call this relay “Native R22”.

Direct Native R22 is proven only when the current ChatGPT session itself exposes the distinct callable Native/R22 tool namespace and passes read-only consumer probes.

Until then, Plus relay mode is the supported production path.
