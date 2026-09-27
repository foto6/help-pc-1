# Native Desktop Tool Parity v1

## Scope

PC Core exposes a native operations surface behind `pc_executor.Executor`.
This milestone covers the installed Desktop Commander 0.2.51 core operation
semantics without bypassing Executor policy. PDF create/modify remains an
explicit hard capability gap. The existing
`pc_executor.capabilities.v1`, action preflight, execution-context binding,
audit, `pc_executor.action_outcome.v1`, and `OutcomeJournal` remain the
authority for execution.

The umbrella native contract is `pc_executor.native_tool_parity.v1`.
Capability discovery is available through `ops.capabilities.get` and
publishes exact request/result/cursor/handle contract versions plus a
SHA-256 attestation of the capability document.

## Execution and safety invariants

Native read operations execute through the same Executor dispatch boundary.
Every native side-effect action is part of `SIDE_EFFECTING_ACTIONS`.
A live native side effect is rejected unless an existing `OutcomeJournal`
is configured. The frozen `action_outcome.v1` source blob is not modified;
the parity layer registers its versioned native action names with that
validator at process initialization so the existing journal records native
request/action identities directly. Executor records `dispatch_started`
before adapter dispatch and then writes the terminal outcome. An exception
after dispatch produces `effect_state=unknown`; the same request identity
cannot be blindly replayed.

Executor's existing `pc_executor.action_preflight.v1` is used for native
actions. Filesystem operations perform lexical and resolved-path validation.
Mutations re-check path identity/policy immediately before atomic replacement
or move. Existing hash preconditions provide compare-and-set semantics for
writes, edits, copies/moves where requested, and deletion.

The protected Windows root configured by the existing safety policy remains
protected. Tests use only mocked/path-policy rejection for that root and prove
rejection occurs before any filesystem probe.

`process.start` and `shell.session.start` can use the existing
`pc_executor.execution_context_binding.v1`. The authoritative shell
executable and working-directory identity are revalidated immediately before
dispatch.

Audit records redact file contents, stdin, environment values, process output,
and edit payloads. Sensitive credential/CAPTCHA paths, environment variables,
arguments and stdin remain blocked by the inherited policy.

## Native actions

Filesystem reads: `fs.list`, `fs.stat`, `fs.read_text`,
`fs.read_many`, `fs.read_bytes`, `fs.hash`, `fs.find`, `fs.glob`,
and `fs.search`. Text reads support absolute line ranges or bounded tail
reads. `fs.read_many` is a true deterministic batch primitive with per-file
success/error, a per-file byte bound, and a configured aggregate byte bound.
Binary reads use absolute byte offsets. The legacy `fs.search` remains a
deterministic bounded one-shot/cursor primitive and shares safe traversal with
the stateful search layer.

Stateful Desktop Commander search parity is provided by `search.start`,
`search.read`, `search.list`, and `search.stop`, with handle metadata
versioned as `pc_executor.search_session.v1`. `search.start` and
`search.stop` mutate managed lifecycle state and therefore use the existing
Executor outcome journal; `search.read` and `search.list` are read-only.

Filesystem mutations: `fs.write_text`, `fs.append_text`, `fs.edit_text`,
`fs.mkdir`, `fs.copy`, `fs.move`, and `fs.delete`. Direct filesystem
APIs are used instead of shell commands. `fs.edit_text` requires an exact
current SHA-256 and exact replacement count.

Log operations: `log.tail`, `log.read_since`, and `log.search`.
`log.read_since` uses an identity-bound cursor and rejects stale file
identity.

Managed process operations: `process.start`, `process.status`,
`process.read_output`, `process.terminate`, and `process.managed.list`.
Interactive sessions use `shell.session.start/read/write_stdin/terminate`.
Managed identities are persisted. After gateway restart, prior handles are
reported as `stale_after_restart` and cannot accept output reads, stdin, or
termination through the new generation.

System process discovery uses `process.list` and `process.inspect`.
On Windows, enumeration uses Toolhelp32 directly rather than `tasklist` or a
shell. `system.process.kill` requires both PID and expected executable name.
It rechecks executable identity on the opened Windows process handle before
calling `TerminateProcess`.

Device/system discovery: `device.info`, `identity.get`, `health.get`,
`config.get`, `audit.history`, `metrics.get`, `system.info`,
`system.resources`, and `system.paths`. `identity.get` exposes only
non-sensitive controller/device/session metadata. `audit.history` and
`metrics.get` return bounded sanitized metadata and never raw arguments,
results, or audit details.

`config.set` is a journaled side effect restricted to the explicit mutable
key allowlist. Updates are revision-aware and atomically persisted with
rollback on verification failure. `allowed_roots=[]` means deny all
filesystem access; it never means unrestricted access. `device.shutdown`
is a journaled current-device/current-session action that gracefully stops
the authenticated device agent. It is not an OS shutdown/power action.

## Bounded output and pagination

`fs.read_text` uses `start_line/end_line` or `tail_lines`, with
`max_bytes`. `fs.read_many` preserves input order and enforces both
per-file and aggregate output bytes while returning deterministic per-file
error codes. `fs.read_bytes` returns `next_offset` and explicit
`truncated`. `log.tail` returns explicit truncation; `log.read_since`
returns an identity-bound cursor and `has_more`.

Managed stdout/stderr are stored in fixed-size byte windows. Reads use absolute
offset cursors or `tail_bytes`. Results expose the retained base offset,
total bytes observed, and explicit `*_truncated_before_cursor` flags. Data
loss from buffer eviction is therefore never silent.

`fs.search` returns a versioned stateless cursor with root/query digests and
an absolute result offset. Stateful searches execute in a bounded worker pool
with bounded result memory, timeout and cancellation checkpoints. Results are
kept in deterministic traversal order. `search.read` uses an absolute
zero-based result offset and defaults to 100 results; a negative offset reads
that many results from the tail and ignores length. Completed, cancelled,
timed-out, and max-result searches remain readable for 300 seconds by default,
then are garbage-collected.

## Desktop Commander mapping

| Desktop Commander | Native tool(s) | Status |
| --- | --- | --- |
| `list_devices` | `device.info` | Local authorized device only |
| `ping` | `health.get` | Direct |
| `get_config` | `config.get` | Direct, includes revisioned admin config |
| `set_config_value` | `config.set` | Explicit allowlist + atomic revisioned update |
| `who_am_i` | `identity.get` | Non-sensitive controller/device/session metadata |
| `shutdown` | `device.shutdown` | Current authenticated agent/session only |
| `read_file` | `fs.read_text`, `fs.read_bytes`, `log.tail` | Direct |
| `read_multiple_files` | `fs.read_many` | True bounded deterministic batch |
| `write_file` | `fs.write_text`, `fs.append_text` | Direct |
| `edit_block` | `fs.edit_text` | Hash + replacement CAS |
| `list_directory` | `fs.list` | Direct |
| `move_file` | `fs.move` | Direct |
| `create_directory` | `fs.mkdir` | Direct |
| `get_file_info` | `fs.stat`, `fs.hash` | Direct |
| `start_search` | `search.start` | Stateful handle |
| `get_more_search_results` | `search.read` | Absolute/tail pagination |
| `stop_search` | `search.stop` | Cancel addressed current-generation handle |
| `list_searches` | `search.list` | Active/recent current-generation handles |
| `start_process` | `process.start`, `shell.session.start` | Direct |
| `read_process_output` | `process.read_output`, `shell.session.read` | Direct |
| `interact_with_process` | `shell.session.write_stdin` | Direct |
| `list_sessions` | `process.managed.list`, `process.status` | Direct |
| `force_terminate` | `process.terminate` | Managed current-generation handle |
| `list_processes` | `process.list`, `process.inspect` | Direct |
| `kill_process` | `system.process.kill` | PID + executable identity |
| `get_usage_stats` | `metrics.get` | Sanitized bounded operation metrics, not billing |
| `get_recent_tool_calls` | `audit.history` | Sanitized bounded audit metadata |
| `write_pdf` | — | **Hard gap:** PDF create/modify not implemented |

The canonical machine-readable mapping is
`tests/fixtures/native_tool_parity_v1/desktop_commander_mapping.json`.

## Schema artifacts

Generated schema artifacts are:

- `schemas/pc_executor.native_tool_request.v1.schema.json`
- `schemas/pc_executor.native_tool_result.v1.schema.json`
- `schemas/pc_executor.native_tool_capabilities.v1.schema.json`

They are generated by `tools/generate_native_tool_schemas.py`. The request
and result schemas freeze the native action inventory. Capability discovery
also publishes the existing preflight/context/cursor/handle versions used by
the implementation.

## Remaining capability gaps and non-core commands

PDF create/modify remains a hard explicit PC Core capability gap; this
milestone does not claim full Desktop Commander parity while that action is
absent. Remote multi-device brokering is also outside PC Core: the transport
binds one authenticated device agent/session at a time. The implemented
`device.shutdown` action stops that agent/session and does not power off the
operating system.

Vendor onboarding, prompt/help, and feedback commands such as
`give_feedback_to_desktop_commander` and `get_prompts` are not core
execution actions and are intentionally excluded from the native capability
registry.

Search handles are scoped to the current Executor/device generation. A restart
makes persisted prior-generation IDs explicitly stale; they cannot be read,
stopped, or silently rebound. Reconnects that retain the same generation keep
the handle valid. Protected roots are rejected before traversal, and
symlink/reparse traversal is skipped fail-closed.
