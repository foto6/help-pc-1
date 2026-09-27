# Native Desktop Tool Parity v1

## Scope

Wave 1 adds a native local operations surface behind `pc_executor.Executor`.
It is intended to replace the Desktop Commander operations used by the
coordinator without bypassing Executor policy. The existing
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
`fs.read_bytes`, `fs.hash`, `fs.find`, `fs.glob`, and `fs.search`.
Text reads support absolute line ranges or bounded tail reads. Binary reads use
absolute byte offsets. Search is deterministic and stateless; continuation is
represented by `pc_executor.search_cursor.v1`.

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

Device/system discovery: `device.info`, `health.get`, `config.get`,
`system.info`, `system.resources`, and `system.paths`. Configuration is
read-only through this surface.

## Bounded output and pagination

`fs.read_text` uses `start_line/end_line` or `tail_lines`, with
`max_bytes`. `fs.read_bytes` returns `next_offset` and explicit
`truncated`. `log.tail` returns explicit truncation; `log.read_since`
returns an identity-bound cursor and `has_more`.

Managed stdout/stderr are stored in fixed-size byte windows. Reads use absolute
offset cursors or `tail_bytes`. Results expose the retained base offset,
total bytes observed, and explicit `*_truncated_before_cursor` flags. Data
loss from buffer eviction is therefore never silent.

`fs.search` returns a versioned stateless cursor with root/query digests and
an absolute result offset. Content search is bounded by result count, depth,
per-file text size and aggregate scanned bytes.

## Desktop Commander mapping

| Desktop Commander | Native tool(s) | Status |
| --- | --- | --- |
| `list_devices` | `device.info` | Local authorized device only |
| `ping` | `health.get` | Direct |
| `get_config` | `config.get` | Read-only |
| `set_config_value` | — | Intentionally unsupported |
| `read_file` | `fs.read_text`, `fs.read_bytes`, `log.tail` | Direct |
| `read_multiple_files` | composed bounded `fs.read_*` calls | Composed |
| `write_file` | `fs.write_text`, `fs.append_text` | Direct |
| `edit_block` | `fs.edit_text` | Hash + replacement CAS |
| `list_directory` | `fs.list` | Direct |
| `move_file` | `fs.move` | Direct |
| `create_directory` | `fs.mkdir` | Direct |
| `get_file_info` | `fs.stat`, `fs.hash` | Direct |
| `start_search` | `fs.search`, `fs.find`, `fs.glob`, `log.search` | Direct |
| `get_more_search_results` | `fs.search` cursor / `log.read_since` | Cursor |
| `stop_search` / `list_searches` | — | Not needed; search is stateless |
| `start_process` | `process.start`, `shell.session.start` | Direct |
| `read_process_output` | `process.read_output`, `shell.session.read` | Direct |
| `interact_with_process` | `shell.session.write_stdin` | Direct |
| `list_sessions` | `process.managed.list`, `process.status` | Direct |
| `force_terminate` | `process.terminate` | Managed current-generation handle |
| `list_processes` | `process.list`, `process.inspect` | Direct |
| `kill_process` | `system.process.kill` | PID + executable identity |
| `write_pdf` | — | Outside Wave 1 |
| `shutdown` | — | Outside Wave 1 |
| `who_am_i` | — | Identity disclosure not required |
| `get_recent_tool_calls` | existing Executor audit/outcome journals | Existing authority |

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

## Intentionally unsupported edges

Wave 1 does not implement remote multi-device routing, device shutdown,
mutable safety configuration, credential/account identity disclosure, PDF
generation, or server-side search handles. These exclusions prevent a
duplicate policy plane or unbounded transport semantics. Higher layers may
compose bounded reads or document generation while native side effects remain
inside Executor.
