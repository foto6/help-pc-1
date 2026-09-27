# PC Structured Operations Gateway v1

Wave2 adds a versioned structured operations surface for routine engineering work while preserving the frozen PC Executor v1 contracts byte-for-byte. The hardened relay remains the transport; Executor remains the policy boundary.

## Compatibility split

The existing `pc_executor.capabilities.v1`, `pc_executor.action_preflight.v1`, `pc_executor.action_outcome.v1`, legacy outcome journal, and execution-context-binding v1 contracts are unchanged. Existing consumers therefore retain exact fixture compatibility.

Wave2 is additive:

- operations contract: `pc_executor.ops.v1`
- capabilities: `pc_executor.ops_capabilities.v1`
- preflight result: `pc_executor.ops_preflight.v1`
- start-context binding: `pc_executor.ops_context_binding.v1`
- side-effect outcome evidence: `pc_executor.ops_action_outcome.v1`
- durable journal record: `pc_executor.ops_outcome_journal.record.v1`
- stream cursor: `pc_executor.stream_cursor.v1`
- log cursor: `pc_executor.log_cursor.v1`
- managed handle: `pc_executor.process_handle.v1`

Use `ops.capabilities.get` to discover this surface and `ops.preflight` to preflight structured actions. Do not send these actions through the frozen `action.preflight` v1 contract.

## Action inventory

Filesystem reads:

- `fs.list`
- `fs.stat`
- `fs.read_text`
- `fs.read_bytes`
- `fs.hash`
- `fs.find`
- `fs.glob`

Filesystem mutations:

- `fs.write_text`
- `fs.append_text`
- `fs.mkdir`
- `fs.copy`
- `fs.move`
- `fs.delete`

Logs:

- `log.tail`
- `log.read_since`
- `log.search`

Managed processes:

- `process.list`
- `process.inspect`
- `process.start`
- `process.status`
- `process.read_output`
- `process.terminate`

Managed shell sessions:

- `shell.session.start`
- `shell.session.read`
- `shell.session.write_stdin`
- `shell.session.terminate`

System reads:

- `system.info`
- `system.resources`
- `system.paths`

Meta actions are `ops.capabilities.get` and `ops.preflight`. There are 31 Wave2/meta actions total and 29 day-to-day operations.

## Filesystem policy

All path-bearing actions run the lexical protected-path check and then resolve the requested target or the nearest existing ancestor. Existing ancestors are re-resolved individually, which catches practical symlink/junction/reparse-point aliases, relative paths, parent traversal, alternate separators, and case aliases before access.

The protected Windows root `E:\manhwa` remains unreachable. No Wave2 operation has a bypass flag.

Structured reads refuse common credential/config filenames such as `.env`, `.git-credentials`, private-key defaults, and obvious secrets files. Read bounds are explicit:

- text read: at most 1 MiB returned;
- binary read: at most 1 MiB returned and base64 encoded;
- hash: at most 1 GiB input;
- list/find/glob: at most 500 returned entries;
- recursive find: at most depth 32.

Text-oriented line APIs normalize decoded CRLF/CR line endings to LF. Byte reads and log cursors remain byte-offset based.

### Mutation semantics

`fs.write_text` uses an adjacent temporary file, fsync, and atomic replace. Existing files require either a matching `expected_current_hash` or explicit `overwrite=true`; `create_only=true` refuses an existing target.

`fs.append_text` reconstructs the old file plus suffix into an adjacent temporary file and atomically replaces the destination. It can require an expected current hash, so an interrupted append before replace leaves the old bytes intact rather than a partial suffix.

`fs.copy` uses bounded streaming into an adjacent temporary file and atomic destination replace. `fs.move` is restricted to the same filesystem and uses atomic replace. Copy/move are capped at 256 MiB by the structured path.

`fs.delete` requires an explicit classification. Only `file` and `empty_directory` are accepted. File deletion requires an exact expected SHA-256 and rechecks it at execution. Recursive tree deletion is not provided.

## Logs

Log operations are finite reads. There is no follow/stream action.

`log.tail` is bounded by lines and bytes. `log.search` is bounded by scanned bytes and match count and supports literal or validated regular expressions.

`log.read_since` returns a `pc_executor.log_cursor.v1` carrying resolved-path digest, device/inode identity, and byte offset. Rotation/replacement or an invalid offset fails closed. Polling is an explicit read-only request.

## Managed processes

`process.start` validates argv/cwd with the configured `SafeShellAdapter`; it does not introduce a second executable allowlist. Environment overlays are bounded and reject credential-like key names. Optional `inherit_env=false` allows an explicitly constructed environment.

A successful start returns a durable handle record. Stdout/stderr are drained concurrently into separate bounded rolling byte windows. `process.read_output` uses an explicit `pc_executor.stream_cursor.v1` and reports whether requested bytes had already fallen out of the bounded window.

`process.terminate` accepts only a handle owned by the current gateway generation. Arbitrary PID termination is intentionally absent.

Persisted handles discovered after gateway restart are marked `stale_after_restart`. The new process cannot read stdin/output or terminate them because it no longer owns the OS pipe/process object. This is a deliberate fail-closed restart semantic.

## Shell sessions

A shell session is a managed child process with stdin plus the same bounded stdout/stderr windows. It is intended for interactive tools where repeated `shell.run` calls would lose process state.

- `shell.session.start` uses the same executable/cwd/env policy as `process.start`.
- `shell.session.read` is cursor-based and finite.
- `shell.session.write_stdin` is byte-bounded and rejects `sensitive=true` plus obvious credential/token/CAPTCHA forms.
- `shell.session.terminate` only operates on a current-generation managed session.

Sessions do not survive a gateway restart as active controllable sessions. Persisted IDs become stale audit evidence.

## Preflight and execution context

All structured side effects have strict parameter validation and a read-only `ops.preflight` path. Filesystem preflight validates protected paths, target type, overwrite/create policy, and expected hashes where relevant.

`process.start` and `shell.session.start` preflight additionally return `pc_executor.ops_context_binding.v1`, containing only executable identity plus a digest/device/inode description of cwd. The raw cwd is not duplicated into the binding. Supplying this binding on execution forces a second observation; cwd replacement or executable change blocks before dispatch.

File mutations use explicit hash/path-identity preconditions rather than pretending a shell-context binding describes file bytes.

## Outcomes, retries, and audit

Every Wave2 side effect is wrapped by Executor's existing effect boundary but writes a separate additive `pc_executor.ops_outcome_journal.record.v1` journal so the frozen v1 outcome contract remains unchanged.

The journal records a durable provisional `unknown/dispatch_started` record before the adapter call and a terminal record afterward. Completed or unknown request IDs are never blindly replay-authorized. Duplicate request IDs bound to another action fail closed.

Relay reconciliation calls the same Executor `read_outcome_evidence` method; it routes Wave2 actions to the ops journal and legacy actions to the legacy journal.

Audit details recursively redact file text, base64 data, stdout, stderr, log lines/matches, values, and environment dictionaries. Payload content is not copied into outcome evidence.

## Timeouts and cancellation

Executor `timeout_ms` bounds each operation. Filesystem hashing/walking/copy/append and managed termination poll the cancellation token. Child output read waits are independently bounded to 2 seconds. No action offers an infinite wait.

## System reads

`system.info` returns normalized platform/Python/CPU-count metadata. `system.resources` returns CPU count, load average where portable, physical-memory totals where safely available, and disk usage for a validated path. GPU is reported as `null` until a safe provider is available. `system.paths` exposes resolved cwd and optional requested-path existence information.

## Git

No structured Git security model is introduced. Git remains available through `shell.run` and through managed process/session primitives only when the configured SafeShellAdapter permits `git`. This keeps one command execution policy.

## Consumer fixture pack

The handoff for `foto6/help-pc-2` / `agent/pc-ops-gateway` is in `tests/fixtures/pc_ops_v1`.

The fixture manifest pins schema and fixture bytes by SHA-256, records the Wave2 source head, action inventory, contract versions, and frozen legacy v1 Git blob identities. `shell_migration_matrix.json` maps ordinary shell equivalents to their preferred structured actions.

Schemas:

- `schemas/pc_executor.ops.request.v1.schema.json`
- `schemas/pc_executor.ops.result.v1.schema.json`
- `schemas/pc_executor.ops_capabilities.v1.schema.json`
- `schemas/pc_executor.ops_preflight.v1.schema.json`
- `schemas/pc_executor.ops_context_binding.v1.schema.json`
- `schemas/pc_executor.ops_outcome.v1.schema.json`
- `schemas/pc_executor.ops_outcome_journal.record.v1.schema.json`

The request schema has an exact per-action params object with `additionalProperties=false`. The result schema has a strict ActionResult envelope and per-action successful data shape; error data remains an opaque object because error-specific diagnostic evidence is intentionally evolvable.

## Migration guidance for coordinators

Prefer structured actions for file, log, process, session, and system work represented in the fixture migration matrix. Keep `shell.run` for short commands that have no structured equivalent, especially Git. Use `process.start` for bounded background commands and `shell.session.*` only when actual process state must persist between interactions.

Do not convert historical requests in-place. New structured operations use new immutable request IDs and the Wave2 outcome journal.
