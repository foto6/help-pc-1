# PC Executor

Safe Windows execution layer for agentic computer control.

Round 2 hardens the accessibility-first executor with deterministic UIA re-resolution, ambiguity/staleness classification, read-only UIA snapshots, operation cancellation/deadlines, bounded shell output, correlatable screenshot metadata, replayable fake adapters, and structured error kinds while preserving `vision.grounded_target.v1`.

Safety baseline remains unchanged: no credential entry, no CAPTCHA solving, no destructive default actions, raw coordinate clicking disabled by default, and `E:\manhwa` protected.

## Run

~~~powershell
py -m pip install -e ".[test]"
pytest
~~~

Dry-run JSONL service:

~~~powershell
'{"action":"windows.list","params":{},"timeout_ms":5000}' | pc-executor
~~~

Enable live side effects explicitly with `pc-executor --live`. Coordinate clicks additionally require `--allow-coordinate-fallback`; Vision target invocation never uses that fallback.

## Runtime contracts

- `uia.snapshot` provides canonical read-only accessibility observations for future Vision adapters.
- `screenshot.capture` returns digest, dimensions and display geometry in physical screen pixels.
- failures expose `error_kind` for stale, ambiguous, policy, timeout, cancellation, transient and executor failures.
- side-effecting actions emit `pc_executor.action_outcome.v1` evidence so post-dispatch uncertainty is reconciled instead of blindly re-executed.
- `shell.run` reports deterministic output truncation metadata.

See `docs/ARCHITECTURE.md`, `docs/TOOL_SCHEMA.md`, and `docs/INTEGRATION_CONTRACT.md`.
