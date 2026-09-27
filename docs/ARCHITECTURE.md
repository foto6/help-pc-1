# PC Executor architecture

The executor is a small policy-enforcing facade around five replaceable adapters:

1. ScreenshotProvider — desktop capture as PNG bytes.
2. WindowEnumerator — visible top-level window discovery.
3. AccessibilityAdapter — Windows UI Automation inspection, focus, invoke and value setting. This is the primary interaction path.
4. InputAdapter — keyboard, clipboard and raw coordinate mouse fallback. Coordinate fallback is disabled by default.
5. SafeShellAdapter — argv-only subprocess execution with shell=False, executable allowlisting, timeouts and protected-path checks.

Executor.execute(ActionRequest) owns cross-cutting policy: dry-run, credential/sensitive-entry blocking, coordinate fallback policy, structured results and audit emission. Windows-specific dependencies are lazily imported so policy and integration tests run on non-Windows hosts.

## Safety invariants

- Default mode is dry-run.
- uia.* actions are preferred over coordinate actions.
- mouse.click is blocked unless allow_coordinate_fallback=True is explicit.
- No credential/sensitive text entry. Password UIA controls are rejected by the UIA adapter.
- Shell execution is argv only, never shell=True, and is restricted to a conservative executable allowlist by default.
- E:\manhwa and descendants are rejected by shell path validation.
- No CAPTCHA-solving action exists.
- No destructive filesystem/process action exists in the public action set.
- Audits record metadata/results, not typed or clipboard text bodies.

## Failure model

Every request returns an ActionResult with status in completed, dry_run, blocked, or error. Policy violations are blocked; adapter/OS failures are error. This lets orchestration decide whether to re-observe, use a different deterministic selector, or ask the user.
