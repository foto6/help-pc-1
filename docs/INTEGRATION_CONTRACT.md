# Integration contract: help-pc-2 / vision-2 -> PC Executor

The upstream planner/vision component proposes intent plus selectors; PC Executor owns final local policy enforcement and side effects.

## Recommended loop

1. screenshot.capture and/or windows.list to observe state.
2. Vision/planner identifies a target.
3. Prefer uia.inspect to verify the target by accessibility metadata.
4. Use uia.invoke, uia.focus, or uia.set_value when supported.
5. Re-observe after the action.
6. Only if UIA cannot identify the target, the orchestrator may explicitly opt into coordinate fallback for the executor instance and issue mouse.click based on a fresh screenshot.

## Boundary rules

- Upstream components must not send credentials, secrets, authentication codes, CAPTCHA answers, or password-field content.
- The executor does not expose a CAPTCHA action and rejects sensitive/password value entry.
- Upstream must treat blocked as a policy decision, not a transient failure to retry around.
- Upstream may retry error only after re-observation or selector refinement.
- shell.run must use an argv array; shell command strings are not accepted.
- No upstream component may request access to E:\manhwa; PC Executor rejects the protected path regardless.

## Audit correlation

Preserve a stable request_id from planner -> executor -> telemetry. Each request emits start and finish audit events carrying action name, dry-run state, outcome and non-sensitive result metadata. Text bodies are intentionally excluded from audit details.
