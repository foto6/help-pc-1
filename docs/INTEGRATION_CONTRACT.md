# Integration contract: help-pc-2 / vision-2 -> PC Executor

The upstream planner/vision component proposes intent plus selectors; PC Executor owns final local policy enforcement and side effects.

## Recommended loop

1. screenshot.capture and/or windows.list to observe state.
2. Vision/planner identifies a target.
3. Prefer uia.inspect to verify the target by accessibility metadata.
4. For `vision.grounded_target.v1`, use `vision.target.invoke`; it strictly validates the transport and re-resolves only by non-empty UIA `automation_id`.
5. Use uia.invoke, uia.focus, or uia.set_value for non-Vision UIA actions when supported.
6. Re-observe after the action.
7. Generic coordinate fallback remains a separately gated `mouse.click` capability; `vision.target.invoke` never uses target coordinates or the raw input adapter.

## Boundary rules

- Upstream components must not send credentials, secrets, authentication codes, CAPTCHA answers, or password-field content.
- The executor does not expose a CAPTCHA action and rejects sensitive/password value entry.
- Upstream must treat blocked as a policy decision, not a transient failure to retry around.
- Upstream may retry error only after re-observation or selector refinement.
- shell.run must use an argv array; shell command strings are not accepted.
- No upstream component may request access to E:\manhwa; PC Executor rejects the protected path regardless.

## Audit correlation

Preserve a stable request_id from planner -> executor -> telemetry. Each request emits start and finish audit events carrying action name, dry-run state, outcome and non-sensitive result metadata. Text bodies are intentionally excluded from audit details.
