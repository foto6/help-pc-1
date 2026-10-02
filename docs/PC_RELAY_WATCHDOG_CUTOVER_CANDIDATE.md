# PC Relay watchdog cutover candidate

Repository: foto6/help-pc-1
Candidate branch: agent/pc-relay-watchdog-cutover-candidate-20261002
Exact development base: 33d063dffa507833a23c642d3e3e06bfa5d02b76

This branch prepares a production cutover candidate only. It does not alter, restart, repoint, register, or cut over the live agent/pc-github-relay checkout/process.

## Preserved runtime contracts

The candidate preserves pc_relay.health.v1, pc_relay.watchdog_status.v1, .pc-relay/state/<request-id>.json, .pc-relay/outcomes.jsonl, interrupted-side-effect reconciliation through outcome.lookup, and reexecuted=false / replay_authorized=false for unresolved side effects. Recovered process health or reboot recovery never authorizes replay.

## Recorded live baseline

On 2026-10-02 the remote live branch was observed at agent/pc-github-relay @ d487452dcb4556cf9a41ed69783f4231d0799873.

That observation is not perpetual authorization. Immediately before any separately authorized production change, the operator must re-read the remote live branch and record the actual pre-cutover SHA. If it differs, abort and regenerate the exact rollback pin.

## Windows autostart design

The candidate uses a per-user Windows Scheduled Task triggered at interactive logon, delayed 30 seconds. This is intentionally not a boot-time service because interactive UI adapters require the user's desktop session.

Plan-only installer:

    powershell.exe -NoProfile -File tools\install_pc_relay_autostart.ps1 -Repo <relay-checkout> -ExpectedHead <exact-candidate-sha>

Without -Apply, the installer prints the deterministic plan only. An authorized -Apply invocation requires exact candidate HEAD/branch and a clean tracked checkout, uses AtLogOn + Interactive + Limited, sets MultipleInstances IgnoreNew, registers but does not immediately start the task, kills no process, and mutates no queue/state/outcome file.

Plan-only uninstaller:

    powershell.exe -NoProfile -File tools\uninstall_pc_relay_autostart.ps1 -Repo <relay-checkout>

It refuses mutation while a matching relay process exists and never deletes runtime state or the outcome journal.

## Reboot recovery

After an authorized future registration, user logon invokes tools/start_pc_control_relay.ps1. The launcher groups a normal py.exe -> python.exe tree as one logical relay, never starts a second relay when one healthy logical relay exists, surfaces STALE / RECONCILIATION_REQUIRED / ambiguous states without killing, starts only when no matching relay tree exists, and reuses the same checkout-local .pc-relay/state and .pc-relay/outcomes.jsonl.

A request left in started side-effect state therefore remains bound to its original request ID and must reconcile through outcome.lookup after reboot.

## Bounded logs

Before starting a new relay process, the launcher rotates .pc-relay/live.stdout.log and .pc-relay/live.stderr.log. Default bound is 5,242,880 bytes per active log with three retained rotations. An already-running relay is not disturbed merely to rotate logs.

## Future authorized migration sequence

1. Record actual live SHA with git rev-parse origin/agent/pc-github-relay.
2. Record read-only queue/health evidence and reconcile any unknown side effect.
3. Preserve the existing .pc-relay directory in the dedicated relay checkout.
4. Verify tracked checkout is clean.
5. Manually stop the old relay tree only after ownership is confirmed.
6. Confirm the old relay tree is absent.
7. Fetch the exact green candidate SHA and switch the same dedicated checkout to agent/pc-relay-watchdog-cutover-candidate-20261002 at that exact SHA. The live branch itself is not moved.
8. Run the installer without -Apply and inspect the plan.
9. Only under separate cutover authorization, run installer with -Apply.
10. Start through tools/start_pc_control_relay.ps1.
11. Require HEALTHY watchdog evidence and verify backlog/result forward progress using existing request IDs.
12. Perform a separately authorized reboot/logon verification before declaring autostart accepted.

Any STALE, RECONCILIATION_REQUIRED, DUPLICATE_AMBIGUOUS, missing health evidence, or source-pin mismatch aborts the cutover.

## Exact rollback

Before cutover, retain the actual pre-cutover live SHA as <PREVIOUS_HEAD>. Plan-only rollback:

    powershell.exe -NoProfile -File tools\rollback_pc_relay_cutover.ps1 -Repo <relay-checkout> -PreviousHead <PREVIOUS_HEAD>

With separate authorization and -Apply, rollback requires no matching relay process, a clean tracked checkout, and origin/agent/pc-github-relay still equal to <PREVIOUS_HEAD>. It unregisters the candidate autostart task if present and checks out the exact previous SHA in detached mode. It does not move/rewrite the live branch, delete .pc-relay, start a relay, or kill a process.

If the live branch pin changed, rollback refuses until a new explicit pin is supplied.

## Incident fixture

tests/fixtures/pc_relay_cutover_candidate/incident_2026-10-01.json encodes the recorded stale-sync incident: py.exe PID 4612 -> python3.13.exe PID 15056, local HEAD be374169e51309bbc943f68e7965f23f53c85380, observed remote HEAD e29d3746d2fbdc35b26e4b0725a63b78100a07c6, successful manual fetch, clean checkout, 22 requests without results, unconsumed read-only probe, and recovery using existing request IDs.

The candidate tests require that fixture to classify as STALE, while fresh-forward-progress and unknown-side-effect variants classify as HEALTHY and RECONCILIATION_REQUIRED.

## Release boundary

CI validates scripts in plan/syntax mode only. It does not call Register-ScheduledTask or Unregister-ScheduledTask, start a relay, stop a process, or mutate the live branch.

NO_LIVE_CUTOVER.
