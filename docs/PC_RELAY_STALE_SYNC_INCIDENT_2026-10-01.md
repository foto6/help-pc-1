# PC Relay stale-sync incident — 2026-10-01

## Symptom
A live relay process existed and the launcher reported it as already running, but the relay stopped consuming new GitHub requests.

Observed process chain:
- py.exe PID 4612
- python3.13.exe PID 15056, child of py.exe
- command: tools/github_relay.py --repo E:\pc-github-relay --live

This was one logical relay, not two competing relays.

## Evidence
- Local relay checkout HEAD remained at be374169e51309bbc943f68e7965f23f53c85380.
- Remote agent/pc-github-relay advanced through queued requests to e29d3746d2fbdc35b26e4b0725a63b78100a07c6 and later.
- Manual git fetch succeeded and updated origin/agent/pc-github-relay, but the running relay still did not consume a new read-only capabilities.get health probe.
- live.stderr.log stayed empty.
- live.stdout.log stopped advancing while the process remained alive.
- git status was clean.
- No active child git process was observed under the Python relay at diagnosis time.
- At diagnosis, 22 request files lacked result files.

Therefore process existence alone was a false liveness signal.

## Recovery used
1. Do NOT replay pending side-effect requests.
2. Preserve .pc-relay state/outcomes journal.
3. Terminate the stale relay process tree.
4. Restart through tools/start_pc_control_relay.ps1.
5. Reconcile existing request IDs/results before any replacement dispatch.
6. Confirm queue progress using a harmless capabilities.get request and durable relay/results commits.

After restart the queue resumed and previously queued requests were processed in filename order.

## Required product fix
Implement a fail-safe stale-sync watchdog on a development branch, without mutating the live relay branch during development.

The relay/launcher must distinguish:
- process_exists
- process_healthy
- process_stale

Health must include durable forward-progress/freshness evidence, not PID presence alone. At minimum cover:
- local HEAD vs origin branch freshness
- last successful sync timestamp
- last completed cycle timestamp
- last processed request/result timestamp
- current cycle phase (fetch/rebase/execute/publish/sleep)
- bounded age thresholds
- no blind side-effect replay after interrupted execution

Add deterministic tests for:
- alive Python process + stale local HEAD
- clean checkout + successful manual fetch + no cycle progress
- backlog present + no results
- interrupted side effect requiring reconciliation
- safe restart preserving state/outcome journal
- launcher refusing to report healthy when only PID existence is proven

No automatic live restart/cutover from CI or agent code. Any production replacement remains separately authorized.
