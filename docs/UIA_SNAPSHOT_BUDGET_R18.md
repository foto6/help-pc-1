# R18 PC Control UIA snapshot timeout audit

Issue: `foto6/help-pc-1#5`  
Branch: `agent/pc-control-uia-timeout-r18-20261001`  
Exact base: `2cc1e40f792a3d74560b726a0d246c90b7f077e9`

## Live evidence and root cause

The supplied smoke evidence already established that capabilities, window
enumeration, shell, screenshot, and outcome-journal lookup succeeded while
`uia.snapshot` timed out for both Chrome hwnd 68302 and File Explorer hwnd
9701010. R18 does not repeat live UI actions.

The failure is adapter-wide and has two compounding causes in the base code:

1. `Executor._bounded` runs every native operation in a worker thread.
   Python-UIAutomation-for-Windows requires
   `UIAutomationInitializerInThread` before UI controls are used from a new
   thread. The base `WindowsUIAutomationAdapter` did not establish that
   per-thread UIA/COM context.
2. Snapshot traversal was breadth-first to depth 12 with no node, child,
   work, or inner-time budget. Every visited control called several synchronous
   UIA properties plus Invoke/Value pattern probes. Chrome accessibility trees
   and native Explorer trees can therefore exceed the Executor's outer
   five-second timeout. Cancelling the Python future cannot interrupt an
   already-running COM call, so merely increasing the outer timeout would
   leave the underlying monopolization risk intact.

## R18 behavior

All public native UIA entry points now run inside a per-worker
`UIAutomationInitializerInThread` session when the provider exposes it.
Injected test adapters without that helper remain supported.

Native snapshots use `pc_executor.uia_snapshot_observation.v1` with fixed
hard caps:

- at most 256 emitted nodes;
- at most 64 children from any one node;
- at most 2048 traversal work units;
- maximum depth 12;
- at most two seconds of native snapshot work, further reduced to 60% of the
  request/Executor timeout so the outer Executor timeout retains cleanup
  headroom.

Child enumeration prefers UIA's first-child/next-sibling TreeWalker calls and
does not materialize an entire large child collection. The existing
`GetChildren` path is retained only as a compatibility fallback for injected
adapters.

A bounded observation returns normally with a structured top-level
`observation` object (also embedded in the snapshot). It is either
`status=complete` or `status=partial`. Partial reasons are explicit:
`time_budget_exhausted`, `node_budget_exhausted`,
`work_budget_exhausted`, `child_budget_exhausted`, or
`depth_budget_exhausted`. `timed_out=true` means the *inner UIA work
budget* expired and a valid partial snapshot was returned; an Executor-level
`status=timeout` remains reserved for a provider call that itself fails to
return before the outer deadline.

Legacy injected snapshots created without observation metadata preserve their
prior JSON shape and digest inputs.

## Safety invariants

R18 does not add coordinate fallback. Snapshot observations explicitly report
`coordinate_fallback_used=false` and `side_effects=false`. UIA invoke,
focus, and value-setting still re-resolve targets; execution-context binding is
unchanged. Credential/sensitive and CAPTCHA policy is unchanged. No protected
path handling, shell policy, outcome journal, Native MCP, relay, or deployment
code is changed.

## Deterministic regression matrix

`tests/test_uia_snapshot_budget.py` proves the budget contract, legacy
snapshot compatibility, structured partial serialization, and bounded sibling
enumeration on every platform.

`tests/windows/test_uia_snapshot_budget_windows.py` uses mock-only UIA trees
on the Windows CI runner:

- a Chrome-like 15-level tree with many siblings must return a bounded partial
  snapshot rather than an Executor timeout;
- an Explorer-like native window with 300 sibling items must stop at the
  per-parent child cap with explicit `child_budget_exhausted`;
- a deterministic stepping clock must produce
  `time_budget_exhausted` partial semantics;
- the UIA thread initializer must execute inside the Executor worker thread for
  both snapshot and inspect paths.

No test starts applications, performs UI effects, changes SCM/UAC state, or
accesses `E:\\manhwa`.

## Operator / consumer guidance

A partial snapshot is valid read-only evidence of the nodes actually emitted,
not proof that an omitted target does not exist. Consumers must not transform
partial absence into coordinates, blind clicks, or stale target identity.
Actions continue to require normal UIA target resolution and context binding.
If a specific control is absent from a partial snapshot, narrow the window or
selector and retry read-only discovery rather than increasing the Executor
timeout or bypassing UIA.
