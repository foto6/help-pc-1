# Canonical full-stack + stateful search integration

This branch is the integration-only `agent/pc-native-full-stack-search` lineage for
`foto6/help-pc-1`. It adds the green stateful search lifecycle to the current
native PC full stack without merging or releasing producer branches.

## Exact provenance

- Primary base: `3a07382fa98f3e02a3d1ffbb4cc3c61b806e2e63`.
- Search source: `603d7a5791d6e0fc145e65e6b14ad031a5b2cf75`.
- Search source parent: `18a6496b24520bade8246dae0759306a00a5a372`.
- Existing remote transport/adapter source already present in the base:
  `9254fe113f474a1108cacff97f5bccfd5107f06c`.

The search source is applied as a three-way commit delta only. Its older parity
parent is not merged. Search-native files are carried byte-for-byte from the
green source except the CI workflow, which retains the current full-stack jobs.

## Search lifecycle

The native operations surface exposes `search.start`, `search.read`,
`search.list`, and `search.stop` using
`pc_executor.search_session.v1`. Search supports files/content modes,
regex-by-default or literal matching, ignore-case by default, bounded context,
hidden-file control, max-results, timeout, absolute pagination, negative-tail
reads, cancellation, retained terminal results, and retention GC.

Search IDs are opaque and generation-scoped. Executor restart makes persisted
IDs stale and fail-closed. Protected/sensitive paths are rejected before
traversal, and reparse/symlink escapes are not followed.

## Remote full-stack binding

The existing authenticated transport and Executor adapter remain authoritative.
The adapter adds only the four search lifecycle tools. Existing tool names and
semantics are preserved.

A remote search handle is bound to the control session, device ID, authenticated
transport epoch, and hello-time capability-manifest digest. A changed epoch or
capability digest fails closed with `STALE_SEARCH_HANDLE`. `search.list`
filters out handles from other epochs/digests. `search.stop` does not close the
handle, so final results remain readable for the native retention window.

The hello manifest advertises the native search actions through the current
operations capability snapshot and pins the evolved tool-registry digest.

## Verification

`tools/audit_full_stack_integration.py` verifies the exact base/source pins,
single-commit topology, byte identity of the search delta, absence of old relay
history, restricted remote transport drift, workflow coverage, and
`git diff --check`.

CI runs search lifecycle tests, native parity/schema checks, Windows search
fixtures, remote transport/adapter tests, the real full-stack integration suite,
and the complete test suite on Ubuntu and Windows.
