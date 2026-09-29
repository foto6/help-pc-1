# R21 — real signed Python → Node float canonicalization regression

Date: 2026-09-29. Source-only fix; original R15c and R20 user service are UNCHANGED.

## Independently reproduced defect

Real signed Python producer `foto6/help-pc-1@30c65d04e905af61dd731904b454fb08153f589a`
connected to `foto6/help-pc-2@c3502aa9371d66332c9a90c95ce35e755e4aa131`,
the built-in Relay and Control, and the official MCP SDK. All 28 Desktop
Commander compatibility operation names were present and shown available
by the live producer capability manifest. **That is only discovery, not 28
successfully executed operations.**

The independent R21 Windows safe-operation runner obtained **17 distinct
REAL completed compatibility operations**, including two real private TEMP
file writes/edit/move, true multi-file batch, search start/read/stop and
secret-sanitized usage/identity/audit. The old file.write ID did NOT replay
over later edits. URL-mode read correctly failed closed without any side
effect.

`list_searches` reproducibly returned `reconciliation_required`, even
before any search session was started. Private diagnostic instrumentation
proved the REAL Python `ExecutorRemoteDispatcher` had already returned
`DispatchResult(payload.status="completed")` for the native `search.list`.
A standalone REAL Python Executor `search.list` independently succeeded.
The signed Relay then failed its read-only delivery with device connection
lost. This is not evidence of a completed functional `list_searches`.

A minimal cross-language reproduction showed the cause in the old signed
wire canonicalizer:

```text
Python  canonical_json({"retention_seconds":900.0,"runtime_ms":0})
        {"retention_seconds":900.0,"runtime_ms":0}
Node    JSON.stringify({retention_seconds:900.0,runtime_ms:0})
        {"retention_seconds":900,"runtime_ms":0}
```

The actual producer's `SearchSessionManager.list()` includes the numeric
float `retention_seconds`; Python signs `900.0`, whereas JavaScript's
recomputed canonical HMAC uses numeric `900`. The same underlying
precision/signed-frame concerns previously required JS-safe integer
hardening. Because signature checks are necessary, **do not bypass HMAC or
turn off Relay verification** to work around this.

## Narrow source fix

`pc_remote_transport.protocol._js_safe_json` now canonically normalizes
finite integral Python float leaves (including negative zero) before both
HMAC signing and JSON wire emission. Integral floats above the JS safe
integer bound become canonical decimal strings, matching existing
`int` policy. Non-finite floats fail closed; ordinary finite fractional
floats (for example 1.5) retain numeric representation.

New `tests/test_r21_signed_float_canonical.py` exercises nested data,
integer floats, signed zero, oversized numeric safety, non-finite errors,
and an actual signed frame. Dedicated `r21-signed-float.yml` additionally
constructs the exact signed Python frame and independently re-verifies its
HMAC with Node `JSON.stringify` on both Windows and Ubuntu. This
particular fix does NOT purport to implement all exotic IEEE754 decimal
formatting cases, such as every arbitrary fractional exponent boundary;
those require their own cross-language corpus if future real data
demonstrates the need.

## Release boundary

- The SOURCE + CI milestone requires exact-head Windows and Ubuntu
  full pytest and Node HMAC verification.
- R21 real-host acceptance separately requires building a wheel from the
  fixed exact Python SHA, installing into private Windows TEMP venv and
  repeating the real signed Python ↔ Node Relay ↔ Control ↔ MCP SDK
  `list_searches` and bounded compatibility operations, with an identical
  fixed Control SHA. A passing Python-only unit test is NOT this result.
- No source changes are permitted to frozen old R15c, production Bridge,
  current fixed-name Windows service, or any protected/user files.
- Vendor-only Desktop Commander get_prompts/give_feedback are not target
  equivalents. Destructive `kill_process`, shutdown, arbitrary shell
  commands and real user-configuration mutations are excluded from the
  safe private parity lane, NOT deceptively counted as passed.
