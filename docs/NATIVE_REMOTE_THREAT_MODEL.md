# Native Remote Transport Threat Model

Scope: `pc_remote_transport` message delivery between one device agent and a relay.
Application authorization, Executor policy and control-plane tool schemas are outside
this layer and must remain independently enforced.

| Threat / failure | Required behavior | Mechanism | Deterministic coverage |
| --- | --- | --- | --- |
| Forged device | Reject before dispatch | Per-device HMAC token, authenticated device ID and hello | `test_forged_device_or_token_is_rejected` |
| Forged relay | Reject before dispatch | Relay `welcome` and all inbound frames require the same per-device token | authenticated E2E handshake tests |
| Stale epoch | Reject | Fresh device-created session epoch is bound into every HMAC frame | `test_stale_session_epoch_is_rejected` |
| Replayed frame | Reject | Strict monotonic inbound sequence per epoch | `test_replay_and_reordered_frame_sequence_are_rejected` |
| Duplicate logical request | Harmless | Durable request fingerprint + cached completed response | `test_local_e2e_duplicate_delivery_is_harmless` |
| Request-ID substitution | Reject | Fingerprint binds request ID, version, semantics and body | duplicate/conflict path in `DeviceAgent` |
| Reordered stream chunks | Reject | Monotonic chunk index and declared chunk count | `test_stream_integrity_round_trip_and_reordered_chunk_rejection` |
| Corrupted stream | Reject | Per-chunk and whole-stream SHA-256 plus byte counts | stream integrity tests |
| Disconnect after dispatch | Never blind-replay | Durable state is written before dispatch; completed state is cached; unresolved dispatch becomes reconciliation | disconnect + unknown-outcome tests |
| Device crash/power loss after dispatch start | Surface unknown | Durable `dispatch_started` becomes `UNKNOWN_RECONCILE` on redelivery | `test_unknown_prior_side_effect_requires_reconciliation_never_replays` |
| Token theft after rotation | Old generation rejected | Rotation advances generation exactly one and immediately changes verification key | `test_token_rotation_switches_generation_and_rejects_old_token` |
| Oversized frame/request/stream | Reject before unbounded work | Explicit byte limits at frame, request, chunk and stream layers | oversized frame/request and stream-bound tests |
| Compression bomb | Avoid | WebSocket compression disabled; bounded decoded frame size | connector configuration + frame limits |
| Credential leakage via repository | Avoid | Native RPC state is never stored in Git; token comes from deployment configuration | architecture invariant |
| Raw shell exposure by transport | Avoid | Transport sees only opaque body plus generic semantics; no shell/action registry exists in transport | module layering + review |
| Dual-transport side effects during fallback | Block operationally | Migration requires quiesce/reconcile before enabling historical fallback | migration runbook |

## Trust and deployment assumptions

- Each device receives a unique high-entropy token of at least 256 bits.
- Remote production endpoints use `wss://` with normal certificate validation.
- Relay authorization maps the authenticated token to exactly one expected device ID.
- The device runtime directory is writable only by the local service identity.
- Token persistence/rotation uses an OS secret store in production. The in-memory
  `TokenRing` is the protocol primitive, not a secret-storage product.
- The application dispatcher validates its own schema and authorization. Transport
  metadata such as `semantics` is not a substitute for Executor outcome journaling or
  policy checks.

## Residual risks

A stolen current device token permits impersonation until rotation/revocation. HMAC
authentication does not provide confidentiality without TLS. The transport request
ledger is local durability, not a distributed transaction; after an unresolved
side-effect dispatch, only the application/Executor reconciliation source of truth can
determine outcome. This is why native transport never guesses and never auto-replays
that state.
