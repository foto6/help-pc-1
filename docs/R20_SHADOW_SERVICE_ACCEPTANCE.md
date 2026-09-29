# R20 shadow Windows service — source acceptance and live install gate

Date: 2026-09-29. Personal SINGLE OWNER. Full existing native tool capabilities are preserved. No OAuth, role system, new interactive login, global Python or unrelated service modification.

## Proven prior stack, pinned candidates

- Original LIVE producer, not modified: `foto6/help-pc-1@04f817299b46ecb0ffa8aa908ce84fdb4c3300d0`.
- Original LIVE Control, not modified: `foto6/help-pc-2@2e5e06ba6966435c0e49e49a9de6e9c550eae8f6`.
- Original LIVE Launcher and Bridge, not modified: `foto6/boss@792d3b0d1efbd73170f8e52f3a74c4dab882e092`, Bridge `cb852e013634287669f957253d13d8ef2b45cada`.
- Stage-1 R18 Control hardening `3a21044e3c45d48f1a64b19250ef24d59b7f3f8b`.
- Stage-2 TRUE Python installed-Wheel Control integration `foto6/help-pc-2@c3502aa9371d66332c9a90c95ce35e755e4aa131` (full Windows+Ubuntu CI green [36581937252](https://github.com/foto6/help-pc-2/actions/runs/36581937252)).
- Stage-2 real Python base `foto6/help-pc-1@30c65d04e905af61dd731904b454fb08153f589a`, SHA-verified Windows Wheel was `3636c60dde33c5f3bc4fcab419d87ad8690e01211403b2713501badfca668538` for that PRE-R20 producer source.
- Detailed tested process-mode end-to-end results: `foto6/boss/LOG/R19_REAL_PYTHON_PROCESS_STACK_2026-09-29.md`. Actual private signed Python + Relay + Control + MCP SDK, old-ID no redispatch on Control/Python/Relay restarts, real previous R15c-source-generated quiescent JSON migration PASS.

## R20: independent Windows SCM resource matrix

| Resource | FROZEN R15c | NEW R20 candidate |
| --- | --- | --- |
| SCM name | `PCNativeDeviceService` | `PCNativeCandidateR20` |
| Python service class | `pc_remote_transport.windows_service.PCNativeDeviceService` | `pc_remote_transport.r20_candidate.PCNativeCandidateR20Service` |
| Service custom `StateRoot` | existing R15c registration | dedicated R20 registration, must match exact expected root |
| Default ProgramData state | `%ProgramData%\\PCNativeDeviceService` | `%ProgramData%\\PCNativeCandidateR20` |
| LSA secret key | `L$OpenAI.PCNativeDeviceService` | `L$OpenAI.PCNativeCandidateR20` |
| Operations state | existing service-account default `pc-executor/operations` | injected `R20_STATE_ROOT/operations` (managed-processes, search sessions, native settings) |
| Signed transport | existing R15c channel | separate device ID, random secret and dedicated candidate Relay channel |
| Python runtime | original frozen service | isolated *installed-wheel* venv with its OWN pywin32 service host |
| Initial SCM StartType | old policy unchanged | **DEMAND_START**, never auto-start while staging |
| Uninstall/rollback | untouched | R20 ONLY; requires confirmed stopped before removal |

The isolated candidate secret adapter maps all three internal existing calls
`DEFAULT_SECRET_NAME` (read/write, including token rotation) to
`L$OpenAI.PCNativeCandidateR20`, and rejects unknown names. It never queries or
deletes the original LSA secret. The existing service runtime default behavior
remains unchanged because `operations_state_root` is an OPTIONAL injected
argument that defaults to the original behavior when omitted.

The candidate installer demands a separate installed-wheel venv and pywin32
binaries sourced from that SAME venv. It rejects globally installed/source
checkout execution, wrong/missing `StateRoot`, shared/overlapping state roots,
symlinks/junctions/reparse paths, a previously registered candidate SCM name,
and ambiguous error states. Failure of candidate `sc.exe failure` policy
programming removes **only** the newly created candidate service. It never
calls the inherited legacy installer.

## Safe operator order

Do not mix candidate registration with the prior `pc-native-device-service`
entrypoint. All commands below address R20 alone.

1. Build a new deterministic Wheel from EXACT R20 source SHA, hash it, and
   install it in a separate dedicated Windows venv that also contains an
   isolated copy of pywin32. Assert module imports from that venv's
   `site-packages`, not PYTHONPATH/source.
2. Capture a read-only hash/status snapshot of all four FROZEN live checkouts
   and the PID/status of `PCNativeDeviceService`; confirm that the R20 name
   does not already exist:
   `pc-native-r20-service preflight`.
3. Run source CI and separate candidate-only mock SCM/LSA tests. Check
   `StateRoot` equals exactly `%ProgramData%\\PCNativeCandidateR20`; never
   copy any R15c machine secret or live journal into it.
4. Only in an approved administrator-side shadow install test, run
   `pc-native-r20-service install`. This must install **only**
   `PCNativeCandidateR20` and initially set `DEMAND_START`; the original
   service must retain its existing PID and service configuration.
5. Configure an isolated private Relay endpoint and device ID, provision
   ONLY the new candidate LSA transport key from internally generated
   pairing bytes (not a user login), set candidate `--enable`, then manually
   `start`. Check real SCM state + health + signed handshake, replay an
   old request ID, restart the candidate, check journal/epoch, verify
   original R15c still healthy throughout.
6. Rollback: `stop` candidate, wait until its own status is `stopped`,
   `uninstall` candidate (ONLY its own SCM name and candidate LSA key, R20
   config disabled). Original R15c running/PID/config must remain unchanged.
   Candidate state/audit retained for diagnosis. Verify no test worker
   processes remain. OS cold-reboot/autostart is a SEPARATE acceptance gate
   and must be tested on a dedicated Windows VM.

## Current evidence definitions — do not confuse

- R20 static and mock controller CI on Windows+Ubuntu proves exact source
  scope, state/secret isolation and rollback control flow **without SCM install**.
- Manual R19 Windows real installed-Wheel process-mode test proves full signed
  Python↔Relay↔Control↔MCP with controlled TEMP file operations and restarts.
- Neither alone proves that `PCNativeCandidateR20` was registered in SCM or
  that a rebooted PC automatically starts it. Claim this only after observing
  the actual candidate status/health, candidate-only removal and original
  R15c unchanged on the authorized Windows machine or a dedicated VM.

No new GitHub action is allowed to install a Windows service or handle a real
machine secret. No hourly/periodic automation is created.

## Windows independent packaging and observed privilege gate

The first isolated R20 source SHA `975e342a76acca0e455f01a2cf3104ed1f9266fb` passed BOTH exact-head R20 GitHub Windows and Ubuntu full test jobs ([36585926816](https://github.com/foto6/help-pc-1/actions/runs/36585926816)) and a separate complete local Windows Python test run (exit `0`). Its first SHA-verified Wheel was `968a21291c781a200da41f71c470a306c32801aae49f85c93b0a15979bdc31aa`; **this is evidence for that prior SHA, NOT a hash for later R20 source changes.** Wheel module imported from the isolated venv's own `site-packages`, and the new `pc-native-r20-service` CLI resolved.

Independent first read-only Windows preflight showed candidate SCM name **not registered**, with original service still running. Additional checks exposed two distinct conditions: remote interactive process did not have an elevated Administrator token and pywin32 initially resolved from the global Python 3.12 site-packages.

The second condition was corrected **inside the private R20 venv only** by explicitly installing `pywin32==312` into its own site-packages. `win32service.__file__` now resolves under that R20 venv. The original service's own `_stage_isolated_service_host` routine was then invoked only against the isolated venv; it successfully staged `pythonservice.exe`, version-matching DLLs and `pythonservice._pth` there. Staged private host SHA-256: `e26e252534fd4833c24a6ebad8051482049ddece1b762b556dcec60ee1e03dce`. No SCM/LSA or global Python mutation occurred.

**Remaining actual host condition:** the authorized Desktop Commander session reported `ELEVATED_ADMIN_TOKEN=False`. This cannot be turned into an actual SCM acceptance by a green unit test, and no elevation bypass, hidden UAC operation or legacy service stop is attempted. R20 CLI now reports name availability **separately** from `candidate_install_eligible`; preflight additionally checks candidate wheel import, private pywin32 location, separate venv and current Windows elevated token. An unready installer is blocked BEFORE binary staging. The tested candidate source includes explicit fake-win32 SCM API tests proving `SERVICE_DEMAND_START`, candidate-only `StateRoot` binding and candidate-only removal on installation failure.

The original first CI failure at `68d0d860...` was a TEST EXPECTATION ERROR: it incorrectly rejected the internal protocol key `DEFAULT_SECRET_NAME`, which must be safely mapped to the distinct R20 LSA secret without ever exposing the old key to LSA. Negative tests now reject truly unknown internal names and assert the underlying recorder sees ONLY `L$OpenAI.PCNativeCandidateR20`. Do not erase that initial failure from the engineering record.

No Windows SCM candidate install, OS reboot or actual LSA candidate key write has yet occurred. Final R20 source SHA, final Wheel SHA and final exact-head CI run must be recorded after all amendments.
