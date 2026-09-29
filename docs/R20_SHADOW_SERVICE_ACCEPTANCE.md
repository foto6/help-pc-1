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

## Final verified R20 candidate artifact and read-only install readiness

R20 source commit before this documentation-only evidence update:
`7c040bc8ece85b6c130c38592992aa5c03f12943`.

### Independently verified source tests

- Exact source HEAD Windows+Ubuntu full targeted and complete pytest jobs: [GitHub Actions 36586579102](https://github.com/foto6/help-pc-1/actions/runs/36586579102), **both completed SUCCESS**; PR companion run [36586586321](https://github.com/foto6/help-pc-1/actions/runs/36586586321) also completed SUCCESS.
- Fresh, separate local authorized Windows checkout at that EXACT tracked-clean source SHA: targeted R20/old-service/artifact pytest **exit 0** (two preexisting environment skips); complete pytest **exit 0** (8 expected platform/fixture skips). Both original outputs retained as `r20-final-targeted-windows.log` and `r20-final-full-windows.log` inside the isolated source clone under TEMP. Early CI failed due to an incorrectly written secret-alias negative test; that test was corrected and the exact post-fix CI independently passed.
- Actual `pc-native-r20-service` CLI comes from the **installed candidate Wheel** in its private venv. No source checkout is injected by `PYTHONPATH`.

### Byte-verified independently installed Windows package

- Source SHA `7c040bc8ece85b6c130c38592992aa5c03f12943`.
- Wheel `pc_executor-0.1.0-py3-none-any.whl` SHA-256:
  `b6f5edd097cf996d88ef0087973d91a66b31bad0b9ef5521c60dac153602aac9`.
- Isolated candidate package location:
  `%TEMP%\\native-pc-r20-final-artifact-20260929\\venv\\Lib\\site-packages\\pc_remote_transport\\r20_candidate.py`.
- `pywin32==312` independently installed in the SAME private venv; `win32service.pyd` resolves under its own `Lib/site-packages/win32`. Original isolated `_stage_isolated_service_host` successfully produced a complete private `pythonservice.exe` in that venv; binary SHA-256:
  `e26e252534fd4833c24a6ebad8051482049ddece1b762b556dcec60ee1e03dce`.
- Strict test invoked `<private-venv-python> -I` with `PYTHONPATH` unset and the working directory moved **outside** the source checkout, confirmed both service module and pywin32 package physically inside the isolated venv.
- An earlier preflight after `pytest` flagged `installed_wheel=false` because the calling PowerShell still had source checkout `PYTHONPATH` in its environment; this was a VALID fail-closed signal and was corrected by explicitly removing that environment variable and using Python `-I`, **not** by bypassing the guard.

### Actual installed-artifact preflight on the authorized PC

Read-only command `<R20-private-venv-python> -I -m pc_remote_transport.r20_candidate_cli preflight` produced:

```json
{
  "blockers": ["elevated_token"],
  "candidate_install_eligible": false,
  "candidate_name_available": true,
  "candidate_scm_state": "not_installed",
  "candidate_service": "PCNativeCandidateR20",
  "candidate_state_root": "C:\\ProgramData\\PCNativeCandidateR20",
  "environment": {
    "elevated_token": false,
    "installed_wheel": true,
    "private_pywin32": true,
    "separate_venv": true,
    "windows": true
  },
  "legacy_service_touched": false,
  "machine_secret_read": false
}
```

Intentional code `2`: the **ONLY remaining local install prerequisite is an elevated Windows token**. The authorized Remote Desktop Commander session is not running elevated. Do not claim this is an SCM-installed or boot-tested service; the guard intentionally prevents the attempted registration before any machine mutation.

Last independent live read-only check: original `PCNativeDeviceService=Running`, PID `16944`. Original frozen checkouts were previously independently confirmed tracked-clean. The R20 SCM name is currently free and no R20 service has been registered. No Windows LSA secret has been created/deleted and no real installed service has been restarted.

**Precise verdict:** R20 source + Python regressions + private installed-Wheel/pywin32/service-host packaging + SCM-negative/preflight acceptance **PASS**; administrator-only candidate SCM register/start/stop/uninstall, cold restart/autostart, and production cutover **NOT EXECUTED**. Proceed only via separately approved elevated shadow-service lane, preserving old R15c.

## R20 final REAL dual-SCM acceptance on DISPOSABLE Windows GitHub runner

**First genuinely installed Windows SCM gate now PASSED on a clean disposable Windows runner, without attempting any installation on the user's non-elevated actual PC.** The test used TWO separate SHA-pinned installed Wheels and two private pywin32 service hosts:

- Original immutable live-code R15c source: `foto6/help-pc-1@04f817299b46ecb0ffa8aa908ce84fdb4c3300d0`.
- R20 candidate source HEAD used in this test: `90fdd2aaae9ba4f2fe97fbff3ff62c97ea0645de`, code unchanged from the previously independently fully tested exact source `7c040bc8ece85b6c130c38592992aa5c03f12943` except documentation, isolated workflow, and PowerShell pipeline-output repair.
- Disposable SCM workflow: [GitHub Actions 36588533191](https://github.com/foto6/help-pc-1/actions/runs/36588533191), job `two-real-native-services-cold-runner` **completed SUCCESS**, zero failed steps. The dedicated source workflow at this exact head [36588533097](https://github.com/foto6/help-pc-1/actions/runs/36588533097) has **Windows SUCCESS / Ubuntu SUCCESS**; duplicate [36588540366](https://github.com/foto6/help-pc-1/actions/runs/36588540366) likewise Windows+Ubuntu SUCCESS.
- Sanitized actual dual-SCM artifact: [r20-two-real-services-36588533191](https://github.com/foto6/help-pc-1/actions/runs/36588533191/artifacts/11042976081), GitHub artifact ZIP SHA-256 `e7c454d1fc4aee06554c1c9e82e698df332d66d1e1627a68602a308a87b66988`. No service secrets, state JSON, registry binary exports or token bytes are uploaded.

Verified actual Windows-SCM report from the runner's execution log (not an offline mock):

```json
{
  "schema": "pc_native.r20_two_real_windows_scm_coexistence.v1",
  "both_names_initially_absent": true,
  "legacy_r15_installed_running": true,
  "candidate_r20_installed_running": true,
  "distinct_service_pids_and_state_roots": true,
  "legacy_pid_unchanged_after_candidate_restart": true,
  "candidate_removed_while_legacy_running": true,
  "legacy_pid_unchanged_after_candidate_uninstall": true,
  "both_services_uninstalled": true,
  "rollback_complete": true,
  "status": "PASS"
}
```

Actual implementation calls the **real** frozen R15c service CLI and the **real** candidate R20 service CLI. It verifies exact pinned old source ancestry, both SCM identities absent before installing either test-owned service, two independent installed-wheel/private pywin32 service hosts, both SCM services RUNNING with distinct PID/state root, candidate initially **Manual / DEMAND_START**, candidate restart without legacy PID change, candidate-only stop/uninstall without interrupting still-running legacy, then controlled removal of original disposable test service. Both SCM entries absent after cleanup. All commands are restricted to this disposable runner by the script's environment guard; the actual user's R15c service and machine LSA are not accessed.

**Repro evidence correction preserved:** the first disposable CI attempt [36588277199](https://github.com/foto6/help-pc-1/actions/runs/36588277199) failed in its PowerShell Wheel factory because pip progress stdout and a SHA Write-Output were accidentally returned with the single intended Python venv path. One narrow commit piped pip output to `Out-Null` and emitted the hash with `Write-Host`. The later exact candidate run [36588533191](https://github.com/foto6/help-pc-1/actions/runs/36588533191) passed the full REAL two-service lifecycle and rollback.

**Updated R20 gate decision:**

1. Source, targeted/full tests, candidate state/LSA/operations isolation and SHA-verified installed-wheel packaging: **PASS**.
2. Real Windows SCM installation, parallel operation, candidate restart and candidate-only rollback against real frozen R15c on a disposable GitHub Windows runner: **PASS**.
3. Same side-by-side registration on the user's real PC: **NOT ATTEMPTED** because current Desktop Commander Windows token is not elevated. Existing R15c on that PC remained Running PID `16944`, candidate name unregistered.
4. True OS reboot/autostart (not simply SCM manual restart), long-duration stress, unrestricted full tool operation and actual cloud ChatGPT plugin registration: **NOT CLAIMED**; distinct later acceptance gates. Candidate intentionally starts as DEMAND_START while being staged; no auto-start was configured.
