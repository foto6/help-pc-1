# Native PC Device Service

This component hosts the existing pc_remote_transport.DeviceAgent as a real Windows
Service. It is an installability/operations layer only: transport requests still flow
through the native Executor dispatcher when that adapter is present.

## Security model

- The service is **disabled by default**. Installing or starting the Windows service does
  not enable remote transport.
- config.json under machine app-data contains only non-secret settings.
- Token material is stored as Windows LSA private data in machine policy so the
  LocalSystem service can read it after an Administrator bootstrap. The token is never
  accepted on the command line.
- CLI status and the health file expose secret_source as <redacted>; they do not expose
  the LSA secret name or token bytes.
- Windows Event Log messages are fixed strings and never contain exception text,
  configuration values, tokens, or secret identifiers.
- The service state root rejects the protected E:\manhwa tree before any filesystem
  access can occur.
- The relay endpoint must use wss://. Plain ws:// is accepted only for explicit
  loopback configuration. URL userinfo, query strings, and fragments are rejected so
  bearer material cannot be persisted inside the non-secret endpoint setting.
- If the Executor adapter is not present in the integrated build, runtime startup fails
  closed with health reason RUNTIME_UNAVAILABLE; no fallback side-effect engine exists.

## Files and state

Default machine state root:

    %ProgramData%\PCNativeDeviceService

Non-secret files include:

- config.json — versioned service configuration.
- config.backup.json — previous atomic configuration snapshot.
- health.json — redacted service/transport health.
- request-ledger\ — transport idempotency ledger.
- audit.jsonl and outcome-journal.jsonl — existing Executor audit/outcome paths
  after the Executor adapter is integrated.

Configuration writes are staged, fsynced, atomically replaced, re-read, and rolled back
to the previous bytes if post-write validation fails.

## Install / bootstrap

Run the bootstrap from an Administrator PowerShell. If it is not elevated, it
self-elevates before prompting for configuration.

    .\tools\install_pc_native_device_service.ps1 \
      -Endpoint "wss://relay.example/device" \
      -DeviceId "workstation-01"

That installs and starts the Windows service but leaves transport disabled. To opt in
during bootstrap, add -Enable.

The bootstrap creates an isolated virtual environment under ProgramData, installs the
current repository build into it, prompts for the token with hidden input, stores it as
Windows LSA private data, configures SCM crash recovery, and starts the service.

## CLI commands

    pc-native-device-service install
    pc-native-device-service start
    pc-native-device-service stop
    pc-native-device-service restart
    pc-native-device-service status
    pc-native-device-service uninstall

Configure non-secret settings atomically:

    pc-native-device-service configure \
      --endpoint "wss://relay.example/device" \
      --device-id "workstation-01"

    pc-native-device-service configure --enable
    pc-native-device-service configure --disable

Store or rotate the machine secret without placing token bytes in argv or logs:

    pc-native-device-service secret set --generation 1

The command prompts for base64 token material with hidden input. Protocol-driven token
rotation persists the new generation and secret to Windows LSA private data before
sending token.rotated; a persistence failure prevents acknowledgement.

uninstall removes the SCM service, deletes the LSA private-data entry, and forces the
retained non-secret configuration back to enabled=false.

## Health contract

pc.native.device_service.health.v1 reports:

- SCM/service state (CLI adds the live SCM state).
- configured enabled/disabled state.
- device ID.
- current session epoch.
- transport state such as disabled, connecting, handshaking, connected, backoff,
  blocked, or stopped.
- last observed heartbeat timestamp.
- exact capability-manifest digest advertised by the transport.
- non-secret configuration revision.
- machine-readable reason code for blocked states.

The host watches config and machine-secret generation while running. A kill-switch
disable, token rotation, or configuration change cancels the active transport task cleanly
and reevaluates configuration before reconnecting. Ordinary connection failures continue
to use the existing bounded DeviceAgent.run_forever backoff.

## Windows recovery

Installation configures SCM recovery to restart after crashes with escalating delays:

    5 seconds -> 15 seconds -> 60 seconds

The recovery period resets after 24 hours and recovery actions are enabled for non-crash
service failures as well.

## Integration boundary

This lane intentionally does not copy the Executor adapter. At runtime,
build_default_runtime imports pc_remote_transport.executor_adapter.ExecutorRemoteDispatcher.
After the independent adapter lane is integrated, the service constructs the existing
Executor with its audit and durable outcome journal, uses the adapter capability manifest,
and passes that dispatcher into the existing DeviceAgent.

Until that adapter is available in the build, the service remains observable but blocked;
it does not invent a second dispatch or side-effect path.
