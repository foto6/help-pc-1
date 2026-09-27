# GitHub PC Relay

This relay is a fallback transport for the existing PC Executor when no direct remote-desktop/MCP transport is available.

It does **not** replace Executor safety. Requests are converted to normal `ActionRequest` values and executed by `pc_executor.Executor` with the outcome journal enabled.

## Security model

- Use a dedicated checkout of the private repository.
- The relay is off unless you explicitly run it.
- Default mode is dry-run.
- `--live` is required for side effects.
- Raw coordinate fallback remains disabled.
- Credentials/CAPTCHA rules remain unchanged.
- `E:\manhwa` remains protected by the Executor path checks.
- The relay exposes only a small action set by default.
- PowerShell/cmd are added only to the relay-local shell adapter, not the global Executor allowlist.
- Anyone who can push a valid request to this private branch can ask the relay to execute an enabled action. Stop the relay when you do not want remote execution.

## Windows setup

Use a separate checkout so the relay never changes an active development worktree.

~~~powershell
cd E:\
git clone -b agent/pc-github-relay https://github.com/foto6/help-pc-1.git pc-github-relay
cd E:\pc-github-relay
py -m pip install -e ".[test]"
pytest -q tests\test_github_relay.py
~~~

First run in dry-run mode:

~~~powershell
py tools\github_relay.py --repo E:\pc-github-relay --once
~~~

For the persistent live relay:

~~~powershell
py tools\github_relay.py --repo E:\pc-github-relay --live
~~~

Stop it with `Ctrl+C`.

## Queue format

Requests are immutable files under `relay/requests/<id>.json`:

~~~json
{
  "version": "pc_relay.request.v1",
  "id": "example-001",
  "action": "shell.run",
  "params": {
    "argv": ["powershell.exe", "-NoProfile", "-Command", "Write-Output PC_RELAY_OK"],
    "cwd": "E:\\"
  },
  "timeout_ms": 10000
}
~~~

Results are committed under `relay/results/<id>.json`.

A request ID is executed at most once by the local relay state. If the relay crashes after a side-effect request starts, it does **not** blindly replay the request; it returns/reconciles outcome-journal evidence instead.

## Recommended bootstrap

1. Run the one-shot dry-run command.
2. Confirm that `relay/results/bootstrap-capabilities.json` appears on the branch.
3. Start the persistent relay with `--live`.
4. Submit a separate PowerShell echo request and verify the returned stdout.
5. Only after that use it for orchestration commands.
