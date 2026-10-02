param(
    [Parameter(Mandatory = $true)]
    [string]$Repo,
    [string]$TaskName = 'OpenAI-PC-Relay-Watchdog',
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Repo = (Resolve-Path -LiteralPath $Repo).Path
$repoPattern = [regex]::Escape($Repo)
$matching = @(
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {
            $_.CommandLine -match 'github_relay\.py' -and
            $_.CommandLine -match $repoPattern
        }
)

$plan = [ordered]@{
    contract_version = 'pc_relay.autostart_plan.v1'
    operation = 'uninstall'
    apply = [bool]$Apply
    task_name = $TaskName
    repo = $Repo
    matching_relay_pids = @($matching | ForEach-Object { [int]$_.ProcessId })
    requires_relay_absent = $true
    deletes_runtime_state = $false
    deletes_outcome_journal = $false
    automatic_process_kill = $false
    automatic_replay = $false
}

if (-not $Apply) {
    $plan | ConvertTo-Json -Depth 4
    exit 0
}

if ($matching.Count -gt 0) {
    throw 'Relay process is still running; autostart uninstall refuses to alter registration until ownership is reconciled and the process is absent.'
}

Import-Module ScheduledTasks -ErrorAction Stop
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

# Runtime state and outcome journal are deliberately untouched.
$plan | ConvertTo-Json -Depth 4
