param(
    [Parameter(Mandatory = $true)]
    [string]$Repo,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedHead,
    [string]$ExpectedBranch = 'agent/pc-relay-watchdog-cutover-candidate-20261002',
    [string]$TaskName = 'OpenAI-PC-Relay-Watchdog',
    [int]$DelaySeconds = 30,
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($DelaySeconds -lt 5 -or $DelaySeconds -gt 600) {
    throw 'DelaySeconds must be in [5,600].'
}

$Repo = (Resolve-Path -LiteralPath $Repo).Path
$Launcher = Join-Path $Repo 'tools\start_pc_control_relay.ps1'
if (-not (Test-Path -LiteralPath (Join-Path $Repo '.git'))) {
    throw "Not a Git checkout: $Repo"
}
if (-not (Test-Path -LiteralPath $Launcher)) {
    throw "Relay launcher missing: $Launcher"
}

function Invoke-Git([string[]]$Arguments) {
    $output = & git -C $Repo @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "git failed: $($Arguments -join ' ')"
    }
    return (($output | Out-String).Trim())
}

$head = Invoke-Git @('rev-parse', 'HEAD')
$branch = Invoke-Git @('branch', '--show-current')
$dirty = Invoke-Git @('status', '--porcelain', '--untracked-files=no')

if ($head -ne $ExpectedHead) {
    throw "HEAD mismatch. expected=$ExpectedHead actual=$head"
}
if ($branch -ne $ExpectedBranch) {
    throw "Branch mismatch. expected=$ExpectedBranch actual=$branch"
}
if ($dirty) {
    throw 'Tracked relay checkout is dirty; autostart registration is refused.'
}

$userId = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$powerShell = (Get-Command powershell.exe -ErrorAction Stop).Source
$arguments = @(
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy', 'Bypass',
    '-File', ('"{0}"' -f $Launcher)
) -join ' '

$plan = [ordered]@{
    contract_version = 'pc_relay.autostart_plan.v1'
    operation = 'install'
    apply = [bool]$Apply
    task_name = $TaskName
    user_id = $userId
    trigger = 'AtLogOn'
    delay_seconds = $DelaySeconds
    executable = $powerShell
    arguments = $arguments
    working_directory = $Repo
    expected_head = $ExpectedHead
    expected_branch = $ExpectedBranch
    multiple_instances = 'IgnoreNew'
    run_level = 'Limited'
    preserves_state = '.pc-relay/state'
    preserves_outcome_journal = '.pc-relay/outcomes.jsonl'
    starts_task_immediately = $false
    automatic_process_kill = $false
    automatic_replay = $false
}

if (-not $Apply) {
    $plan | ConvertTo-Json -Depth 4
    exit 0
}

Import-Module ScheduledTasks -ErrorAction Stop

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    throw "Scheduled task already exists: $TaskName. Uninstall or reconcile it first."
}

$action = New-ScheduledTaskAction -Execute $powerShell -Argument $arguments -WorkingDirectory $Repo
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $userId
$trigger.Delay = "PT\${DelaySeconds}S"
$principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "PC relay watchdog autostart pinned to $ExpectedHead"

Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force:$false | Out-Null

# Registration does not start the task. Verify only static registration fields.
$registered = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
if ($registered.State -eq 'Running') {
    throw 'Task unexpectedly entered Running state during registration.'
}

$plan | ConvertTo-Json -Depth 4
