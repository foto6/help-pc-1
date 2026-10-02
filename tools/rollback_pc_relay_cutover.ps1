param(
    [Parameter(Mandatory = $true)]
    [string]$Repo,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$PreviousHead,
    [string]$PreviousBranch = 'agent/pc-github-relay',
    [string]$TaskName = 'OpenAI-PC-Relay-Watchdog',
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Repo = (Resolve-Path -LiteralPath $Repo).Path
if (-not (Test-Path -LiteralPath (Join-Path $Repo '.git'))) {
    throw "Not a Git checkout: $Repo"
}

function Invoke-Git([string[]]$Arguments) {
    $output = & git -C $Repo @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "git failed: $($Arguments -join ' ')"
    }
    return (($output | Out-String).Trim())
}

$repoPattern = [regex]::Escape($Repo)
$matching = @(
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {
            $_.CommandLine -match 'github_relay\.py' -and
            $_.CommandLine -match $repoPattern
        }
)

$dirty = Invoke-Git @('status', '--porcelain', '--untracked-files=no')
if ($dirty) {
    throw 'Tracked relay checkout is dirty; exact rollback is refused.'
}

$commitSpec = $PreviousHead + '^{commit}'
& git -C $Repo cat-file -e $commitSpec 2>$null
if ($LASTEXITCODE -ne 0) {
    throw "PreviousHead is not available locally: $PreviousHead"
}

$previousRemote = (& git -C $Repo rev-parse "refs/remotes/origin/$PreviousBranch" 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $previousRemote -ne $PreviousHead) {
    throw "Previous live branch pin mismatch. expected=$PreviousHead observed=$previousRemote"
}

$statePath = Join-Path $Repo '.pc-relay\state'
$journalPath = Join-Path $Repo '.pc-relay\outcomes.jsonl'

$plan = [ordered]@{
    contract_version = 'pc_relay.rollback_plan.v1'
    operation = 'rollback'
    apply = [bool]$Apply
    repo = $Repo
    previous_branch = $PreviousBranch
    previous_head = $PreviousHead
    checkout_mode = 'detached_exact_head'
    task_name = $TaskName
    matching_relay_pids = @($matching | ForEach-Object { [int]$_.ProcessId })
    preserves_state_path = $statePath
    preserves_outcome_journal = $journalPath
    starts_relay = $false
    automatic_process_kill = $false
    automatic_replay = $false
}

if (-not $Apply) {
    $plan | ConvertTo-Json -Depth 4
    exit 0
}

if ($matching.Count -gt 0) {
    throw 'Relay process is still running; exact rollback refuses to change code while process ownership is active.'
}

Import-Module ScheduledTasks -ErrorAction Stop
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

# Detach to the exact recorded pre-cutover SHA. This does not move or rewrite
# agent/pc-github-relay. Ignored .pc-relay state/outcomes remain in place.
Invoke-Git @('checkout', '--detach', $PreviousHead) | Out-Null

$actual = Invoke-Git @('rev-parse', 'HEAD')
if ($actual -ne $PreviousHead) {
    throw "Rollback HEAD verification failed. expected=$PreviousHead actual=$actual"
}

$plan | ConvertTo-Json -Depth 4
