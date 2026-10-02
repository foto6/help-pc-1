param(
    [switch]$StatusOnly,
    [double]$StaleAfterSeconds = 30,
    [long]$LogMaxBytes = 5242880,
    [int]$LogBackupCount = 3
)

$ErrorActionPreference = 'Stop'

$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$RelayScript = Join-Path $Repo 'tools\github_relay.py'
$LogDir = Join-Path $Repo '.pc-relay'
$Stdout = Join-Path $LogDir 'live.stdout.log'
$Stderr = Join-Path $LogDir 'live.stderr.log'

if (-not (Test-Path -LiteralPath (Join-Path $Repo '.git'))) {
    throw "PC Control repo is not a Git checkout: $Repo"
}
if (-not (Test-Path -LiteralPath $RelayScript)) {
    throw "Relay script not found: $RelayScript"
}

$py = Get-Command py.exe -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command py -ErrorAction SilentlyContinue }
if (-not $py) { throw 'Python launcher "py" was not found.' }

function Get-RelayProcesses {
    $repoPattern = [regex]::Escape($Repo)
    return @(
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object {
                $_.CommandLine -match 'github_relay\.py' -and
                $_.CommandLine -match $repoPattern
            }
    )
}

function Invoke-RelayStatus([object[]]$Processes) {
    $args = @(
        $RelayScript,
        '--repo', $Repo,
        '--status',
        '--stale-after-seconds', ([string]$StaleAfterSeconds)
    )
    foreach ($proc in $Processes) {
        $args += @(
            '--observed-process',
            ('{0}:{1}' -f [int]$proc.ProcessId, [int]$proc.ParentProcessId)
        )
    }

    $raw = & $py.Source @args
    $exitCode = $LASTEXITCODE
    if (-not $raw) {
        throw "Relay status command returned no JSON. Exit code: $exitCode"
    }
    $status = ($raw | Out-String | ConvertFrom-Json)
    return [pscustomobject]@{
        ExitCode = $exitCode
        Status = $status
    }
}

function Rotate-BoundedLog([string]$Path) {
    if ($LogMaxBytes -lt 1024 -or $LogBackupCount -lt 1 -or $LogBackupCount -gt 20) {
        throw 'Log bounds must be LogMaxBytes>=1024 and LogBackupCount in [1,20].'
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $item = Get-Item -LiteralPath $Path
    if ($item.Length -lt $LogMaxBytes) {
        return
    }
    for ($i = $LogBackupCount; $i -ge 1; $i--) {
        $older = if ($i -eq 1) { $Path } else { "$Path.$($i - 1)" }
        $newer = "$Path.$i"
        if (Test-Path -LiteralPath $newer) {
            Remove-Item -LiteralPath $newer -Force
        }
        if (Test-Path -LiteralPath $older) {
            Move-Item -LiteralPath $older -Destination $newer -Force
        }
    }
}


function Show-UnhealthyRecovery([object]$Status) {
    Write-Host ("Relay state: {0}" -f $Status.state)
    if ($Status.stale_reasons) {
        Write-Host ("Stale reasons: {0}" -f (($Status.stale_reasons | ForEach-Object { [string]$_ }) -join ', '))
    }
    if ($Status.observations) {
        Write-Host ("Local HEAD: {0}" -f $Status.observations.local_head)
        Write-Host ("Remote-tracking HEAD: {0}" -f $Status.observations.remote_tracking_head)
        Write-Host ("HEAD relation: {0}" -f $Status.observations.head_relation)
        if ($Status.observations.remote_tracking_queue) {
            Write-Host ("Remote-tracking backlog: {0}" -f $Status.observations.remote_tracking_queue.backlog_count)
        }
    }
    if ($Status.process) {
        Write-Host ("Matching PIDs: {0}" -f (($Status.process.matching_pids | ForEach-Object { [string]$_ }) -join ', '))
        Write-Host ("Logical relay roots: {0}" -f (($Status.process.logical_roots | ForEach-Object { [string]$_ }) -join ', '))
    }
    Write-Host ''
    Write-Host 'SAFE RECOVERY REQUIRES OPERATOR ACTION:'
    Write-Host '1. Preserve .pc-relay\state and .pc-relay\outcomes.jsonl.'
    Write-Host '2. Do not submit replacement side-effect requests.'
    Write-Host '3. Verify ownership of the stale logical process tree before terminating it manually.'
    Write-Host '4. Restart only through this launcher after the old tree is confirmed absent.'
    Write-Host '5. Existing started side-effect request IDs must reconcile through outcome.lookup; liveness recovery never authorizes replay.'
    Write-Host 'No process was killed or restarted automatically.'
}

$existing = Get-RelayProcesses
$statusResult = Invoke-RelayStatus -Processes $existing
$status = $statusResult.Status

if ($StatusOnly) {
    Write-Output ($status | ConvertTo-Json -Depth 8 -Compress)
    exit $statusResult.ExitCode
}

if ($existing.Count -gt 0) {
    if ($status.state -eq 'HEALTHY') {
        Write-Host "PC Control relay is already running and healthy."
        Write-Host ("Logical roots: {0}" -f (($status.process.logical_roots | ForEach-Object { [string]$_ }) -join ', '))
        exit 0
    }

    Write-Host 'PC Control relay process exists but is not proven healthy.'
    Show-UnhealthyRecovery -Status $status
    Write-Host "Logs: $LogDir"
    exit 2
}

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
Rotate-BoundedLog -Path $Stdout
Rotate-BoundedLog -Path $Stderr

$args = @($RelayScript, '--repo', $Repo, '--live')
$p = Start-Process -FilePath $py.Source -ArgumentList $args -WorkingDirectory $Repo -WindowStyle Hidden -RedirectStandardOutput $Stdout -RedirectStandardError $Stderr -PassThru

Start-Sleep -Seconds 2

$startedProcesses = Get-RelayProcesses
if ($startedProcesses.Count -eq 0) {
    Write-Host 'PC Control relay failed to stay running.'
    if (Test-Path -LiteralPath $Stderr) { Get-Content -LiteralPath $Stderr -Tail 30 }
    exit 1
}

$startedStatusResult = Invoke-RelayStatus -Processes $startedProcesses
$startedStatus = $startedStatusResult.Status
if ($startedStatus.state -eq 'HEALTHY') {
    Write-Host "PC Control relay started and is producing healthy forward-progress evidence."
    Write-Host ("Logical roots: {0}" -f (($startedStatus.process.logical_roots | ForEach-Object { [string]$_ }) -join ', '))
    Write-Host "Logs: $LogDir"
    exit 0
}

Write-Host "PC Control relay started, but health is not yet proven."
Show-UnhealthyRecovery -Status $startedStatus
Write-Host "Logs: $LogDir"
exit 2
