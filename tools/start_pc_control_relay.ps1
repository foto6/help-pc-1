param(
    [double]$StallSeconds = 15.0
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
    return @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.CommandLine -match 'github_relay\.py' -and
        $_.CommandLine -match $repoPattern
    })
}

function Get-RelayHealth([int[]]$ObservedPids, [Nullable[int]]$ExpectedPid) {
    $probeArgs = @(
        'tools\github_relay.py',
        '--repo', $Repo,
        '--health',
        '--stall-seconds', ([string]$StallSeconds)
    )
    foreach ($pidValue in $ObservedPids) {
        $probeArgs += @('--observed-pid', ([string]$pidValue))
    }
    if ($null -ne $ExpectedPid) {
        $probeArgs += @('--expected-pid', ([string]$ExpectedPid.Value))
    }
    $raw = & $py.Source @probeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Relay health probe failed with exit code $LASTEXITCODE"
    }
    return ($raw | Out-String | ConvertFrom-Json)
}

$existing = Get-RelayProcesses

if ($existing.Count -gt 1) {
    $ids = @($existing | ForEach-Object { [int]$_.ProcessId })
    $probe = Get-RelayHealth -ObservedPids $ids -ExpectedPid $null
    Write-Host "PC Control relay ownership is ambiguous; matching PIDs: $($ids -join ', ')"
    Write-Host "Liveness state: $($probe.probe.state) reason=$($probe.probe.reason)"
    Write-Host 'No process was killed or restarted.'
    exit 2
}

if ($existing.Count -eq 1) {
    $pidValue = [int]$existing[0].ProcessId
    $probe = Get-RelayHealth -ObservedPids @($pidValue) -ExpectedPid $pidValue
    if ($probe.probe.state -eq 'healthy_progressing') {
        Write-Host "PC Control relay is already healthy and progressing. PID: $pidValue"
        exit 0
    }
    if ($probe.probe.state -eq 'alive_stalled') {
        Write-Host "PC Control relay process is alive but stalled. PID: $pidValue"
    } else {
        Write-Host "PC Control relay process identity/progress is ambiguous. PID: $pidValue"
    }
    Write-Host "Liveness state: $($probe.probe.state) reason=$($probe.probe.reason)"
    Write-Host 'No process was killed or restarted. Reconcile ownership/progress explicitly.'
    exit 2
}

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

$args = @('tools\github_relay.py', '--repo', $Repo, '--live')
$p = Start-Process -FilePath $py.Source -ArgumentList $args -WorkingDirectory $Repo -WindowStyle Hidden -RedirectStandardOutput $Stdout -RedirectStandardError $Stderr -PassThru

Start-Sleep -Seconds 2

if (-not (Get-Process -Id $p.Id -ErrorAction SilentlyContinue)) {
    Write-Host 'PC Control relay failed to stay running.'
    if (Test-Path -LiteralPath $Stderr) { Get-Content -LiteralPath $Stderr -Tail 30 }
    exit 1
}

$startedProbe = Get-RelayHealth -ObservedPids @([int]$p.Id) -ExpectedPid ([int]$p.Id)
if ($startedProbe.probe.state -ne 'healthy_progressing') {
    Write-Host "PC Control relay started but did not prove healthy progress. PID: $($p.Id)"
    Write-Host "Liveness state: $($startedProbe.probe.state) reason=$($startedProbe.probe.reason)"
    Write-Host 'The launcher will not kill or restart it automatically.'
    exit 2
}

Write-Host "PC Control relay started and progress health is current. PID: $($p.Id)"
Write-Host 'You may close this window.'
Write-Host "Logs: $LogDir"
