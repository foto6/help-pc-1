param()

$ErrorActionPreference = 'Stop'

$Repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$RelayScript = Join-Path $Repo 'tools\github_relay.py'
$LogDir = Join-Path $Repo '.pc-relay'
$Stdout = Join-Path $LogDir 'live.stdout.log'
$Stderr = Join-Path $LogDir 'live.stderr.log'
$Health = Join-Path $LogDir 'health.json'
$StaleAfterSeconds = 30

if (-not (Test-Path -LiteralPath (Join-Path $Repo '.git'))) {
    throw "PC Control repo is not a Git checkout: $Repo"
}
if (-not (Test-Path -LiteralPath $RelayScript)) {
    throw "Relay script not found: $RelayScript"
}

$py = Get-Command py.exe -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command py -ErrorAction SilentlyContinue }
if (-not $py) { throw 'Python launcher "py" was not found.' }

$repoPattern = [regex]::Escape($Repo)
$existing = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match 'github_relay\.py' -and $_.CommandLine -match $repoPattern })

if ($existing.Count -gt 0) {
    $ids = ($existing | ForEach-Object ProcessId) -join ', '
    $healthState = 'PROCESS_EXISTS'
    $healthAge = $null
    if (Test-Path -LiteralPath $Health) {
        try {
            $snapshot = Get-Content -LiteralPath $Health -Raw | ConvertFrom-Json
            $healthAge = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - [double]$snapshot.updated_at_unix
            if ($snapshot.health_version -eq 'pc_relay.health.v1' -and $snapshot.status -eq 'healthy' -and $healthAge -le $StaleAfterSeconds) {
                $healthState = 'HEALTHY'
            } elseif ($healthAge -gt $StaleAfterSeconds) {
                $healthState = 'STALE'
            }
        } catch {
            $healthState = 'PROCESS_EXISTS'
        }
    }
    if ($healthState -eq 'HEALTHY') {
        Write-Host "PC Control relay is already running and healthy. PID: $ids"
        exit 0
    }
    Write-Host "PC Control relay process exists but health is $healthState. PID: $ids"
    if ($null -ne $healthAge) { Write-Host "Health age seconds: $([math]::Round($healthAge, 1))" }
    Write-Host 'Do not blind-replay queued side effects. Inspect health/logs and reconcile before restart.'
    Write-Host "Health: $Health"
    Write-Host "Logs: $LogDir"
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

$healthy = $false
for ($i = 0; $i -lt 8; $i++) {
    if (Test-Path -LiteralPath $Health) {
        try {
            $snapshot = Get-Content -LiteralPath $Health -Raw | ConvertFrom-Json
            $age = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - [double]$snapshot.updated_at_unix
            if ($snapshot.health_version -eq 'pc_relay.health.v1' -and $age -le $StaleAfterSeconds) {
                $healthy = $true
                break
            }
        } catch {}
    }
    Start-Sleep -Milliseconds 500
}

if ($healthy) {
    Write-Host "PC Control relay started and is producing fresh health evidence. PID: $($p.Id)"
} else {
    Write-Host "PC Control relay process started, but fresh health evidence is not available yet. PID: $($p.Id)"
    Write-Host 'Treat this as PROCESS_EXISTS, not HEALTHY.'
}
Write-Host 'You may close this window.'
Write-Host "Health: $Health"
Write-Host "Logs: $LogDir"
