param()

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

$repoPattern = [regex]::Escape($Repo)
$existing = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match 'github_relay\.py' -and $_.CommandLine -match $repoPattern })

if ($existing.Count -gt 0) {
    $ids = ($existing | ForEach-Object ProcessId) -join ', '
    Write-Host "PC Control relay is already running. PID: $ids"
    exit 0
}

$py = Get-Command py.exe -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command py -ErrorAction SilentlyContinue }
if (-not $py) { throw 'Python launcher "py" was not found.' }

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

$args = @('tools\github_relay.py', '--repo', $Repo, '--live')
$p = Start-Process -FilePath $py.Source -ArgumentList $args -WorkingDirectory $Repo -WindowStyle Hidden -RedirectStandardOutput $Stdout -RedirectStandardError $Stderr -PassThru

Start-Sleep -Seconds 2

if (-not (Get-Process -Id $p.Id -ErrorAction SilentlyContinue)) {
    Write-Host 'PC Control relay failed to stay running.'
    if (Test-Path -LiteralPath $Stderr) { Get-Content -LiteralPath $Stderr -Tail 30 }
    exit 1
}

Write-Host "PC Control relay started. PID: $($p.Id)"
Write-Host 'You may close this window.'
Write-Host "Logs: $LogDir"
