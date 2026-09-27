param(
    [string]$Endpoint = "",
    [string]$DeviceId = "",
    [int]$TokenGeneration = 1,
    [switch]$Enable
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    $args = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", ('"' + $PSCommandPath + '"')
    )
    if ($Endpoint) {
        $args += @("-Endpoint", ('"' + $Endpoint.Replace('"', '""') + '"'))
    }
    if ($DeviceId) {
        $args += @("-DeviceId", ('"' + $DeviceId.Replace('"', '""') + '"'))
    }
    $args += @("-TokenGeneration", $TokenGeneration.ToString())
    if ($Enable) {
        $args += "-Enable"
    }
    Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $args
    exit 0
}

if (-not $Endpoint) {
    $Endpoint = Read-Host "Relay endpoint (wss://...)"
}
if (-not $DeviceId) {
    $DeviceId = Read-Host "Device ID"
}
if (-not $Endpoint -or -not $DeviceId) {
    throw "Endpoint and Device ID are required."
}
if ($TokenGeneration -lt 1) {
    throw "TokenGeneration must be positive."
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ServiceRoot = Join-Path $env:ProgramData "PCNativeDeviceService"
$Venv = Join-Path $ServiceRoot "venv"
$Python = Join-Path $Venv "Scripts\python.exe"
$Cli = Join-Path $Venv "Scripts\pc-native-device-service.exe"

New-Item -ItemType Directory -Force -Path $ServiceRoot | Out-Null

if (-not (Test-Path $Python)) {
    python -m venv $Venv
}

& $Python -m pip install --disable-pip-version-check --upgrade pip
& $Python -m pip install --disable-pip-version-check $RepoRoot

$configure = @("configure", "--endpoint", $Endpoint, "--device-id", $DeviceId)
if ($Enable) {
    $configure += "--enable"
}
& $Cli @configure

Write-Host "Enter the device token when prompted. It is read with hidden input and stored only as Windows LSA private data."
& $Cli secret set --generation $TokenGeneration

$statusJson = & $Cli status
$status = $statusJson | ConvertFrom-Json
if ($status.scm_state -eq "not_installed") {
    & $Cli install
} else {
    Write-Host "Service is already installed; preserving the existing installation."
}

if ($status.scm_state -eq "running") {
    & $Cli restart
} else {
    & $Cli start
}

& $Cli status
if (-not $Enable) {
    Write-Host "Installed in disabled mode. Run: pc-native-device-service configure --enable ; pc-native-device-service restart"
}
