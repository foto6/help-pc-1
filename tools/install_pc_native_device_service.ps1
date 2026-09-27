param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactPath,
    [Parameter(Mandatory = $true)]
    [string]$ArtifactManifestPath,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedArtifactSha256,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedProducerSha,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedPackageVersion,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedProtocolVersion,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedCapabilityContractVersion,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedCapabilityDigest,
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

function Quote-ProcessArgument([string]$Value) {
    return '"' + $Value.Replace('"', '""') + '"'
}

if (-not (Test-IsAdministrator)) {
    $args = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", (Quote-ProcessArgument $PSCommandPath),
        "-ArtifactPath", (Quote-ProcessArgument $ArtifactPath),
        "-ArtifactManifestPath", (Quote-ProcessArgument $ArtifactManifestPath),
        "-ExpectedArtifactSha256", $ExpectedArtifactSha256,
        "-ExpectedProducerSha", $ExpectedProducerSha,
        "-ExpectedPackageVersion", (Quote-ProcessArgument $ExpectedPackageVersion),
        "-ExpectedProtocolVersion", (Quote-ProcessArgument $ExpectedProtocolVersion),
        "-ExpectedCapabilityContractVersion", (Quote-ProcessArgument $ExpectedCapabilityContractVersion),
        "-ExpectedCapabilityDigest", $ExpectedCapabilityDigest
    )
    if ($Endpoint) {
        $args += @("-Endpoint", (Quote-ProcessArgument $Endpoint))
    }
    if ($DeviceId) {
        $args += @("-DeviceId", (Quote-ProcessArgument $DeviceId))
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

# Production bootstrap deliberately has no RepoRoot/local-source install path.
# The verifier must succeed before ProgramData, a venv, service config, LSA secret,
# or Windows service registration is mutated.
$Verifier = Join-Path $PSScriptRoot "verify_pc_native_service_artifact.py"
if (-not (Test-Path -LiteralPath $Verifier -PathType Leaf)) {
    throw "Artifact verifier is missing; refusing production install."
}

$StageRoot = Join-Path ([IO.Path]::GetTempPath()) ("PCNativeDeviceService-" + [Guid]::NewGuid().ToString("N"))
$verifyArgs = @(
    $Verifier,
    "--artifact", $ArtifactPath,
    "--manifest", $ArtifactManifestPath,
    "--stage-root", $StageRoot,
    "--expected-artifact-sha256", $ExpectedArtifactSha256,
    "--expected-producer-sha", $ExpectedProducerSha,
    "--expected-package-version", $ExpectedPackageVersion,
    "--expected-protocol-version", $ExpectedProtocolVersion,
    "--expected-capability-contract-version", $ExpectedCapabilityContractVersion,
    "--expected-capability-digest", $ExpectedCapabilityDigest
)

$verificationJson = & python @verifyArgs
if ($LASTEXITCODE -ne 0) {
    throw "Artifact verification failed before service mutation."
}
$verification = $verificationJson | ConvertFrom-Json
$StagedArtifact = [string]$verification.staged_artifact
if (-not $StagedArtifact) {
    throw "Artifact verifier returned no staged artifact."
}

$ServiceRoot = Join-Path $env:ProgramData "PCNativeDeviceService"
$Venv = Join-Path $ServiceRoot "venv"
$Python = Join-Path $Venv "Scripts\python.exe"
$Cli = Join-Path $Venv "Scripts\pc-native-device-service.exe"

try {
    New-Item -ItemType Directory -Force -Path $ServiceRoot | Out-Null

    if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
        python -m venv $Venv
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to create service virtual environment."
        }
    }

    & $Python -m pip install --disable-pip-version-check --upgrade pip
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to prepare service package installer."
    }

    # Only the already-verified, atomically staged wheel is accepted here.
    & $Python -m pip install --disable-pip-version-check --upgrade --force-reinstall $StagedArtifact
    if ($LASTEXITCODE -ne 0) {
        throw "Verified service artifact installation failed."
    }

    # Defense in depth: the installed package must expose the same version and
    # protocol/registry contract that were approved by the external manifest.
    $probe = @"
import importlib.metadata as m, sys
from pc_remote_transport.executor_adapter import NATIVE_CONTROL_PROTOCOL_V1, NATIVE_TOOL_REGISTRY_V1, TOOL_REGISTRY_DIGEST
expected = sys.argv[1:]
actual = [m.version("pc-executor"), NATIVE_CONTROL_PROTOCOL_V1, NATIVE_TOOL_REGISTRY_V1, TOOL_REGISTRY_DIGEST]
raise SystemExit(0 if actual == expected else 9)
"@
    & $Python -c $probe $ExpectedPackageVersion $ExpectedProtocolVersion $ExpectedCapabilityContractVersion $ExpectedCapabilityDigest
    if ($LASTEXITCODE -ne 0) {
        throw "Installed package identity/contract verification failed."
    }

    $configure = @("configure", "--endpoint", $Endpoint, "--device-id", $DeviceId)
    if ($Enable) {
        $configure += "--enable"
    } else {
        $configure += "--disable"
    }
    & $Cli @configure
    if ($LASTEXITCODE -ne 0) {
        throw "Service configuration failed."
    }

    Write-Host "Enter the device token when prompted. It is read with hidden input and stored only as Windows LSA private data."
    & $Cli secret set --generation $TokenGeneration
    if ($LASTEXITCODE -ne 0) {
        throw "Service secret configuration failed."
    }

    $statusJson = & $Cli status
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read service status."
    }
    $status = $statusJson | ConvertFrom-Json
    if ($status.scm_state -eq "not_installed") {
        & $Cli install
        if ($LASTEXITCODE -ne 0) {
            throw "Windows service registration failed."
        }
    } else {
        Write-Host "Service is already installed; preserving the existing registration."
    }

    if ($status.scm_state -eq "running") {
        & $Cli restart
    } else {
        & $Cli start
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Windows service start/restart failed."
    }

    & $Cli status
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read final service status."
    }
    if (-not $Enable) {
        Write-Host "Installed in disabled mode. Run: pc-native-device-service configure --enable ; pc-native-device-service restart"
    }
}
finally {
    if (Test-Path -LiteralPath $StageRoot) {
        Remove-Item -LiteralPath $StageRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
