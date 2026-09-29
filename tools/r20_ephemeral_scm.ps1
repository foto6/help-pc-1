# R20 — ACTUAL Windows SCM lifecycle on a disposable GitHub-hosted Windows runner.
# Never run this script on a user's desktop or a machine with the legacy service.
# The installed R20 candidate is deliberately DISABLED and DEMAND_START for
# this SCM-only acceptance; the real signed enabled data path passed R19.
param(
  [Parameter(Mandatory = $true)][string]$CandidatePython
)
$ErrorActionPreference = "Stop"
if ($env:GITHUB_ACTIONS -ne "true" -or $env:RUNNER_OS -ne "Windows" -or
    [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
  throw "R20 real SCM integration is restricted to an ephemeral GitHub Windows runner"
}
$original = "PCNativeDeviceService"
$candidate = "PCNativeCandidateR20"
$reportPath = Join-Path $env:RUNNER_TEMP "r20-cold-runner-scm-result.json"
$report = [ordered]@{
  schema = "pc_native.r20_ephemeral_scm_lifecycle.v1"
  original_service_absent = $false
  candidate_name_free_initially = $false
  private_wheel_and_pywin32 = $false
  installed_demand_start = $false
  private_state_binding = $false
  first_start_healthy_disabled = $false
  restart_with_distinct_pid = $false
  stop_confirmed = $false
  candidate_uninstalled = $false
  original_service_untouched = $false
  rollback_complete = $false
  status = "BLOCKED"
}
$failure = $null

function Assert-OriginalAbsent {
  $item = Get-CimInstance Win32_Service -Filter "Name='PCNativeDeviceService'" -ErrorAction Stop
  if ($null -ne $item) {
    throw "Legacy Windows service is present; this job must be a disposable cold runner"
  }
}

function Query-Candidate {
  return Get-CimInstance Win32_Service -Filter "Name='PCNativeCandidateR20'" -ErrorAction Stop
}

function Invoke-Candidate([string[]]$Commands) {
  $out = & $CandidatePython -m pc_remote_transport.r20_candidate_cli @Commands 2>&1
  if ($LASTEXITCODE -ne 0) {
    throw "Candidate CLI command failed: $($Commands[0]); exit $LASTEXITCODE"
  }
  return $out
}

function Wait-CandidateState([string]$Required) {
  for ($n = 0; $n -lt 60; $n++) {
    $item = Query-Candidate
    if ($null -ne $item -and $item.State -eq $Required) { return $item }
    Start-Sleep -Milliseconds 500
  }
  throw "Candidate SCM state did not reach $Required"
}

function Wait-CandidateRemoved {
  for ($n = 0; $n -lt 50; $n++) {
    if ($null -eq (Query-Candidate)) { return }
    Start-Sleep -Milliseconds 500
  }
  throw "Candidate SCM service name remains registered after uninstall"
}

try {
  $admin = [Security.Principal.WindowsPrincipal](
    [Security.Principal.WindowsIdentity]::GetCurrent()
  )
  if (-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "BLOCKED_NOT_ELEVATED_ON_EPHEMERAL_RUNNER"
  }
  Assert-OriginalAbsent
  $report.original_service_absent = $true
  if ($null -ne (Query-Candidate)) {
    throw "R20 candidate service already exists before rehearsal"
  }
  $report.candidate_name_free_initially = $true

  # Never accidentally import a source tree instead of this pinned Wheel.
  $env:PYTHONPATH = ""
  $probe = & $CandidatePython -c "import pathlib,sys,win32service,pc_remote_transport.r20_candidate as r;v=pathlib.Path(sys.prefix).resolve();assert v!=pathlib.Path(sys.base_prefix).resolve();assert pathlib.Path(win32service.__file__).resolve().is_relative_to(v);assert pathlib.Path(r.__file__).resolve().is_relative_to(v);print('R20_PRIVATE_IMPORT_PASS')"
  if ($LASTEXITCODE -ne 0 -or $probe -notcontains "R20_PRIVATE_IMPORT_PASS") {
    throw "R20 installed Wheel/private pywin32 identity failed"
  }
  $report.private_wheel_and_pywin32 = $true

  $raw = Invoke-Candidate -Commands @("preflight")
  $preflight = ($raw | Out-String | ConvertFrom-Json)
  if (-not $preflight.candidate_install_eligible -or $preflight.blockers.Count -ne 0 -or
      $preflight.candidate_name_available -ne $true) {
    throw "R20 candidate preflight did not prove SCM install eligibility"
  }

  Invoke-Candidate -Commands @("install") | Out-Null
  $registered = Query-Candidate
  if ($null -eq $registered -or $registered.StartMode -ne "Manual") {
    throw "R20 candidate must be installed with DEMAND_START"
  }
  $report.installed_demand_start = $true
  $bound = (& $CandidatePython -c "import win32serviceutil;print(win32serviceutil.GetServiceCustomOption('PCNativeCandidateR20','StateRoot',None))")
  if ($LASTEXITCODE -ne 0 -or
      $bound.TrimEnd("\", "/") -ine (Join-Path $env:PROGRAMDATA "PCNativeCandidateR20")) {
    throw "Candidate SCM StateRoot binding does not match its private ProgramData root"
  }
  $report.private_state_binding = $true

  # Default ConfigStore enabled=false; validate SCM without provisioning any
  # machine key or exposing a real device/desktop to this shared runner.
  Invoke-Candidate -Commands @("start") | Out-Null
  $running = Wait-CandidateState -Required "Running"
  for ($n = 0; $n -lt 50; $n++) {
    $statusRaw = Invoke-Candidate -Commands @("status")
    $status = ($statusRaw | Out-String | ConvertFrom-Json)
    if ($status.scm_state -eq "running" -and
        $status.service_state -eq "running" -and
        $status.transport_state -eq "disabled") { break }
    Start-Sleep -Milliseconds 500
  }
  if ($status.scm_state -ne "running" -or
      $status.service_state -ne "running" -or
      $status.transport_state -ne "disabled" -or
      $running.ProcessId -le 0) {
    throw "R20 real SCM service did not start healthy in candidate-disabled mode"
  }
  $report.first_start_healthy_disabled = $true
  $firstPid = $running.ProcessId

  Invoke-Candidate -Commands @("restart") | Out-Null
  $again = Wait-CandidateState -Required "Running"
  if ($again.ProcessId -le 0 -or $again.ProcessId -eq $firstPid) {
    throw "R20 restart did not yield a distinct positive service process PID"
  }
  $report.restart_with_distinct_pid = $true

  Invoke-Candidate -Commands @("stop") | Out-Null
  [void](Wait-CandidateState -Required "Stopped")
  $report.stop_confirmed = $true
  Invoke-Candidate -Commands @("uninstall") | Out-Null
  Wait-CandidateRemoved
  $report.candidate_uninstalled = $true
  Assert-OriginalAbsent
  $report.original_service_untouched = $true
  $report.rollback_complete = $true
  $report.status = "PASS"
} catch {
  $failure = $_.Exception.Message
} finally {
  # Cleanup is scoped to the candidate service name. Never call a legacy CLI,
  # never delete legacy ProgramData or access legacy LSA key.
  try {
    $remaining = Query-Candidate
    if ($null -ne $remaining) {
      if ($remaining.State -ne "Stopped") {
        & sc.exe stop $candidate *> $null
        [void](Wait-CandidateState -Required "Stopped")
      }
      try {
        Invoke-Candidate -Commands @("uninstall") | Out-Null
      } catch {
        # Candidate-only emergency cleanup on a disposable GitHub runner.
        & sc.exe delete $candidate *> $null
        $report.status = "BLOCKED"
        if ($null -eq $failure) { $failure = "R20 CLI uninstall failed; candidate-only cleanup fallback used" }
      }
      Wait-CandidateRemoved
    }
    $report.rollback_complete = $true
    Assert-OriginalAbsent
    $report.original_service_untouched = $true
  } catch {
    $report.status = "BLOCKED"
    if ($null -eq $failure) { $failure = "R20 candidate-only cleanup could not be proven" }
  }
  $report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $reportPath -Encoding utf8
  Get-Content -LiteralPath $reportPath
}
if ($null -ne $failure) {
  throw "R20_EPHEMERAL_SCM_BLOCKED: $failure"
}
if ($report.status -ne "PASS") {
  throw "R20_EPHEMERAL_SCM_NOT_ACCEPTED"
}
Write-Output "R20_REAL_SCM_INSTALL_START_RESTART_STOP_UNINSTALL_PASS"
