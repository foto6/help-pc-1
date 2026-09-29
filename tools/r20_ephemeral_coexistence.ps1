# Real frozen R15c + R20 side-by-side service test on a DISPOSABLE GitHub Windows runner.
# Both service IDs must be ABSENT before this script is allowed to install either.
# No user-machine, system-wide production or cloud MCP deployment is touched.
param(
  [Parameter(Mandatory = $true)][string]$LegacyPython,
  [Parameter(Mandatory = $true)][string]$CandidatePython
)
$ErrorActionPreference = "Stop"
if ($env:GITHUB_ACTIONS -ne "true" -or $env:RUNNER_OS -ne "Windows" -or
    [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
  throw "R20 coexistence test is allowed only on a disposable GitHub Windows runner"
}
$oldName="PCNativeDeviceService"
$newName="PCNativeCandidateR20"
$reportPath=Join-Path $env:RUNNER_TEMP "r20-coexistence-sanitized.json"
$report=[ordered]@{
  schema="pc_native.r20_two_real_windows_scm_coexistence.v1"
  both_names_initially_absent=$false
  legacy_r15_installed_running=$false
  candidate_r20_installed_running=$false
  distinct_service_pids_and_state_roots=$false
  legacy_pid_unchanged_after_candidate_restart=$false
  candidate_removed_while_legacy_running=$false
  legacy_pid_unchanged_after_candidate_uninstall=$false
  both_services_uninstalled=$false
  rollback_complete=$false
  status="BLOCKED"
}
$failure=$null

function Query-ScopedService([string]$Name) {
  if ($Name -notin @("PCNativeDeviceService","PCNativeCandidateR20")) {
    throw "Unexpected service name in isolated coexistence rehearsal"
  }
  return Get-CimInstance Win32_Service -Filter ("Name='"+$Name+"'") -ErrorAction Stop
}
function Invoke-ScopedCli([string]$Executable,[string]$ModuleName,[string[]]$Commands) {
  if ($Executable -notin @($LegacyPython,$CandidatePython)) { throw "Unexpected CLI executable" }
  if ($ModuleName -notin @("pc_remote_transport.service_cli",
                           "pc_remote_transport.r20_candidate_cli")) {
    throw "Unexpected native service CLI module"
  }
  $output=& $Executable -m $ModuleName @Commands 2>&1
  if ($LASTEXITCODE -ne 0) {
    throw ("Scoped service CLI "+$ModuleName+" "+$Commands[0]+" failed; exit "+$LASTEXITCODE)
  }
  return $output
}
function Wait-ScopedState([string]$Name,[string]$Wanted) {
  for($i=0;$i -lt 60;$i++){
    $item=Query-ScopedService -Name $Name
    if($null -ne $item -and $item.State -eq $Wanted){return $item}
    Start-Sleep -Milliseconds 500
  }
  throw ("Service "+$Name+" did not reach state "+$Wanted)
}
function Wait-Removed([string]$Name) {
  for($i=0;$i -lt 50;$i++){
    if($null -eq (Query-ScopedService -Name $Name)){return}
    Start-Sleep -Milliseconds 500
  }
  throw ("Service "+$Name+" still registered after candidate-only cleanup")
}

try {
  $admin=[Security.Principal.WindowsPrincipal](
    [Security.Principal.WindowsIdentity]::GetCurrent()
  )
  if(-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "BLOCKED_RUNNER_NOT_ELEVATED"
  }
  if($null -ne (Query-ScopedService -Name $oldName) -or
     $null -ne (Query-ScopedService -Name $newName)) {
    throw "Both native service names MUST be absent on the disposable runner"
  }
  $report.both_names_initially_absent=$true
  $env:PYTHONPATH=""
  $legacyProbe=& $LegacyPython -c "import sys,pathlib,win32service,pc_remote_transport.windows_service as m;v=pathlib.Path(sys.prefix).resolve();assert pathlib.Path(m.__file__).resolve().is_relative_to(v);assert pathlib.Path(win32service.__file__).resolve().is_relative_to(v);assert m.SERVICE_NAME=='PCNativeDeviceService';print('FROZEN_R15_PRIVATE_WHEEL_OK')"
  if($LASTEXITCODE -ne 0 -or $legacyProbe -notcontains "FROZEN_R15_PRIVATE_WHEEL_OK") {
    throw "Frozen original R15c Wheel is not isolated"
  }
  $candidateProbe=& $CandidatePython -c "import sys,pathlib,win32service,pc_remote_transport.r20_candidate as m;v=pathlib.Path(sys.prefix).resolve();assert pathlib.Path(m.__file__).resolve().is_relative_to(v);assert pathlib.Path(win32service.__file__).resolve().is_relative_to(v);assert m.R20_SERVICE_NAME=='PCNativeCandidateR20';print('CANDIDATE_R20_PRIVATE_WHEEL_OK')"
  if($LASTEXITCODE -ne 0 -or $candidateProbe -notcontains "CANDIDATE_R20_PRIVATE_WHEEL_OK") {
    throw "R20 Wheel is not isolated"
  }

  # Intentionally install and RUN the historical frozen service on this
  # initially empty ephemeral machine. Its default config is disabled, so it
  # does not connect to an unknown relay or read an LSA secret.
  Invoke-ScopedCli -Executable $LegacyPython -ModuleName "pc_remote_transport.service_cli" -Commands @("install")|Out-Null
  Invoke-ScopedCli -Executable $LegacyPython -ModuleName "pc_remote_transport.service_cli" -Commands @("start")|Out-Null
  $old=Wait-ScopedState -Name $oldName -Wanted "Running"
  if($old.ProcessId -le 0){throw "Old service lacks a running process"}
  $originalPid=$old.ProcessId
  $report.legacy_r15_installed_running=$true

  # Original is already RUNNING. Installing R20 must not call the original
  # service controller, share its ProgramData root, or change its process.
  $preflight=Invoke-ScopedCli -Executable $CandidatePython -ModuleName "pc_remote_transport.r20_candidate_cli" -Commands @("preflight")
  $decision=$preflight | Out-String | ConvertFrom-Json
  if(-not $decision.candidate_install_eligible -or $decision.blockers.Count -ne 0){
    throw "R20 preflight failed with the frozen R15c service running"
  }
  Invoke-ScopedCli -Executable $CandidatePython -ModuleName "pc_remote_transport.r20_candidate_cli" -Commands @("install")|Out-Null
  $registered=Query-ScopedService -Name $newName
  if($registered.StartMode -ne "Manual"){throw "Candidate must not auto-start during dual-service test"}
  Invoke-ScopedCli -Executable $CandidatePython -ModuleName "pc_remote_transport.r20_candidate_cli" -Commands @("start")|Out-Null
  $candidate=Wait-ScopedState -Name $newName -Wanted "Running"
  $old2=Query-ScopedService -Name $oldName
  if($old2.State -ne "Running" -or $old2.ProcessId -ne $originalPid -or
     $candidate.ProcessId -le 0 -or $candidate.ProcessId -eq $originalPid){
    throw "Two independent SCM services did not retain distinct running PIDs"
  }
  $report.candidate_r20_installed_running=$true
  $oldRoot=(& $LegacyPython -c "import win32serviceutil;print(win32serviceutil.GetServiceCustomOption('PCNativeDeviceService','StateRoot',None))").Trim()
  $newRoot=(& $CandidatePython -c "import win32serviceutil;print(win32serviceutil.GetServiceCustomOption('PCNativeCandidateR20','StateRoot',None))").Trim()
  if($oldRoot -ieq $newRoot -or
     $oldRoot.TrimEnd("\","/") -ine (Join-Path $env:PROGRAMDATA $oldName) -or
     $newRoot.TrimEnd("\","/") -ine (Join-Path $env:PROGRAMDATA $newName)){
    throw "Real frozen/candidate SCM StateRoot bindings overlap or differ from the expected isolated roots"
  }
  $report.distinct_service_pids_and_state_roots=$true

  Invoke-ScopedCli -Executable $CandidatePython -ModuleName "pc_remote_transport.r20_candidate_cli" -Commands @("restart")|Out-Null
  $candidateAgain=Wait-ScopedState -Name $newName -Wanted "Running"
  $oldAfterRestart=Query-ScopedService -Name $oldName
  if($candidateAgain.ProcessId -le 0 -or $candidateAgain.ProcessId -eq $candidate.ProcessId -or
     $oldAfterRestart.State -ne "Running" -or $oldAfterRestart.ProcessId -ne $originalPid){
    throw "Candidate restart disrupted original frozen service"
  }
  $report.legacy_pid_unchanged_after_candidate_restart=$true

  Invoke-ScopedCli -Executable $CandidatePython -ModuleName "pc_remote_transport.r20_candidate_cli" -Commands @("stop")|Out-Null
  [void](Wait-ScopedState -Name $newName -Wanted "Stopped")
  Invoke-ScopedCli -Executable $CandidatePython -ModuleName "pc_remote_transport.r20_candidate_cli" -Commands @("uninstall")|Out-Null
  Wait-Removed -Name $newName
  $report.candidate_removed_while_legacy_running=$true
  $oldAfterRemoval=Query-ScopedService -Name $oldName
  if($oldAfterRemoval.State -ne "Running" -or $oldAfterRemoval.ProcessId -ne $originalPid){
    throw "Candidate-only rollback changed the original service PID/state"
  }
  $report.legacy_pid_unchanged_after_candidate_uninstall=$true

  # Test-owned old service is cleaned up ONLY after the candidate has been
  # removed and the original running state has been independently confirmed.
  Invoke-ScopedCli -Executable $LegacyPython -ModuleName "pc_remote_transport.service_cli" -Commands @("stop")|Out-Null
  [void](Wait-ScopedState -Name $oldName -Wanted "Stopped")
  Invoke-ScopedCli -Executable $LegacyPython -ModuleName "pc_remote_transport.service_cli" -Commands @("uninstall")|Out-Null
  Wait-Removed -Name $oldName
  $report.both_services_uninstalled=$true
  $report.rollback_complete=$true
  $report.status="PASS"
} catch {
  $failure=$_.Exception.Message
} finally {
  # Emergency cleanup is permitted only for the two identities which were
  # VERIFIED ABSENT on this disposable runner before the test began.
  if($report.both_names_initially_absent){
    foreach($item in @(
      @($newName,$CandidatePython,"pc_remote_transport.r20_candidate_cli"),
      @($oldName,$LegacyPython,"pc_remote_transport.service_cli")
    )){
      try{
        $current=Query-ScopedService -Name $item[0]
        if($null -ne $current){
          if($current.State -ne "Stopped"){
            & sc.exe stop $item[0] *> $null
            [void](Wait-ScopedState -Name $item[0] -Wanted "Stopped")
          }
          try{
            Invoke-ScopedCli -Executable $item[1] -ModuleName $item[2] -Commands @("uninstall")|Out-Null
          } catch {
            & sc.exe delete $item[0] *> $null
            if($null -eq $failure){$failure="Emergency cleanup required for disposable service"}
          }
          Wait-Removed -Name $item[0]
        }
      }catch{
        if($null -eq $failure){$failure="Disposable service cleanup incomplete"}
      }
    }
    if($null -eq (Query-ScopedService -Name $oldName) -and
       $null -eq (Query-ScopedService -Name $newName)){
      $report.rollback_complete=$true
    }
  }
  if($null -ne $failure){$report.status="BLOCKED"}
  $report|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $reportPath -Encoding utf8
  Get-Content -LiteralPath $reportPath
}
if($null -ne $failure){throw ("R20_PARALLEL_SERVICE_TEST_BLOCKED: "+$failure)}
if($report.status -ne "PASS"){throw "R20_PARALLEL_SERVICE_TEST_NOT_ACCEPTED"}
Write-Output "R20_FROZEN_R15_AND_CANDIDATE_R20_RUNNING_TOGETHER_WITH_INDEPENDENT_ROLLBACK_PASS"
