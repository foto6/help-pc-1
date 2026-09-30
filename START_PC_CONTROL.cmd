@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\start_pc_control_relay.ps1"
if errorlevel 1 (
  echo.
  echo PC Control failed to start. Send the error above to ChatGPT.
  pause
  exit /b 1
)
exit /b 0
