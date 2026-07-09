@echo off
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
  echo This must be run as Administrator. Right-click this file and choose "Run as administrator".
  pause
  exit /b 1
)

if not exist "trustsign-service.exe" (
  echo trustsign-service.exe not found in this folder.
  pause
  exit /b 1
)

trustsign-service.exe stop
trustsign-service.exe uninstall
echo TrustSign service removed.
pause
