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
  echo trustsign-service.exe not found in this folder. Rebuild/re-extract the Windows client package.
  pause
  exit /b 1
)

echo Installing TrustSign as a Windows Service...
trustsign-service.exe install
if %errorlevel% neq 0 (
  echo Install failed. Check service\windows\trustsign-service.err.log if present.
  pause
  exit /b 1
)

echo Starting TrustSign service...
trustsign-service.exe start

echo.
echo Done. TrustSign now starts automatically at boot (before login) and keeps
echo running through logout and restarts if it crashes.
echo.
echo Manage it with services.msc ("TrustSign Signing Service"), or:
echo   Stop:    trustsign-service.exe stop
echo   Restart: trustsign-service.exe restart
echo   Remove:  uninstall-service.bat
pause
