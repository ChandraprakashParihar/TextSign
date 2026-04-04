@echo off
title TrustSign Service
cd /d "%~dp0"

REM Use bundled JRE if present (client does not need to install Java)
if exist "jre\bin\java.exe" (
  set "JAVA_EXE=jre\bin\java.exe"
) else (
  set "JAVA_EXE=java"
)

set "JAR="
for %%f in (trustsign-*-all.jar trustsign*.jar) do set "JAR=%%f"
if not defined JAR (
  echo No trustsign JAR found. Put trustsign-0.1.0-all.jar in this folder.
  pause
  exit /b 1
)

if not exist "config" mkdir config
if not exist "config\config.json" (
  echo Missing config\config.json. Copy your config.json into the config folder.
  pause
  exit /b 1
)

echo Starting TrustSign service...
echo Press Ctrl+C to stop.
echo.
"%JAVA_EXE%" -jar "%JAR%" %*
pause
