@echo off
rem ================================================================
rem  V-Scanner vehicle demo device prep (AAOS emulator + frida + app)
rem  The 8773 "new AAOS capture" mode hard-checks five things:
rem    device online and automotive, API 35, app installed on user 10
rem    as a single APK with matching sha256, app already running,
rem    frida-server listening on 127.0.0.1:27043
rem  This script sets all of them up and re-checks each one.
rem    prepare-vehicle-device.bat              full prep
rem    prepare-vehicle-device.bat -NoEmulator  device started elsewhere
rem    prepare-vehicle-device.bat -SkipApp     device + frida only
rem  ASCII-only on purpose: cmd.exe parses .bat in the OEM code page,
rem  so UTF-8 Chinese comments break line parsing. Keep it English here.
rem ================================================================
setlocal
set "PS1=%~dp0prepare-vehicle-device.ps1"
if not exist "%PS1%" (
    echo [ERROR] prepare-vehicle-device.ps1 not found next to this script.
    pause
    exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
set "RC=%ERRORLEVEL%"
if "%~1"=="" pause
exit /b %RC%
