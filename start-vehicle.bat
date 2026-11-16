@echo off
rem ================================================================
rem  V-Scanner vehicle workbench launcher (AAOS audit, single port)
rem  vehicle/webapp serves vehicle/frontend itself on 127.0.0.1:8773,
rem  so there is no separate static server to start.
rem    start-vehicle.bat            start and open http://127.0.0.1:8773/
rem    start-vehicle.bat -NoBrowser start without opening a browser
rem    start-vehicle.bat -Status    show ports / health
rem    start-vehicle.bat -Stop      stop the vehicle service only
rem  Extra flags are forwarded to start-all.ps1 (-Only is already set).
rem  ASCII-only on purpose: cmd.exe parses .bat in the OEM code page,
rem  so UTF-8 Chinese comments break line parsing. Keep it English here.
rem ================================================================
setlocal
set "PS1=%~dp0start-all.ps1"
if not exist "%PS1%" (
    echo [ERROR] start-all.ps1 not found next to this script.
    pause
    exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -Only vehicle %*
set "RC=%ERRORLEVEL%"
if "%~1"=="" pause
exit /b %RC%
