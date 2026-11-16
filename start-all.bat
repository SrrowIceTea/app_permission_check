@echo off
rem ================================================================
rem  V-Scanner one-click launcher (frontend + backends)
rem  Double-click, or pass flags through to start-all.ps1:
rem    start-all.bat                 start frontend + pipeline + workbench
rem    start-all.bat -Only pipeline  start the audit pipeline only
rem    start-all.bat -Status         show ports / health
rem    start-all.bat -Stop           stop services started by this script
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
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" %*
set "RC=%ERRORLEVEL%"
if "%~1"=="" pause
exit /b %RC%
