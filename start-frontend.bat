@echo off
setlocal
rem ================================================================
rem  V-Scanner one-click launcher (frontend + backends)
rem  ASCII-only batch: avoids GBK/UTF-8 mojibake on Chinese paths.
rem    frontend : http://localhost:8090/app.html
rem    pipeline : http://127.0.0.1:8771  (dynamic audit, NEW)
rem    workbench: http://127.0.0.1:8770  (static workbench)
rem ================================================================

rem Project root = this script's directory (safe for Chinese paths)
set "ROOT=%~dp0"

rem Python 3.13 (the only interpreter with frida/mitmproxy/reportlab).
rem Derived from LOCALAPPDATA so we never hardcode the Chinese username.
set "PY=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"

if not exist "%PY%" (
    echo [ERROR] Python 3.13 not found:
    echo          %PY%
    echo Install it, or edit the PY variable in this script.
    pause
    exit /b 1
)

echo ================================================================
echo   V-Scanner one-click launcher
echo   frontend : http://localhost:8090/app.html
echo   pipeline : http://127.0.0.1:8771   dynamic audit
echo   workbench: http://127.0.0.1:8770   static workbench
echo ================================================================
echo.
echo Starting three services in separate windows...

start "VScanner Pipeline 8771" /D "%ROOT%" cmd /k "%PY% mobile\pipeline\server.py --port 8771 --workdir D:/vscanner-tp/pipeline"

start "VScanner Workbench 8770" /D "%ROOT%" cmd /k "%PY% vehicle\workbench\server.py --port 8770"

start "VScanner Frontend 8090" /D "%ROOT%frontend" cmd /k "%PY% -m http.server 8090 --bind 127.0.0.1"

rem Wait until the frontend port is listening, then open the browser.
rem Poll 127.0.0.1:8090 via a .NET TcpClient (PowerShell is always present).
echo.
echo Waiting for frontend (up to ~20s)...

set /a tries=0

:waitloop
powershell -NoProfile -Command "$c = New-Object System.Net.Sockets.TcpClient; try { $c.Connect('127.0.0.1', 8090); exit 0 } catch { exit 1 } finally { $c.Dispose() }"
if not errorlevel 1 goto opened
set /a tries+=1
if %tries% geq 20 goto giveup
ping -n 2 127.0.0.1 >nul
goto waitloop

:opened
echo Frontend is up. Opening browser...
start "" "http://localhost:8090/app.html"
goto done

:giveup
echo Frontend did not respond in time. Open it manually:
echo   http://localhost:8090/app.html
goto done

:done
echo.
echo Close a service window to stop that service.
echo.
pause
