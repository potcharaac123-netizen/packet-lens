@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

set PORT=5179

echo ==================================================
echo   PacketLens - Local Launcher
echo ==================================================
echo.

if exist "dist\index.html" (
    node --version >nul 2>nul
    if %errorlevel%==0 (
        node serve.mjs
        goto :cleanup
    )

    python --version >nul 2>nul
    if %errorlevel%==0 (
        python -c "import http.server, functools, mimetypes, webbrowser, os; mimetypes.add_type('application/javascript', '.js'); mimetypes.add_type('text/css', '.css'); h = functools.partial(http.server.SimpleHTTPRequestHandler, directory='dist'); s = http.server.ThreadingHTTPServer(('127.0.0.1', %PORT%), h); print('PacketLens is running at http://127.0.0.1:%PORT%'); print('Close this window or press Ctrl+C to stop.'); webbrowser.open('http://127.0.0.1:%PORT%'); s.serve_forever()"
        goto :cleanup
    )

    py --version >nul 2>nul
    if %errorlevel%==0 (
        py -c "import http.server, functools, mimetypes, webbrowser, os; mimetypes.add_type('application/javascript', '.js'); mimetypes.add_type('text/css', '.css'); h = functools.partial(http.server.SimpleHTTPRequestHandler, directory='dist'); s = http.server.ThreadingHTTPServer(('127.0.0.1', %PORT%), h); print('PacketLens is running at http://127.0.0.1:%PORT%'); print('Close this window or press Ctrl+C to stop.'); webbrowser.open('http://127.0.0.1:%PORT%'); s.serve_forever()"
        goto :cleanup
    )
)

node --version >nul 2>nul
if %errorlevel%==0 (
    if not exist "node_modules" (
        echo Installing dependencies for first run...
        call npm install
    )
    call npm run dev -- --port %PORT% --open
    goto :cleanup
)

echo [Error] Neither Node.js nor Python was found on this computer.
echo Please install Node.js (https://nodejs.org) or Python (https://python.org).
pause
exit /b 1

:cleanup
echo.
echo Server stopped. Everything is back to normal.
pause
endlocal
