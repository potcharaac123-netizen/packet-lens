@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

set PORT=5179
set URL=http://localhost:%PORT%

echo ==================================================
echo   PacketLens - Local Launcher
echo ==================================================
echo.
echo   URL: %URL%
echo   Close this window or press Ctrl+C to stop server
echo   and restore everything back to normal.
echo ==================================================
echo.

if exist "dist\index.html" (
    python --version >nul 2>nul
    if %errorlevel%==0 (
        start /b cmd /c "timeout /t 1 /nobreak >nul && start "" "%URL%""
        python -c "import http.server, functools, mimetypes; mimetypes.add_type('application/javascript', '.js'); mimetypes.add_type('text/css', '.css'); h = functools.partial(http.server.SimpleHTTPRequestHandler, directory='dist'); http.server.ThreadingHTTPServer(('127.0.0.1', %PORT%), h).serve_forever()"
        goto :cleanup
    )

    py --version >nul 2>nul
    if %errorlevel%==0 (
        start /b cmd /c "timeout /t 1 /nobreak >nul && start "" "%URL%""
        py -c "import http.server, functools, mimetypes; mimetypes.add_type('application/javascript', '.js'); mimetypes.add_type('text/css', '.css'); h = functools.partial(http.server.SimpleHTTPRequestHandler, directory='dist'); http.server.ThreadingHTTPServer(('127.0.0.1', %PORT%), h).serve_forever()"
        goto :cleanup
    )

    node --version >nul 2>nul
    if %errorlevel%==0 (
        start /b cmd /c "timeout /t 2 /nobreak >nul && start "" "%URL%""
        call npx --yes serve dist -l %PORT%
        goto :cleanup
    )
)

node --version >nul 2>nul
if %errorlevel%==0 (
    if not exist "node_modules" (
        echo Installing dependencies for first run...
        call npm install
    )
    start /b cmd /c "timeout /t 2 /nobreak >nul && start "" "%URL%""
    call npm run dev -- --port %PORT%
    goto :cleanup
)

echo [Error] Neither Python nor Node.js was found on this computer.
echo Please install Node.js (https://nodejs.org) or Python (https://python.org).
pause
exit /b 1

:cleanup
echo.
echo Server stopped. Everything is back to normal.
endlocal
