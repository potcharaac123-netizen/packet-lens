@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

set PORT=8080
set URL=http://localhost:%PORT%

echo ==================================================
echo   PacketLens - Local Launcher
echo ==================================================
echo.
echo   Opening browser: %URL%
echo   Close this window or press Ctrl+C to stop server
echo   and restore everything back to normal.
echo ==================================================
echo.

:: Check if dist folder exists (fastest, zero install)
if exist "dist\index.html" (
    where python >nul 2>nul
    if %errorlevel%==0 (
        start "" "%URL%"
        python -m http.server %PORT% -d dist
        goto :cleanup
    )

    where py >nul 2>nul
    if %errorlevel%==0 (
        start "" "%URL%"
        py -m http.server %PORT% -d dist
        goto :cleanup
    )

    where npx >nul 2>nul
    if %errorlevel%==0 (
        start "" "%URL%"
        call npx --yes serve dist -l %PORT%
        goto :cleanup
    )
)

:: Fallback to Node.js dev server if dist is missing or no python
where npm >nul 2>nul
if %errorlevel%==0 (
    if not exist "node_modules" (
        echo Installing dependencies for first run...
        call npm install
    )
    start "" "%URL%"
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
