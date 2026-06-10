@echo off
setlocal EnableDelayedExpansion

REM ── PRISM Risk Assessment Tool — Windows launcher ───────────────────────────
REM
REM  Double-click this file to start the tool.
REM  Flask runs in this window — close the window to stop the server.
REM
REM  Requirements: Python virtual environment at .venv\
REM  First-time setup (run once in a Command Prompt):
REM    python -m venv .venv
REM    .venv\Scripts\pip install -r requirements.txt

cd /d "%~dp0"

echo.
echo   PRISM Risk Assessment Tool
echo   ==========================================

REM ── Locate venv Python ───────────────────────────────────────────────────────
if exist ".venv\Scripts\python.exe" (
    set "PYTHON=.venv\Scripts\python.exe"
) else (
    echo.
    echo   [ERROR] Virtual environment not found.
    echo   Expected: .venv\Scripts\python.exe
    echo.
    echo   Run these commands once to set it up:
    echo     python -m venv .venv
    echo     .venv\Scripts\pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)

echo   URL     : http://127.0.0.1:5000
echo   Database: %CD%\data\carver.db
echo   Stop    : Use the Shut Down button in the app, or close this window
echo.

REM ── Open the browser after a 3-second delay ───────────────────────────────────
REM  Runs in the background so it does not block Flask from starting.
start "" /B cmd /c "timeout /t 3 /nobreak >nul && start http://127.0.0.1:5000"

REM ── Start Flask in the foreground ─────────────────────────────────────────────
REM  Closing this window stops the server.
%PYTHON% app.py
