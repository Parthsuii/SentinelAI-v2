@echo off
setlocal
set "PYTHON_BIN=python"
if exist "%~dp0venv\Scripts\python.exe" (
  set "PYTHON_BIN=%~dp0venv\Scripts\python.exe"
)
echo ==========================================
echo    🛡️ SentinelAI v3.0 — Unified Launcher
echo ==========================================
echo.

:: Start Backend
echo [1/2] Starting SentinelAI Backend (Port 8000)...
start "SentinelAI Backend" cmd /c ""%PYTHON_BIN%" -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000"

:: Wait for backend to initialize
timeout /t 5 /nobreak > nul

:: Start Simulation Toolkit
echo [2/2] Starting Attack Simulation Toolkit (Port 5000)...
start "Attack Simulator" cmd /c ""%PYTHON_BIN%" simulation/app.py"

echo.
echo ==========================================
echo    ✅ Services are running!
echo.
echo    Backend: http://127.0.0.1:8000
echo    Simulator: http://127.0.0.1:5000
echo.
echo    To use the extension:
echo    1. Go to chrome://extensions
echo    2. Load unpacked: %cd%
echo ==========================================
pause
