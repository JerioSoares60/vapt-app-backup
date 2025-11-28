@echo off
REM Startup script for the backend server (Windows)
REM This script starts the FastAPI backend server with proper configuration

cd /d "%~dp0"

echo Starting Report Generator Backend Server...
echo ==========================================

REM Check if virtual environment exists
if exist "venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call venv\Scripts\activate.bat
) else if exist ".venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call .venv\Scripts\activate.bat
)

REM Check if .env file exists
if not exist "Automation\backend\.env" (
    echo Warning: .env file not found at Automation\backend\.env
    echo Please create it with required environment variables
)

REM Get port from environment or use default
if "%PORT%"=="" set PORT=8000
if "%HOST%"=="" set HOST=0.0.0.0

echo Starting server on %HOST%:%PORT%...
echo.

REM Start uvicorn server
uvicorn app:app --host %HOST% --port %PORT% --reload --log-level info --access-log

