@echo off
REM Enhanced CLI Scanner Launcher
REM Ensures proper execution environment for Python

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [!] Python is not installed or not in PATH.
    echo Please install Python from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [*] Starting Advanced Vulnerability Scanner...
python scanner.py %*

if %errorlevel% neq 0 (
    echo [!] Scanner exited with error code %errorlevel%.
)
pause
