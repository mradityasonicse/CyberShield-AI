@echo off
title CyberShield AI - Threat Analysis & Awareness Assistant
echo ========================================================
echo         Starting CyberShield AI Server
echo ========================================================
echo.
echo Checking Python interpreter...

set PYTHON_CMD=python
if exist "%LOCALAPPDATA%\Python\pythoncore-3.14-64\python.exe" (
    set "PYTHON_CMD=%LOCALAPPDATA%\Python\pythoncore-3.14-64\python.exe"
)

echo Using: %PYTHON_CMD%
echo.
echo Opening browser at http://127.0.0.1:5000 ...
start http://127.0.0.1:5000

"%PYTHON_CMD%" app.py
pause
