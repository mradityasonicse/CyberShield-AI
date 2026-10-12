# CyberShield AI PowerShell Launcher
$ErrorActionPreference = "Stop"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "       Launching CyberShield AI (Port 5000)             " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

$pythonExe = "$env:LOCALAPPDATA\Python\pythoncore-3.14-64\python.exe"
if (-not (Test-Path $pythonExe)) {
    $pythonExe = "python"
}

Write-Host "`nOpening browser at http://127.0.0.1:5000 ..." -ForegroundColor Green
Start-Process "http://127.0.0.1:5000"

Write-Host "Running server with $pythonExe ...`n" -ForegroundColor Yellow
& $pythonExe app.py
