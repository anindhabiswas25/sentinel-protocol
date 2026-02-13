#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Starts Sentinel Protocol locally (Backend + Frontend)

.DESCRIPTION
    This script starts both the FastAPI backend and Next.js frontend
    for local development of the Sentinel Protocol application.
#>

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "🛡️  Sentinel Protocol - Local Startup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Get the script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Backend directory
$BackendDir = Join-Path $ScriptDir "backend"
# Frontend directory
$FrontendDir = Join-Path $ScriptDir "frontend"

# Check if directories exist
if (-not (Test-Path $BackendDir)) {
    Write-Host "❌ Backend directory not found: $BackendDir" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $FrontendDir)) {
    Write-Host "❌ Frontend directory not found: $FrontendDir" -ForegroundColor Red
    exit 1
}

# Function to stop jobs on exit
function Stop-Jobs {
    Write-Host "`n🛑 Shutting down services..." -ForegroundColor Yellow
    Get-Job | Stop-Job
    Get-Job | Remove-Job
    Write-Host "✅ All services stopped" -ForegroundColor Green
}

# Register cleanup on exit
Register-EngineEvent PowerShell.Exiting -Action { Stop-Jobs } | Out-Null

try {
    # Start Backend
    Write-Host "🚀 Starting Backend (FastAPI)..." -ForegroundColor Green
    Write-Host "   Location: $BackendDir" -ForegroundColor Gray
    Write-Host "   URL: http://localhost:8000" -ForegroundColor Cyan
    Write-Host ""

    $BackendJob = Start-Job -ScriptBlock {
        param($dir)
        Set-Location $dir
        & python main.py
    } -ArgumentList $BackendDir

    # Wait a bit for backend to start
    Start-Sleep -Seconds 3

    # Start Frontend
    Write-Host "🚀 Starting Frontend (Next.js)..." -ForegroundColor Green
    Write-Host "   Location: $FrontendDir" -ForegroundColor Gray
    Write-Host "   URL: http://localhost:3000" -ForegroundColor Cyan
    Write-Host ""

    $FrontendJob = Start-Job -ScriptBlock {
        param($dir)
        Set-Location $dir
        & npm run dev
    } -ArgumentList $FrontendDir

    # Wait a bit for frontend to start
    Start-Sleep -Seconds 3

    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "✅ Services Started Successfully!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "📍 Backend:  http://localhost:8000" -ForegroundColor Cyan
    Write-Host "📍 Frontend: http://localhost:3000" -ForegroundColor Cyan
    Write-Host "📍 API Docs: http://localhost:8000/docs" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Press Ctrl+C to stop all services" -ForegroundColor Yellow
    Write-Host ""

    # Show logs from both services
    while ($true) {
        # Get backend output
        $BackendOutput = Receive-Job -Job $BackendJob
        if ($BackendOutput) {
            Write-Host "[BACKEND] " -ForegroundColor Blue -NoNewline
            Write-Host $BackendOutput
        }

        # Get frontend output
        $FrontendOutput = Receive-Job -Job $FrontendJob
        if ($FrontendOutput) {
            Write-Host "[FRONTEND] " -ForegroundColor Magenta -NoNewline
            Write-Host $FrontendOutput
        }

        # Check if jobs are still running
        if ($BackendJob.State -ne "Running") {
            Write-Host "❌ Backend stopped unexpectedly" -ForegroundColor Red
            break
        }
        if ($FrontendJob.State -ne "Running") {
            Write-Host "❌ Frontend stopped unexpectedly" -ForegroundColor Red
            break
        }

        Start-Sleep -Milliseconds 500
    }
}
catch {
    Write-Host "❌ Error: $_" -ForegroundColor Red
}
finally {
    Stop-Jobs
}
