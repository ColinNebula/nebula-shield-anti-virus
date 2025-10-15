#!/usr/bin/env pwsh
# Nebula Shield - Stop All Services Script

Write-Host ""
Write-Host "🛑 Stopping Nebula Shield Services..." -ForegroundColor Yellow
Write-Host ""

# Stop all Node.js processes
$nodeProcesses = Get-Process -Name "node" -ErrorAction SilentlyContinue
if ($nodeProcesses) {
    Write-Host "   Stopping $($nodeProcesses.Count) Node.js process(es)..." -ForegroundColor Gray
    $nodeProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Host "   ✅ Node.js processes stopped" -ForegroundColor Green
}

# Stop backend scanner
$backendProcesses = Get-Process -Name "nebula_shield_backend" -ErrorAction SilentlyContinue
if ($backendProcesses) {
    Write-Host "   Stopping backend scanner..." -ForegroundColor Gray
    $backendProcesses | Stop-Process -Force -ErrorAction SilentlyContinue
    Write-Host "   ✅ Backend scanner stopped" -ForegroundColor Green
}

Write-Host ""
Write-Host "✅ All Nebula Shield services stopped" -ForegroundColor Green
Write-Host ""
Write-Host "To restart, run: .\start-nebula-shield.ps1" -ForegroundColor Cyan
Write-Host ""

Start-Sleep -Seconds 2
