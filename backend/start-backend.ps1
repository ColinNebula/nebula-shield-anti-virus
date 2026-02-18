# Nebula Shield Backend Startup Script
Write-Host "Starting Nebula Shield Backend Server..." -ForegroundColor Cyan
try {
    node auth-server.js
} catch {
    Write-Host "Error starting backend: $_" -ForegroundColor Red
    Read-Host "Press Enter to exit"
}
