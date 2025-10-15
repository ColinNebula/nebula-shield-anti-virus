# Auto-enable Real-time Protection
# This script runs after backend service starts

$maxRetries = 10
$retryCount = 0
$backendReady = $false

Write-Host "Waiting for Nebula Shield Backend to be ready..." -ForegroundColor Yellow

# Wait for backend to be ready
while (-not $backendReady -and $retryCount -lt $maxRetries) {
    try {
        $status = Invoke-RestMethod -Uri "http://localhost:8080/api/status" -TimeoutSec 2 -ErrorAction Stop
        if ($status.server_running -and $status.scanner_initialized) {
            $backendReady = $true
            Write-Host "✓ Backend ready!" -ForegroundColor Green
        }
    } catch {
        $retryCount++
        Start-Sleep -Seconds 2
    }
}

if ($backendReady) {
    # Enable real-time protection
    try {
        $result = Invoke-RestMethod -Uri "http://localhost:8080/api/protection/start" -Method POST -ErrorAction Stop
        if ($result.success) {
            Write-Host "✓ Real-time protection enabled!" -ForegroundColor Green
            
            # Verify
            $status = Invoke-RestMethod -Uri "http://localhost:8080/api/status"
            if ($status.real_time_protection) {
                Write-Host "✓ Status confirmed: ACTIVE" -ForegroundColor Green
            }
        }
    } catch {
        Write-Host "⚠ Failed to enable real-time protection: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "✗ Backend not ready after $maxRetries attempts" -ForegroundColor Red
}
