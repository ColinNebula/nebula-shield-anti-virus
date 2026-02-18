# Server Health Check Script
# Checks if all required servers are running before build

Write-Host ""
Write-Host "Nebula Shield - Server Health Check" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$allServersRunning = $true
$requiredServers = @()

# Check if backend server is running on port 8080
Write-Host "Checking Backend Server (Port 8080)..." -NoNewline
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8080/api/health" -TimeoutSec 2 -UseBasicParsing -ErrorAction SilentlyContinue
    if ($response.StatusCode -eq 200) {
        Write-Host " OK Running" -ForegroundColor Green
    } else {
        Write-Host " ERROR Not responding correctly" -ForegroundColor Red
        $allServersRunning = $false
        $requiredServers += "Backend Server (port 8080)"
    }
} catch {
    Write-Host " ERROR Not running" -ForegroundColor Red
    $allServersRunning = $false
    $requiredServers += "Backend Server (port 8080)"
}

# Check if preview/dev server is running on common ports
$frontendPorts = @(3000, 3001, 3002)
$frontendRunning = $false

foreach ($port in $frontendPorts) {
    Write-Host "Checking Frontend Server (Port $port)..." -NoNewline
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect("localhost", $port)
        $tcpClient.Close()
        Write-Host " OK Running" -ForegroundColor Green
        $frontendRunning = $true
        break
    } catch {
        Write-Host " WARNING Not running" -ForegroundColor Yellow
    }
}

if (-not $frontendRunning) {
    Write-Host ""
    Write-Host "INFO: No frontend dev/preview server detected (optional for builds)" -ForegroundColor Yellow
}

# Check Node.js processes
Write-Host ""
Write-Host "Active Node.js Processes:" -ForegroundColor Cyan
$nodeProcesses = Get-Process -Name "node" -ErrorAction SilentlyContinue
if ($nodeProcesses) {
    $nodeProcesses | Select-Object Id, ProcessName, StartTime, @{Name="Memory(MB)";Expression={[math]::Round($_.WorkingSet64/1MB,2)}} | Format-Table -AutoSize
} else {
    Write-Host "No Node.js processes found" -ForegroundColor Yellow
}

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
if ($allServersRunning) {
    Write-Host "All required servers are running!" -ForegroundColor Green
    Write-Host "Ready to build." -ForegroundColor Green
    exit 0
} else {
    Write-Host "Some servers are not running!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Missing servers:" -ForegroundColor Yellow
    foreach ($server in $requiredServers) {
        Write-Host "  - $server" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "To start servers, run:" -ForegroundColor Cyan
    Write-Host "  node backend/auth-server.js" -ForegroundColor White
    Write-Host ""
    Write-Host "Or use:" -ForegroundColor Cyan
    Write-Host "  npm run dev" -ForegroundColor White
    Write-Host ""
    Write-Host "WARNING: Continuing with build anyway..." -ForegroundColor Yellow
    exit 0
}
