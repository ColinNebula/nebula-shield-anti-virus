#!/usr/bin/env pwsh
# Start Expo Development Server
# This script starts the Expo development server with tunnel mode for remote testing

Write-Host "Starting Nebula Shield Mobile - Expo Development Server" -ForegroundColor Cyan
Write-Host "--------------------------------------------------------" -ForegroundColor Gray
Write-Host ""

# Navigate to mobile directory
Set-Location -Path $PSScriptRoot

# Set environment variables
$env:RCT_METRO_PORT = "8082"

# Start Expo
Write-Host "Starting Expo on port 8082 with tunnel mode..." -ForegroundColor Green
Write-Host "You can scan the QR code with Expo Go app on your phone" -ForegroundColor Gray
Write-Host ""

npx expo start --tunnel --port 8082
