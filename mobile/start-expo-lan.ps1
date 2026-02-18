#!/usr/bin/env pwsh
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Nebula Shield Mobile - Expo SDK 54" -ForegroundColor Green
Write-Host "  LAN Mode (Same WiFi Required)" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Set-Location $PSScriptRoot
& .\node_modules\.bin\expo.cmd start
