# Quick Build Script for Nebula Shield Backend
# This attempts to build without vcpkg first

Write-Host "`n==== Building Nebula Shield C++ Backend ====`n" -ForegroundColor Cyan

# Try to build directly
Write-Host "Attempting to build the C++ backend...`n" -ForegroundColor Yellow
Write-Host "This requires:" -ForegroundColor Gray
Write-Host "  - Visual Studio 2022 (or Build Tools)" -ForegroundColor Gray
Write-Host "  - CMake" -ForegroundColor Gray
Write-Host "  - SQLite3 and OpenSSL libraries`n" -ForegroundColor Gray

$backendPath = ".\backend"
$buildPath = ".\backend\build"

# Create build directory
if (Test-Path $buildPath) {
    Write-Host "Cleaning old build..." -ForegroundColor Yellow
    Remove-Item $buildPath -Recurse -Force
}

New-Item -Path $buildPath -ItemType Directory | Out-Null
Set-Location $buildPath

Write-Host "Configuring with CMake..." -ForegroundColor Green
cmake .. -G "Visual Studio 17 2022" -A x64

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nBuilding..." -ForegroundColor Green
    cmake --build . --config Release
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "`n✓ BUILD SUCCESSFUL!" -ForegroundColor Green
        Write-Host "`nExecutable: backend\build\bin\Release\nebula_shield_backend.exe`n" -ForegroundColor Cyan
    } else {
        Write-Host "`n✗ Build failed. You may need to install dependencies." -ForegroundColor Red
        Write-Host "See INTEGRATION_GUIDE.md for full setup instructions.`n" -ForegroundColor Yellow
    }
} else {
    Write-Host "`n✗ CMake configuration failed." -ForegroundColor Red
    Write-Host "`nYou need to install:" -ForegroundColor Yellow
    Write-Host "  1. Visual Studio 2022 with C++ tools" -ForegroundColor White
    Write-Host "  2. vcpkg and dependencies (see INTEGRATION_GUIDE.md)`n" -ForegroundColor White
}

Set-Location ..\..
