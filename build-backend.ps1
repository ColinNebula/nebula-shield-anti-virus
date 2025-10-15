# Nebula Shield Backend Build Script
# Builds the C++ backend with CMake

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Building Nebula Shield C++ Backend" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Navigate to backend directory
$backendPath = Join-Path $PSScriptRoot "backend"
$buildPath = Join-Path $backendPath "build"

if (-not (Test-Path $backendPath)) {
    Write-Host "✗ Backend directory not found at: $backendPath" -ForegroundColor Red
    exit 1
}

Set-Location $backendPath
Write-Host "Working directory: $backendPath`n" -ForegroundColor Gray

# Check for vcpkg
$vcpkgPath = $env:VCPKG_ROOT
if (-not $vcpkgPath) {
    $vcpkgPath = "C:\vcpkg"
}

$toolchainFile = Join-Path $vcpkgPath "scripts\buildsystems\vcpkg.cmake"

if (-not (Test-Path $toolchainFile)) {
    Write-Host "⚠ vcpkg toolchain not found at: $toolchainFile" -ForegroundColor Yellow
    Write-Host "  Building without vcpkg (may fail if dependencies are missing)`n" -ForegroundColor Yellow
    $toolchainFile = $null
}

# Create build directory
Write-Host "[1/3] Creating build directory..." -ForegroundColor Green
if (Test-Path $buildPath) {
    Write-Host "  Cleaning existing build directory..." -ForegroundColor Yellow
    Remove-Item -Path $buildPath -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -Path $buildPath -ItemType Directory -Force | Out-Null
Write-Host "  ✓ Build directory ready`n" -ForegroundColor Green

# Configure with CMake
Write-Host "[2/3] Configuring with CMake..." -ForegroundColor Green
Set-Location $buildPath

try {
    if ($toolchainFile) {
        Write-Host "  Using vcpkg toolchain: $toolchainFile" -ForegroundColor Gray
        cmake .. -G "Visual Studio 17 2022" -A x64 -DCMAKE_TOOLCHAIN_FILE="$toolchainFile"
    } else {
        cmake .. -G "Visual Studio 17 2022" -A x64
    }
    
    if ($LASTEXITCODE -ne 0) {
        throw "CMake configuration failed"
    }
    Write-Host "  ✓ Configuration complete`n" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Configuration failed: $_" -ForegroundColor Red
    Write-Host "`n  Possible solutions:" -ForegroundColor Yellow
    Write-Host "    1. Install Visual Studio 2022 with C++ tools" -ForegroundColor White
    Write-Host "    2. Run setup-build-environment.ps1 first" -ForegroundColor White
    Write-Host "    3. Check INTEGRATION_GUIDE.md for detailed instructions`n" -ForegroundColor White
    exit 1
}

# Build
Write-Host "[3/3] Building (Release mode)..." -ForegroundColor Green
Write-Host "  This may take several minutes...`n" -ForegroundColor Gray

try {
    cmake --build . --config Release
    
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed"
    }
    Write-Host "`n  ✓ Build complete`n" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Build failed: $_" -ForegroundColor Red
    Write-Host "`n  Check the error messages above for details.`n" -ForegroundColor Yellow
    exit 1
}

# Verify output
$exePath = Join-Path $buildPath "bin\Release\nebula_shield_backend.exe"
if (Test-Path $exePath) {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "✓ BUILD SUCCESSFUL!" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    Write-Host "Executable location:" -ForegroundColor Cyan
    Write-Host "  $exePath`n" -ForegroundColor White
    
    Write-Host "To run the backend:" -ForegroundColor Cyan
    Write-Host "  cd backend\build\bin\Release" -ForegroundColor White
    Write-Host "  .\nebula_shield_backend.exe`n" -ForegroundColor White
    
    Write-Host "Or use the start script:" -ForegroundColor Cyan
    Write-Host "  .\start-backend.ps1`n" -ForegroundColor White
} else {
    Write-Host "⚠ Executable not found at expected location" -ForegroundColor Yellow
    Write-Host "  Expected: $exePath" -ForegroundColor Gray
    Write-Host "  Check build output for errors`n" -ForegroundColor Yellow
}

Set-Location $PSScriptRoot
