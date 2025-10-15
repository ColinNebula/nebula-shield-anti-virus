# Build Inno Setup Installer
# This script compiles the Inno Setup script to create the final installer

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Inno Setup Compiler" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$ErrorActionPreference = "Stop"
$InstallerDir = $PSScriptRoot
$IssFile = Join-Path $InstallerDir "nebula-shield.iss"

# Check if Inno Setup is installed
$InnoSetupPaths = @(
    "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
    "C:\Program Files\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles}\Inno Setup 6\ISCC.exe"
)

$IsccPath = $null
foreach ($path in $InnoSetupPaths) {
    if (Test-Path $path) {
        $IsccPath = $path
        break
    }
}

if ($null -eq $IsccPath) {
    Write-Host "ERROR: Inno Setup not found!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please install Inno Setup from:" -ForegroundColor Yellow
    Write-Host "https://jrsoftware.org/isdl.php" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "After installation, run this script again." -ForegroundColor Yellow
    
    $response = Read-Host "`nWould you like to open the download page now? (Y/N)"
    if ($response -eq 'Y' -or $response -eq 'y') {
        Start-Process "https://jrsoftware.org/isdl.php"
    }
    
    exit 1
}

Write-Host "Found Inno Setup at: $IsccPath" -ForegroundColor Green
Write-Host ""

# Check if build directory exists
$BuildDir = Join-Path $InstallerDir "build"
if (!(Test-Path $BuildDir)) {
    Write-Host "ERROR: Build directory not found!" -ForegroundColor Red
    Write-Host "Please run build-installer.ps1 first to prepare the installation files." -ForegroundColor Yellow
    exit 1
}

# Compile the installer
Write-Host "Compiling installer..." -ForegroundColor Green
Write-Host ""

& $IsccPath $IssFile

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  Installer Created Successfully!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    
    $OutputDir = Join-Path $InstallerDir "output"
    $Installers = Get-ChildItem -Path $OutputDir -Filter "*.exe"
    
    if ($Installers.Count -gt 0) {
        Write-Host "Installer location:" -ForegroundColor Cyan
        foreach ($installer in $Installers) {
            Write-Host "  $($installer.FullName)" -ForegroundColor White
            Write-Host "  Size: $([math]::Round($installer.Length / 1MB, 2)) MB" -ForegroundColor Gray
        }
        Write-Host ""
        
        $response = Read-Host "Would you like to open the output folder? (Y/N)"
        if ($response -eq 'Y' -or $response -eq 'y') {
            Start-Process $OutputDir
        }
    }
} else {
    Write-Host ""
    Write-Host "ERROR: Installer compilation failed!" -ForegroundColor Red
    Write-Host "Check the output above for errors." -ForegroundColor Yellow
    exit 1
}
