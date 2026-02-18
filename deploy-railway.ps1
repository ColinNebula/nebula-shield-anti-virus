# ====================================
# Quick Deployment to Railway
# ====================================

param(
    [Parameter(Mandatory=$false)]
    [switch]$Install,
    
    [Parameter(Mandatory=$false)]
    [switch]$Deploy,
    
    [Parameter(Mandatory=$false)]
    [switch]$Logs,
    
    [Parameter(Mandatory=$false)]
    [switch]$Status
)

$ErrorActionPreference = "Continue"

Write-Host "🚂 Nebula Shield - Railway Deployment" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan

# Check if Railway CLI is installed
$railwayInstalled = Get-Command railway -ErrorAction SilentlyContinue

if ($Install -or (-not $railwayInstalled)) {
    Write-Host "📦 Installing Railway CLI..." -ForegroundColor Yellow
    
    # Install via npm (most reliable cross-platform method)
    Write-Host "Installing via npm..." -ForegroundColor Yellow
    npm install -g @railway/cli
    
    Write-Host "✅ Railway CLI installed!" -ForegroundColor Green
    Write-Host ""
}

if ($Deploy) {
    Write-Host "🚀 Deploying to Railway..." -ForegroundColor Green
    Write-Host ""
    
    # Check if user is logged in
    Write-Host "Step 1: Login to Railway" -ForegroundColor Cyan
    railway login
    
    Write-Host ""
    Write-Host "Step 2: Initialize project (if not already done)" -ForegroundColor Cyan
    $initResponse = Read-Host "Is this a new project? (y/n)"
    
    if ($initResponse -eq "y") {
        railway init
    }
    else {
        Write-Host "Using existing Railway project" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "Step 3: Set environment variables" -ForegroundColor Cyan
    Write-Host "You can set these now or later in Railway dashboard" -ForegroundColor Yellow
    Write-Host ""
    
    $setEnvVars = Read-Host "Do you want to set environment variables now? (y/n)"
    
    if ($setEnvVars -eq "y") {
        Write-Host ""
        Write-Host "Enter your environment variables (press Enter to skip):" -ForegroundColor Yellow
        
        $jwtSecret = Read-Host "JWT_SECRET (will be generated if empty)"
        if ($jwtSecret) {
            railway variables set "JWT_SECRET=$jwtSecret"
        }
        else {
            # Generate a random JWT secret
            $randomSecret = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | ForEach-Object {[char]$_})
            railway variables set "JWT_SECRET=$randomSecret"
            Write-Host "Generated random JWT_SECRET" -ForegroundColor Green
        }
        
        $stripeKey = Read-Host "STRIPE_SECRET_KEY (optional)"
        if ($stripeKey) {
            railway variables set "STRIPE_SECRET_KEY=$stripeKey"
        }
        
        $emailUser = Read-Host "EMAIL_USER (optional)"
        if ($emailUser) {
            railway variables set "EMAIL_USER=$emailUser"
        }
        
        $emailPass = Read-Host "EMAIL_PASSWORD (optional)"
        if ($emailPass) {
            railway variables set "EMAIL_PASSWORD=$emailPass"
        }
        
        Write-Host "✅ Environment variables set!" -ForegroundColor Green
        Write-Host "You can add more variables in Railway dashboard" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "Step 4: Deploy backend" -ForegroundColor Cyan
    Write-Host "Note: Railway will build and deploy from the backend directory" -ForegroundColor Yellow
    
    # Deploy using railway up
    railway up
    
    Write-Host ""
    Write-Host "✅ Deployment initiated!" -ForegroundColor Green
    Write-Host "Check status in Railway dashboard: https://railway.app" -ForegroundColor Yellow
    
    Write-Host ""
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "🎉 Deployment Complete!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "1. Open Railway dashboard to get your deployment URL" -ForegroundColor White
    Write-Host "   https://railway.app/dashboard" -ForegroundColor Cyan
    Write-Host "2. In Settings, generate a domain" -ForegroundColor White
    Write-Host "3. Test: curl https://your-app.railway.app/api/health" -ForegroundColor White
    Write-Host "4. Configure app:" -ForegroundColor White
    Write-Host "   .\configure-deployment.ps1 -Mode cloud -CloudUrl https://your-app.railway.app" -ForegroundColor Cyan
    Write-Host ""
}

if ($Logs) {
    Write-Host "📋 Fetching logs..." -ForegroundColor Yellow
    railway logs
}

if ($Status) {
    Write-Host "📊 Checking deployment status..." -ForegroundColor Yellow
    railway status
}

if (-not $Install -and -not $Deploy -and -not $Logs -and -not $Status) {
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\deploy-railway.ps1 -Install    # Install Railway CLI" -ForegroundColor White
    Write-Host "  .\deploy-railway.ps1 -Deploy     # Deploy to Railway" -ForegroundColor White
    Write-Host "  .\deploy-railway.ps1 -Logs       # View logs" -ForegroundColor White
    Write-Host "  .\deploy-railway.ps1 -Status     # Check status" -ForegroundColor White
    Write-Host ""
    Write-Host "Quick start:" -ForegroundColor Cyan
    Write-Host "  .\deploy-railway.ps1 -Deploy" -ForegroundColor Green
    Write-Host ""
}
