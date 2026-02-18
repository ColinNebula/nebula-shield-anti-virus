# Simple Railway Deployment Script for Nebula Shield

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Nebula Shield - Railway Deployment" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check Railway CLI
Write-Host "[1/5] Checking Railway CLI..." -ForegroundColor Yellow
$railwayCli = Get-Command railway -ErrorAction SilentlyContinue

if (-not $railwayCli) {
    Write-Host "Railway CLI not found. Installing..." -ForegroundColor Yellow
    npm install -g @railway/cli
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to install Railway CLI" -ForegroundColor Red
        Write-Host "Please install manually: npm install -g @railway/cli" -ForegroundColor Yellow
        exit 1
    }
    
    Write-Host "✅ Railway CLI installed successfully!" -ForegroundColor Green
} else {
    Write-Host "✅ Railway CLI already installed" -ForegroundColor Green
}

Write-Host ""

# Step 2: Login
Write-Host "[2/5] Logging in to Railway..." -ForegroundColor Yellow
Write-Host "A browser window will open for authentication..." -ForegroundColor Gray
railway login

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Railway login failed" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Logged in successfully!" -ForegroundColor Green
Write-Host ""

# Step 3: Project setup
Write-Host "[3/5] Project setup..." -ForegroundColor Yellow

# Check if already linked to a project
$linkedProject = railway status 2>&1

if ($linkedProject -like "*No linked project*" -or $LASTEXITCODE -ne 0) {
    Write-Host "Creating new Railway project for Nebula Shield..." -ForegroundColor Yellow
    Write-Host ""
    
    # Change to backend directory first
    Push-Location backend
    
    try {
        railway init
        
        if ($LASTEXITCODE -ne 0) {
            Write-Host "ERROR: Failed to create project" -ForegroundColor Red
            Pop-Location
            exit 1
        }
    }
    finally {
        Pop-Location
    }
} else {
    Write-Host "✅ Already linked to a Railway project" -ForegroundColor Green
}

Write-Host "✅ Project configured" -ForegroundColor Green
Write-Host ""

# Step 4: Environment variables
Write-Host "[4/5] Setting environment variables..." -ForegroundColor Yellow
Write-Host ""

Write-Host "Setting required variables..." -ForegroundColor Yellow

# Generate JWT secret
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$jwtSecret = [Convert]::ToBase64String($bytes)

# Change to backend directory
Push-Location backend

try {
    $null = railway variables --set "NODE_ENV=production" 2>&1
    $null = railway variables --set "AUTH_PORT=8082" 2>&1
    $null = railway variables --set "PORT=8082" 2>&1
    $null = railway variables --set "JWT_SECRET=$jwtSecret" 2>&1
    
    Write-Host "✅ Basic environment variables set!" -ForegroundColor Green
}
catch {
    Write-Host "⚠️  Some variables may not have been set. You can set them in Railway dashboard." -ForegroundColor Yellow
}
finally {
    Pop-Location
}

Write-Host ""
Write-Host "💡 Add more variables in Railway dashboard:" -ForegroundColor Cyan
Write-Host "   https://railway.app/dashboard → Your Project → Variables" -ForegroundColor Gray
Write-Host ""
Write-Host "  Optional variables:" -ForegroundColor Yellow
Write-Host "   - STRIPE_SECRET_KEY" -ForegroundColor Gray
Write-Host "   - PAYPAL_CLIENT_ID" -ForegroundColor Gray
Write-Host "   - EMAIL_USER" -ForegroundColor Gray
Write-Host "   - EMAIL_PASSWORD" -ForegroundColor Gray
Write-Host "   (see backend/.env.production for full list)" -ForegroundColor Gray

Write-Host ""

# Step 5: Deploy
Write-Host "[5/5] Deploying to Railway..." -ForegroundColor Yellow
Write-Host "This may take a few minutes..." -ForegroundColor Gray
Write-Host ""

# Change to backend directory for deployment
Push-Location backend

try {
    railway up
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Deployment failed" -ForegroundColor Red
        Write-Host "Check Railway dashboard for details: https://railway.app/dashboard" -ForegroundColor Yellow
        Pop-Location
        exit 1
    }
}
finally {
    Pop-Location
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ✅ DEPLOYMENT COMPLETE!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. Open Railway dashboard:" -ForegroundColor White
Write-Host "   https://railway.app/dashboard" -ForegroundColor Cyan
Write-Host ""
Write-Host "2. In your project Settings:" -ForegroundColor White
Write-Host "   - Go to Networking tab" -ForegroundColor Gray
Write-Host "   - Click 'Generate Domain' to get your public URL" -ForegroundColor Gray
Write-Host ""
Write-Host "3. Set any missing environment variables in Variables tab" -ForegroundColor White
Write-Host ""
Write-Host "4. Test your deployment:" -ForegroundColor White
Write-Host "   curl https://your-app.railway.app/api/health" -ForegroundColor Cyan
Write-Host ""
Write-Host "5. Configure your app to use cloud backend:" -ForegroundColor White
Write-Host "   .\configure-deployment.ps1 -Mode cloud -CloudUrl https://your-app.railway.app" -ForegroundColor Cyan
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
