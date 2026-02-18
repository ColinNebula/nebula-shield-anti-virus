param(
    [switch]$Deploy,
    [switch]$Setup,
    [switch]$SetEnv,
    [switch]$Logs,
    [switch]$Status,
    [string]$AppName = "nebula-shield-backend"
)

# Color output function
function Write-Color {
    param(
        [string]$Text,
        [string]$Color = "White"
    )
    Write-Host $Text -ForegroundColor $Color
}

# Header
Write-Host "`n================================" -ForegroundColor Cyan
Write-Host "NEBULA SHIELD HEROKU DEPLOYMENT" -ForegroundColor Cyan
Write-Host "================================`n" -ForegroundColor Cyan

# Check if Heroku CLI is installed
function Test-HerokuCLI {
    try {
        $herokuVersion = heroku --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Color "✓ Heroku CLI found: $herokuVersion" "Green"
            return $true
        }
    } catch {
        Write-Color "✗ Heroku CLI not installed" "Red"
        Write-Host "`nInstall from: https://devcenter.heroku.com/articles/heroku-cli" -ForegroundColor Yellow
        Write-Host "Or run: npm install -g heroku`n" -ForegroundColor Yellow
        return $false
    }
}

# Setup: Login and create app
if ($Setup) {
    Write-Color "`n[SETUP] Heroku App Setup" "Yellow"
    Write-Host "========================`n"
    
    if (-not (Test-HerokuCLI)) {
        exit 1
    }
    
    # Login
    Write-Color "`n1. Logging into Heroku..." "Cyan"
    heroku login
    
    if ($LASTEXITCODE -ne 0) {
        Write-Color "✗ Login failed" "Red"
        exit 1
    }
    
    # Create app
    Write-Color "`n2. Creating Heroku app: $AppName" "Cyan"
    heroku create $AppName
    
    if ($LASTEXITCODE -ne 0) {
        Write-Color "✗ Failed to create app (it may already exist)" "Yellow"
    } else {
        Write-Color "✓ App created successfully" "Green"
    }
    
    # Add git remote
    Write-Color "`n3. Adding Heroku remote..." "Cyan"
    git remote remove heroku 2>$null
    heroku git:remote -a $AppName
    
    Write-Color "`n✓ Setup complete!" "Green"
    Write-Host "`nNext steps:" -ForegroundColor Cyan
    Write-Host "  1. Set environment variables: .\deploy-to-heroku.ps1 -SetEnv" -ForegroundColor White
    Write-Host "  2. Deploy the backend: .\deploy-to-heroku.ps1 -Deploy`n" -ForegroundColor White
    
    exit 0
}

# Set environment variables
if ($SetEnv) {
    Write-Color "`n[ENVIRONMENT] Setting Environment Variables" "Yellow"
    Write-Host "============================================`n"
    
    if (-not (Test-HerokuCLI)) {
        exit 1
    }
    
    # Check if .env file exists
    if (-not (Test-Path "backend\.env")) {
        Write-Color "✗ backend\.env file not found" "Red"
        Write-Host "Create a backend\.env file first with your environment variables`n" -ForegroundColor Yellow
        exit 1
    }
    
    Write-Color "Reading environment variables from backend\.env..." "Cyan"
    
    # Required variables
    $requiredVars = @(
        "JWT_SECRET",
        "NODE_ENV"
    )
    
    # Optional variables
    $optionalVars = @(
        "STRIPE_SECRET_KEY",
        "STRIPE_PUBLISHABLE_KEY",
        "PAYPAL_CLIENT_ID",
        "PAYPAL_CLIENT_SECRET",
        "EMAIL_USER",
        "EMAIL_PASSWORD"
    )
    
    # Read .env file
    $envContent = Get-Content "backend\.env" -ErrorAction SilentlyContinue
    $envVars = @{}
    
    foreach ($line in $envContent) {
        if ($line -match '^([^#][^=]+)=(.+)$') {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()
            $envVars[$key] = $value
        }
    }
    
    # Set required variables
    Write-Color "`nSetting required variables..." "Cyan"
    foreach ($var in $requiredVars) {
        if ($envVars.ContainsKey($var)) {
            $value = $envVars[$var]
            Write-Host "  Setting $var..." -NoNewline
            heroku config:set "${var}=${value}" --app $AppName 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Color " ✓" "Green"
            } else {
                Write-Color " ✗" "Red"
            }
        } else {
            Write-Color "  ✗ $var not found in .env file" "Red"
        }
    }
    
    # Set optional variables
    Write-Color "`nSetting optional variables..." "Cyan"
    foreach ($var in $optionalVars) {
        if ($envVars.ContainsKey($var) -and $envVars[$var] -ne "") {
            Write-Host "  Setting $var..." -NoNewline
            heroku config:set "${var}=$($envVars[$var])" --app $AppName 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Color " ✓" "Green"
            } else {
                Write-Color " ✗" "Red"
            }
        }
    }
    
    # Set production environment
    Write-Host "`n  Setting NODE_ENV=production..." -NoNewline
    heroku config:set NODE_ENV=production --app $AppName 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Color " ✓" "Green"
    }
    
    Write-Color "`n✓ Environment variables set!" "Green"
    Write-Host "`nView all config: heroku config --app $AppName`n" -ForegroundColor Yellow
    
    exit 0
}

# View logs
if ($Logs) {
    Write-Color "`n[LOGS] Viewing Heroku Logs" "Yellow"
    Write-Host "==========================`n"
    
    heroku logs --tail --app $AppName
    exit 0
}

# Check status
if ($Status) {
    Write-Color "`n[STATUS] Heroku App Status" "Yellow"
    Write-Host "==========================`n"
    
    heroku ps --app $AppName
    Write-Host ""
    heroku apps:info --app $AppName
    Write-Host ""
    
    exit 0
}

# Deploy to Heroku
if ($Deploy) {
    Write-Color "`n[DEPLOY] Deploying to Heroku" "Yellow"
    Write-Host "============================`n"
    
    if (-not (Test-HerokuCLI)) {
        exit 1
    }
    
    # Check if backend directory exists
    if (-not (Test-Path "backend")) {
        Write-Color "✗ backend directory not found" "Red"
        exit 1
    }
    
    # Check if Procfile exists
    if (-not (Test-Path "backend\Procfile")) {
        Write-Color "✗ backend\Procfile not found" "Red"
        Write-Host "Creating Procfile..." -ForegroundColor Yellow
        
        @"
web: node auth-server.js
scanner: node real-scanner-api.js
protection: node integrated-protection-service.js
"@ | Out-File -FilePath "backend\Procfile" -Encoding ASCII -NoNewline
        
        Write-Color "✓ Procfile created" "Green"
    }
    
    # Check if heroku remote exists
    $remotes = git remote -v 2>&1
    if ($remotes -notmatch "heroku") {
        Write-Color "`n⚠ Heroku remote not found" "Yellow"
        Write-Host "Run setup first: .\deploy-to-heroku.ps1 -Setup`n" -ForegroundColor Yellow
        exit 1
    }
    
    Write-Color "1. Checking git status..." "Cyan"
    git status --short
    
    $uncommitted = git status --porcelain
    if ($uncommitted) {
        Write-Color "`n⚠ Uncommitted changes detected" "Yellow"
        $commit = Read-Host "Commit changes before deploying? (y/n)"
        if ($commit -eq "y") {
            git add -A
            $message = Read-Host "Commit message"
            if ([string]::IsNullOrWhiteSpace($message)) {
                $message = "Pre-deployment commit"
            }
            git commit -m $message
            Write-Color "✓ Changes committed" "Green"
        }
    }
    
    Write-Color "`n2. Deploying backend to Heroku..." "Cyan"
    Write-Host "This will deploy only the backend folder using git subtree...`n"
    
    # Deploy using git subtree (this deploys only the backend folder)
    git subtree push --prefix backend heroku main
    
    if ($LASTEXITCODE -ne 0) {
        Write-Color "`n✗ Deployment failed" "Red"
        Write-Host "`nTroubleshooting:" -ForegroundColor Yellow
        Write-Host "  1. Make sure you're logged in: heroku login" -ForegroundColor White
        Write-Host "  2. Check if app exists: heroku apps:info --app $AppName" -ForegroundColor White
        Write-Host "  3. Try forcing: git push heroku `git subtree split --prefix backend main`:main --force`n" -ForegroundColor White
        exit 1
    }
    
    Write-Color "`n✓ Deployment complete!" "Green"
    
    # Get app URL
    $appUrl = (heroku apps:info --app $AppName --json | ConvertFrom-Json).app.web_url
    
    Write-Host "`n================================" -ForegroundColor Cyan
    Write-Host "DEPLOYMENT SUCCESSFUL" -ForegroundColor Green
    Write-Host "================================" -ForegroundColor Cyan
    Write-Host "`nApp URL: $appUrl" -ForegroundColor White
    Write-Host "`nUseful commands:" -ForegroundColor Cyan
    Write-Host "  View logs:   .\deploy-to-heroku.ps1 -Logs" -ForegroundColor White
    Write-Host "  Check status: .\deploy-to-heroku.ps1 -Status" -ForegroundColor White
    Write-Host "  Open app:    heroku open --app $AppName" -ForegroundColor White
    Write-Host "  Dashboard:   heroku dashboard" -ForegroundColor White
    Write-Host "`n"
    
    exit 0
}

# Default: Show help
Write-Host "Usage:" -ForegroundColor Yellow
Write-Host "  .\deploy-to-heroku.ps1 -Setup           # First-time setup (login, create app)" -ForegroundColor White
Write-Host "  .\deploy-to-heroku.ps1 -SetEnv          # Set environment variables from .env" -ForegroundColor White
Write-Host "  .\deploy-to-heroku.ps1 -Deploy          # Deploy backend to Heroku" -ForegroundColor White
Write-Host "  .\deploy-to-heroku.ps1 -Logs            # View application logs" -ForegroundColor White
Write-Host "  .\deploy-to-heroku.ps1 -Status          # Check app status" -ForegroundColor White
Write-Host "`nOptions:" -ForegroundColor Yellow
Write-Host "  -AppName <name>                         # Specify app name (default: nebula-shield-backend)" -ForegroundColor White
Write-Host "`nExamples:" -ForegroundColor Yellow
Write-Host "  .\deploy-to-heroku.ps1 -Setup -AppName my-custom-app" -ForegroundColor White
Write-Host "  .\deploy-to-heroku.ps1 -Deploy" -ForegroundColor White
Write-Host "`n"
