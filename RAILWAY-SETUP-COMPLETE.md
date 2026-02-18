# Railway Deployment - Completing Setup

## Your Project Information

**Project Created:** ✅ Nebula Shield Anti Virus  
**Project URL:** https://railway.com/project/[YOUR-PROJECT-ID]  
**Account:** [Your Railway Account]

## Step-by-Step: Complete Deployment from Railway Dashboard

### 1. Open Your Project
Go to: https://railway.com/project/9af0fb33-40b6-4ffa-a363-3e5a0ba0d291

### 2. Check Build Status
- Click on your service in the dashboard
- Look at the "Deployments" tab
- Click on the latest deployment to see logs

### 3. If Build Failed - Common Fixes

#### Option A: Redeploy from Dashboard
1. In Railway dashboard, click "Deploy" button
2. Select "Redeploy"
3. Watch the logs for any errors

#### Option B: Deploy from GitHub
1. **Push your code to GitHub** (if not already done):
   ```powershell
   git init
   git add .
   git commit -m "Initial commit for Railway deployment"
   git branch -M main
   git remote add origin YOUR_GITHUB_REPO_URL
   git push -u origin main
   ```

2. **Connect GitHub to Railway:**
   - In Railway dashboard, go to Settings
   - Click "Connect Repo"
   - Select your GitHub repository
   - Choose `backend` as the root directory
   - Railway will automatically redeploy

### 4. Set Root Directory (Important!)

If deploying single directory:
1. Go to Settings in Railway dashboard
2. Scroll to "Root Directory"  
3. Set to: `backend`
4. Save and redeploy

### 5. Verify Environment Variables

Go to Variables tab and ensure these are set:
```
✅ NODE_ENV=production
✅ AUTH_PORT=8082
✅ PORT=8082
✅ JWT_SECRET=(auto-generated)
```

**Optional variables to add:**
```
STRIPE_SECRET_KEY=your_stripe_key
STRIPE_PUBLISHABLE_KEY=your_stripe_pub_key
PAYPAL_CLIENT_ID=your_paypal_id
PAYPAL_CLIENT_SECRET=your_paypal_secret
PAYPAL_MODE=live
EMAIL_SERVICE=gmail
EMAIL_USER=your_email@gmail.com
EMAIL_PASSWORD=your_app_password
EMAIL_FROM=Nebula Shield <noreply@nebulashield.com>
```

### 6. Generate Public Domain

Once deployment succeeds:
1. Go to Settings tab
2. Scroll to "Networking"
3. Click "Generate Domain"
4. You'll get a URL like: `https://nebula-shield-anti-virus-production.up.railway.app`

### 7. Test Your Deployment

```powershell
# Test health endpoint
curl https://YOUR-DOMAIN.railway.app/api/health

# Should return:
# {"status":"healthy","service":"Nebula Shield Auth Server",...}
```

### 8. Configure Your App

Once deployed and working:
```powershell
.\configure-deployment.ps1 -Mode cloud -CloudUrl https://YOUR-DOMAIN.railway.app
```

---

## Alternative: Deploy Using GitHub (Easier Method)

### Step 1: Create GitHub Repository

1. Go to https://github.com/new
2. Create repository "nebula-shield-anti-virus"
3. Don't initialize with README (you already have files)

### Step 2: Push Code to GitHub

```powershell
cd YOUR_PROJECT_PATH

# Initialize git if not already done
git init

# Add files
git add .
git commit -m "Initial commit - Nebula Shield"

# Add remote
git remote add origin https://github.com/YOUR_USERNAME/nebula-shield-anti-virus.git

# Push
git branch -M main
git push -u origin main
```

### Step 3: Connect Railway to GitHub

1. Go back to Railway dashboard
2. Click your project
3. Go to Settings
4. Click "Connect Repo"
5. Select your GitHub repo
6. Set "Root Directory" to `backend`
7. Railway will automatically build and deploy

---

## Troubleshooting Common Issues

### Issue: Build Fails with "Module not found"

**Fix:** Ensure all dependencies are in `backend/package.json`

### Issue: "Cannot find module 'xyz'"

**Fix in Railway:**
1. Go to Settings → Variables
2. Add: `NODE_ENV=production`
3. Redeploy

### Issue: "Port already in use"

**Fix:**
Railway auto-assigns PORT. Your app should use:
```javascript
const PORT = process.env.PORT || process.env.AUTH_PORT || 8082;
```

Check `backend/auth-server.js` to ensure it reads PORT correctly.

### Issue: Database errors

Railway provides PostgreSQL for free. To upgrade from SQLite:
1. In Railway, click "+ New"
2. Add "PostgreSQL"
3. Get DATABASE_URL from Variables
4. Update your app to use PostgreSQL instead of SQLite

---

## Current Status

✅ Railway CLI installed  
✅ Project created on Railway  
✅ Basic environment variables set  
⚠️ Deployment needs to complete  
❌ Domain generation (do after successful deploy)  
❌ App configuration (do after successful deploy)

---

## Quick Fix Script

If you want to try deploying from CLI again with better error handling:

```powershell
# Navigate to backend directory
cd backend

# Link to your existing Railway project
railway link 9af0fb33-40b6-4ffa-a363-3e5a0ba0d291

# Set variables again (in case they didn't save)
railway variables --set "NODE_ENV=production"
railway variables --set "PORT=8082"

# Deploy
railway up

# Watch logs
railway logs
```

---

## Need Help?

1. **Check Build Logs:**
   https://railway.com/project/9af0fb33-40b6-4ffa-a363-3e5a0ba0d291
   
2. **Railway Docs:**
   https://docs.railway.app/guides/nodejs

3. **Support:**
   - Railway Discord: https://discord.gg/railway
   - Railway Help: help@railway.app

---

**Once deployment succeeds, you'll have a cloud backend running 24/7! 🎉**
