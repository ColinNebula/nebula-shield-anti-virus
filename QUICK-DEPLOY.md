# Quick Start: Deploy Nebula Shield to Cloud

## 🚀 Fastest Method: Railway.app (5 minutes)

### 1. Prerequisites
- GitHub account
- Railway account (sign up at [railway.app](https://railway.app))

### 2. Deploy in 3 Steps

#### Option A: Deploy via Railway Dashboard (Easiest)

1. **Push your code to GitHub**
   ```powershell
   git add .
   git commit -m "Prepare for cloud deployment"
   git push origin main
   ```

2. **Deploy to Railway**
   - Go to [railway.app](https://railway.app)
   - Click "New Project" → "Deploy from GitHub repo"
   - Select your repository
   - Railway will auto-detect and deploy!

3. **Configure Environment Variables**
   - In Railway dashboard, go to "Variables"
   - Add these required variables:
     ```
     NODE_ENV=production
     JWT_SECRET=your_secure_random_string_here
     AUTH_PORT=8082
     ```
   - Add optional payment/email variables as needed

4. **Get Your URL**
   - Railway will provide a URL like: `https://your-app-production.up.railway.app`
   - Test it: `https://your-app-production.up.railway.app/api/health`

#### Option B: Deploy via CLI (More Control)

```powershell
# 1. Install Railway CLI and deploy
.\deploy-railway.ps1 -Deploy

# 2. Follow the interactive prompts

# 3. Get your deployment URL from Railway dashboard
```

### 3. Configure Your App to Use Cloud Backend

```powershell
# Replace YOUR_URL with your Railway URL
.\configure-deployment.ps1 -Mode cloud -CloudUrl https://your-app.railway.app
```

### 4. Test Your Deployment

```powershell
# Test health endpoint
curl https://your-app.railway.app/api/health

# Should return:
# {
#   "status": "healthy",
#   "service": "Nebula Shield Auth Server"
# }
```

### 5. Update Mobile App

Your mobile app is automatically configured to use the cloud backend!

Just rebuild:
```bash
cd mobile
npm run build
```

---

## 🎯 What This Achieves

✅ Mobile app works without your computer on  
✅ Authentication works from anywhere  
✅ Payment processing available 24/7  
✅ Multiple devices can connect simultaneously  
✅ Professional deployment with SSL/HTTPS  

---

## 🔄 Switch Back to Local

```powershell
.\configure-deployment.ps1 -Mode local
```

---

## 💰 Cost

**Railway Free Tier:**
- $5 free credit per month
- Enough for testing and small-scale use
- Paid plans start at $5/month for more usage

---

## 🆘 Troubleshooting

### "Cannot connect to backend"
1. Check your Railway deployment is running (dashboard shows green)
2. Verify URL is correct (no trailing slash)
3. Test health endpoint: `curl https://your-url/api/health`

### "Environment variables not working"
1. Go to Railway dashboard → Variables
2. Click "Raw Editor"
3. Paste your variables
4. Restart deployment

### "Build failed"
1. Check Railway build logs
2. Ensure `backend/package.json` exists
3. Verify all dependencies are in package.json

---

## 📚 More Options

See [CLOUD-DEPLOYMENT-GUIDE.md](CLOUD-DEPLOYMENT-GUIDE.md) for:
- AWS EC2 deployment
- Render.com deployment  
- Heroku deployment
- Custom domain setup
- Production security hardening
- Database migration to PostgreSQL

---

## ⚡ Ultra-Quick Summary

```powershell
# 1. Deploy to Railway
.\deploy-railway.ps1 -Deploy

# 2. Configure app
.\configure-deployment.ps1 -Mode cloud -CloudUrl YOUR_RAILWAY_URL

# 3. Test
curl YOUR_RAILWAY_URL/api/health

# Done! 🎉
```
