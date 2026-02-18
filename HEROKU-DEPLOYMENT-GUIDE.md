# Heroku Deployment Guide

Quick guide to deploy Nebula Shield backend to Heroku.

## Prerequisites

1. **Heroku Account**: Sign up at [heroku.com](https://heroku.com)
2. **Heroku CLI**: Install from [devcenter.heroku.com/articles/heroku-cli](https://devcenter.heroku.com/articles/heroku-cli)
3. **Git**: Make sure git is installed
4. **Environment Variables**: Have your `.env` file ready in the `backend/` folder

## Quick Start (3 Steps)

### Step 1: Setup Heroku App

```powershell
.\deploy-to-heroku.ps1 -Setup
```

This will:
- Login to Heroku
- Create a new app called `nebula-shield-backend`
- Add Heroku git remote

**Custom app name:**
```powershell
.\deploy-to-heroku.ps1 -Setup -AppName my-custom-name
```

### Step 2: Set Environment Variables

```powershell
.\deploy-to-heroku.ps1 -SetEnv
```

This automatically reads `backend/.env` and sets all variables on Heroku.

**Required variables:**
- `JWT_SECRET` (CRITICAL - app won't start without it)
- `NODE_ENV` (automatically set to `production`)

**Optional variables:**
- `STRIPE_SECRET_KEY`, `STRIPE_PUBLISHABLE_KEY`
- `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`
- `EMAIL_USER`, `EMAIL_PASSWORD`

### Step 3: Deploy

```powershell
.\deploy-to-heroku.ps1 -Deploy
```

This deploys only the `backend/` folder to Heroku using git subtree.

## Other Commands

### View Logs
```powershell
.\deploy-to-heroku.ps1 -Logs
```

### Check Status
```powershell
.\deploy-to-heroku.ps1 -Status
```

### Open App in Browser
```powershell
heroku open --app nebula-shield-backend
```

### View Dashboard
```powershell
heroku dashboard
```

## Manual Deployment (Alternative)

If you prefer manual commands:

```bash
# 1. Login
heroku login

# 2. Create app
heroku create nebula-shield-backend

# 3. Set environment variables
heroku config:set JWT_SECRET=your_secret_here
heroku config:set NODE_ENV=production

# 4. Deploy
git subtree push --prefix backend heroku main
```

## Heroku Configuration

### Procfile

The `backend/Procfile` defines what processes to run:

```
web: node auth-server.js
scanner: node real-scanner-api.js
protection: node integrated-protection-service.js
```

Only the `web` process runs by default on the free tier. To enable others, scale them:

```bash
heroku ps:scale web=1 scanner=1 protection=1
```

### Database

Heroku uses ephemeral filesystem. For production, add a database:

```bash
# Add PostgreSQL (recommended for production)
heroku addons:create heroku-postgresql:mini

# Or use ClearDB MySQL
heroku addons:create cleardb:ignite
```

**Important:** SQLite won't persist across deployments on Heroku.

## Update Backend URL in Frontend

After deployment, update your frontend to use the Heroku URL:

### For Desktop App

Update `src/contexts/AuthContext.js`:

```javascript
const API_BASE = process.env.REACT_APP_CLOUD_BACKEND === 'true' 
  ? 'https://nebula-shield-backend.herokuapp.com/api'
  : 'http://localhost:8082/api';
```

Or set environment variable:
```bash
REACT_APP_API_URL=https://nebula-shield-backend.herokuapp.com
```

### For Mobile App

Update `mobile/src/services/AuthService.ts`:

```typescript
const API_URL = 'https://nebula-shield-backend.herokuapp.com/api';
```

## Troubleshooting

### Deployment Failed

**Force push if needed:**
```bash
git push heroku `git subtree split --prefix backend main`:main --force
```

### App Crashed

**Check logs:**
```powershell
.\deploy-to-heroku.ps1 -Logs
```

**Common issues:**
- `JWT_SECRET` not set → Set with `-SetEnv`
- Port binding error → Make sure `auth-server.js` uses `process.env.PORT`
- Missing dependencies → Check `backend/package.json`

### Can't Find Heroku Remote

**Re-add remote:**
```bash
heroku git:remote -a nebula-shield-backend
```

## Heroku Pricing

| Tier | Cost | Resources |
|------|------|-----------|
| Eco Dyno | $5/month | 1000 dyno hours |
| Basic | $7/month | Always on, custom domain |
| Standard 1X | $25/month | 512MB RAM, performance |
| Standard 2X | $50/month | 1GB RAM, better performance |

**Note:** Heroku deprecated free tier in November 2022.

## CI/CD with GitHub

Enable automatic deployments from GitHub:

1. Go to Heroku Dashboard
2. Select your app
3. Go to "Deploy" tab
4. Connect to GitHub
5. Enable "Automatic Deploys" for your branch

## Environment Variables Reference

Set these on Heroku:

```bash
# Required
JWT_SECRET=your-secure-random-string
NODE_ENV=production

# Payment (optional)
STRIPE_SECRET_KEY=sk_live_...
STRIPE_PUBLISHABLE_KEY=pk_live_...
PAYPAL_CLIENT_ID=...
PAYPAL_CLIENT_SECRET=...

# Email (optional)
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-app-password

# Database (if using external DB)
DATABASE_URL=postgres://...
```

## Next Steps

1. ✅ Deploy backend to Heroku
2. 🔄 Migrate from SQLite to PostgreSQL (recommended)
3. 🔄 Set up custom domain
4. 🔄 Enable SSL (automatic with custom domain)
5. 🔄 Set up monitoring and alerts
6. 🔄 Configure CI/CD pipeline

## Useful Links

- [Heroku Dashboard](https://dashboard.heroku.com)
- [Heroku CLI Documentation](https://devcenter.heroku.com/articles/heroku-cli)
- [Node.js on Heroku](https://devcenter.heroku.com/articles/getting-started-with-nodejs)
- [Heroku Postgres](https://devcenter.heroku.com/articles/heroku-postgresql)

---

**Need help?** Run: `.\deploy-to-heroku.ps1` (no arguments) to see command reference.
