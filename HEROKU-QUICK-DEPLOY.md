# Heroku Quick Deploy Reference

⚡ **3-Step Deployment Process**

## Step 1: Setup
```powershell
npm run deploy:heroku:setup
```
Or with custom name:
```powershell
.\deploy-to-heroku.ps1 -Setup -AppName my-app-name
```

## Step 2: Set Environment Variables
```powershell
npm run deploy:heroku:env
```
Reads from `backend/.env` and sets all variables on Heroku.

## Step 3: Deploy
```powershell
npm run deploy:heroku
```

---

## 🎯 Quick Commands

| Command | What it does |
|---------|-------------|
| `npm run deploy:heroku:setup` | First-time setup |
| `npm run deploy:heroku:env` | Update environment variables |
| `npm run deploy:heroku` | Deploy to Heroku |
| `npm run deploy:heroku:logs` | View live logs |

## 📋 Manual Commands

```bash
# View status
.\deploy-to-heroku.ps1 -Status

# Open app in browser
heroku open --app nebula-shield-backend

# View config
heroku config --app nebula-shield-backend

# Database migration (if using PostgreSQL)
heroku run npm run migrate --app nebula-shield-backend
```

## ⚠️ Important Notes

1. **JWT_SECRET is required** - App won't start without it
2. **SQLite won't persist** - Use PostgreSQL addon for production
3. **Only backend folder is deployed** - Uses git subtree
4. **Port is automatic** - Heroku sets `PORT` environment variable

## 🔧 Troubleshooting

**App crashed?**
```powershell
npm run deploy:heroku:logs
```

**Need to force deploy?**
```bash
git push heroku `git subtree split --prefix backend main`:main --force
```

**Environment variables not set?**
```powershell
npm run deploy:heroku:env
```

---

📖 **Full Guide:** See [HEROKU-DEPLOYMENT-GUIDE.md](HEROKU-DEPLOYMENT-GUIDE.md)
