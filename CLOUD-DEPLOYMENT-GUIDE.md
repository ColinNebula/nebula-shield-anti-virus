# Cloud Deployment Guide

## Making Your App Work Without Your Computer On

### Understanding the Architecture

**Important:** Desktop antivirus software MUST run locally on the computer it protects. However, you can deploy the backend to the cloud so:
- Mobile apps work without your PC on
- Multiple devices can connect to the same backend
- Remote management features work from anywhere

## Option 1: Deploy to Railway.app (Recommended for Beginners)

### Step 1: Prepare Backend for Cloud

1. **Create a production environment file** (`backend/.env.production`):
```env
# ================================
# AUTHENTICATION
# ================================
AUTH_PORT=8082
JWT_SECRET=YOUR_SECURE_SECRET_HERE_GENERATE_RANDOM_STRING

# ================================
# STRIPE PAYMENT CONFIGURATION
# ================================
STRIPE_SECRET_KEY=your_stripe_key_here
STRIPE_PUBLISHABLE_KEY=your_publishable_key_here
STRIPE_WEBHOOK_SECRET=your_webhook_secret_here

# ================================
# PAYPAL PAYMENT CONFIGURATION
# ================================
PAYPAL_CLIENT_ID=your_paypal_client_id
PAYPAL_CLIENT_SECRET=your_paypal_secret
PAYPAL_MODE=live

# ================================
# EMAIL CONFIGURATION
# ================================
EMAIL_SERVICE=gmail
EMAIL_USER=your_email@gmail.com
EMAIL_PASSWORD=your_app_password
EMAIL_FROM=Nebula Shield <noreply@nebulashield.com>

# ================================
# APPLICATION SETTINGS
# ================================
APP_URL=https://your-app-domain.railway.app
PREMIUM_PRICE_USD=49.00
PREMIUM_PRICE_YEARLY=49.00
CURRENCY=USD
NODE_ENV=production
```

### Step 2: Update Backend Package.json

Ensure your `backend/package.json` has proper start script:
```json
{
  "scripts": {
    "start": "node auth-server.js",
    "start:all": "concurrently \"npm run start\" \"npm run start:scanner\" \"npm run start:protection\""
  }
}
```

### Step 3: Deploy to Railway

1. **Sign up at [railway.app](https://railway.app)**

2. **Create New Project** → "Deploy from GitHub"

3. **Configure Variables:**
   - Add all environment variables from `.env.production`
   - Set `PORT` to `8082` (or Railway will assign one)

4. **Set Root Directory:**
   - In settings, set root directory to `/backend`

5. **Deploy!**
   - Railway will automatically deploy
   - You'll get a URL like: `https://your-app.railway.app`

### Step 4: Update Mobile App Configuration

Edit `mobile/app.json` or wherever API_URL is configured:
```json
{
  "extra": {
    "apiUrl": "https://your-app.railway.app/api"
  }
}
```

Edit `mobile/src/services/AuthService.ts`:
```typescript
const API_URL = Constants.expoConfig?.extra?.apiUrl || 'https://your-app.railway.app/api';
```

---

## Option 2: Deploy to Render.com (Free Tier)

### Step 1: Create `render.yaml`

Create `render.yaml` in project root:
```yaml
services:
  - type: web
    name: nebula-shield-backend
    env: node
    region: oregon
    plan: free
    buildCommand: cd backend && npm install
    startCommand: cd backend && npm start
    envVars:
      - key: NODE_ENV
        value: production
      - key: AUTH_PORT
        value: 8082
      - key: JWT_SECRET
        generateValue: true
      - key: APP_URL
        value: https://nebula-shield-backend.onrender.com
      # Add other env vars from your .env file
```

### Step 2: Deploy

1. Sign up at [render.com](https://render.com)
2. Connect your GitHub repo
3. Render will auto-detect `render.yaml`
4. Add environment variables in dashboard
5. Deploy!

---

## Option 3: AWS EC2 (For Production)

### Step 1: Launch EC2 Instance

1. **Create Ubuntu Server** (t2.micro for free tier)
2. **Configure Security Group:**
   - Allow port 22 (SSH)
   - Allow port 8082 (Backend)
   - Allow port 443 (HTTPS with nginx)

### Step 2: Install Node.js

```bash
ssh into your instance
sudo apt update
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
sudo npm install -g pm2
```

### Step 3: Deploy Backend

```bash
# Clone your repo
git clone https://github.com/yourusername/nebula-shield-anti-virus.git
cd nebula-shield-anti-virus/backend

# Install dependencies
npm install --production

# Set up environment
cp .env.example .env
nano .env  # Edit with production values

# Start with PM2
pm2 start auth-server.js --name nebula-auth
pm2 start real-scanner-api.js --name nebula-scanner
pm2 start integrated-protection-service.js --name nebula-protection

# Save PM2 config
pm2 save
pm2 startup
```

### Step 4: Set Up Nginx (Optional for HTTPS)

```bash
sudo apt install nginx certbot python3-certbot-nginx

# Configure nginx
sudo nano /etc/nginx/sites-available/nebula
```

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:8082;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/nebula /etc/nginx/sites-enabled/
sudo certbot --nginx -d your-domain.com
sudo nginx -t && sudo nginx -s reload
```

---

## Option 4: Deploy to Heroku

### Step 1: Create Procfile

Create `Procfile` in backend directory:
```
web: node auth-server.js
```

### Step 2: Deploy

```bash
# Install Heroku CLI
# Then:
heroku login
heroku create nebula-shield-backend

# Set environment variables
heroku config:set JWT_SECRET=your_secret_here
heroku config:set NODE_ENV=production
# ... add all other env vars

# Deploy
git subtree push --prefix backend heroku main
```

---

## After Deployment: Update Frontend

### For Mobile App

1. **Update API URL** in `mobile/src/services/AuthService.ts`:
```typescript
const API_URL = 'https://your-deployed-backend.com/api';
```

2. **Update all API services** to use the new URL

3. **Rebuild and redeploy mobile app**

### For Desktop App (if using cloud backend)

1. **Update environment variable:**
   - Set `CLOUD_BACKEND=true`
   - Set `API_URL=https://your-deployed-backend.com`

2. **Update `src/contexts/AuthContext.js`:**
```javascript
const API_BASE = process.env.CLOUD_BACKEND 
  ? process.env.API_URL 
  : (isElectron ? 'http://localhost:8080' : '');
```

---

## Security Considerations

### 1. Secure Your Backend

Add rate limiting (already in place):
```javascript
// backend/auth-server.js
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});

app.use('/api/', limiter);
```

### 2. Use HTTPS

- Railway and Render provide automatic SSL
- For EC2, use Let's Encrypt with certbot
- Update all API URLs to use `https://`

### 3. Secure Environment Variables

- Never commit `.env` files
- Use platform's secret management (Railway/Render/AWS Secrets Manager)
- Rotate secrets regularly

### 4. CORS Configuration

Update `backend/auth-server.js`:
```javascript
const cors = require('cors');

app.use(cors({
  origin: [
    'https://your-mobile-app-domain.com',
    'capacitor://localhost',
    'http://localhost:3000' // for development
  ],
  credentials: true
}));
```

---

## Testing Your Deployment

### 1. Test Health Endpoint

```bash
curl https://your-backend.com/api/health
```

Expected response:
```json
{
  "status": "healthy",
  "service": "Nebula Shield Auth Server",
  "timestamp": "2026-02-18T..."
}
```

### 2. Test Authentication

```bash
curl -X POST https://your-backend.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.com","password":"admin"}'
```

### 3. Test from Mobile App

- Update mobile app with new API URL
- Try logging in
- Check all features work

---

## Monitoring & Maintenance

### Railway
- Check logs in dashboard
- Set up alerts for downtime
- Monitor usage (free tier limits)

### AWS EC2
```bash
# View logs
pm2 logs

# Monitor processes
pm2 monit

# Restart if needed
pm2 restart all
```

### Database Backups
```bash
# For SQLite database
cd backend
cp auth.db auth.db.backup-$(date +%Y%m%d)

# Automated backup script
0 2 * * * /backup-script.sh  # daily at 2am
```

---

## Cost Estimates

| Platform | Free Tier | Paid Plans |
|----------|-----------|------------|
| Railway.app | $5 credit/month | $5-20/month |
| Render.com | 750 hours/month | $7-25/month |
| AWS EC2 | 750 hours/month (1 year) | $5-50/month |
| Heroku | Discontinued free tier | $7-25/month |

---

## Troubleshooting

### Mobile App Can't Connect
- Check API URL is correct (no trailing slash)
- Verify backend is running: `curl https://your-backend.com/api/health`
- Check CORS settings allow your mobile app domain

### Database Errors
- Ensure SQLite is compatible with your hosting platform
- Consider migrating to PostgreSQL for production (Railway/Render offer free PostgreSQL)

### Environment Variables Not Loading
- Check they're set in the hosting platform dashboard
- Restart the service after adding new variables
- Verify with: `console.log(process.env.JWT_SECRET)`

---

## Alternative: Hybrid Approach

**Best of both worlds:**
- Desktop app runs locally with local backend (for antivirus features)
- Deploy separate API backend to cloud (for authentication, payments, mobile)
- Mobile app connects to cloud backend
- Desktop app can optionally sync with cloud for premium features

This requires:
1. Separating auth/payment APIs from antivirus logic
2. Deploying only the auth server to cloud
3. Keeping scanner/protection services local

---

## Next Steps

1. ✅ Choose a hosting platform
2. ✅ Set up account and create project
3. ✅ Configure environment variables
4. ✅ Deploy backend
5. ✅ Update mobile app API URLs
6. ✅ Test all functionality
7. ✅ Set up monitoring and backups
8. ✅ Configure custom domain (optional)
9. ✅ Set up CI/CD for automatic deployments

**Need help with any step? Let me know which platform you'd like to use!**
