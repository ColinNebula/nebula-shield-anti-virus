# Development Mode Authentication

## Issue
The C++ backend only implements antivirus functionality and does NOT have authentication endpoints:
- ❌ `/api/auth/login`
- ❌ `/api/auth/register`
- ❌ `/api/auth/verify`
- ❌ `/api/subscription`

## Solution
Added **Development Mode Fallback** in `AuthContext.js` that:
- ✅ Detects when auth endpoints return 404
- ✅ Creates mock tokens and users automatically
- ✅ Allows you to develop and test the UI without a full auth system
- ✅ Shows warning in console: "⚠️ Using mock authentication"

## How It Works

### Login
- Any email/password combination will work
- Creates a mock token: `dev-token-{timestamp}`
- Creates a mock user with admin/premium access
- Shows "Logged in (Development Mode)" message

### Register
- Any email/password will create an account
- No validation or database storage
- Immediate login after registration

### Token Verification
- Mock tokens (starting with `dev-token-`) are automatically recognized
- Keeps you logged in across page refreshes

## Available Backend Endpoints
The C++ backend DOES have these endpoints:
- ✅ `/api/status` - Get antivirus status
- ✅ `/api/scan/file` - Scan a file
- ✅ `/api/scan/directory` - Scan a directory
- ✅ `/api/scan/quick` - Quick scan
- ✅ `/api/scan/full` - Full system scan
- ✅ `/api/scan/results` - Get scan results
- ✅ `/api/protection/start` - Start real-time protection
- ✅ `/api/protection/stop` - Stop real-time protection
- ✅ `/api/quarantine` - List quarantined files
- ✅ `/api/quarantine/restore` - Restore from quarantine
- ✅ `/api/signatures/update` - Update virus signatures
- ✅ `/api/config` - Get/set configuration

## For Production
To implement real authentication, you would need to:
1. Add auth endpoints to the C++ backend (`/api/auth/*`)
2. Implement user database (SQLite already available)
3. Add JWT token generation/verification
4. Add password hashing (bcrypt or similar)
5. Remove the development mode fallback from AuthContext

## Current Status
✅ **Works for development** - You can test all UI features
⚠️ **Not secure** - Anyone can log in with any credentials
🔧 **Auth backend needed** - For production deployment

---
Created by Colin Nebula for Nebula3ddev.com
