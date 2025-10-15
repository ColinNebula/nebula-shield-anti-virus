# Authentication & Subscription System

## Overview
Nebula Shield now includes a complete authentication and subscription system with **Free** and **Premium** tiers.

## Features Implemented

### 🔐 Authentication System
- **User Registration**: Email, password, full name
- **Login/Logout**: JWT-based authentication
- **Session Management**: 7-day token expiry
- **Protected Routes**: Dashboard requires authentication
- **Profile Display**: User info in sidebar with tier badge

### 💳 Subscription Tiers

#### Free Tier (Default)
- ✅ Real-time malware protection
- ✅ Manual file scanning
- ✅ Threat history (last 30 days)
- ✅ Basic scan reports
- ❌ Scheduled automatic scans
- ❌ Custom scan paths
- ❌ Advanced PDF reports
- ❌ Priority support

#### Premium Tier ($49/year)
- ✅ Everything in Free
- ✅ Scheduled automatic scans
- ✅ Custom scan paths & folders
- ✅ Advanced PDF reports with charts
- ✅ Unlimited threat history
- ✅ Priority 24/7 support
- ✅ Advanced threat detection
- ✅ Early access to new features

## Technical Stack

### Backend (Auth Server)
- **Port**: 8081
- **Framework**: Express.js
- **Database**: SQLite (`data/auth.db`)
- **Security**: bcryptjs, JWT
- **Validation**: express-validator

### Frontend
- **React Router**: Navigation & protected routes
- **AuthContext**: Global authentication state
- **Axios**: HTTP client for API calls
- **Token Storage**: localStorage

## API Endpoints

### Authentication
- `POST /api/auth/register` - Create new account
- `POST /api/auth/login` - User login
- `GET /api/auth/verify` - Verify JWT token

### Subscription
- `GET /api/subscription` - Get user subscription info
- `POST /api/subscription/upgrade` - Upgrade to Premium
- `POST /api/subscription/check-feature` - Check feature access

## Premium Features List

Use the `feature` identifier with `<PremiumFeature>` component:

- `scheduled-scans` - Automated scanning schedules
- `advanced-reports` - PDF reports with charts
- `custom-scan-paths` - Scan custom directories
- `priority-support` - 24/7 priority support
- `advanced-threats` - Advanced threat detection

## Usage Examples

### Protecting a Feature

```jsx
import PremiumFeature from '../components/PremiumFeature';

<PremiumFeature feature="scheduled-scans">
  <ScheduledScansSettings />
</PremiumFeature>
```

### Custom Fallback

```jsx
<PremiumFeature 
  feature="advanced-reports"
  fallback={<BasicReport />}
>
  <AdvancedPDFReport />
</PremiumFeature>
```

### Check Access in Code

```jsx
const { checkFeatureAccess } = useAuth();

const handleAdvancedScan = async () => {
  const access = await checkFeatureAccess('custom-scan-paths');
  if (!access.hasAccess) {
    toast.error('Premium feature - Upgrade to access');
    return;
  }
  // Proceed with feature
};
```

## Servers Running

1. **C++ Backend** - Port 8080 (antivirus functionality)
2. **Auth Server** - Port 8081 (authentication & subscriptions)
3. **React Frontend** - Port 3000 (user interface)

## Testing the System

### 1. Register a New Account
- Navigate to http://localhost:3000
- You'll be redirected to `/login`
- Click "Create one for free"
- Fill in email, password, full name
- Account created with Free tier

### 2. View Premium Plans
- Click "Upgrade" button in sidebar
- Or navigate to `/premium`
- See feature comparison
- Click "Upgrade to Premium" (instant upgrade for testing)

### 3. Access Premium Features
- Premium features show unlock prompts for Free users
- After upgrading, features become accessible
- Tier badge updates to "Premium" with crown icon

## Database Schema

### users
- id (PRIMARY KEY)
- email (UNIQUE)
- password_hash
- full_name
- created_at
- last_login

### subscriptions
- id (PRIMARY KEY)
- user_id (FOREIGN KEY)
- tier (free/premium)
- status (active/inactive)
- started_at
- expires_at

## Next Steps

To lock existing features behind Premium:

1. Wrap components with `<PremiumFeature>`
2. Add feature checks before API calls
3. Show upgrade prompts in UI
4. Test with both Free and Premium accounts

## Security Notes

⚠️ **Production Checklist**:
- Change `JWT_SECRET` in `.env`
- Use HTTPS for API calls
- Implement rate limiting
- Add email verification
- Set up payment integration (Stripe/PayPal)
- Add password reset flow
- Implement refresh tokens

---

**Status**: ✅ Fully Implemented & Running
**Last Updated**: October 11, 2025
