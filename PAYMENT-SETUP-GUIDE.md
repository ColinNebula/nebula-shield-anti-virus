# 💳 Payment System Setup Guide

## Overview

Nebula Shield now includes a comprehensive payment system with:
- ✅ Stripe integration (Credit/Debit cards)
- ✅ PayPal integration
- ✅ Automated email confirmations
- ✅ Transaction tracking
- ✅ Secure payment processing

---

## 🚀 Quick Start

### 1. Install Dependencies (Already Done)
```bash
cd backend
npm install stripe @paypal/checkout-server-sdk nodemailer
```

### 2. Configure Environment Variables

Copy the `.env.example` file to `.env`:
```bash
cd Z:\Directory\projects\nebula-shield-anti-virus\backend
cp .env.example .env
```

Edit the `.env` file with your credentials:

---

## 🔐 Stripe Setup

### Get Stripe Keys:
1. Go to https://dashboard.stripe.com/
2. Create an account (or login)
3. Get your keys from https://dashboard.stripe.com/apikeys

### Add to `.env`:
```env
STRIPE_SECRET_KEY=sk_test_YOUR_SECRET_KEY_HERE
STRIPE_PUBLISHABLE_KEY=pk_test_YOUR_PUBLISHABLE_KEY_HERE
```

### Testing:
- Use test mode keys (start with `sk_test_` and `pk_test_`)
- Test card: `4242 4242 4242 4242`
- Expiry: Any future date
- CVC: Any 3 digits

---

## 💰 PayPal Setup

### Get PayPal Credentials:
1. Go to https://developer.paypal.com/
2. Create a developer account
3. Go to Dashboard -> My Apps & Credentials
4. Create a new app in Sandbox
5. Copy Client ID and Secret

### Add to `.env`:
```env
PAYPAL_CLIENT_ID=YOUR_CLIENT_ID_HERE
PAYPAL_CLIENT_SECRET=YOUR_SECRET_HERE
PAYPAL_MODE=sandbox
```

### Testing:
- Use `PAYPAL_MODE=sandbox` for testing
- Test account: Create sandbox accounts in PayPal Developer Dashboard
- For production: Change to `PAYPAL_MODE=live`

---

## 📧 Email Configuration

### Gmail Setup (Recommended for testing):

1. Enable 2-Factor Authentication on your Gmail account
2. Generate an App Password:
   - Go to https://myaccount.google.com/apppasswords
   - Select "Mail" and your device
   - Copy the 16-character password

3. Add to `.env`:
```env
EMAIL_SERVICE=gmail
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-16-char-app-password
EMAIL_FROM=Nebula Shield <noreply@nebulashield.com>
```

### Alternative Email Services:

**Outlook/Hotmail:**
```env
EMAIL_SERVICE=hotmail
EMAIL_USER=your-email@outlook.com
EMAIL_PASSWORD=your-password
```

**Custom SMTP:**
```env
EMAIL_HOST=smtp.yourdomain.com
EMAIL_PORT=587
EMAIL_USER=your-email@yourdomain.com
EMAIL_PASSWORD=your-password
```

---

## 🏗️ Complete `.env` File Example

```env
# Authentication
JWT_SECRET=your-super-secret-jwt-key-here
AUTH_PORT=8081

# Stripe
STRIPE_SECRET_KEY=sk_test_51QHjREP4xDJQw2lwrqYZ8KJF9hGn5XqrVFLx0n8
STRIPE_PUBLISHABLE_KEY=pk_test_51QHjREP4xDJQw2lwrqYZ8KJF9hGn5XqrVFLx0n8
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret_here

# PayPal
PAYPAL_CLIENT_ID=AZabc123xyz789EXAMPLE
PAYPAL_CLIENT_SECRET=EMdef456uvw012EXAMPLE
PAYPAL_MODE=sandbox

# Email
EMAIL_SERVICE=gmail
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=abcd efgh ijkl mnop
EMAIL_FROM=Nebula Shield <noreply@nebulashield.com>

# App Settings
APP_URL=http://localhost:3000
PREMIUM_PRICE_USD=49.00
```

---

## 🧪 Testing the System

### 1. Start the Services:
```powershell
# Start auth server
cd Z:\Directory\projects\nebula-shield-anti-virus\backend
node auth-server.js

# Or restart the Windows service
cd "C:\Program Files\Nebula Shield"
.\nssm.exe restart NebulaShieldAuth
```

### 2. Test Payment Flow:

1. Login to Nebula Shield
2. Go to Premium page
3. Click "Pay with Card (Stripe)" or "Pay with PayPal"
4. Complete test payment
5. Verify:
   - Redirected to success page
   - Account upgraded to Premium
   - Email received with purchase details

### 3. Test Cards (Stripe):

| Card Number         | Description          |
|---------------------|----------------------|
| 4242 4242 4242 4242 | Success (Visa)       |
| 4000 0025 0000 3155 | 3D Secure Required   |
| 4000 0000 0000 9995 | Declined (Insufficient funds) |

---

## 📊 Database Structure

### Transactions Table (Auto-created):
```sql
CREATE TABLE transactions (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL,
  order_id TEXT NOT NULL UNIQUE,
  payment_method TEXT NOT NULL,
  amount REAL NOT NULL,
  currency TEXT DEFAULT 'USD',
  status TEXT NOT NULL DEFAULT 'pending',
  transaction_id TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  completed_at DATETIME
);
```

---

## 🎯 Features Included

### Payment Processing:
- ✅ Stripe Checkout (Cards)
- ✅ PayPal Express Checkout
- ✅ Secure payment verification
- ✅ Transaction logging
- ✅ Error handling

### Email Notifications:
- ✅ Purchase confirmation email
- ✅ Payment details
- ✅ Premium features list
- ✅ Next steps guidance
- ✅ HTML formatted emails

### User Experience:
- ✅ Payment success page
- ✅ Payment cancelled page
- ✅ Real-time payment status
- ✅ Automatic account upgrade
- ✅ Demo mode (quick upgrade for testing)

---

## 🛡️ Security Features

- ✅ Environment variables for sensitive data
- ✅ Secure payment gateway connections
- ✅ JWT token authentication
- ✅ SQL injection protection
- ✅ Transaction logging
- ✅ Webhook signature verification

---

## 🔄 Payment Flow

### Stripe Flow:
1. User clicks "Pay with Card"
2. Create Stripe Checkout Session
3. Redirect to Stripe hosted page
4. User enters card details
5. Stripe processes payment
6. Redirect to success page
7. Verify payment server-side
8. Upgrade account to Premium
9. Send confirmation email
10. Show success message

### PayPal Flow:
1. User clicks "Pay with PayPal"
2. Create PayPal order
3. Redirect to PayPal login
4. User approves payment
5. Capture payment server-side
6. Upgrade account to Premium
7. Send confirmation email
8. Show success message

---

## 📧 Email Templates

### Purchase Confirmation Email Includes:
- Welcome message
- Order ID and details
- Payment method
- Amount paid
- Expiration date
- Premium features list
- Next steps
- Support information

---

## 🚨 Troubleshooting

### Email Not Sending:
1. Check EMAIL_USER and EMAIL_PASSWORD in `.env`
2. For Gmail, ensure App Password is used (not regular password)
3. Check console logs for error messages
4. Test with: `node -e "require('./config/email').sendEmail('test@example.com', {subject: 'Test', html: '<p>Test</p>'})"`

### Stripe Errors:
1. Verify API keys in `.env`
2. Check Stripe Dashboard for errors
3. Ensure test mode keys for testing
4. Check console for detailed errors

### PayPal Errors:
1. Verify credentials in `.env`
2. Ensure PAYPAL_MODE is set correctly
3. Check PayPal Developer Dashboard
4. Test with sandbox account

---

## 📝 Production Checklist

Before going live:

- [ ] Switch to Stripe live mode keys
- [ ] Switch to PayPal live mode
- [ ] Use production email service
- [ ] Update APP_URL to production domain
- [ ] Set strong JWT_SECRET
- [ ] Enable Stripe webhooks
- [ ] Test full payment flow
- [ ] Test email delivery
- [ ] Set up SSL/HTTPS
- [ ] Configure proper error logging

---

## 🎉 You're All Set!

The payment system is ready to use. Users can now:
1. Click "Upgrade to Premium"
2. Choose payment method
3. Complete secure payment
4. Get instant account upgrade
5. Receive confirmation email

For testing without real payments, use the "Quick Upgrade (Demo)" button.

---

**Need Help?**
- Stripe Docs: https://stripe.com/docs
- PayPal Docs: https://developer.paypal.com/docs
- Nodemailer Docs: https://nodemailer.com/
