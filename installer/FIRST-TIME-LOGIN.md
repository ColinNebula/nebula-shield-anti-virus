# 🎉 Welcome to Nebula Shield Anti-Virus!

## Installation Complete - First Time Login

**Built with ❤️ by Colin Nebula for Nebula3ddev.com**

---

## 🔐 Your Default Admin Credentials

After installation, a default administrator account has been created for you:

```
Email:    admin@nebulashield.local
Password: NebulaAdmin2025!
```

### Login URL
**http://localhost:3001**

---

## ⚠️ IMPORTANT SECURITY NOTICE

**For your security, please change this password immediately after first login!**

### How to Change Your Password:

1. Login with the default credentials above
2. Go to **Settings** → **Account**
3. Click **Change Password**
4. Enter a new strong password
5. Save changes

---

## 🚀 Getting Started

### 1. Start Nebula Shield

The installer has created desktop and Start Menu shortcuts:

**Option A:** Double-click the **Nebula Shield** icon on your desktop

**Option B:** Start Menu → Nebula Shield → Nebula Shield

**Option C:** Run the batch file:
```
C:\Program Files\Nebula Shield\Start-Nebula-Shield.bat
```

### 2. What Will Start

Three services will launch in separate terminal windows:

- **Auth Server** (Port 8082) - User authentication
- **Backend Server** (Port 8080) - Core security engine
- **Frontend** (Port 3001) - Web interface

Your browser will automatically open to: **http://localhost:3001**

### 3. Login

Use the default credentials:
- Email: `admin@nebulashield.local`
- Password: `NebulaAdmin2025!`

### 4. Change Password

**IMMEDIATELY** change your password:
1. Click your profile in the sidebar
2. Go to Settings → Account
3. Change password
4. Logout and login with new password

---

## 🛡️ What's Included

Your installation includes:

✅ **Real-time Protection** - Continuous threat monitoring  
✅ **Virus Scanner** - Quick & custom scans with VirusTotal integration  
✅ **Quarantine System** - AES-256 encrypted threat isolation  
✅ **Network Protection** - Intrusion detection system (IDS)  
✅ **Web Protection** - Malicious website blocking  
✅ **Email Protection** - Attachment scanning  
✅ **Premium Features** - Full admin account with all features unlocked  

---

## ⚙️ Optional Configuration

### VirusTotal API (Recommended)

For enhanced threat detection, configure your VirusTotal API key:

1. Get a free API key from: https://www.virustotal.com/
2. Open: `C:\Program Files\Nebula Shield\.env`
3. Add your key:
   ```
   REACT_APP_VIRUSTOTAL_API_KEY=your_api_key_here
   ```
4. Restart Nebula Shield

---

## 📚 Additional Accounts

### Create More Users

You can create additional user accounts:

1. **From Frontend:** Login → Register new account
2. **From Admin Panel:** Settings → User Management → Add User

### Account Types

- **Free Tier:** Basic protection features
- **Premium Tier:** All advanced features (your default admin is Premium)
- **Admin Role:** Full system control (your default account)
- **User Role:** Standard protection access

---

## 🔧 Troubleshooting

### Can't Access http://localhost:3001

**Solution:** Make sure all 3 services started successfully
- Check terminal windows for errors
- Ensure ports 8080, 8082, and 3001 are not in use

### Forgot Password

**Solution:** Use the password reset script:
1. Open PowerShell as Administrator
2. Navigate to: `C:\Program Files\Nebula Shield\installer`
3. Run: `.\reset-password.ps1`
4. Enter email and new password

### Services Won't Start

**Solution:** Check Node.js installation
```powershell
node --version
npm --version
```

If not installed: https://nodejs.org/ (LTS version)

### Port Already in Use

**Solution:** Kill the conflicting process:
```powershell
netstat -ano | findstr :8080
netstat -ano | findstr :8082
netstat -ano | findstr :3001
taskkill /PID <process_id> /F
```

---

## 📞 Support & Documentation

### Installed Documentation

Check these files in your installation folder:

- `README.md` - Complete user guide
- `installer/README.md` - Installation guide
- `installer/QUICKSTART.md` - Quick reference

### Online Resources

- 🌐 Website: https://nebula3ddev.com
- 📧 Email: support@nebula3ddev.com
- 💬 Issues: GitHub repository

---

## 🎯 Quick Reference

### Default Admin Credentials
```
Email:    admin@nebulashield.local
Password: NebulaAdmin2025!
URL:      http://localhost:3001
```

### Installation Location
```
C:\Program Files\Nebula Shield\
```

### Desktop Shortcuts
- **Nebula Shield** - Launch all services
- **Nebula Shield (Backend Only)** - Backend services only

### Start Menu
- Start Menu → Nebula Shield → Multiple options available

---

## 🔒 Security Best Practices

1. ✅ **Change default password** immediately after first login
2. ✅ **Use strong passwords** (12+ characters, mixed case, numbers, symbols)
3. ✅ **Enable VirusTotal** integration for enhanced protection
4. ✅ **Keep software updated** - Check for updates regularly
5. ✅ **Review quarantine** regularly to ensure no false positives
6. ✅ **Monitor activity** - Check scan history and threat logs

---

## 🎉 You're All Set!

Your Nebula Shield Anti-Virus is ready to protect your system.

### Next Steps:

1. ✅ Login with default credentials
2. ✅ Change your password
3. ✅ Configure VirusTotal API (optional but recommended)
4. ✅ Run your first scan
5. ✅ Explore the features!

---

**Thank you for choosing Nebula Shield!** 🛡️

**Built with ❤️ by Colin Nebula for Nebula3ddev.com**

*Stay Protected. Stay Secure.*

---

*Installation Date: [Auto-generated]*  
*Version: 1.0.0*  
*Platform: Windows 10/11 (64-bit)*  
*License: MIT*
