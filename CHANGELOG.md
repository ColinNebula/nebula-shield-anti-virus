# Changelog

All notable changes to Nebula Shield Anti-Virus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Linux and macOS support
- Cloud-based signature updates
- Machine learning threat detection
- Browser extension integration
- Email scanning capabilities

---

## [2.0.0] - 2024-12-20

### 🚀 Major Release - Production Ready

This release marks a significant milestone with a fully functional C++ backend, real-time file monitoring, and comprehensive security hardening.

### Added

#### Backend (C++)
- **Real-time File System Monitoring**
  - Windows ReadDirectoryChangesW API integration
  - Monitors `C:\Users\Public\Downloads` and `C:\Windows\Temp`
  - Automatic threat detection on file creation/modification
  - Background file monitoring service

- **HTTP REST API Server**
  - `/api/status` - System and protection status
  - `/api/config` - Configuration management
  - `/api/protection/toggle` - Toggle real-time protection
  - `/api/scan/quick` - Quick system scan
  - `/api/scan/full` - Full system scan
  - `/api/scan/custom` - Custom path scan
  - JSON path escaping for Windows file paths

- **Virus Signature Database**
  - SQLite3 database integration
  - 10+ common threat signatures (EICAR, WannaCry, Emotet, etc.)
  - Hash-based signature matching (MD5, SHA-256)
  - Signature update capability

#### Frontend (React)
- **Dashboard Refresh Button**
  - Manual refresh to force backend status update
  - Toast notification on refresh
  - Fixes stale state issues with browser caching

- **Settings Page Backend Sync**
  - Real-time protection status synced from backend every 30 seconds
  - Loads status from both `/api/config` and `/api/status`
  - Persistent toggle state across page navigation

- **Mobile Responsiveness**
  - 6 responsive breakpoints (480px, 640px, 768px, 1024px, 1200px, 1920px)
  - Hamburger menu for mobile devices
  - Touch-friendly interface elements
  - Optimized layouts for all screen sizes

#### Security
- **Helmet Security Headers**
  - Content Security Policy (CSP)
  - HTTP Strict Transport Security (HSTS)
  - X-Content-Type-Options: nosniff
  - X-XSS-Protection enabled

- **CORS Protection**
  - Whitelist-based origin validation
  - Configurable allowed origins via environment variables
  - Default: `localhost:3000`, `localhost:3001`

- **Rate Limiting**
  - 100 requests per 15 minutes (general API)
  - 20 requests per 5 minutes (scan endpoints)
  - IP-based tracking

- **Input Validation**
  - Path traversal protection (`..` blocked)
  - Path length validation (260 characters max)
  - Dangerous character filtering

- **File Upload Security**
  - MIME type whitelist
  - 100MB file size limit
  - Single file upload enforcement

#### Documentation
- **SECURITY.md** - Comprehensive security policy
- **CONTRIBUTING.md** - Development guidelines and standards
- **CHANGELOG.md** - This file
- **GitHub Actions** - Automated security scanning workflow
- **Dependabot** - Automated dependency updates

### Changed

#### Backend
- Upgraded to C++20 standard
- Improved error handling with detailed logging
- Configuration moved to JSON file (`backend/data/config.json`)
- Database schema optimized for performance

#### Frontend
- **PDF Library Compatibility Fix**
  - Downgraded `jspdf-autotable` from 5.0.2 to 3.8.4
  - Fixed compatibility with jsPDF 3.0.3
  - Side-effect import for autoTable plugin
  - All PDF reports now generate successfully

- **Settings Page**
  - Improved UI/UX with better organization
  - Added real-time protection sync mechanism
  - Better error handling and user feedback

- **Dashboard**
  - Enhanced protection monitor component
  - Real-time status updates every 10 seconds
  - Better loading states and error messages

### Fixed

- **Quick Scan JSON Error**
  - Fixed: "Bad escaped character in JSON" error
  - Added `escapeJsonString()` function for Windows paths
  - Properly escapes backslashes in file paths (e.g., `C:\Users\...`)

- **Real-time Protection Toggle**
  - Fixed: UI showing "disabled" when backend was enabled
  - Added proper state synchronization
  - Settings page now syncs every 30 seconds
  - Dashboard shows actual backend status

- **PDF Report Generation**
  - Fixed: "doc.autoTable is not a function" error
  - Resolved jsPDF version conflict
  - All 3 report types working (Scan, Health, Threat Analysis)

- **File Monitoring**
  - Fixed: File monitor not calling watch function
  - Backend now properly monitors directories
  - Events logged and processed correctly

### Security

- **Fixed 7 Major Vulnerabilities**
  - ✅ Unrestricted CORS (MEDIUM)
  - ✅ Missing input validation (MEDIUM)
  - ✅ Unsafe file uploads (HIGH)
  - ✅ No rate limiting (MEDIUM)
  - ✅ No request size limits (LOW)
  - ✅ Missing security headers (MEDIUM)
  - ✅ API key exposure (HIGH)

- **Security Score Improvement**
  - Before: 6/10
  - After: 9/10
  - Production dependencies: 0 vulnerabilities

---

## [1.5.0] - 2024-10-11

### Added

#### Core Features
- **VirusTotal Integration**
  - SHA-256 file hashing using crypto-js
  - VirusTotal API v3 support
  - Intelligent caching system (1-hour TTL)
  - Reputation scoring (Clean, Potentially Unwanted, Suspicious, Malicious)
  - Mock report generation for demo mode
  - Detection ratio display (e.g., "5/70 vendors")
  - Color-coded reputation badges

- **PDF Report Generation**
  - Three professional report types:
    - Scan Report (detailed threat list)
    - System Health Report (protection status)
    - Threat Analysis Report (trends and statistics)
  - Purple-branded headers with gradients
  - Auto-pagination and professional formatting
  - Color-coded threat levels
  - Security recommendations included

- **Desktop Notifications**
  - Native browser notification API
  - 8 notification types (threats, scans, updates, etc.)
  - Auto-dismiss after 5 seconds
  - Vibration support for critical alerts
  - Permission management

- **Theme System**
  - Dark/Light mode toggle
  - CSS variable-based theming
  - LocalStorage persistence
  - Smooth transitions between themes
  - Professional color schemes

- **Scheduled Scans**
  - Frequency options (Daily, Weekly, Monthly)
  - Time picker (24-hour format)
  - Scan type selection (Quick/Full)
  - Schedule preview
  - Enable/disable toggle

#### UI Enhancements
- **Dynamic Page Headers**
  - Live statistics display
  - Connection status indicator
  - Contextual information
  - Animated updates

- **Enhanced Visual Design**
  - Background images with gradient overlays
  - Hover effects and animations
  - Responsive design improvements
  - Improved card layouts

### Changed
- Upgraded React to 19.0.0
- Improved error handling throughout application
- Enhanced loading states and user feedback
- Better mobile responsiveness

### Fixed
- Settings API endpoint (/api/config) integration
- Notification permission handling
- Theme persistence across sessions
- Various UI bugs and inconsistencies

---

## [1.0.0] - 2024-09-15

### Added

#### Initial Release
- **React Frontend**
  - Dashboard with system status overview
  - File and directory scanner
  - Quarantine management system
  - Settings page with configuration options
  - Sidebar navigation

- **Mock Backend**
  - Node.js/Express API server
  - Simulated scanning functionality
  - Mock threat detection
  - Basic configuration management

- **UI Components**
  - Modern dark theme
  - Framer Motion animations
  - Recharts data visualization
  - Lucide React icons
  - Toast notifications

- **Core Features**
  - File scanning (individual files and directories)
  - Threat detection and quarantine
  - Real-time system status monitoring
  - Scan history tracking
  - Protection toggle

- **Styling**
  - Responsive CSS Grid layouts
  - Flexbox components
  - CSS custom properties
  - Mobile-friendly design

### Technical Stack
- React 18.x
- React Router 6.x
- Framer Motion 11.x
- Recharts 2.x
- Axios for API calls
- jsPDF for PDF generation

---

## Version History Summary

| Version | Date | Highlights |
|---------|------|------------|
| 2.0.0 | 2024-12-20 | Production-ready with C++ backend, security hardening |
| 1.5.0 | 2024-10-11 | VirusTotal integration, PDF reports, themes |
| 1.0.0 | 2024-09-15 | Initial release with React frontend |

---

## Upgrade Guide

### From 1.5.0 to 2.0.0

**Prerequisites:**
1. Install Visual Studio 2019/2022 with C++ desktop development
2. Install CMake 3.16+
3. Install vcpkg package manager

**Backend Setup:**
```powershell
# Install C++ dependencies
cd C:\vcpkg
.\vcpkg install sqlite3:x64-windows
.\vcpkg install openssl:x64-windows

# Build backend
cd backend\build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

**Frontend Setup:**
```powershell
# Update dependencies
npm install

# Update environment variables
Copy-Item .env.example .env
# Edit .env with your configuration
```

**Breaking Changes:**
- Backend now runs on port 8080 (was 3001 in mock backend)
- Real-time protection requires Windows 10/11
- File monitoring limited to configured directories

### From 1.0.0 to 1.5.0

**Dependencies:**
```powershell
npm install
```

**New Environment Variables:**
```bash
REACT_APP_VIRUSTOTAL_API_KEY=your_api_key_here
```

**Breaking Changes:**
- Settings page restructured with tabs
- Theme system requires browser LocalStorage support

---

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## Security

For security vulnerabilities, please see [SECURITY.md](SECURITY.md) for our responsible disclosure policy.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Maintained by**: Nebula Shield Development Team  
**Repository**: https://github.com/owner/nebula-shield-anti-virus  
**Documentation**: https://github.com/owner/nebula-shield-anti-virus/wiki
