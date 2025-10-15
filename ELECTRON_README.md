# Nebula Shield Anti-Virus - Electron Desktop Application

## Overview

Nebula Shield is now a fully-featured Electron desktop application that provides advanced anti-virus protection with a native desktop experience.

## Features

✅ **Native Desktop Application**
- System tray integration for background monitoring
- Native file dialogs for scanning
- Desktop notifications for threats
- Keyboard shortcuts for quick actions
- Runs on Windows, macOS, and Linux

✅ **Advanced Protection**
- Real-time virus scanning
- Firewall protection
- Email protection
- Network monitoring
- Threat quarantine system
- Driver scanner
- Hacker protection

✅ **Performance Optimized**
- Lightweight resource usage
- Fast startup time
- Efficient background monitoring
- Built with modern web technologies

## Installation

### Prerequisites

- Node.js 16.x or higher
- npm 8.x or higher

### Install Dependencies

```bash
npm install
```

## Development

### Start Development Server

Run the application in development mode with hot-reload:

```powershell
# Using PowerShell script
.\start-electron-dev.ps1

# Or using npm
npm run electron:dev
```

This will:
1. Start the React development server on port 3001
2. Wait for the server to be ready
3. Launch the Electron application

### Development Tools

- **DevTools**: Press `Ctrl+Shift+I` (Windows/Linux) or `Cmd+Option+I` (Mac)
- **Reload**: Press `Ctrl+R` (Windows/Linux) or `Cmd+R` (Mac)
- **Force Reload**: Press `Ctrl+Shift+R` (Windows/Linux) or `Cmd+Shift+R` (Mac)

## Building for Production

### Build for Windows

```powershell
# Using PowerShell script
.\build-electron.ps1 -Platform win

# Or using npm
npm run dist:win
```

This creates:
- NSIS installer (`.exe`)
- Portable executable

### Build for macOS

```bash
npm run dist:mac
```

This creates:
- DMG installer
- ZIP archive

### Build for Linux

```bash
npm run dist:linux
```

This creates:
- AppImage
- Debian package (`.deb`)

### Build for All Platforms

```powershell
.\build-electron.ps1 -Platform all
```

## Keyboard Shortcuts

| Action | Windows/Linux | macOS |
|--------|---------------|-------|
| Quick Scan | `Ctrl+Q` | `Cmd+Q` |
| Full Scan | `Ctrl+F` | `Cmd+F` |
| Settings | `Ctrl+,` | `Cmd+,` |
| Exit | `Ctrl+W` | `Cmd+W` |
| DevTools | `Ctrl+Shift+I` | `Cmd+Option+I` |
| Reload | `Ctrl+R` | `Cmd+R` |

## System Tray

The application runs in the system tray when minimized:

- **Left Click**: Show/hide main window
- **Right Click**: Access quick actions menu
  - Quick Scan
  - Protection Status
  - Exit

## File Structure

```
nebula-shield-anti-virus/
├── public/
│   ├── electron.js          # Main Electron process
│   ├── favicon.ico          # Windows icon
│   └── index.html           # HTML template
├── src/                     # React application source
├── build/                   # Production build output
├── dist/                    # Electron distribution packages
├── electron-builder.json    # Electron builder configuration
├── package.json            # Dependencies and scripts
├── start-electron-dev.ps1  # Development launcher
└── build-electron.ps1      # Production builder
```

## Configuration

### Electron Builder

Edit `electron-builder.json` to customize:
- Application ID and name
- Icons and resources
- Installer options
- Platform-specific settings

### Application Settings

The main Electron configuration is in `public/electron.js`:
- Window size and behavior
- Menu items
- System tray setup
- IPC handlers
- Backend server integration

## Backend Integration

The application includes an integrated backend server:

- **Development**: Backend runs separately (port 8080)
- **Production**: Backend is bundled and auto-started

Backend files are packaged in `resources/backend/` directory.

## Security Features

- **Context Isolation**: Enabled for security
- **Node Integration**: Controlled access
- **Web Security**: Enabled in production
- **DevTools**: Disabled in production builds

## IPC Communication

The app uses Inter-Process Communication (IPC) for:

- File/directory selection dialogs
- System notifications
- External URL opening
- App path access

### Available IPC Channels

```javascript
// File selection
ipcRenderer.invoke('select-file')
ipcRenderer.invoke('select-directory')

// Notifications
ipcRenderer.invoke('show-notification', { title, body })

// System
ipcRenderer.invoke('get-app-path')
ipcRenderer.invoke('open-external', url)

// Scan triggers
ipcRenderer.on('trigger-quick-scan', callback)
ipcRenderer.on('trigger-full-scan', callback)
```

## Distribution

### Windows

The built installer is in `dist/`:
- **NSIS Installer**: `Nebula Shield Anti-Virus Setup x.x.x.exe`
- **Portable**: `Nebula Shield Anti-Virus x.x.x.exe`

Features:
- Custom installation directory
- Desktop and Start Menu shortcuts
- Automatic updates support

### macOS

- **DMG**: Drag and drop installer
- **ZIP**: Portable application bundle

### Linux

- **AppImage**: Universal package (no installation needed)
- **DEB**: Debian/Ubuntu package

## Troubleshooting

### App won't start in development

1. Check if port 3001 is available:
   ```powershell
   netstat -ano | findstr :3001
   ```

2. Clear React cache:
   ```bash
   rm -rf node_modules/.cache
   ```

3. Reinstall dependencies:
   ```bash
   npm install
   ```

### Build fails

1. Clear previous builds:
   ```powershell
   Remove-Item -Recurse -Force build, dist
   ```

2. Update electron-builder:
   ```bash
   npm install electron-builder@latest --save-dev
   ```

3. Check Node.js version:
   ```bash
   node --version  # Should be 16.x or higher
   ```

### Backend not starting

Check the backend files are in place:
- Development: `mock-backend.js` in root
- Production: Bundled in `resources/backend/`

## Performance Tips

### Development
- Use `npm run start` for React-only development
- Use `npm run electron:dev` for full app testing

### Production
- Disable source maps: `GENERATE_SOURCEMAP=false`
- Use production build: `npm run build:production`
- Minimize package size by excluding dev dependencies

## Updates

The app is configured for auto-updates:
- Uses electron-builder's publish configuration
- Set `publish` in `electron-builder.json` for your update server

## License

This project is licensed under the terms specified in the LICENSE file.

## Support

For issues and questions:
- GitHub Issues: [Report a bug](https://github.com/nebula-shield/issues)
- Documentation: [Full docs](https://github.com/nebula-shield/docs)

## Version

Current version: **0.1.0**

---

**Built with ❤️ using Electron, React, and Node.js**
