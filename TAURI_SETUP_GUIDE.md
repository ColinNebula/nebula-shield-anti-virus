# 🚀 Tauri Setup for Nebula Shield Anti-Virus

## Overview

This guide covers the complete Tauri setup for Nebula Shield, transitioning from Electron to a more secure, lightweight, and performant desktop application framework.

## Why Tauri?

### Benefits Over Electron
- **93% Smaller Bundle Size**: ~10-15 MB vs ~120-200 MB
- **70% Less Memory Usage**: Uses system WebView instead of bundling Chromium
- **Better Security**: Written in Rust (memory-safe language)
- **Native Performance**: Direct OS API access without overhead
- **Perfect for Antivirus**: Low-level system access, better for security operations

## Prerequisites

### Required Software
1. **Rust** (latest stable)
   ```powershell
   # Install Rust via rustup
   winget install Rustlang.Rustup
   # Or download from: https://rustup.rs/
   ```

2. **Visual Studio Build Tools**
   ```powershell
   # Install C++ build tools
   winget install Microsoft.VisualStudio.2022.BuildTools
   ```

3. **WebView2 Runtime** (Windows 10/11 has this pre-installed)
   ```powershell
   # Check if installed
   Get-AppxPackage -Name Microsoft.WebView2
   ```

4. **Node.js** (already installed)

## Installation Steps

### 1. Install Tauri CLI

```powershell
# Install Tauri CLI globally
npm install -g @tauri-apps/cli@latest

# Or use it via package.json scripts (recommended)
npm install --save-dev @tauri-apps/cli
```

### 2. Install Rust Dependencies

```powershell
cd src-tauri
cargo build
```

This will download and compile all Rust dependencies specified in `Cargo.toml`.

### 3. Verify Installation

```powershell
# Check Rust installation
rustc --version
cargo --version

# Check Tauri CLI
npm run tauri --version
```

## Project Structure

```
nebula-shield-anti-virus/
├── src/                          # React frontend (unchanged)
├── src-tauri/                    # Tauri backend (Rust)
│   ├── src/
│   │   ├── main.rs              # Entry point, system tray, window management
│   │   ├── commands.rs          # Tauri commands (API for frontend)
│   │   ├── scanner.rs           # File scanning logic
│   │   ├── quarantine.rs        # Quarantine management
│   │   ├── monitoring.rs        # Real-time protection
│   │   └── windows_integration.rs # Windows API integrations
│   ├── Cargo.toml               # Rust dependencies
│   ├── build.rs                 # Build script
│   └── tauri.conf.json         # Tauri configuration
├── tauri.conf.json              # Tauri app configuration
└── package.json                 # NPM scripts updated for Tauri
```

## Configuration Files

### tauri.conf.json
Main configuration file with:
- **App metadata**: Name, version, identifier
- **Build settings**: Dev server, build output
- **Bundle options**: Icons, installers, resources
- **Security**: CSP, IPC permissions, file system access
- **System tray**: Icon, menu items
- **Plugins**: Updater, notifications, dialogs, file system, shell

### Cargo.toml
Rust dependencies including:
- **Tauri core**: Application framework
- **Windows API**: Registry, services, processes, firewall
- **Security**: SHA2, MD5 for file hashing
- **Async runtime**: Tokio for concurrent operations
- **Serialization**: Serde for JSON communication

## Development Workflow

### Running in Development Mode

```powershell
# Start Vite dev server + Tauri app
npm run tauri:dev

# The app will:
# 1. Start Vite dev server on http://localhost:3004
# 2. Compile Rust code
# 3. Launch Tauri window with your React app
# 4. Hot reload on frontend changes
```

### Building for Production

```powershell
# Build optimized production bundle
npm run tauri:build

# Output will be in:
# src-tauri/target/release/bundle/
#   ├── msi/           # Windows Installer
#   └── nsis/          # NSIS Installer
```

### Debug Build (Faster compilation)

```powershell
npm run tauri:build:debug
```

## Frontend Integration

### Calling Rust Commands from React

```javascript
import { invoke } from '@tauri-apps/api/core';

// Scan a file
const result = await invoke('scan_file', { 
  filePath: 'C:\\Users\\Documents\\file.exe' 
});

// Get protection status
const status = await invoke('get_protection_status');

// Start real-time protection
await invoke('start_realtime_protection');

// Quarantine a file
await invoke('quarantine_file', {
  filePath: 'C:\\malware.exe',
  threatName: 'Trojan.Generic'
});
```

### Available Commands

#### Scanner Commands
- `scan_file(filePath: string)` - Scan single file
- `scan_directory(directoryPath: string)` - Scan directory
- `quick_scan()` - Quick system scan
- `full_scan()` - Full system scan
- `get_scan_progress()` - Get scan status
- `cancel_scan()` - Cancel running scan

#### Quarantine Commands
- `quarantine_file(filePath, threatName)` - Move file to quarantine
- `restore_file(quarantineId)` - Restore from quarantine
- `delete_quarantined_file(quarantineId)` - Delete permanently
- `list_quarantined_files()` - List all quarantined files

#### Monitoring Commands
- `start_realtime_protection()` - Enable real-time scanning
- `stop_realtime_protection()` - Disable real-time scanning
- `get_protection_status()` - Get current protection status
- `get_threat_history(days)` - Get threat detection history

#### Windows Integration Commands
- `check_windows_defender_status()` - Check Windows Defender
- `get_firewall_status()` - Get Windows Firewall status
- `scan_registry()` - Scan registry for threats
- `check_startup_programs()` - List startup programs
- `get_running_processes()` - Get running processes

#### System Commands
- `get_system_info()` - Get OS and hardware info
- `check_for_updates()` - Check for app updates
- `get_signature_version()` - Get virus signature version
- `update_signatures()` - Update virus signatures

#### Settings Commands
- `get_settings()` - Load settings
- `update_settings(settings)` - Save settings
- `export_logs(outputPath)` - Export logs

## System Tray Integration

The app runs in the system tray with these menu items:
- **Show Nebula Shield** - Restore window
- **Quick Scan** - Run quick scan
- **Full Scan** - Run full scan
- **Real-Time Protection** - Toggle protection
- **Quit** - Exit application

Click the tray icon to show/hide the window.

## Building Features

### Real-Time File Scanning

Implement in `src-tauri/src/monitoring.rs`:
- File system watcher using Windows API
- Scan files on access/modify
- Automatic quarantine of threats

### Registry Monitoring

Implement in `src-tauri/src/windows_integration.rs`:
- Monitor critical registry keys
- Detect unauthorized changes
- Alert on suspicious modifications

### Process Monitoring

Check running processes for:
- Digital signatures
- Known malware patterns
- Suspicious behavior (high CPU, network)

## Security Features

### Content Security Policy (CSP)
Configured in `tauri.conf.json`:
- Scripts only from self + inline (for React)
- Connects to localhost:8080 (backend API)
- Loads images from self + data URIs

### File System Access
Scoped to specific directories:
- `$APPDATA` - Application data
- `$TEMP` - Temporary files
- User folders (Downloads, Documents, Desktop)

### IPC Security
- All commands require explicit registration
- Type-safe communication via Serde
- No direct DOM access from backend

## Performance Optimization

### Release Build Settings
In `Cargo.toml`:
```toml
[profile.release]
panic = "abort"        # Smaller binary
codegen-units = 1      # Better optimization
lto = true            # Link-time optimization
opt-level = "z"       # Optimize for size
strip = true          # Remove debug symbols
```

### Bundle Size Comparison
- **Electron**: ~150 MB
- **Tauri**: ~12 MB
- **Savings**: 92%

## Migration from Electron

### What Changes
- ✅ React frontend stays the same
- ✅ No changes to UI components
- ✅ Node.js backend can stay (optional)
- ❌ Replace Electron IPC with Tauri invoke
- ❌ Move system operations to Rust commands

### Migration Strategy
1. **Phase 1**: Run both (Electron + Tauri)
2. **Phase 2**: Move features to Tauri gradually
3. **Phase 3**: Remove Electron dependencies
4. **Phase 4**: Optimize Rust implementations

### Updated API Calls

**Before (Electron)**:
```javascript
const { ipcRenderer } = require('electron');
const result = await ipcRenderer.invoke('scan-file', filePath);
```

**After (Tauri)**:
```javascript
import { invoke } from '@tauri-apps/api/core';
const result = await invoke('scan_file', { filePath });
```

## Troubleshooting

### Rust Compilation Errors
```powershell
# Update Rust
rustup update

# Clean build cache
cd src-tauri
cargo clean
cargo build
```

### WebView2 Missing
```powershell
# Install WebView2 Runtime
winget install Microsoft.EdgeWebView2Runtime
```

### Build Takes Too Long
```powershell
# Use debug build during development
npm run tauri:build:debug

# Enable incremental compilation (default)
$env:CARGO_INCREMENTAL = "1"
```

### Port Already in Use
Edit `tauri.conf.json`:
```json
{
  "build": {
    "devUrl": "http://localhost:3004"  // Change port
  }
}
```

## Next Steps

### Implement Core Features
1. **File Scanner**: Add virus signature matching in `scanner.rs`
2. **Quarantine**: Encrypt quarantined files in `quarantine.rs`
3. **Real-Time Protection**: File system watcher in `monitoring.rs`
4. **Windows Integration**: Registry/firewall APIs in `windows_integration.rs`

### Add Dependencies
```toml
# In Cargo.toml, add as needed:
notify = "6.0"           # File system watcher
aes = "0.8"             # File encryption
clamav = "0.10"         # ClamAV integration
windows-service = "0.6" # Windows service support
```

### Testing
```powershell
# Run Rust tests
cd src-tauri
cargo test

# Run with logging
$env:RUST_LOG = "debug"
npm run tauri:dev
```

## Resources

- **Tauri Docs**: https://tauri.app/
- **Rust Book**: https://doc.rust-lang.org/book/
- **Windows API**: https://docs.rs/windows/latest/windows/
- **Tauri Examples**: https://github.com/tauri-apps/tauri/tree/dev/examples

## Support

For Tauri-specific issues:
- GitHub: https://github.com/tauri-apps/tauri/issues
- Discord: https://discord.gg/tauri

---

**Ready to build!** 🚀

Run `npm run tauri:dev` to start developing with Tauri!
