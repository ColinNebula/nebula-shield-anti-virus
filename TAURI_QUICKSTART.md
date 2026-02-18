# Tauri Quick Start - Nebula Shield

## Install Prerequisites

```powershell
# 1. Install Rust
winget install Rustlang.Rustup

# 2. Install Visual Studio Build Tools
winget install Microsoft.VisualStudio.2022.BuildTools

# 3. Install Tauri CLI
npm install
```

## Run in Development

```powershell
npm run tauri:dev
```

## Build for Production

```powershell
npm run tauri:build
```

Output: `src-tauri/target/release/bundle/`

## Using Tauri Commands in React

```javascript
import { invoke } from '@tauri-apps/api/core';

// Scan a file
const result = await invoke('scan_file', { 
  filePath: 'C:\\path\\to\\file.exe' 
});

// Get protection status
const status = await invoke('get_protection_status');
```

## Key Files

- `tauri.conf.json` - App configuration
- `src-tauri/Cargo.toml` - Rust dependencies
- `src-tauri/src/main.rs` - Rust entry point
- `src-tauri/src/commands.rs` - Backend API commands

## Troubleshooting

**Rust not found?**
```powershell
rustup update
```

**Build fails?**
```powershell
cd src-tauri
cargo clean
cargo build
```

**Port conflict?**
Change `devUrl` in `tauri.conf.json`

## Learn More

Read `TAURI_SETUP_GUIDE.md` for complete documentation.
