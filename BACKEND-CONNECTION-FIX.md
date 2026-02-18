# Backend Connection Error - Solution Guide

## Problem
`GET http://localhost:8080/api/status net::ERR_CONNECTION_REFUSED`

The packaged app can't connect to the backend because backend dependencies weren't installed.

## Solutions

### ✅ Option 1: Production Build (Recommended for Distribution)
**Includes all dependencies - works on any PC without Node.js**

```bash
npm run electron:build:win:production
```

**Pros:**
- ✅ Works on any Windows PC (no Node.js required)
- ✅ No first-run setup delay
- ✅ Ready to distribute

**Cons:**
- ❌ Larger file size (~200-250MB vs ~120MB)
- ❌ Slower build time (~3-5 minutes vs ~1 minute)

### ⚡ Option 2: Lightweight Build (For Development/Testing)
**Smaller package, requires Node.js on target system**

```bash
npm run electron:build:win:portable
```

**Pros:**
- ✅ Much faster build (~1-2 minutes)
- ✅ Smaller file size (~120MB)

**Cons:**
- ❌ Requires Node.js + npm on user's system
- ❌ 30-60 second first-run setup (installs dependencies)
- ❌ Requires internet connection on first run

**First Run Experience:**
1. App shows "Setting Up Nebula Shield" screen
2. Installs backend dependencies (30-60 seconds)
3. Starts backend server
4. Loads main app

**Requirements:**
- Node.js must be installed on target PC
- npm must be in PATH
- Internet connection (first run only)

## Quick Start for Testing

If you just built with `npm run electron:build:win:portable`:

**On a PC WITH Node.js:**
1. Run the portable .exe
2. Wait for first-run setup (30-60s)
3. App works normally

**On a PC WITHOUT Node.js:**
- Use production build instead: `npm run electron:build:win:production`

## Current Build Status

The portable build you just created (`npm run electron:build:win:portable`) is **optimized for speed and size**, but requires Node.js.

For **distribution to end users**, use:
```bash
npm run electron:build:win:production
```

This creates a fully standalone package with everything bundled.

## Summary

| Build Type | Command | Size | Build Time | Node.js Required |
|-----------|---------|------|------------|------------------|
| **Production** | `electron:build:win:production` | ~220MB | ~3-5 min | ❌ No |
| **Portable** | `electron:build:win:portable` | ~120MB | ~1-2 min | ✅ Yes |
| **Dev Test** | `pack` | N/A | ~30s | ✅ Yes (unpacked) |
