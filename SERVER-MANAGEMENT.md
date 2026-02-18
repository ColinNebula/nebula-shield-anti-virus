# Server Management Guide

## Quick Start

### Start All Servers

**Windows (Batch):**
```batch
START-SERVERS.bat
```

**PowerShell/Cross-platform:**
```powershell
.\start-servers.ps1
```

**NPM Scripts:**
```bash
npm run dev:all        # Start backend + frontend dev server
npm run start:all      # Same as above
```

### Check Server Health

```bash
npm run check:servers
```

Or directly:
```powershell
powershell -ExecutionPolicy Bypass -File ./check-servers.ps1
```

### Individual Servers

**Backend Only:**
```bash
npm run start:backend       # Production mode
npm run start:backend:dev   # Development mode with auto-reload
```

**Frontend Only:**
```bash
npm run dev      # Development server (port 3002)
npm run preview  # Preview production build (port 3001)
```

## Server Ports

| Service | Port | Health Check |
|---------|------|--------------|
| Backend Server | 8080 | http://localhost:8080/api/health |
| Frontend Dev | 3002 | http://localhost:3002 |
| Frontend Preview | 3001 | http://localhost:3001 |

## Build Commands (with automatic server checks)

All build commands now automatically check if servers are running:

```bash
# Regular builds
npm run build                    # React production build
npm run electron:build:win      # Windows Electron build
npm run electron:build:mac      # macOS Electron build
npm run electron:build:linux    # Linux Electron build

# Distribution builds
npm run dist:win                # Windows installer
npm run dist:mac                # macOS installer
npm run dist:linux              # Linux installer
```

## Server Health Check Details

The health check script (`check-servers.ps1`) verifies:

✅ Backend server is running on port 8080
✅ Backend health endpoint responds correctly
✅ Frontend dev/preview server is running (optional)
✅ Lists all active Node.js processes

### What happens if servers aren't running?

- The check will **warn** you but **won't fail the build**
- You'll see which servers are missing
- Instructions to start them will be displayed
- Build continues (useful for CI/CD)

## Troubleshooting

### Backend won't start (port 8080 in use)

```powershell
# Find what's using port 8080
netstat -ano | Select-String ":8080"

# Stop all node processes
Stop-Process -Name "node" -Force
```

### Frontend won't start (port 3002 in use)

The dev server will automatically try the next available port.

### Health check fails but server is running

1. Make sure you're using the latest `backend/auth-server.js` with the `/api/health` endpoint
2. Restart the backend server
3. Check firewall settings

### Permission denied when stopping processes

Run PowerShell or terminal as Administrator.

## Development Workflow

**Recommended workflow:**

1. **Start servers:**
   ```bash
   npm run dev:all
   ```

2. **Work on code** - servers auto-reload on changes

3. **Before building:**
   ```bash
   npm run check:servers  # Verify everything is running
   npm run build          # Build (includes auto-check)
   ```

4. **Preview build:**
   ```bash
   npm run preview
   ```

## Automated Server Startup

The build commands automatically check servers but won't start them.

To auto-start before builds, use:

```bash
npm run dev:all && npm run build
```

Or for Electron:

```bash
npm run electron:dev  # Auto-starts backend + frontend + Electron
```

## CI/CD Integration

In CI/CD pipelines, the server check will warn but not fail:

```yaml
# Example GitHub Actions
- name: Check Servers
  run: npm run check:servers
  continue-on-error: true

- name: Build
  run: npm run build
```

## Server Monitoring

Monitor server status in real-time:

```powershell
# Watch backend health
while ($true) { 
  curl http://localhost:8080/api/health 
  Start-Sleep -Seconds 5 
}
```

## Files

- `check-servers.ps1` - Server health check script
- `start-servers.ps1` - PowerShell server launcher
- `START-SERVERS.bat` - Batch server launcher
- `backend/auth-server.js` - Main backend server (includes `/api/health`)
- `vite.config.js` - Frontend config with API proxy

## Health Endpoint Response

```json
{
  "status": "healthy",
  "service": "Nebula Shield Auth Server",
  "timestamp": "2025-10-26T17:52:33.123Z",
  "uptime": 123.456,
  "port": 8080
}
```
