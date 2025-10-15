# Installation and Setup Guide for Nebula Shield Anti-Virus Backend

This guide will walk you through setting up the C++ backend for your Nebula Shield Anti-Virus application.

## Prerequisites Installation

### Windows Setup

1. **Install Visual Studio 2022**
   - Download from: https://visualstudio.microsoft.com/vs/
   - Select "Desktop development with C++" workload
   - Include: MSVC compiler, Windows SDK, CMake tools

2. **Install CMake**
   - Download from: https://cmake.org/download/
   - Add to PATH during installation
   - Verify: `cmake --version`

3. **Install vcpkg (Recommended)**
   ```batch
   # Clone vcpkg
   git clone https://github.com/Microsoft/vcpkg.git C:\vcpkg
   cd C:\vcpkg
   .\bootstrap-vcpkg.bat
   
   # Install dependencies
   .\vcpkg install sqlite3:x64-windows
   .\vcpkg install openssl:x64-windows
   
   # Set environment variable
   setx VCPKG_ROOT "C:\vcpkg"
   ```

### Linux Setup (Ubuntu/Debian)

```bash
# Update package list
sudo apt update

# Install build tools
sudo apt install build-essential cmake git

# Install dependencies
sudo apt install libsqlite3-dev libssl-dev pkg-config

# Install additional tools
sudo apt install curl wget unzip
```

### Linux Setup (CentOS/RHEL/Fedora)

```bash
# For CentOS/RHEL
sudo yum groupinstall "Development Tools"
sudo yum install cmake git sqlite-devel openssl-devel

# For Fedora
sudo dnf groupinstall "Development Tools"
sudo dnf install cmake git sqlite-devel openssl-devel
```

## Building the Backend

### Step 1: Navigate to Backend Directory
```bash
cd /path/to/nebula-shield-anti-virus/backend
```

### Step 2: Build on Windows
```batch
# Using the provided script (recommended)
scripts\build_windows.bat

# Manual build
mkdir build
cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

### Step 3: Build on Linux
```bash
# Using the provided script (recommended)
chmod +x scripts/build_linux.sh
./scripts/build_linux.sh

# Manual build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

## Configuration

### Step 1: Create Data Directories
```bash
# Create required directories
mkdir -p data logs quarantine

# On Windows
mkdir data logs quarantine
```

### Step 2: Configure the Application
Edit `data/config.json` to match your environment:

```json
{
  "server": {
    "host": "localhost",
    "port": 8080,
    "cors_enabled": true,
    "allowed_origins": "http://localhost:3000"
  },
  "scanner": {
    "max_file_size": 104857600,
    "timeout_seconds": 30
  },
  "database": {
    "path": "data/nebula_shield.db"
  },
  "logging": {
    "level": "INFO",
    "file": "logs/nebula_shield.log"
  }
}
```

## Running the Backend

### Development Mode

```bash
# Linux
cd build/bin
./nebula_shield_backend

# Windows
cd build\bin\Release
nebula_shield_backend.exe
```

### Verify Installation

1. **Check Server Status**
   ```bash
   curl http://localhost:8080/api/status
   ```

2. **Expected Response**
   ```json
   {
     "server_running": true,
     "scanner_initialized": true,
     "total_scanned_files": 0,
     "total_threats_found": 0,
     "real_time_protection": false
   }
   ```

## Integration with React Frontend

### Step 1: Update Frontend Configuration
In your React project, update the API base URL:

```javascript
// src/config/api.js
const API_BASE_URL = 'http://localhost:8080/api';

export const scanFile = async (filePath) => {
  const response = await fetch(`${API_BASE_URL}/scan/file`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ file_path: filePath }),
  });
  return response.json();
};
```

### Step 2: Test Integration
```bash
# Start backend (in one terminal)
cd backend/build/bin
./nebula_shield_backend

# Start frontend (in another terminal)
cd ../  # Go back to project root
npm start
```

## Production Deployment

### Windows Service

1. **Create Service**
   ```batch
   sc create "NebulaShield" binPath="C:\path\to\nebula_shield_backend.exe" start=auto
   sc description "NebulaShield" "Nebula Shield Anti-Virus Backend Service"
   ```

2. **Start Service**
   ```batch
   sc start "NebulaShield"
   ```

### Linux Systemd Service

1. **Create Service File**
   ```bash
   sudo nano /etc/systemd/system/nebula-shield.service
   ```

2. **Add Service Configuration**
   ```ini
   [Unit]
   Description=Nebula Shield Anti-Virus Backend
   After=network.target

   [Service]
   Type=simple
   User=www-data
   WorkingDirectory=/opt/nebula-shield
   ExecStart=/opt/nebula-shield/nebula_shield_backend
   Restart=always
   RestartSec=10

   [Install]
   WantedBy=multi-user.target
   ```

3. **Enable and Start Service**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable nebula-shield
   sudo systemctl start nebula-shield
   ```

## Troubleshooting

### Build Issues

**CMake Configuration Failed**
```bash
# Check CMake version
cmake --version

# Clear build cache
rm -rf build
mkdir build && cd build

# Try with verbose output
cmake .. -DCMAKE_VERBOSE_MAKEFILE=ON
```

**Missing Dependencies (Linux)**
```bash
# Install missing packages
sudo apt install libsqlite3-dev libssl-dev

# For older systems
sudo apt install libssl1.0-dev
```

**Missing Dependencies (Windows)**
```batch
# Install with vcpkg
vcpkg install sqlite3:x64-windows openssl:x64-windows

# Or download manually from official sources
```

### Runtime Issues

**Port Already in Use**
```bash
# Check what's using port 8080
netstat -tulpn | grep 8080  # Linux
netstat -ano | findstr 8080  # Windows

# Change port in config.json
"server": {
  "port": 8081
}
```

**Database Permission Error**
```bash
# Fix permissions (Linux)
chmod 755 data/
chmod 644 data/nebula_shield.db

# Windows: Check folder permissions in Properties
```

**Log File Issues**
```bash
# Create log directory
mkdir -p logs

# Check disk space
df -h  # Linux
dir   # Windows
```

### API Connection Issues

**CORS Errors**
- Verify `allowed_origins` in config.json
- Check browser developer tools for CORS errors
- Ensure React dev server is running on expected port

**Network Connectivity**
```bash
# Test local connection
curl http://localhost:8080/api/status

# Test from another machine
curl http://YOUR_IP:8080/api/status
```

## Performance Optimization

### Memory Usage
```json
{
  "scanner": {
    "max_file_size": 52428800,  // 50MB instead of 100MB
    "timeout_seconds": 15       // Faster timeouts
  }
}
```

### Database Optimization
```bash
# Regular maintenance
sqlite3 data/nebula_shield.db "VACUUM;"
sqlite3 data/nebula_shield.db "REINDEX;"
```

### Log Management
```bash
# Rotate logs manually
mv logs/nebula_shield.log logs/nebula_shield.log.1
touch logs/nebula_shield.log
```

## Security Hardening

### File Permissions
```bash
# Secure configuration
chmod 600 data/config.json

# Secure database
chmod 600 data/nebula_shield.db

# Secure logs
chmod 600 logs/nebula_shield.log
```

### Firewall Configuration
```bash
# Linux (ufw)
sudo ufw allow 8080/tcp

# Windows Firewall
netsh advfirewall firewall add rule name="Nebula Shield" dir=in action=allow protocol=TCP localport=8080
```

## Updates and Maintenance

### Updating Signatures
The backend automatically updates threat signatures. To force an update:
```bash
curl -X POST http://localhost:8080/api/signatures/update
```

### Database Cleanup
```bash
curl -X POST http://localhost:8080/api/admin/cleanup
```

### Backup and Restore
```bash
# Backup database
cp data/nebula_shield.db data/nebula_shield.db.backup

# Backup configuration
cp data/config.json data/config.json.backup

# Restore
cp data/nebula_shield.db.backup data/nebula_shield.db
```

## Next Steps

1. **Test All Features**: Verify file scanning, directory scanning, and API endpoints
2. **Configure Real-time Protection**: Enable if needed for production
3. **Set Up Monitoring**: Monitor logs and performance
4. **Plan Backups**: Regular database and configuration backups
5. **Security Audit**: Review security settings and access controls

## Support

If you encounter issues:

1. Check the logs: `tail -f logs/nebula_shield.log`
2. Verify configuration: `cat data/config.json`
3. Test API manually: `curl http://localhost:8080/api/status`
4. Review this guide for common solutions
5. Submit issues to the project repository

Your Nebula Shield Anti-Virus backend is now ready for use!