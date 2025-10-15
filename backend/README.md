# Nebula Shield Anti-Virus Backend

A high-performance C++ backend for the Nebula Shield Anti-Virus application, providing comprehensive malware detection, real-time protection, and HTTP API services for the React frontend.

## Features

### Core Engine
- **File Scanning**: Deep analysis of files with signature-based and heuristic detection
- **Threat Detection**: Multi-layered approach including virus signatures, behavioral analysis, and entropy checking
- **Real-time Protection**: Background monitoring of file system changes
- **Quarantine System**: Safe isolation of detected threats

### HTTP API
- **RESTful API**: Full REST API for communication with React frontend
- **CORS Support**: Configurable cross-origin resource sharing
- **Real-time Updates**: WebSocket-like functionality for live scan progress

### Database Integration
- **SQLite Database**: Persistent storage for scan results, signatures, and configuration
- **Performance Optimized**: Efficient queries with proper indexing
- **Data Management**: Automatic cleanup of old records

### Configuration & Logging
- **Flexible Configuration**: JSON-based configuration with runtime updates
- **Comprehensive Logging**: Multi-level logging with file rotation
- **System Integration**: Platform-specific optimizations for Windows and Linux

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   React Frontend │    │   HTTP Server   │    │ Scanner Engine  │
│                 │◄──►│   (Port 8080)   │◄──►│                 │
│   (Port 3000)   │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │ Database Manager│    │ Threat Detector │
                       │   (SQLite)      │    │                 │
                       └─────────────────┘    └─────────────────┘
                                                       │
                                                       ▼
                                              ┌─────────────────┐
                                              │  File Monitor   │
                                              │ (Real-time)     │
                                              └─────────────────┘
```

## Prerequisites

### Windows
- **Visual Studio 2019/2022** with C++ support
- **CMake 3.16+**
- **vcpkg** (recommended for dependency management)

### Linux
- **GCC 8+** or **Clang 10+**
- **CMake 3.16+**
- **pkg-config**

### Dependencies
- **SQLite3** (auto-detected or embedded)
- **OpenSSL** (for cryptographic functions)
- **Threads** (C++11 threading support)

## Building

### Windows
```batch
# Using the provided script
cd backend
scripts\build_windows.bat

# Or manually
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

### Linux
```bash
# Using the provided script
cd backend
chmod +x scripts/build_linux.sh
./scripts/build_linux.sh

# Or manually
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

### Dependencies with vcpkg (Windows)
```batch
# Install vcpkg
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat

# Install dependencies
.\vcpkg install sqlite3:x64-windows
.\vcpkg install openssl:x64-windows

# Set environment variable
set VCPKG_ROOT=C:\path\to\vcpkg
```

## Configuration

Configuration is managed through `data/config.json`:

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
    "timeout_seconds": 30,
    "threat_threshold": 0.6
  },
  "protection": {
    "real_time_enabled": false,
    "auto_quarantine": true
  }
}
```

### Key Configuration Options

| Setting | Description | Default |
|---------|-------------|---------|
| `server.port` | HTTP server port | 8080 |
| `scanner.max_file_size` | Maximum file size to scan (bytes) | 100MB |
| `scanner.threat_threshold` | Threat confidence threshold | 0.6 |
| `protection.real_time_enabled` | Enable real-time protection | false |
| `database.path` | SQLite database location | data/nebula_shield.db |

## Running

### Development Mode
```bash
# Start the backend server
cd build/bin
./nebula_shield_backend

# Or on Windows
nebula_shield_backend.exe
```

### Production Mode
```bash
# Create systemd service (Linux)
sudo cp nebula_shield_backend /usr/local/bin/
sudo systemctl enable nebula-shield
sudo systemctl start nebula-shield

# Or Windows Service
sc create "Nebula Shield" binPath="C:\path\to\nebula_shield_backend.exe"
sc start "Nebula Shield"
```

## API Endpoints

### Scanning Operations
```http
POST /api/scan/file
Content-Type: application/json
{
  "file_path": "/path/to/file"
}

POST /api/scan/directory
Content-Type: application/json
{
  "directory_path": "/path/to/directory",
  "recursive": true
}

GET /api/scan/results
```

### System Status
```http
GET /api/status
Response:
{
  "server_running": true,
  "scanner_initialized": true,
  "total_scanned_files": 1247,
  "total_threats_found": 3,
  "real_time_protection": false
}
```

### Protection Control
```http
POST /api/protection/start
POST /api/protection/stop
```

### Quarantine Management
```http
GET /api/quarantine
POST /api/quarantine/restore
{
  "file_path": "/path/to/file"
}
```

### Configuration
```http
GET /api/config
POST /api/config
{
  "real_time_protection": true,
  "auto_quarantine": true
}
```

## Database Schema

### scan_results
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PRIMARY KEY | Unique scan result ID |
| file_path | TEXT | Scanned file path |
| threat_type | TEXT | Type of threat detected |
| threat_name | TEXT | Name of specific threat |
| confidence | REAL | Detection confidence (0.0-1.0) |
| hash | TEXT | File hash (SHA-256) |
| file_size | INTEGER | File size in bytes |
| scan_time | TEXT | Timestamp of scan |
| quarantined | INTEGER | Whether file was quarantined |

### signatures
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PRIMARY KEY | Unique signature ID |
| name | TEXT UNIQUE | Signature name |
| pattern | BLOB | Binary pattern data |
| type | TEXT | Threat type |
| severity | REAL | Severity score |
| description | TEXT | Human-readable description |

## Logging

Logs are written to `logs/nebula_shield.log` with configurable levels:

- **DEBUG**: Detailed diagnostic information
- **INFO**: General operational messages
- **WARNING**: Warning conditions
- **ERROR**: Error conditions
- **CRITICAL**: Critical error conditions

### Log Format
```
[2024-01-01 12:00:00] [INFO] HTTP Server started on port 8080
[2024-01-01 12:00:01] [WARN] Real-time protection disabled
[2024-01-01 12:00:02] [ERROR] Failed to load signature: malware.sig
```

## Performance Tuning

### Memory Usage
- Adjust `scanner.max_file_size` to limit memory usage
- Configure database cleanup intervals
- Set appropriate log rotation limits

### CPU Usage
- Use threading for parallel scans
- Adjust heuristic analysis sensitivity
- Configure real-time monitoring frequency

### I/O Optimization
- Use SSD storage for database
- Configure appropriate file buffer sizes
- Optimize signature database layout

## Security Considerations

### File Access
- Run with minimal required privileges
- Implement proper file path validation
- Use secure temporary directories

### Network Security
- Configure CORS appropriately
- Use HTTPS in production (reverse proxy)
- Implement rate limiting

### Data Protection
- Encrypt sensitive configuration data
- Secure database file permissions
- Implement secure logging practices

## Troubleshooting

### Common Issues

**Build Errors**
```bash
# Missing dependencies
sudo apt-get install build-essential cmake libsqlite3-dev libssl-dev

# Windows: Install Visual Studio C++ tools
# Install vcpkg and required packages
```

**Runtime Errors**
```bash
# Check configuration file
cat data/config.json

# Verify database permissions
ls -la data/nebula_shield.db

# Check log files
tail -f logs/nebula_shield.log
```

**API Connection Issues**
```bash
# Test server connectivity
curl http://localhost:8080/api/status

# Check CORS configuration
# Verify allowed_origins setting
```

### Performance Issues
- Monitor CPU and memory usage
- Check database performance
- Review scan timeouts
- Optimize signature database

## Development

### Adding New Features

1. **New Threat Detection**
```cpp
// Implement in threat_detector.cpp
bool ThreatDetector::detectNewThreatType(const std::vector<uint8_t>& data) {
    // Your detection logic here
    return false;
}
```

2. **New API Endpoints**
```cpp
// Add to http_server.cpp
ApiResponse HttpServer::handleNewEndpoint(const std::string& request_body) {
    // Your endpoint logic here
    return ApiResponse(200, "application/json", jsonSuccess());
}
```

3. **New Configuration Options**
```cpp
// Add to config_manager.cpp
void ConfigManager::loadDefaults() {
    // Add new default values
    setString("new_feature.enabled", "false");
}
```

### Testing

```bash
# Unit tests (if implemented)
cd build
ctest

# Manual API testing
curl -X POST http://localhost:8080/api/scan/file \
  -H "Content-Type: application/json" \
  -d '{"file_path": "/path/to/test/file"}'
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add tests if applicable
5. Update documentation
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Check the troubleshooting section
- Review log files for errors
- Submit issues on the project repository
- Contact the development team

## Roadmap

### Version 1.1
- Machine learning-based detection
- Cloud signature updates
- Enhanced real-time protection
- Performance optimizations

### Version 1.2
- Distributed scanning
- Advanced heuristics
- Network traffic analysis
- Mobile device support