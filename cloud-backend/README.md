# Nebula Shield Cloud Backend

Real-time communication hub for Nebula Shield antivirus desktop and mobile apps.

## Features

- ✅ **WebSocket Server** - Real-time bidirectional communication
- ✅ **JWT Authentication** - Secure token-based auth
- ✅ **Device Management** - Register and track multiple devices per user
- ✅ **Push Notifications** - FCM/APNs integration ready
- ✅ **Rate Limiting** - Protect against abuse
- ✅ **CORS Support** - Secure cross-origin requests

## Installation

```bash
cd cloud-backend
npm install
```

## Configuration

1. Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

2. Update environment variables:
```env
PORT=3001
JWT_SECRET=your-super-secret-jwt-key-min-32-chars
MONGODB_URI=mongodb://localhost:27017/nebula-shield
REDIS_URL=redis://localhost:6379
```

## Running the Server

### Development
```bash
npm run dev
```

### Production
```bash
npm start
```

## API Endpoints

### Authentication

#### POST /api/auth/login
Login with email and password.

**Request:**
```json
{
  "email": "admin@test.com",
  "password": "admin"
}
```

**Response:**
```json
{
  "success": true,
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": "1",
    "email": "admin@test.com",
    "fullName": "Test Admin"
  }
}
```

#### POST /api/auth/register
Register new user.

#### POST /api/auth/verify
Verify JWT token validity.

### Device Management

#### POST /api/devices/register
Register a new device.

**Headers:**
```
Authorization: Bearer <token>
```

**Request:**
```json
{
  "deviceId": "desktop-001",
  "deviceType": "desktop",
  "deviceName": "My Desktop",
  "os": "Windows 11",
  "version": "1.0.0"
}
```

#### GET /api/devices
Get all devices for authenticated user.

#### DELETE /api/devices/:deviceId
Unregister a device.

### Notifications

#### POST /api/notifications/register-token
Register FCM/APNs token for push notifications.

#### POST /api/notifications/send
Send push notification to user devices.

## WebSocket Events

### Client → Server

#### authenticate
Authenticate socket connection.

```javascript
socket.emit('authenticate', {
  token: 'your-jwt-token',
  deviceId: 'desktop-001',
  deviceType: 'desktop'
});
```

#### threat:detected
Desktop sends threat detection alert.

```javascript
socket.emit('threat:detected', {
  threatName: 'Trojan.Win32.Agent',
  filePath: 'C:\\suspicious.exe',
  severity: 'high',
  action: 'quarantined'
});
```

#### scan:status
Desktop sends scan progress update.

```javascript
socket.emit('scan:status', {
  status: 'scanning',
  progress: 45,
  filesScanned: 1200,
  threatsFound: 2
});
```

#### command:execute
Mobile sends remote command to desktop.

```javascript
socket.emit('command:execute', {
  targetDeviceId: 'desktop-001',
  command: 'start-scan',
  params: { type: 'full' }
});
```

### Server → Client

#### authenticated
Confirmation of successful authentication.

```javascript
socket.on('authenticated', (data) => {
  console.log('Connected:', data.deviceId);
});
```

#### threat:alert
Threat detection alert from desktop to mobile.

```javascript
socket.on('threat:alert', (data) => {
  // Show push notification
  showNotification(data.threatName, data.filePath);
});
```

#### scan:update
Scan progress update.

```javascript
socket.on('scan:update', (data) => {
  updateProgressBar(data.progress);
});
```

#### command:received
Desktop receives command from mobile.

```javascript
socket.on('command:received', (data) => {
  executeCommand(data.command, data.params);
});
```

#### metrics:data
System metrics from desktop to mobile.

```javascript
socket.on('metrics:data', (data) => {
  updateDashboard(data.cpu, data.memory, data.disk);
});
```

## Architecture

```
┌─────────────────┐         ┌──────────────────┐         ┌─────────────────┐
│  Desktop App    │◄───────►│   Cloud Backend  │◄───────►│   Mobile App    │
│  (Electron)     │  HTTPS  │   (Node.js +     │  HTTPS  │  (React Native) │
│                 │  WS     │    Socket.io)    │  WS     │                 │
└─────────────────┘         └──────────────────┘         └─────────────────┘
                                     │
                                     ▼
                            ┌──────────────────┐
                            │   MongoDB/Redis  │
                            │   (Database)     │
                            └──────────────────┘
```

## Testing

Test the WebSocket connection:

```javascript
const io = require('socket.io-client');

const socket = io('http://localhost:3001');

socket.on('connect', () => {
  console.log('Connected!');
  
  socket.emit('authenticate', {
    token: 'your-token',
    deviceId: 'test-001',
    deviceType: 'desktop'
  });
});

socket.on('authenticated', (data) => {
  console.log('Authenticated:', data);
  
  // Test threat alert
  socket.emit('threat:detected', {
    threatName: 'Test.Virus',
    filePath: '/test/file.exe',
    severity: 'high'
  });
});
```

## Security

- All endpoints protected with JWT authentication
- Rate limiting on API routes (100 requests per 15 minutes)
- CORS configured for allowed origins only
- Helmet.js for security headers
- WebSocket connections require authentication

## Logging

Server uses Morgan for HTTP request logging and Winston for application logging.

## Deployment

### Docker (Recommended)

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3001
CMD ["node", "server.js"]
```

### Deploy to Heroku

```bash
heroku create nebula-shield-cloud
git push heroku main
```

### Deploy to AWS EC2

1. Install Node.js 18+
2. Clone repository
3. Install dependencies: `npm ci --only=production`
4. Set environment variables
5. Use PM2 for process management: `pm2 start server.js`

## License

MIT

---

**Next Step:** Set up React Native mobile app!
