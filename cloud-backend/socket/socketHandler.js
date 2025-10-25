/**
 * WebSocket Connection Handler
 * Manages real-time communication between devices
 */

const jwt = require('jsonwebtoken');

// Store active connections: userId -> [socket.id, socket.id, ...]
const activeConnections = new Map();

// Store device info: socket.id -> { userId, deviceId, deviceType }
const deviceSockets = new Map();

/**
 * Handle new socket connection
 */
function handleSocketConnection(io, socket) {
  console.log(`🔌 New connection: ${socket.id}`);

  // Authenticate socket connection
  socket.on('authenticate', async (data) => {
    try {
      const { token, deviceId, deviceType } = data;

      // Verify JWT token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const userId = decoded.id;

      // Store device info
      deviceSockets.set(socket.id, {
        userId,
        deviceId,
        deviceType, // 'desktop' or 'mobile'
        connectedAt: new Date()
      });

      // Track user's active connections
      if (!activeConnections.has(userId)) {
        activeConnections.set(userId, []);
      }
      activeConnections.get(userId).push(socket.id);

      // Join user's room for targeted broadcasts
      socket.join(`user:${userId}`);

      console.log(`✅ Authenticated: User ${userId}, Device ${deviceId} (${deviceType})`);

      // Send confirmation
      socket.emit('authenticated', {
        success: true,
        userId,
        deviceId,
        activeDevices: activeConnections.get(userId).length
      });

      // Notify other devices about new connection
      socket.to(`user:${userId}`).emit('device:connected', {
        deviceId,
        deviceType,
        timestamp: new Date()
      });

    } catch (error) {
      console.error('Authentication failed:', error.message);
      socket.emit('authentication:failed', {
        success: false,
        error: 'Invalid token'
      });
      socket.disconnect();
    }
  });

  // Handle threat detection from desktop
  socket.on('threat:detected', (data) => {
    const deviceInfo = deviceSockets.get(socket.id);
    if (!deviceInfo) return;

    const { userId } = deviceInfo;
    console.log(`🚨 Threat detected for user ${userId}:`, data.threatName);

    // Broadcast to all user's mobile devices
    const userSockets = activeConnections.get(userId) || [];
    userSockets.forEach(socketId => {
      const targetDevice = deviceSockets.get(socketId);
      if (targetDevice && targetDevice.deviceType === 'mobile') {
        io.to(socketId).emit('threat:alert', {
          ...data,
          timestamp: new Date(),
          sourceDevice: deviceInfo.deviceId
        });
      }
    });
  });

  // Handle scan status updates from desktop
  socket.on('scan:status', (data) => {
    const deviceInfo = deviceSockets.get(socket.id);
    if (!deviceInfo) return;

    const { userId } = deviceInfo;
    
    // Broadcast to all user's devices
    socket.to(`user:${userId}`).emit('scan:update', {
      ...data,
      deviceId: deviceInfo.deviceId,
      timestamp: new Date()
    });
  });

  // Handle remote commands from mobile
  socket.on('command:execute', (data) => {
    const deviceInfo = deviceSockets.get(socket.id);
    if (!deviceInfo) return;

    const { userId } = deviceInfo;
    const { targetDeviceId, command, params } = data;

    console.log(`📱 Command from mobile: ${command} for device ${targetDeviceId}`);

    // Find target desktop device
    const userSockets = activeConnections.get(userId) || [];
    userSockets.forEach(socketId => {
      const targetDevice = deviceSockets.get(socketId);
      if (targetDevice && 
          targetDevice.deviceId === targetDeviceId && 
          targetDevice.deviceType === 'desktop') {
        io.to(socketId).emit('command:received', {
          command,
          params,
          timestamp: new Date(),
          requestedBy: deviceInfo.deviceId
        });
      }
    });
  });

  // Handle quarantine actions
  socket.on('quarantine:action', (data) => {
    const deviceInfo = deviceSockets.get(socket.id);
    if (!deviceInfo) return;

    const { userId } = deviceInfo;

    // Broadcast to all devices
    socket.to(`user:${userId}`).emit('quarantine:updated', {
      ...data,
      timestamp: new Date()
    });
  });

  // Handle system metrics from desktop
  socket.on('metrics:update', (data) => {
    const deviceInfo = deviceSockets.get(socket.id);
    if (!deviceInfo) return;

    const { userId } = deviceInfo;

    // Send to mobile devices only
    const userSockets = activeConnections.get(userId) || [];
    userSockets.forEach(socketId => {
      const targetDevice = deviceSockets.get(socketId);
      if (targetDevice && targetDevice.deviceType === 'mobile') {
        io.to(socketId).emit('metrics:data', {
          ...data,
          deviceId: deviceInfo.deviceId,
          timestamp: new Date()
        });
      }
    });
  });

  // Handle ping/pong for connection health
  socket.on('ping', () => {
    socket.emit('pong', { timestamp: Date.now() });
  });

  // Handle disconnection
  socket.on('disconnect', () => {
    const deviceInfo = deviceSockets.get(socket.id);
    
    if (deviceInfo) {
      const { userId, deviceId, deviceType } = deviceInfo;
      console.log(`🔌 Disconnected: User ${userId}, Device ${deviceId} (${deviceType})`);

      // Remove from active connections
      if (activeConnections.has(userId)) {
        const sockets = activeConnections.get(userId);
        const index = sockets.indexOf(socket.id);
        if (index > -1) {
          sockets.splice(index, 1);
        }
        if (sockets.length === 0) {
          activeConnections.delete(userId);
        }
      }

      // Notify other devices
      socket.to(`user:${userId}`).emit('device:disconnected', {
        deviceId,
        deviceType,
        timestamp: new Date()
      });

      // Clean up
      deviceSockets.delete(socket.id);
    }
  });
}

/**
 * Get active devices for a user
 */
function getUserDevices(userId) {
  const socketIds = activeConnections.get(userId) || [];
  return socketIds.map(id => deviceSockets.get(id)).filter(Boolean);
}

/**
 * Send notification to specific user's devices
 */
function sendToUser(io, userId, event, data) {
  io.to(`user:${userId}`).emit(event, data);
}

module.exports = {
  handleSocketConnection,
  getUserDevices,
  sendToUser,
  activeConnections,
  deviceSockets
};
