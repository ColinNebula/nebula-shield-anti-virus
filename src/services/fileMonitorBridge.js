/**
 * WebSocket Bridge for C++ File Monitor Integration
 * 
 * Provides real-time communication between the C++ backend file monitor
 * and the React frontend using WebSocket protocol
 */

class FileMonitorBridge {
  constructor() {
    this.ws = null;
    this.isConnected = false;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 10;
    this.reconnectDelay = 2000;
    this.listeners = new Map();
    this.messageQueue = [];
    this.stats = {
      messagesReceived: 0,
      messagesSent: 0,
      eventsProcessed: 0,
      reconnects: 0,
      lastEvent: null
    };
    
    // Event handlers
    this.eventHandlers = new Map();
  }

  /**
   * Connect to C++ backend WebSocket server
   */
  connect(port = 8081) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      return;
    }
    
    const url = `ws://localhost:${port}/file-monitor`;
    
    try {
      this.ws = new WebSocket(url);
      
      this.ws.onopen = () => this.handleOpen();
      this.ws.onmessage = (event) => this.handleMessage(event);
      this.ws.onerror = (error) => this.handleError(error);
      this.ws.onclose = () => this.handleClose();
      
    } catch (error) {
      // Silently fail - file monitor is optional
      this.isConnected = false;
    }
  }

  /**
   * Disconnect from WebSocket
   */
  disconnect() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.isConnected = false;
    this.reconnectAttempts = 0;
  }

  /**
   * Handle WebSocket open
   */
  handleOpen() {
    this.isConnected = true;
    this.reconnectAttempts = 0;
    
    // Send queued messages
    this.flushMessageQueue();
    
    // Notify listeners
    this.emit('connected', { timestamp: Date.now() });
    
    // Request initial state
    this.send({
      type: 'get_status',
      timestamp: Date.now()
    });
  }

  /**
   * Handle incoming WebSocket message
   */
  handleMessage(event) {
    this.stats.messagesReceived++;
    
    try {
      const data = JSON.parse(event.data);
      this.processMessage(data);
    } catch (error) {
      console.error('Failed to parse WebSocket message:', error);
    }
  }

  /**
   * Process incoming message
   */
  processMessage(data) {
    const { type, payload, timestamp } = data;
    
    this.stats.eventsProcessed++;
    this.stats.lastEvent = new Date(timestamp).toISOString();
    
    switch (type) {
      case 'file_event':
        this.handleFileEvent(payload);
        break;
        
      case 'status_update':
        this.handleStatusUpdate(payload);
        break;
        
      case 'statistics':
        this.handleStatistics(payload);
        break;
        
      case 'threat_detected':
        this.handleThreatDetected(payload);
        break;
        
      case 'threat_blocked':
        this.handleThreatBlocked(payload);
        break;
        
      case 'monitoring_started':
        this.emit('monitoring_started', payload);
        break;
        
      case 'monitoring_stopped':
        this.emit('monitoring_stopped', payload);
        break;
        
      case 'error':
        this.handleErrorMessage(payload);
        break;
        
      default:
        console.warn('Unknown message type:', type);
    }
  }

  /**
   * Handle file event from C++ monitor
   */
  handleFileEvent(payload) {
    const event = {
      file_path: payload.filePath || payload.file_path,
      event_type: payload.eventType || payload.event_type,
      timestamp: payload.timestamp,
      file_size: payload.fileSize || payload.file_size,
      file_extension: payload.fileExtension || payload.file_extension,
      is_executable: payload.isExecutable || payload.is_executable,
      process_id: payload.processId || payload.process_id,
      threat_level: payload.threatLevel || 0
    };
    
    this.emit('file_event', event);
  }

  /**
   * Handle status update
   */
  handleStatusUpdate(payload) {
    this.emit('status_update', {
      isMonitoring: payload.is_monitoring,
      isPaused: payload.is_paused,
      realTimeProtection: payload.real_time_protection,
      watchedDirectories: payload.watched_directories,
      queueSize: payload.queue_size
    });
  }

  /**
   * Handle statistics update
   */
  handleStatistics(payload) {
    this.emit('statistics', {
      totalEvents: payload.total_events,
      filesScanned: payload.files_scanned,
      threatsDetected: payload.threats_detected,
      threatsBlocked: payload.threats_blocked,
      eventsPerSecond: payload.events_per_second,
      cpuUsage: payload.cpu_usage,
      memoryUsageMB: payload.memory_usage_mb
    });
  }

  /**
   * Handle threat detected
   */
  handleThreatDetected(payload) {
    this.emit('threat_detected', {
      filePath: payload.file_path,
      threatType: payload.threat_type,
      severity: payload.severity,
      description: payload.description,
      timestamp: payload.timestamp,
      processId: payload.process_id
    });
  }

  /**
   * Handle threat blocked
   */
  handleThreatBlocked(payload) {
    this.emit('threat_blocked', {
      filePath: payload.file_path,
      threatType: payload.threat_type,
      action: payload.action,
      timestamp: payload.timestamp
    });
  }

  /**
   * Handle error message
   */
  handleErrorMessage(payload) {
    console.error('File monitor error:', payload.message);
    this.emit('error', payload);
  }

  /**
   * Handle WebSocket error
   */
  handleError(error) {
    // Silently handle connection errors - file monitor is optional
    if (this.reconnectAttempts === 0) {
      console.warn('⚠️ File monitor not available (optional feature)');
    }
    this.isConnected = false;
  }

  /**
   * Handle WebSocket close
   */
  handleClose() {
    // Silently handle disconnection - file monitor is optional
    this.isConnected = false;
    
    this.emit('disconnected', { timestamp: Date.now() });
    
    // Only attempt reconnection if we were previously connected
    if (this.reconnectAttempts > 0 && this.reconnectAttempts < 3) {
      this.scheduleReconnect();
    }
  }

  /**
   * Schedule reconnection attempt
   */
  scheduleReconnect() {
    // Don't reconnect - file monitor is an optional feature
    // It will be started manually when the C++ backend is available
    return;
  }

  /**
   * Send message to C++ backend
   */
  send(data) {
    if (!this.isConnected || !this.ws || this.ws.readyState !== WebSocket.OPEN) {
      // Queue message for later
      this.messageQueue.push(data);
      return false;
    }
    
    try {
      this.ws.send(JSON.stringify(data));
      this.stats.messagesSent++;
      return true;
    } catch (error) {
      console.error('Failed to send message:', error);
      return false;
    }
  }

  /**
   * Flush queued messages
   */
  flushMessageQueue() {
    while (this.messageQueue.length > 0 && this.isConnected) {
      const message = this.messageQueue.shift();
      this.send(message);
    }
  }

  /**
   * Start file monitoring
   */
  startMonitoring(directories = []) {
    return this.send({
      type: 'start_monitoring',
      payload: { directories },
      timestamp: Date.now()
    });
  }

  /**
   * Stop file monitoring
   */
  stopMonitoring() {
    return this.send({
      type: 'stop_monitoring',
      timestamp: Date.now()
    });
  }

  /**
   * Add directory to watch
   */
  addWatchDirectory(directory) {
    return this.send({
      type: 'add_directory',
      payload: { directory },
      timestamp: Date.now()
    });
  }

  /**
   * Remove directory from watch
   */
  removeWatchDirectory(directory) {
    return this.send({
      type: 'remove_directory',
      payload: { directory },
      timestamp: Date.now()
    });
  }

  /**
   * Get current statistics
   */
  requestStatistics() {
    return this.send({
      type: 'get_statistics',
      timestamp: Date.now()
    });
  }

  /**
   * Update configuration
   */
  updateConfig(config) {
    return this.send({
      type: 'update_config',
      payload: config,
      timestamp: Date.now()
    });
  }

  /**
   * Add file to whitelist
   */
  addToWhitelist(pathOrHash) {
    return this.send({
      type: 'add_whitelist',
      payload: { item: pathOrHash },
      timestamp: Date.now()
    });
  }

  /**
   * Add file to blacklist
   */
  addToBlacklist(pathOrHash) {
    return this.send({
      type: 'add_blacklist',
      payload: { item: pathOrHash },
      timestamp: Date.now()
    });
  }

  /**
   * Subscribe to events
   */
  on(event, callback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, []);
    }
    this.listeners.get(event).push(callback);
    
    return () => this.off(event, callback);
  }

  /**
   * Unsubscribe from events
   */
  off(event, callback) {
    if (!this.listeners.has(event)) return;
    
    const callbacks = this.listeners.get(event);
    const index = callbacks.indexOf(callback);
    if (index > -1) {
      callbacks.splice(index, 1);
    }
  }

  /**
   * Emit event to listeners
   */
  emit(event, data) {
    if (!this.listeners.has(event)) return;
    
    const callbacks = this.listeners.get(event);
    for (const callback of callbacks) {
      try {
        callback(data);
      } catch (error) {
        console.error(`Error in event listener for ${event}:`, error);
      }
    }
  }

  /**
   * Get connection statistics
   */
  getStatistics() {
    return {
      ...this.stats,
      isConnected: this.isConnected,
      reconnectAttempts: this.reconnectAttempts,
      queuedMessages: this.messageQueue.length
    };
  }

  /**
   * Reset statistics
   */
  resetStatistics() {
    this.stats = {
      messagesReceived: 0,
      messagesSent: 0,
      eventsProcessed: 0,
      reconnects: 0,
      lastEvent: null
    };
  }
}

// Export singleton
const fileMonitorBridge = new FileMonitorBridge();
export default fileMonitorBridge;
