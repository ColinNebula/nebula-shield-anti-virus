import {io, Socket} from 'socket.io-client';
import AsyncStorage from '@react-native-async-storage/async-storage';
import {Platform} from 'react-native';

const SOCKET_URL = 'http://10.0.0.72:3001';

// Fallback for Expo Go compatibility (DeviceInfo not supported)
const getUniqueDeviceId = async (): Promise<string> => {
  try {
    // Try to use expo-device if available
    const Device = require('expo-device');
    return Device.osInternalBuildId || Device.modelId || `${Platform.OS}-${Date.now()}`;
  } catch {
    // Fallback to random ID for Expo Go
    return `${Platform.OS}-${Math.random().toString(36).substring(2, 15)}`;
  }
};

class SocketServiceClass {
  private socket: Socket | null = null;
  private deviceId: string = '';
  private reconnectAttempts: number = 0;
  private maxReconnectAttempts: number = 5;
  private reconnectDelay: number = 2000;

  async initializeDeviceId(): Promise<string> {
    try {
      // Try to get stored device ID
      let storedId = await AsyncStorage.getItem('deviceId');
      
      if (!storedId) {
        // Generate unique device ID
        const uniqueId = await getUniqueDeviceId();
        storedId = `mobile-${uniqueId}`;
        await AsyncStorage.setItem('deviceId', storedId);
      }
      
      this.deviceId = storedId;
      return storedId;
    } catch (error) {
      console.error('Error initializing device ID:', error);
      this.deviceId = `mobile-${Date.now()}`;
      return this.deviceId;
    }
  }

  async connect(token: string): Promise<void> {
    if (this.socket?.connected) {
      console.log('✅ Socket already connected');
      return;
    }

    await this.initializeDeviceId();

    console.log('🔌 Connecting to WebSocket:', SOCKET_URL);

    this.socket = io(SOCKET_URL, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionAttempts: this.maxReconnectAttempts,
      reconnectionDelay: this.reconnectDelay,
      autoConnect: true,
    });

    this.socket.on('connect', async () => {
      console.log('✅ Socket connected:', this.socket?.id);
      this.reconnectAttempts = 0;

      // Get device info with fallback for Expo Go
      let deviceName = 'Mobile Device';
      let platform = Platform.OS;
      
      try {
        const Device = require('expo-device');
        deviceName = Device.deviceName || Device.modelName || 'Mobile Device';
        platform = Device.osName || Platform.OS;
      } catch {
        // Fallback for Expo Go
        deviceName = `${Platform.OS === 'ios' ? 'iPhone' : 'Android'} Device`;
      }

      // Authenticate socket connection
      this.socket?.emit('authenticate', {
        token,
        deviceId: this.deviceId,
        deviceType: 'mobile',
        deviceName,
        platform,
      });
    });

    this.socket.on('authenticated', (data) => {
      console.log('✅ Socket authenticated:', data);
    });

    this.socket.on('authentication:failed', (data) => {
      console.error('❌ Socket authentication failed:', data.error);
    });

    this.socket.on('disconnect', (reason) => {
      console.log('🔌 Socket disconnected:', reason);
      
      if (reason === 'io server disconnect') {
        // Server disconnected, try to reconnect
        this.socket?.connect();
      }
    });

    this.socket.on('connect_error', (error) => {
      console.error('❌ Socket connection error:', error.message);
      this.reconnectAttempts++;
      
      if (this.reconnectAttempts >= this.maxReconnectAttempts) {
        console.error('❌ Max reconnection attempts reached');
      }
    });

    this.socket.on('reconnect', (attemptNumber) => {
      console.log('🔄 Socket reconnected after', attemptNumber, 'attempts');
    });
  }

  disconnect(): void {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
  }

  emit(event: string, data: any): void {
    if (!this.socket?.connected) {
      console.warn('Socket not connected, cannot emit:', event);
      return;
    }

    this.socket.emit(event, data);
  }

  on(event: string, callback: (data: any) => void): void {
    if (!this.socket) {
      console.warn('Socket not initialized');
      return;
    }

    this.socket.on(event, callback);
  }

  off(event: string): void {
    if (!this.socket) {
      return;
    }

    this.socket.off(event);
  }

  isConnected(): boolean {
    return this.socket?.connected || false;
  }
}

export const SocketService = new SocketServiceClass();
