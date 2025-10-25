import {io, Socket} from 'socket.io-client';

const SOCKET_URL = 'http://localhost:3001';

class SocketServiceClass {
  private socket: Socket | null = null;
  private deviceId: string = 'mobile-001'; // TODO: Generate unique device ID

  connect(token: string): void {
    if (this.socket?.connected) {
      console.log('Socket already connected');
      return;
    }

    this.socket = io(SOCKET_URL, {
      transports: ['websocket'],
      autoConnect: true,
    });

    this.socket.on('connect', () => {
      console.log('✅ Socket connected:', this.socket?.id);

      // Authenticate socket connection
      this.socket?.emit('authenticate', {
        token,
        deviceId: this.deviceId,
        deviceType: 'mobile',
      });
    });

    this.socket.on('authenticated', (data) => {
      console.log('✅ Socket authenticated:', data);
    });

    this.socket.on('authentication:failed', (data) => {
      console.error('❌ Socket authentication failed:', data.error);
    });

    this.socket.on('disconnect', () => {
      console.log('🔌 Socket disconnected');
    });

    this.socket.on('connect_error', (error) => {
      console.error('Socket connection error:', error);
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
