/**
 * Privacy Audit Service
 * Tracks app permission usage and privacy timeline
 */

import { Platform } from 'react-native';
import ApiService from './ApiService';

export interface PermissionUsage {
  id: string;
  app: string;
  appIcon: string;
  permission: 'camera' | 'microphone' | 'location' | 'contacts' | 'photos' | 'calendar' | 'bluetooth' | 'notifications';
  permissionName: string;
  timestamp: string;
  duration: number; // in seconds
  frequency: number; // times used today
  isSuspicious: boolean;
  riskLevel: 'low' | 'medium' | 'high';
  location?: string;
}

export interface PrivacyScore {
  overall: number;
  breakdown: {
    permissions: number;
    tracking: number;
    dataSharing: number;
    encryption: number;
  };
  rating: 'excellent' | 'good' | 'fair' | 'poor';
  improvements: string[];
}

export interface AppPrivacyReport {
  appName: string;
  appIcon: string;
  packageName: string;
  permissions: {
    granted: string[];
    denied: string[];
    dangerous: string[];
  };
  dataAccess: {
    camera: number;
    microphone: number;
    location: number;
    contacts: number;
    photos: number;
  };
  tracking: {
    domains: string[];
    thirdPartyTrackers: number;
  };
  lastUsed: string;
  privacyScore: number;
  recommendations: string[];
}

export interface PrivacyTimeline {
  date: string;
  events: PermissionUsage[];
  summary: {
    totalAccesses: number;
    uniqueApps: number;
    suspiciousActivity: number;
    mostUsedPermission: string;
  };
}

export interface DataBreach {
  id: string;
  service: string;
  serviceIcon: string;
  email: string;
  breachDate: string;
  discoveredDate: string;
  affectedAccounts: number;
  dataTypes: string[];
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  recommendations: string[];
  isPasswordChanged: boolean;
  isPwned: boolean;
}

export interface PermissionRecommendation {
  id: string;
  app: string;
  appIcon: string;
  permission: string;
  reason: string;
  riskLevel: 'high' | 'medium' | 'low';
  usageFrequency: 'never' | 'rarely' | 'sometimes' | 'often';
  lastUsed: string;
  action: 'revoke' | 'review' | 'keep';
  impact: string;
}

export interface PermissionAnalytics {
  totalPermissions: number;
  grantedPermissions: number;
  revokedPermissions: number;
  dangerousPermissions: number;
  byType: {
    [key: string]: {
      count: number;
      apps: string[];
      lastUsed: string;
      riskScore: number;
    };
  };
  trends: {
    date: string;
    accesses: number;
  }[];
}

export interface AppBehaviorAnalysis {
  appName: string;
  suspiciousPatterns: string[];
  normalBehavior: {
    averageUsageTime: number;
    typicalPermissions: string[];
    usualLocations: string[];
  };
  anomalies: {
    type: string;
    description: string;
    timestamp: string;
    severity: 'low' | 'medium' | 'high';
  }[];
  trustScore: number;
}

class PrivacyAuditServiceClass {
  /**
   * Get privacy score and recommendations
   */
  async getPrivacyScore(): Promise<PrivacyScore> {
    // TODO: Uncomment when backend endpoint is ready
    // try {
    //   const result = await ApiService.client.get('/privacy/score');
    //   if (result.data.success) {
    //     return result.data.data;
    //   }
    // } catch (error) {
    //   console.error('Privacy score error:', error);
    // }

    // Fallback: Calculate mock privacy score
    return {
      overall: 75,
      breakdown: {
        permissions: 80,
        tracking: 65,
        dataSharing: 70,
        encryption: 85,
      },
      rating: 'good',
      improvements: [
        'Revoke unnecessary location permissions',
        'Enable tracking prevention in settings',
        'Review apps with camera access',
      ],
    };
  }

  /**
   * Get permission usage timeline
   */
  async getPermissionTimeline(days: number = 7): Promise<PrivacyTimeline[]> {
    // TODO: Uncomment when backend endpoint is ready
    // try {
    //   const result = await ApiService.client.get(`/privacy/timeline?days=${days}`);
    //   if (result.data.success) {
    //     return result.data.data;
    //   }
    // } catch (error) {
    //   console.error('Timeline error:', error);
    // }

    // Fallback: Generate mock timeline
    return this.generateMockTimeline(days);
  }

  /**
   * Get today's permission usage
   */
  async getTodayActivity(): Promise<PermissionUsage[]> {
    // TODO: Uncomment when backend endpoint is ready
    // try {
    //   const result = await ApiService.client.get('/privacy/today');
    //   if (result.data.success) {
    //     return result.data.data;
    //   }
    // } catch (error) {
    //   console.error('Today activity error:', error);
    // }

    // Fallback: Generate mock activity
    return this.generateMockActivity();
  }

  /**
   * Get detailed app privacy report
   */
  async getAppPrivacyReport(appName: string): Promise<AppPrivacyReport> {
    // TODO: Uncomment when backend endpoint is ready
    // try {
    //   const result = await ApiService.client.get(`/privacy/app/${encodeURIComponent(appName)}`);
    //   if (result.data.success) {
    //     return result.data.data;
    //   }
    // } catch (error) {
    //   console.error('App report error:', error);
    // }

    // Fallback: Generate mock report
    return {
      appName,
      appIcon: 'application',
      packageName: `com.example.${appName.toLowerCase()}`,
      permissions: {
        granted: ['Camera', 'Microphone', 'Location'],
        denied: ['Contacts', 'Calendar'],
        dangerous: ['Location', 'Camera'],
      },
      dataAccess: {
        camera: 15,
        microphone: 8,
        location: 42,
        contacts: 0,
        photos: 5,
      },
      tracking: {
        domains: ['analytics.google.com', 'facebook.com', 'doubleclick.net'],
        thirdPartyTrackers: 8,
      },
      lastUsed: new Date().toISOString(),
      privacyScore: 65,
      recommendations: [
        'Consider revoking location access',
        'Review third-party tracker list',
        'Enable privacy mode if available',
      ],
    };
  }

  /**
   * Get apps with specific permission
   */
  async getAppsWithPermission(permission: string): Promise<AppPrivacyReport[]> {
    // TODO: Uncomment when backend endpoint is ready
    // try {
    //   const result = await ApiService.client.get(`/privacy/permission/${permission}`);
    //   if (result.data.success) {
    //     return result.data.data;
    //   }
    // } catch (error) {
    //   console.error('Apps with permission error:', error);
    // }

    return [];
  }

  /**
   * Check for data breaches associated with user accounts
   */
  async checkDataBreaches(emails: string[]): Promise<DataBreach[]> {
    // TODO: Uncomment when backend endpoint is ready
    // try {
    //   const result = await ApiService.client.post('/privacy/breaches', { emails });
    //   if (result.data.success) {
    //     return result.data.data;
    //   }
    // } catch (error) {
    //   console.error('Data breach check error:', error);
    // }

    // Fallback: Generate mock breach data
    return this.generateMockBreaches(emails);
  }

  /**
   * Get permission revocation recommendations
   */
  async getPermissionRecommendations(): Promise<PermissionRecommendation[]> {
    // TODO: Uncomment when backend endpoint is ready
    // try {
    //   const result = await ApiService.client.get('/privacy/recommendations');
    //   if (result.data.success) {
    //     return result.data.data;
    //   }
    // } catch (error) {
    //   console.error('Recommendations error:', error);
    // }

    // Fallback: Generate mock recommendations
    return this.generateMockRecommendations();
  }

  /**
   * Get permission analytics and trends
   */
  async getPermissionAnalytics(days: number = 30): Promise<PermissionAnalytics> {
    // TODO: Uncomment when backend endpoint is ready
    // try {
    //   const result = await ApiService.client.get(`/privacy/analytics?days=${days}`);
    //   if (result.data.success) {
    //     return result.data.data;
    //   }
    // } catch (error) {
    //   console.error('Analytics error:', error);
    // }

    // Fallback: Generate mock analytics
    return this.generateMockAnalytics(days);
  }

  /**
   * Analyze app behavior for anomalies
   */
  async analyzeAppBehavior(appName: string): Promise<AppBehaviorAnalysis> {
    // TODO: Uncomment when backend endpoint is ready
    // try {
    //   const result = await ApiService.client.get(`/privacy/behavior/${encodeURIComponent(appName)}`);
    //   if (result.data.success) {
    //     return result.data.data;
    //   }
    // } catch (error) {
    //   console.error('Behavior analysis error:', error);
    // }

    // Fallback: Generate mock analysis
    return {
      appName,
      suspiciousPatterns: [
        'Accessing location in background',
        'Frequent microphone usage',
      ],
      normalBehavior: {
        averageUsageTime: 45,
        typicalPermissions: ['camera', 'microphone', 'photos'],
        usualLocations: ['Home', 'Work'],
      },
      anomalies: [
        {
          type: 'unusual_time',
          description: 'App accessed camera at 3:00 AM',
          timestamp: new Date(Date.now() - 3600000).toISOString(),
          severity: 'medium',
        },
      ],
      trustScore: 72,
    };
  }

  /**
   * Get real-time permission monitoring status
   */
  async getRealtimeMonitoring(): Promise<{
    isActive: boolean;
    currentAccesses: PermissionUsage[];
    alertsToday: number;
  }> {
    return {
      isActive: true,
      currentAccesses: this.generateMockActivity().slice(0, 3),
      alertsToday: Math.floor(Math.random() * 5),
    };
  }

  /**
   * Generate mock activity data
   */
  private generateMockActivity(): PermissionUsage[] {
    const apps = [
      { name: 'Instagram', icon: 'instagram' },
      { name: 'WhatsApp', icon: 'whatsapp' },
      { name: 'Maps', icon: 'map' },
      { name: 'Camera', icon: 'camera' },
      { name: 'Uber', icon: 'car' },
    ];

    const permissions: Array<{type: PermissionUsage['permission'], name: string}> = [
      { type: 'camera', name: 'Camera' },
      { type: 'microphone', name: 'Microphone' },
      { type: 'location', name: 'Location' },
      { type: 'photos', name: 'Photos' },
      { type: 'contacts', name: 'Contacts' },
    ];

    const activity: PermissionUsage[] = [];
    const now = new Date();

    for (let i = 0; i < 15; i++) {
      const app = apps[Math.floor(Math.random() * apps.length)];
      const permission = permissions[Math.floor(Math.random() * permissions.length)];
      const minutesAgo = Math.floor(Math.random() * 480); // Last 8 hours
      const timestamp = new Date(now.getTime() - minutesAgo * 60000);

      activity.push({
        id: `usage-${i}`,
        app: app.name,
        appIcon: app.icon,
        permission: permission.type,
        permissionName: permission.name,
        timestamp: timestamp.toISOString(),
        duration: Math.floor(Math.random() * 300) + 10,
        frequency: Math.floor(Math.random() * 10) + 1,
        isSuspicious: Math.random() > 0.9,
        riskLevel: Math.random() > 0.8 ? 'high' : Math.random() > 0.5 ? 'medium' : 'low',
        location: permission.type === 'location' ? 'New York, NY' : undefined,
      });
    }

    return activity.sort((a, b) => 
      new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
  }

  /**
   * Generate mock timeline data
   */
  private generateMockTimeline(days: number): PrivacyTimeline[] {
    const timeline: PrivacyTimeline[] = [];
    const now = new Date();

    for (let i = 0; i < days; i++) {
      const date = new Date(now);
      date.setDate(date.getDate() - i);
      
      const events = this.generateMockActivity().slice(0, Math.floor(Math.random() * 10) + 5);
      const suspiciousCount = events.filter(e => e.isSuspicious).length;
      const uniqueApps = new Set(events.map(e => e.app)).size;
      
      const permissionCounts: { [key: string]: number } = {};
      events.forEach(e => {
        permissionCounts[e.permission] = (permissionCounts[e.permission] || 0) + 1;
      });
      const mostUsed = Object.keys(permissionCounts).reduce((a, b) => 
        permissionCounts[a] > permissionCounts[b] ? a : b
      , 'location');

      timeline.push({
        date: date.toISOString().split('T')[0],
        events,
        summary: {
          totalAccesses: events.length,
          uniqueApps,
          suspiciousActivity: suspiciousCount,
          mostUsedPermission: mostUsed,
        },
      });
    }

    return timeline;
  }

  /**
   * Generate mock data breach data
   */
  private generateMockBreaches(emails: string[]): DataBreach[] {
    const breaches: DataBreach[] = [];
    const services = [
      { name: 'Adobe', icon: 'adobe', date: '2023-10-15', accounts: 153000000 },
      { name: 'LinkedIn', icon: 'linkedin', date: '2023-06-20', accounts: 700000000 },
      { name: 'Facebook', icon: 'facebook', date: '2023-04-10', accounts: 533000000 },
      { name: 'Twitter', icon: 'twitter', date: '2023-01-05', accounts: 235000000 },
    ];

    emails.forEach((email, index) => {
      if (index < 2) { // Simulate some breaches
        const service = services[index % services.length];
        breaches.push({
          id: `breach-${index}`,
          service: service.name,
          serviceIcon: service.icon,
          email,
          breachDate: service.date,
          discoveredDate: new Date(new Date(service.date).getTime() + 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
          affectedAccounts: service.accounts,
          dataTypes: ['Email addresses', 'Passwords', 'Names', 'Phone numbers'],
          severity: index === 0 ? 'critical' : 'high',
          description: `${service.name} experienced a data breach affecting ${service.accounts.toLocaleString()} accounts. Your email was found in the leaked data.`,
          recommendations: [
            'Change your password immediately',
            'Enable two-factor authentication',
            'Monitor account for suspicious activity',
            'Use a unique password for this service',
          ],
          isPasswordChanged: false,
          isPwned: true,
        });
      }
    });

    return breaches;
  }

  /**
   * Generate mock permission recommendations
   */
  private generateMockRecommendations(): PermissionRecommendation[] {
    return [
      {
        id: 'rec-1',
        app: 'Facebook',
        appIcon: 'facebook',
        permission: 'Location',
        reason: 'App accesses location even when not in use. Used 0 times in last 30 days.',
        riskLevel: 'high',
        usageFrequency: 'never',
        lastUsed: new Date(Date.now() - 45 * 24 * 60 * 60 * 1000).toISOString(),
        action: 'revoke',
        impact: 'App may not be able to tag your location in posts',
      },
      {
        id: 'rec-2',
        app: 'Weather App',
        appIcon: 'weather-partly-cloudy',
        permission: 'Contacts',
        reason: 'Weather app has access to contacts but doesn\'t require it for core functionality.',
        riskLevel: 'medium',
        usageFrequency: 'never',
        lastUsed: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000).toISOString(),
        action: 'revoke',
        impact: 'No impact on weather functionality',
      },
      {
        id: 'rec-3',
        app: 'Flashlight',
        appIcon: 'flashlight',
        permission: 'Camera',
        reason: 'Flashlight app only needs camera for flash, not full camera access.',
        riskLevel: 'high',
        usageFrequency: 'rarely',
        lastUsed: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
        action: 'review',
        impact: 'Consider using built-in flashlight instead',
      },
      {
        id: 'rec-4',
        app: 'Shopping App',
        appIcon: 'shopping',
        permission: 'Microphone',
        reason: 'Shopping app has microphone access but rarely uses it. Last used 90 days ago.',
        riskLevel: 'medium',
        usageFrequency: 'rarely',
        lastUsed: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
        action: 'review',
        impact: 'Voice search feature will be disabled',
      },
      {
        id: 'rec-5',
        app: 'Games',
        appIcon: 'gamepad-variant',
        permission: 'Location',
        reason: 'Gaming app tracks location for ads and analytics.',
        riskLevel: 'high',
        usageFrequency: 'often',
        lastUsed: new Date(Date.now() - 1 * 60 * 60 * 1000).toISOString(),
        action: 'revoke',
        impact: 'You may see less relevant ads',
      },
    ];
  }

  /**
   * Generate mock analytics data
   */
  private generateMockAnalytics(days: number): PermissionAnalytics {
    const trends: { date: string; accesses: number }[] = [];
    const now = new Date();

    for (let i = days - 1; i >= 0; i--) {
      const date = new Date(now);
      date.setDate(date.getDate() - i);
      trends.push({
        date: date.toISOString().split('T')[0],
        accesses: Math.floor(Math.random() * 50) + 10,
      });
    }

    return {
      totalPermissions: 42,
      grantedPermissions: 28,
      revokedPermissions: 14,
      dangerousPermissions: 8,
      byType: {
        camera: {
          count: 12,
          apps: ['Instagram', 'WhatsApp', 'Snapchat', 'Facebook'],
          lastUsed: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
          riskScore: 65,
        },
        microphone: {
          count: 10,
          apps: ['WhatsApp', 'Zoom', 'Discord', 'Voice Recorder'],
          lastUsed: new Date(Date.now() - 1 * 60 * 60 * 1000).toISOString(),
          riskScore: 55,
        },
        location: {
          count: 15,
          apps: ['Google Maps', 'Uber', 'Weather', 'Instagram', 'Facebook'],
          lastUsed: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
          riskScore: 75,
        },
        contacts: {
          count: 8,
          apps: ['WhatsApp', 'Telegram', 'Signal', 'Phone'],
          lastUsed: new Date(Date.now() - 5 * 60 * 60 * 1000).toISOString(),
          riskScore: 45,
        },
        photos: {
          count: 14,
          apps: ['Instagram', 'Facebook', 'WhatsApp', 'Gallery', 'Google Photos'],
          lastUsed: new Date(Date.now() - 1 * 60 * 60 * 1000).toISOString(),
          riskScore: 40,
        },
      },
      trends,
    };
  }

  /**
   * Format time ago
   */
  formatTimeAgo(timestamp: string): string {
    const now = new Date();
    const then = new Date(timestamp);
    const seconds = Math.floor((now.getTime() - then.getTime()) / 1000);

    if (seconds < 60) return `${seconds}s ago`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
  }

  /**
   * Get risk level color
   */
  getRiskColor(level: 'low' | 'medium' | 'high'): string {
    switch (level) {
      case 'high': return '#f44336';
      case 'medium': return '#ff9800';
      case 'low': return '#4caf50';
      default: return '#9e9e9e';
    }
  }

  /**
   * Get permission icon
   */
  getPermissionIcon(permission: PermissionUsage['permission']): string {
    const icons: { [key: string]: string } = {
      camera: 'camera',
      microphone: 'microphone',
      location: 'map-marker',
      contacts: 'account-multiple',
      photos: 'image-multiple',
      calendar: 'calendar',
      bluetooth: 'bluetooth',
      notifications: 'bell',
    };
    return icons[permission] || 'shield-alert';
  }
}

export const PrivacyAuditService = new PrivacyAuditServiceClass();
