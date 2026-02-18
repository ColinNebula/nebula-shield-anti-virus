import {Alert, Linking} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';

interface UrlCheckResult {
  success: boolean;
  url?: string;
  domain?: string;
  malicious?: boolean;
  type?: string;
  score?: number;
  sources?: string[];
  error?: string;
}

class SafeBrowsingService {
  private static API_URL = 'http://10.0.0.72:8080/api';

  /**
   * Check if Web Shield is enabled
   */
  static async isWebShieldEnabled(): Promise<boolean> {
    try {
      const status = await AsyncStorage.getItem('web_shield_enabled');
      return status === 'true' || status === null; // Default to enabled
    } catch (error) {
      console.error('Failed to check web shield status:', error);
      return true; // Default to enabled on error
    }
  }

  /**
   * Check URL safety against threat database
   */
  static async checkUrl(url: string): Promise<UrlCheckResult> {
    try {
      const response = await fetch(`${this.API_URL}/browser-extension/check-url`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
        timeout: 5000,
      });

      const result = await response.json();
      return result;
    } catch (error) {
      console.error('URL check failed:', error);
      // On error, allow the URL (fail-open for availability)
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Open URL with safety check
   * This is the main method to use throughout the app
   */
  static async openUrlSafely(url: string): Promise<void> {
    const webShieldEnabled = await this.isWebShieldEnabled();

    if (!webShieldEnabled) {
      // Web Shield disabled, open directly
      Linking.openURL(url);
      return;
    }

    // Check URL safety
    const result = await this.checkUrl(url);

    if (result.success && result.malicious) {
      // Malicious URL detected
      Alert.alert(
        '⚠️ Dangerous Site Blocked',
        `This website has been identified as ${result.type}.\n\nRisk Score: ${result.score}/100\n\nFor your safety, this site has been blocked.`,
        [
          {
            text: 'Cancel',
            style: 'cancel',
          },
          {
            text: 'Visit Anyway (Not Recommended)',
            style: 'destructive',
            onPress: () => Linking.openURL(url),
          },
          {
            text: 'Report False Positive',
            onPress: () => this.reportFalsePositive(url),
          },
        ]
      );
    } else {
      // Safe URL or check failed (fail-open)
      Linking.openURL(url);
    }
  }

  /**
   * Report a URL as a false positive
   */
  static async reportFalsePositive(url: string): Promise<void> {
    try {
      await fetch(`${this.API_URL}/browser-extension/report-false-positive`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url,
          reason: 'User reported false positive',
        }),
      });

      Alert.alert(
        'Thank You',
        'Your report has been submitted. Our security team will review this URL.',
        [{text: 'OK'}]
      );
    } catch (error) {
      console.error('Failed to report false positive:', error);
      Alert.alert('Error', 'Failed to submit report. Please try again later.');
    }
  }

  /**
   * Report a phishing URL
   */
  static async reportPhishing(url: string, description?: string): Promise<void> {
    try {
      await fetch(`${this.API_URL}/browser-extension/report-phishing`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url,
          description,
        }),
      });

      Alert.alert(
        'Report Submitted',
        'Thank you for helping keep the community safe. We will investigate this site.',
        [{text: 'OK'}]
      );
    } catch (error) {
      console.error('Failed to report phishing:', error);
      Alert.alert('Error', 'Failed to submit report. Please try again later.');
    }
  }

  /**
   * Get browsing statistics (for the Web Protection screen)
   */
  static async getStatistics(): Promise<any> {
    try {
      const response = await fetch(`${this.API_URL}/browser-extension/statistics`);
      const result = await response.json();
      return result;
    } catch (error) {
      console.error('Failed to get statistics:', error);
      return {success: false, error};
    }
  }

  /**
   * Scan browser history for malicious sites
   * Note: React Native doesn't have access to browser history
   * This is a placeholder for future native module integration
   */
  static async scanBrowserHistory(): Promise<any> {
    // Simulated history scan
    // In a real implementation, this would require a native module
    // to access browser history on Android/iOS
    
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve({
          success: true,
          scanned: 0,
          threats: 0,
          message: 'Browser history scanning requires system-level permissions. This feature is available on desktop.',
        });
      }, 2000);
    });
  }
}

export default SafeBrowsingService;
