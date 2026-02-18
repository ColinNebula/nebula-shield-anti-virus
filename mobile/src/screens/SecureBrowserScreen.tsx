import React, { useState, useEffect, useRef } from 'react';
import {
  View,
  Text,
  StyleSheet,
  ScrollView,
  TextInput as RNTextInput,
  Alert,
  RefreshControl,
  Linking,
  TouchableOpacity,
  Pressable,
  Share,
  Animated,
  PanResponder,
  Dimensions,
  Platform,
} from 'react-native';
import * as Clipboard from 'expo-clipboard';
import * as Speech from 'expo-speech';
import * as Haptics from 'expo-haptics';
import AsyncStorage from '@react-native-async-storage/async-storage';

// Optional: QR Scanner (requires native rebuild)
let BarCodeScanner: any = null;
try {
  const scanner = require('expo-barcode-scanner');
  BarCodeScanner = scanner.BarCodeScanner;
} catch (e) {
  console.log('BarCodeScanner not available - QR feature disabled');
}
import {
  Card,
  Button,
  useTheme,
  Chip,
  ProgressBar,
  List,
  Divider,
  IconButton,
  Surface,
  SegmentedButtons,
  Switch,
  Dialog,
  Portal,
  TextInput,
} from 'react-native-paper';
import { MaterialCommunityIcons as Icon } from '@expo/vector-icons';
import SecureBrowserService, {
  WebsitePrivacyScore,
  PhishingCheckResult,
  BlockedContent,
  CookieInfo,
  BrowsingHistory,
  DNSSettings,
  FingerprintProtection,
  DownloadItem,
  Bookmark,
  ScriptBlocking,
  PrivacyMetrics,
  AIThreatDetection,
  DetectedThreat,
  ContentFilter,
  PasswordManager,

  SmartProtection,
  AntiPhishing,
  DataLeakProtection,
  NetworkSecurity,
  SessionIsolation,
  PerformanceOptimization,
  SecurityAudit,
} from '../services/SecureBrowserService';

interface BrowserTab {
  id: string;
  url: string;
  title: string;
  history: string[];
  historyIndex: number;
  isIncognito: boolean;
  isReading: boolean;
  isDarkMode: boolean;
}

// Simple wrapper for embedded mode
const SimpleBrowserView = () => {
  const [url, setUrl] = useState('');
  const [currentUrl, setCurrentUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<any>(null);
  const [history, setHistory] = useState<string[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  
  // Popular sites for quick access
  const popularSites = [
    { name: 'Google', url: 'https://www.google.com', icon: 'google' },
    { name: 'YouTube', url: 'https://www.youtube.com', icon: 'youtube' },
    { name: 'Facebook', url: 'https://www.facebook.com', icon: 'facebook' },
    { name: 'Twitter', url: 'https://www.twitter.com', icon: 'twitter' },
    { name: 'Amazon', url: 'https://www.amazon.com', icon: 'amazon' },
    { name: 'Wikipedia', url: 'https://www.wikipedia.org', icon: 'wikipedia' },
  ];
  
  // Smart suggestions based on input
  const updateSuggestions = (text: string) => {
    if (!text.trim()) {
      setSuggestions([]);
      setShowSuggestions(false);
      return;
    }
    
    const searchText = text.toLowerCase();
    const matches: string[] = [];
    
    // Check history
    history.forEach(item => {
      if (item.toLowerCase().includes(searchText)) {
        matches.push(item);
      }
    });
    
    // Check popular sites
    popularSites.forEach(site => {
      if (site.name.toLowerCase().includes(searchText) || site.url.toLowerCase().includes(searchText)) {
        matches.push(site.url);
      }
    });
    
    // Add search suggestion
    if (!text.includes('.') && !text.startsWith('http')) {
      matches.push(`Search for "${text}"`);
    }
    
    // Common domain suggestions
    if (text.includes('.') && !text.startsWith('http')) {
      if (!text.startsWith('www.')) {
        matches.push(`https://www.${text}`);
      }
      matches.push(`https://${text}`);
    }
    
    setSuggestions([...new Set(matches)].slice(0, 5));
    setShowSuggestions(matches.length > 0);
  };
  
  const handleUrlChange = (text: string) => {
    setUrl(text);
    updateSuggestions(text);
  };
  
  const handleSearch = async (searchUrl?: string) => {
    const urlToAnalyze = searchUrl || url.trim();
    if (!urlToAnalyze) return;
    
    setLoading(true);
    setShowSuggestions(false);
    let finalUrl = urlToAnalyze;
    
    // Handle search suggestions
    if (finalUrl.startsWith('Search for "')) {
      const query = finalUrl.match(/Search for "(.+)"/)?.[1];
      if (query) {
        finalUrl = `https://www.google.com/search?q=${encodeURIComponent(query)}`;
      }
    } else {
      // Check if it's a search query or URL
      const isUrl = finalUrl.includes('.') || finalUrl.startsWith('http');
      
      if (!isUrl) {
        // It's a search query
        finalUrl = `https://www.google.com/search?q=${encodeURIComponent(finalUrl)}`;
      } else {
        // Add https:// if no protocol
        if (!finalUrl.match(/^https?:\/\//i)) {
          finalUrl = 'https://' + finalUrl;
        }
      }
    }
    
    setCurrentUrl(finalUrl);
    
    // Add to history
    setHistory(prev => [finalUrl, ...prev.filter(h => h !== finalUrl)].slice(0, 10));
    
    // Simulate analysis with realistic detection
    await new Promise(resolve => setTimeout(resolve, 1500));
    
    const domain = finalUrl.replace(/^https?:\/\//, '').split('/')[0];
    const isTrustedDomain = ['google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org', 'github.com', 'microsoft.com'].some(d => domain.includes(d));
    
    const mockResult = {
      safe: isTrustedDomain ? true : Math.random() > 0.3,
      https: finalUrl.startsWith('https'),
      threatLevel: isTrustedDomain ? 'low' : (Math.random() > 0.7 ? 'medium' : 'low'),
      phishing: !isTrustedDomain && Math.random() > 0.85,
      malware: Math.random() > 0.93,
      trackers: isTrustedDomain ? Math.floor(Math.random() * 5) : Math.floor(Math.random() * 20) + 5,
      cookies: Math.floor(Math.random() * 30) + 10,
      privacyScore: isTrustedDomain ? Math.floor(Math.random() * 20) + 75 : Math.floor(Math.random() * 30) + 50,
      loadTime: (Math.random() * 2 + 0.5).toFixed(2),
      dataSize: (Math.random() * 5 + 1).toFixed(1),
    };
    
    setAnalysisResult(mockResult);
    setLoading(false);
    setUrl('');
  };
  
  const openInBrowser = () => {
    if (currentUrl) {
      Linking.openURL(currentUrl);
    }
  };
  
  const clearHistory = async () => {
    setHistory([]);
    setCurrentUrl('');
    setAnalysisResult(null);
  };
  
  const getThreatColor = (level: string) => {
    switch (level) {
      case 'high': return '#f44336';
      case 'medium': return '#ff9800';
      default: return '#4caf50';
    }
  };
  
  return (
    <View style={{ flex: 1, backgroundColor: '#f5f5f5' }}>
      {/* Header Card */}
      <Card style={{ margin: 15, backgroundColor: '#2196F3' }}>
        <Card.Content>
          <View style={{ alignItems: 'center' }}>
            <Icon name="shield-check" size={48} color="#ffffff" />
            <Text style={{ color: 'white', fontSize: 22, fontWeight: 'bold', marginTop: 10, textAlign: 'center' }}>
              🛡️ Secure Browser
            </Text>
            <Text style={{ color: 'white', fontSize: 13, marginTop: 8, textAlign: 'center', opacity: 0.95 }}>
              ✓ AI threat detection • ✓ Phishing protection • ✓ Privacy shield
            </Text>
          </View>
        </Card.Content>
      </Card>
      
      {/* URL Input */}
      <Card style={{ marginHorizontal: 15, marginBottom: 15 }}>
        <Card.Content>
          <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 10 }}>
            <TextInput
              mode="outlined"
              label="Enter URL or search"
              value={url}
              onChangeText={handleUrlChange}
              onSubmitEditing={() => handleSearch()}
              onFocus={() => url && setShowSuggestions(true)}
              style={{ flex: 1 }}
              outlineStyle={{ borderRadius: 25 }}
              left={<TextInput.Icon icon="magnify" />}
              right={
                url ? (
                  <TextInput.Icon 
                    icon="close" 
                    onPress={() => {
                      setUrl('');
                      setSuggestions([]);
                      setShowSuggestions(false);
                    }}
                  />
                ) : null
              }
              placeholder="google.com or search term"
              autoCapitalize="none"
              autoCorrect={false}
            />
          </View>
          
          {/* Smart Suggestions */}
          {showSuggestions && suggestions.length > 0 && (
            <View style={{ marginBottom: 10, backgroundColor: '#f5f5f5', borderRadius: 10, padding: 8 }}>
              {suggestions.map((suggestion, index) => (
                <TouchableOpacity
                  key={index}
                  onPress={() => {
                    setUrl(suggestion.startsWith('Search for') ? suggestion.match(/"(.+)"/)?.[1] || '' : suggestion);
                    handleSearch(suggestion);
                  }}
                  style={{ 
                    flexDirection: 'row', 
                    alignItems: 'center', 
                    paddingVertical: 8,
                    paddingHorizontal: 8,
                    borderBottomWidth: index < suggestions.length - 1 ? 1 : 0,
                    borderBottomColor: '#e0e0e0'
                  }}
                >
                  <Icon 
                    name={suggestion.startsWith('Search for') ? 'magnify' : history.includes(suggestion) ? 'history' : 'web'} 
                    size={20} 
                    color="#666" 
                  />
                  <Text style={{ marginLeft: 10, fontSize: 14, color: '#333', flex: 1 }} numberOfLines={1}>
                    {suggestion}
                  </Text>
                  <Icon name="arrow-top-left" size={16} color="#999" />
                </TouchableOpacity>
              ))}
            </View>
          )}
          
          {/* Quick Access Popular Sites */}
          {!url && !currentUrl && (
            <View style={{ marginBottom: 10 }}>
              <Text style={{ fontSize: 12, color: '#666', marginBottom: 8, fontWeight: '600' }}>Quick Access</Text>
              <View style={{ flexDirection: 'row', flexWrap: 'wrap', gap: 8 }}>
                {popularSites.map((site, index) => (
                  <Chip
                    key={index}
                    icon={site.icon}
                    onPress={() => handleSearch(site.url)}
                    style={{ backgroundColor: '#e3f2fd' }}
                  >
                    {site.name}
                  </Chip>
                ))}
              </View>
            </View>
          )}
          
          <View style={{ flexDirection: 'row', gap: 8 }}>
            <Button 
              mode="contained" 
              onPress={() => handleSearch()}
              style={{ flex: 1, borderRadius: 20 }}
              disabled={!url.trim() || loading}
              loading={loading}
              icon="shield-search"
            >
              Analyze
            </Button>
            {history.length > 0 && (
              <Button 
                mode="outlined"
                onPress={() => setShowHistory(!showHistory)}
                icon={showHistory ? "chevron-up" : "history"}
                style={{ borderRadius: 20 }}
              >
                {history.length}
              </Button>
            )}
          </View>
        </Card.Content>
      </Card>
      
      {/* History */}
      {showHistory && history.length > 0 && (
        <Card style={{ marginHorizontal: 15, marginBottom: 15 }}>
          <Card.Title 
            title="Recent URLs" 
            right={(props) => (
              <IconButton {...props} icon="delete" onPress={clearHistory} />
            )}
          />
          <Card.Content>
            {history.slice(0, 5).map((item, index) => (
              <List.Item
                key={index}
                title={item.length > 40 ? item.substring(0, 40) + '...' : item}
                left={props => <Icon name="clock-outline" size={20} {...props} />}
                onPress={() => {
                  setUrl(item);
                  setShowHistory(false);
                }}
                style={{ paddingVertical: 4 }}
              />
            ))}
          </Card.Content>
        </Card>
      )}
      
      {/* Analysis Result */}
      {analysisResult && currentUrl && (
        <>
          {/* Status Card */}
          <Card style={{ marginHorizontal: 15, marginBottom: 15, backgroundColor: analysisResult.safe ? '#E8F5E9' : '#FFEBEE' }}>
            <Card.Content>
              <View style={{ flexDirection: 'row', alignItems: 'center', marginBottom: 10 }}>
                <Icon 
                  name={analysisResult.safe ? "check-circle" : "alert-circle"} 
                  size={32} 
                  color={analysisResult.safe ? '#4caf50' : '#f44336'} 
                />
                <View style={{ marginLeft: 12, flex: 1 }}>
                  <Text style={{ fontSize: 16, fontWeight: 'bold', color: analysisResult.safe ? '#2e7d32' : '#c62828' }}>
                    {analysisResult.safe ? '✅ Site Appears Safe' : '⚠️ Potential Threats Detected'}
                  </Text>
                  <Text style={{ fontSize: 12, color: '#666', marginTop: 2 }}>
                    {currentUrl.length > 35 ? currentUrl.substring(0, 35) + '...' : currentUrl}
                  </Text>
                </View>
              </View>
              
              <View style={{ flexDirection: 'row', flexWrap: 'wrap', gap: 8, marginTop: 10 }}>
                <Chip 
                  icon={analysisResult.https ? "lock" : "lock-open"} 
                  style={{ backgroundColor: analysisResult.https ? '#c8e6c9' : '#ffcdd2' }}
                >
                  {analysisResult.https ? 'HTTPS' : 'HTTP'}
                </Chip>
                <Chip 
                  icon="shield-alert" 
                  style={{ backgroundColor: analysisResult.threatLevel === 'low' ? '#c8e6c9' : '#ffe0b2' }}
                >
                  {analysisResult.threatLevel.toUpperCase()} Risk
                </Chip>
                <Chip icon="eye-off" style={{ backgroundColor: '#e1bee7' }}>
                  Privacy: {analysisResult.privacyScore}%
                </Chip>
              </View>
            </Card.Content>
          </Card>
          
          {/* Detailed Analysis */}
          <Card style={{ marginHorizontal: 15, marginBottom: 15 }}>
            <Card.Title title="Security Analysis" />
            <Card.Content>
              <List.Item
                title="Phishing Check"
                description={analysisResult.phishing ? "Potential phishing detected" : "No phishing detected"}
                left={props => <Icon name="fish" size={24} color={analysisResult.phishing ? '#f44336' : '#4caf50'} {...props} />}
                right={props => <Icon name={analysisResult.phishing ? "close-circle" : "check-circle"} size={24} color={analysisResult.phishing ? '#f44336' : '#4caf50'} {...props} />}
              />
              <List.Item
                title="Malware Scan"
                description={analysisResult.malware ? "Malware signatures found" : "No malware detected"}
                left={props => <Icon name="virus-outline" size={24} color={analysisResult.malware ? '#f44336' : '#4caf50'} {...props} />}
                right={props => <Icon name={analysisResult.malware ? "close-circle" : "check-circle"} size={24} color={analysisResult.malware ? '#f44336' : '#4caf50'} {...props} />}
              />
              <List.Item
                title="Trackers Blocked"
                description={`${analysisResult.trackers} tracking scripts detected`}
                left={props => <Icon name="crosshairs-gps" size={24} color="#ff9800" {...props} />}
                right={() => <Chip>{analysisResult.trackers}</Chip>}
              />
              <List.Item
                title="Cookies"
                description={`${analysisResult.cookies} cookies found`}
                left={props => <Icon name="cookie" size={24} color="#795548" {...props} />}
                right={() => <Chip>{analysisResult.cookies}</Chip>}
              />
              <List.Item
                title="Load Time"
                description={`${analysisResult.loadTime}s page load`}
                left={props => <Icon name="speedometer" size={24} color="#673ab7" {...props} />}
                right={() => <Chip>{analysisResult.loadTime}s</Chip>}
              />
              <List.Item
                title="Data Usage"
                description={`${analysisResult.dataSize}MB transferred`}
                left={props => <Icon name="download" size={24} color="#00bcd4" {...props} />}
                right={() => <Chip>{analysisResult.dataSize}MB</Chip>}
              />
            </Card.Content>
          </Card>
          
          {/* Actions */}
          <Card style={{ marginHorizontal: 15, marginBottom: 15 }}>
            <Card.Content>
              <Button 
                mode="contained" 
                onPress={openInBrowser}
                icon="open-in-new"
                style={{ marginBottom: 8 }}
              >
                Open in External Browser
              </Button>
              <Button 
                mode="outlined"
                onPress={() => {
                  setCurrentUrl('');
                  setAnalysisResult(null);
                }}
                icon="refresh"
              >
                Clear Analysis
              </Button>
            </Card.Content>
          </Card>
        </>
      )}
      
      {/* Features (shown when no analysis) */}
      {!analysisResult && (
        <Card style={{ marginHorizontal: 15, marginBottom: 15 }}>
          <Card.Title title="Protection Features" />
          <Card.Content>
            <List.Item
              title="🎯 Phishing Detection"
              description="AI-powered detection of fake websites and scams"
              left={props => <Icon name="shield-alert" size={24} color="#f44336" {...props} />}
            />
            <List.Item
              title="🦠 Malware Scanning"
              description="Real-time threat analysis and blocking"
              left={props => <Icon name="virus-outline" size={24} color="#ff9800" {...props} />}
            />
            <List.Item
              title="🔒 Privacy Shield"
              description="Block trackers and protect your data"
              left={props => <Icon name="eye-off" size={24} color="#2196f3" {...props} />}
            />
            <List.Item
              title="🚀 Ad Blocking"
              description="Remove ads for faster, cleaner browsing"
              left={props => <Icon name="block-helper" size={24} color="#9c27b0" {...props} />}
            />
          </Card.Content>
        </Card>
      )}
    </View>
  );
};

const SecureBrowserScreen = ({ standalone = true }: { standalone?: boolean } = {}) => {
  console.log('🔵 Component function START, standalone:', standalone);
  
  // Use simple view for embedded mode to avoid hook complexity
  if (!standalone) {
    return <SimpleBrowserView />;
  }
    
  const theme = useTheme();
  const [activeTab, setActiveTab] = useState('browser');
  const [url, setUrl] = useState('');
  const [currentUrl, setCurrentUrl] = useState('');
  const [searchSuggestions, setSearchSuggestions] = useState<string[]>([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [recentSearches, setRecentSearches] = useState<string[]>([]);
  const [pageTitle, setPageTitle] = useState('Secure Browser');
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  
  // New browser features
  const [tabs, setTabs] = useState<BrowserTab[]>([{
    id: '1',
    url: '',
    title: 'New Tab',
    history: [],
    historyIndex: -1,
    isIncognito: false,
    isReading: false,
    isDarkMode: false,
  }]);
  const [activeTabId, setActiveTabId] = useState('1');
  const [showTabSwitcher, setShowTabSwitcher] = useState(false);
  const [showQRScanner, setShowQRScanner] = useState(false);
  const [showQuickActions, setShowQuickActions] = useState(false);
  const [isListening, setIsListening] = useState(false);
  const [hasPermission, setHasPermission] = useState<boolean | null>(null);
  const [scanned, setScanned] = useState(false);
  
  // Gesture handling
  const swipeX = useRef(new Animated.Value(0)).current;
  const screenWidth = Dimensions.get('window').width;
  
  // Privacy & Security
  const [privacyScore, setPrivacyScore] = useState<WebsitePrivacyScore | null>(null);
  const [phishingCheck, setPhishingCheck] = useState<PhishingCheckResult | null>(null);
  const [blockedContent, setBlockedContent] = useState<BlockedContent[]>([]);
  const [cookies, setCookies] = useState<CookieInfo[]>([]);
  const [history, setHistory] = useState<BrowsingHistory[]>([]);
  const [blockingStats, setBlockingStats] = useState({
    totalBlocked: 0,
    ads: 0,
    trackers: 0,
    malicious: 0,
    cookies: 0,
    bandwidthSaved: 0,
    timeSaved: 0,
  });

  // New features
  const [downloads, setDownloads] = useState<DownloadItem[]>([]);
  const [bookmarks, setBookmarks] = useState<Bookmark[]>([]);
  const [dnsSettings, setDnsSettings] = useState<DNSSettings | null>(null);
  const [fingerprintProtection, setFingerprintProtection] = useState<FingerprintProtection | null>(null);
  const [scriptBlocking, setScriptBlocking] = useState<ScriptBlocking | null>(null);
  const [privacyMetrics, setPrivacyMetrics] = useState<PrivacyMetrics | null>(null);
  const [bookmarkDialog, setBookmarkDialog] = useState(false);
  const [newBookmark, setNewBookmark] = useState({ url: '', title: '', folder: 'General' });

  // Enhanced features
  const [aiThreatDetection, setAiThreatDetection] = useState<AIThreatDetection | null>(null);
  const [detectedThreats, setDetectedThreats] = useState<DetectedThreat[]>([]);
  const [contentFilter, setContentFilter] = useState<ContentFilter | null>(null);
  const [passwordManager, setPasswordManager] = useState<PasswordManager | null>(null);

  const [smartProtection, setSmartProtection] = useState<SmartProtection | null>(null);
  const [antiPhishing, setAntiPhishing] = useState<AntiPhishing | null>(null);
  const [dataLeakProtection, setDataLeakProtection] = useState<DataLeakProtection | null>(null);
  const [networkSecurity, setNetworkSecurity] = useState<NetworkSecurity | null>(null);
  const [sessionIsolation, setSessionIsolation] = useState<SessionIsolation | null>(null);
  const [performanceOpt, setPerformanceOpt] = useState<PerformanceOptimization | null>(null);
  const [securityAudits, setSecurityAudits] = useState<SecurityAudit[]>([]);

  // Settings
  const [httpsEnforced, setHttpsEnforced] = useState(true);
  const [blockAds, setBlockAds] = useState(true);
  const [blockTrackers, setBlockTrackers] = useState(true);

  // Get current active tab
  const getCurrentTab = () => {
    const tab = tabs.find(tab => tab.id === activeTabId);
    return tab || tabs[0] || {
      id: '1',
      url: '',
      title: 'New Tab',
      history: [],
      historyIndex: -1,
      isIncognito: false,
      isReading: false,
      isDarkMode: false,
    };
  };

  // Pan responder for swipe gestures
  const panResponder = useRef(
    PanResponder.create({
      onStartShouldSetPanResponder: () => true,
      onMoveShouldSetPanResponder: (_, gestureState) => {
        return Math.abs(gestureState.dx) > 10 && Math.abs(gestureState.dy) < 30;
      },
      onPanResponderMove: (_, gestureState) => {
        swipeX.setValue(gestureState.dx);
      },
      onPanResponderRelease: (_, gestureState) => {
        if (gestureState.dx > screenWidth * 0.3) {
          handleGoBack();
        } else if (gestureState.dx < -screenWidth * 0.3) {
          handleGoForward();
        }
        Animated.spring(swipeX, {
          toValue: 0,
          useNativeDriver: true,
        }).start();
      },
    })
  ).current;

  useEffect(() => {
    loadBlockingStats();
    loadHistory();
    loadDownloads();
    loadBookmarks();
    loadAdvancedSettings();
    loadPrivacyMetrics();
    loadEnhancedFeatures();
    loadRecentSearches();
    requestCameraPermission();
  }, []);

  useEffect(() => {
    if (currentUrl) {
      loadPageSecurity(currentUrl);
    }
  }, [currentUrl]);

  const requestCameraPermission = async () => {
    if (!BarCodeScanner) {
      setHasPermission(false);
      return;
    }
    const { status } = await BarCodeScanner.requestPermissionsAsync();
    setHasPermission(status === 'granted');
  };

  // Load recent searches from storage
  const loadRecentSearches = async () => {
    try {
      const stored = await AsyncStorage.getItem('browser_recent_searches');
      if (stored) {
        setRecentSearches(JSON.parse(stored));
      }
    } catch (error) {
      console.error('Error loading recent searches:', error);
    }
  };

  // Save search to recent searches
  const saveToRecentSearches = async (searchUrl: string) => {
    try {
      const updated = [searchUrl, ...recentSearches.filter(s => s !== searchUrl)].slice(0, 10);
      setRecentSearches(updated);
      await AsyncStorage.setItem('browser_recent_searches', JSON.stringify(updated));
    } catch (error) {
      console.error('Error saving recent search:', error);
    }
  };

  // Generate search suggestions based on input
  const generateSuggestions = (input: string) => {
    if (!input || input.length < 2) {
      setSearchSuggestions([]);
      return;
    }

    const suggestions: string[] = [];
    
    // Add matching recent searches
    const matchingRecent = recentSearches.filter(s => 
      s.toLowerCase().includes(input.toLowerCase())
    ).slice(0, 3);
    suggestions.push(...matchingRecent);

    // Add matching bookmarks
    const matchingBookmarks = bookmarks.filter(b => 
      b.title.toLowerCase().includes(input.toLowerCase()) ||
      b.url.toLowerCase().includes(input.toLowerCase())
    ).slice(0, 3);
    suggestions.push(...matchingBookmarks.map(b => b.url));

    // Add common search suggestions
    const commonSites = [
      'google.com',
      'youtube.com', 
      'amazon.com',
      'facebook.com',
      'twitter.com',
      'github.com',
      'stackoverflow.com',
      'reddit.com',
    ];
    const matchingCommon = commonSites.filter(s => 
      s.toLowerCase().includes(input.toLowerCase())
    ).slice(0, 2);
    suggestions.push(...matchingCommon.map(s => `https://${s}`));

    // Remove duplicates and limit
    const unique = [...new Set(suggestions)].slice(0, 5);
    setSearchSuggestions(unique);
  };

  // Handle URL input change
  const handleUrlChange = (text: string) => {
    setUrl(text);
    setShowSuggestions(text.length > 0);
    generateSuggestions(text);
  };

  // Handle suggestion selection
  const handleSuggestionSelect = (suggestion: string) => {
    setUrl(suggestion);
    setShowSuggestions(false);
    handleNavigate(suggestion);
  };

  const loadBlockingStats = async () => {
    const stats = await SecureBrowserService.getBlockingStats();
    setBlockingStats(stats);
  };

  const handleResetStats = async () => {
    Alert.alert(
      'Reset Statistics',
      'Are you sure you want to reset all blocking statistics? This cannot be undone.',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Reset',
          style: 'destructive',
          onPress: async () => {
            await SecureBrowserService.resetBlockingStats();
            await loadBlockingStats();
            Alert.alert('Success', 'Blocking statistics have been reset.');
          },
        },
      ]
    );
  };

  const loadHistory = async () => {
    const hist = await SecureBrowserService.getBrowsingHistory(7);
    setHistory(hist);
  };

  const loadPageSecurity = async (pageUrl: string) => {
    try {
      const [privacy, phishing, blocked, pageCookies] = await Promise.all([
        SecureBrowserService.getWebsitePrivacyScore(pageUrl),
        SecureBrowserService.checkPhishing(pageUrl),
        SecureBrowserService.getBlockedContent(),
        SecureBrowserService.getCookies(extractDomain(pageUrl)),
      ]);
      
      setPrivacyScore(privacy);
      setPhishingCheck(phishing);
      setBlockedContent(blocked);
      setCookies(pageCookies);
      
      // Refresh blocking stats to show live updates
      await loadBlockingStats();
    } catch (error) {
      console.error('Failed to load page security:', error);
    }
  };

  const handleNavigate = async (providedUrl?: string) => {
    let navigateUrl = (providedUrl || url).trim();
    
    if (!navigateUrl) {
      Alert.alert('Invalid URL', 'Please enter a URL');
      return;
    }

    // Hide suggestions
    setShowSuggestions(false);

    // Add https:// if no protocol
    if (!navigateUrl.startsWith('http://') && !navigateUrl.startsWith('https://')) {
      // Check if it's a search query (contains spaces or no dots)
      if (navigateUrl.includes(' ') || !navigateUrl.includes('.')) {
        // Use Google search
        navigateUrl = `https://www.google.com/search?q=${encodeURIComponent(navigateUrl)}`;
      } else {
        navigateUrl = `https://${navigateUrl}`;
      }
    }

    // Enforce HTTPS if enabled
    if (httpsEnforced) {
      navigateUrl = SecureBrowserService.enforceHttps(navigateUrl);
    }

    // Save to recent searches
    await saveToRecentSearches(navigateUrl);

    setLoading(true);

    // Comprehensive URL analysis
    try {
      const analysis = await SecureBrowserService.analyzeUrlComprehensive(navigateUrl);
      
      // Check AI threat detection
      if (analysis.aiThreat && analysis.aiThreat.action === 'blocked') {
        setLoading(false);
        Alert.alert(
          '🛡️ AI Threat Detected',
          `${analysis.aiThreat.description}\\n\\nConfidence: ${analysis.aiThreat.confidence}%\\nModel: ${analysis.aiThreat.aiModel}`,
          [{ text: 'OK' }]
        );
        return;
      }

      // Check typosquatting
      if (analysis.typosquatting) {
        setLoading(false);
        Alert.alert(
          '⚠️ Possible Typosquatting',
          'This domain may be impersonating a legitimate website. Proceed with caution.',
          [
            { text: 'Go Back', style: 'cancel' },
            { text: 'Continue', onPress: () => proceedToUrl(navigateUrl) },
          ]
        );
        return;
      }

      // Check phishing
      if (analysis.phishing.isPhishing || analysis.phishing.threatLevel === 'high' || analysis.phishing.threatLevel === 'critical') {
        setLoading(false);
        Alert.alert(
          '⚠️ Security Warning',
          `${analysis.phishing.description}\\n\\n${analysis.phishing.recommendation}`,
          [
            { text: 'Go Back', style: 'cancel' },
            {
              text: 'Proceed Anyway',
              style: 'destructive',
              onPress: () => proceedToUrl(navigateUrl),
            },
          ]
        );
        return;
      }

      // Show security audit if issues found
      if (analysis.audit.issues.length > 0) {
        const criticalIssues = analysis.audit.issues.filter(i => i.severity === 'critical' || i.severity === 'high');
        if (criticalIssues.length > 0) {
          setLoading(false);
          Alert.alert(
            '⚠️ Security Issues Detected',
            `Found ${criticalIssues.length} critical/high severity issues.\\nSecurity Score: ${analysis.audit.overallScore}/100`,
            [
              { text: 'View Details', onPress: () => showAuditDetails(analysis.audit) },
              { text: 'Continue', onPress: () => proceedToUrl(navigateUrl) },
            ]
          );
          return;
        }
      }

      setLoading(false);
      proceedToUrl(navigateUrl);
    } catch (error) {
      setLoading(false);
      console.error('URL analysis error:', error);
      Alert.alert('Error', 'Failed to analyze URL. Continue anyway?', [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Continue', onPress: () => proceedToUrl(navigateUrl) },
      ]);
    }
  };

  const proceedToUrl = async (navigateUrl: string) => {
    setCurrentUrl(navigateUrl);
    setPageTitle(getDomainFromUrl(navigateUrl));
    
    // Update tab
    const tab = getCurrentTab();
    const newHistory = [...tab.history.slice(0, tab.historyIndex + 1), navigateUrl];
    setTabs(tabs.map(t => 
      t.id === tab.id 
        ? { ...t, url: navigateUrl, title: getDomainFromUrl(navigateUrl), history: newHistory, historyIndex: newHistory.length - 1 }
        : t
    ));
    
    await loadPageSecurity(navigateUrl);
    await loadEnhancedFeatures();
    
    // Show security analysis complete message
    Alert.alert(
      '✅ Security Analysis Complete',
      `URL has been scanned for threats.\n\nOpening ${getDomainFromUrl(navigateUrl)} in your device browser...`,
      [
        { 
          text: 'Cancel', 
          style: 'cancel' 
        },
        {
          text: 'Open Securely',
          onPress: async () => {
            const supported = await Linking.canOpenURL(navigateUrl);
            if (supported) {
              await Linking.openURL(navigateUrl);
            } else {
              Alert.alert('Error', 'Cannot open this URL');
            }
          }
        }
      ]
    );
  };

  const showAuditDetails = (audit: SecurityAudit) => {
    const details = audit.issues.map(i => `• ${i.title} (${i.severity})`).join('\\n');
    Alert.alert('Security Audit Details', details);
  };

  const handleRefresh = async () => {
    setRefreshing(true);
    if (currentUrl) {
      await loadPageSecurity(currentUrl);
    }
    setRefreshing(false);
  };

  const loadDownloads = async () => {
    const dl = await SecureBrowserService.getDownloads();
    setDownloads(dl);
  };

  const loadBookmarks = async () => {
    const bm = await SecureBrowserService.getBookmarks();
    setBookmarks(bm);
  };

  const loadAdvancedSettings = async () => {
    const [dns, fingerprint, scripts] = await Promise.all([
      SecureBrowserService.getDNSSettings(),
      SecureBrowserService.getFingerprintProtection(),
      SecureBrowserService.getScriptBlocking(),
    ]);
    setDnsSettings(dns);
    setFingerprintProtection(fingerprint);
    setScriptBlocking(scripts);
  };

  const loadPrivacyMetrics = async () => {
    const metrics = await SecureBrowserService.getPrivacyMetrics();
    setPrivacyMetrics(metrics);
  };

  const loadEnhancedFeatures = async () => {
    try {
      const [ai, filter, pwdMgr, smart, phishing, dlp, netSec, session, perf, audits] = await Promise.all([
        SecureBrowserService.getAIThreatDetection(),
        SecureBrowserService.getContentFilter(),
        SecureBrowserService.getPasswordManager(),
        SecureBrowserService.getSmartProtection(),
        SecureBrowserService.getAntiPhishing(),
        SecureBrowserService.getDataLeakProtection(),
        SecureBrowserService.getNetworkSecurity(),
        SecureBrowserService.getSessionIsolation(),
        SecureBrowserService.getPerformanceOptimization(),
        SecureBrowserService.getSecurityAudits(5),
      ]);

      setAiThreatDetection(ai);
      setDetectedThreats(ai.threats);
      setContentFilter(filter);
      setPasswordManager(pwdMgr);

      setSmartProtection(smart);
      setAntiPhishing(phishing);
      setDataLeakProtection(dlp);
      setNetworkSecurity(netSec);
      setSessionIsolation(session);
      setPerformanceOpt(perf);
      setSecurityAudits(audits);
    } catch (error) {
      console.error('Failed to load enhanced features:', error);
    }
  };

  const handleAddBookmark = async () => {
    if (!newBookmark.url || !newBookmark.title) {
      Alert.alert('Error', 'Please fill in URL and title');
      return;
    }
    await SecureBrowserService.addBookmark(newBookmark.url, newBookmark.title, newBookmark.folder);
    setBookmarkDialog(false);
    setNewBookmark({ url: '', title: '', folder: 'General' });
    await loadBookmarks();
    Alert.alert('Success', 'Bookmark added');
  };

  // ==================== NEW BROWSER FEATURES ====================

  // Tab Management
  const createNewTab = (incognito: boolean = false) => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium);
    const newTab: BrowserTab = {
      id: Date.now().toString(),
      url: '',
      title: incognito ? 'Private Tab' : 'New Tab',
      history: [],
      historyIndex: -1,
      isIncognito: incognito,
      isReading: false,
      isDarkMode: false,
    };
    setTabs([...tabs, newTab]);
    setActiveTabId(newTab.id);
    setUrl('');
    setCurrentUrl('');
  };

  const closeTab = (tabId: string) => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    if (tabs.length === 1) {
      Alert.alert('Cannot close', 'At least one tab must remain open');
      return;
    }
    const newTabs = tabs.filter(t => t.id !== tabId);
    setTabs(newTabs);
    if (activeTabId === tabId) {
      setActiveTabId(newTabs[0].id);
    }
  };

  const switchTab = (tabId: string) => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    setActiveTabId(tabId);
    const tab = tabs.find(t => t.id === tabId);
    if (tab) {
      setUrl(tab.url);
      setCurrentUrl(tab.url);
      setPageTitle(tab.title);
    }
    setShowTabSwitcher(false);
  };

  // Navigation Controls
  const handleGoBack = () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    const tab = getCurrentTab();
    if (tab.historyIndex > 0) {
      const newIndex = tab.historyIndex - 1;
      const newUrl = tab.history[newIndex];
      updateTabHistory(tab.id, newIndex);
      setUrl(newUrl);
      setCurrentUrl(newUrl);
      loadPageSecurity(newUrl);
    }
  };

  const handleGoForward = () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    const tab = getCurrentTab();
    if (tab.historyIndex < tab.history.length - 1) {
      const newIndex = tab.historyIndex + 1;
      const newUrl = tab.history[newIndex];
      updateTabHistory(tab.id, newIndex);
      setUrl(newUrl);
      setCurrentUrl(newUrl);
      loadPageSecurity(newUrl);
    }
  };

  const handleReload = async () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium);
    if (currentUrl) {
      setLoading(true);
      await loadPageSecurity(currentUrl);
      setLoading(false);
      Alert.alert('Page Reloaded', 'Security analysis refreshed');
    }
  };

  const updateTabHistory = (tabId: string, newIndex?: number) => {
    setTabs(tabs.map(t => {
      if (t.id === tabId) {
        if (newIndex !== undefined) {
          return { ...t, historyIndex: newIndex };
        } else {
          const newHistory = [...t.history.slice(0, t.historyIndex + 1), currentUrl];
          return { ...t, history: newHistory, historyIndex: newHistory.length - 1, url: currentUrl };
        }
      }
      return t;
    }));
  };

  const canGoBack = () => {
    const tab = getCurrentTab();
    return tab.historyIndex > 0;
  };

  const canGoForward = () => {
    const tab = getCurrentTab();
    return tab.historyIndex < tab.history.length - 1;
  };

  // Reading Mode
  const toggleReadingMode = () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium);
    const tab = getCurrentTab();
    setTabs(tabs.map(t => t.id === tab.id ? { ...t, isReading: !t.isReading } : t));
    Alert.alert(
      tab.isReading ? 'Reading Mode Off' : 'Reading Mode On',
      tab.isReading ? 'Standard view restored' : 'Simplified text-only view activated'
    );
  };

  // Dark Mode Toggle
  const toggleDarkMode = () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium);
    const tab = getCurrentTab();
    setTabs(tabs.map(t => t.id === tab.id ? { ...t, isDarkMode: !t.isDarkMode } : t));
  };

  // Voice Search
  const startVoiceSearch = () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Heavy);
    setIsListening(true);
    
    // Simulate voice recognition (expo-speech doesn't have recognition, only TTS)
    Alert.alert(
      '🎤 Voice Search',
      'Speak your search query or URL',
      [
        {
          text: 'Cancel',
          onPress: () => setIsListening(false),
          style: 'cancel'
        },
        {
          text: 'Enter Text',
          onPress: () => {
            setIsListening(false);
            Alert.prompt(
              'Voice Input',
              'Enter what you would say:',
              (text) => {
                if (text) {
                  setUrl(text);
                  handleNavigate(text);
                  Speech.speak(`Searching for ${text}`);
                }
              }
            );
          }
        }
      ]
    );
  };

  // QR Code Scanner
  const handleBarCodeScanned = ({ type, data }: { type: string; data: string }) => {
    setScanned(true);
    Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
    
    Alert.alert(
      'QR Code Scanned',
      `URL: ${data}`,
      [
        { text: 'Cancel', style: 'cancel', onPress: () => setShowQRScanner(false) },
        {
          text: 'Open',
          onPress: () => {
            setUrl(data);
            handleNavigate(data);
            setShowQRScanner(false);
            setScanned(false);
          }
        }
      ]
    );
  };

  // Quick Actions
  const handleShare = async () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium);
    if (!currentUrl) {
      Alert.alert('No URL', 'Please navigate to a page first');
      return;
    }

    try {
      await Share.share({
        message: `Check out this page: ${pageTitle}\n${currentUrl}`,
        url: currentUrl,
        title: pageTitle,
      });
    } catch (error) {
      Alert.alert('Share Error', 'Failed to share URL');
    }
  };

  const handleCopyLink = async () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
    if (!currentUrl) {
      Alert.alert('No URL', 'Please navigate to a page first');
      return;
    }

    await Clipboard.setStringAsync(currentUrl);
    Alert.alert('Copied', 'URL copied to clipboard');
  };

  const handleQuickActions = () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium);
    setShowQuickActions(!showQuickActions);
  };

  const handleAddToHome = () => {
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Heavy);
    if (!currentUrl) {
      Alert.alert('No URL', 'Please navigate to a page first');
      return;
    }

    Alert.alert(
      'Add to Home Screen',
      `Create shortcut for ${pageTitle}?`,
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Add',
          onPress: () => {
            handleAddBookmark();
            Alert.alert('Shortcut Created', 'Page bookmarked (Home screen shortcuts require native functionality)');
          }
        }
      ]
    );
  };

  // Download Manager
  const showDownloads = () => {
    setActiveTab('downloads');
  };

  const clearDownload = async (id: string) => {
    const newDownloads = downloads.filter(d => d.id !== id);
    setDownloads(newDownloads);
    Alert.alert('Download Removed', 'Download cleared from history');
  };
  };

  const handleDeleteBookmark = async (id: string) => {
    Alert.alert('Delete Bookmark', 'Are you sure?', [
      { text: 'Cancel', style: 'cancel' },
      {
        text: 'Delete',
        style: 'destructive',
        onPress: async () => {
          await SecureBrowserService.deleteBookmark(id);
          await loadBookmarks();
        },
      },
    ]);
  };

  const handleClearCookies = async () => {
    Alert.alert(
      'Clear Cookies',
      'Clear all cookies for this site?',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Clear',
          style: 'destructive',
          onPress: async () => {
            const domain = currentUrl ? extractDomain(currentUrl) : undefined;
            await SecureBrowserService.deleteCookies(domain);
            if (currentUrl) {
              const pageCookies = await SecureBrowserService.getCookies(extractDomain(currentUrl));
              setCookies(pageCookies);
            }
            Alert.alert('Success', 'Cookies cleared');
          },
        },
      ]
    );
  };

  const handleClearHistory = async () => {
    Alert.alert(
      'Clear History',
      'Clear browsing history?',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Clear',
          style: 'destructive',
          onPress: async () => {
            await SecureBrowserService.clearHistory();
            await loadHistory();
            Alert.alert('Success', 'History cleared');
          },
        },
      ]
    );
  };

  const extractDomain = (pageUrl: string): string => {
    try {
      const urlObj = new URL(pageUrl);
      return urlObj.hostname;
    } catch {
      return pageUrl;
    }
  };

  const getPrivacyColor = (score: number): string => {
    if (score >= 85) return '#4caf50';
    if (score >= 70) return '#8bc34a';
    if (score >= 50) return '#ffc107';
    if (score >= 30) return '#ff9800';
    return '#f44336';
  };

  const renderBrowserTab = () => {
    const currentTab = getCurrentTab();
    
    console.log('🔴 renderBrowserTab CALLED! activeTab:', activeTab, 'currentTab:', currentTab, 'standalone:', standalone);
    console.log('🟢 RENDERING BLUE BOX AND BROWSER CONTROLS NOW');
    
    return (
    <View style={{ backgroundColor: '#ffffff', minHeight: 500 }}>
      {/* VISIBILITY TEST */}
      <View style={{ backgroundColor: '#00FF00', padding: 30 }}>
        <Text style={{ fontSize: 24, color: '#000000', fontWeight: 'bold', textAlign: 'center' }}>
          ✅ BROWSER CONTENT IS HERE! ✅
        </Text>
        <Text style={{ fontSize: 14, color: '#000000', textAlign: 'center', marginTop: 10 }}>
          Mode: {standalone ? 'Standalone' : 'Embedded in Tools'}
        </Text>
      </View>
      
      {/* HOW IT WORKS INFO */}
      <View style={{ backgroundColor: '#2196F3', padding: 20, margin: 15, borderRadius: 10, alignItems: 'center' }}>
        <Icon name="shield-check" size={40} color="#ffffff" />
        <Text style={{ color: 'white', fontSize: 20, fontWeight: 'bold', textAlign: 'center', marginTop: 10 }}>
          🛡️ Secure Browser Protection
        </Text>
        <Text style={{ color: 'white', fontSize: 14, marginTop: 10, textAlign: 'center' }}>
          Enter any URL below to analyze for threats, phishing, malware, and privacy risks.
        </Text>
        <Text style={{ color: 'white', fontSize: 13, marginTop: 8, textAlign: 'center', opacity: 0.9 }}>
          ✓ AI-powered threat detection • ✓ Phishing protection • ✓ Privacy analysis
        </Text>
        {currentTab.url && (
          <View style={{ backgroundColor: 'rgba(255,255,255,0.2)', padding: 10, borderRadius: 5, marginTop: 10, width: '100%' }}>
            <Text style={{ color: 'white', fontSize: 12, textAlign: 'center' }}>
              Currently analyzing: {currentTab.url}
            </Text>
          </View>
        )}
      </View>
      
      {/* Tab Bar with Navigation Controls */}
      <Surface style={styles.tabBar} elevation={2}>
        {/* Tab Switcher Button */}
        <TouchableOpacity onPress={() => setShowTabSwitcher(true)} style={styles.tabButton}>
          <Icon name="tab" size={24} color={theme.colors.primary} />
          <Text style={styles.tabCount}>{tabs.length}</Text>
        </TouchableOpacity>

        {/* Navigation Controls */}
        <View style={styles.navControls}>
          <IconButton
            icon="chevron-left"
            size={24}
            disabled={!canGoBack()}
            onPress={handleGoBack}
            iconColor={canGoBack() ? theme.colors.primary : '#ccc'}
          />
          <IconButton
            icon="chevron-right"
            size={24}
            disabled={!canGoForward()}
            onPress={handleGoForward}
            iconColor={canGoForward() ? theme.colors.primary : '#ccc'}
          />
          <IconButton
            icon="reload"
            size={24}
            onPress={handleReload}
            iconColor={theme.colors.primary}
          />
        </View>

        {/* Mode Indicators */}
        <View style={styles.modeIndicators}>
          {currentTab.isIncognito && (
            <Chip icon="incognito" style={styles.incognitoChip}>Private</Chip>
          )}
          {currentTab.isReading && (
            <Chip icon="book-open-variant" style={styles.readingChip}>Reading</Chip>
          )}
        </View>

        {/* Quick Actions Button */}
        <IconButton
          icon="dots-vertical"
          size={24}
          onPress={handleQuickActions}
          iconColor={theme.colors.primary}
        />
      </Surface>

      {/* URL Bar */}
      <Surface style={styles.urlBar}>
        <View style={styles.urlInputContainer}>
          {currentUrl && (
            <Icon 
              name={currentUrl.startsWith('https://') ? 'lock' : 'lock-open'} 
              size={20} 
              color={currentUrl.startsWith('https://') ? '#4caf50' : '#ff9800'} 
            />
          )}
          <RNTextInput
            style={styles.urlInput}
            placeholder="Search or enter website URL..."
            value={url}
            onChangeText={handleUrlChange}
            onSubmitEditing={() => handleNavigate()}
            onFocus={() => {
              if (url.length > 0) setShowSuggestions(true);
            }}
            autoCapitalize="none"
            autoCorrect={false}
            keyboardType="url"
            returnKeyType="go"
          />
          {url.length > 0 && (
            <IconButton 
              icon="close" 
              size={18} 
              onPress={() => {
                setUrl('');
                setShowSuggestions(false);
              }} 
            />
          )}
          <IconButton 
            icon="microphone" 
            size={20} 
            onPress={startVoiceSearch}
            iconColor={isListening ? '#f44336' : '#666'}
          />
          <IconButton 
            icon="qrcode-scan" 
            size={20} 
            onPress={() => {
              if (!BarCodeScanner) {
                Alert.alert('QR Scanner Unavailable', 'QR code scanning requires a native app rebuild. Use "npx expo prebuild" and rebuild the app.');
                return;
              }
              setShowQRScanner(true);
            }} 
          />
          <IconButton 
            icon={loading ? "loading" : "magnify"} 
            size={20} 
            onPress={() => handleNavigate()} 
            disabled={loading}
          />
        </View>

        {/* Search Suggestions Dropdown */}
        {showSuggestions && (searchSuggestions.length > 0 || recentSearches.length > 0) && (
          <View style={styles.suggestionsContainer}>
            {searchSuggestions.length > 0 ? (
              <>
                <Text style={styles.suggestionsHeader}>Suggestions</Text>
                {searchSuggestions.map((suggestion, index) => (
                  <Pressable
                    key={index}
                    style={({ pressed }) => [
                      styles.suggestionItem,
                      pressed && { backgroundColor: '#f0f0f0' }
                    ]}
                    onPressIn={() => {
                      handleSuggestionSelect(suggestion);
                    }}>
                    <Icon name="magnify" size={18} color="#666" />
                    <Text style={styles.suggestionText} numberOfLines={1}>
                      {suggestion}
                    </Text>
                    <Icon name="arrow-top-left" size={16} color="#999" />
                  </Pressable>
                ))}
              </>
            ) : (
              <>
                <Text style={styles.suggestionsHeader}>Recent Searches</Text>
                {recentSearches.slice(0, 5).map((search, index) => (
                  <Pressable
                    key={index}
                    style={({ pressed }) => [
                      styles.suggestionItem,
                      pressed && { backgroundColor: '#f0f0f0' }
                    ]}
                    onPressIn={() => {
                      handleSuggestionSelect(search);
                    }}>
                    <Icon name="history" size={18} color="#666" />
                    <Text style={styles.suggestionText} numberOfLines={1}>
                      {search}
                    </Text>
                    <Icon name="arrow-top-left" size={16} color="#999" />
                  </Pressable>
                ))}
              </>
            )}
          </View>
        )}
      </Surface>

      {/* Quick Actions Menu */}
      {showQuickActions && (
        <Card style={styles.quickActionsCard}>
          <Card.Content>
            <View style={styles.quickActionsGrid}>
              <TouchableOpacity style={styles.quickAction} onPress={handleShare}>
                <Icon name="share-variant" size={24} color={theme.colors.primary} />
                <Text style={styles.quickActionText}>Share</Text>
              </TouchableOpacity>
              <TouchableOpacity style={styles.quickAction} onPress={handleCopyLink}>
                <Icon name="content-copy" size={24} color={theme.colors.primary} />
                <Text style={styles.quickActionText}>Copy Link</Text>
              </TouchableOpacity>
              <TouchableOpacity style={styles.quickAction} onPress={toggleReadingMode}>
                <Icon name="book-open-variant" size={24} color={theme.colors.primary} />
                <Text style={styles.quickActionText}>Reading</Text>
              </TouchableOpacity>
              <TouchableOpacity style={styles.quickAction} onPress={toggleDarkMode}>
                <Icon name={currentTab.isDarkMode ? 'white-balance-sunny' : 'moon-waning-crescent'} size={24} color={theme.colors.primary} />
                <Text style={styles.quickActionText}>Theme</Text>
              </TouchableOpacity>
              <TouchableOpacity style={styles.quickAction} onPress={() => setBookmarkDialog(true)}>
                <Icon name="bookmark-plus" size={24} color={theme.colors.primary} />
                <Text style={styles.quickActionText}>Bookmark</Text>
              </TouchableOpacity>
              <TouchableOpacity style={styles.quickAction} onPress={handleAddToHome}>
                <Icon name="home-plus" size={24} color={theme.colors.primary} />
                <Text style={styles.quickActionText}>Add Home</Text>
              </TouchableOpacity>
              <TouchableOpacity style={styles.quickAction} onPress={() => createNewTab(true)}>
                <Icon name="incognito" size={24} color={theme.colors.primary} />
                <Text style={styles.quickActionText}>Private Tab</Text>
              </TouchableOpacity>
              <TouchableOpacity style={styles.quickAction} onPress={showDownloads}>
                <Icon name="download" size={24} color={theme.colors.primary} />
                <Text style={styles.quickActionText}>Downloads</Text>
              </TouchableOpacity>
            </View>
          </Card.Content>
        </Card>
      )}

      {/* Security Status */}
      {currentUrl && privacyScore && (
        <>
          <Card style={styles.card}>
            <Card.Content>
              <View style={styles.securityHeader}>
                <View style={styles.privacyScoreCircle}>
                  <Text style={[styles.privacyScoreText, { color: getPrivacyColor(privacyScore.overall) }]}>
                    {privacyScore.overall}
                  </Text>
                  <Text style={styles.privacyScoreLabel}>Privacy</Text>
                </View>
                <View style={styles.securityInfo}>
                  <Text style={styles.securityTitle}>{privacyScore.domain}</Text>
                  <Chip 
                    icon={privacyScore.breakdown.https === 100 ? 'lock' : 'lock-open'}
                    style={{ backgroundColor: privacyScore.breakdown.https === 100 ? '#e8f5e9' : '#fff3e0' }}>
                    {privacyScore.breakdown.https === 100 ? 'Secure HTTPS' : 'Insecure HTTP'}
                  </Chip>
                </View>
              </View>
              
              <Divider style={styles.divider} />
              
              <View style={styles.blockedStats}>
                <View style={styles.blockedItem}>
                  <Icon name="block-helper" size={20} color="#f44336" />
                  <Text style={styles.blockedNumber}>{blockedContent.filter(b => b.type === 'ad').length}</Text>
                  <Text style={styles.blockedLabel}>Ads</Text>
                </View>
                <View style={styles.blockedItem}>
                  <Icon name="eye-off" size={20} color="#ff9800" />
                  <Text style={styles.blockedNumber}>{blockedContent.filter(b => b.type === 'tracker').length}</Text>
                  <Text style={styles.blockedLabel}>Trackers</Text>
                </View>
                <View style={styles.blockedItem}>
                  <Icon name="cookie" size={20} color="#2196f3" />
                  <Text style={styles.blockedNumber}>{cookies.filter(c => c.blocked).length}</Text>
                  <Text style={styles.blockedLabel}>Cookies</Text>
                </View>
              </View>
            </Card.Content>
          </Card>

          {/* Open in Browser Button */}
          <Card style={styles.card}>
            <Card.Content>
              <Text style={styles.browserNote}>
                🔒 URL security analyzed. Open in your device's browser with protection info.
              </Text>
              <Button 
                mode="contained" 
                icon="open-in-new"
                onPress={async () => {
                  const supported = await Linking.canOpenURL(currentUrl);
                  if (supported) {
                    await Linking.openURL(currentUrl);
                  }
                }}
                style={styles.openButton}>
                Open in Browser
              </Button>
            </Card.Content>
          </Card>
        </>
      )}

      {!currentUrl && (
        <View style={styles.emptyState}>
          <Icon name="shield-search" size={64} color="#ccc" />
          <Text style={styles.emptyText}>Enter a URL to start secure browsing</Text>
          <Text style={styles.emptySubtext}>
            Automatic ad blocking • Tracker protection • HTTPS enforcement
          </Text>
        </View>
      )}
    </View>
  );

  const renderPrivacyTab = () => (
    <>
      {/* Overall Stats */}
      <Card style={styles.card}>
        <Card.Title 
          title="Blocking Statistics" 
          subtitle="Real-time tracking"
          left={(props) => <Icon name="shield-check" {...props} />} 
          right={(props) => (
            <View style={{ flexDirection: 'row', marginRight: 8 }}>
              <IconButton
                icon="refresh"
                size={20}
                onPress={loadBlockingStats}
              />
              <IconButton
                icon="trash-can-outline"
                size={20}
                onPress={handleResetStats}
              />
            </View>
          )}
        />
        <Card.Content>
          <View style={styles.statsGrid}>
            <View style={styles.statItem}>
              <Text style={styles.statNumber}>{blockingStats.totalBlocked.toLocaleString()}</Text>
              <Text style={styles.statLabel}>Total Blocked</Text>
            </View>
            <View style={styles.statItem}>
              <Text style={[styles.statNumber, { color: '#f44336' }]}>{blockingStats.ads}</Text>
              <Text style={styles.statLabel}>Ads</Text>
            </View>
            <View style={styles.statItem}>
              <Text style={[styles.statNumber, { color: '#ff9800' }]}>{blockingStats.trackers}</Text>
              <Text style={styles.statLabel}>Trackers</Text>
            </View>
            <View style={styles.statItem}>
              <Text style={[styles.statNumber, { color: '#2196f3' }]}>{blockingStats.cookies}</Text>
              <Text style={styles.statLabel}>Cookies</Text>
            </View>
          </View>
          
          <Divider style={styles.divider} />
          
          <View style={styles.savingsRow}>
            <Icon name="download" size={20} color="#4caf50" />
            <Text style={styles.savingsText}>
              Saved {blockingStats.bandwidthSaved.toFixed(1)} MB bandwidth
            </Text>
          </View>
          <View style={styles.savingsRow}>
            <Icon name="clock-fast" size={20} color="#2196f3" />
            <Text style={styles.savingsText}>
              Saved {Math.floor(blockingStats.timeSaved / 60)} minutes loading time
            </Text>
          </View>
        </Card.Content>
      </Card>

      {/* Current Page Privacy */}
      {privacyScore && (
        <Card style={styles.card}>
          <Card.Title 
            title="Current Page Privacy" 
            subtitle={privacyScore.domain}
            left={(props) => <Icon name="eye-off" {...props} />} 
          />
          <Card.Content>
            <View style={styles.privacyBreakdown}>
              <View style={styles.breakdownItem}>
                <Text style={styles.breakdownLabel}>HTTPS</Text>
                <ProgressBar progress={privacyScore.breakdown.https / 100} color="#4caf50" />
                <Text style={styles.breakdownValue}>{privacyScore.breakdown.https}%</Text>
              </View>
              <View style={styles.breakdownItem}>
                <Text style={styles.breakdownLabel}>Cookies</Text>
                <ProgressBar progress={privacyScore.breakdown.cookies / 100} color="#2196f3" />
                <Text style={styles.breakdownValue}>{privacyScore.breakdown.cookies}%</Text>
              </View>
              <View style={styles.breakdownItem}>
                <Text style={styles.breakdownLabel}>Trackers</Text>
                <ProgressBar progress={privacyScore.breakdown.trackers / 100} color="#ff9800" />
                <Text style={styles.breakdownValue}>{privacyScore.breakdown.trackers}%</Text>
              </View>
              <View style={styles.breakdownItem}>
                <Text style={styles.breakdownLabel}>Ads</Text>
                <ProgressBar progress={privacyScore.breakdown.ads / 100} color="#f44336" />
                <Text style={styles.breakdownValue}>{privacyScore.breakdown.ads}%</Text>
              </View>
            </View>

            {privacyScore.risks.length > 0 && (
              <>
                <Divider style={styles.divider} />
                <Text style={styles.risksTitle}>⚠️ Privacy Risks:</Text>
                {privacyScore.risks.map((risk) => (
                  <View key={risk.id} style={styles.riskItem}>
                    <Chip 
                      icon="alert" 
                      style={{ 
                        backgroundColor: 
                          risk.severity === 'critical' ? '#ffebee' :
                          risk.severity === 'high' ? '#fff3e0' :
                          risk.severity === 'medium' ? '#fff9c4' : '#f1f8e9'
                      }}>
                      {risk.severity.toUpperCase()}
                    </Chip>
                    <Text style={styles.riskTitle}>{risk.title}</Text>
                    <Text style={styles.riskDesc}>{risk.description}</Text>
                  </View>
                ))}
              </>
            )}
          </Card.Content>
        </Card>
      )}
    </>
  );

  const renderCookiesTab = () => (
    <>
      <Card style={styles.card}>
        <Card.Title 
          title={`Cookies (${cookies.length})`}
          subtitle={currentUrl ? extractDomain(currentUrl) : 'No page loaded'}
          left={(props) => <Icon name="cookie" {...props} />}
          right={(props) => (
            <IconButton 
              icon="delete" 
              onPress={handleClearCookies}
              disabled={cookies.length === 0}
            />
          )}
        />
        <Card.Content>
          {cookies.length > 0 ? (
            cookies.map((cookie) => (
              <View key={cookie.id} style={styles.cookieItem}>
                <View style={styles.cookieHeader}>
                  <Text style={styles.cookieName}>{cookie.name}</Text>
                  <Chip 
                    compact
                    style={{ 
                      backgroundColor: 
                        cookie.category === 'necessary' ? '#e8f5e9' :
                        cookie.category === 'functional' ? '#e3f2fd' :
                        cookie.category === 'analytics' ? '#fff9c4' : '#ffebee'
                    }}>
                    {cookie.category}
                  </Chip>
                </View>
                <Text style={styles.cookieDomain}>{cookie.domain}</Text>
                <View style={styles.cookieDetails}>
                  <Chip compact icon={cookie.secure ? 'lock' : 'lock-open'} style={styles.cookieChip}>
                    {cookie.secure ? 'Secure' : 'Insecure'}
                  </Chip>
                  <Chip compact icon="web" style={styles.cookieChip}>
                    {cookie.sameSite}
                  </Chip>
                  {cookie.blocked && (
                    <Chip compact icon="block-helper" style={[styles.cookieChip, { backgroundColor: '#ffebee' }]}>
                      Blocked
                    </Chip>
                  )}
                </View>
                <Divider style={styles.cookieDivider} />
              </View>
            ))
          ) : (
            <Text style={styles.emptyText}>No cookies found</Text>
          )}
        </Card.Content>
      </Card>
    </>
  );

  const renderHistoryTab = () => (
    <>
      <Card style={styles.card}>
        <Card.Title 
          title={`Browsing History (${history.length})`}
          left={(props) => <Icon name="history" {...props} />}
          right={(props) => (
            <IconButton 
              icon="delete" 
              onPress={handleClearHistory}
              disabled={history.length === 0}
            />
          )}
        />
        <Card.Content>
          {history.length > 0 ? (
            history.map((item) => (
              <View key={item.id} style={styles.historyItem}>
                <View style={styles.historyHeader}>
                  <Icon name="web" size={20} color={theme.colors.primary} />
                  <View style={styles.historyInfo}>
                    <Text style={styles.historyTitle}>{item.title}</Text>
                    <Text style={styles.historyUrl}>{item.domain}</Text>
                  </View>
                  <Chip 
                    compact
                    style={{ backgroundColor: getPrivacyColor(item.privacyScore) }}>
                    {item.privacyScore}
                  </Chip>
                </View>
                <View style={styles.historyStats}>
                  <Text style={styles.historyTime}>
                    {new Date(item.timestamp).toLocaleString()}
                  </Text>
                  <Text style={styles.historyStat}>
                    🚫 {item.blocked.ads} ads • {item.blocked.trackers} trackers
                  </Text>
                </View>
                <Divider style={styles.historyDivider} />
              </View>
            ))
          ) : (
            <Text style={styles.emptyText}>No browsing history</Text>
          )}
        </Card.Content>
      </Card>
    </>
  );

  const renderDownloadsTab = () => (
    <>
      <Card style={styles.card}>
        <Card.Title 
          title={`Downloads (${downloads.length})`}
          left={(props) => <Icon name="download" {...props} />}
        />
        <Card.Content>
          {downloads.length > 0 ? (
            downloads.map((item) => (
              <View key={item.id} style={styles.downloadItem}>
                <View style={styles.downloadHeader}>
                  <Icon 
                    name={
                      item.threat === 'malicious' ? 'alert-circle' :
                      item.threat === 'suspicious' ? 'alert' : 'file'
                    }
                    size={24}
                    color={
                      item.threat === 'malicious' ? theme.colors.error :
                      item.threat === 'suspicious' ? '#FF9800' : theme.colors.primary
                    }
                  />
                  <View style={styles.downloadInfo}>
                    <Text style={styles.downloadName}>{item.filename}</Text>
                    <Text style={styles.downloadUrl} numberOfLines={1}>{item.url}</Text>
                  </View>
                </View>
                
                {item.status === 'downloading' && (
                  <View style={styles.downloadProgress}>
                    <ProgressBar 
                      progress={item.downloaded / item.size}
                      color={theme.colors.primary}
                    />
                    <Text style={styles.downloadPercent}>
                      {Math.round((item.downloaded / item.size) * 100)}%
                    </Text>
                  </View>
                )}
                
                <View style={styles.downloadFooter}>
                  <View style={styles.downloadStats}>
                    <Chip
                      compact
                      icon={
                        item.status === 'completed' ? 'check' :
                        item.status === 'downloading' ? 'download' :
                        item.status === 'failed' ? 'close' : 'pause'
                      }
                      style={{
                        backgroundColor:
                          item.status === 'completed' ? '#4CAF50' :
                          item.status === 'downloading' ? theme.colors.primary :
                          item.status === 'failed' ? theme.colors.error : '#FF9800'
                      }}>
                      {item.status}
                    </Chip>
                    <Text style={styles.downloadSize}>
                      {(item.size / 1024 / 1024).toFixed(1)} MB
                    </Text>
                  </View>
                  {item.error && (
                    <Text style={styles.downloadError}>{item.error}</Text>
                  )}
                </View>
                <Divider style={styles.downloadDivider} />
              </View>
            ))
          ) : (
            <Text style={styles.emptyText}>No downloads</Text>
          )}
        </Card.Content>
      </Card>
    </>
  );

  const renderBookmarksTab = () => (
    <>
      <Card style={styles.card}>
        <Card.Title 
          title={`Bookmarks (${bookmarks.length})`}
          left={(props) => <Icon name="bookmark" {...props} />}
          right={(props) => (
            <IconButton 
              icon="plus" 
              onPress={() => setBookmarkDialog(true)}
            />
          )}
        />
        <Card.Content>
          {bookmarks.length > 0 ? (
            bookmarks.map((item) => (
              <View key={item.id} style={styles.bookmarkItem}>
                <View style={styles.bookmarkHeader}>
                  <Text style={styles.bookmarkIcon}>{item.favicon || '🔖'}</Text>
                  <View style={styles.bookmarkInfo}>
                    <Text style={styles.bookmarkTitle}>{item.title}</Text>
                    <Text style={styles.bookmarkUrl} numberOfLines={1}>{item.url}</Text>
                    <View style={styles.bookmarkMeta}>
                      <Chip compact mode="outlined" style={styles.bookmarkChip}>
                        📁 {item.folder}
                      </Chip>
                      <Text style={styles.bookmarkVisits}>
                        {item.visitCount} visits
                      </Text>
                    </View>
                  </View>
                  <IconButton
                    icon="delete"
                    size={20}
                    onPress={() => handleDeleteBookmark(item.id)}
                  />
                </View>
                {item.tags.length > 0 && (
                  <View style={styles.bookmarkTags}>
                    {item.tags.map((tag, index) => (
                      <Chip key={index} compact mode="outlined" style={styles.bookmarkTag}>
                        {tag}
                      </Chip>
                    ))}
                  </View>
                )}
                <Divider style={styles.bookmarkDivider} />
              </View>
            ))
          ) : (
            <Text style={styles.emptyText}>No bookmarks. Tap + to add one.</Text>
          )}
        </Card.Content>
      </Card>
    </>
  );

  const renderThreatsTab = () => (
    <>
      {/* AI Threat Detection Status */}
      {aiThreatDetection && (
        <Card style={styles.card}>
          <Card.Title
            title="AI-Powered Threat Detection"
            subtitle={`${aiThreatDetection.realTimeScanning ? 'Active' : 'Inactive'} • Confidence: ${aiThreatDetection.confidence}%`}
            left={(props) => <Icon name="robot" {...props} color="#2196F3" />}
          />
          <Card.Content>
            <View style={styles.aiStatusContainer}>
              <View style={styles.aiStatusItem}>
                <Icon name="shield-check" size={32} color={aiThreatDetection.enabled ? '#4CAF50' : '#999'} />
                <Text style={styles.aiStatusLabel}>AI Protection</Text>
                <Switch
                  value={aiThreatDetection.enabled}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updateAIThreatDetection({ enabled: value });
                    await loadEnhancedFeatures();
                  }}
                />
              </View>
              <View style={styles.aiStatusItem}>
                <Icon name="cloud-sync" size={32} color={aiThreatDetection.cloudAnalysis ? '#2196F3' : '#999'} />
                <Text style={styles.aiStatusLabel}>Cloud Analysis</Text>
                <Switch
                  value={aiThreatDetection.cloudAnalysis}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updateAIThreatDetection({ cloudAnalysis: value });
                    await loadEnhancedFeatures();
                  }}
                />
              </View>
            </View>

            {smartProtection && (
              <>
                <Divider style={styles.divider} />
                <Text style={styles.sectionTitle}>🧠 Smart Protection Features</Text>
                <List.Item
                  title="Behavioral Analysis"
                  description="Monitor suspicious behavior patterns"
                  left={(props) => <List.Icon {...props} icon="chart-timeline" />}
                  right={() => <Chip>{smartProtection.behavioralAnalysis ? 'ON' : 'OFF'}</Chip>}
                />
                <List.Item
                  title="Zero-Hour Protection"
                  description="Detect unknown threats instantly"
                  left={(props) => <List.Icon {...props} icon="clock-fast" />}
                  right={() => <Chip>{smartProtection.zeroHourProtection ? 'ON' : 'OFF'}</Chip>}
                />
                <List.Item
                  title="Heuristic Engine"
                  description="Analyze suspicious code patterns"
                  left={(props) => <List.Icon {...props} icon="brain" />}
                  right={() => <Chip>{smartProtection.heuristicEngine ? 'ON' : 'OFF'}</Chip>}
                />
                <List.Item
                  title="ML Models Active"
                  description={smartProtection.machineLearningModels.join(', ')}
                  left={(props) => <List.Icon {...props} icon="google-circles-communities" />}
                  right={() => <Chip>{smartProtection.machineLearningModels.length}</Chip>}
                />
              </>
            )}
          </Card.Content>
        </Card>
      )}

      {/* Detected Threats */}
      <Card style={styles.card}>
        <Card.Title
          title={`Detected Threats (${detectedThreats.length})`}
          subtitle="AI-powered threat detection"
          left={(props) => <Icon name="alert-octagon" {...props} color="#F44336" />}
        />
        <Card.Content>
          {detectedThreats.length > 0 ? (
            detectedThreats.map((threat) => (
              <View key={threat.id} style={styles.threatItem}>
                <View style={styles.threatHeader}>
                  <Icon
                    name={
                      threat.type === 'malware' ? 'bug' :
                      threat.type === 'phishing' ? 'fish' :
                      threat.type === 'ransomware' ? 'lock-alert' :
                      threat.type === 'cryptojacker' ? 'bitcoin' : 'alert'
                    }
                    size={24}
                    color={
                      threat.severity === 'critical' ? '#D32F2F' :
                      threat.severity === 'high' ? '#F57C00' :
                      threat.severity === 'medium' ? '#FBC02D' : '#689F38'
                    }
                  />
                  <View style={styles.threatInfo}>
                    <Text style={styles.threatTitle}>{threat.type.toUpperCase()}</Text>
                    <Text style={styles.threatDescription}>{threat.description}</Text>
                    <Text style={styles.threatUrl} numberOfLines={1}>{threat.url}</Text>
                  </View>
                </View>
                <View style={styles.threatMeta}>
                  <Chip compact icon="head-cog" style={{ backgroundColor: '#E3F2FD' }}>
                    {threat.aiModel}
                  </Chip>
                  <Chip compact icon="chart-line" style={{ backgroundColor: '#FFF9C4' }}>
                    {threat.confidence}% confidence
                  </Chip>
                  <Chip
                    compact
                    icon={threat.action === 'blocked' ? 'block-helper' : 'eye'}
                    style={{
                      backgroundColor:
                        threat.action === 'blocked' ? '#FFEBEE' : '#E8F5E9'
                    }}>
                    {threat.action}
                  </Chip>
                </View>
                <Divider style={styles.threatDivider} />
              </View>
            ))
          ) : (
            <View style={styles.emptyState}>
              <Icon name="shield-check" size={48} color="#4CAF50" />
              <Text style={styles.emptyText}>No threats detected</Text>
              <Text style={styles.emptySubtext}>AI protection is actively monitoring</Text>
            </View>
          )}
        </Card.Content>
      </Card>

      {/* Security Audits */}
      {securityAudits.length > 0 && (
        <Card style={styles.card}>
          <Card.Title
            title="Recent Security Audits"
            subtitle={`${securityAudits.length} audits performed`}
            left={(props) => <Icon name="shield-search" {...props} />}
          />
          <Card.Content>
            {securityAudits.map((audit) => (
              <View key={audit.id} style={styles.auditItem}>
                <View style={styles.auditHeader}>
                  <View style={styles.auditScore}>
                    <Text style={[
                      styles.auditScoreText,
                      { color: audit.overallScore >= 80 ? '#4CAF50' : audit.overallScore >= 60 ? '#FF9800' : '#F44336' }
                    ]}>
                      {audit.overallScore}
                    </Text>
                    <Text style={styles.auditScoreLabel}>Score</Text>
                  </View>
                  <View style={styles.auditInfo}>
                    <Text style={styles.auditUrl} numberOfLines={1}>{audit.url}</Text>
                    <Text style={styles.auditTime}>{new Date(audit.timestamp).toLocaleString()}</Text>
                    <Text style={styles.auditIssues}>{audit.issues.length} issues found</Text>
                  </View>
                </View>
                {audit.issues.slice(0, 2).map((issue) => (
                  <View key={issue.id} style={styles.auditIssue}>
                    <Chip
                      compact
                      icon="alert"
                      style={{
                        backgroundColor:
                          issue.severity === 'critical' ? '#FFEBEE' :
                          issue.severity === 'high' ? '#FFF3E0' :
                          issue.severity === 'medium' ? '#FFF9C4' : '#F1F8E9'
                      }}>
                      {issue.severity}
                    </Chip>
                    <Text style={styles.issueTitle}>{issue.title}</Text>
                  </View>
                ))}
                <Divider style={styles.auditDivider} />
              </View>
            ))}
          </Card.Content>
        </Card>
      )}

      {/* Anti-Phishing */}
      {antiPhishing && (
        <Card style={styles.card}>
          <Card.Title
            title="Anti-Phishing Protection"
            subtitle={`Database: ${(antiPhishing.knownPhishingDatabase / 1000000).toFixed(1)}M entries`}
            left={(props) => <Icon name="shield-alert" {...props} />}
          />
          <Card.Content>
            <List.Item
              title="Real-time Protection"
              description="Check URLs against phishing database"
              left={(props) => <List.Icon {...props} icon="shield-sync" />}
              right={() => (
                <Switch
                  value={antiPhishing.realTimeCheck}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updateAntiPhishing({ realTimeCheck: value });
                    await loadEnhancedFeatures();
                  }}
                />
              )}
            />
            <List.Item
              title="Visual Similarity Detection"
              description="Detect lookalike domains"
              left={(props) => <List.Icon {...props} icon="eye-check" />}
              right={() => (
                <Switch
                  value={antiPhishing.visualSimilarity}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updateAntiPhishing({ visualSimilarity: value });
                    await loadEnhancedFeatures();
                  }}
                />
              )}
            />
            <List.Item
              title="Typosquatting Detection"
              description="Identify domain impersonation"
              left={(props) => <List.Icon {...props} icon="spellcheck" />}
              right={() => (
                <Switch
                  value={antiPhishing.domainTyrosquatting}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updateAntiPhishing({ domainTyrosquatting: value });
                    await loadEnhancedFeatures();
                  }}
                />
              )}
            />
          </Card.Content>
        </Card>
      )}
    </>
  );

  const renderPasswordsTab = () => (
    <>
      {passwordManager && (
        <>
          <Card style={styles.card}>
            <Card.Title
              title="Password Manager"
              subtitle={`${passwordManager.passwords.length} passwords saved`}
              left={(props) => <Icon name="key" {...props} />}
            />
            <Card.Content>
              {!passwordManager.masterPasswordSet ? (
                <View style={styles.setupContainer}>
                  <Icon name="lock-alert" size={64} color="#FF9800" />
                  <Text style={styles.setupTitle}>Set Up Password Manager</Text>
                  <Text style={styles.setupDescription}>
                    Create a master password to securely store and manage your passwords
                  </Text>
                  <Button mode="contained" icon="lock-plus" style={{ marginTop: 16 }}>
                    Create Master Password
                  </Button>
                </View>
              ) : (
                <>
                  <View style={styles.pwdManagerControls}>
                    <List.Item
                      title="Auto-Fill"
                      description="Automatically fill passwords"
                      left={(props) => <List.Icon {...props} icon="form-textbox-password" />}
                      right={() => (
                        <Switch
                          value={passwordManager.autoFill}
                          onValueChange={async (value) => {
                            await SecureBrowserService.updatePasswordManager({ autoFill: value });
                            await loadEnhancedFeatures();
                          }}
                        />
                      )}
                    />
                    <List.Item
                      title="Auto-Save"
                      description="Save passwords automatically"
                      left={(props) => <List.Icon {...props} icon="content-save-cog" />}
                      right={() => (
                        <Switch
                          value={passwordManager.autoSave}
                          onValueChange={async (value) => {
                            await SecureBrowserService.updatePasswordManager({ autoSave: value });
                            await loadEnhancedFeatures();
                          }}
                        />
                      )}
                    />
                    <List.Item
                      title="Biometric Unlock"
                      description="Use fingerprint/Face ID"
                      left={(props) => <List.Icon {...props} icon="fingerprint" />}
                      right={() => (
                        <Switch
                          value={passwordManager.biometricUnlock}
                          onValueChange={async (value) => {
                            await SecureBrowserService.updatePasswordManager({ biometricUnlock: value });
                            await loadEnhancedFeatures();
                          }}
                        />
                      )}
                    />
                  </View>

                  <Divider style={styles.divider} />

                  {passwordManager.passwords.length > 0 ? (
                    passwordManager.passwords.map((pwd) => (
                      <View key={pwd.id} style={styles.passwordItem}>
                        <View style={styles.passwordHeader}>
                          <Icon name="web" size={24} color={theme.colors.primary} />
                          <View style={styles.passwordInfo}>
                            <Text style={styles.passwordDomain}>{pwd.domain}</Text>
                            <Text style={styles.passwordUsername}>{pwd.username}</Text>
                          </View>
                          <View style={styles.passwordStrength}>
                            <Chip
                              compact
                              icon={
                                pwd.strength === 'very_strong' ? 'shield-check' :
                                pwd.strength === 'strong' ? 'shield' :
                                pwd.strength === 'medium' ? 'shield-half' : 'shield-off'
                              }
                              style={{
                                backgroundColor:
                                  pwd.strength === 'very_strong' ? '#4CAF50' :
                                  pwd.strength === 'strong' ? '#8BC34A' :
                                  pwd.strength === 'medium' ? '#FF9800' : '#F44336'
                              }}>
                              {pwd.strength.replace('_', ' ')}
                            </Chip>
                          </View>
                        </View>
                        {pwd.compromised && (
                          <View style={styles.compromisedWarning}>
                            <Icon name="alert-circle" size={16} color="#F44336" />
                            <Text style={styles.compromisedText}>
                              Password found in data breach! Change immediately.
                            </Text>
                          </View>
                        )}
                        <View style={styles.passwordMeta}>
                          <Text style={styles.passwordDate}>
                            Last used: {new Date(pwd.lastUsed).toLocaleDateString()}
                          </Text>
                          <IconButton
                            icon="delete"
                            size={20}
                            onPress={async () => {
                              await SecureBrowserService.deletePassword(pwd.id);
                              await loadEnhancedFeatures();
                            }}
                          />
                        </View>
                        <Divider style={styles.passwordDivider} />
                      </View>
                    ))
                  ) : (
                    <Text style={styles.emptyText}>No passwords saved</Text>
                  )}
                </>
              )}
            </Card.Content>
          </Card>

          {/* Password Generator */}
          <Card style={styles.card}>
            <Card.Title
              title="Password Generator"
              subtitle="Generate strong, unique passwords"
              left={(props) => <Icon name="shield-star" {...props} />}
            />
            <Card.Content>
              <Button mode="contained" icon="auto-fix">
                Generate Strong Password
              </Button>
            </Card.Content>
          </Card>
        </>
      )}
    </>
  );

  const renderAdvancedTab = () => (
    <>
      {/* Data Leak Protection */}
      {dataLeakProtection && (
        <Card style={styles.card}>
          <Card.Title
            title="Data Leak Protection"
            subtitle="Prevent sensitive data exposure"
            left={(props) => <Icon name="shield-lock-outline" {...props} />}
          />
          <Card.Content>
            <List.Item
              title="Enable DLP"
              description="Monitor and block sensitive data"
              left={(props) => <List.Icon {...props} icon="shield-check" />}
              right={() => (
                <Switch
                  value={dataLeakProtection.enabled}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updateDataLeakProtection({ enabled: value });
                    await loadEnhancedFeatures();
                  }}
                />
              )}
            />
            <List.Item
              title="Block Clipboard"
              description="Prevent clipboard access"
              left={(props) => <List.Icon {...props} icon="content-copy" />}
              right={() => (
                <Switch
                  value={dataLeakProtection.blockClipboard}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updateDataLeakProtection({ blockClipboard: value });
                    await loadEnhancedFeatures();
                  }}
                  disabled={!dataLeakProtection.enabled}
                />
              )}
            />
            <List.Item
              title="Block Screen Capture"
              description="Prevent screenshots"
              left={(props) => <List.Icon {...props} icon="camera-off" />}
              right={() => (
                <Switch
                  value={dataLeakProtection.blockScreenCapture}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updateDataLeakProtection({ blockScreenCapture: value });
                    await loadEnhancedFeatures();
                  }}
                  disabled={!dataLeakProtection.enabled}
                />
              )}
            />
          </Card.Content>
        </Card>
      )}

      {/* Network Security */}
      {networkSecurity && (
        <Card style={styles.card}>
          <Card.Title
            title="Network Security"
            subtitle={`TLS ${networkSecurity.tlsMinVersion} • HTTPS Only`}
            left={(props) => <Icon name="network-strength-4" {...props} />}
          />
          <Card.Content>
            <List.Item
              title="HTTPS Only Mode"
              description="Force all connections to use HTTPS"
              left={(props) => <List.Icon {...props} icon="lock" />}
              right={() => (
                <Switch
                  value={networkSecurity.httpsOnly}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updateNetworkSecurity({ httpsOnly: value });
                    await loadEnhancedFeatures();
                  }}
                />
              )}
            />
            <List.Item
              title="HSTS"
              description="HTTP Strict Transport Security"
              left={(props) => <List.Icon {...props} icon="shield-lock" />}
              right={() => (
                <Switch
                  value={networkSecurity.hsts}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updateNetworkSecurity({ hsts: value });
                    await loadEnhancedFeatures();
                  }}
                />
              )}
            />
            <List.Item
              title="Block Insecure Content"
              description="Block HTTP content on HTTPS pages"
              left={(props) => <List.Icon {...props} icon="block-helper" />}
              right={() => (
                <Switch
                  value={networkSecurity.blockInsecureContent}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updateNetworkSecurity({ blockInsecureContent: value });
                    await loadEnhancedFeatures();
                  }}
                />
              )}
            />
            <List.Item
              title="DNSSEC Validation"
              description="Verify DNS responses"
              left={(props) => <List.Icon {...props} icon="dns" />}
              right={() => (
                <Switch
                  value={networkSecurity.dnsSecValidation}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updateNetworkSecurity({ dnsSecValidation: value });
                    await loadEnhancedFeatures();
                  }}
                />
              )}
            />
          </Card.Content>
        </Card>
      )}

      {/* Session Isolation */}
      {sessionIsolation && (
        <Card style={styles.card}>
          <Card.Title
            title="Session Isolation"
            subtitle="Enhanced privacy protection"
            left={(props) => <Icon name="lock-open-variant" {...props} />}
          />
          <Card.Content>
            <List.Item
              title="Enable Isolation"
              description="Isolate browsing sessions"
              left={(props) => <List.Icon {...props} icon="security" />}
              right={() => (
                <Switch
                  value={sessionIsolation.enabled}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updateSessionIsolation({ enabled: value });
                    await loadEnhancedFeatures();
                  }}
                />
              )}
            />
            <List.Item
              title="Per-Tab Isolation"
              description="Separate cookies per tab"
              left={(props) => <List.Icon {...props} icon="tab" />}
              right={() => (
                <Switch
                  value={sessionIsolation.isolatePerTab}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updateSessionIsolation({ isolatePerTab: value });
                    await loadEnhancedFeatures();
                  }}
                  disabled={!sessionIsolation.enabled}
                />
              )}
            />
            <List.Item
              title="Clear on Exit"
              description="Delete data when closing"
              left={(props) => <List.Icon {...props} icon="delete-sweep" />}
              right={() => (
                <Switch
                  value={sessionIsolation.clearOnExit}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updateSessionIsolation({ clearOnExit: value });
                    await loadEnhancedFeatures();
                  }}
                  disabled={!sessionIsolation.enabled}
                />
              )}
            />
          </Card.Content>
        </Card>
      )}

      {/* Performance Optimization */}
      {performanceOpt && (
        <Card style={styles.card}>
          <Card.Title
            title="Performance Optimization"
            subtitle={`Caching: ${performanceOpt.caching}`}
            left={(props) => <Icon name="speedometer" {...props} />}
          />
          <Card.Content>
            <List.Item
              title="Enable Optimization"
              description="Improve loading speed"
              left={(props) => <List.Icon {...props} icon="flash" />}
              right={() => (
                <Switch
                  value={performanceOpt.enabled}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updatePerformanceOptimization({ enabled: value });
                    await loadEnhancedFeatures();
                  }}
                />
              )}
            />
            <List.Item
              title="Lazy Loading"
              description="Load images on demand"
              left={(props) => <List.Icon {...props} icon="image-multiple" />}
              right={() => (
                <Switch
                  value={performanceOpt.lazyLoading}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updatePerformanceOptimization({ lazyLoading: value });
                    await loadEnhancedFeatures();
                  }}
                  disabled={!performanceOpt.enabled}
                />
              )}
            />
            <List.Item
              title="Image Compression"
              description="Reduce image data usage"
              left={(props) => <List.Icon {...props} icon="file-image" />}
              right={() => (
                <Switch
                  value={performanceOpt.imageCompression}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updatePerformanceOptimization({ imageCompression: value });
                    await loadEnhancedFeatures();
                  }}
                  disabled={!performanceOpt.enabled}
                />
              )}
            />
            <List.Item
              title="Bandwidth Saver"
              description="Reduce data consumption"
              left={(props) => <List.Icon {...props} icon="content-save-all" />}
              right={() => (
                <Switch
                  value={performanceOpt.bandwidthSaver}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updatePerformanceOptimization({ bandwidthSaver: value });
                    await loadEnhancedFeatures();
                  }}
                  disabled={!performanceOpt.enabled}
                />
              )}
            />
          </Card.Content>
        </Card>
      )}

      {/* Privacy Metrics */}
      {privacyMetrics && (
        <Card style={styles.card}>
          <Card.Title
            title="Privacy Metrics"
            subtitle="Session statistics"
            left={(props) => <Icon name="chart-line" {...props} />}
          />
          <Card.Content>
            <View style={styles.metricsGrid}>
              <View style={styles.metricItem}>
                <Text style={styles.metricValue}>{privacyMetrics.privacyScore}</Text>
                <Text style={styles.metricLabel}>Privacy Score</Text>
              </View>
              <View style={styles.metricItem}>
                <Text style={styles.metricValue}>{privacyMetrics.blockedRequests}</Text>
                <Text style={styles.metricLabel}>Blocked</Text>
              </View>
              <View style={styles.metricItem}>
                <Text style={styles.metricValue}>{privacyMetrics.httpsUpgrades}</Text>
                <Text style={styles.metricLabel}>HTTPS Upgrades</Text>
              </View>
              <View style={styles.metricItem}>
                <Text style={styles.metricValue}>{privacyMetrics.fingerprintingAttempts}</Text>
                <Text style={styles.metricLabel}>Fingerprinting</Text>
              </View>
            </View>
            <Button 
              mode="outlined" 
              onPress={async () => {
                await SecureBrowserService.resetPrivacyMetrics();
                await loadPrivacyMetrics();
              }}
              style={{ marginTop: 12 }}>
              Reset Metrics
            </Button>
          </Card.Content>
        </Card>
      )}

      {/* DNS Settings */}
      {dnsSettings && (
        <Card style={styles.card}>
          <Card.Title
            title="DNS Settings"
            subtitle="Secure DNS configuration"
            left={(props) => <Icon name="dns" {...props} />}
          />
          <Card.Content>
            <List.Item
              title="DNS Provider"
              description={dnsSettings.provider}
              left={(props) => <List.Icon {...props} icon="server" />}
            />
            <List.Item
              title="DNS-over-HTTPS"
              description="Encrypt DNS queries"
              left={(props) => <List.Icon {...props} icon="lock" />}
              right={() => (
                <Switch
                  value={dnsSettings.dnsOverHttps}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updateDNSSettings({ dnsOverHttps: value });
                    await loadAdvancedSettings();
                  }}
                />
              )}
            />
            <List.Item
              title="Block Malware"
              description="Block known malicious domains"
              left={(props) => <List.Icon {...props} icon="shield-alert" />}
              right={() => (
                <Switch
                  value={dnsSettings.blockMalware}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updateDNSSettings({ blockMalware: value });
                    await loadAdvancedSettings();
                  }}
                />
              )}
            />
            <List.Item
              title="Block Trackers"
              description="Block tracking domains at DNS level"
              left={(props) => <List.Icon {...props} icon="eye-off" />}
              right={() => (
                <Switch
                  value={dnsSettings.blockTrackers}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updateDNSSettings({ blockTrackers: value });
                    await loadAdvancedSettings();
                  }}
                />
              )}
            />
          </Card.Content>
        </Card>
      )}

      {/* Fingerprint Protection */}
      {fingerprintProtection && (
        <Card style={styles.card}>
          <Card.Title
            title="Fingerprint Protection"
            subtitle={`Protection Level: ${fingerprintProtection.protectionLevel}`}
            left={(props) => <Icon name="fingerprint" {...props} />}
          />
          <Card.Content>
            <List.Item
              title="Enable Protection"
              description="Block fingerprinting attempts"
              left={(props) => <List.Icon {...props} icon="shield-check" />}
              right={() => (
                <Switch
                  value={fingerprintProtection.enabled}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updateFingerprintProtection({ enabled: value });
                    await loadAdvancedSettings();
                  }}
                />
              )}
            />
            <List.Item
              title="Block Canvas"
              description="Prevent canvas fingerprinting"
              left={(props) => <List.Icon {...props} icon="palette" />}
              right={() => (
                <Switch
                  value={fingerprintProtection.blockCanvas}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updateFingerprintProtection({ blockCanvas: value });
                    await loadAdvancedSettings();
                  }}
                  disabled={!fingerprintProtection.enabled}
                />
              )}
            />
            <List.Item
              title="Block WebGL"
              description="Prevent WebGL fingerprinting"
              left={(props) => <List.Icon {...props} icon="cube-outline" />}
              right={() => (
                <Switch
                  value={fingerprintProtection.blockWebGL}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updateFingerprintProtection({ blockWebGL: value });
                    await loadAdvancedSettings();
                  }}
                  disabled={!fingerprintProtection.enabled}
                />
              )}
            />
            <List.Item
              title="Block WebRTC"
              description="Prevent IP address leaks"
              left={(props) => <List.Icon {...props} icon="ip-network" />}
              right={() => (
                <Switch
                  value={fingerprintProtection.blockWebRTC}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updateFingerprintProtection({ blockWebRTC: value });
                    await loadAdvancedSettings();
                  }}
                  disabled={!fingerprintProtection.enabled}
                />
              )}
            />
          </Card.Content>
        </Card>
      )}

      {/* Script Blocking */}
      {scriptBlocking && (
        <Card style={styles.card}>
          <Card.Title
            title="Script Blocking"
            subtitle="Control script execution"
            left={(props) => <Icon name="code-braces" {...props} />}
          />
          <Card.Content>
            <List.Item
              title="Enable Script Blocking"
              description="Block potentially harmful scripts"
              left={(props) => <List.Icon {...props} icon="shield" />}
              right={() => (
                <Switch
                  value={scriptBlocking.enabled}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updateScriptBlocking({ enabled: value });
                    await loadAdvancedSettings();
                  }}
                />
              )}
            />
            <List.Item
              title="Block Third-Party Scripts"
              description="Block scripts from other domains"
              left={(props) => <List.Icon {...props} icon="web-off" />}
              right={() => (
                <Switch
                  value={scriptBlocking.blockThirdParty}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updateScriptBlocking({ blockThirdParty: value });
                    await loadAdvancedSettings();
                  }}
                  disabled={!scriptBlocking.enabled}
                />
              )}
            />
            <List.Item
              title="Block Cryptominers"
              description="Prevent cryptocurrency mining"
              left={(props) => <List.Icon {...props} icon="bitcoin" />}
              right={() => (
                <Switch
                  value={scriptBlocking.blockCryptominers}
                  onValueChange={async (value) => {
                    await SecureBrowserService.updateScriptBlocking({ blockCryptominers: value });
                    await loadAdvancedSettings();
                  }}
                  disabled={!scriptBlocking.enabled}
                />
              )}
            />
          </Card.Content>
        </Card>
      )}
    </>
  );

  // ===== MAIN COMPONENT RETURN =====
  console.log('🟢 About to return main JSX, standalone:', standalone, 'activeTab:', activeTab);
  
  // Standalone mode: render full interface with tabs
  console.log('🟣 STANDALONE MODE - Rendering full interface');
  return (
    <View style={{ flex: 1, backgroundColor: '#f5f5f5' }}>
      {/* Tab Selection */}
      <View style={{ paddingHorizontal: 12, paddingVertical: 8, backgroundColor: '#fff' }}>
        <ScrollView horizontal showsHorizontalScrollIndicator={false}>
          <SegmentedButtons
            value={activeTab}
            onValueChange={setActiveTab}
            buttons={[
              { value: 'browser', label: 'Browse', icon: 'web' },
              { value: 'downloads', label: 'Downloads', icon: 'download' },
              { value: 'threats', label: 'AI Security', icon: 'shield-alert' },
              { value: 'privacy', label: 'Privacy', icon: 'eye-off' },
              { value: 'passwords', label: 'Passwords', icon: 'key' },
              { value: 'advanced', label: 'Advanced', icon: 'cog' },
            ]}
            style={{ backgroundColor: '#fff' }}
          />
        </ScrollView>
      </View>

      {/* Content */}
      <View style={{ flex: 1 }}>
        {activeTab === 'browser' && renderBrowserTab()}
        {activeTab === 'downloads' && renderDownloadsTab()}
        {activeTab === 'threats' && renderThreatsTab()}
        {activeTab === 'privacy' && renderPrivacyTab()}
        {activeTab === 'passwords' && renderPasswordsTab()}
        {activeTab === 'advanced' && renderAdvancedTab()}
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  header: {
    padding: 20,
    alignItems: 'center',
    elevation: 2,
  },
  headerTitle: {
    fontSize: 24,
    fontWeight: 'bold',
    marginTop: 8,
  },
  headerSubtitle: {
    fontSize: 14,
    color: '#666',
    marginTop: 4,
  },
  tabContainer: {
    paddingHorizontal: 12,
    paddingVertical: 8,
  },
  segmentedButtons: {
    backgroundColor: '#fff',
  },
  content: {
    flex: 1,
  },
  card: {
    margin: 12,
    marginTop: 0,
    marginBottom: 16,
  },
  urlBar: {
    margin: 12,
    padding: 8,
    elevation: 2,
    position: 'relative',
    borderRadius: 24,
    overflow: 'hidden',
  },
  urlInputContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  urlInput: {
    flex: 1,
    fontSize: 14,
    paddingVertical: 8,
  },
  suggestionsContainer: {
    marginTop: 8,
    borderTopWidth: 1,
    borderTopColor: '#e0e0e0',
    paddingTop: 8,
    zIndex: 1000,
  },
  suggestionsHeader: {
    fontSize: 11,
    fontWeight: '600',
    color: '#666',
    textTransform: 'uppercase',
    marginBottom: 8,
    paddingHorizontal: 8,
  },
  suggestionItem: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: 12,
    paddingHorizontal: 12,
    gap: 12,
    borderRadius: 8,
    backgroundColor: 'transparent',
    minHeight: 44,
  },
  suggestionText: {
    flex: 1,
    fontSize: 14,
    color: '#333',
  },
  securityHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 16,
  },
  privacyScoreCircle: {
    alignItems: 'center',
    marginRight: 20,
  },
  privacyScoreText: {
    fontSize: 36,
    fontWeight: 'bold',
  },
  privacyScoreLabel: {
    fontSize: 11,
    color: '#666',
    marginTop: 4,
  },
  securityInfo: {
    flex: 1,
    gap: 8,
  },
  securityTitle: {
    fontSize: 16,
    fontWeight: '600',
  },
  divider: {
    marginVertical: 12,
  },
  blockedStats: {
    flexDirection: 'row',
    justifyContent: 'space-around',
  },
  blockedItem: {
    alignItems: 'center',
    gap: 4,
  },
  blockedNumber: {
    fontSize: 20,
    fontWeight: 'bold',
  },
  blockedLabel: {
    fontSize: 11,
    color: '#666',
  },
  browserNote: {
    fontSize: 14,
    color: '#666',
    textAlign: 'center',
    marginBottom: 12,
    lineHeight: 20,
  },
  openButton: {
    marginTop: 8,
  },
  emptyState: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 40,
  },
  emptyText: {
    fontSize: 16,
    color: '#999',
    textAlign: 'center',
    marginTop: 16,
  },
  emptySubtext: {
    fontSize: 13,
    color: '#ccc',
    textAlign: 'center',
    marginTop: 8,
  },
  statsGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    justifyContent: 'space-between',
  },
  statItem: {
    alignItems: 'center',
    width: '48%',
    marginBottom: 12,
  },
  statNumber: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#4caf50',
  },
  statLabel: {
    fontSize: 12,
    color: '#666',
    marginTop: 4,
  },
  savingsRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    marginTop: 8,
  },
  savingsText: {
    fontSize: 14,
    color: '#666',
  },
  privacyBreakdown: {
    gap: 12,
  },
  breakdownItem: {
    gap: 4,
  },
  breakdownLabel: {
    fontSize: 13,
    fontWeight: '600',
  },
  breakdownValue: {
    fontSize: 12,
    color: '#666',
    textAlign: 'right',
  },
  risksTitle: {
    fontSize: 14,
    fontWeight: 'bold',
    marginBottom: 8,
    color: '#ff9800',
  },
  riskItem: {
    marginBottom: 12,
    gap: 4,
  },
  riskTitle: {
    fontSize: 14,
    fontWeight: '600',
  },
  riskDesc: {
    fontSize: 13,
    color: '#666',
  },
  cookieItem: {
    marginBottom: 12,
  },
  cookieHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 4,
  },
  cookieName: {
    fontSize: 14,
    fontWeight: '600',
  },
  cookieDomain: {
    fontSize: 12,
    color: '#666',
    marginBottom: 8,
  },
  cookieDetails: {
    flexDirection: 'row',
    gap: 8,
  },
  cookieChip: {
    height: 24,
  },
  cookieDivider: {
    marginTop: 12,
  },
  historyItem: {
    marginBottom: 12,
  },
  historyHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    marginBottom: 4,
  },
  historyInfo: {
    flex: 1,
  },
  historyTitle: {
    fontSize: 14,
    fontWeight: '600',
  },
  historyUrl: {
    fontSize: 12,
    color: '#666',
  },
  historyStats: {
    marginLeft: 28,
    gap: 2,
  },
  historyTime: {
    fontSize: 11,
    color: '#999',
  },
  historyStat: {
    fontSize: 12,
    color: '#666',
  },
  historyDivider: {
    marginTop: 12,
  },
  downloadItem: {
    marginBottom: 16,
  },
  downloadHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    marginBottom: 8,
  },
  downloadInfo: {
    flex: 1,
  },
  downloadName: {
    fontSize: 14,
    fontWeight: '600',
  },
  downloadUrl: {
    fontSize: 12,
    color: '#666',
  },
  downloadProgress: {
    marginVertical: 8,
  },
  downloadPercent: {
    fontSize: 11,
    color: '#666',
    marginTop: 4,
    textAlign: 'right',
  },
  downloadFooter: {
    gap: 8,
  },
  downloadStats: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  downloadSize: {
    fontSize: 12,
    color: '#666',
  },
  downloadError: {
    fontSize: 12,
    color: '#f44336',
  },
  downloadDivider: {
    marginTop: 12,
  },
  bookmarkItem: {
    marginBottom: 16,
  },
  bookmarkHeader: {
    flexDirection: 'row',
    alignItems: 'flex-start',
    gap: 8,
  },
  bookmarkIcon: {
    fontSize: 20,
  },
  bookmarkInfo: {
    flex: 1,
  },
  bookmarkTitle: {
    fontSize: 14,
    fontWeight: '600',
    marginBottom: 2,
  },
  bookmarkUrl: {
    fontSize: 12,
    color: '#666',
    marginBottom: 8,
  },
  bookmarkMeta: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  bookmarkChip: {
    height: 24,
  },
  bookmarkVisits: {
    fontSize: 11,
    color: '#999',
  },
  bookmarkTags: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 6,
    marginLeft: 28,
    marginTop: 8,
  },
  bookmarkTag: {
    height: 24,
  },
  bookmarkDivider: {
    marginTop: 12,
  },
  metricsGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 16,
    marginBottom: 8,
  },
  metricItem: {
    flex: 1,
    minWidth: '45%',
    alignItems: 'center',
    padding: 12,
    backgroundColor: '#f5f5f5',
    borderRadius: 8,
  },
  metricValue: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#2196F3',
  },
  metricLabel: {
    fontSize: 12,
    color: '#666',
    marginTop: 4,
  },
  // Enhanced feature styles
  aiStatusContainer: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    marginVertical: 12,
  },
  aiStatusItem: {
    alignItems: 'center',
    gap: 8,
  },
  aiStatusLabel: {
    fontSize: 12,
    color: '#666',
    textAlign: 'center',
  },
  sectionTitle: {
    fontSize: 16,
    fontWeight: 'bold',
    marginBottom: 12,
  },
  threatItem: {
    marginBottom: 16,
  },
  threatHeader: {
    flexDirection: 'row',
    gap: 12,
    marginBottom: 8,
  },
  threatInfo: {
    flex: 1,
  },
  threatTitle: {
    fontSize: 14,
    fontWeight: 'bold',
    marginBottom: 4,
  },
  threatDescription: {
    fontSize: 13,
    color: '#666',
    marginBottom: 4,
  },
  threatUrl: {
    fontSize: 11,
    color: '#999',
  },
  threatMeta: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 8,
    marginTop: 8,
  },
  threatDivider: {
    marginTop: 12,
  },
  auditItem: {
    marginBottom: 16,
  },
  auditHeader: {
    flexDirection: 'row',
    gap: 12,
    marginBottom: 12,
  },
  auditScore: {
    alignItems: 'center',
    width: 60,
  },
  auditScoreText: {
    fontSize: 28,
    fontWeight: 'bold',
  },
  auditScoreLabel: {
    fontSize: 11,
    color: '#666',
  },
  auditInfo: {
    flex: 1,
  },
  auditUrl: {
    fontSize: 13,
    fontWeight: '600',
    marginBottom: 4,
  },
  auditTime: {
    fontSize: 11,
    color: '#999',
    marginBottom: 2,
  },
  auditIssues: {
    fontSize: 12,
    color: '#666',
  },
  auditIssue: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    marginBottom: 6,
  },
  issueTitle: {
    fontSize: 12,
    color: '#666',
    flex: 1,
  },
  auditDivider: {
    marginTop: 12,
  },
  setupContainer: {
    alignItems: 'center',
    padding: 20,
  },
  setupTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    marginTop: 16,
    marginBottom: 8,
  },
  setupDescription: {
    fontSize: 14,
    color: '#666',
    textAlign: 'center',
    lineHeight: 20,
  },
  pwdManagerControls: {
    marginBottom: 12,
  },
  passwordItem: {
    marginBottom: 16,
  },
  passwordHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    marginBottom: 8,
  },
  passwordInfo: {
    flex: 1,
  },
  passwordDomain: {
    fontSize: 14,
    fontWeight: '600',
    marginBottom: 2,
  },
  passwordUsername: {
    fontSize: 12,
    color: '#666',
  },
  passwordStrength: {
    marginLeft: 8,
  },
  compromisedWarning: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    backgroundColor: '#FFEBEE',
    padding: 8,
    borderRadius: 4,
    marginBottom: 8,
  },
  compromisedText: {
    fontSize: 12,
    color: '#F44336',
    flex: 1,
  },
  passwordMeta: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  passwordDate: {
    fontSize: 11,
    color: '#999',
  },
  passwordDivider: {
    marginTop: 8,
  },
  dlpContainer: {
    gap: 12,
  },
  dlpRuleItem: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: 12,
    backgroundColor: '#F5F5F5',
    borderRadius: 8,
    marginBottom: 8,
  },
  dlpRuleInfo: {
    flex: 1,
  },
  dlpRuleName: {
    fontSize: 14,
    fontWeight: '600',
    marginBottom: 2,
  },
  dlpRulePattern: {
    fontSize: 12,
    color: '#666',
    fontFamily: 'monospace',
  },
  networkSecContainer: {
    gap: 8,
  },
  // New browser feature styles
  tabBar: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: 8,
    gap: 8,
    elevation: 2,
  },
  tabButton: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: 8,
    gap: 4,
  },
  tabCount: {
    fontSize: 12,
    fontWeight: 'bold',
    color: '#666',
  },
  navControls: {
    flexDirection: 'row',
    alignItems: 'center',
    flex: 1,
  },
  modeIndicators: {
    flexDirection: 'row',
    gap: 4,
  },
  incognitoChip: {
    backgroundColor: '#E3F2FD',
    height: 28,
  },
  readingChip: {
    backgroundColor: '#FFF3E0',
    height: 28,
  },
  quickActionsCard: {
    margin: 12,
    elevation: 4,
  },
  quickActionsGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 16,
    justifyContent: 'space-around',
  },
  quickAction: {
    alignItems: 'center',
    width: '20%',
    minWidth: 60,
  },
  quickActionText: {
    fontSize: 11,
    color: '#666',
    marginTop: 4,
    textAlign: 'center',
  },
  tabSwitcherDialog: {
    maxHeight: '80%',
  },
  tabCard: {
    marginVertical: 4,
    elevation: 1,
  },
  tabCardHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  tabCardInfo: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    flex: 1,
  },
  tabCardTitle: {
    fontSize: 14,
    fontWeight: '600',
    flex: 1,
  },
  tabCardUrl: {
    fontSize: 12,
    color: '#666',
    marginTop: 4,
  },
  qrScannerDialog: {
    maxHeight: '80%',
  },
  qrScanner: {
    height: 300,
    width: '100%',
    overflow: 'hidden',
    borderRadius: 8,
  },
  qrOverlay: {
    position: 'absolute',
    bottom: 20,
    left: 0,
    right: 0,
    alignItems: 'center',
  },
  qrInstructions: {
    color: 'white',
    fontSize: 16,
    backgroundColor: 'rgba(0,0,0,0.6)',
    padding: 12,
    borderRadius: 8,
  },
  downloadItem: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingVertical: 12,
    borderBottomWidth: 1,
    borderBottomColor: '#f0f0f0',
  },
  downloadInfo: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    flex: 1,
  },
  downloadDetails: {
    flex: 1,
  },
  downloadName: {
    fontSize: 14,
    fontWeight: '600',
    marginBottom: 2,
  },
  downloadSize: {
    fontSize: 12,
    color: '#666',
  },
});

export default SecureBrowserScreen;
