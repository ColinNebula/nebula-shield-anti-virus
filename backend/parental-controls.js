const EventEmitter = require('events');
const fs = require('fs').promises;
const path = require('path');

class ParentalControls extends EventEmitter {
  constructor() {
    super();
    this.configPath = path.join(__dirname, 'data', 'parental-controls.json');
    this.activityLogPath = path.join(__dirname, 'data', 'activity-logs.json');
    this.initialized = false;
    
    // Configuration
    this.config = {
      enabled: false,
      profiles: [], // Multiple child profiles
      activeProfile: null,
      masterPin: null // 4-6 digit PIN for parent access
    };
    
    // Activity tracking
    this.activityLogs = [];
    this.currentSession = null;
    this.screenTimeTimer = null;
    
    // Website categories with patterns
    this.websiteCategories = {
      'Adult Content': {
        blocked: true,
        keywords: ['porn', 'xxx', 'sex', 'adult', 'nude', 'nsfw'],
        domains: ['pornhub.com', 'xvideos.com', 'xhamster.com', 'redtube.com']
      },
      'Gambling': {
        blocked: true,
        keywords: ['casino', 'poker', 'betting', 'gambling', 'slots'],
        domains: ['bet365.com', 'pokerstars.com', 'casino.com']
      },
      'Violence': {
        blocked: false,
        keywords: ['gore', 'brutal', 'violence'],
        domains: []
      },
      'Social Media': {
        blocked: false,
        keywords: ['facebook', 'instagram', 'tiktok', 'snapchat', 'twitter'],
        domains: ['facebook.com', 'instagram.com', 'tiktok.com', 'snapchat.com', 'twitter.com', 'x.com']
      },
      'Gaming': {
        blocked: false,
        keywords: ['game', 'gaming', 'steam', 'epic'],
        domains: ['steam.com', 'epicgames.com', 'roblox.com', 'minecraft.net']
      },
      'Streaming': {
        blocked: false,
        keywords: ['youtube', 'netflix', 'twitch', 'streaming'],
        domains: ['youtube.com', 'netflix.com', 'twitch.tv', 'hulu.com', 'disneyplus.com']
      },
      'Shopping': {
        blocked: false,
        keywords: ['shop', 'buy', 'store', 'cart'],
        domains: ['amazon.com', 'ebay.com', 'walmart.com', 'target.com']
      },
      'News': {
        blocked: false,
        keywords: ['news', 'media', 'press'],
        domains: ['cnn.com', 'bbc.com', 'nytimes.com', 'foxnews.com']
      },
      'Education': {
        blocked: false,
        keywords: ['edu', 'learn', 'school', 'university', 'course'],
        domains: ['khan.org', 'coursera.org', 'udemy.com', 'edx.org']
      },
      'Hacking/Dark Web': {
        blocked: true,
        keywords: ['hack', 'crack', 'exploit', 'darkweb', 'tor', 'onion'],
        domains: []
      }
    };
    
    // Social media monitoring
    this.socialMediaPlatforms = {
      'Facebook': { monitored: true, timeSpent: 0, visits: 0 },
      'Instagram': { monitored: true, timeSpent: 0, visits: 0 },
      'TikTok': { monitored: true, timeSpent: 0, visits: 0 },
      'Snapchat': { monitored: true, timeSpent: 0, visits: 0 },
      'Twitter/X': { monitored: true, timeSpent: 0, visits: 0 },
      'YouTube': { monitored: true, timeSpent: 0, visits: 0 },
      'Discord': { monitored: true, timeSpent: 0, visits: 0 },
      'WhatsApp': { monitored: true, timeSpent: 0, visits: 0 },
      'Telegram': { monitored: true, timeSpent: 0, visits: 0 }
    };
  }

  async initialize() {
    try {
      const dataDir = path.join(__dirname, 'data');
      await fs.mkdir(dataDir, { recursive: true });
      
      await this.loadConfig();
      await this.loadActivityLogs();
      
      this.initialized = true;
      console.log('👨‍👩‍👧‍👦 Parental Controls initialized');
      this.emit('initialized');
      
      return { success: true };
    } catch (error) {
      console.error('Failed to initialize Parental Controls:', error);
      throw error;
    }
  }

  async loadConfig() {
    try {
      const data = await fs.readFile(this.configPath, 'utf8');
      this.config = JSON.parse(data);
    } catch (error) {
      if (error.code === 'ENOENT') {
        await this.saveConfig();
      }
    }
  }

  async saveConfig() {
    try {
      await fs.writeFile(this.configPath, JSON.stringify(this.config, null, 2));
    } catch (error) {
      console.error('Failed to save config:', error);
      throw error;
    }
  }

  async loadActivityLogs() {
    try {
      const data = await fs.readFile(this.activityLogPath, 'utf8');
      this.activityLogs = JSON.parse(data);
    } catch (error) {
      if (error.code === 'ENOENT') {
        await this.saveActivityLogs();
      }
    }
  }

  async saveActivityLogs() {
    try {
      // Keep only last 10,000 logs
      if (this.activityLogs.length > 10000) {
        this.activityLogs = this.activityLogs.slice(-10000);
      }
      await fs.writeFile(this.activityLogPath, JSON.stringify(this.activityLogs, null, 2));
    } catch (error) {
      console.error('Failed to save activity logs:', error);
    }
  }

  // PIN Management
  hashPin(pin) {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(pin.toString()).digest('hex');
  }

  async setMasterPin(pin) {
    if (!pin || pin.toString().length < 4) {
      throw new Error('PIN must be at least 4 digits');
    }
    
    this.config.masterPin = this.hashPin(pin);
    await this.saveConfig();
    
    this.emit('pin-set');
    return { success: true, message: 'Master PIN set successfully' };
  }

  verifyPin(pin) {
    if (!this.config.masterPin) {
      throw new Error('No master PIN set');
    }
    
    const hashedPin = this.hashPin(pin);
    return hashedPin === this.config.masterPin;
  }

  // Profile Management
  async createProfile(profileData) {
    const { name, age, pin } = profileData;
    
    if (!name) {
      throw new Error('Profile name is required');
    }
    
    const profile = {
      id: require('crypto').randomUUID(),
      name,
      age: age || 0,
      pin: pin ? this.hashPin(pin) : null,
      createdAt: new Date().toISOString(),
      
      // Web filtering
      webFiltering: {
        enabled: true,
        blockedCategories: ['Adult Content', 'Gambling', 'Hacking/Dark Web'],
        customBlockedSites: [],
        customAllowedSites: [],
        safeSearch: true
      },
      
      // Screen time limits
      screenTime: {
        enabled: true,
        dailyLimit: 120, // minutes
        weekendLimit: 180, // minutes
        bedtime: {
          enabled: true,
          start: '21:00',
          end: '07:00'
        },
        timeSlots: [
          { day: 'weekday', start: '15:00', end: '21:00', limit: 120 },
          { day: 'weekend', start: '09:00', end: '21:00', limit: 180 }
        ]
      },
      
      // App/Website specific limits
      appLimits: {
        'Social Media': 30, // minutes per day
        'Gaming': 60,
        'Streaming': 60
      },
      
      // Monitoring
      monitoring: {
        enabled: true,
        trackWebsites: true,
        trackSearches: true,
        trackSocialMedia: true,
        trackApps: true,
        alertOnBlocked: true,
        alertOnSuspicious: true
      },
      
      // Statistics
      stats: {
        totalScreenTime: 0,
        websitesVisited: 0,
        websitesBlocked: 0,
        searchesTracked: 0,
        alertsGenerated: 0
      }
    };
    
    this.config.profiles.push(profile);
    await this.saveConfig();
    
    this.emit('profile-created', { id: profile.id, name: profile.name });
    return { success: true, profile };
  }

  async updateProfile(profileId, updates) {
    const profile = this.config.profiles.find(p => p.id === profileId);
    if (!profile) {
      throw new Error('Profile not found');
    }
    
    // Update allowed fields
    if (updates.name) profile.name = updates.name;
    if (updates.age !== undefined) profile.age = updates.age;
    if (updates.webFiltering) Object.assign(profile.webFiltering, updates.webFiltering);
    if (updates.screenTime) Object.assign(profile.screenTime, updates.screenTime);
    if (updates.appLimits) Object.assign(profile.appLimits, updates.appLimits);
    if (updates.monitoring) Object.assign(profile.monitoring, updates.monitoring);
    
    await this.saveConfig();
    this.emit('profile-updated', { id: profileId });
    
    return { success: true, profile };
  }

  async deleteProfile(profileId) {
    const index = this.config.profiles.findIndex(p => p.id === profileId);
    if (index === -1) {
      throw new Error('Profile not found');
    }
    
    const profile = this.config.profiles[index];
    this.config.profiles.splice(index, 1);
    
    if (this.config.activeProfile === profileId) {
      this.config.activeProfile = null;
    }
    
    await this.saveConfig();
    this.emit('profile-deleted', { id: profileId, name: profile.name });
    
    return { success: true };
  }

  getProfile(profileId) {
    const profile = this.config.profiles.find(p => p.id === profileId);
    if (!profile) {
      throw new Error('Profile not found');
    }
    return profile;
  }

  getAllProfiles() {
    return this.config.profiles.map(p => ({
      id: p.id,
      name: p.name,
      age: p.age,
      stats: p.stats,
      screenTime: p.screenTime,
      webFiltering: p.webFiltering
    }));
  }

  // Session Management
  async startSession(profileId, pin) {
    const profile = this.getProfile(profileId);
    
    // Verify profile PIN if set
    if (profile.pin && !this.verifyPin(pin)) {
      throw new Error('Invalid PIN');
    }
    
    // Check if in bedtime
    if (this.isInBedtime(profile)) {
      throw new Error('Cannot start session during bedtime');
    }
    
    // Check daily screen time limit
    const todayScreenTime = this.getTodayScreenTime(profileId);
    const limit = this.isWeekend() ? profile.screenTime.weekendLimit : profile.screenTime.dailyLimit;
    
    if (todayScreenTime >= limit) {
      throw new Error('Daily screen time limit reached');
    }
    
    this.currentSession = {
      profileId,
      startTime: new Date(),
      activities: []
    };
    
    this.config.activeProfile = profileId;
    await this.saveConfig();
    
    // Start screen time tracking
    this.startScreenTimeTracking();
    
    this.emit('session-started', { profileId, profile: profile.name });
    return { success: true, profile: profile.name, remainingTime: limit - todayScreenTime };
  }

  endSession() {
    if (!this.currentSession) {
      return { success: true, message: 'No active session' };
    }
    
    const duration = Math.floor((new Date() - this.currentSession.startTime) / 1000 / 60); // minutes
    
    // Save activity log
    this.activityLogs.push({
      profileId: this.currentSession.profileId,
      startTime: this.currentSession.startTime.toISOString(),
      endTime: new Date().toISOString(),
      duration,
      activities: this.currentSession.activities
    });
    
    // Update profile stats
    const profile = this.getProfile(this.currentSession.profileId);
    profile.stats.totalScreenTime += duration;
    
    this.saveActivityLogs();
    this.saveConfig();
    
    this.stopScreenTimeTracking();
    
    const sessionData = { ...this.currentSession, duration };
    this.currentSession = null;
    this.config.activeProfile = null;
    
    this.emit('session-ended', sessionData);
    return { success: true, duration };
  }

  startScreenTimeTracking() {
    if (this.screenTimeTimer) {
      clearInterval(this.screenTimeTimer);
    }
    
    this.screenTimeTimer = setInterval(() => {
      if (this.currentSession) {
        const profile = this.getProfile(this.currentSession.profileId);
        const todayScreenTime = this.getTodayScreenTime(this.currentSession.profileId);
        const limit = this.isWeekend() ? profile.screenTime.weekendLimit : profile.screenTime.dailyLimit;
        const remaining = limit - todayScreenTime;
        
        // Warning at 10 minutes remaining
        if (remaining === 10) {
          this.emit('screen-time-warning', { profileId: this.currentSession.profileId, remaining });
        }
        
        // Auto-end session when limit reached
        if (remaining <= 0) {
          this.emit('screen-time-limit-reached', { profileId: this.currentSession.profileId });
          this.endSession();
        }
        
        // Check bedtime
        if (this.isInBedtime(profile)) {
          this.emit('bedtime-reached', { profileId: this.currentSession.profileId });
          this.endSession();
        }
      }
    }, 60000); // Check every minute
  }

  stopScreenTimeTracking() {
    if (this.screenTimeTimer) {
      clearInterval(this.screenTimeTimer);
      this.screenTimeTimer = null;
    }
  }

  // Web Filtering
  async checkWebsite(url) {
    if (!this.config.enabled || !this.config.activeProfile) {
      return { allowed: true, reason: 'Parental controls not active' };
    }
    
    const profile = this.getProfile(this.config.activeProfile);
    if (!profile.webFiltering.enabled) {
      return { allowed: true, reason: 'Web filtering disabled' };
    }
    
    const urlLower = url.toLowerCase();
    const domain = this.extractDomain(url);
    
    // Check custom allowed sites first
    if (profile.webFiltering.customAllowedSites.some(site => domain.includes(site.toLowerCase()))) {
      this.logActivity('website-visit', { url, domain, allowed: true, reason: 'Whitelisted' });
      return { allowed: true, reason: 'Site whitelisted by parent' };
    }
    
    // Check custom blocked sites
    if (profile.webFiltering.customBlockedSites.some(site => domain.includes(site.toLowerCase()))) {
      profile.stats.websitesBlocked++;
      await this.saveConfig();
      this.logActivity('website-blocked', { url, domain, reason: 'Blacklisted' });
      this.emit('website-blocked', { profileId: profile.id, url, reason: 'Blacklisted' });
      return { allowed: false, reason: 'Site blocked by parent', category: 'Custom' };
    }
    
    // Check blocked categories
    for (const [category, config] of Object.entries(this.websiteCategories)) {
      if (profile.webFiltering.blockedCategories.includes(category)) {
        // Check domains
        if (config.domains.some(blockedDomain => domain.includes(blockedDomain))) {
          profile.stats.websitesBlocked++;
          await this.saveConfig();
          this.logActivity('website-blocked', { url, domain, category, reason: 'Category blocked' });
          this.emit('website-blocked', { profileId: profile.id, url, category });
          return { allowed: false, reason: `Blocked category: ${category}`, category };
        }
        
        // Check keywords
        if (config.keywords.some(keyword => urlLower.includes(keyword))) {
          profile.stats.websitesBlocked++;
          await this.saveConfig();
          this.logActivity('website-blocked', { url, domain, category, reason: 'Keyword match' });
          this.emit('website-blocked', { profileId: profile.id, url, category });
          return { allowed: false, reason: `Blocked category: ${category}`, category };
        }
      }
    }
    
    // Check social media monitoring
    const socialPlatform = this.identifySocialPlatform(domain);
    if (socialPlatform && profile.monitoring.trackSocialMedia) {
      this.logActivity('social-media-visit', { url, domain, platform: socialPlatform });
    }
    
    // Log allowed visit
    profile.stats.websitesVisited++;
    await this.saveConfig();
    this.logActivity('website-visit', { url, domain, allowed: true });
    
    return { allowed: true, reason: 'Site allowed' };
  }

  extractDomain(url) {
    try {
      const urlObj = new URL(url.startsWith('http') ? url : `https://${url}`);
      return urlObj.hostname.replace(/^www\./, '');
    } catch {
      return url;
    }
  }

  identifySocialPlatform(domain) {
    const platforms = {
      'facebook.com': 'Facebook',
      'instagram.com': 'Instagram',
      'tiktok.com': 'TikTok',
      'snapchat.com': 'Snapchat',
      'twitter.com': 'Twitter/X',
      'x.com': 'Twitter/X',
      'youtube.com': 'YouTube',
      'discord.com': 'Discord',
      'whatsapp.com': 'WhatsApp',
      'telegram.org': 'Telegram'
    };
    
    for (const [platformDomain, platformName] of Object.entries(platforms)) {
      if (domain.includes(platformDomain)) {
        return platformName;
      }
    }
    
    return null;
  }

  // Activity Logging
  logActivity(type, data) {
    if (!this.currentSession) return;
    
    const activity = {
      type,
      timestamp: new Date().toISOString(),
      ...data
    };
    
    this.currentSession.activities.push(activity);
    
    // Real-time save for important events
    if (type === 'website-blocked' || type === 'search-tracked') {
      this.saveActivityLogs();
    }
  }

  // Screen Time Utilities
  getTodayScreenTime(profileId) {
    const today = new Date().toISOString().split('T')[0];
    
    const todayLogs = this.activityLogs.filter(log => 
      log.profileId === profileId && 
      log.startTime.startsWith(today)
    );
    
    return todayLogs.reduce((total, log) => total + log.duration, 0);
  }

  isWeekend() {
    const day = new Date().getDay();
    return day === 0 || day === 6;
  }

  isInBedtime(profile) {
    if (!profile.screenTime.bedtime.enabled) return false;
    
    const now = new Date();
    const currentTime = now.getHours() * 60 + now.getMinutes();
    
    const [startHour, startMin] = profile.screenTime.bedtime.start.split(':').map(Number);
    const [endHour, endMin] = profile.screenTime.bedtime.end.split(':').map(Number);
    
    const bedtimeStart = startHour * 60 + startMin;
    const bedtimeEnd = endHour * 60 + endMin;
    
    // Handle overnight bedtime (e.g., 21:00 to 07:00)
    if (bedtimeStart > bedtimeEnd) {
      return currentTime >= bedtimeStart || currentTime < bedtimeEnd;
    } else {
      return currentTime >= bedtimeStart && currentTime < bedtimeEnd;
    }
  }

  // Reports
  async getActivityReport(profileId, days = 7) {
    const profile = this.getProfile(profileId);
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - days);
    
    const relevantLogs = this.activityLogs.filter(log => 
      log.profileId === profileId && 
      new Date(log.startTime) >= cutoffDate
    );
    
    // Calculate statistics
    const totalScreenTime = relevantLogs.reduce((sum, log) => sum + log.duration, 0);
    const averageDaily = totalScreenTime / days;
    
    // Website categories visited
    const categoriesVisited = {};
    const websitesVisited = new Map();
    const socialMediaTime = {};
    const blockedAttempts = [];
    
    relevantLogs.forEach(log => {
      log.activities.forEach(activity => {
        if (activity.type === 'website-visit' && activity.allowed) {
          websitesVisited.set(activity.domain, (websitesVisited.get(activity.domain) || 0) + 1);
        }
        
        if (activity.type === 'website-blocked') {
          blockedAttempts.push({
            url: activity.url,
            category: activity.category,
            timestamp: activity.timestamp
          });
        }
        
        if (activity.type === 'social-media-visit') {
          socialMediaTime[activity.platform] = (socialMediaTime[activity.platform] || 0) + 1;
        }
      });
    });
    
    // Daily breakdown
    const dailyBreakdown = {};
    relevantLogs.forEach(log => {
      const date = log.startTime.split('T')[0];
      dailyBreakdown[date] = (dailyBreakdown[date] || 0) + log.duration;
    });
    
    return {
      profileId,
      profileName: profile.name,
      period: {
        days,
        from: cutoffDate.toISOString(),
        to: new Date().toISOString()
      },
      screenTime: {
        total: totalScreenTime,
        averageDaily: Math.round(averageDaily),
        dailyLimit: profile.screenTime.dailyLimit,
        weekendLimit: profile.screenTime.weekendLimit,
        dailyBreakdown
      },
      websites: {
        totalVisited: websitesVisited.size,
        topSites: Array.from(websitesVisited.entries())
          .sort((a, b) => b[1] - a[1])
          .slice(0, 10)
          .map(([domain, visits]) => ({ domain, visits }))
      },
      socialMedia: {
        platforms: socialMediaTime,
        totalVisits: Object.values(socialMediaTime).reduce((sum, v) => sum + v, 0)
      },
      security: {
        blockedAttempts: blockedAttempts.length,
        recentBlocked: blockedAttempts.slice(-10)
      },
      stats: profile.stats
    };
  }

  async getSocialMediaReport(profileId, days = 7) {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - days);
    
    const relevantLogs = this.activityLogs.filter(log => 
      log.profileId === profileId && 
      new Date(log.startTime) >= cutoffDate
    );
    
    const platforms = {};
    const timeline = [];
    
    relevantLogs.forEach(log => {
      log.activities.forEach(activity => {
        if (activity.type === 'social-media-visit') {
          const platform = activity.platform;
          
          if (!platforms[platform]) {
            platforms[platform] = {
              name: platform,
              visits: 0,
              timeSpent: 0,
              lastVisit: null
            };
          }
          
          platforms[platform].visits++;
          platforms[platform].lastVisit = activity.timestamp;
          
          timeline.push({
            platform,
            url: activity.url,
            timestamp: activity.timestamp
          });
        }
      });
    });
    
    return {
      profileId,
      period: { days, from: cutoffDate.toISOString(), to: new Date().toISOString() },
      platforms: Object.values(platforms).sort((a, b) => b.visits - a.visits),
      timeline: timeline.slice(-50).reverse(),
      totalVisits: Object.values(platforms).reduce((sum, p) => sum + p.visits, 0)
    };
  }

  // Statistics
  getStatistics() {
    return {
      enabled: this.config.enabled,
      totalProfiles: this.config.profiles.length,
      activeProfile: this.config.activeProfile,
      hasMasterPin: !!this.config.masterPin,
      sessionActive: !!this.currentSession,
      totalActivityLogs: this.activityLogs.length,
      profiles: this.config.profiles.map(p => ({
        id: p.id,
        name: p.name,
        age: p.age,
        stats: p.stats
      }))
    };
  }

  // Master Control
  async enable() {
    this.config.enabled = true;
    await this.saveConfig();
    this.emit('enabled');
    return { success: true, message: 'Parental controls enabled' };
  }

  async disable(pin) {
    if (!this.verifyPin(pin)) {
      throw new Error('Invalid master PIN');
    }
    
    this.config.enabled = false;
    if (this.currentSession) {
      this.endSession();
    }
    await this.saveConfig();
    this.emit('disabled');
    return { success: true, message: 'Parental controls disabled' };
  }
}

const parentalControls = new ParentalControls();
module.exports = parentalControls;
