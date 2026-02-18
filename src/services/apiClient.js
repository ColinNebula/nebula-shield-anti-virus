/**
 * Enhanced API Client
 * 
 * Features:
 * - Automatic retry with exponential backoff
 * - Offline mode with cached data
 * - Request deduplication
 * - Background refresh
 * - Optimized batch requests
 * - Request prioritization
 * - Error recovery strategies
 */

// IndexedDB cache manager
class CacheManager {
  constructor() {
    this.dbName = 'NebulaShieldCache';
    this.version = 1;
    this.db = null;
    this.storeName = 'apiCache';
    this.maxAge = 5 * 60 * 1000; // 5 minutes default
  }

  async init() {
    if (this.db) return this.db;

    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, this.version);

      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        this.db = request.result;
        resolve(this.db);
      };

      request.onupgradeneeded = (event) => {
        const db = event.target.result;
        if (!db.objectStoreNames.contains(this.storeName)) {
          const store = db.createObjectStore(this.storeName, { keyPath: 'key' });
          store.createIndex('timestamp', 'timestamp', { unique: false });
          store.createIndex('expiresAt', 'expiresAt', { unique: false });
        }
      };
    });
  }

  async get(key) {
    await this.init();
    
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([this.storeName], 'readonly');
      const store = transaction.objectStore(this.storeName);
      const request = store.get(key);

      request.onsuccess = () => {
        const result = request.result;
        
        // Check if expired
        if (result && result.expiresAt > Date.now()) {
          resolve(result.data);
        } else {
          // Clean up expired entry
          if (result) {
            this.delete(key);
          }
          resolve(null);
        }
      };

      request.onerror = () => reject(request.error);
    });
  }

  async set(key, data, maxAge = this.maxAge) {
    await this.init();
    
    const entry = {
      key,
      data,
      timestamp: Date.now(),
      expiresAt: Date.now() + maxAge
    };

    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([this.storeName], 'readwrite');
      const store = transaction.objectStore(this.storeName);
      const request = store.put(entry);

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  async delete(key) {
    await this.init();
    
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([this.storeName], 'readwrite');
      const store = transaction.objectStore(this.storeName);
      const request = store.delete(key);

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  async clear() {
    await this.init();
    
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([this.storeName], 'readwrite');
      const store = transaction.objectStore(this.storeName);
      const request = store.clear();

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  }

  async cleanExpired() {
    await this.init();
    
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction([this.storeName], 'readwrite');
      const store = transaction.objectStore(this.storeName);
      const index = store.index('expiresAt');
      const range = IDBKeyRange.upperBound(Date.now());
      const request = index.openCursor(range);

      request.onsuccess = (event) => {
        const cursor = event.target.result;
        if (cursor) {
          store.delete(cursor.primaryKey);
          cursor.continue();
        } else {
          resolve();
        }
      };

      request.onerror = () => reject(request.error);
    });
  }
}

// Enhanced API Client
class APIClient {
  constructor(baseURL = '/api') {
    this.baseURL = baseURL;
    this.cache = new CacheManager();
    this.pendingRequests = new Map(); // Request deduplication
    this.retryConfig = {
      maxRetries: 3,
      baseDelay: 1000, // 1 second
      maxDelay: 10000, // 10 seconds
      backoffFactor: 2,
      retryableStatuses: [408, 429, 500, 502, 503, 504]
    };
    this.offlineMode = false;
    this.backgroundRefreshEnabled = true;
    this.backgroundRefreshInterval = 30000; // 30 seconds
    this.backgroundTasks = new Map();
    this.requestQueue = []; // Priority queue
    this.isProcessingQueue = false;

    // Monitor online/offline status
    if (typeof window !== 'undefined') {
      window.addEventListener('online', () => this.handleOnline());
      window.addEventListener('offline', () => this.handleOffline());
      this.offlineMode = !navigator.onLine;
    }

    // Start background cleanup
    this.startBackgroundCleanup();
  }

  /**
   * Handle online status
   */
  handleOnline() {
    console.log('🌐 Back online - resuming API calls');
    this.offlineMode = false;
    this.processQueue();
    
    // Trigger event
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('api_online'));
    }
  }

  /**
   * Handle offline status
   */
  handleOffline() {
    console.log('📵 Offline - switching to cached data');
    this.offlineMode = true;
    
    // Trigger event
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('api_offline'));
    }
  }

  /**
   * Make API request with retry logic
   */
  async request(endpoint, options = {}) {
    const {
      method = 'GET',
      body = null,
      headers = {},
      cache = true,
      cacheTTL = 5 * 60 * 1000, // 5 minutes
      priority = 'normal', // low, normal, high, critical
      retryable = true,
      offlineFallback = true,
      backgroundRefresh = false
    } = options;

    const url = `${this.baseURL}${endpoint}`;
    const cacheKey = this.getCacheKey(method, endpoint, body);

    // Request deduplication - avoid duplicate simultaneous requests
    if (this.pendingRequests.has(cacheKey)) {
      console.log('🔄 Deduplicating request:', endpoint);
      return this.pendingRequests.get(cacheKey);
    }

    // If offline and cache is available, return cached data
    if (this.offlineMode && offlineFallback && method === 'GET') {
      const cachedData = await this.cache.get(cacheKey);
      if (cachedData) {
        console.log('📦 Returning cached data (offline):', endpoint);
        return cachedData;
      }
    }

    // Create the request promise
    const requestPromise = this.executeRequest({
      url,
      method,
      body,
      headers,
      cache,
      cacheTTL,
      cacheKey,
      retryable,
      priority
    });

    // Store pending request
    this.pendingRequests.set(cacheKey, requestPromise);

    try {
      const result = await requestPromise;
      
      // Setup background refresh if enabled
      if (backgroundRefresh && cache && method === 'GET') {
        this.setupBackgroundRefresh(endpoint, options);
      }
      
      return result;
    } finally {
      // Clean up pending request
      this.pendingRequests.delete(cacheKey);
    }
  }

  /**
   * Execute request with retry logic
   */
  async executeRequest(config) {
    const { url, method, body, headers, cache, cacheTTL, cacheKey, retryable, priority } = config;
    let lastError;
    let attempt = 0;

    while (attempt <= this.retryConfig.maxRetries) {
      try {
        // Check cache first for GET requests
        if (method === 'GET' && cache && attempt === 0) {
          const cachedData = await this.cache.get(cacheKey);
          if (cachedData) {
            console.log('📦 Returning cached data:', url);
            
            // Trigger background refresh if stale
            this.triggerBackgroundRefresh(config);
            
            return cachedData;
          }
        }

        // Make the request
        const response = await fetch(url, {
          method,
          headers: {
            'Content-Type': 'application/json',
            ...headers
          },
          body: body ? JSON.stringify(body) : null
        });

        // Handle response
        if (!response.ok) {
          // Check if retryable
          if (retryable && this.retryConfig.retryableStatuses.includes(response.status)) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
          }
          
          // Non-retryable error
          const errorData = await response.json().catch(() => ({}));
          throw new Error(errorData.message || `HTTP ${response.status}: ${response.statusText}`);
        }

        // Parse response
        const data = await response.json();

        // Cache successful GET requests
        if (method === 'GET' && cache) {
          await this.cache.set(cacheKey, data, cacheTTL);
        }

        return data;

      } catch (error) {
        lastError = error;
        attempt++;

        // If not retryable or max retries reached
        if (!retryable || attempt > this.retryConfig.maxRetries) {
          console.error(`❌ Request failed after ${attempt} attempts:`, url, error.message);
          
          // Try to return cached data as fallback
          if (method === 'GET' && cache) {
            const cachedData = await this.cache.get(cacheKey);
            if (cachedData) {
              console.log('📦 Returning stale cached data as fallback:', url);
              return cachedData;
            }
          }
          
          throw error;
        }

        // Calculate delay with exponential backoff
        const delay = Math.min(
          this.retryConfig.baseDelay * Math.pow(this.retryConfig.backoffFactor, attempt - 1),
          this.retryConfig.maxDelay
        );

        console.warn(`⚠️ Retry ${attempt}/${this.retryConfig.maxRetries} after ${delay}ms:`, url);
        await this.sleep(delay);
      }
    }

    throw lastError;
  }

  /**
   * Batch multiple requests
   */
  async batch(requests, options = {}) {
    const { 
      parallel = true,
      maxConcurrent = 5,
      continueOnError = true 
    } = options;

    if (parallel) {
      // Execute in parallel with concurrency limit
      const results = [];
      const errors = [];

      for (let i = 0; i < requests.length; i += maxConcurrent) {
        const batch = requests.slice(i, i + maxConcurrent);
        const batchPromises = batch.map(req => 
          this.request(req.endpoint, req.options)
            .catch(error => {
              errors.push({ request: req, error });
              return continueOnError ? null : Promise.reject(error);
            })
        );

        const batchResults = await Promise.all(batchPromises);
        results.push(...batchResults);
      }

      return { results, errors };
    } else {
      // Execute sequentially
      const results = [];
      const errors = [];

      for (const req of requests) {
        try {
          const result = await this.request(req.endpoint, req.options);
          results.push(result);
        } catch (error) {
          errors.push({ request: req, error });
          if (!continueOnError) {
            throw error;
          }
          results.push(null);
        }
      }

      return { results, errors };
    }
  }

  /**
   * Setup background refresh for an endpoint
   */
  setupBackgroundRefresh(endpoint, options) {
    if (!this.backgroundRefreshEnabled) return;

    const key = `bg_${endpoint}`;
    
    // Clear existing refresh task
    if (this.backgroundTasks.has(key)) {
      clearInterval(this.backgroundTasks.get(key));
    }

    // Setup new refresh task
    const interval = setInterval(async () => {
      try {
        console.log('🔄 Background refresh:', endpoint);
        await this.request(endpoint, { ...options, cache: true });
      } catch (error) {
        console.error('Background refresh error:', error);
      }
    }, this.backgroundRefreshInterval);

    this.backgroundTasks.set(key, interval);
  }

  /**
   * Stop background refresh for an endpoint
   */
  stopBackgroundRefresh(endpoint) {
    const key = `bg_${endpoint}`;
    if (this.backgroundTasks.has(key)) {
      clearInterval(this.backgroundTasks.get(key));
      this.backgroundTasks.delete(key);
    }
  }

  /**
   * Trigger background refresh if data is stale
   */
  triggerBackgroundRefresh(config) {
    // Trigger async refresh without waiting
    setTimeout(async () => {
      try {
        console.log('🔄 Refreshing stale cache:', config.url);
        const response = await fetch(config.url, {
          method: config.method,
          headers: {
            'Content-Type': 'application/json',
            ...config.headers
          },
          body: config.body ? JSON.stringify(config.body) : null
        });

        if (response.ok) {
          const data = await response.json();
          await this.cache.set(config.cacheKey, data, config.cacheTTL);
          
          // Notify listeners of fresh data
          if (typeof window !== 'undefined') {
            window.dispatchEvent(new CustomEvent('cache_refreshed', { 
              detail: { endpoint: config.url, data } 
            }));
          }
        }
      } catch (error) {
        console.error('Background refresh error:', error);
      }
    }, 0);
  }

  /**
   * Add request to priority queue
   */
  enqueue(endpoint, options = {}, priority = 'normal') {
    this.requestQueue.push({ endpoint, options, priority });
    this.requestQueue.sort((a, b) => {
      const priorities = { critical: 0, high: 1, normal: 2, low: 3 };
      return priorities[a.priority] - priorities[b.priority];
    });
    
    if (!this.isProcessingQueue) {
      this.processQueue();
    }
  }

  /**
   * Process request queue
   */
  async processQueue() {
    if (this.isProcessingQueue || this.requestQueue.length === 0) return;

    this.isProcessingQueue = true;

    while (this.requestQueue.length > 0) {
      const { endpoint, options } = this.requestQueue.shift();
      try {
        await this.request(endpoint, options);
      } catch (error) {
        console.error('Queue processing error:', error);
      }
    }

    this.isProcessingQueue = false;
  }

  /**
   * Get cache key
   */
  getCacheKey(method, endpoint, body) {
    const bodyStr = body ? JSON.stringify(body) : '';
    return `${method}:${endpoint}:${bodyStr}`;
  }

  /**
   * Sleep utility
   */
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Start background cleanup of expired cache
   */
  startBackgroundCleanup() {
    setInterval(async () => {
      try {
        await this.cache.cleanExpired();
        console.log('🧹 Cache cleanup completed');
      } catch (error) {
        console.error('Cache cleanup error:', error);
      }
    }, 10 * 60 * 1000); // Every 10 minutes
  }

  /**
   * Clear all cache
   */
  async clearCache() {
    await this.cache.clear();
    console.log('🗑️ Cache cleared');
  }

  /**
   * Get cache statistics
   */
  async getCacheStats() {
    await this.cache.init();
    
    return new Promise((resolve, reject) => {
      const transaction = this.cache.db.transaction([this.cache.storeName], 'readonly');
      const store = transaction.objectStore(this.cache.storeName);
      const countRequest = store.count();

      countRequest.onsuccess = () => {
        resolve({
          totalEntries: countRequest.result,
          offlineMode: this.offlineMode,
          backgroundRefreshEnabled: this.backgroundRefreshEnabled,
          activeBackgroundTasks: this.backgroundTasks.size,
          pendingRequests: this.pendingRequests.size,
          queuedRequests: this.requestQueue.length
        });
      };

      countRequest.onerror = () => reject(countRequest.error);
    });
  }

  /**
   * Enable/disable background refresh
   */
  setBackgroundRefresh(enabled, interval = 30000) {
    this.backgroundRefreshEnabled = enabled;
    if (interval) {
      this.backgroundRefreshInterval = interval;
    }
    
    if (!enabled) {
      // Stop all background tasks
      this.backgroundTasks.forEach((task, key) => {
        clearInterval(task);
      });
      this.backgroundTasks.clear();
    }
  }

  /**
   * Prefetch endpoints
   */
  async prefetch(endpoints) {
    const requests = endpoints.map(endpoint => ({
      endpoint,
      options: { cache: true, priority: 'low' }
    }));

    return this.batch(requests, { parallel: true, continueOnError: true });
  }
}

// Create singleton instance
const apiClient = new APIClient();

export default apiClient;

// Export convenience methods
export const get = (endpoint, options) => apiClient.request(endpoint, { ...options, method: 'GET' });
export const post = (endpoint, body, options) => apiClient.request(endpoint, { ...options, method: 'POST', body });
export const put = (endpoint, body, options) => apiClient.request(endpoint, { ...options, method: 'PUT', body });
export const del = (endpoint, options) => apiClient.request(endpoint, { ...options, method: 'DELETE' });
export const batch = (requests, options) => apiClient.batch(requests, options);
export const clearCache = () => apiClient.clearCache();
export const getCacheStats = () => apiClient.getCacheStats();
export const setBackgroundRefresh = (enabled, interval) => apiClient.setBackgroundRefresh(enabled, interval);
export const prefetch = (endpoints) => apiClient.prefetch(endpoints);
