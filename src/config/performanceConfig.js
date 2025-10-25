/**
 * Performance Optimization Configuration
 * Applied optimizations to reduce initial load time
 */

// Webpack Bundle Analyzer (run: npm run build -- --stats)
// Use this to identify large dependencies that can be code-split

// Performance Budget
export const PERFORMANCE_BUDGET = {
  maxInitialBundle: 500, // KB
  maxAsyncChunk: 200, // KB
  maxImageSize: 100, // KB
  targetLoadTime: 2000, // ms (First Contentful Paint)
};

// Lazy Loading Priority
export const LAZY_LOAD_PRIORITY = {
  // Critical (preload after initial render)
  critical: ['Dashboard', 'Scanner', 'Login'],
  
  // High (preload on user interaction)
  high: ['Settings', 'Quarantine', 'WebProtection'],
  
  // Medium (load on demand)
  medium: ['EmailProtection', 'NetworkProtection', 'Firewall'],
  
  // Low (load when needed)
  low: ['Premium', 'AdminPanel', 'TermsOfService'],
};

// Image Optimization
export const IMAGE_FORMATS = {
  svg: ['logo', 'icons'], // Use SVG for scalable graphics
  webp: ['screenshots', 'backgrounds'], // Use WebP for photos
  png: ['fallback'], // PNG as fallback
};

// Cache Strategy
export const CACHE_CONFIG = {
  // Service Worker Cache (disabled for Electron)
  static: {
    enabled: false,
    maxAge: 7 * 24 * 60 * 60, // 7 days
  },
  
  // Memory Cache
  runtime: {
    maxSize: 50, // MB
    ttl: 5 * 60 * 1000, // 5 minutes
  },
  
  // LocalStorage
  persistent: {
    maxSize: 10, // MB
    keys: ['auth', 'settings', 'theme'],
  },
};

// Network Optimization
export const NETWORK_CONFIG = {
  timeout: 10000, // 10 seconds
  retries: 3,
  retryDelay: 1000, // 1 second
  compression: true,
  prefetch: {
    enabled: true,
    routes: ['/', '/dashboard', '/scanner'],
  },
};

// Animation Performance
export const ANIMATION_CONFIG = {
  // Reduce animations on low-end devices
  reducedMotion: window.matchMedia('(prefers-reduced-motion: reduce)').matches,
  
  // Animation budgets (ms)
  transitions: {
    fast: 150,
    normal: 300,
    slow: 500,
  },
  
  // Disable heavy animations
  disableHeavyEffects: false,
};

// Code Splitting Thresholds
export const CODE_SPLIT_CONFIG = {
  minSize: 20000, // 20KB - minimum size to create new chunk
  maxSize: 244000, // 244KB - maximum size before warning
  maxAsyncRequests: 30,
  maxInitialRequests: 30,
};

export default {
  PERFORMANCE_BUDGET,
  LAZY_LOAD_PRIORITY,
  IMAGE_FORMATS,
  CACHE_CONFIG,
  NETWORK_CONFIG,
  ANIMATION_CONFIG,
  CODE_SPLIT_CONFIG,
};
