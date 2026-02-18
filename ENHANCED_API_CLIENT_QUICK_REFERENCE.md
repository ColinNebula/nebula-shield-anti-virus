# Enhanced API Client - Quick Reference

## 📖 Import Statements

```javascript
// React Hooks
import { useAPI, useBatchAPI, useMutation, useCache, useOffline } from '../hooks/useAPI';

// Direct API Client
import apiClient from '../services/apiClient';
```

---

## 🎯 Common Patterns

### GET Request with Cache
```javascript
const { data, loading, error, refresh } = useAPI('/endpoint', {
  cache: true,
  cacheTTL: 5 * 60 * 1000,
  backgroundRefresh: true
});
```

### POST Request (Mutation)
```javascript
const { mutate, loading, error } = useMutation('/endpoint', {
  method: 'POST',
  onSuccess: (data) => console.log(data),
  onError: (err) => console.error(err)
});

await mutate({ key: 'value' });
```

### Batch Multiple Requests
```javascript
const { data, loading, errors } = useBatchAPI([
  { endpoint: '/status', options: { cache: true } },
  { endpoint: '/stats', options: { cache: true } }
]);
```

### Offline Detection
```javascript
const offline = useOffline();
if (offline) {
  // Show offline indicator
}
```

### Cache Management
```javascript
const { stats, clear } = useCache();
console.log(stats);  // View cache statistics
await clear();       // Clear all cache
```

---

## ⚙️ Configuration Options

### Request Options
```javascript
{
  method: 'GET',              // HTTP method
  body: { ... },              // Request body (for POST/PUT)
  cache: true,                // Enable caching
  cacheTTL: 5 * 60 * 1000,    // Cache duration (5 minutes)
  priority: 'normal',         // Priority: low, normal, high, critical
  retryable: true,            // Enable automatic retry
  offlineFallback: true,      // Use cache when offline
  backgroundRefresh: true     // Refresh in background
}
```

### Hook Options
```javascript
{
  autoFetch: true,            // Fetch on mount
  cache: true,                // Enable caching
  cacheTTL: 5 * 60 * 1000,    // Cache TTL
  backgroundRefresh: true,    // Background refresh
  refreshInterval: 30000,     // Refresh every 30s
  onSuccess: (data) => {},    // Success callback
  onError: (error) => {},     // Error callback
  dependencies: []            // Re-fetch when deps change
}
```

---

## 🚀 Direct API Client Methods

### Simple Request
```javascript
const data = await apiClient.request('/endpoint', options);
```

### Batch Requests
```javascript
const { results, errors } = await apiClient.batch([
  { endpoint: '/status', options: {} },
  { endpoint: '/stats', options: {} }
], { parallel: true });
```

### Prefetch Data
```javascript
await apiClient.prefetch(['/status', '/stats']);
```

### Cache Operations
```javascript
await apiClient.clearCache();
const stats = await apiClient.getCacheStats();
```

### Background Refresh Control
```javascript
apiClient.setBackgroundRefresh(true, 30000);
apiClient.stopBackgroundRefresh('/endpoint');
```

---

## 🎨 UI Patterns

### Loading State
```javascript
if (loading && !data) {
  return <LoadingSpinner />;
}
```

### Error State with Retry
```javascript
if (error && !data) {
  return <ErrorDisplay error={error} onRetry={refresh} />;
}
```

### Offline Indicator
```javascript
{offline && (
  <div className="offline-banner">
    📵 Offline - showing cached data
  </div>
)}
```

### Cache Badge
```javascript
{fromCache && (
  <span className="cache-badge">
    📦 Cached Data
  </span>
)}
```

---

## 🔧 Global Configuration

```javascript
import apiClient from '../services/apiClient';

// Retry settings
apiClient.retryConfig = {
  maxRetries: 3,
  baseDelay: 1000,
  maxDelay: 10000,
  backoffFactor: 2,
  retryableStatuses: [408, 429, 500, 502, 503, 504]
};

// Background refresh interval
apiClient.setBackgroundRefresh(true, 30000);

// Default cache TTL
apiClient.cache.maxAge = 5 * 60 * 1000;
```

---

## 📊 Return Values

### useAPI Hook
```javascript
{
  data: any,           // Response data
  error: Error,        // Error object
  loading: boolean,    // Loading state
  offline: boolean,    // Offline status
  fromCache: boolean,  // Data from cache
  refresh: () => {},   // Force refresh
  retry: () => {},     // Retry request
  fetch: () => {}      // Manual fetch
}
```

### useMutation Hook
```javascript
{
  data: any,           // Response data
  error: Error,        // Error object
  loading: boolean,    // Loading state
  mutate: (body) => {}, // Execute mutation
  reset: () => {}      // Reset state
}
```

### useBatchAPI Hook
```javascript
{
  data: any[],         // Array of responses
  errors: Error[],     // Array of errors
  loading: boolean,    // Loading state
  refresh: () => {},   // Refresh all
  fetch: () => {}      // Manual fetch
}
```

### useCache Hook
```javascript
{
  stats: {
    totalEntries: number,
    offlineMode: boolean,
    backgroundRefreshEnabled: boolean,
    activeBackgroundTasks: number,
    pendingRequests: number,
    queuedRequests: number
  },
  clear: () => {},     // Clear cache
  refresh: () => {}    // Refresh stats
}
```

---

## 🎯 Priority Levels

- **`critical`** - Immediate processing (threat blocking, alerts)
- **`high`** - Important operations (scans, updates)
- **`normal`** - Regular requests (dashboard data)
- **`low`** - Background tasks (analytics, prefetch)

---

## ⚡ Performance Tips

1. **Enable cache for GET requests**
   ```javascript
   useAPI('/status', { cache: true })
   ```

2. **Use batch for multiple endpoints**
   ```javascript
   useBatchAPI([...], { parallel: true })
   ```

3. **Prefetch critical data**
   ```javascript
   apiClient.prefetch(['/status', '/stats'])
   ```

4. **Set appropriate cache TTL**
   - Dynamic data: 1-5 minutes
   - Static data: 10-60 minutes

5. **Enable background refresh for dashboards**
   ```javascript
   useAPI('/dashboard', { backgroundRefresh: true })
   ```

---

## 🐛 Debugging

### Check Cache Stats
```javascript
const stats = await apiClient.getCacheStats();
console.log(stats);
```

### Clear Cache
```javascript
await apiClient.clearCache();
```

### Monitor Events
```javascript
window.addEventListener('cache_refreshed', (e) => {
  console.log('Fresh data:', e.detail);
});

window.addEventListener('api_offline', () => {
  console.log('API offline');
});

window.addEventListener('api_online', () => {
  console.log('API online');
});
```

### Force Network Request
```javascript
const data = await apiClient.request('/endpoint', {
  cache: false
});
```

---

## ✅ Best Practices

1. ✅ Always handle offline state in UI
2. ✅ Show cache indicator when displaying cached data
3. ✅ Provide manual refresh option
4. ✅ Set appropriate cache TTL for data type
5. ✅ Use batch requests for related data
6. ✅ Enable background refresh for real-time data
7. ✅ Clear cache on logout
8. ✅ Prioritize user-triggered actions
9. ✅ Test offline functionality
10. ✅ Monitor cache statistics

---

## 🔗 Related Documentation

- **Full Guide**: `ENHANCED_API_CLIENT_GUIDE.md`
- **Summary**: `ENHANCED_API_CLIENT_SUMMARY.md`
- **Example**: `src/components/EnhancedDashboardExample.js`
- **Implementation**: `src/services/apiClient.js`

---

## 📝 Examples Location

See `src/components/EnhancedDashboardExample.js` for complete working examples of:
- Single API requests with cache
- Batch requests
- Mutations (POST/PUT/DELETE)
- Cache management
- Offline handling
- Background refresh
