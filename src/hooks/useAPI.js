/**
 * React Hook for Enhanced API Client
 * 
 * Features:
 * - Automatic loading states
 * - Error handling with retry
 * - Offline detection
 * - Background refresh
 * - Cache management
 */

import { useState, useEffect, useCallback, useRef } from 'react';
import apiClient from '../services/apiClient';

/**
 * Main useAPI hook
 */
export const useAPI = (endpoint, options = {}) => {
  const {
    method = 'GET',
    body = null,
    autoFetch = true,
    cache = true,
    cacheTTL = 5 * 60 * 1000,
    backgroundRefresh = false,
    refreshInterval = 30000,
    onSuccess = null,
    onError = null,
    dependencies = []
  } = options;

  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(autoFetch);
  const [offline, setOffline] = useState(!navigator.onLine);
  const [fromCache, setFromCache] = useState(false);

  const isMountedRef = useRef(true);
  const refreshIntervalRef = useRef(null);

  // Fetch function
  const fetchData = useCallback(async (customOptions = {}) => {
    setLoading(true);
    setError(null);

    try {
      const result = await apiClient.request(endpoint, {
        method,
        body,
        cache,
        cacheTTL,
        backgroundRefresh,
        ...customOptions
      });

      if (isMountedRef.current) {
        setData(result);
        setFromCache(false);
        
        if (onSuccess) {
          onSuccess(result);
        }
      }

      return result;
    } catch (err) {
      if (isMountedRef.current) {
        setError(err);
        
        if (onError) {
          onError(err);
        }
      }
      throw err;
    } finally {
      if (isMountedRef.current) {
        setLoading(false);
      }
    }
  }, [endpoint, method, body, cache, cacheTTL, backgroundRefresh, onSuccess, onError]);

  // Refresh function
  const refresh = useCallback(() => {
    return fetchData({ cache: false });
  }, [fetchData]);

  // Retry function
  const retry = useCallback(() => {
    return fetchData();
  }, [fetchData]);

  // Auto-fetch on mount and dependencies change
  useEffect(() => {
    if (autoFetch) {
      fetchData();
    }
  }, [autoFetch, ...dependencies]);

  // Setup background refresh
  useEffect(() => {
    if (backgroundRefresh && refreshInterval > 0) {
      refreshIntervalRef.current = setInterval(() => {
        fetchData({ cache: true });
      }, refreshInterval);

      return () => {
        if (refreshIntervalRef.current) {
          clearInterval(refreshIntervalRef.current);
        }
      };
    }
  }, [backgroundRefresh, refreshInterval, fetchData]);

  // Listen for online/offline events
  useEffect(() => {
    const handleOnline = () => setOffline(false);
    const handleOffline = () => setOffline(true);
    const handleCacheRefreshed = (event) => {
      if (event.detail.endpoint.includes(endpoint)) {
        setFromCache(false);
      }
    };

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);
    window.addEventListener('cache_refreshed', handleCacheRefreshed);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
      window.removeEventListener('cache_refreshed', handleCacheRefreshed);
    };
  }, [endpoint]);

  // Cleanup
  useEffect(() => {
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  return {
    data,
    error,
    loading,
    offline,
    fromCache,
    refresh,
    retry,
    fetch: fetchData
  };
};

/**
 * Hook for batch API requests
 */
export const useBatchAPI = (requests, options = {}) => {
  const {
    autoFetch = true,
    parallel = true,
    maxConcurrent = 5,
    continueOnError = true,
    onSuccess = null,
    onError = null,
    dependencies = []
  } = options;

  const [data, setData] = useState(null);
  const [errors, setErrors] = useState([]);
  const [loading, setLoading] = useState(autoFetch);

  const isMountedRef = useRef(true);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setErrors([]);

    try {
      const result = await apiClient.batch(requests, {
        parallel,
        maxConcurrent,
        continueOnError
      });

      if (isMountedRef.current) {
        setData(result.results);
        setErrors(result.errors);
        
        if (onSuccess) {
          onSuccess(result);
        }
      }

      return result;
    } catch (err) {
      if (isMountedRef.current) {
        setErrors([{ error: err }]);
        
        if (onError) {
          onError(err);
        }
      }
      throw err;
    } finally {
      if (isMountedRef.current) {
        setLoading(false);
      }
    }
  }, [requests, parallel, maxConcurrent, continueOnError, onSuccess, onError]);

  useEffect(() => {
    if (autoFetch) {
      fetchData();
    }
  }, [autoFetch, ...dependencies]);

  useEffect(() => {
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  return {
    data,
    errors,
    loading,
    refresh: fetchData,
    fetch: fetchData
  };
};

/**
 * Hook for mutations (POST, PUT, DELETE)
 */
export const useMutation = (endpoint, options = {}) => {
  const {
    method = 'POST',
    onSuccess = null,
    onError = null
  } = options;

  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const isMountedRef = useRef(true);

  const mutate = useCallback(async (body, customOptions = {}) => {
    setLoading(true);
    setError(null);

    try {
      const result = await apiClient.request(endpoint, {
        method,
        body,
        cache: false,
        ...customOptions
      });

      if (isMountedRef.current) {
        setData(result);
        
        if (onSuccess) {
          onSuccess(result);
        }
      }

      return result;
    } catch (err) {
      if (isMountedRef.current) {
        setError(err);
        
        if (onError) {
          onError(err);
        }
      }
      throw err;
    } finally {
      if (isMountedRef.current) {
        setLoading(false);
      }
    }
  }, [endpoint, method, onSuccess, onError]);

  const reset = useCallback(() => {
    setData(null);
    setError(null);
    setLoading(false);
  }, []);

  useEffect(() => {
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  return {
    data,
    error,
    loading,
    mutate,
    reset
  };
};

/**
 * Hook for cache management
 */
export const useCache = () => {
  const [stats, setStats] = useState(null);

  const refreshStats = useCallback(async () => {
    const cacheStats = await apiClient.getCacheStats();
    setStats(cacheStats);
  }, []);

  const clear = useCallback(async () => {
    await apiClient.clearCache();
    await refreshStats();
  }, [refreshStats]);

  useEffect(() => {
    refreshStats();
  }, [refreshStats]);

  return {
    stats,
    clear,
    refresh: refreshStats
  };
};

/**
 * Hook for offline detection
 */
export const useOffline = () => {
  const [offline, setOffline] = useState(!navigator.onLine);

  useEffect(() => {
    const handleOnline = () => setOffline(false);
    const handleOffline = () => setOffline(true);

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);
    window.addEventListener('api_online', handleOnline);
    window.addEventListener('api_offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
      window.removeEventListener('api_online', handleOnline);
      window.removeEventListener('api_offline', handleOffline);
    };
  }, []);

  return offline;
};

export default useAPI;
