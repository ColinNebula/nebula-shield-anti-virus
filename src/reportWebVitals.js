/**
 * Web Vitals Reporting
 * Sends performance metrics to analytics service
 */

const reportWebVitals = (onPerfEntry) => {
  if (onPerfEntry && onPerfEntry instanceof Function) {
    import('web-vitals').then(({ getCLS, getFID, getFCP, getLCP, getTTFB }) => {
      getCLS(onPerfEntry);
      getFID(onPerfEntry);
      getFCP(onPerfEntry);
      getLCP(onPerfEntry);
      getTTFB(onPerfEntry);
    });
  }
};

/**
 * Send performance metrics to analytics backend
 */
export const reportToAnalytics = () => {
  if (typeof window === 'undefined') return;

  reportWebVitals((metric) => {
    // Send to analytics backend
    const body = JSON.stringify({
      name: metric.name,
      value: metric.value,
      delta: metric.delta,
      id: metric.id,
      rating: metric.rating,
      navigationType: metric.navigationType,
      timestamp: Date.now(),
      url: window.location.href,
      userAgent: navigator.userAgent,
    });

    // Use sendBeacon if available, otherwise fallback to fetch
    if ('sendBeacon' in navigator) {
      navigator.sendBeacon('http://localhost:8080/api/analytics/performance', body);
    } else {
      fetch('http://localhost:8080/api/analytics/performance', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
        keepalive: true,
      }).catch((err) => {
        console.error('Failed to send performance metric:', err);
      });
    }

    // Also log to console in development
    if (process.env.NODE_ENV === 'development') {
      console.log('Web Vital:', metric.name, metric.value, metric.rating);
    }
  });
};

export default reportWebVitals;
