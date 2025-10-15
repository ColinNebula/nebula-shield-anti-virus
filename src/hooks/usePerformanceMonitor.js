import { useEffect, useRef } from 'react';

/**
 * Hook to monitor component performance
 * @param {string} componentName - Name of the component
 * @param {object} dependencies - Dependencies to track re-renders
 */
const usePerformanceMonitor = (componentName, dependencies = {}) => {
  const renderCount = useRef(0);
  const renderTimes = useRef([]);
  const lastRenderTime = useRef(performance.now());

  useEffect(() => {
    renderCount.current++;
    const currentTime = performance.now();
    const timeSinceLastRender = currentTime - lastRenderTime.current;
    
    renderTimes.current.push(timeSinceLastRender);
    
    // Keep only last 10 render times
    if (renderTimes.current.length > 10) {
      renderTimes.current.shift();
    }

    const avgRenderTime = renderTimes.current.reduce((a, b) => a + b, 0) / renderTimes.current.length;

    // Log performance data in development
    if (process.env.NODE_ENV === 'development') {
      console.log(`[Performance] ${componentName}:`, {
        renderCount: renderCount.current,
        timeSinceLastRender: `${timeSinceLastRender.toFixed(2)}ms`,
        avgRenderTime: `${avgRenderTime.toFixed(2)}ms`,
        dependencies: Object.keys(dependencies).join(', ') || 'none'
      });

      // Warn if component is re-rendering too frequently
      if (renderCount.current > 50) {
        console.warn(`⚠️ ${componentName} has rendered ${renderCount.current} times - possible performance issue`);
      }

      // Warn if render time is too long
      if (timeSinceLastRender > 100) {
        console.warn(`⚠️ ${componentName} took ${timeSinceLastRender.toFixed(2)}ms to render - might be slow`);
      }
    }

    lastRenderTime.current = currentTime;
  });

  return {
    renderCount: renderCount.current,
    avgRenderTime: renderTimes.current.reduce((a, b) => a + b, 0) / renderTimes.current.length || 0
  };
};

/**
 * Hook to measure Web Vitals
 */
export const useWebVitals = () => {
  useEffect(() => {
    if ('web-vitals' in window || process.env.NODE_ENV === 'development') {
      import('web-vitals').then(({ getCLS, getFID, getFCP, getLCP, getTTFB }) => {
        getCLS(console.log);
        getFID(console.log);
        getFCP(console.log);
        getLCP(console.log);
        getTTFB(console.log);
      });
    }
  }, []);
};

export default usePerformanceMonitor;
