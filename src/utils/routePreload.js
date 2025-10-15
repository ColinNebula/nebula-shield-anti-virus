/**
 * Route Preloading Utility
 * Preloads route components on hover/mouseenter to improve navigation speed
 */

const preloadedComponents = new Set();

/**
 * Preload a lazy-loaded component
 * @param {Function} lazyComponent - The lazy-loaded component
 * @returns {Promise} - Promise that resolves when component is loaded
 */
export const preloadComponent = (lazyComponent) => {
  if (!lazyComponent || typeof lazyComponent._payload?._result !== 'undefined') {
    // Already loaded
    return Promise.resolve();
  }

  // Check if already being preloaded
  const componentKey = lazyComponent.toString();
  if (preloadedComponents.has(componentKey)) {
    return Promise.resolve();
  }

  preloadedComponents.add(componentKey);

  // Trigger the lazy load
  return lazyComponent._payload._result || lazyComponent._init?.(lazyComponent._payload);
};

/**
 * Create a preloadable link component
 * @param {Object} props - Link properties
 * @param {Function} component - Lazy component to preload
 */
export const createPreloadableLink = (LinkComponent) => {
  return ({ to, component, onMouseEnter, ...props }) => {
    const handleMouseEnter = (e) => {
      if (component) {
        preloadComponent(component);
      }
      if (onMouseEnter) {
        onMouseEnter(e);
      }
    };

    return (
      <LinkComponent 
        to={to} 
        onMouseEnter={handleMouseEnter}
        {...props} 
      />
    );
  };
};

/**
 * Preload multiple components in parallel
 * @param {Array} components - Array of lazy components
 */
export const preloadComponents = (components) => {
  return Promise.all(components.map(preloadComponent));
};

/**
 * Preload components after initial page load
 * Useful for preloading frequently accessed routes
 * @param {Array} components - Array of lazy components to preload
 * @param {Number} delay - Delay before starting preload (ms)
 */
export const preloadAfterLoad = (components, delay = 2000) => {
  if (typeof window === 'undefined') return;

  const loadComponents = () => {
    if ('requestIdleCallback' in window) {
      requestIdleCallback(() => preloadComponents(components), {
        timeout: 5000
      });
    } else {
      setTimeout(() => preloadComponents(components), delay);
    }
  };

  if (document.readyState === 'complete') {
    loadComponents();
  } else {
    window.addEventListener('load', loadComponents);
  }
};

/**
 * Preload component on link hover with debouncing
 */
export const useRoutePreload = (routes) => {
  const preloadRoute = (routePath) => {
    const route = routes.find(r => r.path === routePath);
    if (route && route.component) {
      preloadComponent(route.component);
    }
  };

  return { preloadRoute };
};

export default {
  preloadComponent,
  preloadComponents,
  preloadAfterLoad,
  createPreloadableLink,
  useRoutePreload
};
