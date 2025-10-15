/**
 * Route Configuration with Code Splitting
 * All routes use lazy loading for optimal bundle size
 */

import { lazy } from 'react';

// Lazy load all route components
export const routeComponents = {
  // Auth routes
  Login: lazy(() => import('../pages/Login')),
  Register: lazy(() => import('../pages/Register')),
  ForgotPassword: lazy(() => import('../pages/ForgotPassword')),
  VerifyEmail: lazy(() => import('../pages/VerifyEmail')),
  CheckEmail: lazy(() => import('../pages/CheckEmail')),
  
  // Main app routes
  Dashboard: lazy(() => import('../components/Dashboard')),
  Scanner: lazy(() => import('../components/Scanner')),
  Quarantine: lazy(() => import('../components/Quarantine')),
  Settings: lazy(() => import('../components/Settings')),
  
  // Premium features
  Premium: lazy(() => import('../pages/Premium')),
  PaymentSuccess: lazy(() => import('../pages/PaymentSuccess')),
  PaymentCancel: lazy(() => import('../pages/PaymentCancel')),
  
  // Security features
  WebProtection: lazy(() => import('../pages/WebProtection')),
  EnhancedWebProtection: lazy(() => import('../pages/EnhancedWebProtection')),
  EmailProtection: lazy(() => import('../pages/EmailProtection')),
  HackerProtection: lazy(() => import('../pages/HackerProtection')),
  RansomwareProtection: lazy(() => import('../pages/RansomwareProtection')),
  DataProtection: lazy(() => import('../pages/DataProtection')),
  
  // Network & System
  EnhancedDriverScanner: lazy(() => import('../pages/EnhancedDriverScanner')),
  EnhancedNetworkProtection: lazy(() => import('../pages/EnhancedNetworkProtection')),
  AdvancedFirewall: lazy(() => import('../pages/AdvancedFirewall')),
  FirewallLogs: lazy(() => import('../pages/FirewallLogs')),
  
  // Advanced features
  EnhancedScanner: lazy(() => import('../pages/EnhancedScanner')),
  MLDetection: lazy(() => import('../pages/MLDetection')),
  DiskCleanup: lazy(() => import('../pages/DiskCleanup')),
  PerformanceMetrics: lazy(() => import('../pages/PerformanceMetrics')),
  
  // Admin
  AdminPanel: lazy(() => import('../pages/AdminPanel')),
};

/**
 * Route configuration with metadata
 * Used for preloading and navigation
 */
export const routes = [
  // Public routes
  { path: '/login', component: routeComponents.Login, public: true, preload: true },
  { path: '/register', component: routeComponents.Register, public: true },
  { path: '/forgot-password', component: routeComponents.ForgotPassword, public: true },
  { path: '/verify-email', component: routeComponents.VerifyEmail, public: true },
  { path: '/check-email', component: routeComponents.CheckEmail, public: true },
  
  // Protected routes
  { path: '/', component: routeComponents.Dashboard, protected: true, preload: true },
  { path: '/scanner', component: routeComponents.Scanner, protected: true, preload: true },
  { path: '/quarantine', component: routeComponents.Quarantine, protected: true },
  { path: '/settings', component: routeComponents.Settings, protected: true },
  
  // Premium routes
  { path: '/premium', component: routeComponents.Premium, protected: true },
  { path: '/payment-success', component: routeComponents.PaymentSuccess, protected: true },
  { path: '/payment-cancel', component: routeComponents.PaymentCancel, protected: true },
  
  // Security routes
  { path: '/web-protection', component: routeComponents.WebProtection, protected: true },
  { path: '/enhanced-web-protection', component: routeComponents.EnhancedWebProtection, protected: true, premium: true },
  { path: '/email-protection', component: routeComponents.EmailProtection, protected: true },
  { path: '/hacker-protection', component: routeComponents.HackerProtection, protected: true },
  { path: '/ransomware-protection', component: routeComponents.RansomwareProtection, protected: true },
  { path: '/data-protection', component: routeComponents.DataProtection, protected: true },
  
  // Network & System routes
  { path: '/driver-scanner', component: routeComponents.EnhancedDriverScanner, protected: true },
  { path: '/network-protection', component: routeComponents.EnhancedNetworkProtection, protected: true },
  { path: '/advanced-firewall', component: routeComponents.AdvancedFirewall, protected: true, premium: true },
  { path: '/firewall-logs', component: routeComponents.FirewallLogs, protected: true, premium: true },
  
  // Advanced routes
  { path: '/enhanced-scanner', component: routeComponents.EnhancedScanner, protected: true },
  { path: '/ml-detection', component: routeComponents.MLDetection, protected: true, premium: true },
  { path: '/disk-cleanup', component: routeComponents.DiskCleanup, protected: true },
  { path: '/performance-metrics', component: routeComponents.PerformanceMetrics, protected: true },
  
  // Admin routes
  { path: '/admin', component: routeComponents.AdminPanel, protected: true, admin: true },
];

/**
 * Get routes that should be preloaded
 */
export const getPreloadRoutes = () => {
  return routes
    .filter(route => route.preload)
    .map(route => route.component);
};

/**
 * Get component by route path
 */
export const getRouteComponent = (path) => {
  const route = routes.find(r => r.path === path);
  return route ? route.component : null;
};

export default routes;
