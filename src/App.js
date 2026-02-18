import React, { useState, useEffect, useCallback, lazy, Suspense } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { ThemeProvider } from './contexts/ThemeContext';
import { ThemeProvider as MuiThemeProvider } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { AuthProvider } from './contexts/AuthContext';
import notificationService from './services/notificationService';
import usbMonitorService from './services/usbMonitorService';
import ProtectedRoute from './components/ProtectedRoute';
import SplashScreen from './components/SplashScreen';
import ErrorBoundary from './components/ErrorBoundary';
import ErrorBoundaryWithReporting from './components/ErrorBoundaryWithReporting';
import PWAInstallPrompt from './components/PWAInstallPrompt';
import OfflineIndicator from './components/OfflineIndicator';
import ThemeToggle from './components/ThemeToggle';
import KeyboardShortcutsModal from './components/KeyboardShortcutsModal';
import useKeyboardShortcuts from './hooks/useKeyboardShortcuts';
import { preloadAfterLoad } from './utils/routePreload';
import muiDarkTheme from './muiTheme';
import './styles/themes.css';
import './theme.css';
import './styles/light-theme-fixes.css';
import './App.css';

/**
 * Performance Optimizations Applied:
 * 1. Code Splitting - All routes lazy loaded for smaller initial bundle
 * 2. Route Preloading - Critical routes preloaded after initial load
 * 3. Virtual Scrolling - Large lists (Quarantine, Logs) use VirtualList component
 * 4. Service Worker - Offline capability and asset caching
 * 5. Bundle Optimization - Vendor chunks split for better caching
 * 6. Web Vitals - Performance metrics sent to analytics
 * 7. PWA Support - Install prompt and offline indicators
 */

// Lazy load all route components for optimal code splitting
// Critical routes (Dashboard, Scanner, Login) are preloaded after page load
const Dashboard = lazy(() => import('./components/Dashboard'));
const Scanner = lazy(() => import('./components/Scanner'));
const Quarantine = lazy(() => import('./components/Quarantine'));
const Settings = lazy(() => import('./components/Settings'));
const Login = lazy(() => import('./pages/Login'));
const Register = lazy(() => import('./pages/Register'));
const ForgotPassword = lazy(() => import('./pages/ForgotPassword'));
const VerifyEmail = lazy(() => import('./pages/VerifyEmail'));
const CheckEmail = lazy(() => import('./pages/CheckEmail'));
const Premium = lazy(() => import('./pages/Premium'));
const PaymentSuccess = lazy(() => import('./pages/PaymentSuccess'));
const PaymentCancel = lazy(() => import('./pages/PaymentCancel'));
const WebProtection = lazy(() => import('./pages/WebProtection'));
const EnhancedWebProtection = lazy(() => import('./pages/EnhancedWebProtection'));
const BrowserProtection = lazy(() => import('./pages/BrowserProtection'));
const EmailProtection = lazy(() => import('./pages/EmailProtection'));
const EnhancedDriverScanner = lazy(() => import('./pages/EnhancedDriverScanner'));
const EnhancedNetworkProtection = lazy(() => import('./pages/EnhancedNetworkProtection'));
const EnhancedScanner = lazy(() => import('./pages/EnhancedScanner'));
const HackerProtection = lazy(() => import('./pages/HackerProtection'));
const RansomwareProtection = lazy(() => import('./pages/RansomwareProtection'));
const AdvancedFirewall = lazy(() => import('./pages/AdvancedFirewall'));
const MLDashboard = lazy(() => import('./components/MLDashboard'));
const FirewallLogs = lazy(() => import('./pages/FirewallLogs'));
const DataProtection = lazy(() => import('./pages/DataProtection'));
const AdminPanel = lazy(() => import('./pages/AdminPanel'));
const MLDetection = lazy(() => import('./pages/MLDetection'));
const DiskCleanup = lazy(() => import('./pages/DiskCleanup'));
const PerformanceMetrics = lazy(() => import('./pages/PerformanceMetrics'));
const TermsOfService = lazy(() => import('./pages/TermsOfService'));
const LicenseActivation = lazy(() => import('./pages/LicenseActivation'));
const CyberCapture = lazy(() => import('./components/CyberCapture'));
const StartupManager = lazy(() => import('./pages/StartupManager'));
const PasswordManager = lazy(() => import('./pages/PasswordManager'));
const ParentalControls = lazy(() => import('./pages/ParentalControls'));
const Sidebar = lazy(() => import('./components/Sidebar'));

// Loading fallback component
const PageLoader = () => (
  <div style={{
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    height: '100vh',
    background: 'var(--bg-primary)',
    color: 'var(--text-primary)'
  }}>
    <div style={{ textAlign: 'center' }}>
      <div className="spinner" style={{
        width: '40px',
        height: '40px',
        border: '3px solid var(--border-primary)',
        borderTopColor: 'var(--accent-primary)',
        borderRadius: '50%',
        animation: 'spin 0.8s linear infinite',
        margin: '0 auto 16px'
      }}></div>
      <p>Loading...</p>
    </div>
  </div>
);

// Wrapper component to use keyboard shortcuts inside Router
const AppContent = ({ showSplash, isMobileMenuOpen, closeMobileMenu, toggleMobileMenu, handleShowSplash, showShortcutsModal, setShowShortcutsModal }) => {
  // Enable keyboard shortcuts (must be inside Router and ThemeProvider)
  useKeyboardShortcuts(true, () => setShowShortcutsModal(true));

  return (
    <>
      {!showSplash && (
        <>
          {/* Mobile Menu Overlay */}
          {isMobileMenuOpen && (
            <div className="mobile-overlay" onClick={closeMobileMenu}></div>
          )}
          
          {/* Mobile Menu Button */}
          <button className="mobile-menu-button" onClick={toggleMobileMenu} aria-label="Toggle menu">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              {isMobileMenuOpen ? (
                <>
                  <line x1="18" y1="6" x2="6" y2="18"></line>
                  <line x1="6" y1="6" x2="18" y2="18"></line>
                </>
              ) : (
                <>
                  <line x1="3" y1="12" x2="21" y2="12"></line>
                  <line x1="3" y1="6" x2="21" y2="6"></line>
                  <line x1="3" y1="18" x2="21" y2="18"></line>
                </>
              )}
            </svg>
          </button>
        </>
      )}
      
      <Suspense fallback={<PageLoader />}>
              <Routes>
                {/* Public Routes */}
                <Route path="/login" element={<Login />} />
                <Route path="/register" element={<Register />} />
                <Route path="/forgot-password" element={<ForgotPassword />} />
                <Route path="/verify-email" element={<VerifyEmail />} />
                <Route path="/check-email" element={<CheckEmail />} />
                <Route path="/payment/success" element={<PaymentSuccess />} />
                <Route path="/payment/cancel" element={<PaymentCancel />} />
              
              {/* Protected Routes */}
              <Route path="/" element={
                <ProtectedRoute>
                  <>
                    <Sidebar isOpen={isMobileMenuOpen} onClose={closeMobileMenu} />
                    <main className="main-content">
                      <Dashboard />
                    </main>
                  </>
                </ProtectedRoute>
              } />
              <Route path="/dashboard" element={
                <ProtectedRoute>
                  <>
                    <Sidebar isOpen={isMobileMenuOpen} onClose={closeMobileMenu} />
                    <main className="main-content">
                      <Dashboard />
                    </main>
                  </>
                </ProtectedRoute>
              } />
              <Route path="/scanner" element={
                <ProtectedRoute>
                  <>
                    <Sidebar isOpen={isMobileMenuOpen} onClose={closeMobileMenu} />
                    <main className="main-content">
                      <EnhancedScanner />
                    </main>
                  </>
                </ProtectedRoute>
              } />
              <Route path="/web-protection" element={
                <ProtectedRoute>
                  <>
                    <Sidebar isOpen={isMobileMenuOpen} onClose={closeMobileMenu} />
                    <main className="main-content">
                      <EnhancedWebProtection />
                    </main>
                  </>
                </ProtectedRoute>
              } />
              <Route path="/browser-protection" element={
                <ProtectedRoute>
                  <>
                    <Sidebar isOpen={isMobileMenuOpen} onClose={closeMobileMenu} />
                    <main className="main-content">
                      <BrowserProtection />
                    </main>
                  </>
                </ProtectedRoute>
              } />
              <Route path="/email-protection" element={
                <ProtectedRoute>
                  <>
                    <Sidebar isOpen={isMobileMenuOpen} onClose={closeMobileMenu} />
                    <main className="main-content">
                      <EmailProtection />
                    </main>
                  </>
                </ProtectedRoute>
              } />
              <Route path="/driver-scanner" element={
                <ProtectedRoute>
                  <>
                    <Sidebar isOpen={isMobileMenuOpen} onClose={closeMobileMenu} />
                    <main className="main-content">
                      <EnhancedDriverScanner />
                    </main>
                  </>
                </ProtectedRoute>
              } />
              <Route path="/network-protection" element={
                <ProtectedRoute>
                  <>
                    <Sidebar isOpen={isMobileMenuOpen} onClose={closeMobileMenu} />
                    <main className="main-content">
                      <EnhancedNetworkProtection />
                    </main>
                  </>
                </ProtectedRoute>
              } />
              <Route path="/advanced-firewall" element={
                <ProtectedRoute>
                  <>
                    <Sidebar isOpen={isMobileMenuOpen} onClose={closeMobileMenu} />
                    <main className="main-content">
                      <AdvancedFirewall />
                    </main>
                  </>
                </ProtectedRoute>
              } />
              <Route path="/firewall-logs" element={
                <ProtectedRoute>
                  <>
                    <Sidebar isOpen={isMobileMenuOpen} onClose={closeMobileMenu} />
                    <main className="main-content">
                      <FirewallLogs />
                    </main>
                  </>
                </ProtectedRoute>
              } />
              <Route path="/ml-detection" element={
                <ProtectedRoute>
                  <>
                    <Sidebar isOpen={isMobileMenuOpen} onClose={closeMobileMenu} />
                    <main className="main-content">
                      <MLDetection />
                    </main>
                  </>
                </ProtectedRoute>
              } />
              <Route path="/data-protection" element={
                <ProtectedRoute>
                  <>
                    <Sidebar isOpen={isMobileMenuOpen} onClose={closeMobileMenu} />
                    <main className="main-content">
                      <DataProtection />
                    </main>
                  </>
                </ProtectedRoute>
              } />
              <Route path="/hacker-protection" element={
                <ProtectedRoute>
                  <>
                    <Sidebar isOpen={isMobileMenuOpen} onClose={closeMobileMenu} />
                    <main className="main-content">
                      <HackerProtection />
                    </main>
                  </>
                </ProtectedRoute>
              } />
              <Route path="/ransomware-protection" element={
                <ProtectedRoute>
                  <>
                    <Sidebar isOpen={isMobileMenuOpen} onClose={closeMobileMenu} />
                    <main className="main-content">
                      <RansomwareProtection />
                    </main>
                  </>
                </ProtectedRoute>
              } />
              <Route path="/quarantine" element={
                <ProtectedRoute>
                  <>
                    <Sidebar isOpen={isMobileMenuOpen} onClose={closeMobileMenu} />
                    <main className="main-content">
                      <Quarantine />
                    </main>
                  </>
                </ProtectedRoute>
              } />
              <Route path="/settings" element={
                <ProtectedRoute>
                  <>
                    <Sidebar isOpen={isMobileMenuOpen} onClose={closeMobileMenu} />
                    <main className="main-content">
                      <Settings onShowSplash={handleShowSplash} />
                    </main>
                  </>
                </ProtectedRoute>
              } />
              <Route path="/premium" element={
                <ProtectedRoute>
                  <Premium />
                </ProtectedRoute>
              } />
              <Route path="/admin" element={
                <ProtectedRoute>
                  <>
                    <Sidebar isOpen={isMobileMenuOpen} onClose={closeMobileMenu} />
                    <main className="main-content">
                      <AdminPanel />
                    </main>
                  </>
                </ProtectedRoute>
              } />
              <Route path="/disk-cleanup" element={
                <ProtectedRoute>
                  <>
                    <Sidebar isOpen={isMobileMenuOpen} onClose={closeMobileMenu} />
                    <main className="main-content">
                      <DiskCleanup />
                    </main>
                  </>
                </ProtectedRoute>
              } />
              <Route path="/startup-manager" element={
                <ProtectedRoute>
                  <>
                    <Sidebar isOpen={isMobileMenuOpen} onClose={closeMobileMenu} />
                    <main className="main-content">
                      <StartupManager />
                    </main>
                  </>
                </ProtectedRoute>
              } />
              <Route path="/performance-metrics" element={
                <ProtectedRoute>
                  <>
                    <Sidebar isOpen={isMobileMenuOpen} onClose={closeMobileMenu} />
                    <main className="main-content">
                      <PerformanceMetrics />
                    </main>
                  </>
                </ProtectedRoute>
              } />
              <Route path="/password-manager" element={
                <ProtectedRoute>
                  <>
                    <Sidebar isOpen={isMobileMenuOpen} onClose={closeMobileMenu} />
                    <main className="main-content">
                      <PasswordManager />
                    </main>
                  </>
                </ProtectedRoute>
              } />
              <Route path="/parental-controls" element={
                <ProtectedRoute>
                  <>
                    <Sidebar isOpen={isMobileMenuOpen} onClose={closeMobileMenu} />
                    <main className="main-content">
                      <ParentalControls />
                    </main>
                  </>
                </ProtectedRoute>
              } />
              <Route path="/terms-of-service" element={
                <TermsOfService />
              } />
              <Route path="/license" element={
                <ProtectedRoute>
                  <>
                    <Sidebar isOpen={isMobileMenuOpen} onClose={closeMobileMenu} />
                    <main className="main-content">
                      <LicenseActivation />
                    </main>
                  </>
                </ProtectedRoute>
              } />
              <Route path="/cyber-capture" element={
                <ProtectedRoute>
                  <>
                    <Sidebar isOpen={isMobileMenuOpen} onClose={closeMobileMenu} />
                    <main className="main-content">
                      <CyberCapture />
                    </main>
                  </>
                </ProtectedRoute>
              } />
              <Route path="/ml-dashboard" element={
                <ProtectedRoute>
                  <>
                    <Sidebar isOpen={isMobileMenuOpen} onClose={closeMobileMenu} />
                    <main className="main-content">
                      <MLDashboard />
                    </main>
                  </>
                </ProtectedRoute>
              } />
              </Routes>
            </Suspense>
            
            <Toaster
              position="top-right"
              toastOptions={{
                duration: 4000,
                style: {
                  background: 'var(--card-bg)',
                  color: 'var(--text-primary)',
                  border: '1px solid var(--border-primary)',
                },
                success: {
                  iconTheme: {
                    primary: 'var(--accent-success)',
                    secondary: 'white',
                  },
                },
                error: {
                  iconTheme: {
                    primary: 'var(--accent-danger)',
                    secondary: 'white',
                  },
                },
              }}
            />
      </>
    );
  };

  function App() {
      const [showSplash, setShowSplash] = useState(true);
      const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
      const [showShortcutsModal, setShowShortcutsModal] = useState(false);

  useEffect(() => {
    // Initialize USB monitoring
    const handleUSBEvent = (event, device) => {
      if (event === 'connected') {
        notificationService.notifyUSBDevice(device.name, device.scanning);
      } else if (event === 'scan-complete') {
        const { filesScanned, threatsFound } = device.scanResult || {};
        notificationService.notifyScanComplete(filesScanned, threatsFound);
      }
    };

    const cleanup = usbMonitorService.addListener(handleUSBEvent);

    // Defer notification permission request to not block initial load
    const requestNotifications = async () => {
      const granted = await notificationService.requestPermission();
      if (granted) {
        console.log('✅ Desktop notifications enabled');
      } else {
        console.warn('⚠️ Desktop notifications disabled');
      }
    };
    
    // Defer these operations until after the app is interactive
    setTimeout(() => {
      requestNotifications();
      // Preload critical routes after initial page load
      preloadAfterLoad([Dashboard, Scanner, Login], 2000);
    }, 1000);

    return () => {
      if (cleanup) cleanup();
    };
  }, []);      const handleShowSplash = () => {
        setShowSplash(true);
      };

      const handleSplashComplete = () => {
        setShowSplash(false);
      };

      const toggleMobileMenu = (e) => {
        e?.stopPropagation();
        setIsMobileMenuOpen(!isMobileMenuOpen);
      };

      const closeMobileMenu = useCallback(() => {
        setIsMobileMenuOpen(false);
      }, []);

      return (
        <MuiThemeProvider theme={muiDarkTheme}>
          <CssBaseline />
          <ErrorBoundary>
            <ThemeProvider>
              <AuthProvider>
                {showSplash && <SplashScreen onComplete={handleSplashComplete} />}
                <ErrorBoundaryWithReporting>
                  <Router>
                    <div className="app">
                      <AppContent
                        showSplash={showSplash}
                        isMobileMenuOpen={isMobileMenuOpen}
                        closeMobileMenu={closeMobileMenu}
                        toggleMobileMenu={toggleMobileMenu}
                        handleShowSplash={handleShowSplash}
                        showShortcutsModal={showShortcutsModal}
                        setShowShortcutsModal={setShowShortcutsModal}
                      />
                      
                      <Toaster
                        position="top-right"
                        toastOptions={{
                          duration: 4000,
                          style: {
                            background: 'var(--card-bg)',
                            color: 'var(--text-primary)',
                            border: '1px solid var(--border-primary)',
                          },
                          success: {
                            iconTheme: {
                              primary: 'var(--accent-success)',
                              secondary: 'white',
                            },
                          },
                          error: {
                            iconTheme: {
                              primary: 'var(--accent-danger)',
                              secondary: 'white',
                            },
                          },
                        }}
                      />
                      
                      {/* PWA Components */}
                      <PWAInstallPrompt />
                      <OfflineIndicator />
                      
                      {/* Keyboard Shortcuts Modal */}
                      <KeyboardShortcutsModal 
                        isOpen={showShortcutsModal}
                        onClose={() => setShowShortcutsModal(false)}
                      />
                    </div>
                  </Router>
                </ErrorBoundaryWithReporting>
              </AuthProvider>
            </ThemeProvider>
          </ErrorBoundary>
        </MuiThemeProvider>
      );
    }

export default App;
