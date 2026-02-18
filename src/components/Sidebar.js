import React, { useState, useEffect, useRef } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  Home,
  Search,
  Archive,
  Settings,
  ChevronRight,
  ChevronDown,
  Power,
  Wifi,
  WifiOff,
  LogOut,
  Crown,
  User,
  Globe,
  Mail,
  HardDrive,
  ShieldAlert,
  Lock,
  Database,
  FileKey,
  FileText,
  Brain,
  BarChart3,
  Key,
  Cloud,
  Zap,
  Cookie,
  UserCheck,
  KeyRound
} from 'lucide-react';
import AntivirusAPI from '../services/antivirusApi';
import { useAuth } from '../contexts/AuthContext';
import NebulaLogo from './NebulaLogo';
import toast from 'react-hot-toast';
import './Sidebar.css';

const Sidebar = ({ isOpen = false, onClose = () => {} }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const prevLocationRef = useRef(location.pathname);
  const { user, logout, isPremium, isAdmin } = useAuth();
  const [isConnected, setIsConnected] = useState(false);
  const [systemStatus, setSystemStatus] = useState(null);
  const [showShutdownDialog, setShowShutdownDialog] = useState(false);
  const [expandedSections, setExpandedSections] = useState({
    main: true,
    protection: true,
    privacy: false,
    advanced: false,
    system: false,
    settings: true
  });

  useEffect(() => {
    checkConnection();
    const interval = setInterval(checkConnection, 5000); // Check every 5 seconds
    return () => clearInterval(interval);
  }, []);

  // Close sidebar when route actually changes on mobile
  useEffect(() => {
    if (location.pathname !== prevLocationRef.current && isOpen && window.innerWidth <= 1024) {
      onClose();
    }
    prevLocationRef.current = location.pathname;
  }, [location.pathname, isOpen, onClose]);

  const checkConnection = async () => {
    try {
      const status = await AntivirusAPI.getSystemStatus();
      setSystemStatus(status);
      setIsConnected(true);
    } catch (error) {
      setIsConnected(false);
      setSystemStatus(null);
    }
  };

  const handleShutdown = async () => {
    try {
      const loadingToast = toast.loading('Shutting down backend...');
      
      await AntivirusAPI.shutdownBackend();
      
      toast.dismiss(loadingToast);
      toast.success('Backend shut down successfully!');
      
      // Update UI to show disconnected
      setIsConnected(false);
      setSystemStatus(null);
      setShowShutdownDialog(false);
      
    } catch (error) {
      toast.error('Failed to shutdown backend: ' + error.message);
      setShowShutdownDialog(false);
    }
  };

  const toggleSection = (section) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  const menuSections = [
    {
      id: 'main',
      label: 'Main',
      icon: Home,
      items: [
        {
          path: '/',
          icon: Home,
          label: 'Dashboard',
          badge: null
        },
        {
          path: '/scanner',
          icon: Search,
          label: 'Scanner',
          badge: null
        },
        {
          path: '/quarantine',
          icon: Archive,
          label: 'Quarantine',
          badge: systemStatus?.quarantined_files || null
        }
      ]
    },
    {
      id: 'protection',
      label: 'Protection',
      icon: Shield,
      items: [
        {
          path: '/web-protection',
          icon: Globe,
          label: 'Web Protection',
          badge: null,
          premium: false
        },
        {
          path: '/browser-protection',
          icon: Cookie,
          label: 'Browser Protection',
          badge: null,
          premium: false
        },
        {
          path: '/email-protection',
          icon: Mail,
          label: 'Email Protection',
          badge: null,
          premium: false
        },
        {
          path: '/hacker-protection',
          icon: ShieldAlert,
          label: 'Hacker Protection',
          badge: null,
          premium: false
        },
        {
          path: '/ransomware-protection',
          icon: FileKey,
          label: 'Ransomware Protection',
          badge: null,
          premium: false
        },
        {
          path: '/network-protection',
          icon: Wifi,
          label: 'Network Protection',
          badge: null,
          premium: false
        },
        {
          path: '/data-protection',
          icon: Database,
          label: 'Data Protection',
          badge: null,
          premium: false
        }
      ]
    },
    {
      id: 'privacy',
      label: 'Privacy & Family',
      icon: UserCheck,
      items: [
        {
          path: '/password-manager',
          icon: KeyRound,
          label: 'Password Manager',
          badge: null,
          premium: false
        },
        {
          path: '/parental-controls',
          icon: UserCheck,
          label: 'Parental Controls',
          badge: null,
          premium: false
        }
      ]
    },
    {
      id: 'advanced',
      label: 'Advanced Features',
      icon: Brain,
      items: [
        {
          path: '/advanced-firewall',
          icon: Shield,
          label: 'Advanced Firewall',
          badge: null,
          premium: true
        },
        {
          path: '/firewall-logs',
          icon: FileText,
          label: 'Firewall Logs',
          badge: null,
          premium: true
        },
        {
          path: '/ml-detection',
          icon: Brain,
          label: 'ML Detection',
          badge: null,
          premium: true
        },
        {
          path: '/ml-dashboard',
          icon: Brain,
          label: 'ML Dashboard',
          badge: '🧠',
          premium: false
        },
        {
          path: '/cyber-capture',
          icon: Cloud,
          label: 'CyberCapture',
          badge: null,
          premium: false
        }
      ]
    },
    {
      id: 'system',
      label: 'System Tools',
      icon: HardDrive,
      items: [
        {
          path: '/driver-scanner',
          icon: HardDrive,
          label: 'Driver Scanner',
          badge: null,
          premium: false
        },
        {
          path: '/disk-cleanup',
          icon: HardDrive,
          label: 'Disk Cleanup',
          badge: null,
          premium: false
        },
        {
          path: '/startup-manager',
          icon: Zap,
          label: 'Startup Manager',
          badge: null,
          premium: false
        },
        {
          path: '/performance-metrics',
          icon: BarChart3,
          label: 'Performance Metrics',
          badge: null,
          premium: false
        }
      ]
    },
    {
      id: 'settings',
      label: 'Settings & Admin',
      icon: Settings,
      items: [
        {
          path: '/admin',
          icon: Crown,
          label: 'Admin Panel',
          badge: null,
          adminOnly: true
        },
        {
          path: '/license',
          icon: Key,
          label: 'License',
          badge: null
        },
        {
          path: '/settings',
          icon: Settings,
          label: 'Settings',
          badge: null
        }
      ]
    }
  ];

  // Check if mobile for animation control
  const isMobile = typeof window !== 'undefined' && window.innerWidth <= 1024;

  // Use regular aside on mobile to avoid Framer Motion conflicts
  const SidebarElement = isMobile ? 'aside' : motion.aside;
  const sidebarProps = isMobile 
    ? { className: `sidebar ${isOpen ? 'open' : ''}` }
    : {
        className: `sidebar ${isOpen ? 'open' : ''}`,
        initial: { x: -280 },
        animate: { x: 0 },
        transition: { type: "spring", stiffness: 100, damping: 20 }
      };

  return (
    <SidebarElement {...sidebarProps}>
      {/* Logo and Brand */}
      <div className="sidebar-header">
        <motion.div
          className="logo-container"
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
        >
          <div className="logo-icon">
            <NebulaLogo size={32} animated={true} />
          </div>
          <div className="logo-text">
            <h1 className="brand-name">Nebula Shield</h1>
            <p className="brand-tagline">Anti-Virus Protection</p>
          </div>
        </motion.div>
      </div>

      {/* Connection Status */}
      <div className="connection-status">
        <div className={`status-indicator ${isConnected ? 'connected' : 'disconnected'}`}>
          {isConnected ? <Wifi size={16} /> : <WifiOff size={16} />}
          <span>{isConnected ? 'Connected' : 'Disconnected'}</span>
        </div>
        {systemStatus && (
          <div className="system-info">
            <div className="system-stat">
              <span className="stat-label">Files Scanned</span>
              <span className="stat-value">{systemStatus.total_scanned_files?.toLocaleString()}</span>
            </div>
            <div className="system-stat">
              <span className="stat-label">Threats Found</span>
              <span className="stat-value threat-count">{systemStatus.total_threats_found}</span>
            </div>
          </div>
        )}
      </div>

      {/* Navigation Menu */}
      <nav className="sidebar-nav">
        <ul className="nav-list">
          {menuSections.map((section, sectionIndex) => {
            const SectionIcon = section.icon;
            const isExpanded = expandedSections[section.id];
            const filteredItems = section.items.filter(
              item => !item.adminOnly || (item.adminOnly && isAdmin)
            );

            // Don't render empty sections
            if (filteredItems.length === 0) return null;

            return (
              <li key={section.id} className="nav-section">
                <motion.button
                  className={`section-header ${isExpanded ? 'expanded' : ''}`}
                  onClick={() => toggleSection(section.id)}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: sectionIndex * 0.05 }}
                  whileHover={{ x: 2 }}
                  whileTap={{ scale: 0.98 }}
                >
                  <div className="section-header-content">
                    <SectionIcon size={18} />
                    <span className="section-label">{section.label}</span>
                  </div>
                  <motion.div
                    animate={{ rotate: isExpanded ? 180 : 0 }}
                    transition={{ duration: 0.2 }}
                  >
                    <ChevronDown size={16} />
                  </motion.div>
                </motion.button>

                <AnimatePresence initial={false}>
                  {isExpanded && (
                    <motion.ul
                      className="section-items"
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: "auto", opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.2 }}
                    >
                      {filteredItems.map((item, index) => {
                        const isActive = location.pathname === item.path;
                        const Icon = item.icon;

                        return (
                          <motion.li
                            key={item.path}
                            className="nav-item"
                            initial={{ opacity: 0, x: -10 }}
                            animate={{ opacity: 1, x: 0 }}
                            exit={{ opacity: 0, x: -10 }}
                            transition={{ delay: index * 0.03 }}
                          >
                            <Link to={item.path} className={`nav-link ${isActive ? 'active' : ''}`}>
                              <motion.div
                                className="nav-content"
                                whileHover={{ x: 4 }}
                                whileTap={{ scale: 0.98 }}
                              >
                                <div className="nav-icon">
                                  <Icon size={18} />
                                </div>
                                <span className="nav-label">{item.label}</span>
                                {item.badge && (
                                  <span className="nav-badge">{item.badge}</span>
                                )}
                                {item.premium && !isPremium && (
                                  <Crown size={14} className="premium-icon" />
                                )}
                                <ChevronRight size={14} className="nav-arrow" />
                              </motion.div>
                              {isActive && (
                                <motion.div
                                  className="active-indicator"
                                  layoutId="activeIndicator"
                                  initial={false}
                                  transition={{ type: "spring", stiffness: 300, damping: 30 }}
                                />
                              )}
                            </Link>
                          </motion.li>
                        );
                      })}
                    </motion.ul>
                  )}
                </AnimatePresence>
              </li>
            );
          })}
        </ul>
      </nav>

      {/* Protection Status */}
      <div className="protection-status">
        <div className="protection-card">
          <div className="protection-header">
            <div className="protection-icon">
              <Shield size={20} />
            </div>
            <div className="protection-info">
              <h3>Real-time Protection</h3>
              <p className={`protection-state ${systemStatus?.real_time_protection ? 'active' : 'inactive'}`}>
                {systemStatus?.real_time_protection ? 'Active' : 'Inactive'}
              </p>
            </div>
          </div>
          <div className={`protection-toggle ${systemStatus?.real_time_protection ? 'on' : 'off'}`}>
            <div className="toggle-indicator"></div>
          </div>
        </div>
      </div>

      {/* User Profile Section */}
      <div className="user-profile">
        <div className="profile-card">
          <div className="profile-avatar">
            <User size={20} />
          </div>
          <div className="profile-info">
            <h4>{user?.name || user?.email?.split('@')[0] || 'User'}</h4>
            <p className={`tier-badge ${isPremium ? 'premium' : 'free'}`}>
              {isPremium && <Crown size={12} />}
              {isPremium ? 'Premium' : 'Free'}
            </p>
          </div>
        </div>
        <div className="profile-actions">
          {!isPremium && (
            <motion.button
              className="upgrade-button"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={() => navigate('/premium')}
            >
              <Crown size={16} />
              Upgrade
            </motion.button>
          )}
          <motion.button
            className="logout-button"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={() => {
              logout();
              toast.success('Logged out successfully');
              navigate('/login');
            }}
            title="Logout"
          >
            <LogOut size={18} />
          </motion.button>
        </div>
      </div>

      {/* Sidebar Footer */}
      <div className="sidebar-footer">
        <motion.button
          className="power-button"
          whileHover={{ scale: 1.1 }}
          whileTap={{ scale: 0.9 }}
          title="Shutdown Backend"
          onClick={() => setShowShutdownDialog(true)}
        >
          <Power size={20} />
        </motion.button>
        <div className="version-info">
          <p>Version 1.0.0</p>
          <p>© 2024 Nebula Shield</p>
        </div>
      </div>

      {/* Shutdown Confirmation Dialog */}
      {showShutdownDialog && (
        <motion.div
          className="shutdown-overlay"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={() => setShowShutdownDialog(false)}
        >
          <motion.div
            className="shutdown-dialog"
            initial={{ scale: 0.8, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.8, opacity: 0 }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="dialog-header">
              <Power size={32} className="dialog-icon" />
              <h3>Shutdown Backend?</h3>
            </div>
            <div className="dialog-content">
              <p>This will stop the Nebula Shield backend service:</p>
              <ul>
                <li>Real-time protection will be disabled</li>
                <li>Active scans will be stopped</li>
                <li>Connection will be lost</li>
              </ul>
              <p className="warning">You'll need to restart it manually.</p>
            </div>
            <div className="dialog-actions">
              <motion.button
                className="dialog-button cancel"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={() => setShowShutdownDialog(false)}
              >
                Cancel
              </motion.button>
              <motion.button
                className="dialog-button shutdown"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={handleShutdown}
              >
                Shutdown
              </motion.button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </SidebarElement>
  );
};

export default Sidebar;
