import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  UserCheck,
  Shield,
  Clock,
  Globe,
  Youtube,
  Facebook,
  Twitter,
  Instagram,
  Monitor,
  Calendar,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Plus,
  Edit,
  Trash2,
  Eye,
  Ban,
  Filter,
  BarChart3,
  Settings,
  Users,
  Lock,
  Unlock,
  Search,
  Download,
  Activity
} from 'lucide-react';
import toast from 'react-hot-toast';
import './ParentalControls.css';

const API_BASE = 'http://localhost:5000/api';

const ParentalControls = () => {
  const [profiles, setProfiles] = useState([]);
  const [selectedProfile, setSelectedProfile] = useState(null);
  const [config, setConfig] = useState(null);
  const [activityLogs, setActivityLogs] = useState([]);
  const [stats, setStats] = useState({
    totalProfiles: 0,
    blockedAttempts: 0,
    activeProfiles: 0,
    screenTimeToday: 0
  });
  const [showAddProfileModal, setShowAddProfileModal] = useState(false);
  const [showEditProfileModal, setShowEditProfileModal] = useState(false);
  const [showAddRuleModal, setShowAddRuleModal] = useState(false);
  const [editingProfile, setEditingProfile] = useState(null);
  const [newProfile, setNewProfile] = useState({
    name: '',
    age: '',
    screenTimeLimit: 120,
    allowedHours: { start: '09:00', end: '21:00' },
    blockedCategories: [],
    allowedWebsites: [],
    blockedWebsites: []
  });
  const [newRule, setNewRule] = useState({
    type: 'block',
    category: 'adult',
    url: '',
    keywords: []
  });
  const [activeTab, setActiveTab] = useState('overview');
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState('all');

  const contentCategories = [
    { id: 'adult', label: 'Adult Content', icon: Ban, color: '#ef4444' },
    { id: 'violence', label: 'Violence', icon: AlertTriangle, color: '#f59e0b' },
    { id: 'drugs', label: 'Drugs & Alcohol', icon: XCircle, color: '#dc2626' },
    { id: 'gambling', label: 'Gambling', icon: Ban, color: '#b91c1c' },
    { id: 'weapons', label: 'Weapons', icon: Shield, color: '#991b1b' },
    { id: 'hate', label: 'Hate Speech', icon: XCircle, color: '#7f1d1d' },
    { id: 'malware', label: 'Malware', icon: AlertTriangle, color: '#ef4444' },
    { id: 'social', label: 'Social Media', icon: Users, color: '#3b82f6' }
  ];

  const socialPlatforms = [
    { id: 'facebook', label: 'Facebook', icon: Facebook, color: '#1877f2' },
    { id: 'youtube', label: 'YouTube', icon: Youtube, color: '#ff0000' },
    { id: 'twitter', label: 'Twitter', icon: Twitter, color: '#1da1f2' },
    { id: 'instagram', label: 'Instagram', icon: Instagram, color: '#e4405f' }
  ];

  const tabs = [
    { id: 'overview', label: 'Overview', icon: BarChart3 },
    { id: 'profiles', label: 'Profiles', icon: Users },
    { id: 'web-filter', label: 'Web Filter', icon: Globe },
    { id: 'screen-time', label: 'Screen Time', icon: Clock },
    { id: 'activity', label: 'Activity Log', icon: Activity },
    { id: 'settings', label: 'Settings', icon: Settings }
  ];

  useEffect(() => {
    loadConfig();
    loadProfiles();
    loadActivityLogs();
    updateStats();
  }, []);

  const loadConfig = async () => {
    try {
      const response = await fetch(`${API_BASE}/parental-controls/config`);
      const data = await response.json();
      if (data.success) {
        setConfig(data.config);
      }
    } catch (error) {
      console.error('Failed to load config:', error);
    }
  };

  const loadProfiles = async () => {
    try {
      const response = await fetch(`${API_BASE}/parental-controls/profiles`);
      const data = await response.json();
      if (data.success) {
        setProfiles(data.profiles);
        if (data.profiles.length > 0 && !selectedProfile) {
          setSelectedProfile(data.profiles[0]);
        }
      }
    } catch (error) {
      toast.error('Failed to load profiles');
    }
  };

  const loadActivityLogs = async () => {
    try {
      const response = await fetch(`${API_BASE}/parental-controls/activity`);
      const data = await response.json();
      if (data.success) {
        setActivityLogs(data.activity);
      }
    } catch (error) {
      console.error('Failed to load activity logs');
    }
  };

  const updateStats = async () => {
    try {
      const response = await fetch(`${API_BASE}/parental-controls/stats`);
      const data = await response.json();
      if (data.success) {
        setStats(data.stats);
      }
    } catch (error) {
      console.error('Failed to load stats');
    }
  };

  const addProfile = async () => {
    if (!newProfile.name || !newProfile.age) {
      toast.error('Name and age are required');
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/parental-controls/profiles`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newProfile)
      });

      const data = await response.json();

      if (data.success) {
        toast.success('Profile created successfully!');
        setShowAddProfileModal(false);
        resetNewProfile();
        await loadProfiles();
        await updateStats();
      } else {
        toast.error(data.error || 'Failed to create profile');
      }
    } catch (error) {
      toast.error('Error creating profile');
    }
  };

  const updateProfile = async () => {
    if (!editingProfile) return;

    try {
      const response = await fetch(`${API_BASE}/parental-controls/profiles/${editingProfile.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(editingProfile)
      });

      const data = await response.json();

      if (data.success) {
        toast.success('Profile updated successfully!');
        setShowEditProfileModal(false);
        setEditingProfile(null);
        await loadProfiles();
      } else {
        toast.error('Failed to update profile');
      }
    } catch (error) {
      toast.error('Error updating profile');
    }
  };

  const deleteProfile = async (id) => {
    if (!window.confirm('Are you sure you want to delete this profile?')) return;

    try {
      const response = await fetch(`${API_BASE}/parental-controls/profiles/${id}`, {
        method: 'DELETE'
      });

      const data = await response.json();

      if (data.success) {
        toast.success('Profile deleted');
        if (selectedProfile?.id === id) {
          setSelectedProfile(null);
        }
        await loadProfiles();
        await updateStats();
      } else {
        toast.error('Failed to delete profile');
      }
    } catch (error) {
      toast.error('Error deleting profile');
    }
  };

  const toggleProfileStatus = async (id) => {
    try {
      const response = await fetch(`${API_BASE}/parental-controls/profiles/${id}/toggle`, {
        method: 'POST'
      });

      const data = await response.json();

      if (data.success) {
        toast.success(`Profile ${data.enabled ? 'enabled' : 'disabled'}`);
        await loadProfiles();
        await updateStats();
      }
    } catch (error) {
      toast.error('Failed to toggle profile');
    }
  };

  const addWebsiteRule = async () => {
    if (!selectedProfile || !newRule.url) {
      toast.error('Profile and URL are required');
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/parental-controls/web-filter`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          profileId: selectedProfile.id,
          ...newRule
        })
      });

      const data = await response.json();

      if (data.success) {
        toast.success('Rule added successfully!');
        setShowAddRuleModal(false);
        resetNewRule();
        await loadProfiles();
      } else {
        toast.error('Failed to add rule');
      }
    } catch (error) {
      toast.error('Error adding rule');
    }
  };

  const checkUrl = async (url) => {
    if (!selectedProfile) return;

    try {
      const response = await fetch(`${API_BASE}/parental-controls/check-url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          profileId: selectedProfile.id,
          url
        })
      });

      const data = await response.json();

      if (data.success) {
        if (data.allowed) {
          toast.success('URL is allowed');
        } else {
          toast.error(`URL blocked: ${data.reason}`);
        }
      }
    } catch (error) {
      toast.error('Failed to check URL');
    }
  };

  const toggleCategory = (category) => {
    if (!editingProfile) return;
    
    const categories = editingProfile.blockedCategories || [];
    const index = categories.indexOf(category);
    
    if (index > -1) {
      categories.splice(index, 1);
    } else {
      categories.push(category);
    }
    
    setEditingProfile({ ...editingProfile, blockedCategories: categories });
  };

  const exportActivityReport = async () => {
    try {
      const response = await fetch(`${API_BASE}/parental-controls/activity`);
      const data = await response.json();
      
      if (data.success) {
        const blob = new Blob([JSON.stringify(data.activity, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `parental-controls-report-${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        toast.success('Report exported successfully!');
      }
    } catch (error) {
      toast.error('Failed to export report');
    }
  };

  const resetNewProfile = () => {
    setNewProfile({
      name: '',
      age: '',
      screenTimeLimit: 120,
      allowedHours: { start: '09:00', end: '21:00' },
      blockedCategories: [],
      allowedWebsites: [],
      blockedWebsites: []
    });
  };

  const resetNewRule = () => {
    setNewRule({
      type: 'block',
      category: 'adult',
      url: '',
      keywords: []
    });
  };

  const openEditModal = (profile) => {
    setEditingProfile({ ...profile });
    setShowEditProfileModal(true);
  };

  const formatTime = (minutes) => {
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    return `${hours}h ${mins}m`;
  };

  const getActivityTypeColor = (type) => {
    switch (type) {
      case 'blocked':
        return '#ef4444';
      case 'allowed':
        return '#10b981';
      case 'warning':
        return '#f59e0b';
      default:
        return '#6b7280';
    }
  };

  const filteredLogs = activityLogs.filter(log => {
    if (filterType !== 'all' && log.type !== filterType) return false;
    if (searchQuery && !log.url.toLowerCase().includes(searchQuery.toLowerCase())) return false;
    if (selectedProfile && log.profileId !== selectedProfile.id) return false;
    return true;
  });

  const renderOverview = () => (
    <div className="overview-section">
      <div className="stats-grid">
        <motion.div className="stat-card" whileHover={{ scale: 1.02 }}>
          <div className="stat-icon profiles">
            <Users size={28} />
          </div>
          <div className="stat-info">
            <span className="stat-value">{stats.totalProfiles}</span>
            <span className="stat-label">Total Profiles</span>
          </div>
        </motion.div>

        <motion.div className="stat-card" whileHover={{ scale: 1.02 }}>
          <div className="stat-icon active">
            <CheckCircle size={28} />
          </div>
          <div className="stat-info">
            <span className="stat-value">{stats.activeProfiles}</span>
            <span className="stat-label">Active Profiles</span>
          </div>
        </motion.div>

        <motion.div className="stat-card" whileHover={{ scale: 1.02 }}>
          <div className="stat-icon blocked">
            <Ban size={28} />
          </div>
          <div className="stat-info">
            <span className="stat-value">{stats.blockedAttempts}</span>
            <span className="stat-label">Blocked Today</span>
          </div>
        </motion.div>

        <motion.div className="stat-card" whileHover={{ scale: 1.02 }}>
          <div className="stat-icon time">
            <Clock size={28} />
          </div>
          <div className="stat-info">
            <span className="stat-value">{formatTime(stats.screenTimeToday)}</span>
            <span className="stat-label">Screen Time Today</span>
          </div>
        </motion.div>
      </div>

      <div className="quick-actions">
        <h3>Quick Actions</h3>
        <div className="actions-grid">
          <motion.button
            className="action-card"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={() => setShowAddProfileModal(true)}
          >
            <Plus size={24} />
            <span>Add Profile</span>
          </motion.button>

          <motion.button
            className="action-card"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={() => setActiveTab('web-filter')}
          >
            <Filter size={24} />
            <span>Web Filter</span>
          </motion.button>

          <motion.button
            className="action-card"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={() => setActiveTab('activity')}
          >
            <Activity size={24} />
            <span>View Activity</span>
          </motion.button>

          <motion.button
            className="action-card"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={exportActivityReport}
          >
            <Download size={24} />
            <span>Export Report</span>
          </motion.button>
        </div>
      </div>

      {profiles.length > 0 && (
        <div className="recent-activity">
          <h3>Recent Activity</h3>
          <div className="activity-list">
            {filteredLogs.slice(0, 5).map((log, index) => (
              <motion.div
                key={index}
                className="activity-item"
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.05 }}
              >
                <div
                  className="activity-indicator"
                  style={{ backgroundColor: getActivityTypeColor(log.type) }}
                />
                <div className="activity-content">
                  <span className="activity-url">{log.url}</span>
                  <span className="activity-time">
                    {new Date(log.timestamp).toLocaleString()}
                  </span>
                </div>
                <span className={`activity-status ${log.type}`}>
                  {log.type}
                </span>
              </motion.div>
            ))}
          </div>
        </div>
      )}
    </div>
  );

  const renderProfiles = () => (
    <div className="profiles-section">
      <div className="section-header">
        <h3>User Profiles</h3>
        <motion.button
          className="btn-primary"
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          onClick={() => setShowAddProfileModal(true)}
        >
          <Plus size={18} />
          Add Profile
        </motion.button>
      </div>

      <div className="profiles-grid">
        {profiles.map((profile, index) => (
          <motion.div
            key={profile.id}
            className={`profile-card ${selectedProfile?.id === profile.id ? 'selected' : ''}`}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.05 }}
            whileHover={{ y: -4 }}
            onClick={() => setSelectedProfile(profile)}
          >
            <div className="profile-header">
              <div className="profile-avatar">
                <Users size={32} />
              </div>
              <div className="profile-info">
                <h4>{profile.name}</h4>
                <span className="profile-age">{profile.age} years old</span>
              </div>
              <div className="profile-status">
                <motion.button
                  className={`status-toggle ${profile.enabled ? 'active' : ''}`}
                  whileTap={{ scale: 0.9 }}
                  onClick={(e) => {
                    e.stopPropagation();
                    toggleProfileStatus(profile.id);
                  }}
                >
                  {profile.enabled ? <Unlock size={16} /> : <Lock size={16} />}
                </motion.button>
              </div>
            </div>

            <div className="profile-stats">
              <div className="profile-stat">
                <Clock size={16} />
                <span>{formatTime(profile.screenTimeLimit)} limit</span>
              </div>
              <div className="profile-stat">
                <Ban size={16} />
                <span>{profile.blockedCategories?.length || 0} categories blocked</span>
              </div>
            </div>

            <div className="profile-actions">
              <motion.button
                className="btn-action"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={(e) => {
                  e.stopPropagation();
                  openEditModal(profile);
                }}
              >
                <Edit size={16} />
                Edit
              </motion.button>
              <motion.button
                className="btn-action danger"
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={(e) => {
                  e.stopPropagation();
                  deleteProfile(profile.id);
                }}
              >
                <Trash2 size={16} />
                Delete
              </motion.button>
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );

  const renderWebFilter = () => (
    <div className="web-filter-section">
      <div className="section-header">
        <h3>Web Content Filter</h3>
        {selectedProfile && (
          <motion.button
            className="btn-primary"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={() => setShowAddRuleModal(true)}
          >
            <Plus size={18} />
            Add Rule
          </motion.button>
        )}
      </div>

      {!selectedProfile ? (
        <div className="empty-state">
          <Users size={64} />
          <h3>No Profile Selected</h3>
          <p>Select a profile to manage web filtering rules</p>
        </div>
      ) : (
        <>
          <div className="filter-categories">
            <h4>Content Categories</h4>
            <div className="categories-grid">
              {contentCategories.map(cat => {
                const Icon = cat.icon;
                const isBlocked = selectedProfile.blockedCategories?.includes(cat.id);
                return (
                  <motion.div
                    key={cat.id}
                    className={`category-card ${isBlocked ? 'blocked' : ''}`}
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                    style={{ borderColor: cat.color }}
                  >
                    <div className="category-icon" style={{ backgroundColor: cat.color }}>
                      <Icon size={24} />
                    </div>
                    <span className="category-label">{cat.label}</span>
                    {isBlocked && (
                      <div className="blocked-badge">
                        <Ban size={16} />
                      </div>
                    )}
                  </motion.div>
                );
              })}
            </div>
          </div>

          <div className="filter-lists">
            <div className="filter-list">
              <h4>Blocked Websites</h4>
              <div className="website-list">
                {selectedProfile.blockedWebsites?.length > 0 ? (
                  selectedProfile.blockedWebsites.map((url, index) => (
                    <div key={index} className="website-item blocked">
                      <Globe size={16} />
                      <span>{url}</span>
                      <XCircle size={16} />
                    </div>
                  ))
                ) : (
                  <p className="empty-text">No blocked websites</p>
                )}
              </div>
            </div>

            <div className="filter-list">
              <h4>Allowed Websites</h4>
              <div className="website-list">
                {selectedProfile.allowedWebsites?.length > 0 ? (
                  selectedProfile.allowedWebsites.map((url, index) => (
                    <div key={index} className="website-item allowed">
                      <Globe size={16} />
                      <span>{url}</span>
                      <CheckCircle size={16} />
                    </div>
                  ))
                ) : (
                  <p className="empty-text">No specifically allowed websites</p>
                )}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );

  const renderScreenTime = () => (
    <div className="screen-time-section">
      <h3>Screen Time Management</h3>

      {!selectedProfile ? (
        <div className="empty-state">
          <Clock size={64} />
          <h3>No Profile Selected</h3>
          <p>Select a profile to manage screen time limits</p>
        </div>
      ) : (
        <div className="screen-time-content">
          <div className="time-limit-card">
            <div className="card-header">
              <Clock size={24} />
              <h4>Daily Limit</h4>
            </div>
            <div className="time-display">
              <span className="time-value">{formatTime(selectedProfile.screenTimeLimit)}</span>
              <span className="time-label">per day</span>
            </div>
          </div>

          <div className="allowed-hours-card">
            <div className="card-header">
              <Calendar size={24} />
              <h4>Allowed Hours</h4>
            </div>
            <div className="hours-display">
              <div className="hour-item">
                <span className="hour-label">Start</span>
                <span className="hour-value">{selectedProfile.allowedHours?.start || '09:00'}</span>
              </div>
              <div className="hour-divider">→</div>
              <div className="hour-item">
                <span className="hour-label">End</span>
                <span className="hour-value">{selectedProfile.allowedHours?.end || '21:00'}</span>
              </div>
            </div>
          </div>

          <div className="social-media-card">
            <div className="card-header">
              <Users size={24} />
              <h4>Social Media</h4>
            </div>
            <div className="platforms-grid">
              {socialPlatforms.map(platform => {
                const Icon = platform.icon;
                const isBlocked = selectedProfile.blockedCategories?.includes('social');
                return (
                  <div
                    key={platform.id}
                    className={`platform-item ${isBlocked ? 'blocked' : ''}`}
                    style={{ borderColor: platform.color }}
                  >
                    <Icon size={24} style={{ color: platform.color }} />
                    <span>{platform.label}</span>
                    {isBlocked && <Ban size={16} />}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );

  const renderActivity = () => (
    <div className="activity-section">
      <div className="section-header">
        <h3>Activity Log</h3>
        <motion.button
          className="btn-secondary"
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          onClick={exportActivityReport}
        >
          <Download size={18} />
          Export
        </motion.button>
      </div>

      <div className="activity-filters">
        <div className="search-box">
          <Search size={20} />
          <input
            type="text"
            placeholder="Search URLs..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        <div className="filter-buttons">
          {['all', 'blocked', 'allowed', 'warning'].map(type => (
            <button
              key={type}
              className={`filter-btn ${filterType === type ? 'active' : ''}`}
              onClick={() => setFilterType(type)}
            >
              {type.charAt(0).toUpperCase() + type.slice(1)}
            </button>
          ))}
        </div>
      </div>

      <div className="activity-table">
        {filteredLogs.length === 0 ? (
          <div className="empty-state">
            <Activity size={64} />
            <h3>No Activity</h3>
            <p>Activity logs will appear here</p>
          </div>
        ) : (
          <div className="activity-entries">
            {filteredLogs.map((log, index) => (
              <motion.div
                key={index}
                className="activity-entry"
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.03 }}
              >
                <div
                  className="entry-indicator"
                  style={{ backgroundColor: getActivityTypeColor(log.type) }}
                />
                <div className="entry-content">
                  <div className="entry-header">
                    <span className="entry-url">{log.url}</span>
                    <span className={`entry-badge ${log.type}`}>
                      {log.type === 'blocked' && <Ban size={14} />}
                      {log.type === 'allowed' && <CheckCircle size={14} />}
                      {log.type === 'warning' && <AlertTriangle size={14} />}
                      {log.type}
                    </span>
                  </div>
                  <div className="entry-meta">
                    <span className="entry-profile">
                      <Users size={14} />
                      {profiles.find(p => p.id === log.profileId)?.name || 'Unknown'}
                    </span>
                    <span className="entry-time">
                      <Clock size={14} />
                      {new Date(log.timestamp).toLocaleString()}
                    </span>
                    {log.reason && (
                      <span className="entry-reason">
                        <AlertTriangle size={14} />
                        {log.reason}
                      </span>
                    )}
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        )}
      </div>
    </div>
  );

  return (
    <div className="parental-controls">
      {/* Header */}
      <motion.div
        className="pc-header"
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div className="header-content">
          <div className="header-icon">
            <UserCheck size={48} />
          </div>
          <div className="header-text">
            <h1>Parental Controls</h1>
            <p>Protect your family with advanced web filtering and screen time management</p>
          </div>
        </div>
        <div className="header-status">
          <div className={`status-badge ${config?.enabled ? 'active' : 'inactive'}`}>
            <Shield size={20} />
            <span>{config?.enabled ? 'Active' : 'Inactive'}</span>
          </div>
        </div>
      </motion.div>

      {/* Tabs */}
      <div className="tabs-container">
        {tabs.map(tab => {
          const Icon = tab.icon;
          return (
            <motion.button
              key={tab.id}
              className={`tab-btn ${activeTab === tab.id ? 'active' : ''}`}
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={() => setActiveTab(tab.id)}
            >
              <Icon size={20} />
              {tab.label}
            </motion.button>
          );
        })}
      </div>

      {/* Content */}
      <div className="tab-content">
        {activeTab === 'overview' && renderOverview()}
        {activeTab === 'profiles' && renderProfiles()}
        {activeTab === 'web-filter' && renderWebFilter()}
        {activeTab === 'screen-time' && renderScreenTime()}
        {activeTab === 'activity' && renderActivity()}
      </div>

      {/* Add Profile Modal */}
      <AnimatePresence>
        {showAddProfileModal && (
          <motion.div
            className="modal-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setShowAddProfileModal(false)}
          >
            <motion.div
              className="modal-content"
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="modal-header">
                <h2>Add New Profile</h2>
                <button onClick={() => setShowAddProfileModal(false)}>×</button>
              </div>

              <div className="modal-body">
                <div className="form-group">
                  <label>Name *</label>
                  <input
                    type="text"
                    placeholder="e.g., John Doe"
                    value={newProfile.name}
                    onChange={(e) => setNewProfile({ ...newProfile, name: e.target.value })}
                  />
                </div>

                <div className="form-group">
                  <label>Age *</label>
                  <input
                    type="number"
                    placeholder="Age"
                    value={newProfile.age}
                    onChange={(e) => setNewProfile({ ...newProfile, age: e.target.value })}
                  />
                </div>

                <div className="form-group">
                  <label>Daily Screen Time Limit (minutes)</label>
                  <input
                    type="number"
                    placeholder="120"
                    value={newProfile.screenTimeLimit}
                    onChange={(e) => setNewProfile({ ...newProfile, screenTimeLimit: parseInt(e.target.value) })}
                  />
                </div>

                <div className="form-row">
                  <div className="form-group">
                    <label>Allowed Start Time</label>
                    <input
                      type="time"
                      value={newProfile.allowedHours.start}
                      onChange={(e) => setNewProfile({
                        ...newProfile,
                        allowedHours: { ...newProfile.allowedHours, start: e.target.value }
                      })}
                    />
                  </div>

                  <div className="form-group">
                    <label>Allowed End Time</label>
                    <input
                      type="time"
                      value={newProfile.allowedHours.end}
                      onChange={(e) => setNewProfile({
                        ...newProfile,
                        allowedHours: { ...newProfile.allowedHours, end: e.target.value }
                      })}
                    />
                  </div>
                </div>
              </div>

              <div className="modal-footer">
                <button className="btn-cancel" onClick={() => setShowAddProfileModal(false)}>
                  Cancel
                </button>
                <button className="btn-save" onClick={addProfile}>
                  <Plus size={18} />
                  Add Profile
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Edit Profile Modal */}
      <AnimatePresence>
        {showEditProfileModal && editingProfile && (
          <motion.div
            className="modal-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setShowEditProfileModal(false)}
          >
            <motion.div
              className="modal-content large"
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="modal-header">
                <h2>Edit Profile: {editingProfile.name}</h2>
                <button onClick={() => setShowEditProfileModal(false)}>×</button>
              </div>

              <div className="modal-body">
                <div className="form-group">
                  <label>Name</label>
                  <input
                    type="text"
                    value={editingProfile.name}
                    onChange={(e) => setEditingProfile({ ...editingProfile, name: e.target.value })}
                  />
                </div>

                <div className="form-group">
                  <label>Age</label>
                  <input
                    type="number"
                    value={editingProfile.age}
                    onChange={(e) => setEditingProfile({ ...editingProfile, age: e.target.value })}
                  />
                </div>

                <div className="form-group">
                  <label>Daily Screen Time Limit (minutes)</label>
                  <input
                    type="number"
                    value={editingProfile.screenTimeLimit}
                    onChange={(e) => setEditingProfile({ ...editingProfile, screenTimeLimit: parseInt(e.target.value) })}
                  />
                </div>

                <div className="form-group">
                  <label>Blocked Content Categories</label>
                  <div className="categories-selector">
                    {contentCategories.map(cat => {
                      const Icon = cat.icon;
                      const isBlocked = editingProfile.blockedCategories?.includes(cat.id);
                      return (
                        <motion.div
                          key={cat.id}
                          className={`category-option ${isBlocked ? 'selected' : ''}`}
                          whileTap={{ scale: 0.95 }}
                          onClick={() => toggleCategory(cat.id)}
                        >
                          <Icon size={20} />
                          <span>{cat.label}</span>
                          {isBlocked && <CheckCircle size={16} />}
                        </motion.div>
                      );
                    })}
                  </div>
                </div>
              </div>

              <div className="modal-footer">
                <button className="btn-cancel" onClick={() => setShowEditProfileModal(false)}>
                  Cancel
                </button>
                <button className="btn-save" onClick={updateProfile}>
                  <CheckCircle size={18} />
                  Save Changes
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Add Rule Modal */}
      <AnimatePresence>
        {showAddRuleModal && (
          <motion.div
            className="modal-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setShowAddRuleModal(false)}
          >
            <motion.div
              className="modal-content"
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="modal-header">
                <h2>Add Web Filter Rule</h2>
                <button onClick={() => setShowAddRuleModal(false)}>×</button>
              </div>

              <div className="modal-body">
                <div className="form-group">
                  <label>Rule Type</label>
                  <select
                    value={newRule.type}
                    onChange={(e) => setNewRule({ ...newRule, type: e.target.value })}
                  >
                    <option value="block">Block</option>
                    <option value="allow">Allow</option>
                  </select>
                </div>

                <div className="form-group">
                  <label>URL / Domain *</label>
                  <input
                    type="text"
                    placeholder="example.com"
                    value={newRule.url}
                    onChange={(e) => setNewRule({ ...newRule, url: e.target.value })}
                  />
                </div>

                <div className="form-group">
                  <label>Category</label>
                  <select
                    value={newRule.category}
                    onChange={(e) => setNewRule({ ...newRule, category: e.target.value })}
                  >
                    {contentCategories.map(cat => (
                      <option key={cat.id} value={cat.id}>{cat.label}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="modal-footer">
                <button className="btn-cancel" onClick={() => setShowAddRuleModal(false)}>
                  Cancel
                </button>
                <button className="btn-save" onClick={addWebsiteRule}>
                  <Plus size={18} />
                  Add Rule
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default ParentalControls;
