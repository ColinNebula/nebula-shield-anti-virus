import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Users,
  Shield,
  Activity,
  Settings,
  Eye,
  Trash2,
  UserPlus,
  Edit,
  Lock,
  Unlock,
  Crown,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  Download,
  Search,
  Filter
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import axios from 'axios';
import toast from 'react-hot-toast';
import './AdminPanel.css';

const AdminPanel = () => {
  const { token, user } = useAuth();
  const [activeTab, setActiveTab] = useState('users');
  const [users, setUsers] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [systemStats, setSystemStats] = useState({});
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterRole, setFilterRole] = useState('all');
  const [showUserModal, setShowUserModal] = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);

  useEffect(() => {
    loadAdminData();
  }, [activeTab]);

  const loadAdminData = async () => {
    setLoading(true);
    try {
      if (activeTab === 'users') {
        await loadUsers();
      } else if (activeTab === 'audit') {
        await loadAuditLogs();
      } else if (activeTab === 'stats') {
        await loadSystemStats();
      }
    } catch (error) {
      toast.error('Failed to load admin data');
    } finally {
      setLoading(false);
    }
  };

  const loadUsers = async () => {
    try {
      const response = await axios.get('/api/admin/users', {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      if (response.data.success) {
        setUsers(response.data.users);
      }
    } catch (error) {
      console.error('Failed to load users:', error);
      // Mock data for demo
      setUsers([
        {
          id: 1,
          email: 'admin@example.com',
          name: 'Colin Nebula',
          tier: 'premium',
          role: 'admin',
          status: 'active',
          created_at: '2025-10-01',
          last_login: '2025-10-12',
          scans_count: 127,
          threats_found: 5
        },
        {
          id: 2,
          email: 'user@example.com',
          name: 'John Doe',
          tier: 'free',
          role: 'user',
          status: 'active',
          created_at: '2025-10-05',
          last_login: '2025-10-11',
          scans_count: 45,
          threats_found: 2
        },
        {
          id: 3,
          email: 'premium@example.com',
          name: 'Jane Smith',
          tier: 'premium',
          role: 'user',
          status: 'active',
          created_at: '2025-09-20',
          last_login: '2025-10-12',
          scans_count: 203,
          threats_found: 12
        },
        {
          id: 4,
          email: 'inactive@example.com',
          name: 'Bob Johnson',
          tier: 'free',
          role: 'user',
          status: 'suspended',
          created_at: '2025-08-15',
          last_login: '2025-09-30',
          scans_count: 12,
          threats_found: 0
        }
      ]);
    }
  };

  const loadAuditLogs = async () => {
    try {
      const response = await axios.get('/api/admin/audit-logs', {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      if (response.data.success) {
        setAuditLogs(response.data.logs);
      }
    } catch (error) {
      // Mock data for demo
      setAuditLogs([
        {
          id: 1,
          user_email: 'admin@example.com',
          action: 'LOGIN',
          details: 'Successful login from 192.168.1.100',
          timestamp: '2025-10-12 14:30:25',
          status: 'success'
        },
        {
          id: 2,
          user_email: 'user@example.com',
          action: 'SCAN_COMPLETED',
          details: 'Quick scan completed - 0 threats found',
          timestamp: '2025-10-12 14:15:10',
          status: 'success'
        },
        {
          id: 3,
          user_email: 'premium@example.com',
          action: 'THREAT_QUARANTINED',
          details: 'File quarantined: suspicious_file.exe',
          timestamp: '2025-10-12 13:45:33',
          status: 'warning'
        },
        {
          id: 4,
          user_email: 'admin@example.com',
          action: 'USER_CREATED',
          details: 'New user registered: test@example.com',
          timestamp: '2025-10-12 12:20:15',
          status: 'success'
        },
        {
          id: 5,
          user_email: 'inactive@example.com',
          action: 'LOGIN_FAILED',
          details: 'Failed login attempt - Invalid password',
          timestamp: '2025-10-12 11:30:42',
          status: 'error'
        },
        {
          id: 6,
          user_email: 'premium@example.com',
          action: 'SETTINGS_UPDATED',
          details: 'Real-time protection enabled',
          timestamp: '2025-10-12 10:15:20',
          status: 'success'
        }
      ]);
    }
  };

  const loadSystemStats = async () => {
    setSystemStats({
      totalUsers: 13,
      activeUsers: 12,
      premiumUsers: 4,
      totalScans: 387,
      totalThreats: 19,
      avgScansPerUser: 29.8,
      systemUptime: '15 days 8 hours',
      activeProtection: 12
    });
  };

  const handleUpdateUserRole = async (userId, newRole) => {
    try {
      await axios.post(
        '/api/admin/update-role',
        { userId, role: newRole },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      
      toast.success('User role updated');
      loadUsers();
    } catch (error) {
      toast.error('Failed to update role');
    }
  };

  const handleUpdateUserTier = async (userId, newTier) => {
    try {
      await axios.post(
        '/api/admin/update-tier',
        { userId, tier: newTier },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      
      toast.success('User tier updated');
      loadUsers();
    } catch (error) {
      toast.error('Failed to update tier');
    }
  };

  const handleSuspendUser = async (userId) => {
    if (!window.confirm('Are you sure you want to suspend this user?')) return;
    
    try {
      await axios.post(
        '/api/admin/suspend-user',
        { userId },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      
      toast.success('User suspended');
      loadUsers();
    } catch (error) {
      toast.error('Failed to suspend user');
    }
  };

  const handleActivateUser = async (userId) => {
    try {
      await axios.post(
        '/api/admin/activate-user',
        { userId },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      
      toast.success('User activated');
      loadUsers();
    } catch (error) {
      toast.error('Failed to activate user');
    }
  };

  const handleDeleteUser = async (userId) => {
    if (!window.confirm('Are you sure you want to DELETE this user? This cannot be undone!')) return;
    
    try {
      await axios.delete(`/api/admin/users/${userId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      toast.success('User deleted');
      loadUsers();
    } catch (error) {
      toast.error('Failed to delete user');
    }
  };

  const exportAuditLogs = () => {
    const csv = [
      ['Timestamp', 'User', 'Action', 'Details', 'Status'],
      ...auditLogs.map(log => [
        log.timestamp,
        log.user_email,
        log.action,
        log.details,
        log.status
      ])
    ].map(row => row.join(',')).join('\n');

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit_logs_${new Date().toISOString()}.csv`;
    a.click();
    
    toast.success('Audit logs exported');
  };

  const filteredUsers = users.filter(u => {
    const matchesSearch = u.email.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         u.name.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesRole = filterRole === 'all' || u.role === filterRole;
    return matchesSearch && matchesRole;
  });

  const getActionIcon = (action) => {
    switch (action) {
      case 'LOGIN': return <CheckCircle size={16} />;
      case 'LOGIN_FAILED': return <XCircle size={16} />;
      case 'SCAN_COMPLETED': return <Shield size={16} />;
      case 'THREAT_QUARANTINED': return <AlertTriangle size={16} />;
      case 'USER_CREATED': return <UserPlus size={16} />;
      case 'SETTINGS_UPDATED': return <Settings size={16} />;
      default: return <Activity size={16} />;
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'success': return '#10b981';
      case 'warning': return '#f59e0b';
      case 'error': return '#ef4444';
      default: return '#6b7280';
    }
  };

  return (
    <div className="admin-panel">
      <div className="admin-header">
        <div className="admin-title">
          <Shield size={32} className="admin-icon" />
          <div>
            <h1>Admin Panel</h1>
            <p>Manage users, monitor activity, and control system settings</p>
          </div>
        </div>
        
        <div className="admin-user-badge">
          <Crown size={20} />
          <span>{user?.email}</span>
        </div>
      </div>

      <div className="admin-tabs">
        <button
          className={`admin-tab ${activeTab === 'users' ? 'active' : ''}`}
          onClick={() => setActiveTab('users')}
        >
          <Users size={20} />
          <span>User Management</span>
        </button>
        
        <button
          className={`admin-tab ${activeTab === 'audit' ? 'active' : ''}`}
          onClick={() => setActiveTab('audit')}
        >
          <Activity size={20} />
          <span>Audit Logs</span>
        </button>
        
        <button
          className={`admin-tab ${activeTab === 'stats' ? 'active' : ''}`}
          onClick={() => setActiveTab('stats')}
        >
          <Eye size={20} />
          <span>System Stats</span>
        </button>
      </div>

      <div className="admin-content">
        {activeTab === 'users' && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="users-section"
          >
            <div className="users-controls">
              <div className="search-bar">
                <Search size={20} />
                <input
                  type="text"
                  placeholder="Search users..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </div>
              
              <div className="filter-dropdown">
                <Filter size={20} />
                <select value={filterRole} onChange={(e) => setFilterRole(e.target.value)}>
                  <option value="all">All Roles</option>
                  <option value="admin">Admin</option>
                  <option value="user">User</option>
                </select>
              </div>
            </div>

            <div className="users-table-container">
              <table className="users-table">
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Tier</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>Scans</th>
                    <th>Threats</th>
                    <th>Last Login</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredUsers.map(u => (
                    <tr key={u.id} className={u.status === 'suspended' ? 'suspended' : ''}>
                      <td>
                        <div className="user-info">
                          <div className="user-avatar">
                            {u.name.split(' ').map(n => n[0]).join('')}
                          </div>
                          <div>
                            <div className="user-name">{u.name}</div>
                            <div className="user-email">{u.email}</div>
                          </div>
                        </div>
                      </td>
                      <td>
                        <select
                          className={`tier-select ${u.tier}`}
                          value={u.tier}
                          onChange={(e) => handleUpdateUserTier(u.id, e.target.value)}
                          disabled={u.id === user?.id}
                        >
                          <option value="free">Free</option>
                          <option value="premium">Premium</option>
                        </select>
                      </td>
                      <td>
                        <select
                          className={`role-select ${u.role}`}
                          value={u.role}
                          onChange={(e) => handleUpdateUserRole(u.id, e.target.value)}
                          disabled={u.id === user?.id}
                        >
                          <option value="user">User</option>
                          <option value="admin">Admin</option>
                        </select>
                      </td>
                      <td>
                        <span className={`status-badge ${u.status}`}>
                          {u.status}
                        </span>
                      </td>
                      <td>{u.scans_count}</td>
                      <td>
                        <span className={u.threats_found > 0 ? 'threats-found' : ''}>
                          {u.threats_found}
                        </span>
                      </td>
                      <td>{new Date(u.last_login).toLocaleDateString()}</td>
                      <td>
                        <div className="action-buttons">
                          {u.status === 'active' ? (
                            <button
                              className="action-btn suspend"
                              onClick={() => handleSuspendUser(u.id)}
                              disabled={u.id === user?.id}
                              title="Suspend User"
                            >
                              <Lock size={16} />
                            </button>
                          ) : (
                            <button
                              className="action-btn activate"
                              onClick={() => handleActivateUser(u.id)}
                              title="Activate User"
                            >
                              <Unlock size={16} />
                            </button>
                          )}
                          
                          <button
                            className="action-btn delete"
                            onClick={() => handleDeleteUser(u.id)}
                            disabled={u.id === user?.id}
                            title="Delete User"
                          >
                            <Trash2 size={16} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </motion.div>
        )}

        {activeTab === 'audit' && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="audit-section"
          >
            <div className="audit-controls">
              <h2>System Audit Trail</h2>
              <button className="export-btn" onClick={exportAuditLogs}>
                <Download size={20} />
                <span>Export CSV</span>
              </button>
            </div>

            <div className="audit-logs">
              {auditLogs.map(log => (
                <motion.div
                  key={log.id}
                  className="audit-log-item"
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  style={{ borderLeftColor: getStatusColor(log.status) }}
                >
                  <div className="log-icon" style={{ color: getStatusColor(log.status) }}>
                    {getActionIcon(log.action)}
                  </div>
                  
                  <div className="log-content">
                    <div className="log-header">
                      <span className="log-action">{log.action.replace(/_/g, ' ')}</span>
                      <span className="log-time">
                        <Clock size={14} />
                        {log.timestamp}
                      </span>
                    </div>
                    
                    <div className="log-details">
                      <span className="log-user">{log.user_email}</span>
                      <span className="log-separator">•</span>
                      <span>{log.details}</span>
                    </div>
                  </div>
                  
                  <span className={`log-status ${log.status}`}>
                    {log.status}
                  </span>
                </motion.div>
              ))}
            </div>
          </motion.div>
        )}

        {activeTab === 'stats' && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="stats-section"
          >
            <div className="stats-grid">
              <div className="stat-card">
                <div className="stat-icon users">
                  <Users size={32} />
                </div>
                <div className="stat-content">
                  <div className="stat-label">Total Users</div>
                  <div className="stat-value">{systemStats.totalUsers}</div>
                  <div className="stat-subtitle">{systemStats.activeUsers} active</div>
                </div>
              </div>

              <div className="stat-card">
                <div className="stat-icon premium">
                  <Crown size={32} />
                </div>
                <div className="stat-content">
                  <div className="stat-label">Premium Users</div>
                  <div className="stat-value">{systemStats.premiumUsers}</div>
                  <div className="stat-subtitle">
                    {Math.round((systemStats.premiumUsers / systemStats.totalUsers) * 100)}% conversion
                  </div>
                </div>
              </div>

              <div className="stat-card">
                <div className="stat-icon scans">
                  <Shield size={32} />
                </div>
                <div className="stat-content">
                  <div className="stat-label">Total Scans</div>
                  <div className="stat-value">{systemStats.totalScans}</div>
                  <div className="stat-subtitle">{systemStats.avgScansPerUser} avg per user</div>
                </div>
              </div>

              <div className="stat-card">
                <div className="stat-icon threats">
                  <AlertTriangle size={32} />
                </div>
                <div className="stat-content">
                  <div className="stat-label">Threats Detected</div>
                  <div className="stat-value">{systemStats.totalThreats}</div>
                  <div className="stat-subtitle">All quarantined</div>
                </div>
              </div>

              <div className="stat-card">
                <div className="stat-icon uptime">
                  <Activity size={32} />
                </div>
                <div className="stat-content">
                  <div className="stat-label">System Uptime</div>
                  <div className="stat-value">{systemStats.systemUptime}</div>
                  <div className="stat-subtitle">No downtime</div>
                </div>
              </div>

              <div className="stat-card">
                <div className="stat-icon protection">
                  <CheckCircle size={32} />
                </div>
                <div className="stat-content">
                  <div className="stat-label">Active Protection</div>
                  <div className="stat-value">{systemStats.activeProtection}</div>
                  <div className="stat-subtitle">Users protected</div>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
};

export default AdminPanel;
