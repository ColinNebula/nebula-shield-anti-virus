/**
 * Security API Service
 * Handles 2FA, session management, activity logs, and backup/restore
 */

// In development with React dev server, use proxy (relative URLs)
// In Electron or production, use direct backend URLs
const isElectron = typeof window !== 'undefined' && window.electronAPI?.isElectron;
const API_BASE_URL = isElectron ? 'http://localhost:8080' : '';

// Get auth token from localStorage
const getAuthToken = () => {
  return localStorage.getItem('authToken');
};

// Set auth headers
const getAuthHeaders = () => {
  const token = getAuthToken();
  return {
    'Content-Type': 'application/json',
    ...(token && { 'Authorization': `Bearer ${token}` })
  };
};

// ==================== AUTHENTICATION & 2FA ====================

/**
 * Login with credentials
 */
export const login = async (email, password) => {
  const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });

  const data = await response.json();

  if (data.success && data.sessionToken) {
    localStorage.setItem('authToken', data.sessionToken);
  }

  return data;
};

/**
 * Verify 2FA code
 */
export const verify2FA = async (email, token) => {
  const response = await fetch(`${API_BASE_URL}/api/auth/verify-2fa`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, token })
  });

  const data = await response.json();

  if (data.success && data.sessionToken) {
    localStorage.setItem('authToken', data.sessionToken);
  }

  return data;
};

/**
 * Logout
 */
export const logout = async () => {
  const response = await fetch(`${API_BASE_URL}/api/auth/logout`, {
    method: 'POST',
    headers: getAuthHeaders()
  });

  localStorage.removeItem('authToken');

  return response.json();
};

/**
 * Enable 2FA
 */
export const enable2FA = async () => {
  const response = await fetch(`${API_BASE_URL}/api/auth/enable-2fa`, {
    method: 'POST',
    headers: getAuthHeaders()
  });

  if (!response.ok) {
    throw new Error('Failed to enable 2FA');
  }

  return response.json();
};

/**
 * Confirm 2FA with verification code
 */
export const confirm2FA = async (token) => {
  const response = await fetch(`${API_BASE_URL}/api/auth/confirm-2fa`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify({ token })
  });

  if (!response.ok) {
    throw new Error('Failed to confirm 2FA');
  }

  return response.json();
};

/**
 * Disable 2FA
 */
export const disable2FA = async (password) => {
  const response = await fetch(`${API_BASE_URL}/api/auth/disable-2fa`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify({ password })
  });

  if (!response.ok) {
    throw new Error('Failed to disable 2FA');
  }

  return response.json();
};

/**
 * Change password
 */
export const changePassword = async (currentPassword, newPassword) => {
  const response = await fetch(`${API_BASE_URL}/api/auth/change-password`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify({ currentPassword, newPassword })
  });

  if (!response.ok) {
    throw new Error('Failed to change password');
  }

  const data = await response.json();

  if (data.success) {
    localStorage.removeItem('authToken');
  }

  return data;
};

// ==================== SESSION MANAGEMENT ====================

/**
 * Get all active sessions
 */
export const getSessions = async () => {
  const response = await fetch(`${API_BASE_URL}/api/sessions`, {
    headers: getAuthHeaders()
  });

  if (!response.ok) {
    throw new Error('Failed to fetch sessions');
  }

  return response.json();
};

/**
 * Revoke specific session
 */
export const revokeSession = async (sessionId) => {
  const response = await fetch(`${API_BASE_URL}/api/sessions/${sessionId}`, {
    method: 'DELETE',
    headers: getAuthHeaders()
  });

  if (!response.ok) {
    throw new Error('Failed to revoke session');
  }

  return response.json();
};

/**
 * Revoke all sessions except current
 */
export const revokeAllSessions = async () => {
  const response = await fetch(`${API_BASE_URL}/api/sessions/revoke-all`, {
    method: 'POST',
    headers: getAuthHeaders()
  });

  if (!response.ok) {
    throw new Error('Failed to revoke sessions');
  }

  return response.json();
};

// ==================== ACTIVITY LOGS ====================

/**
 * Get activities with filters
 */
export const getActivities = async (filters = {}) => {
  const params = new URLSearchParams();
  
  Object.entries(filters).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      params.append(key, value);
    }
  });

  const url = `${API_BASE_URL}/api/activities?${params.toString()}`;
  const response = await fetch(url, {
    headers: getAuthHeaders()
  });

  if (!response.ok) {
    throw new Error('Failed to fetch activities');
  }

  return response.json();
};

/**
 * Get activity statistics
 */
export const getActivityStats = async (days = 30) => {
  const response = await fetch(`${API_BASE_URL}/api/activities/stats?days=${days}`, {
    headers: getAuthHeaders()
  });

  if (!response.ok) {
    throw new Error('Failed to fetch activity statistics');
  }

  return response.json();
};

/**
 * Search activities
 */
export const searchActivities = async (query, limit = 100) => {
  const response = await fetch(
    `${API_BASE_URL}/api/activities/search?q=${encodeURIComponent(query)}&limit=${limit}`,
    { headers: getAuthHeaders() }
  );

  if (!response.ok) {
    throw new Error('Failed to search activities');
  }

  return response.json();
};

/**
 * Export activities
 */
export const exportActivities = async (filters = {}) => {
  const params = new URLSearchParams();
  
  Object.entries(filters).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      params.append(key, value);
    }
  });

  const url = `${API_BASE_URL}/api/activities/export?${params.toString()}`;
  const response = await fetch(url, {
    headers: getAuthHeaders()
  });

  if (!response.ok) {
    throw new Error('Failed to export activities');
  }

  return response.json();
};

// ==================== BACKUP & RESTORE ====================

/**
 * Create backup
 */
export const createBackup = async (options = {}) => {
  const response = await fetch(`${API_BASE_URL}/api/backup/create`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(options)
  });

  if (!response.ok) {
    throw new Error('Failed to create backup');
  }

  return response.json();
};

/**
 * List all backups
 */
export const listBackups = async () => {
  const response = await fetch(`${API_BASE_URL}/api/backup/list`, {
    headers: getAuthHeaders()
  });

  if (!response.ok) {
    throw new Error('Failed to list backups');
  }

  return response.json();
};

/**
 * Restore backup
 */
export const restoreBackup = async (backupId, options = {}) => {
  const response = await fetch(`${API_BASE_URL}/api/backup/restore/${backupId}`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(options)
  });

  if (!response.ok) {
    throw new Error('Failed to restore backup');
  }

  return response.json();
};

/**
 * Delete backup
 */
export const deleteBackup = async (backupId) => {
  const response = await fetch(`${API_BASE_URL}/api/backup/${backupId}`, {
    method: 'DELETE',
    headers: getAuthHeaders()
  });

  if (!response.ok) {
    throw new Error('Failed to delete backup');
  }

  return response.json();
};

/**
 * Get backup statistics
 */
export const getBackupStats = async () => {
  const response = await fetch(`${API_BASE_URL}/api/backup/stats`, {
    headers: getAuthHeaders()
  });

  if (!response.ok) {
    throw new Error('Failed to fetch backup statistics');
  }

  return response.json();
};

/**
 * Export configuration
 */
export const exportConfiguration = async () => {
  const response = await fetch(`${API_BASE_URL}/api/config/export`, {
    headers: getAuthHeaders()
  });

  if (!response.ok) {
    throw new Error('Failed to export configuration');
  }

  return response.json();
};

/**
 * Import configuration
 */
export const importConfiguration = async (config) => {
  const response = await fetch(`${API_BASE_URL}/api/config/import`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(config)
  });

  if (!response.ok) {
    throw new Error('Failed to import configuration');
  }

  return response.json();
};

// ==================== HELPER FUNCTIONS ====================

/**
 * Check if user is authenticated
 */
export const isAuthenticated = () => {
  return !!getAuthToken();
};

/**
 * Format file size
 */
export const formatFileSize = (bytes) => {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
};

/**
 * Format date
 */
export const formatDate = (date) => {
  if (!date) return 'N/A';
  const d = new Date(date);
  return d.toLocaleString();
};

/**
 * Get relative time
 */
export const getRelativeTime = (date) => {
  if (!date) return 'N/A';
  
  const now = new Date();
  const then = new Date(date);
  const diff = now - then;
  
  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  
  if (days > 0) return `${days} day${days > 1 ? 's' : ''} ago`;
  if (hours > 0) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
  if (minutes > 0) return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
  return 'Just now';
};

export default {
  // Auth
  login,
  verify2FA,
  logout,
  enable2FA,
  confirm2FA,
  disable2FA,
  changePassword,
  
  // Sessions
  getSessions,
  revokeSession,
  revokeAllSessions,
  
  // Activities
  getActivities,
  getActivityStats,
  searchActivities,
  exportActivities,
  
  // Backup
  createBackup,
  listBackups,
  restoreBackup,
  deleteBackup,
  getBackupStats,
  exportConfiguration,
  importConfiguration,
  
  // Helpers
  isAuthenticated,
  formatFileSize,
  formatDate,
  getRelativeTime
};
