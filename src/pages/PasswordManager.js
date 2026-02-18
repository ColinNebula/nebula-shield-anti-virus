import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  KeyRound,
  Plus,
  Eye,
  EyeOff,
  Copy,
  Edit,
  Trash2,
  Search,
  Lock,
  Unlock,
  Shield,
  AlertTriangle,
  CheckCircle,
  RefreshCw,
  Globe,
  Mail,
  CreditCard,
  Wifi,
  FileText,
  Star
} from 'lucide-react';
import toast from 'react-hot-toast';
import './PasswordManager.css';

const API_BASE = 'http://localhost:5000/api';

const PasswordManager = () => {
  const [isLocked, setIsLocked] = useState(true);
  const [masterPassword, setMasterPassword] = useState('');
  const [hasMasterPassword, setHasMasterPassword] = useState(false);
  const [passwords, setPasswords] = useState([]);
  const [filteredPasswords, setFilteredPasswords] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [showPassword, setShowPassword] = useState({});
  const [showAddModal, setShowAddModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [editingPassword, setEditingPassword] = useState(null);
  const [newPassword, setNewPassword] = useState({
    name: '',
    username: '',
    password: '',
    url: '',
    category: 'login',
    notes: ''
  });
  const [generatedPassword, setGeneratedPassword] = useState('');
  const [passwordStrength, setPasswordStrength] = useState(null);
  const [breachStatus, setBreachStatus] = useState({});
  const [stats, setStats] = useState({
    totalPasswords: 0,
    weakPasswords: 0,
    breachedPasswords: 0,
    strongPasswords: 0
  });

  const categories = [
    { id: 'all', label: 'All', icon: KeyRound },
    { id: 'login', label: 'Logins', icon: Globe },
    { id: 'email', label: 'Email', icon: Mail },
    { id: 'payment', label: 'Payment', icon: CreditCard },
    { id: 'wifi', label: 'WiFi', icon: Wifi },
    { id: 'notes', label: 'Secure Notes', icon: FileText },
    { id: 'favorite', label: 'Favorites', icon: Star }
  ];

  useEffect(() => {
    checkMasterPassword();
  }, []);

  useEffect(() => {
    filterPasswords();
  }, [passwords, searchQuery, selectedCategory]);

  const checkMasterPassword = async () => {
    try {
      const response = await fetch(`${API_BASE}/passwords/master/status`);
      const data = await response.json();
      setHasMasterPassword(data.hasMasterPassword);
    } catch (error) {
      console.error('Failed to check master password:', error);
    }
  };

  const setMasterPasswordHandler = async () => {
    if (masterPassword.length < 8) {
      toast.error('Master password must be at least 8 characters');
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/passwords/master/set`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: masterPassword })
      });

      if (response.ok) {
        toast.success('Master password set successfully!');
        setHasMasterPassword(true);
        unlockVault();
      } else {
        toast.error('Failed to set master password');
      }
    } catch (error) {
      toast.error('Error setting master password');
    }
  };

  const unlockVault = async () => {
    try {
      const response = await fetch(`${API_BASE}/passwords/unlock`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ masterPassword })
      });

      const data = await response.json();

      if (data.success) {
        setIsLocked(false);
        setMasterPassword('');
        toast.success('Vault unlocked!');
        await loadPasswords();
      } else {
        toast.error('Incorrect master password');
      }
    } catch (error) {
      toast.error('Failed to unlock vault');
    }
  };

  const lockVault = async () => {
    try {
      await fetch(`${API_BASE}/passwords/lock`, { method: 'POST' });
      setIsLocked(true);
      setPasswords([]);
      setFilteredPasswords([]);
      toast.success('Vault locked');
    } catch (error) {
      toast.error('Failed to lock vault');
    }
  };

  const loadPasswords = async () => {
    try {
      const response = await fetch(`${API_BASE}/passwords/list`);
      const data = await response.json();

      if (data.success) {
        setPasswords(data.passwords);
        updateStats(data.passwords);
      }
    } catch (error) {
      toast.error('Failed to load passwords');
    }
  };

  const updateStats = (passwordList) => {
    const total = passwordList.length;
    let weak = 0;
    let breached = 0;
    let strong = 0;

    passwordList.forEach(pwd => {
      if (pwd.strength && pwd.strength.score <= 2) weak++;
      else if (pwd.strength && pwd.strength.score >= 4) strong++;
      if (breachStatus[pwd.id]?.isBreached) breached++;
    });

    setStats({ totalPasswords: total, weakPasswords: weak, breachedPasswords: breached, strongPasswords: strong });
  };

  const filterPasswords = () => {
    let filtered = passwords;

    if (selectedCategory !== 'all') {
      if (selectedCategory === 'favorite') {
        filtered = filtered.filter(pwd => pwd.favorite);
      } else {
        filtered = filtered.filter(pwd => pwd.category === selectedCategory);
      }
    }

    if (searchQuery) {
      filtered = filtered.filter(pwd =>
        pwd.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        pwd.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
        pwd.url.toLowerCase().includes(searchQuery.toLowerCase())
      );
    }

    setFilteredPasswords(filtered);
  };

  const addPassword = async () => {
    if (!newPassword.name || !newPassword.password) {
      toast.error('Name and password are required');
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/passwords/add`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newPassword)
      });

      const data = await response.json();

      if (data.success) {
        toast.success('Password added successfully!');
        setShowAddModal(false);
        resetNewPassword();
        await loadPasswords();
      } else {
        toast.error('Failed to add password');
      }
    } catch (error) {
      toast.error('Error adding password');
    }
  };

  const updatePassword = async () => {
    if (!editingPassword) return;

    try {
      const response = await fetch(`${API_BASE}/passwords/update/${editingPassword.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(editingPassword)
      });

      const data = await response.json();

      if (data.success) {
        toast.success('Password updated successfully!');
        setShowEditModal(false);
        setEditingPassword(null);
        await loadPasswords();
      } else {
        toast.error('Failed to update password');
      }
    } catch (error) {
      toast.error('Error updating password');
    }
  };

  const deletePassword = async (id) => {
    if (!window.confirm('Are you sure you want to delete this password?')) return;

    try {
      const response = await fetch(`${API_BASE}/passwords/delete/${id}`, {
        method: 'DELETE'
      });

      const data = await response.json();

      if (data.success) {
        toast.success('Password deleted');
        await loadPasswords();
      } else {
        toast.error('Failed to delete password');
      }
    } catch (error) {
      toast.error('Error deleting password');
    }
  };

  const generatePassword = async (length = 16) => {
    try {
      const response = await fetch(`${API_BASE}/passwords/generate?length=${length}&includeSymbols=true&includeNumbers=true`);
      const data = await response.json();

      if (data.success) {
        setGeneratedPassword(data.password);
        setPasswordStrength(data.strength);
        return data.password;
      }
    } catch (error) {
      toast.error('Failed to generate password');
    }
  };

  const checkPasswordStrength = async (password) => {
    try {
      const response = await fetch(`${API_BASE}/passwords/check-strength`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password })
      });

      const data = await response.json();
      if (data.success) {
        setPasswordStrength(data.strength);
      }
    } catch (error) {
      console.error('Failed to check password strength');
    }
  };

  const checkBreach = async (id, password) => {
    try {
      const response = await fetch(`${API_BASE}/passwords/check-breach`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password })
      });

      const data = await response.json();
      if (data.success) {
        setBreachStatus(prev => ({ ...prev, [id]: { isBreached: data.isBreached, count: data.count } }));
      }
    } catch (error) {
      console.error('Failed to check breach');
    }
  };

  const copyToClipboard = (text, label) => {
    navigator.clipboard.writeText(text);
    toast.success(`${label} copied to clipboard!`);
  };

  const togglePasswordVisibility = (id) => {
    setShowPassword(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const toggleFavorite = async (id) => {
    const password = passwords.find(pwd => pwd.id === id);
    if (!password) return;

    try {
      const response = await fetch(`${API_BASE}/passwords/update/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...password, favorite: !password.favorite })
      });

      if (response.ok) {
        await loadPasswords();
      }
    } catch (error) {
      console.error('Failed to toggle favorite');
    }
  };

  const resetNewPassword = () => {
    setNewPassword({
      name: '',
      username: '',
      password: '',
      url: '',
      category: 'login',
      notes: ''
    });
    setGeneratedPassword('');
    setPasswordStrength(null);
  };

  const openEditModal = (password) => {
    setEditingPassword({ ...password });
    setShowEditModal(true);
  };

  const getCategoryIcon = (category) => {
    const cat = categories.find(c => c.id === category);
    return cat ? cat.icon : Globe;
  };

  const getStrengthColor = (score) => {
    if (score <= 2) return '#ef4444';
    if (score === 3) return '#f59e0b';
    return '#10b981';
  };

  const getStrengthLabel = (score) => {
    if (score <= 2) return 'Weak';
    if (score === 3) return 'Moderate';
    return 'Strong';
  };

  if (isLocked) {
    return (
      <div className="password-manager locked">
        <motion.div
          className="unlock-container"
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
        >
          <div className="unlock-icon">
            <Lock size={64} />
          </div>
          <h1>Password Manager</h1>
          <p className="unlock-subtitle">
            {hasMasterPassword ? 'Enter your master password to unlock vault' : 'Set a master password to get started'}
          </p>

          <div className="unlock-form">
            <div className="input-group">
              <KeyRound size={20} />
              <input
                type="password"
                placeholder={hasMasterPassword ? 'Master Password' : 'Create Master Password (min 8 characters)'}
                value={masterPassword}
                onChange={(e) => setMasterPassword(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && (hasMasterPassword ? unlockVault() : setMasterPasswordHandler())}
              />
            </div>
            <motion.button
              className="unlock-button"
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              onClick={hasMasterPassword ? unlockVault : setMasterPasswordHandler}
            >
              <Unlock size={20} />
              {hasMasterPassword ? 'Unlock Vault' : 'Set Master Password'}
            </motion.button>
          </div>

          <div className="security-info">
            <Shield size={16} />
            <span>Your passwords are encrypted with AES-256-CBC</span>
          </div>
        </motion.div>
      </div>
    );
  }

  return (
    <div className="password-manager">
      {/* Header */}
      <motion.div
        className="pm-header"
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div className="header-content">
          <div className="header-icon">
            <KeyRound size={48} />
          </div>
          <div className="header-text">
            <h1>Password Manager</h1>
            <p>Securely store and manage your passwords</p>
          </div>
        </div>
        <div className="header-actions">
          <motion.button
            className="btn-add"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={() => setShowAddModal(true)}
          >
            <Plus size={20} />
            Add Password
          </motion.button>
          <motion.button
            className="btn-lock"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={lockVault}
          >
            <Lock size={20} />
            Lock Vault
          </motion.button>
        </div>
      </motion.div>

      {/* Stats */}
      <div className="stats-grid">
        <motion.div className="stat-card" whileHover={{ scale: 1.02 }}>
          <div className="stat-icon total">
            <KeyRound size={24} />
          </div>
          <div className="stat-info">
            <span className="stat-value">{stats.totalPasswords}</span>
            <span className="stat-label">Total Passwords</span>
          </div>
        </motion.div>

        <motion.div className="stat-card" whileHover={{ scale: 1.02 }}>
          <div className="stat-icon strong">
            <CheckCircle size={24} />
          </div>
          <div className="stat-info">
            <span className="stat-value">{stats.strongPasswords}</span>
            <span className="stat-label">Strong Passwords</span>
          </div>
        </motion.div>

        <motion.div className="stat-card" whileHover={{ scale: 1.02 }}>
          <div className="stat-icon weak">
            <AlertTriangle size={24} />
          </div>
          <div className="stat-info">
            <span className="stat-value">{stats.weakPasswords}</span>
            <span className="stat-label">Weak Passwords</span>
          </div>
        </motion.div>

        <motion.div className="stat-card" whileHover={{ scale: 1.02 }}>
          <div className="stat-icon breached">
            <Shield size={24} />
          </div>
          <div className="stat-info">
            <span className="stat-value">{stats.breachedPasswords}</span>
            <span className="stat-label">Breached</span>
          </div>
        </motion.div>
      </div>

      {/* Filters */}
      <div className="filters-section">
        <div className="search-box">
          <Search size={20} />
          <input
            type="text"
            placeholder="Search passwords..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        <div className="category-filters">
          {categories.map(cat => {
            const Icon = cat.icon;
            return (
              <motion.button
                key={cat.id}
                className={`category-btn ${selectedCategory === cat.id ? 'active' : ''}`}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={() => setSelectedCategory(cat.id)}
              >
                <Icon size={18} />
                {cat.label}
              </motion.button>
            );
          })}
        </div>
      </div>

      {/* Password List */}
      <div className="passwords-grid">
        <AnimatePresence>
          {filteredPasswords.length === 0 ? (
            <motion.div
              className="empty-state"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
            >
              <KeyRound size={64} />
              <h3>No passwords found</h3>
              <p>Add your first password to get started</p>
            </motion.div>
          ) : (
            filteredPasswords.map((pwd, index) => {
              const CategoryIcon = getCategoryIcon(pwd.category);
              const breach = breachStatus[pwd.id];

              return (
                <motion.div
                  key={pwd.id}
                  className="password-card"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ delay: index * 0.05 }}
                  whileHover={{ y: -4 }}
                >
                  <div className="card-header">
                    <div className="card-icon">
                      <CategoryIcon size={24} />
                    </div>
                    <div className="card-title">
                      <h3>{pwd.name}</h3>
                      {pwd.url && <span className="url">{pwd.url}</span>}
                    </div>
                    <motion.button
                      className={`btn-favorite ${pwd.favorite ? 'active' : ''}`}
                      whileHover={{ scale: 1.2 }}
                      whileTap={{ scale: 0.9 }}
                      onClick={() => toggleFavorite(pwd.id)}
                    >
                      <Star size={18} fill={pwd.favorite ? '#fbbf24' : 'none'} />
                    </motion.button>
                  </div>

                  <div className="card-body">
                    {pwd.username && (
                      <div className="info-row">
                        <span className="label">Username</span>
                        <div className="value-group">
                          <span className="value">{pwd.username}</span>
                          <button onClick={() => copyToClipboard(pwd.username, 'Username')}>
                            <Copy size={16} />
                          </button>
                        </div>
                      </div>
                    )}

                    <div className="info-row">
                      <span className="label">Password</span>
                      <div className="value-group">
                        <span className="value password">
                          {showPassword[pwd.id] ? pwd.password : '••••••••••••'}
                        </span>
                        <button onClick={() => togglePasswordVisibility(pwd.id)}>
                          {showPassword[pwd.id] ? <EyeOff size={16} /> : <Eye size={16} />}
                        </button>
                        <button onClick={() => copyToClipboard(pwd.password, 'Password')}>
                          <Copy size={16} />
                        </button>
                      </div>
                    </div>

                    {pwd.strength && (
                      <div className="strength-indicator">
                        <span className="label">Strength</span>
                        <div className="strength-bar">
                          <div
                            className="strength-fill"
                            style={{
                              width: `${(pwd.strength.score / 5) * 100}%`,
                              backgroundColor: getStrengthColor(pwd.strength.score)
                            }}
                          />
                        </div>
                        <span className="strength-label" style={{ color: getStrengthColor(pwd.strength.score) }}>
                          {getStrengthLabel(pwd.strength.score)}
                        </span>
                      </div>
                    )}

                    {breach && breach.isBreached && (
                      <div className="breach-warning">
                        <AlertTriangle size={16} />
                        <span>Password found in {breach.count} data breaches!</span>
                      </div>
                    )}
                  </div>

                  <div className="card-actions">
                    <motion.button
                      className="btn-action"
                      whileHover={{ scale: 1.05 }}
                      whileTap={{ scale: 0.95 }}
                      onClick={() => openEditModal(pwd)}
                    >
                      <Edit size={16} />
                      Edit
                    </motion.button>
                    <motion.button
                      className="btn-action danger"
                      whileHover={{ scale: 1.05 }}
                      whileTap={{ scale: 0.95 }}
                      onClick={() => deletePassword(pwd.id)}
                    >
                      <Trash2 size={16} />
                      Delete
                    </motion.button>
                  </div>
                </motion.div>
              );
            })
          )}
        </AnimatePresence>
      </div>

      {/* Add Password Modal */}
      <AnimatePresence>
        {showAddModal && (
          <motion.div
            className="modal-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setShowAddModal(false)}
          >
            <motion.div
              className="modal-content"
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="modal-header">
                <h2>Add New Password</h2>
                <button onClick={() => setShowAddModal(false)}>×</button>
              </div>

              <div className="modal-body">
                <div className="form-group">
                  <label>Name *</label>
                  <input
                    type="text"
                    placeholder="e.g., GitHub, Gmail"
                    value={newPassword.name}
                    onChange={(e) => setNewPassword({ ...newPassword, name: e.target.value })}
                  />
                </div>

                <div className="form-group">
                  <label>Username / Email</label>
                  <input
                    type="text"
                    placeholder="username@example.com"
                    value={newPassword.username}
                    onChange={(e) => setNewPassword({ ...newPassword, username: e.target.value })}
                  />
                </div>

                <div className="form-group">
                  <label>Password *</label>
                  <div className="password-input-group">
                    <input
                      type="text"
                      placeholder="Enter or generate password"
                      value={newPassword.password}
                      onChange={(e) => {
                        setNewPassword({ ...newPassword, password: e.target.value });
                        if (e.target.value) checkPasswordStrength(e.target.value);
                      }}
                    />
                    <button
                      className="btn-generate"
                      onClick={async () => {
                        const pwd = await generatePassword();
                        if (pwd) setNewPassword({ ...newPassword, password: pwd });
                      }}
                    >
                      <RefreshCw size={18} />
                      Generate
                    </button>
                  </div>
                  {passwordStrength && (
                    <div className="strength-feedback">
                      <div className="strength-bar">
                        <div
                          className="strength-fill"
                          style={{
                            width: `${(passwordStrength.score / 5) * 100}%`,
                            backgroundColor: getStrengthColor(passwordStrength.score)
                          }}
                        />
                      </div>
                      <span style={{ color: getStrengthColor(passwordStrength.score) }}>
                        {getStrengthLabel(passwordStrength.score)}
                      </span>
                    </div>
                  )}
                </div>

                <div className="form-group">
                  <label>URL</label>
                  <input
                    type="text"
                    placeholder="https://example.com"
                    value={newPassword.url}
                    onChange={(e) => setNewPassword({ ...newPassword, url: e.target.value })}
                  />
                </div>

                <div className="form-group">
                  <label>Category</label>
                  <select
                    value={newPassword.category}
                    onChange={(e) => setNewPassword({ ...newPassword, category: e.target.value })}
                  >
                    {categories.filter(c => c.id !== 'all' && c.id !== 'favorite').map(cat => (
                      <option key={cat.id} value={cat.id}>{cat.label}</option>
                    ))}
                  </select>
                </div>

                <div className="form-group">
                  <label>Notes</label>
                  <textarea
                    placeholder="Additional notes (optional)"
                    value={newPassword.notes}
                    onChange={(e) => setNewPassword({ ...newPassword, notes: e.target.value })}
                    rows={3}
                  />
                </div>
              </div>

              <div className="modal-footer">
                <button className="btn-cancel" onClick={() => setShowAddModal(false)}>
                  Cancel
                </button>
                <button className="btn-save" onClick={addPassword}>
                  <Plus size={18} />
                  Add Password
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Edit Password Modal */}
      <AnimatePresence>
        {showEditModal && editingPassword && (
          <motion.div
            className="modal-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setShowEditModal(false)}
          >
            <motion.div
              className="modal-content"
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="modal-header">
                <h2>Edit Password</h2>
                <button onClick={() => setShowEditModal(false)}>×</button>
              </div>

              <div className="modal-body">
                <div className="form-group">
                  <label>Name</label>
                  <input
                    type="text"
                    value={editingPassword.name}
                    onChange={(e) => setEditingPassword({ ...editingPassword, name: e.target.value })}
                  />
                </div>

                <div className="form-group">
                  <label>Username / Email</label>
                  <input
                    type="text"
                    value={editingPassword.username}
                    onChange={(e) => setEditingPassword({ ...editingPassword, username: e.target.value })}
                  />
                </div>

                <div className="form-group">
                  <label>Password</label>
                  <input
                    type="text"
                    value={editingPassword.password}
                    onChange={(e) => setEditingPassword({ ...editingPassword, password: e.target.value })}
                  />
                </div>

                <div className="form-group">
                  <label>URL</label>
                  <input
                    type="text"
                    value={editingPassword.url}
                    onChange={(e) => setEditingPassword({ ...editingPassword, url: e.target.value })}
                  />
                </div>

                <div className="form-group">
                  <label>Category</label>
                  <select
                    value={editingPassword.category}
                    onChange={(e) => setEditingPassword({ ...editingPassword, category: e.target.value })}
                  >
                    {categories.filter(c => c.id !== 'all' && c.id !== 'favorite').map(cat => (
                      <option key={cat.id} value={cat.id}>{cat.label}</option>
                    ))}
                  </select>
                </div>

                <div className="form-group">
                  <label>Notes</label>
                  <textarea
                    value={editingPassword.notes}
                    onChange={(e) => setEditingPassword({ ...editingPassword, notes: e.target.value })}
                    rows={3}
                  />
                </div>
              </div>

              <div className="modal-footer">
                <button className="btn-cancel" onClick={() => setShowEditModal(false)}>
                  Cancel
                </button>
                <button className="btn-save" onClick={updatePassword}>
                  <CheckCircle size={18} />
                  Save Changes
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default PasswordManager;
