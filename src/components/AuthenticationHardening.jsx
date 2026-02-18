/**
 * React component for Authentication Hardening dashboard
 */

import React, { useState, useEffect } from 'react';
import {
  Shield,
  Fingerprint,
  MapPin,
  Activity,
  Lock,
  AlertTriangle,
  CheckCircle,
  Users,
  Eye,
  TrendingUp
} from 'lucide-react';

const AuthenticationHardening = () => {
  const [activeSessions, setActiveSessions] = useState([]);
  const [deviceFingerprints, setDeviceFingerprints] = useState([]);
  const [behaviorProfiles, setBehaviorProfiles] = useState([]);
  const [anomalousLogins, setAnomalousLogins] = useState([]);
  const [lockedAccounts, setLockedAccounts] = useState([]);
  const [stats, setStats] = useState({
    activeSessions: 0,
    deviceFingerprints: 0,
    behaviorProfiles: 0,
    lockedAccounts: 0
  });
  const [selectedSession, setSelectedSession] = useState(null);

  useEffect(() => {
    loadAuthData();
    const interval = setInterval(loadAuthData, 3000);
    return () => clearInterval(interval);
  }, []);

  const loadAuthData = async () => {
    try {
      const response = await fetch('/api/auth/hardening/stats');
      const data = await response.json();
      setStats(data.stats);
      setActiveSessions(data.sessions);
      setDeviceFingerprints(data.fingerprints);
      setAnomalousLogins(data.anomalousLogins);
      setLockedAccounts(data.lockedAccounts);
    } catch (error) {
      console.error('Failed to load auth data:', error);
    }
  };

  const terminateSession = async (sessionId) => {
    try {
      await fetch(`/api/auth/session/${sessionId}`, { method: 'DELETE' });
      setActiveSessions(activeSessions.filter(s => s.id !== sessionId));
    } catch (error) {
      console.error('Failed to terminate session:', error);
    }
  };

  const unlockAccount = async (userId) => {
    try {
      await fetch(`/api/auth/unlock/${userId}`, { method: 'POST' });
      setLockedAccounts(lockedAccounts.filter(a => a.userId !== userId));
    } catch (error) {
      console.error('Failed to unlock account:', error);
    }
  };

  const getTrustLevelColor = (level) => {
    const colors = {
      HIGH: 'text-green-600 bg-green-100',
      MEDIUM: 'text-yellow-600 bg-yellow-100',
      LOW: 'text-red-600 bg-red-100'
    };
    return colors[level] || colors.MEDIUM;
  };

  const getRiskColor = (score) => {
    if (score >= 0.7) return 'text-red-600 bg-red-100';
    if (score >= 0.4) return 'text-orange-600 bg-orange-100';
    if (score >= 0.2) return 'text-yellow-600 bg-yellow-100';
    return 'text-green-600 bg-green-100';
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 flex items-center gap-2">
            <Lock className="text-blue-600" />
            Authentication Hardening
          </h1>
          <p className="text-gray-600 mt-1">
            Advanced authentication security and behavioral analysis
          </p>
        </div>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white p-6 rounded-lg shadow-md">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-600 text-sm">Active Sessions</p>
              <p className="text-3xl font-bold text-gray-900">{stats.activeSessions}</p>
            </div>
            <Activity className="text-green-600" size={32} />
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg shadow-md">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-600 text-sm">Device Fingerprints</p>
              <p className="text-3xl font-bold text-gray-900">{stats.deviceFingerprints}</p>
            </div>
            <Fingerprint className="text-blue-600" size={32} />
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg shadow-md">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-600 text-sm">Behavior Profiles</p>
              <p className="text-3xl font-bold text-gray-900">{stats.behaviorProfiles}</p>
            </div>
            <TrendingUp className="text-purple-600" size={32} />
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg shadow-md">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-600 text-sm">Locked Accounts</p>
              <p className="text-3xl font-bold text-gray-900">{stats.lockedAccounts}</p>
            </div>
            <AlertTriangle className="text-red-600" size={32} />
          </div>
        </div>
      </div>

      {/* Active Sessions */}
      <div className="bg-white p-6 rounded-lg shadow-md">
        <h2 className="text-xl font-bold text-gray-900 mb-4 flex items-center gap-2">
          <Activity className="text-green-600" />
          Active Sessions
        </h2>
        
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b">
                <th className="text-left py-3 px-4">User</th>
                <th className="text-left py-3 px-4">IP Address</th>
                <th className="text-left py-3 px-4">Location</th>
                <th className="text-left py-3 px-4">Device</th>
                <th className="text-left py-3 px-4">Risk Score</th>
                <th className="text-left py-3 px-4">Last Activity</th>
                <th className="text-left py-3 px-4">Actions</th>
              </tr>
            </thead>
            <tbody>
              {activeSessions.map((session) => (
                <tr key={session.id} className="border-b hover:bg-gray-50">
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-2">
                      <Users size={16} className="text-gray-600" />
                      <span className="font-medium">{session.userId}</span>
                    </div>
                  </td>
                  <td className="py-3 px-4 font-mono text-sm">{session.ipAddress}</td>
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-1">
                      <MapPin size={14} className="text-gray-600" />
                      <span className="text-sm">
                        {session.location?.city}, {session.location?.country}
                      </span>
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-1">
                      <Fingerprint size={14} className="text-gray-600" />
                      <span className="text-xs font-mono">
                        {session.fingerprint?.substring(0, 8)}...
                      </span>
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-1 rounded text-xs font-semibold ${getRiskColor(session.riskScore)}`}>
                      {(session.riskScore * 100).toFixed(0)}%
                    </span>
                  </td>
                  <td className="py-3 px-4 text-sm text-gray-600">
                    {new Date(session.lastActivity).toLocaleTimeString()}
                  </td>
                  <td className="py-3 px-4">
                    <button
                      onClick={() => terminateSession(session.id)}
                      className="text-red-600 hover:text-red-800 text-sm"
                    >
                      Terminate
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Anomalous Login Attempts */}
      <div className="bg-white p-6 rounded-lg shadow-md">
        <h2 className="text-xl font-bold text-gray-900 mb-4 flex items-center gap-2">
          <AlertTriangle className="text-red-600" />
          Anomalous Login Attempts
        </h2>
        
        <div className="space-y-3">
          {anomalousLogins.map((login, index) => (
            <div key={index} className="p-4 border-l-4 border-red-500 bg-red-50 rounded">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2">
                    <Users size={16} className="text-red-600" />
                    <span className="font-semibold text-gray-900">{login.userId}</span>
                    <span className={`px-2 py-1 rounded text-xs font-semibold ${getRiskColor(login.riskScore)}`}>
                      Risk: {(login.riskScore * 100).toFixed(0)}%
                    </span>
                  </div>
                  
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <p className="text-gray-600">IP Address:</p>
                      <p className="font-mono">{login.ipAddress}</p>
                    </div>
                    <div>
                      <p className="text-gray-600">Location:</p>
                      <p>{login.location?.city}, {login.location?.country}</p>
                    </div>
                    <div>
                      <p className="text-gray-600">Reason:</p>
                      <p className="text-red-600 font-semibold">{login.reason}</p>
                    </div>
                    <div>
                      <p className="text-gray-600">Time:</p>
                      <p>{new Date(login.timestamp).toLocaleString()}</p>
                    </div>
                  </div>

                  {login.details && (
                    <div className="mt-2 p-2 bg-white rounded text-xs">
                      {login.details.timeTravel && (
                        <p className="text-red-600">⚠️ Impossible travel detected</p>
                      )}
                      {login.details.newCountry && (
                        <p className="text-orange-600">⚠️ Login from new country</p>
                      )}
                      {login.details.vpnDetected && (
                        <p className="text-yellow-600">⚠️ VPN detected</p>
                      )}
                      {login.details.torDetected && (
                        <p className="text-yellow-600">⚠️ Tor network detected</p>
                      )}
                      {login.details.distance > 0 && (
                        <p className="text-gray-600">
                          Distance from last login: {login.details.distance.toFixed(0)} km
                        </p>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Device Fingerprints */}
      <div className="bg-white p-6 rounded-lg shadow-md">
        <h2 className="text-xl font-bold text-gray-900 mb-4 flex items-center gap-2">
          <Fingerprint className="text-blue-600" />
          Registered Device Fingerprints
        </h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {deviceFingerprints.slice(0, 6).map((fingerprint) => (
            <div key={fingerprint.hash} className="p-4 border border-gray-200 rounded-lg">
              <div className="flex items-start justify-between mb-3">
                <div>
                  <p className="font-mono text-sm text-gray-600">
                    {fingerprint.hash.substring(0, 16)}...
                  </p>
                  <p className="text-xs text-gray-500">
                    {new Date(fingerprint.timestamp).toLocaleString()}
                  </p>
                </div>
                <CheckCircle className="text-green-600" size={20} />
              </div>

              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-600">Platform:</span>
                  <span className="font-medium">{fingerprint.hardware?.platform}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">OS:</span>
                  <span className="font-medium">{fingerprint.software?.osVersion}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Browser:</span>
                  <span className="font-medium truncate max-w-[200px]">
                    {fingerprint.software?.userAgent?.split('/')[0]}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-600">Timezone:</span>
                  <span className="font-medium">{fingerprint.software?.timezone}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Locked Accounts */}
      {lockedAccounts.length > 0 && (
        <div className="bg-white p-6 rounded-lg shadow-md">
          <h2 className="text-xl font-bold text-gray-900 mb-4 flex items-center gap-2">
            <Lock className="text-red-600" />
            Locked Accounts
          </h2>
          
          <div className="space-y-3">
            {lockedAccounts.map((account) => (
              <div key={account.userId} className="flex items-center justify-between p-4 bg-red-50 rounded-lg">
                <div>
                  <p className="font-semibold text-gray-900">{account.userId}</p>
                  <p className="text-sm text-gray-600">
                    Failed attempts: {account.attempts}
                  </p>
                  <p className="text-sm text-gray-600">
                    Locked until: {new Date(account.lockoutEnd).toLocaleString()}
                  </p>
                </div>
                <button
                  onClick={() => unlockAccount(account.userId)}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                >
                  Unlock
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Behavioral Analysis */}
      <div className="bg-white p-6 rounded-lg shadow-md">
        <h2 className="text-xl font-bold text-gray-900 mb-4 flex items-center gap-2">
          <TrendingUp className="text-purple-600" />
          Behavioral Biometrics
        </h2>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 border border-gray-200 rounded-lg">
            <div className="flex items-center gap-2 mb-3">
              <Eye className="text-purple-600" size={20} />
              <span className="font-semibold">Typing Patterns</span>
            </div>
            <p className="text-sm text-gray-600 mb-2">
              Analyzes keystroke dynamics and rhythm to identify users
            </p>
            <div className="flex items-center gap-2">
              <div className="flex-1 bg-gray-200 rounded-full h-2">
                <div className="bg-purple-600 h-2 rounded-full" style={{ width: '85%' }}></div>
              </div>
              <span className="text-sm font-semibold">85%</span>
            </div>
          </div>

          <div className="p-4 border border-gray-200 rounded-lg">
            <div className="flex items-center gap-2 mb-3">
              <Activity className="text-blue-600" size={20} />
              <span className="font-semibold">Mouse Movement</span>
            </div>
            <p className="text-sm text-gray-600 mb-2">
              Tracks mouse speed, acceleration, and movement patterns
            </p>
            <div className="flex items-center gap-2">
              <div className="flex-1 bg-gray-200 rounded-full h-2">
                <div className="bg-blue-600 h-2 rounded-full" style={{ width: '78%' }}></div>
              </div>
              <span className="text-sm font-semibold">78%</span>
            </div>
          </div>

          <div className="p-4 border border-gray-200 rounded-lg">
            <div className="flex items-center gap-2 mb-3">
              <MapPin className="text-green-600" size={20} />
              <span className="font-semibold">Navigation</span>
            </div>
            <p className="text-sm text-gray-600 mb-2">
              Monitors page navigation sequences and interaction patterns
            </p>
            <div className="flex items-center gap-2">
              <div className="flex-1 bg-gray-200 rounded-full h-2">
                <div className="bg-green-600 h-2 rounded-full" style={{ width: '92%' }}></div>
              </div>
              <span className="text-sm font-semibold">92%</span>
            </div>
          </div>
        </div>
      </div>

      {/* Security Features */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-gradient-to-br from-blue-500 to-blue-600 p-6 rounded-lg shadow-md text-white">
          <Shield size={32} className="mb-3" />
          <h3 className="text-xl font-bold mb-2">Multi-Factor Authentication</h3>
          <p className="text-blue-100 mb-4">
            Automatically triggers MFA for high-risk login attempts based on location, device, and behavior analysis
          </p>
          <div className="flex items-center gap-2">
            <CheckCircle size={16} />
            <span className="text-sm">Active and monitoring</span>
          </div>
        </div>

        <div className="bg-gradient-to-br from-purple-500 to-purple-600 p-6 rounded-lg shadow-md text-white">
          <Fingerprint size={32} className="mb-3" />
          <h3 className="text-xl font-bold mb-2">Device Fingerprinting</h3>
          <p className="text-purple-100 mb-4">
            Creates unique device identifiers using hardware, software, and browser characteristics
          </p>
          <div className="flex items-center gap-2">
            <CheckCircle size={16} />
            <span className="text-sm">{stats.deviceFingerprints} devices registered</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AuthenticationHardening;
