import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  Key, Shield, CheckCircle, AlertTriangle, Info,
  Lock, Unlock, Calendar, Users, Zap, Crown,
  Download, RefreshCw, X, ExternalLink
} from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { useNavigate } from 'react-router-dom';
import licenseManager from '../services/licenseManager';
import toast from 'react-hot-toast';
import './LicenseActivation.css';

const LicenseActivation = () => {
  const { user, subscription } = useAuth();
  const navigate = useNavigate();
  const [licenseKey, setLicenseKey] = useState('');
  const [activating, setActivating] = useState(false);
  const [showToS, setShowToS] = useState(false);
  const [tosAccepted, setTosAccepted] = useState(false);
  const [deviceId] = useState(licenseManager.getDeviceId());
  const [currentLicense, setCurrentLicense] = useState(null);
  const [compliance, setCompliance] = useState(null);

  useEffect(() => {
    loadCurrentLicense();
    checkCompliance();
  }, []);

  const loadCurrentLicense = () => {
    const license = licenseManager.getActiveLicense(deviceId);
    setCurrentLicense(license);
    setTosAccepted(license.tosAccepted || false);
  };

  const checkCompliance = () => {
    const result = licenseManager.checkCompliance(deviceId);
    setCompliance(result);
  };

  const handleActivate = async () => {
    if (!licenseKey.trim()) {
      toast.error('Please enter a license key');
      return;
    }

    if (!tosAccepted) {
      setShowToS(true);
      toast.error('You must accept the Terms of Service');
      return;
    }

    setActivating(true);

    try {
      const result = licenseManager.activateLicense(licenseKey, deviceId, tosAccepted);

      if (result.success) {
        toast.success('License activated successfully!');
        setLicenseKey('');
        loadCurrentLicense();
        checkCompliance();
        
        // Record ToS acceptance
        if (user?.email) {
          licenseManager.acceptToS(user.email);
        }
      } else {
        toast.error(result.error || 'License activation failed');
      }
    } catch (error) {
      toast.error('An error occurred during activation');
    } finally {
      setActivating(false);
    }
  };

  const handleDeactivate = () => {
    if (window.confirm('Are you sure you want to deactivate this license on this device?')) {
      const result = licenseManager.deactivateLicense(currentLicense.key, deviceId);
      
      if (result.success) {
        toast.success('License deactivated');
        loadCurrentLicense();
        checkCompliance();
      } else {
        toast.error(result.error);
      }
    }
  };

  const handleGenerateTrial = () => {
    if (!user?.email) {
      toast.error('Please log in to generate a trial license');
      return;
    }

    const trialKey = licenseManager.generateTrialLicense(user.email);
    setLicenseKey(trialKey);
    toast.success('14-day trial license generated!');
  };

  const tiers = licenseManager.getLicenseTiers();

  return (
    <div className="license-activation-page">
      <div className="page-header">
        <Key size={36} className="header-icon" />
        <div>
          <h1>License Management</h1>
          <p>Activate and manage your Nebula Shield license</p>
        </div>
      </div>

      {/* Compliance Issues */}
      {compliance && !compliance.compliant && (
        <motion.div 
          className="compliance-alert"
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <AlertTriangle size={24} />
          <div>
            <h3>License Compliance Issues</h3>
            {compliance.issues.map((issue, idx) => (
              <p key={idx} className={`issue-${issue.severity}`}>
                {issue.message}
              </p>
            ))}
          </div>
        </motion.div>
      )}

      <div className="license-content">
        {/* Current License Status */}
        <motion.div 
          className="license-status-card"
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
        >
          <div className="card-header">
            <Shield size={24} />
            <h2>Current License</h2>
          </div>

          {currentLicense ? (
            <div className="license-details">
              <div className="detail-row">
                <span className="label">Tier:</span>
                <span className={`value tier-${currentLicense.tier}`}>
                  {tiers[currentLicense.tier.toUpperCase()]?.name || currentLicense.tier}
                  {currentLicense.tier !== 'free' && <Crown size={16} />}
                </span>
              </div>

              {currentLicense.expires && (
                <>
                  <div className="detail-row">
                    <span className="label">Expires:</span>
                    <span className="value">
                      {new Date(currentLicense.expires).toLocaleDateString()}
                    </span>
                  </div>
                  <div className="detail-row">
                    <span className="label">Days Remaining:</span>
                    <span className={`value ${currentLicense.daysRemaining < 30 ? 'warning' : ''}`}>
                      {currentLicense.daysRemaining} days
                    </span>
                  </div>
                </>
              )}

              <div className="detail-row">
                <span className="label">Status:</span>
                <span className={`value status-${currentLicense.active ? 'active' : 'inactive'}`}>
                  {currentLicense.active ? (
                    <><Unlock size={16} /> Active</>
                  ) : (
                    <><Lock size={16} /> Inactive</>
                  )}
                </span>
              </div>

              <div className="detail-row">
                <span className="label">Device ID:</span>
                <span className="value device-id">{deviceId.substring(0, 16)}...</span>
              </div>

              <div className="detail-row">
                <span className="label">ToS Accepted:</span>
                <span className={`value ${tosAccepted ? 'accepted' : 'not-accepted'}`}>
                  {tosAccepted ? (
                    <><CheckCircle size={16} /> Yes</>
                  ) : (
                    <><X size={16} /> No</>
                  )}
                </span>
              </div>

              {currentLicense.tier !== 'free' && (
                <motion.button
                  className="btn-deactivate"
                  onClick={handleDeactivate}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                >
                  <Lock size={18} />
                  Deactivate License
                </motion.button>
              )}
            </div>
          ) : (
            <p className="no-license">No active license</p>
          )}
        </motion.div>

        {/* Activate License */}
        <motion.div 
          className="activation-card"
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
        >
          <div className="card-header">
            <Key size={24} />
            <h2>Activate License</h2>
          </div>

          <div className="activation-form">
            <div className="input-group">
              <label>License Key</label>
              <input
                type="text"
                value={licenseKey}
                onChange={(e) => setLicenseKey(e.target.value.toUpperCase())}
                placeholder="XXXX-XXXX-XXXX-XXXX"
                maxLength={19}
              />
              <small>Enter your 16-character license key</small>
            </div>

            <div className="tos-checkbox">
              <input
                type="checkbox"
                id="tos-accept"
                checked={tosAccepted}
                onChange={(e) => setTosAccepted(e.target.checked)}
              />
              <label htmlFor="tos-accept">
                I accept the{' '}
                <a href="/terms-of-service" target="_blank">
                  Terms of Service <ExternalLink size={14} />
                </a>
              </label>
            </div>

            <motion.button
              className="btn-activate"
              onClick={handleActivate}
              disabled={activating || !licenseKey || !tosAccepted}
              whileHover={{ scale: !activating && licenseKey && tosAccepted ? 1.02 : 1 }}
              whileTap={{ scale: !activating && licenseKey && tosAccepted ? 0.98 : 1 }}
            >
              {activating ? (
                <><RefreshCw size={18} className="spinning" /> Activating...</>
              ) : (
                <><Unlock size={18} /> Activate License</>
              )}
            </motion.button>

            <div className="trial-section">
              <div className="divider">
                <span>or</span>
              </div>
              <motion.button
                className="btn-trial"
                onClick={handleGenerateTrial}
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                <Zap size={18} />
                Start 14-Day Free Trial
              </motion.button>
              <small>No credit card required</small>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Available Tiers */}
      <div className="tiers-section">
        <h2>Available License Tiers</h2>
        <div className="tiers-grid">
          {Object.values(tiers).map((tier) => (
            <motion.div
              key={tier.tier}
              className={`tier-card ${tier.tier} ${currentLicense?.tier === tier.tier ? 'current' : ''}`}
              whileHover={{ y: -5 }}
            >
              <div className="tier-header">
                <h3>{tier.name}</h3>
                {tier.price && <p className="price">${tier.price}/year</p>}
                {!tier.price && <p className="price">Free</p>}
              </div>

              <div className="tier-features">
                <div className="feature-item">
                  <Users size={16} />
                  <span>
                    {tier.maxDevices === -1 ? 'Unlimited' : tier.maxDevices} 
                    {' '}Device{tier.maxDevices !== 1 ? 's' : ''}
                  </span>
                </div>
                <div className="feature-item">
                  <Calendar size={16} />
                  <span>{tier.duration}</span>
                </div>
              </div>

              {currentLicense?.tier === tier.tier && (
                <div className="current-badge">
                  <CheckCircle size={16} />
                  Current Plan
                </div>
              )}

              {tier.tier !== 'free' && currentLicense?.tier !== tier.tier && (
                <motion.button
                  className="btn-upgrade"
                  onClick={() => navigate('/premium')}
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                >
                  Upgrade Now
                </motion.button>
              )}
            </motion.div>
          ))}
        </div>
      </div>

      {/* Help Section */}
      <motion.div 
        className="help-section"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
      >
        <Info size={24} />
        <div>
          <h3>Need Help?</h3>
          <ul>
            <li>License keys are sent to your email after purchase</li>
            <li>Each license can be activated on multiple devices (based on tier limits)</li>
            <li>You can deactivate a device to free up a slot</li>
            <li>Contact support@nebulashield.com for assistance</li>
          </ul>
        </div>
      </motion.div>
    </div>
  );
};

export default LicenseActivation;
