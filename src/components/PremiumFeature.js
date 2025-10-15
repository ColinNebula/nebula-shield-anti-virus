import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { Crown } from 'lucide-react';
import './PremiumFeature.css';

const PremiumFeature = ({ 
  feature, 
  children, 
  fallback = null,
  showUpgradePrompt = true 
}) => {
  const { checkFeatureAccess } = useAuth();
  const navigate = useNavigate();
  const [hasAccess, setHasAccess] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    checkAccess();
  }, [feature]);

  const checkAccess = async () => {
    const result = await checkFeatureAccess(feature);
    setHasAccess(result.hasAccess);
    setLoading(false);
  };

  if (loading) {
    return null;
  }

  if (hasAccess) {
    return <>{children}</>;
  }

  if (fallback) {
    return <>{fallback}</>;
  }

  if (!showUpgradePrompt) {
    return null;
  }

  return (
    <div className="premium-prompt">
      <div className="premium-icon">
        <Crown size={24} />
      </div>
      <div className="premium-content">
        <h3>Premium Feature</h3>
        <p>Upgrade to Premium to unlock this feature</p>
      </div>
      <button 
        className="premium-upgrade-btn"
        onClick={() => navigate('/premium')}
      >
        Upgrade Now
      </button>
    </div>
  );
};

export default PremiumFeature;
