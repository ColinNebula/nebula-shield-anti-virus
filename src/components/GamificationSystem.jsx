import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import './GamificationSystem.css';

/**
 * Gamification System - Badges, achievements, and rewards for security milestones
 */
const GamificationSystem = ({ userStats, onClaimReward }) => {
  const [achievements, setAchievements] = useState([]);
  const [unlockedBadges, setUnlockedBadges] = useState([]);
  const [showNotification, setShowNotification] = useState(null);
  const [userLevel, setUserLevel] = useState(1);
  const [xp, setXp] = useState(0);
  const [xpForNextLevel, setXpForNextLevel] = useState(100);

  // Define all available badges
  const allBadges = [
    {
      id: 'first-scan',
      name: 'First Steps',
      description: 'Complete your first scan',
      icon: '🔍',
      xp: 10,
      requirement: { type: 'scans', count: 1 }
    },
    {
      id: 'scan-master',
      name: 'Scan Master',
      description: 'Complete 100 scans',
      icon: '🎯',
      xp: 100,
      requirement: { type: 'scans', count: 100 }
    },
    {
      id: 'threat-hunter',
      name: 'Threat Hunter',
      description: 'Detect 10 threats',
      icon: '🎖️',
      xp: 50,
      requirement: { type: 'threats', count: 10 }
    },
    {
      id: 'defender',
      name: 'Cyber Defender',
      description: 'Block 50 threats',
      icon: '🛡️',
      xp: 150,
      requirement: { type: 'blocked', count: 50 }
    },
    {
      id: 'vigilant',
      name: 'Ever Vigilant',
      description: 'Enable real-time protection for 7 days',
      icon: '👁️',
      xp: 200,
      requirement: { type: 'uptime', count: 7 }
    },
    {
      id: 'clean-sweep',
      name: 'Clean Sweep',
      description: 'Clean 100 infected files',
      icon: '🧹',
      xp: 75,
      requirement: { type: 'cleaned', count: 100 }
    },
    {
      id: 'quarantine-pro',
      name: 'Quarantine Pro',
      description: 'Quarantine 25 threats',
      icon: '🔒',
      xp: 50,
      requirement: { type: 'quarantined', count: 25 }
    },
    {
      id: 'update-champion',
      name: 'Update Champion',
      description: 'Update virus definitions 10 times',
      icon: '📡',
      xp: 30,
      requirement: { type: 'updates', count: 10 }
    },
    {
      id: 'firewall-expert',
      name: 'Firewall Expert',
      description: 'Block 1000 malicious connections',
      icon: '🔥',
      xp: 250,
      requirement: { type: 'firewall_blocks', count: 1000 }
    },
    {
      id: 'perfectionist',
      name: 'Perfectionist',
      description: 'Complete 10 full system scans',
      icon: '💯',
      xp: 125,
      requirement: { type: 'full_scans', count: 10 }
    },
    {
      id: 'speed-demon',
      name: 'Speed Demon',
      description: 'Complete a scan in under 60 seconds',
      icon: '⚡',
      xp: 40,
      requirement: { type: 'quick_scan', count: 1 }
    },
    {
      id: 'security-guru',
      name: 'Security Guru',
      description: 'Reach level 25',
      icon: '🏆',
      xp: 500,
      requirement: { type: 'level', count: 25 }
    }
  ];

  // Check for newly unlocked achievements
  useEffect(() => {
    if (!userStats) return;

    allBadges.forEach(badge => {
      const isUnlocked = unlockedBadges.find(b => b.id === badge.id);
      if (!isUnlocked && checkRequirement(badge.requirement, userStats)) {
        unlockBadge(badge);
      }
    });
  }, [userStats]);

  // Check if requirement is met
  const checkRequirement = (requirement, stats) => {
    const value = stats[requirement.type] || 0;
    return value >= requirement.count;
  };

  // Unlock a badge
  const unlockBadge = (badge) => {
    setUnlockedBadges(prev => [...prev, badge]);
    addXP(badge.xp);
    
    // Show notification
    setShowNotification({
      type: 'badge',
      badge: badge,
      timestamp: Date.now()
    });

    // Hide notification after 5 seconds
    setTimeout(() => {
      setShowNotification(null);
    }, 5000);

    // Play sound (optional)
    playUnlockSound();
  };

  // Add XP and check for level up
  const addXP = (amount) => {
    setXp(prev => {
      const newXP = prev + amount;
      
      // Check for level up
      if (newXP >= xpForNextLevel) {
        const newLevel = userLevel + 1;
        const remainingXP = newXP - xpForNextLevel;
        setUserLevel(newLevel);
        setXpForNextLevel(calculateNextLevelXP(newLevel));
        
        // Show level up notification
        setShowNotification({
          type: 'levelup',
          level: newLevel,
          timestamp: Date.now()
        });

        setTimeout(() => setShowNotification(null), 5000);
        
        return remainingXP;
      }
      
      return newXP;
    });
  };

  // Calculate XP needed for next level
  const calculateNextLevelXP = (level) => {
    return Math.floor(100 * Math.pow(1.5, level - 1));
  };

  // Play unlock sound
  const playUnlockSound = () => {
    const audio = new Audio('data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmwhBTGH0fPTgjMGHm7A7+OZSA0PVqzn77BdGAg+ltrywnUmBjWJ0vPRfS4HKH3K8eSWQwwTYrnv6KRPFBU=');
    audio.volume = 0.3;
    audio.play().catch(() => {}); // Ignore if autoplay is blocked
  };

  // Calculate progress percentage
  const progressPercent = (xp / xpForNextLevel) * 100;

  // Get level title
  const getLevelTitle = (level) => {
    if (level < 5) return 'Novice Guardian';
    if (level < 10) return 'Apprentice Defender';
    if (level < 15) return 'Skilled Protector';
    if (level < 20) return 'Expert Sentinel';
    if (level < 25) return 'Master Guardian';
    return 'Elite Cyber Warrior';
  };

  return (
    <div className="gamification-container">
      {/* Achievement Notification */}
      <AnimatePresence>
        {showNotification && (
          <motion.div
            className="achievement-notification"
            initial={{ opacity: 0, y: -50, scale: 0.8 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -50, scale: 0.8 }}
            transition={{ type: "spring", stiffness: 300, damping: 20 }}
          >
            {showNotification.type === 'badge' ? (
              <>
                <div className="notification-icon">
                  <span className="badge-icon-large">{showNotification.badge.icon}</span>
                  <motion.div
                    className="icon-burst"
                    initial={{ scale: 0 }}
                    animate={{ scale: [0, 1.5, 1] }}
                    transition={{ duration: 0.6 }}
                  />
                </div>
                <div className="notification-content">
                  <h4>Achievement Unlocked!</h4>
                  <p className="achievement-name">{showNotification.badge.name}</p>
                  <p className="achievement-desc">{showNotification.badge.description}</p>
                  <p className="xp-gain">+{showNotification.badge.xp} XP</p>
                </div>
              </>
            ) : (
              <>
                <div className="notification-icon levelup">
                  <span className="levelup-icon">🌟</span>
                </div>
                <div className="notification-content">
                  <h4>Level Up!</h4>
                  <p className="achievement-name">Level {showNotification.level}</p>
                  <p className="achievement-desc">{getLevelTitle(showNotification.level)}</p>
                </div>
              </>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* User Level Card */}
      <motion.div 
        className="level-card"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <div className="level-header">
          <div className="level-info">
            <h3>Level {userLevel}</h3>
            <p className="level-title">{getLevelTitle(userLevel)}</p>
          </div>
          <div className="level-badge">
            <motion.div
              className="level-circle"
              animate={{ rotate: 360 }}
              transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
            >
              <span>{userLevel}</span>
            </motion.div>
          </div>
        </div>
        
        <div className="xp-bar-container">
          <div className="xp-bar-labels">
            <span>{xp} XP</span>
            <span>{xpForNextLevel} XP</span>
          </div>
          <div className="xp-bar">
            <motion.div
              className="xp-fill"
              initial={{ width: 0 }}
              animate={{ width: `${progressPercent}%` }}
              transition={{ duration: 0.5 }}
            />
          </div>
        </div>
      </motion.div>

      {/* Badges Grid */}
      <div className="badges-section">
        <h3>Achievements ({unlockedBadges.length}/{allBadges.length})</h3>
        
        <div className="badges-grid">
          {allBadges.map((badge, index) => {
            const isUnlocked = unlockedBadges.find(b => b.id === badge.id);
            const progress = userStats 
              ? Math.min((userStats[badge.requirement.type] || 0) / badge.requirement.count, 1)
              : 0;

            return (
              <motion.div
                key={badge.id}
                className={`badge-card ${isUnlocked ? 'unlocked' : 'locked'}`}
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: index * 0.05 }}
                whileHover={{ scale: isUnlocked ? 1.05 : 1 }}
              >
                <div className="badge-icon">
                  <span className={isUnlocked ? '' : 'grayscale'}>{badge.icon}</span>
                  {!isUnlocked && (
                    <div className="lock-overlay">
                      <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM9 6c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6z"/>
                      </svg>
                    </div>
                  )}
                </div>
                
                <div className="badge-info">
                  <h4 className="badge-name">{badge.name}</h4>
                  <p className="badge-description">{badge.description}</p>
                  
                  {!isUnlocked && (
                    <div className="badge-progress">
                      <div className="progress-bar">
                        <div 
                          className="progress-fill" 
                          style={{ width: `${progress * 100}%` }}
                        />
                      </div>
                      <span className="progress-text">
                        {Math.floor(progress * 100)}%
                      </span>
                    </div>
                  )}
                  
                  {isUnlocked && (
                    <div className="badge-xp">+{badge.xp} XP</div>
                  )}
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default GamificationSystem;
