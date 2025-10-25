import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Star, Zap, CheckCircle } from 'lucide-react';
import NebulaLogo from './NebulaLogo';
import './SplashScreen.css';

const SplashScreen = ({ onComplete }) => {
  const [currentStep, setCurrentStep] = useState(0);
  const [showLogo, setShowLogo] = useState(false);
  const [showText, setShowText] = useState(false);
  const [showFeatures, setShowFeatures] = useState(false);
  const [isComplete, setIsComplete] = useState(false);

  const features = [
    { icon: Shield, text: "Advanced Threat Detection", delay: 0 },
    { icon: Zap, text: "Real-time Protection", delay: 0.2 },
    { icon: Star, text: "Quantum Security Engine", delay: 0.4 },
    { icon: CheckCircle, text: "Zero-day Protection", delay: 0.6 }
  ];

  useEffect(() => {
    const sequence = async () => {
      // Step 1: Show background
      await new Promise(resolve => setTimeout(resolve, 200));
      
      // Step 2: Show logo
      setShowLogo(true);
      await new Promise(resolve => setTimeout(resolve, 600));
      
      // Step 3: Show text
      setShowText(true);
      await new Promise(resolve => setTimeout(resolve, 400));
      
      // Step 4: Show features
      setShowFeatures(true);
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Step 5: Complete
      setIsComplete(true);
      await new Promise(resolve => setTimeout(resolve, 300));
      
      // Callback to parent
      if (onComplete) {
        onComplete();
      }
    };

    sequence();
  }, [onComplete]);

  const backgroundVariants = {
    initial: { opacity: 0 },
    animate: { 
      opacity: 1,
      transition: { duration: 1 }
    }
  };

  const logoVariants = {
    initial: { 
      scale: 0.3, 
      opacity: 0, 
      rotateY: 180 
    },
    animate: { 
      scale: 1, 
      opacity: 1, 
      rotateY: 0,
      transition: { 
        type: "spring", 
        stiffness: 100, 
        damping: 15,
        duration: 1.2
      }
    }
  };

  const textVariants = {
    initial: { y: 50, opacity: 0 },
    animate: { 
      y: 0, 
      opacity: 1,
      transition: { 
        type: "spring", 
        stiffness: 80, 
        damping: 12 
      }
    }
  };

  const featureVariants = {
    initial: { x: -100, opacity: 0 },
    animate: (custom) => ({
      x: 0,
      opacity: 1,
      transition: {
        delay: custom,
        type: "spring",
        stiffness: 100,
        damping: 15
      }
    })
  };

  const exitVariants = {
    exit: {
      scale: 1.1,
      opacity: 0,
      transition: { duration: 0.8, ease: "easeInOut" }
    }
  };

  // Generate random floating particles
  const particles = Array.from({ length: 20 }, (_, i) => ({
    id: i,
    x: Math.random() * 100,
    y: Math.random() * 100,
    size: Math.random() * 4 + 1,
    delay: Math.random() * 3
  }));

  return (
    <AnimatePresence>
      {!isComplete && (
        <motion.div
          className="splash-screen"
          variants={backgroundVariants}
          initial="initial"
          animate="animate"
          exit="exit"
          {...exitVariants}
        >
          {/* Animated Background */}
          <div className="splash-background">
            <div className="gradient-overlay"></div>
            
            {/* Floating Particles */}
            {particles.map(particle => (
              <motion.div
                key={particle.id}
                className="floating-particle"
                style={{
                  left: `${particle.x}%`,
                  top: `${particle.y}%`,
                  width: `${particle.size}px`,
                  height: `${particle.size}px`
                }}
                animate={{
                  y: [-20, 20, -20],
                  opacity: [0.3, 1, 0.3],
                  scale: [0.8, 1.2, 0.8]
                }}
                transition={{
                  duration: 4,
                  repeat: Infinity,
                  delay: particle.delay,
                  ease: "easeInOut"
                }}
              />
            ))}
            
            {/* Nebula Effect */}
            <div className="nebula-effect">
              <div className="nebula-cloud nebula-1"></div>
              <div className="nebula-cloud nebula-2"></div>
              <div className="nebula-cloud nebula-3"></div>
            </div>
          </div>

          {/* Content */}
          <div className="splash-content">
            {/* Logo Section */}
            <AnimatePresence>
              {showLogo && (
                <motion.div
                  className="splash-logo-section"
                  variants={logoVariants}
                  initial="initial"
                  animate="animate"
                >
                  <div className="logo-container-splash">
                    <NebulaLogo size={120} animated={true} glow={true} />
                    <div className="logo-pulse"></div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Text Section */}
            <AnimatePresence>
              {showText && (
                <motion.div
                  className="splash-text-section"
                  variants={textVariants}
                  initial="initial"
                  animate="animate"
                >
                  <motion.h1 
                    className="splash-title"
                    animate={{
                      backgroundPosition: ["0% 50%", "100% 50%", "0% 50%"]
                    }}
                    transition={{
                      duration: 3,
                      repeat: Infinity,
                      ease: "linear"
                    }}
                  >
                    Nebula Shield
                  </motion.h1>
                  <motion.h2 
                    className="splash-subtitle"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.3 }}
                  >
                    Anti-Virus Protection
                  </motion.h2>
                  <motion.p 
                    className="splash-tagline"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.6 }}
                  >
                    Defending your digital universe with next-generation security
                  </motion.p>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Features Section */}
            <AnimatePresence>
              {showFeatures && (
                <motion.div className="splash-features">
                  {features.map((feature, index) => (
                    <motion.div
                      key={index}
                      className="splash-feature"
                      variants={featureVariants}
                      initial="initial"
                      animate="animate"
                      custom={feature.delay}
                    >
                      <div className="feature-icon">
                        <feature.icon size={20} />
                      </div>
                      <span className="feature-text">{feature.text}</span>
                      <motion.div
                        className="feature-checkmark"
                        initial={{ scale: 0, opacity: 0 }}
                        animate={{ scale: 1, opacity: 1 }}
                        transition={{ delay: feature.delay + 0.5, type: "spring" }}
                      >
                        <CheckCircle size={16} />
                      </motion.div>
                    </motion.div>
                  ))}
                </motion.div>
              )}
            </AnimatePresence>

            {/* Loading Progress */}
            <motion.div 
              className="splash-loading"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 1 }}
            >
              <div className="loading-bar">
                <motion.div
                  className="loading-progress"
                  initial={{ width: "0%" }}
                  animate={{ width: "100%" }}
                  transition={{ duration: 4, ease: "easeInOut" }}
                />
              </div>
              <motion.p 
                className="loading-text"
                animate={{
                  opacity: [0.5, 1, 0.5]
                }}
                transition={{
                  duration: 1.5,
                  repeat: Infinity,
                  ease: "easeInOut"
                }}
              >
                Initializing security protocols...
              </motion.p>
            </motion.div>
          </div>

          {/* Scanning Lines Effect */}
          <div className="scanning-lines">
            <motion.div
              className="scan-line"
              animate={{
                y: ["-100vh", "100vh"],
                opacity: [0, 1, 0]
              }}
              transition={{
                duration: 2,
                repeat: Infinity,
                ease: "linear",
                repeatDelay: 1
              }}
            />
            <motion.div
              className="scan-line scan-line-2"
              animate={{
                y: ["-100vh", "100vh"],
                opacity: [0, 0.5, 0]
              }}
              transition={{
                duration: 2.5,
                repeat: Infinity,
                ease: "linear",
                repeatDelay: 1.5,
                delay: 0.5
              }}
            />
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

export default SplashScreen;