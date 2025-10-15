import React from 'react';
import { motion } from 'framer-motion';
import './NebulaLogo.css';

const NebulaLogo = ({ size = 32, animated = false, glow = false, className = "" }) => {
  const logoStyle = {
    width: `${size}px`,
    height: `${size}px`,
    display: 'inline-block'
  };

  const logoClasses = [
    'nebula-logo',
    animated ? 'animated' : '',
    glow ? 'glow' : '',
    className
  ].filter(Boolean).join(' ');

  if (animated) {
    return (
      <motion.img
        src="/logo.svg"
        alt="Nebula Shield"
        style={logoStyle}
        className={logoClasses}
        whileHover={{ scale: 1.1, rotate: 5 }}
        whileTap={{ scale: 0.95 }}
        transition={{ type: "spring", stiffness: 300, damping: 20 }}
      />
    );
  }

  return (
    <img
      src="/logo.svg"
      alt="Nebula Shield"
      style={logoStyle}
      className={logoClasses}
    />
  );
};

export default NebulaLogo;