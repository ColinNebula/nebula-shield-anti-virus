import React from 'react';
import { motion } from 'framer-motion';
import './NebulaLogo.css';
import logoSvg from '../logo.svg';

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

  // Use imported SVG instead of public path for better bundling
  const logoSrc = logoSvg;

  if (animated) {
    return (
      <motion.img
        src={logoSrc}
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
      src={logoSrc}
      alt="Nebula Shield"
      style={logoStyle}
      className={logoClasses}
    />
  );
};

export default NebulaLogo;