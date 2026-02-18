import React, { useEffect, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import './ThreatGlobe.css';

/**
 * 3D Threat Globe - Interactive visualization of global threats
 * Shows real-time threat locations on an animated globe
 */
const ThreatGlobe = ({ threats = [], onThreatClick }) => {
  const canvasRef = useRef(null);
  const [hoveredThreat, setHoveredThreat] = useState(null);
  const [rotation, setRotation] = useState(0);
  const animationRef = useRef(null);

  // Globe configuration
  const config = {
    radius: 150,
    segments: 32,
    rotationSpeed: 0.002,
    threatPulseSpeed: 2,
    colors: {
      globe: '#1a237e',
      gridLines: '#3949ab',
      threat: {
        low: '#4caf50',
        medium: '#ff9800',
        high: '#f44336',
        critical: '#b71c1c'
      }
    }
  };

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const width = canvas.width = canvas.offsetWidth * 2; // Retina display
    const height = canvas.height = canvas.offsetHeight * 2;
    ctx.scale(2, 2);

    const centerX = width / 4;
    const centerY = height / 4;

    // Convert lat/long to 3D coordinates
    const latLongToXYZ = (lat, long, radius, rotation) => {
      const phi = (90 - lat) * (Math.PI / 180);
      const theta = (long + rotation * 180 / Math.PI) * (Math.PI / 180);
      
      return {
        x: radius * Math.sin(phi) * Math.cos(theta),
        y: radius * Math.cos(phi),
        z: radius * Math.sin(phi) * Math.sin(theta)
      };
    };

    // Draw globe with grid
    const drawGlobe = (currentRotation) => {
      ctx.clearRect(0, 0, width / 2, height / 2);

      // Draw globe sphere
      const gradient = ctx.createRadialGradient(
        centerX, centerY, 0,
        centerX, centerY, config.radius
      );
      gradient.addColorStop(0, config.colors.globe + '40');
      gradient.addColorStop(0.5, config.colors.globe + '80');
      gradient.addColorStop(1, config.colors.globe);

      ctx.beginPath();
      ctx.arc(centerX, centerY, config.radius, 0, Math.PI * 2);
      ctx.fillStyle = gradient;
      ctx.fill();

      // Draw latitude lines
      for (let lat = -80; lat <= 80; lat += 20) {
        ctx.beginPath();
        ctx.strokeStyle = config.colors.gridLines + '40';
        ctx.lineWidth = 0.5;

        let firstPoint = true;
        for (let long = -180; long <= 180; long += 5) {
          const point = latLongToXYZ(lat, long, config.radius, currentRotation);
          if (point.z > 0) {
            const x = centerX + point.x;
            const y = centerY - point.y;
            if (firstPoint) {
              ctx.moveTo(x, y);
              firstPoint = false;
            } else {
              ctx.lineTo(x, y);
            }
          }
        }
        ctx.stroke();
      }

      // Draw longitude lines
      for (let long = -180; long <= 180; long += 20) {
        ctx.beginPath();
        ctx.strokeStyle = config.colors.gridLines + '40';
        ctx.lineWidth = 0.5;

        let firstPoint = true;
        for (let lat = -90; lat <= 90; lat += 5) {
          const point = latLongToXYZ(lat, long, config.radius, currentRotation);
          if (point.z > 0) {
            const x = centerX + point.x;
            const y = centerY - point.y;
            if (firstPoint) {
              ctx.moveTo(x, y);
              firstPoint = false;
            } else {
              ctx.lineTo(x, y);
            }
          }
        }
        ctx.stroke();
      }
    };

    // Draw threat markers
    const drawThreats = (currentRotation, time) => {
      threats.forEach((threat, index) => {
        const point = latLongToXYZ(
          threat.latitude || (Math.random() * 180 - 90),
          threat.longitude || (Math.random() * 360 - 180),
          config.radius,
          currentRotation
        );

        if (point.z > 0) { // Only draw if facing forward
          const x = centerX + point.x;
          const y = centerY - point.y;

          // Pulsing effect
          const pulse = Math.sin(time * config.threatPulseSpeed + index) * 0.5 + 0.5;
          const size = 3 + pulse * 3;

          // Threat color based on severity
          const color = config.colors.threat[threat.severity || 'medium'];

          // Glow effect
          const glowGradient = ctx.createRadialGradient(x, y, 0, x, y, size * 3);
          glowGradient.addColorStop(0, color + 'ff');
          glowGradient.addColorStop(0.5, color + '80');
          glowGradient.addColorStop(1, color + '00');

          ctx.beginPath();
          ctx.arc(x, y, size * 3, 0, Math.PI * 2);
          ctx.fillStyle = glowGradient;
          ctx.fill();

          // Core marker
          ctx.beginPath();
          ctx.arc(x, y, size, 0, Math.PI * 2);
          ctx.fillStyle = color;
          ctx.fill();

          // Ring effect for critical threats
          if (threat.severity === 'critical') {
            ctx.beginPath();
            ctx.arc(x, y, size + 5 + pulse * 5, 0, Math.PI * 2);
            ctx.strokeStyle = color + '80';
            ctx.lineWidth = 2;
            ctx.stroke();
          }
        }
      });
    };

    // Animation loop
    let time = 0;
    const animate = () => {
      time += 0.05;
      const currentRotation = rotation + time * config.rotationSpeed;
      
      drawGlobe(currentRotation);
      drawThreats(currentRotation, time);

      animationRef.current = requestAnimationFrame(animate);
    };

    animate();

    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, [threats, rotation]);

  // Handle mouse interactions
  const handleMouseMove = (e) => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    // Check if hovering over a threat (simplified)
    // In production, you'd calculate actual 3D positions
    setHoveredThreat(null);
  };

  return (
    <div className="threat-globe-container">
      <div className="threat-globe-header">
        <h3>Global Threat Map</h3>
        <div className="threat-legend">
          <div className="legend-item">
            <span className="legend-dot severity-low"></span>
            <span>Low</span>
          </div>
          <div className="legend-item">
            <span className="legend-dot severity-medium"></span>
            <span>Medium</span>
          </div>
          <div className="legend-item">
            <span className="legend-dot severity-high"></span>
            <span>High</span>
          </div>
          <div className="legend-item">
            <span className="legend-dot severity-critical"></span>
            <span>Critical</span>
          </div>
        </div>
      </div>

      <motion.div
        className="globe-wrapper"
        initial={{ opacity: 0, scale: 0.8 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.8 }}
      >
        <canvas
          ref={canvasRef}
          className="threat-globe-canvas"
          onMouseMove={handleMouseMove}
        />

        {hoveredThreat && (
          <motion.div
            className="threat-tooltip"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <div className="tooltip-header">{hoveredThreat.type}</div>
            <div className="tooltip-body">
              <div>Location: {hoveredThreat.location}</div>
              <div>Severity: {hoveredThreat.severity}</div>
              <div>Time: {new Date(hoveredThreat.timestamp).toLocaleTimeString()}</div>
            </div>
          </motion.div>
        )}
      </motion.div>

      <div className="threat-stats">
        <div className="stat-item">
          <div className="stat-value">{threats.length}</div>
          <div className="stat-label">Active Threats</div>
        </div>
        <div className="stat-item">
          <div className="stat-value">
            {threats.filter(t => t.severity === 'critical' || t.severity === 'high').length}
          </div>
          <div className="stat-label">High Priority</div>
        </div>
        <div className="stat-item">
          <div className="stat-value">
            {new Set(threats.map(t => t.country)).size}
          </div>
          <div className="stat-label">Countries</div>
        </div>
      </div>
    </div>
  );
};

export default ThreatGlobe;
