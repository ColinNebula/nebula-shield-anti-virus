// Enhanced Theme Context with Multiple Themes and Customization
import React, { createContext, useContext, useState, useEffect } from 'react';

const ThemeContext = createContext();

// Preset Color Themes
export const THEME_PRESETS = {
  dark: {
    name: 'Dark (Default)',
    type: 'dark',
    colors: {
      primary: '#0f172a',
      secondary: '#1e293b',
      tertiary: '#334155',
      accent: '#4f46e5',
      accentSecondary: '#6366f1',
      success: '#10b981',
      warning: '#f59e0b',
      danger: '#ef4444'
    }
  },
  light: {
    name: 'Light',
    type: 'light',
    colors: {
      primary: '#ffffff',
      secondary: '#f8fafc',
      tertiary: '#e2e8f0',
      accent: '#4f46e5',
      accentSecondary: '#6366f1',
      success: '#10b981',
      warning: '#f59e0b',
      danger: '#ef4444'
    }
  },
  nebula: {
    name: 'Nebula Purple',
    type: 'dark',
    colors: {
      primary: '#1a0b2e',
      secondary: '#2d1b4e',
      tertiary: '#3f2a5e',
      accent: '#a855f7',
      accentSecondary: '#c084fc',
      success: '#10b981',
      warning: '#f59e0b',
      danger: '#ef4444'
    }
  },
  ocean: {
    name: 'Ocean Blue',
    type: 'dark',
    colors: {
      primary: '#0c1e2e',
      secondary: '#1a3347',
      tertiary: '#2a4a5e',
      accent: '#06b6d4',
      accentSecondary: '#22d3ee',
      success: '#10b981',
      warning: '#f59e0b',
      danger: '#ef4444'
    }
  },
  forest: {
    name: 'Forest Green',
    type: 'dark',
    colors: {
      primary: '#0a1f0f',
      secondary: '#16331e',
      tertiary: '#234a2e',
      accent: '#22c55e',
      accentSecondary: '#4ade80',
      success: '#10b981',
      warning: '#f59e0b',
      danger: '#ef4444'
    }
  },
  sunset: {
    name: 'Sunset Orange',
    type: 'dark',
    colors: {
      primary: '#2e1a0c',
      secondary: '#472a1a',
      tertiary: '#5e3a2a',
      accent: '#f97316',
      accentSecondary: '#fb923c',
      success: '#10b981',
      warning: '#f59e0b',
      danger: '#ef4444'
    }
  },
  midnight: {
    name: 'Midnight Blue',
    type: 'dark',
    colors: {
      primary: '#020617',
      secondary: '#0f172a',
      tertiary: '#1e293b',
      accent: '#3b82f6',
      accentSecondary: '#60a5fa',
      success: '#10b981',
      warning: '#f59e0b',
      danger: '#ef4444'
    }
  },
  highContrast: {
    name: 'High Contrast',
    type: 'dark',
    colors: {
      primary: '#000000',
      secondary: '#1a1a1a',
      tertiary: '#2d2d2d',
      accent: '#00ff00',
      accentSecondary: '#00cc00',
      success: '#00ff00',
      warning: '#ffff00',
      danger: '#ff0000'
    }
  }
};

export const useTheme = () => {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};

export const ThemeProvider = ({ children }) => {
  const [theme, setTheme] = useState(() => {
    const savedTheme = localStorage.getItem('nebula-shield-theme');
    return savedTheme || 'dark';
  });

  const [fontSize, setFontSize] = useState(() => {
    const savedSize = localStorage.getItem('nebula-shield-font-size');
    return savedSize || 'normal';
  });

  const [spacing, setSpacing] = useState(() => {
    const savedSpacing = localStorage.getItem('nebula-shield-spacing');
    return savedSpacing || 'comfortable';
  });

  const [borderRadius, setBorderRadius] = useState(() => {
    const savedRadius = localStorage.getItem('nebula-shield-border-radius');
    return savedRadius || 'rounded';
  });

  const [animationSpeed, setAnimationSpeed] = useState(() => {
    const savedSpeed = localStorage.getItem('nebula-shield-animation-speed');
    return savedSpeed || 'normal';
  });

  const [autoTheme, setAutoTheme] = useState(() => {
    const savedAuto = localStorage.getItem('nebula-shield-auto-theme');
    return savedAuto === 'true';
  });

  const [autoThemeSchedule, setAutoThemeSchedule] = useState(() => {
    const savedSchedule = localStorage.getItem('nebula-shield-auto-theme-schedule');
    return savedSchedule ? JSON.parse(savedSchedule) : {
      lightStart: '06:00',
      darkStart: '18:00',
      lightTheme: 'light',
      darkTheme: 'dark'
    };
  });

  const [systemThemeSync, setSystemThemeSync] = useState(() => {
    const savedSync = localStorage.getItem('nebula-shield-system-theme-sync');
    return savedSync === 'true';
  });

  // Apply theme to document
  useEffect(() => {
    const themeConfig = THEME_PRESETS[theme];
    if (themeConfig) {
      document.documentElement.setAttribute('data-theme', theme);
      document.documentElement.setAttribute('data-theme-type', themeConfig.type);
      
      // Apply colors as CSS variables
      Object.entries(themeConfig.colors).forEach(([key, value]) => {
        document.documentElement.style.setProperty(`--theme-${key}`, value);
      });
    }
    localStorage.setItem('nebula-shield-theme', theme);
  }, [theme]);

  // Apply font size
  useEffect(() => {
    const fontSizeMap = {
      small: '14px',
      normal: '16px',
      large: '18px',
      'extra-large': '20px'
    };
    document.documentElement.style.setProperty('--base-font-size', fontSizeMap[fontSize]);
    localStorage.setItem('nebula-shield-font-size', fontSize);
  }, [fontSize]);

  // Apply spacing
  useEffect(() => {
    const spacingMap = {
      compact: '0.75',
      comfortable: '1',
      spacious: '1.25'
    };
    document.documentElement.style.setProperty('--spacing-scale', spacingMap[spacing]);
    localStorage.setItem('nebula-shield-spacing', spacing);
  }, [spacing]);

  // Apply border radius
  useEffect(() => {
    const radiusMap = {
      sharp: '0px',
      rounded: '8px',
      'very-rounded': '16px'
    };
    document.documentElement.style.setProperty('--base-border-radius', radiusMap[borderRadius]);
    localStorage.setItem('nebula-shield-border-radius', borderRadius);
  }, [borderRadius]);

  // Apply animation speed
  useEffect(() => {
    const speedMap = {
      none: '0s',
      reduced: '0.15s',
      normal: '0.3s',
      enhanced: '0.5s'
    };
    document.documentElement.style.setProperty('--animation-speed', speedMap[animationSpeed]);
    localStorage.setItem('nebula-shield-animation-speed', animationSpeed);
  }, [animationSpeed]);

  // Auto theme switching based on time
  useEffect(() => {
    if (!autoTheme) return;

    const checkAndUpdateTheme = () => {
      const now = new Date();
      const currentTime = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
      
      const lightTime = autoThemeSchedule.lightStart;
      const darkTime = autoThemeSchedule.darkStart;
      
      // Determine if we should be in light or dark mode
      const shouldBeDark = currentTime >= darkTime || currentTime < lightTime;
      const targetTheme = shouldBeDark ? autoThemeSchedule.darkTheme : autoThemeSchedule.lightTheme;
      
      if (theme !== targetTheme) {
        setTheme(targetTheme);
      }
    };

    checkAndUpdateTheme();
    const interval = setInterval(checkAndUpdateTheme, 60000); // Check every minute
    
    return () => clearInterval(interval);
  }, [autoTheme, autoThemeSchedule, theme]);

  // System theme sync
  useEffect(() => {
    if (!systemThemeSync) return;

    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    
    const handleChange = (e) => {
      setTheme(e.matches ? 'dark' : 'light');
    };

    handleChange(mediaQuery);
    mediaQuery.addEventListener('change', handleChange);
    
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, [systemThemeSync]);

  // Save auto theme settings
  useEffect(() => {
    localStorage.setItem('nebula-shield-auto-theme', autoTheme);
  }, [autoTheme]);

  useEffect(() => {
    localStorage.setItem('nebula-shield-auto-theme-schedule', JSON.stringify(autoThemeSchedule));
  }, [autoThemeSchedule]);

  useEffect(() => {
    localStorage.setItem('nebula-shield-system-theme-sync', systemThemeSync);
  }, [systemThemeSync]);

  const toggleTheme = () => {
    const currentType = THEME_PRESETS[theme]?.type || 'dark';
    const newTheme = currentType === 'dark' ? 'light' : 'dark';
    setTheme(newTheme);
  };

  const setPresetTheme = (presetName) => {
    if (THEME_PRESETS[presetName]) {
      setTheme(presetName);
    }
  };

  const exportThemeSettings = () => {
    return {
      theme,
      fontSize,
      spacing,
      borderRadius,
      animationSpeed,
      autoTheme,
      autoThemeSchedule,
      systemThemeSync
    };
  };

  const importThemeSettings = (settings) => {
    if (settings.theme) setTheme(settings.theme);
    if (settings.fontSize) setFontSize(settings.fontSize);
    if (settings.spacing) setSpacing(settings.spacing);
    if (settings.borderRadius) setBorderRadius(settings.borderRadius);
    if (settings.animationSpeed) setAnimationSpeed(settings.animationSpeed);
    if (settings.autoTheme !== undefined) setAutoTheme(settings.autoTheme);
    if (settings.autoThemeSchedule) setAutoThemeSchedule(settings.autoThemeSchedule);
    if (settings.systemThemeSync !== undefined) setSystemThemeSync(settings.systemThemeSync);
  };

  const value = {
    theme,
    setTheme,
    toggleTheme,
    setPresetTheme,
    isDark: THEME_PRESETS[theme]?.type === 'dark',
    currentThemeConfig: THEME_PRESETS[theme],
    themePresets: THEME_PRESETS,
    fontSize,
    setFontSize,
    spacing,
    setSpacing,
    borderRadius,
    setBorderRadius,
    animationSpeed,
    setAnimationSpeed,
    autoTheme,
    setAutoTheme,
    autoThemeSchedule,
    setAutoThemeSchedule,
    systemThemeSync,
    setSystemThemeSync,
    exportThemeSettings,
    importThemeSettings
  };

  return (
    <ThemeContext.Provider value={value}>
      {children}
    </ThemeContext.Provider>
  );
};
