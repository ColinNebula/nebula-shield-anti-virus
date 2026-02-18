import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';

const ThemeContext = createContext();

export const useTheme = () => {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};

// Theme presets with comprehensive color schemes
const defaultThemePresets = {
  default: {
    name: 'Default Purple',
    category: 'dark',
    description: 'Classic Nebula Shield theme with vibrant purple accents',
    colors: {
      primary: '#6366f1',
      secondary: '#818cf8',
      success: '#10b981',
      warning: '#f59e0b',
      danger: '#ef4444',
      background: '#0f172a',
      surface: '#1e293b',
      text: '#f1f5f9'
    }
  },
  ocean: {
    name: 'Ocean Deep',
    category: 'dark',
    description: 'Cool ocean blues for a calm, focused experience',
    colors: {
      primary: '#0ea5e9',
      secondary: '#38bdf8',
      success: '#06b6d4',
      warning: '#f59e0b',
      danger: '#ef4444',
      background: '#0c4a6e',
      surface: '#075985',
      text: '#e0f2fe'
    }
  },
  sunset: {
    name: 'Sunset Blaze',
    category: 'dark',
    description: 'Warm sunset oranges for an energetic atmosphere',
    colors: {
      primary: '#f97316',
      secondary: '#fb923c',
      success: '#10b981',
      warning: '#fbbf24',
      danger: '#dc2626',
      background: '#7c2d12',
      surface: '#9a3412',
      text: '#ffedd5'
    }
  },
  forest: {
    name: 'Forest Night',
    category: 'dark',
    description: 'Nature-inspired greens for a refreshing look',
    colors: {
      primary: '#22c55e',
      secondary: '#4ade80',
      success: '#10b981',
      warning: '#eab308',
      danger: '#ef4444',
      background: '#14532d',
      surface: '#166534',
      text: '#dcfce7'
    }
  },
  cyberpunk: {
    name: 'Cyberpunk Neon',
    category: 'dark',
    description: 'Futuristic neon pink and cyan for maximum style',
    colors: {
      primary: '#ec4899',
      secondary: '#f472b6',
      success: '#06b6d4',
      warning: '#f59e0b',
      danger: '#ef4444',
      background: '#18181b',
      surface: '#27272a',
      text: '#fce7f3'
    }
  },
  midnight: {
    name: 'Midnight Aurora',
    category: 'dark',
    description: 'Deep midnight blue with aurora green accents',
    colors: {
      primary: '#8b5cf6',
      secondary: '#a78bfa',
      success: '#34d399',
      warning: '#fbbf24',
      danger: '#f87171',
      background: '#0f0f23',
      surface: '#1a1a3e',
      text: '#e0e7ff'
    }
  },
  volcanic: {
    name: 'Volcanic Red',
    category: 'dark',
    description: 'Intense volcanic red for a bold statement',
    colors: {
      primary: '#dc2626',
      secondary: '#ef4444',
      success: '#10b981',
      warning: '#f59e0b',
      danger: '#991b1b',
      background: '#450a0a',
      surface: '#7f1d1d',
      text: '#fee2e2'
    }
  },
  arctic: {
    name: 'Arctic Frost',
    category: 'light',
    description: 'Cool icy blues on a bright canvas',
    colors: {
      primary: '#0284c7',
      secondary: '#0ea5e9',
      success: '#059669',
      warning: '#d97706',
      danger: '#dc2626',
      background: '#f0f9ff',
      surface: '#e0f2fe',
      text: '#0c4a6e'
    }
  },
  sakura: {
    name: 'Sakura Bloom',
    category: 'light',
    description: 'Soft cherry blossom pink for elegance',
    colors: {
      primary: '#ec4899',
      secondary: '#f472b6',
      success: '#10b981',
      warning: '#f59e0b',
      danger: '#dc2626',
      background: '#fdf2f8',
      surface: '#fce7f3',
      text: '#831843'
    }
  },
  golden: {
    name: 'Golden Hour',
    category: 'light',
    description: 'Warm golden tones for a premium feel',
    colors: {
      primary: '#ca8a04',
      secondary: '#eab308',
      success: '#16a34a',
      warning: '#f59e0b',
      danger: '#dc2626',
      background: '#fefce8',
      surface: '#fef9c3',
      text: '#713f12'
    }
  },
  mint: {
    name: 'Mint Fresh',
    category: 'light',
    description: 'Refreshing mint green for clarity',
    colors: {
      primary: '#059669',
      secondary: '#10b981',
      success: '#16a34a',
      warning: '#d97706',
      danger: '#dc2626',
      background: '#f0fdf4',
      surface: '#dcfce7',
      text: '#064e3b'
    }
  },
  royal: {
    name: 'Royal Purple',
    category: 'dark',
    description: 'Majestic purple for a premium experience',
    colors: {
      primary: '#9333ea',
      secondary: '#a855f7',
      success: '#22c55e',
      warning: '#f59e0b',
      danger: '#ef4444',
      background: '#1e1b4b',
      surface: '#312e81',
      text: '#e9d5ff'
    }
  },
  galaxy: {
    name: 'Galaxy Spiral',
    category: 'dark',
    description: 'Deep space purple with cosmic accents',
    colors: {
      primary: '#7c3aed',
      secondary: '#a78bfa',
      success: '#34d399',
      warning: '#fbbf24',
      danger: '#f472b6',
      background: '#0d0221',
      surface: '#1a0b3a',
      text: '#ddd6fe'
    }
  },
  emerald: {
    name: 'Emerald Matrix',
    category: 'dark',
    description: 'Matrix-inspired green for tech enthusiasts',
    colors: {
      primary: '#10b981',
      secondary: '#34d399',
      success: '#22c55e',
      warning: '#fbbf24',
      danger: '#ef4444',
      background: '#022c22',
      surface: '#064e3b',
      text: '#d1fae5'
    }
  },
  crimson: {
    name: 'Crimson Shadow',
    category: 'dark',
    description: 'Dark crimson for an aggressive look',
    colors: {
      primary: '#be123c',
      secondary: '#e11d48',
      success: '#10b981',
      warning: '#f59e0b',
      danger: '#7f1d1d',
      background: '#1a0000',
      surface: '#450a0a',
      text: '#ffe4e6'
    }
  },
  slate: {
    name: 'Slate Professional',
    category: 'dark',
    description: 'Clean slate gray for a professional workspace',
    colors: {
      primary: '#64748b',
      secondary: '#94a3b8',
      success: '#10b981',
      warning: '#f59e0b',
      danger: '#ef4444',
      background: '#0f172a',
      surface: '#1e293b',
      text: '#f1f5f9'
    }
  },
  
  // Accessibility presets
  highContrast: {
    name: 'High Contrast',
    category: 'accessibility',
    description: 'Maximum contrast for better visibility',
    colors: {
      primary: '#ffffff',
      secondary: '#fbbf24',
      success: '#22c55e',
      warning: '#fbbf24',
      danger: '#ff0000',
      background: '#000000',
      surface: '#1a1a1a',
      text: '#ffffff'
    }
  },
  deuteranopia: {
    name: 'Deuteranopia Safe',
    category: 'accessibility',
    description: 'Optimized for red-green color blindness',
    colors: {
      primary: '#0ea5e9',
      secondary: '#38bdf8',
      success: '#0284c7',
      warning: '#f59e0b',
      danger: '#d97706',
      background: '#0f172a',
      surface: '#1e293b',
      text: '#f1f5f9'
    }
  },
  protanopia: {
    name: 'Protanopia Safe',
    category: 'accessibility',
    description: 'Optimized for red-green color blindness (type 2)',
    colors: {
      primary: '#8b5cf6',
      secondary: '#a78bfa',
      success: '#0ea5e9',
      warning: '#fbbf24',
      danger: '#f59e0b',
      background: '#0f172a',
      surface: '#1e293b',
      text: '#f1f5f9'
    }
  },
  tritanopia: {
    name: 'Tritanopia Safe',
    category: 'accessibility',
    description: 'Optimized for blue-yellow color blindness',
    colors: {
      primary: '#ec4899',
      secondary: '#f472b6',
      success: '#22c55e',
      warning: '#dc2626',
      danger: '#991b1b',
      background: '#0f172a',
      surface: '#1e293b',
      text: '#f1f5f9'
    }
  }
};

export const ThemeProvider = ({ children }) => {
  const [theme, setTheme] = useState(() => {
    // Check localStorage first
    const savedTheme = localStorage.getItem('nebula-shield-theme');
    if (savedTheme) {
      return savedTheme;
    }
    
    // Check system preference
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      return 'dark';
    }
    
    return 'light';
  });

  // Advanced theme customization options
  const [currentPreset, setCurrentPreset] = useState(() => {
    const saved = localStorage.getItem('nebula-shield-theme-preset');
    return saved || 'default';
  });

  const [fontSize, setFontSize] = useState(() => {
    const saved = localStorage.getItem('nebula-shield-font-size');
    return saved || 'normal';
  });

  const [spacing, setSpacing] = useState(() => {
    const saved = localStorage.getItem('nebula-shield-spacing');
    return saved || 'comfortable';
  });

  const [borderRadius, setBorderRadius] = useState(() => {
    const saved = localStorage.getItem('nebula-shield-border-radius');
    return saved || 'rounded';
  });

  const [animationSpeed, setAnimationSpeed] = useState(() => {
    const saved = localStorage.getItem('nebula-shield-animation-speed');
    return saved || 'normal';
  });

  const [autoTheme, setAutoTheme] = useState(() => {
    const saved = localStorage.getItem('nebula-shield-auto-theme');
    return saved === 'true';
  });

  const [autoThemeSchedule, setAutoThemeSchedule] = useState(() => {
    const saved = localStorage.getItem('nebula-shield-auto-theme-schedule');
    return saved ? JSON.parse(saved) : { lightStart: '06:00', darkStart: '18:00' };
  });

  const [systemThemeSync, setSystemThemeSync] = useState(() => {
    const saved = localStorage.getItem('nebula-shield-system-theme-sync');
    return saved === 'true';
  });

  useEffect(() => {
    // Apply theme to document
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('nebula-shield-theme', theme);
    
    // Update meta theme-color
    const metaThemeColor = document.querySelector('meta[name="theme-color"]');
    if (metaThemeColor) {
      metaThemeColor.setAttribute('content', theme === 'dark' ? '#0f172a' : '#6366f1');
    }
  }, [theme]);

  // Apply custom CSS variables
  useEffect(() => {
    const root = document.documentElement;
    const preset = defaultThemePresets[currentPreset] || defaultThemePresets.default;
    
    // Apply theme preset colors to actual CSS variables used by the app
    if (preset.colors) {
      // Main accent colors - these affect buttons, links, borders, etc.
      root.style.setProperty('--accent-primary', preset.colors.primary);
      root.style.setProperty('--accent-secondary', preset.colors.secondary);
      root.style.setProperty('--accent-success', preset.colors.success);
      root.style.setProperty('--accent-warning', preset.colors.warning);
      root.style.setProperty('--accent-danger', preset.colors.danger);
      
      // Also set brand colors for compatibility
      root.style.setProperty('--brand-primary', preset.colors.primary);
      root.style.setProperty('--brand-secondary', preset.colors.secondary);
      
      // Set theme variables for fallback
      root.style.setProperty('--theme-accent', preset.colors.primary);
      root.style.setProperty('--theme-accentSecondary', preset.colors.secondary);
      root.style.setProperty('--theme-success', preset.colors.success);
      root.style.setProperty('--theme-warning', preset.colors.warning);
      root.style.setProperty('--theme-danger', preset.colors.danger);
      
      // Apply background and surface colors based on theme mode
      if (theme === 'dark') {
        root.style.setProperty('--bg-primary', preset.colors.background);
        root.style.setProperty('--bg-secondary', preset.colors.surface);
        root.style.setProperty('--text-primary', preset.colors.text);
      }
    }
    
    // Convert string values to CSS values
    const fontSizeMap = {
      'small': '14px',
      'normal': '16px',
      'large': '18px',
      'extra-large': '20px'
    };
    
    const spacingMap = {
      'compact': '0.75rem',
      'comfortable': '1rem',
      'spacious': '1.5rem'
    };
    
    const borderRadiusMap = {
      'sharp': '0px',
      'rounded': '8px',
      'very-rounded': '16px'
    };
    
    const animationSpeedMap = {
      'none': '0s',
      'reduced': '0.15s',
      'normal': '0.3s',
      'enhanced': '0.5s'
    };
    
    // Apply customization settings
    root.style.setProperty('--font-size-base', fontSizeMap[fontSize] || '16px');
    root.style.setProperty('--spacing-unit', spacingMap[spacing] || '1rem');
    root.style.setProperty('--border-radius-base', borderRadiusMap[borderRadius] || '8px');
    root.style.setProperty('--animation-duration', animationSpeedMap[animationSpeed] || '0.3s');
    
    // Save to localStorage
    localStorage.setItem('nebula-shield-theme-preset', currentPreset);
    localStorage.setItem('nebula-shield-font-size', fontSize);
    localStorage.setItem('nebula-shield-spacing', spacing);
    localStorage.setItem('nebula-shield-border-radius', borderRadius);
    localStorage.setItem('nebula-shield-animation-speed', animationSpeed);
  }, [theme, currentPreset, fontSize, spacing, borderRadius, animationSpeed]);

  // Auto theme scheduling
  useEffect(() => {
    if (!autoTheme) return;

    const checkSchedule = () => {
      const now = new Date();
      const currentTime = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}`;
      
      const { lightStart, darkStart } = autoThemeSchedule;
      
      if (currentTime >= darkStart || currentTime < lightStart) {
        setTheme('dark');
      } else {
        setTheme('light');
      }
    };

    checkSchedule();
    const interval = setInterval(checkSchedule, 60000); // Check every minute
    
    return () => clearInterval(interval);
  }, [autoTheme, autoThemeSchedule]);

  // System theme sync
  useEffect(() => {
    if (!systemThemeSync) return;

    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    
    const handleChange = (e) => {
      setTheme(e.matches ? 'dark' : 'light');
    };

    // Apply initial system theme
    setTheme(mediaQuery.matches ? 'dark' : 'light');

    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, [systemThemeSync]);

  // Save auto theme settings
  useEffect(() => {
    localStorage.setItem('nebula-shield-auto-theme', autoTheme.toString());
    localStorage.setItem('nebula-shield-auto-theme-schedule', JSON.stringify(autoThemeSchedule));
    localStorage.setItem('nebula-shield-system-theme-sync', systemThemeSync.toString());
  }, [autoTheme, autoThemeSchedule, systemThemeSync]);

  const toggleTheme = useCallback(() => {
    setTheme((prevTheme) => (prevTheme === 'light' ? 'dark' : 'light'));
  }, []);

  const setLightTheme = useCallback(() => setTheme('light'), []);
  const setDarkTheme = useCallback(() => setTheme('dark'), []);

  const setPresetTheme = useCallback((presetName) => {
    if (defaultThemePresets[presetName]) {
      setCurrentPreset(presetName);
    }
  }, []);

  const exportThemeSettings = useCallback(() => {
    const settings = {
      theme,
      preset: currentPreset,
      fontSize,
      spacing,
      borderRadius,
      animationSpeed,
      autoTheme,
      autoThemeSchedule,
      systemThemeSync
    };
    return JSON.stringify(settings, null, 2);
  }, [theme, currentPreset, fontSize, spacing, borderRadius, animationSpeed, autoTheme, autoThemeSchedule, systemThemeSync]);

  const importThemeSettings = useCallback((settingsJson) => {
    try {
      const settings = JSON.parse(settingsJson);
      if (settings.theme) setTheme(settings.theme);
      if (settings.preset) setCurrentPreset(settings.preset);
      if (settings.fontSize) setFontSize(settings.fontSize);
      if (settings.spacing) setSpacing(settings.spacing);
      if (settings.borderRadius) setBorderRadius(settings.borderRadius);
      if (settings.animationSpeed) setAnimationSpeed(settings.animationSpeed);
      if (settings.autoTheme !== undefined) setAutoTheme(settings.autoTheme);
      if (settings.autoThemeSchedule) setAutoThemeSchedule(settings.autoThemeSchedule);
      if (settings.systemThemeSync !== undefined) setSystemThemeSync(settings.systemThemeSync);
      return true;
    } catch (error) {
      console.error('Failed to import theme settings:', error);
      return false;
    }
  }, []);

  const value = {
    theme,
    toggleTheme,
    setLightTheme,
    setDarkTheme,
    isDark: theme === 'dark',
    isLight: theme === 'light',
    // Advanced customization
    themePresets: defaultThemePresets,
    currentPreset,
    currentThemeConfig: defaultThemePresets[currentPreset] || defaultThemePresets.default,
    setPresetTheme,
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

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
};

export default ThemeContext;
