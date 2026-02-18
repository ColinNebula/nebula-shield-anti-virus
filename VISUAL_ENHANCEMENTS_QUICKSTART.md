# 🚀 Visual Enhancements Quick Start

## Quick Implementation (5 Minutes)

### Step 1: Import Components

```jsx
// Add to your Dashboard.jsx or main component
import ThreatGlobe from './components/ThreatGlobe';
import ActivityGraph from './components/ActivityGraph';
import GamificationSystem from './components/GamificationSystem';
import AnimatedScanProgress from './components/AnimatedScanProgress';
```

### Step 2: Add State Management

```jsx
function Dashboard() {
  const [threats, setThreats] = useState([]);
  const [userStats, setUserStats] = useState(null);
  const [isScanning, setIsScanning] = useState(false);

  useEffect(() => {
    // Fetch global threats
    fetch('http://localhost:8080/api/threats/global')
      .then(res => res.json())
      .then(data => setThreats(data.threats));

    // Fetch user stats
    fetch('http://localhost:8080/api/gamification/stats', {
      headers: { Authorization: `Bearer ${token}` }
    })
      .then(res => res.json())
      .then(data => setUserStats(data.stats));
  }, []);

  return (
    <div className="dashboard">
      {/* Add components here */}
    </div>
  );
}
```

### Step 3: Add Components to Layout

```jsx
<div className="dashboard-grid">
  {/* Threat Globe */}
  <div className="grid-item">
    <ThreatGlobe threats={threats} />
  </div>

  {/* Activity Graph */}
  <div className="grid-item full-width">
    <ActivityGraph />
  </div>

  {/* Gamification */}
  <div className="grid-item full-width">
    <GamificationSystem userStats={userStats} />
  </div>
</div>

{/* Scan Progress Overlay */}
<AnimatedScanProgress
  isScanning={isScanning}
  progress={50}
  currentFile="C:\\Users\\Documents\\file.exe"
  scanType="quick"
  stats={{ scanned: 1250, threats: 3, cleaned: 2 }}
  onCancel={() => setIsScanning(false)}
/>
```

### Step 4: Add CSS Grid Layout

```css
.dashboard-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
  gap: 24px;
  padding: 24px;
}

.grid-item {
  background: #1a1a2e;
  border-radius: 16px;
  overflow: hidden;
}

.grid-item.full-width {
  grid-column: 1 / -1;
}
```

---

## Integration with Scanner

```jsx
import { useState } from 'react';
import AnimatedScanProgress from './components/AnimatedScanProgress';

function Scanner() {
  const [scanState, setScanState] = useState({
    isScanning: false,
    progress: 0,
    currentFile: '',
    stats: { scanned: 0, threats: 0, cleaned: 0 }
  });

  const startScan = async (type = 'quick') => {
    setScanState({ ...scanState, isScanning: true });

    // Simulate scan
    for (let i = 0; i <= 100; i += 5) {
      await new Promise(resolve => setTimeout(resolve, 200));
      
      setScanState(prev => ({
        ...prev,
        progress: i,
        currentFile: `C:\\Path\\To\\File${i}.exe`,
        stats: {
          scanned: Math.floor(i * 50 / 100),
          threats: Math.floor(Math.random() * 3),
          cleaned: Math.floor(Math.random() * 2)
        }
      }));
    }

    // Update gamification
    await fetch('http://localhost:8080/api/gamification/update', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        action: 'scan_complete',
        data: { scanType: type, duration: 60 }
      })
    });

    setScanState({ ...scanState, isScanning: false, progress: 0 });
  };

  return (
    <>
      <button onClick={() => startScan('quick')}>Quick Scan</button>
      <button onClick={() => startScan('full')}>Full Scan</button>

      <AnimatedScanProgress
        isScanning={scanState.isScanning}
        progress={scanState.progress}
        currentFile={scanState.currentFile}
        scanType="quick"
        stats={scanState.stats}
        onCancel={() => setScanState({ ...scanState, isScanning: false })}
      />
    </>
  );
}
```

---

## Update User Stats

```jsx
// After scanning
const updateStats = async (action, data) => {
  try {
    const response = await fetch('http://localhost:8080/api/gamification/update', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ action, data })
    });

    const result = await response.json();
    
    if (result.levelUp) {
      // Show level up notification
      console.log('Level Up!', result.stats.level);
    }

    return result;
  } catch (error) {
    console.error('Failed to update stats:', error);
  }
};

// Usage examples:
await updateStats('scan_complete', { scanType: 'quick', duration: 45 });
await updateStats('threat_detected', { count: 3 });
await updateStats('threat_blocked', { count: 2 });
await updateStats('file_cleaned', { count: 1 });
```

---

## Live Demo Test

Run this in your browser console to test the APIs:

```javascript
// Test global threats
fetch('http://localhost:8080/api/threats/global')
  .then(r => r.json())
  .then(data => console.log('Threats:', data));

// Test gamification stats (requires auth token)
const token = localStorage.getItem('token');
fetch('http://localhost:8080/api/gamification/stats', {
  headers: { Authorization: `Bearer ${token}` }
})
  .then(r => r.json())
  .then(data => console.log('Stats:', data));

// Update stats
fetch('http://localhost:8080/api/gamification/update', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`
  },
  body: JSON.stringify({
    action: 'scan_complete',
    data: { scanType: 'quick', duration: 30 }
  })
})
  .then(r => r.json())
  .then(data => console.log('Updated:', data));
```

---

## Test Backend APIs

```powershell
# Start backend
cd backend
node mock-backend.js

# In another terminal, test the endpoints:

# Get global threats (no auth required)
Invoke-RestMethod -Uri "http://localhost:8080/api/threats/global" | ConvertTo-Json

# Login first
$login = Invoke-RestMethod -Uri "http://localhost:8080/api/auth/login" `
  -Method Post `
  -Body (@{email="admin@test.com"; password="admin"} | ConvertTo-Json) `
  -ContentType "application/json"

$token = $login.token

# Get gamification stats
Invoke-RestMethod -Uri "http://localhost:8080/api/gamification/stats" `
  -Headers @{Authorization="Bearer $token"} | ConvertTo-Json

# Update stats
Invoke-RestMethod -Uri "http://localhost:8080/api/gamification/update" `
  -Method Post `
  -Headers @{Authorization="Bearer $token"} `
  -Body (@{action="scan_complete"; data=@{scanType="quick"; duration=30}} | ConvertTo-Json) `
  -ContentType "application/json" | ConvertTo-Json
```

---

## Minimal Working Example

Copy this entire file to test all features:

```jsx
// MinimalVisualDemo.jsx
import React, { useState, useEffect } from 'react';
import ThreatGlobe from './components/ThreatGlobe';
import ActivityGraph from './components/ActivityGraph';
import GamificationSystem from './components/GamificationSystem';
import AnimatedScanProgress from './components/AnimatedScanProgress';

function MinimalVisualDemo() {
  const [threats, setThreats] = useState([]);
  const [userStats, setUserStats] = useState(null);
  const [isScanning, setIsScanning] = useState(false);

  useEffect(() => {
    // Fetch data
    fetch('http://localhost:8080/api/threats/global')
      .then(res => res.json())
      .then(data => setThreats(data.threats || []));

    const token = localStorage.getItem('token');
    if (token) {
      fetch('http://localhost:8080/api/gamification/stats', {
        headers: { Authorization: `Bearer ${token}` }
      })
        .then(res => res.json())
        .then(data => setUserStats(data.stats));
    } else {
      // Mock data if not logged in
      setUserStats({
        scans: 25,
        threats: 8,
        blocked: 5,
        cleaned: 10,
        quarantined: 3,
        updates: 2,
        firewall_blocks: 150,
        full_scans: 2,
        uptime: 1
      });
    }
  }, []);

  return (
    <div style={{ padding: '24px', background: '#0d1117', minHeight: '100vh' }}>
      <h1 style={{ color: '#fff', marginBottom: '32px' }}>
        🎨 Visual Enhancements Demo
      </h1>

      <div style={{ display: 'grid', gap: '24px', marginBottom: '24px' }}>
        <ThreatGlobe threats={threats} />
        <ActivityGraph maxDataPoints={30} updateInterval={1000} />
        {userStats && <GamificationSystem userStats={userStats} />}
      </div>

      <button
        onClick={() => setIsScanning(true)}
        style={{
          background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
          border: 'none',
          borderRadius: '12px',
          padding: '16px 32px',
          color: '#fff',
          fontSize: '16px',
          fontWeight: '600',
          cursor: 'pointer',
          marginTop: '24px'
        }}
      >
        Test Scan Animation
      </button>

      <AnimatedScanProgress
        isScanning={isScanning}
        progress={75}
        currentFile="C:\\Users\\Documents\\test.exe"
        scanType="quick"
        stats={{ scanned: 1250, threats: 3, cleaned: 2 }}
        onCancel={() => setIsScanning(false)}
      />
    </div>
  );
}

export default MinimalVisualDemo;
```

---

## File Checklist

Ensure these files exist:
- ✅ `src/components/ThreatGlobe.jsx`
- ✅ `src/components/ThreatGlobe.css`
- ✅ `src/components/ActivityGraph.jsx`
- ✅ `src/components/ActivityGraph.css`
- ✅ `src/components/GamificationSystem.jsx`
- ✅ `src/components/GamificationSystem.css`
- ✅ `src/components/AnimatedScanProgress.jsx`
- ✅ `src/components/AnimatedScanProgress.css`
- ✅ `backend/mock-backend.js` (updated with new endpoints)

---

## Next Steps

1. **Test Components**: Run the minimal demo
2. **Integrate**: Add to your existing dashboard
3. **Customize**: Adjust colors, animations, thresholds
4. **Connect Data**: Hook up to real scan/threat data
5. **Add Sounds**: Implement audio feedback (optional)

---

**Ready to use!** 🚀

All components are fully functional and ready for integration.
