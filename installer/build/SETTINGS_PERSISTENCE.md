# Settings Persistence Implementation

## Overview
User settings are now persisted to the backend database and tied to user accounts. This means settings will be preserved across logout/login sessions and when switching between different browsers or devices (as long as the user is logged in).

## Architecture

### Backend (Auth Server - Port 8081)

#### Database Schema
```sql
CREATE TABLE IF NOT EXISTS user_settings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL UNIQUE,
  settings_json TEXT NOT NULL DEFAULT '{}',
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
)
```

#### API Endpoints

**GET /api/settings**
- Returns the user's saved settings as JSON
- Requires JWT authentication
- Returns empty object `{}` for new users

**POST /api/settings**
- Saves user settings to the database
- Requires JWT authentication
- Uses UPSERT pattern (INSERT...ON CONFLICT)
- Automatically updates `updated_at` timestamp

### Frontend Integration

#### AuthContext (`src/contexts/AuthContext.js`)

Added two new methods to the context:

```javascript
saveSettings(settings)
```
- Persists settings to the auth server
- Returns `{ success: true/false, error?: string }`
- Requires user to be authenticated

```javascript
loadSettings()
```
- Retrieves settings from the auth server
- Returns parsed JSON object or `null`
- Requires user to be authenticated

#### Settings Component (`src/components/Settings.js`)

**On Load:**
1. Loads user settings from auth server
2. Loads system configuration from C++ backend
3. Merges user settings over system defaults
4. Always syncs real-time protection status from actual system state

**On Save:**
1. Updates C++ backend configuration
2. Persists settings to auth server (user account)
3. Shows success toast notification

## Settings Flow

### Login Flow
```
User Login
    ↓
JWT Token Stored
    ↓
Navigate to Settings
    ↓
loadSettings() called
    ↓
1. Load from Auth Server (user-specific)
2. Load from C++ Backend (system config)
3. Merge: user settings override defaults
    ↓
Settings Rendered
```

### Save Flow
```
User Changes Setting
    ↓
Click "Save Settings"
    ↓
handleSaveSettings() called
    ↓
1. Update C++ Backend Config
2. Persist to Auth Server (user account)
    ↓
Success Toast
```

### Logout Flow
```
User Logs Out
    ↓
JWT Token Cleared
    ↓
Settings remain in database
    ↓
Next Login → Settings Restored
```

## What Gets Persisted

All user-configurable settings are persisted, including:

### Protection Settings
- Real-time protection enabled/disabled
- Auto-quarantine malicious files
- Monitoring sensitivity level

### Scanning Settings
- Scan depth (Quick/Full/Deep)
- Scan speed (Fast/Normal/Thorough)
- Archive scanning enabled/disabled
- Max file size limit
- Excluded paths

### Scheduler Settings (Premium)
- Scheduled scan enabled/disabled
- Scan frequency (Daily/Weekly/Monthly)
- Scan time preference

### Appearance Settings
- Theme (Light/Dark/Auto)
- Compact mode
- Animations enabled/disabled

### Notifications
- Toast notifications enabled/disabled
- Sound alerts enabled/disabled
- Desktop notifications

### Advanced Settings
- Debug mode
- Performance mode
- Memory limits

## Data Privacy

- Settings are stored per user account
- Settings JSON is stored as text in SQLite
- No sensitive data is stored in settings
- Settings are only accessible with valid JWT token
- Foreign key constraint ensures data integrity with users table

## Error Handling

### Load Errors
- If auth server unavailable: Falls back to C++ backend defaults only
- If network error: Shows error toast, uses last known settings
- If invalid JSON: Logs error, uses system defaults

### Save Errors
- If C++ backend fails: Shows error, settings not persisted
- If auth server fails: Warning logged, C++ config still updated
- Transaction-like behavior: Both or primary succeeds

## Testing Steps

1. **Login** with a test account
2. **Navigate** to Settings page
3. **Change** some settings (e.g., theme, notifications)
4. **Click** "Save Settings" button
5. **Verify** success toast appears
6. **Logout** completely
7. **Login** again with same account
8. **Navigate** to Settings page
9. **Verify** all settings are restored

## Technical Notes

- Settings are merged with **user settings taking priority** over system defaults
- Real-time protection status is **always synced from system** to prevent state desync
- Settings save is **optimistic** - shows success if C++ backend updates
- Auth server persistence failure is logged but doesn't block the save operation
- First-time users get system defaults until they save settings

## Files Modified

1. `backend/auth-server.js`
   - Added `user_settings` table creation
   - Added GET/POST `/api/settings` endpoints

2. `src/contexts/AuthContext.js`
   - Added `saveSettings()` method
   - Added `loadSettings()` method

3. `src/components/Settings.js`
   - Updated `loadSettings()` to merge user settings
   - Updated `handleSaveSettings()` to persist to auth server
   - Imported `loadUserSettings` and `saveUserSettings` from context

## Database Location

Settings are stored in: `data/auth.db` → `user_settings` table

## Future Enhancements

- Settings versioning (migrate old settings format)
- Settings export/import functionality
- Settings sync conflict resolution
- Settings backup and restore
- Per-device settings preferences
