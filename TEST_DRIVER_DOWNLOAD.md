# Driver Download Testing Guide

## Quick Test Steps

### 1. Start the Application

```powershell
# Build and run Electron app
npm run electron
```

### 2. Navigate to Driver Scanner
- Click on **"Driver Scanner"** in the sidebar
- The enhanced driver scanner should open

### 3. Scan for Drivers
- Click **"Scan Drivers"** button
- Wait 2 seconds for scan to complete
- You should see a list of detected drivers

### 4. Test Driver Download

#### Test Case 1: Direct Download Button
1. Find a driver with "Update Available" status (e.g., NVIDIA GeForce)
2. Expand the driver details (click the row)
3. Click **"Get Update from [Manufacturer]"** button
4. **Expected Result:**
   - Your default browser should open
   - Navigate to manufacturer's download page (e.g., nvidia.com)
   - See toast notification: "Opening [Manufacturer] download page..."
   - Installation dialog appears with instructions

#### Test Case 2: Installation Dialog
1. After clicking download button, the dialog should appear
2. **Verify Dialog Shows:**
   - ✅ Driver name (e.g., "NVIDIA GeForce RTX 4070")
   - ✅ Version number (e.g., "546.17")
   - ✅ File size (e.g., "850 MB")
   - ✅ Manufacturer name
   - ✅ Manual installation instructions

3. Click **"Open Download Page"** button
4. **Expected Result:**
   - Browser opens manufacturer page again
   - Toast notification appears
   - If backup is enabled: "Backup created. Opening..."
   - Dialog closes

#### Test Case 3: Browser Fallback
If Electron APIs fail, it should fallback to window.open():
- Should still open manufacturer page
- May open in new tab instead of default browser

### 5. Verify Different Manufacturers

Test with multiple driver types:

| Driver | Manufacturer | Expected URL |
|--------|-------------|--------------|
| NVIDIA Graphics | NVIDIA | nvidia.com/Download |
| AMD Graphics | AMD | amd.com/support |
| Intel Wi-Fi | Intel | intel.com/download |
| Realtek Audio | Realtek | realtek.com/downloads |

### 6. Check Console Output

Open DevTools (F12) and check for:
- ✅ No JavaScript errors
- ✅ Proper API calls logged
- ✅ URL opening messages

### Expected Console Logs:
```
Opening manufacturer download page...
Using Electron shell API
Opened URL: https://www.nvidia.com/Download/index.aspx
```

## Testing in Different Modes

### Development Mode (npm run electron)
- Uses Electron shell API
- Opens URLs in default browser
- Full DevTools access

### Production Build
```powershell
npm run electron:build:win
cd dist/win-unpacked
./Nebula Shield Anti-Virus.exe
```
- Uses packaged Electron APIs
- Should work identically
- No DevTools (unless explicitly enabled)

### Browser Mode (if running web version)
```powershell
npm start
```
- Falls back to window.open()
- Opens in new browser tab
- Should display same UI

## Common Issues & Solutions

### Issue: Browser doesn't open
**Check:**
1. Electron shell API is exposed: `window.electron.shell`
2. IPC handler exists in electron.js
3. Preload script is loaded
4. Check console for errors

**Solution:**
- Verify preload.js is in public folder
- Check electron.js has preload path set
- Restart application

### Issue: "Download URL not available"
**Check:**
- Driver has downloadUrl in database
- DRIVER_DATABASE has entry for that manufacturer

**Solution:**
- Verify driver category matches database
- Check manufacturer name spelling

### Issue: Dialog doesn't show
**Check:**
- installDialog state is set
- No JavaScript errors in console

**Solution:**
- Check React state updates
- Verify AnimatePresence works

## Verification Checklist

After testing, verify:

- [ ] Browser opens for all manufacturer types
- [ ] Dialog shows correct driver information
- [ ] Manual installation instructions are clear
- [ ] Backup creation works (if enabled)
- [ ] Toast notifications appear
- [ ] No "Driver installed successfully" fake messages
- [ ] Button says "Open Download Page" not "Install Now"
- [ ] No fake download progress bars
- [ ] Vulnerability warnings show for affected drivers
- [ ] Multiple clicks don't open multiple browser windows
- [ ] Dialog closes properly after action

## Success Criteria

✅ **Test Passes If:**
1. Browser opens to manufacturer's official website
2. User receives clear instructions
3. No misleading "installed" messages
4. Dialog provides accurate driver information
5. Backup creation works (when enabled)
6. No JavaScript errors in console
7. Works in both dev and production builds

❌ **Test Fails If:**
1. Browser doesn't open
2. Wrong URL opens
3. Fake "installation" messages appear
4. JavaScript errors occur
5. Dialog doesn't show
6. Backup fails silently

## Manual Testing Scenarios

### Scenario A: First-time User
1. Open app for first time
2. Navigate to Driver Scanner
3. Scan drivers
4. Try to update one driver
5. **Expect:** Clear guidance on manual process

### Scenario B: Power User
1. Scan multiple times
2. Download updates for several drivers
3. Check backup creation
4. **Expect:** Efficient workflow, no confusion

### Scenario C: Security-Conscious User
1. Look for vulnerability warnings
2. Check that official URLs are used
3. Verify no auto-execution
4. **Expect:** Transparency and safety

## Automation Test (Optional)

If you want to automate testing:

```javascript
// Test that shell.openExternal is called
const mockShell = {
  openExternal: jest.fn()
};

window.electron = {
  shell: mockShell
};

// Trigger download
await handleDownloadDriver(testDriver);

expect(mockShell.openExternal).toHaveBeenCalledWith(
  'https://www.nvidia.com/Download/index.aspx'
);
```

## Report Issues

If you find problems:
1. Note the exact steps to reproduce
2. Check browser console for errors
3. Verify Electron logs
4. Check manufacturer URL is accessible
5. Test in both dev and production modes

## Success Message

If all tests pass, you should see:

✅ **Driver download functionality working correctly!**
- Opens real manufacturer pages
- Provides clear instructions
- No fake installations
- Professional and transparent
