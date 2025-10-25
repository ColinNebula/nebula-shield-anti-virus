@echo off
echo ========================================
echo Nebula Shield - Clean Restart
echo ========================================
echo.

echo [1/5] Stopping all Node and Electron processes...
taskkill /F /IM node.exe 2>nul
taskkill /F /IM electron.exe 2>nul
timeout /t 2 /nobreak >nul

echo [2/5] Clearing all caches...
node scripts\force-clear-cache.js

echo [3/5] Clearing React build cache...
if exist node_modules\.cache rmdir /s /q node_modules\.cache
if exist build rmdir /s /q build

echo [4/5] Waiting for ports to clear...
timeout /t 3 /nobreak >nul

echo [5/5] Starting Electron in development mode...
echo.
echo ✅ Cache cleared! Starting fresh...
echo 🔄 Once the app opens:
echo    1. Press Ctrl+Shift+I to open DevTools
echo    2. Go to Application ^> Storage ^> Clear site data
echo    3. Check "Unregister service workers"
echo    4. Click "Clear site data"
echo    5. Press Ctrl+Shift+R to hard refresh
echo.
npm run electron:dev
