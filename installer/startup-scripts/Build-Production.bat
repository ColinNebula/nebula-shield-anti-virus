@echo off
title Nebula Shield - Production Build
echo Building Nebula Shield for Production...
cd /d "%~dp0"

echo.
echo Creating optimized production build...
echo This may take a few minutes...
echo.

call npm run build:production

echo.
echo ✅ Build complete! Files are in the 'build' folder.
echo.
echo To deploy, copy the 'build' folder to your web server.
echo.
pause
