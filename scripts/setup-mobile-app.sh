#!/bin/bash

# Nebula Shield Mobile - Setup Script
# This script sets up the React Native mobile companion app

set -e

echo "╔════════════════════════════════════════════════════════╗"
echo "║   Nebula Shield Mobile Companion - Setup              ║"
echo "║   Created by Colin Nebula                             ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# Check Node.js installation
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 16+ first."
    exit 1
fi

NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 16 ]; then
    echo "❌ Node.js version 16+ required. Current version: $(node -v)"
    exit 1
fi

echo "✅ Node.js $(node -v) detected"

# Check npm installation
if ! command -v npm &> /dev/null; then
    echo "❌ npm is not installed."
    exit 1
fi

echo "✅ npm $(npm -v) detected"

# Navigate to mobile app directory
cd "$(dirname "$0")/../nebula-shield-mobile"

# Install dependencies
echo ""
echo "📦 Installing dependencies..."
npm install

# Install Expo CLI globally if not present
if ! command -v expo &> /dev/null; then
    echo ""
    echo "📱 Installing Expo CLI..."
    npm install -g expo-cli
fi

# Create asset directories
echo ""
echo "📁 Creating asset directories..."
mkdir -p assets/icons
mkdir -p assets/images
mkdir -p assets/fonts

# Create placeholder icon files
echo "🎨 Creating placeholder assets..."
cat > assets/icon-placeholder.txt << EOF
Place your app icon (1024x1024 px) here as:
- icon.png
- adaptive-icon.png (Android)
- favicon.png (Web)
EOF

# Setup complete
echo ""
echo "╔════════════════════════════════════════════════════════╗"
echo "║   Setup Complete! 🎉                                   ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
echo "Next steps:"
echo ""
echo "1. Start the desktop Nebula Shield app"
echo "2. Run development server:"
echo "   cd nebula-shield-mobile"
echo "   npm start"
echo ""
echo "3. Scan QR code with Expo Go app (iOS/Android)"
echo "   or press 'i' for iOS simulator"
echo "   or press 'a' for Android emulator"
echo ""
echo "4. Generate pairing code in desktop app"
echo "5. Enter code in mobile app to connect"
echo ""
echo "📱 Happy coding!"
echo ""
