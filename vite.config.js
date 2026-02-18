import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  
  // Use relative paths for Electron app (important for file:// protocol)
  base: './',
  
  // ESbuild configuration for JSX in .js files
  esbuild: {
    loader: 'jsx',
    include: /src\/.*\.jsx?$/,
    exclude: [],
  },
  
  // Optimize dependencies to include JSX transform for .js files
  optimizeDeps: {
    esbuildOptions: {
      loader: {
        '.js': 'jsx',
      },
    },
    include: [
      'react',
      'react-dom',
      'react-router-dom',
      '@mui/material',
      '@mui/icons-material',
      'recharts',
      'axios',
      'crypto-js',
      'date-fns',
    ],
  },
  
  // Development server configuration
  server: {
    host: '127.0.0.1', // Explicit IPv4 binding
    port: 3002,
    open: false,
    strictPort: true, // Exit if port is already in use
    // HMR configuration for WebSocket
    hmr: {
      host: '127.0.0.1',
      port: 3002,
      protocol: 'ws',
      clientPort: 3002,
      timeout: 30000, // Increase timeout to 30 seconds
      overlay: true, // Show error overlay
    },
    // Watch configuration to improve HMR reliability
    watch: {
      usePolling: false,
      interval: 100,
    },
    // Proxy API requests to backend
    proxy: {
      // Auth endpoints go to Auth Server (port 8082)
      '/api/auth': {
        target: 'http://localhost:8082',
        changeOrigin: true,
        secure: false,
        ws: true,
      },
      // Subscription endpoints go to Auth Server (port 8082)
      '/api/subscription': {
        target: 'http://localhost:8082',
        changeOrigin: true,
        secure: false,
        ws: true,
      },
      // Status endpoint goes to Auth Server (port 8082)
      '/api/status': {
        target: 'http://localhost:8082',
        changeOrigin: true,
        secure: false,
        ws: true,
      },
      // Signature endpoints go to Auth Server (port 8082)
      '/api/signatures': {
        target: 'http://localhost:8082',
        changeOrigin: true,
        secure: false,
        ws: true,
      },
      // Scan endpoints go to Auth Server (port 8082)
      '/api/scan': {
        target: 'http://localhost:8082',
        changeOrigin: true,
        secure: false,
        ws: true,
      },
      // Disk cleanup endpoints go to Auth Server (port 8082)
      '/api/disk': {
        target: 'http://localhost:8082',
        changeOrigin: true,
        secure: false,
        ws: true,
      },
      // Health check endpoint goes to Auth Server (port 8082)
      '/api/health': {
        target: 'http://localhost:8082',
        changeOrigin: true,
        secure: false,
        ws: true,
      },
      // All other API endpoints go to Mock Backend (port 8080)
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
        secure: false,
        ws: true, // WebSocket support
      },
    },
    // CORS configuration
    cors: true,
  },
  
  // Preview server configuration (for production build preview)
  preview: {
    port: 3001,
    open: false,
    // Proxy API requests to backend in preview mode too
    proxy: {
      // Auth endpoints go to Auth Server (port 8082)
      '/api/auth': {
        target: 'http://localhost:8082',
        changeOrigin: true,
        secure: false,
        ws: true,
      },
      // Subscription endpoints go to Auth Server (port 8082)
      '/api/subscription': {
        target: 'http://localhost:8082',
        changeOrigin: true,
        secure: false,
        ws: true,
      },
      // Status endpoint goes to Auth Server (port 8082)
      '/api/status': {
        target: 'http://localhost:8082',
        changeOrigin: true,
        secure: false,
        ws: true,
      },
      // Signature endpoints go to Auth Server (port 8082)
      '/api/signatures': {
        target: 'http://localhost:8082',
        changeOrigin: true,
        secure: false,
        ws: true,
      },
      // Scan endpoints go to Auth Server (port 8082)
      '/api/scan': {
        target: 'http://localhost:8082',
        changeOrigin: true,
        secure: false,
        ws: true,
      },
      // Disk cleanup endpoints go to Auth Server (port 8082)
      '/api/disk': {
        target: 'http://localhost:8082',
        changeOrigin: true,
        secure: false,
        ws: true,
      },
      // Health check endpoint goes to Auth Server (port 8082)
      '/api/health': {
        target: 'http://localhost:8082',
        changeOrigin: true,
        secure: false,
        ws: true,
      },
      // All other API endpoints go to Mock Backend (port 8080)
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
        secure: false,
        ws: true,
      },
    },
  },
  
  // Build configuration
  build: {
    outDir: 'build',
    sourcemap: false,
    minify: 'esbuild', // Faster than terser
    target: 'esnext',
    cssCodeSplit: true,
    cssMinify: 'esbuild',
    reportCompressedSize: false, // Faster builds
    // Chunk splitting for better caching
    rollupOptions: {
      output: {
        manualChunks: {
          'react-vendor': ['react', 'react-dom', 'react-router-dom'],
          'mui-vendor': ['@mui/material', '@mui/icons-material', '@emotion/react', '@emotion/styled'],
          'chart-vendor': ['recharts', 'chart.js', 'react-chartjs-2'],
        },
        // Optimize chunk file names
        chunkFileNames: 'assets/[name]-[hash].js',
        entryFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]',
      },
    },
    // Increase chunk size warning limit
    chunkSizeWarningLimit: 800,
    // Ensure service worker is copied to build directory
    copyPublicDir: true,
  },
  
  // Resolve configuration
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  
  // Environment variables prefix
  envPrefix: 'VITE_',
  
  // Optimize dependencies removed (merged above)
});
