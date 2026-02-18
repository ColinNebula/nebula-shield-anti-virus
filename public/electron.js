const { app, BrowserWindow, Menu, Tray, ipcMain, dialog, shell, protocol } = require('electron');
const path = require('path');
const isDev = require('electron-is-dev');
const fs = require('fs');
const url = require('url');
const http = require('http');
const express = require('express');

let localServer = null;
let localServerPort = 3003;

let mainWindow;
let tray = null;
let backendProcess = null;

// Setup logging for packaged app
const logPath = path.join(app.getPath('userData'), 'electron.log');
function log(...args) {
  const message = args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : String(arg)).join(' ');
  const timestamp = new Date().toISOString();
  const logMessage = `[${timestamp}] ${message}\n`;
  console.log(message);
  if (app.isPackaged) {
    try {
      fs.appendFileSync(logPath, logMessage);
    } catch (e) {
      console.error('Failed to write log:', e);
    }
  }
}

// Security: Disable deprecated features
app.allowRendererProcessReuse = true;

// Determine if running in development
// In packaged app, process.defaultApp is false and app.isPackaged is true
// In dev with 'electron .', process.defaultApp is true
const isDevMode = process.env.ELECTRON_START_URL || (isDev && !app.isPackaged);
log('Running mode:', isDevMode ? 'Development' : 'Production');
log('isDev:', isDev);
log('app.isPackaged:', app.isPackaged);
log('process.defaultApp:', process.defaultApp);
log('ELECTRON_START_URL:', process.env.ELECTRON_START_URL);

// Enable live reload for Electron in development
if (isDevMode) {
  try {
    require('electron-reload')(__dirname, {
      electron: path.join(__dirname, '..', 'node_modules', '.bin', 'electron'),
      hardResetMethod: 'exit'
    });
  } catch (err) {
    console.log('Electron reload not available');
  }
}

// Start local HTTP server to serve build files
function startLocalServer() {
  return new Promise((resolve, reject) => {
    const expressApp = express();
    
    // Determine build path
    let buildPath;
    if (app.isPackaged) {
      // In production, try unpacked first
      const unpackedPath = path.join(process.resourcesPath, 'app.asar.unpacked', 'build');
      const asarPath = path.join(process.resourcesPath, 'app.asar', 'build');
      buildPath = fs.existsSync(path.join(unpackedPath, 'index.html')) ? unpackedPath : asarPath;
    } else {
      buildPath = path.join(app.getAppPath(), 'build');
    }
    
    log('Local server build path:', buildPath);
    
    // Serve static files with fallback to index.html for SPA routing
    expressApp.use(express.static(buildPath, {
      setHeaders: (res, filePath) => {
        // Set proper MIME types for ES modules
        if (filePath.endsWith('.js')) {
          res.setHeader('Content-Type', 'application/javascript');
        } else if (filePath.endsWith('.mjs')) {
          res.setHeader('Content-Type', 'application/javascript');
        } else if (filePath.endsWith('.css')) {
          res.setHeader('Content-Type', 'text/css');
        }
      }
    }));
    
    // Fallback handler for SPA routing - must be after static files
    expressApp.use((req, res, next) => {
      // Only handle GET requests for HTML pages
      if (req.method !== 'GET') {
        return next();
      }
      
      // If the request is for a file with an extension, let it 404
      if (path.extname(req.path) && req.path !== '/') {
        return next();
      }
      
      // Serve index.html for all other routes (SPA routing)
      const indexPath = path.join(buildPath, 'index.html');
      res.sendFile(indexPath, (err) => {
        if (err) {
          log('Error serving index.html:', err);
          if (!res.headersSent) {
            res.status(500).send('Failed to load application');
          }
        }
      });
    });
    
    // Start server
    localServer = expressApp.listen(localServerPort, '127.0.0.1', (err) => {
      if (err) {
        log('❌ Failed to start local server:', err);
        reject(err);
      } else {
        log('✅ Local server started on http://127.0.0.1:' + localServerPort);
        resolve(`http://127.0.0.1:${localServerPort}`);
      }
    });
    
    localServer.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        // Port in use, try next port
        localServerPort++;
        log('Port in use, trying:', localServerPort);
        localServer = null;
        startLocalServer().then(resolve).catch(reject);
      } else {
        log('Server error:', err);
        reject(err);
      }
    });
  });
}

function createWindow() {
  // Ensure userData directory exists for settings persistence
  const userDataPath = app.getPath('userData');
  if (!fs.existsSync(userDataPath)) {
    fs.mkdirSync(userDataPath, { recursive: true });
  }
  log('UserData path:', userDataPath);
  
  // Build webPreferences object with secure defaults
  // contextIsolation + preload = secure API exposure
  const preloadPath = path.join(__dirname, 'preload.js');
  const webPreferences = {
    nodeIntegration: false, // SECURITY: Disable Node.js in renderer
    contextIsolation: true,  // SECURITY: Isolate renderer context
    enableRemoteModule: false,
    webSecurity: true, // Enable web security for HTTP server approach
    allowRunningInsecureContent: false,
    // DevTools enabled for debugging (can be toggled via menu)
    devTools: true,
    sandbox: false, // Disable sandbox to allow full localStorage access
    preload: preloadPath,
    // Explicitly enable web storage with persistent partition
    partition: 'persist:nebula',
    // Enable web storage APIs
    enableWebSQL: false,
    webgl: true,
    // Session persistence
    session: null // Will use default session with partition
  };
  
  log('WebPreferences:', { nodeIntegration: webPreferences.nodeIntegration, contextIsolation: webPreferences.contextIsolation, sandbox: webPreferences.sandbox, partition: webPreferences.partition });
  
  // Determine icon path based on platform and environment
  let iconPath;
  if (process.platform === 'win32') {
    // Windows requires .ico for proper taskbar icon
    if (app.isPackaged) {
      // In production, icon is in resources
      iconPath = path.join(process.resourcesPath, 'icon.ico');
    } else {
      // In development, use build-resources
      iconPath = path.join(app.getAppPath(), 'build-resources', 'icon.ico');
    }
  } else {
    // macOS and Linux use PNG
    iconPath = app.isPackaged 
      ? path.join(process.resourcesPath, 'icon.png')
      : path.join(__dirname, 'icon.png');
  }
  
  const iconExists = fs.existsSync(iconPath);
  log('Icon path:', iconPath, 'exists:', iconExists);
  
  // Set app icon globally for Windows (important for taskbar)
  if (process.platform === 'win32' && iconExists) {
    app.setAppUserModelId('com.nebulashield.antivirus');
  }
  
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1024,
    minHeight: 768,
    icon: iconExists ? iconPath : path.join(__dirname, 'favicon.ico'),
    backgroundColor: '#0a0a0f',
    title: 'Nebula Shield Anti-Virus',
    webPreferences,
    frame: true,
    titleBarStyle: 'default',
    show: false,
    autoHideMenuBar: false
  });

  // Load the app - will be set after starting local server in production
  let startUrl;
  
  if (process.env.ELECTRON_START_URL) {
    // Development mode with custom URL
    startUrl = process.env.ELECTRON_START_URL;
    log('Development mode - custom URL');
  } else if (isDevMode) {
    // Development mode - Vite dev server
    startUrl = 'http://localhost:3002';
    log('Development mode - Vite dev server');
  } else {
    // Production mode - will use local HTTP server (set below)
    startUrl = null; // Will be set after server starts
    log('Production mode - will use local HTTP server');
  }

  log('Running mode:', isDevMode ? 'Development' : 'Production');
  log('__dirname:', __dirname);
  log('app.getAppPath():', app.getAppPath());
  log('process.resourcesPath:', process.resourcesPath);
  
  // For production, also log the exact file path we're trying to load
  if (!isDevMode) {
    const buildPath = app.isPackaged 
      ? path.join(process.resourcesPath, 'app.asar', 'build', 'index.html')
      : path.join(app.getAppPath(), 'build', 'index.html');
    log('Build index.html path:', buildPath);
    log('Build index.html exists:', fs.existsSync(buildPath));
    
    // Also check if asar is unpacked
    if (app.isPackaged) {
      const unpackedPath = path.join(process.resourcesPath, 'app.asar.unpacked', 'build', 'index.html');
      log('Unpacked path:', unpackedPath);
      log('Unpacked exists:', fs.existsSync(unpackedPath));
    }
  }
  
  // Load URL - in production, start local server first
  if (!isDevMode && !startUrl) {
    // Production mode - start local HTTP server then load
    startLocalServer().then(serverUrl => {
      startUrl = serverUrl;
      log('Loading URL from local server:', startUrl);
      return mainWindow.loadURL(startUrl);
    }).catch(err => {
      log('Failed to start local server or load URL:', err);
      dialog.showErrorBox(
        'Failed to Load Application',
        `The application failed to start the local server or load.\n\nPlease check the log file at:\n${logPath}\n\nError: ${err.message}`
      );
    });
  } else {
    // Development mode - load directly
    log('Loading URL:', startUrl);
    mainWindow.loadURL(startUrl).catch(err => {
      log('Failed to load URL:', err);
      log('Attempting to show error dialog to user');
      
      // Show error dialog
      dialog.showErrorBox(
        'Failed to Load Application',
        `The application failed to load.\n\nAttempted URL: ${startUrl}\n\nPlease check the log file at:\n${logPath}\n\nError: ${err.message}`
      );
    });
  }

  // Show window when ready
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    
    // Configure session for persistent storage
    const session = mainWindow.webContents.session;
    
    // Set storage path for persistence
    const storagePath = path.join(app.getPath('userData'), 'storage');
    if (!fs.existsSync(storagePath)) {
      fs.mkdirSync(storagePath, { recursive: true });
    }
    
    log('Storage path:', storagePath);
    log('Session partition:', session.partition);
    
    // Note: Storage path is automatically handled by Electron via the partition
    // The 'persist:nebula' partition already ensures persistent storage in userData
    
    // TEMP: Open DevTools to debug issues
    mainWindow.webContents.openDevTools();
    // Note: DevTools can still be toggled via View menu in both dev and production
  });

  // Log any console messages from the renderer (ALL levels including errors)
  mainWindow.webContents.on('console-message', (event, level, message, line, sourceId) => {
    const levelName = ['LOG', 'WARNING', 'ERROR'][level] || level;
    log(`Renderer Console [${levelName}]:`, message, `(${sourceId}:${line})`);
  });

  // Log navigation events
  mainWindow.webContents.on('did-fail-load', (event, errorCode, errorDescription, validatedURL) => {
    log('Failed to load:', errorDescription, 'URL:', validatedURL, 'Error code:', errorCode);
  });

  mainWindow.webContents.on('did-finish-load', () => {
    log('✅ Page loaded successfully');
  });

  // Capture renderer process errors
  mainWindow.webContents.on('render-process-gone', (event, details) => {
    log('❌ Renderer process crashed:', details);
  });

  mainWindow.webContents.on('unresponsive', () => {
    log('⚠️ Renderer process unresponsive');
  });

  // Handle window close
  mainWindow.on('close', (event) => {
    if (!app.isQuitting) {
      event.preventDefault();
      mainWindow.hide();
      return false;
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  // Create application menu
  createMenu();
}

function createMenu() {
  const template = [
    {
      label: 'File',
      submenu: [
        {
          label: 'Quick Scan',
          accelerator: 'CmdOrCtrl+Q',
          click: () => {
            mainWindow.webContents.send('trigger-quick-scan');
          }
        },
        {
          label: 'Full Scan',
          accelerator: 'CmdOrCtrl+F',
          click: () => {
            mainWindow.webContents.send('trigger-full-scan');
          }
        },
        { type: 'separator' },
        {
          label: 'Settings',
          accelerator: 'CmdOrCtrl+,',
          click: () => {
            mainWindow.webContents.send('open-settings');
          }
        },
        { type: 'separator' },
        {
          label: 'Exit',
          accelerator: 'CmdOrCtrl+W',
          click: () => {
            app.isQuitting = true;
            app.quit();
          }
        }
      ]
    },
    {
      label: 'View',
      submenu: [
        { role: 'reload' },
        { role: 'forceReload' },
        { role: 'toggleDevTools' },
        { type: 'separator' },
        { role: 'resetZoom' },
        { role: 'zoomIn' },
        { role: 'zoomOut' },
        { type: 'separator' },
        { role: 'togglefullscreen' }
      ]
    },
    {
      label: 'Protection',
      submenu: [
        {
          label: 'Real-time Protection',
          type: 'checkbox',
          checked: true,
          click: (menuItem) => {
            mainWindow.webContents.send('toggle-realtime-protection', menuItem.checked);
          }
        },
        {
          label: 'Firewall',
          type: 'checkbox',
          checked: true,
          click: (menuItem) => {
            mainWindow.webContents.send('toggle-firewall', menuItem.checked);
          }
        },
        { type: 'separator' },
        {
          label: 'Quarantine',
          click: () => {
            mainWindow.webContents.send('open-quarantine');
          }
        }
      ]
    },
    {
      label: 'Help',
      submenu: [
        {
          label: 'Documentation',
          click: () => {
            shell.openExternal('https://github.com/nebula-shield/docs');
          }
        },
        {
          label: 'Report Issue',
          click: () => {
            shell.openExternal('https://github.com/nebula-shield/issues');
          }
        },
        { type: 'separator' },
        {
          label: 'About Nebula Shield',
          click: () => {
            dialog.showMessageBox(mainWindow, {
              type: 'info',
              title: 'About Nebula Shield Anti-Virus',
              message: 'Nebula Shield Anti-Virus',
              detail: `Version: ${app.getVersion()}\n\nAdvanced protection for your system with AI-powered threat detection.\n\n© 2025 Nebula Shield`,
              buttons: ['OK']
            });
          }
        }
      ]
    }
  ];

  const menu = Menu.buildFromTemplate(template);
  Menu.setApplicationMenu(menu);
}

function createTray() {
  // Use PNG for better quality, fallback to ICO
  const pngIcon = path.join(__dirname, 'icon.png');
  const icoIcon = path.join(__dirname, 'favicon.ico');
  const iconPath = fs.existsSync(pngIcon) ? pngIcon : icoIcon;
  
  tray = new Tray(iconPath);

  const contextMenu = Menu.buildFromTemplate([
    {
      label: 'Show Nebula Shield',
      click: () => {
        mainWindow.show();
      }
    },
    { type: 'separator' },
    {
      label: 'Quick Scan',
      click: () => {
        mainWindow.webContents.send('trigger-quick-scan');
        mainWindow.show();
      }
    },
    {
      label: 'Protection Status',
      enabled: false
    },
    {
      label: '  ✓ Real-time Protection: Active',
      enabled: false
    },
    { type: 'separator' },
    {
      label: 'Exit',
      click: () => {
        app.isQuitting = true;
        app.quit();
      }
    }
  ]);

  tray.setToolTip('Nebula Shield Anti-Virus - Protected');
  tray.setContextMenu(contextMenu);

  tray.on('click', () => {
    mainWindow.show();
  });
}

function startBackend() {
  if (isDevMode) {
    // In development, backend should be started separately
    log('Running in development mode - start backend separately using npm run start:backend');
    return;
  }

  // In production, start the backend server automatically
  const { spawn, execSync } = require('child_process');
  
  // First, check if Node.js is available
  let nodeCommand = 'node';
  try {
    execSync('node --version', { stdio: 'ignore' });
    log('Node.js is available in PATH');
  } catch (error) {
    log('ERROR: Node.js not found in PATH');
    dialog.showErrorBox(
      'Node.js Required',
      'Nebula Shield requires Node.js to be installed.\n\nPlease install Node.js from https://nodejs.org/ and restart the application.'
    );
    app.quit();
    return;
  }
  
  // Determine backend path and working directory
  // Try multiple possible locations for different packaging scenarios
  const possiblePaths = [
    // Production portable/installer (extraResources)
    path.join(process.resourcesPath, 'backend'),
    // Development unpacked
    path.join(app.getAppPath(), 'backend'),
    // Alternative unpacked location
    path.join(path.dirname(process.resourcesPath), 'backend'),
    // ASAR unpacked
    path.join(process.resourcesPath, 'app.asar.unpacked', 'backend'),
    // Parent of resources
    path.join(path.dirname(process.resourcesPath), '..', 'backend')
  ];
  
  let backendDir = null;
  let backendPath = null;
  
  // Find the first valid backend location
  for (const testDir of possiblePaths) {
    const testPath = path.join(testDir, 'auth-server.js');
    if (fs.existsSync(testPath)) {
      backendDir = testDir;
      backendPath = testPath;
      break;
    }
  }
  
  log('Starting backend server...');
  log('process.resourcesPath:', process.resourcesPath);
  log('app.getAppPath():', app.getAppPath());
  log('__dirname:', __dirname);
  log('Searched paths:', possiblePaths.map(p => `${p} [${fs.existsSync(p) ? 'EXISTS' : 'NOT FOUND'}]`).join('\n  '));
  log('Backend path:', backendPath);
  log('Backend dir:', backendDir);
  log('Backend file exists:', backendPath ? fs.existsSync(backendPath) : false);
  
  if (!backendPath || !fs.existsSync(backendPath)) {
    log('ERROR: Backend server file not found!');
    const errorMsg = `Backend server not found in any expected location.\n\nSearched:\n${possiblePaths.join('\n')}\n\nPlease reinstall the application.`;
    dialog.showErrorBox('Backend Error', errorMsg);
    return;
  }

  // Check if node_modules exists in backend directory
  const backendNodeModules = path.join(backendDir, 'node_modules');
  
  log('Checking for backend dependencies...');
  log('Backend node_modules path:', backendNodeModules);
  log('Backend node_modules exists:', fs.existsSync(backendNodeModules));
  
  if (!fs.existsSync(backendNodeModules)) {
    log('ERROR: Backend dependencies not found!');
    const errorMsg = `Backend dependencies are missing.\n\nBackend path: ${backendDir}\nnode_modules not found at: ${backendNodeModules}\n\nPlease reinstall the application.`;
    dialog.showErrorBox('Backend Error', errorMsg);
    return;
  }

  // Ensure backend data directories exist in a writable location
  // Use userData directory for writable data (not in resources which is read-only on some systems)
  const userDataPath = app.getPath('userData');
  const backendDataPath = path.join(userDataPath, 'backend-data');
  const dataDirectories = [
    backendDataPath,
    path.join(backendDataPath, 'data'),
    path.join(backendDataPath, 'data', 'quarantine'),
    path.join(backendDataPath, 'data', 'logs'),
    path.join(backendDataPath, 'data', 'virus-definitions'),
    path.join(backendDataPath, 'data', 'backups')
  ];
  
  log('Creating backend data directories in:', backendDataPath);
  for (const dir of dataDirectories) {
    if (!fs.existsSync(dir)) {
      try {
        fs.mkdirSync(dir, { recursive: true });
        log('Created directory:', dir);
      } catch (error) {
        log('ERROR creating directory:', dir, error);
      }
    }
  }

  // Copy initial data files if they don't exist
  const sourceDataPath = path.join(process.resourcesPath, 'data');
  if (fs.existsSync(sourceDataPath)) {
    try {
      const copyDataRecursive = (src, dest) => {
        if (!fs.existsSync(dest)) {
          fs.mkdirSync(dest, { recursive: true });
        }
        const entries = fs.readdirSync(src, { withFileTypes: true });
        for (const entry of entries) {
          const srcPath = path.join(src, entry.name);
          const destPath = path.join(dest, entry.name);
          if (entry.isDirectory()) {
            copyDataRecursive(srcPath, destPath);
          } else if (!fs.existsSync(destPath)) {
            // Only copy if destination doesn't exist (preserve user data)
            fs.copyFileSync(srcPath, destPath);
          }
        }
      };
      copyDataRecursive(sourceDataPath, path.join(backendDataPath, 'data'));
      log('Initialized backend data files');
    } catch (error) {
      log('Warning: Could not copy initial data files:', error);
    }
  }

  // Start backend process
  try {
    log('Node executable:', nodeCommand);
    log('Backend run path:', backendPath);
    log('Backend run dir:', backendDir);
    log('Backend data path:', backendDataPath);
    log('Backend file exists:', fs.existsSync(backendPath));
    log('Spawning backend process...');
    
    // Set environment variables for backend
    const envVars = { 
      ...process.env, 
      AUTH_PORT: '8082',
      NODE_ENV: 'production',
      ELECTRON_APP: 'true',
      BACKEND_DATA_PATH: backendDataPath // Tell backend where to write data
    };
    
    backendProcess = spawn(nodeCommand, [backendPath], {
      env: envVars,
      cwd: backendDir,
      stdio: ['ignore', 'pipe', 'pipe']
    });

    backendProcess.stdout.on('data', (data) => {
      log(`Backend: ${data.toString().trim()}`);
    });

    backendProcess.stderr.on('data', (data) => {
      log(`Backend Error: ${data.toString().trim()}`);
    });
    
    backendProcess.on('error', (error) => {
      log('Backend process error:', error);
      log('Error details:', JSON.stringify(error, null, 2));
      
      // Show user-friendly error message
      const errorMsg = `Failed to start backend server.\n\nError: ${error.message}\n\nPossible solutions:\n1. Ensure Node.js is installed\n2. Check if port 8080 is available\n3. Try running as administrator\n\nCheck logs at: ${logPath}`;
      
      dialog.showErrorBox('Backend Startup Error', errorMsg);
    });

    backendProcess.on('exit', (code, signal) => {
      log(`Backend process exited with code ${code} and signal ${signal}`);
      if (code !== 0 && code !== null) {
        log('Backend exited unexpectedly!');
        
        // Auto-restart backend if it crashes (up to 3 times)
        if (!backendProcess._restartCount) backendProcess._restartCount = 0;
        if (backendProcess._restartCount < 3) {
          backendProcess._restartCount++;
          log(`Auto-restarting backend (attempt ${backendProcess._restartCount}/3)...`);
          setTimeout(() => {
            startBackend();
          }, 2000);
        } else {
          dialog.showErrorBox(
            'Backend Error',
            'Backend server has crashed multiple times and cannot be restarted.\n\nPlease restart the application.'
          );
        }
      }
    });

    log('Backend server started successfully');
  } catch (error) {
    log('Failed to spawn backend process:', error);
    dialog.showErrorBox(
      'Backend Startup Error', 
      'Failed to start backend server:\n\n' + error.message
    );
  }
}

// App event handlers
app.whenReady().then(() => {
  createWindow();
  createTray();
  startBackend();
  
  // Wait for backend to be ready before showing window
  if (!isDevMode && app.isPackaged) {
    setTimeout(() => {
      checkBackendHealth();
    }, 3000);
  }

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

// Check if backend is running
function checkBackendHealth() {
  const healthCheckUrl = 'http://localhost:8080/api/health';
  
  http.get(healthCheckUrl, (res) => {
    if (res.statusCode === 200) {
      log('Backend health check passed');
    } else {
      log('Backend health check failed with status:', res.statusCode);
      showBackendError();
    }
  }).on('error', (err) => {
    log('Backend health check error:', err.message);
    showBackendError();
  });
}

function showBackendError() {
  const message = `Backend server is not responding.

Please check:
1. Firewall settings (allow port 8080)
2. Antivirus software (may block the backend)
3. Check logs at: ${logPath}

You can try:
- Restarting the application
- Running as Administrator
- Temporarily disabling antivirus`;

  dialog.showMessageBox(mainWindow, {
    type: 'warning',
    title: 'Backend Connection Issue',
    message: 'Cannot connect to backend server',
    detail: message,
    buttons: ['OK', 'Open Log File', 'Restart Backend']
  }).then((result) => {
    if (result.response === 1) {
      shell.openPath(logPath);
    } else if (result.response === 2) {
      if (backendProcess) {
        backendProcess.kill();
      }
      setTimeout(() => {
        startBackend();
        setTimeout(checkBackendHealth, 3000);
      }, 1000);
    }
  });
}

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('before-quit', () => {
  app.isQuitting = true;
  
  // Close local HTTP server
  if (localServer) {
    log('Closing local server...');
    localServer.close();
    localServer = null;
  }
  
  // Kill backend process
  if (backendProcess) {
    backendProcess.kill();
  }
});

// IPC handlers with input validation
ipcMain.handle('select-file', async (event) => {
  // Validate event origin
  if (event.sender !== mainWindow.webContents) {
    log('select-file: Rejected - invalid sender');
    return [];
  }
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile'],
    filters: [
      { name: 'All Files', extensions: ['*'] },
      { name: 'Executables', extensions: ['exe', 'dll', 'sys'] }
    ]
  });
  return result.filePaths || [];
});

ipcMain.handle('select-directory', async (event) => {
  // Validate event origin
  if (event.sender !== mainWindow.webContents) {
    log('select-directory: Rejected - invalid sender');
    return [];
  }
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory']
  });
  return result.filePaths || [];
});

ipcMain.handle('show-notification', (event, { title, body }) => {
  // Validate event origin
  if (event.sender !== mainWindow.webContents) {
    log('show-notification: Rejected - invalid sender');
    return;
  }
  // Validate inputs
  if (typeof title !== 'string' || typeof body !== 'string') {
    log('show-notification: Invalid input types');
    return;
  }
  if (title.length > 100 || body.length > 500) {
    log('show-notification: Input too long');
    return;
  }
  const { Notification } = require('electron');
  new Notification({ title, body }).show();
});

ipcMain.handle('get-app-path', (event) => {
  // Validate event origin
  if (event.sender !== mainWindow.webContents) {
    log('get-app-path: Rejected - invalid sender');
    return '';
  }
  return app.getPath('userData');
});

ipcMain.handle('open-external', (event, url) => {
  // Validate event origin
  if (event.sender !== mainWindow.webContents) {
    log('open-external: Rejected - invalid sender');
    return { success: false, message: 'Invalid request origin' };
  }
  try {
    // Validate URL format
    if (typeof url !== 'string' || url.length > 2000) {
      log('open-external: Invalid URL format or too long');
      return { success: false, message: 'Invalid URL' };
    }
    // Basic whitelist - only allow known trusted hosts
    const allowedHosts = ['github.com', 'nebula-shield.com', 'docs.nebula-shield.com', 'localhost'];
    const parsed = new URL(url);
    // Only allow http/https
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      log('Blocked openExternal - invalid protocol:', parsed.protocol);
      return { success: false, message: 'Only HTTP/HTTPS URLs allowed' };
    }
    const host = parsed.hostname.replace(/^www\./, '');
    if (!allowedHosts.includes(host)) {
      log('Blocked openExternal to untrusted host:', host, url);
      return { success: false, message: 'Blocked external navigation to untrusted host' };
    }
    shell.openExternal(url);
    return { success: true };
  } catch (e) {
    log('open-external error:', e);
    return { success: false, message: 'Invalid URL' };
  }
});
