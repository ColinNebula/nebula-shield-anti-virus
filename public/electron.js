const { app, BrowserWindow, Menu, Tray, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const isDev = require('electron-is-dev');

let mainWindow;
let tray = null;
let backendProcess = null;

// Enable live reload for Electron
if (isDev) {
  require('electron-reload')(__dirname, {
    electron: path.join(__dirname, '..', 'node_modules', '.bin', 'electron'),
    hardResetMethod: 'exit'
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1024,
    minHeight: 768,
    icon: path.join(__dirname, 'favicon.ico'),
    backgroundColor: '#0a0a0f',
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      enableRemoteModule: true,
      webSecurity: !isDev,
      devTools: isDev
    },
    frame: true,
    titleBarStyle: 'default',
    show: false
  });

  // Load the app
  const startUrl = isDev
    ? 'http://localhost:3001'
    : `file://${path.join(__dirname, '../build/index.html')}`.replace(/\\/g, '/');

  mainWindow.loadURL(startUrl);

  // Show window when ready
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    if (isDev) {
      mainWindow.webContents.openDevTools();
    }
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
  const iconPath = path.join(__dirname, 'favicon.ico');
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
  if (isDev) {
    // In development, backend should be started separately
    console.log('Running in development mode - start backend separately');
    return;
  }

  // In production, start the backend server
  const { spawn } = require('child_process');
  const backendPath = path.join(process.resourcesPath, 'backend', 'mock-backend.js');
  
  backendProcess = spawn('node', [backendPath], {
    env: { ...process.env, PORT: '8080' }
  });

  backendProcess.stdout.on('data', (data) => {
    console.log(`Backend: ${data}`);
  });

  backendProcess.stderr.on('data', (data) => {
    console.error(`Backend Error: ${data}`);
  });
}

// App event handlers
app.whenReady().then(() => {
  createWindow();
  createTray();
  startBackend();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('before-quit', () => {
  app.isQuitting = true;
  if (backendProcess) {
    backendProcess.kill();
  }
});

// IPC handlers
ipcMain.handle('select-file', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile'],
    filters: [
      { name: 'All Files', extensions: ['*'] },
      { name: 'Executables', extensions: ['exe', 'dll', 'sys'] }
    ]
  });
  return result.filePaths;
});

ipcMain.handle('select-directory', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory']
  });
  return result.filePaths;
});

ipcMain.handle('show-notification', (event, { title, body }) => {
  const { Notification } = require('electron');
  new Notification({ title, body }).show();
});

ipcMain.handle('get-app-path', () => {
  return app.getPath('userData');
});

ipcMain.handle('open-external', (event, url) => {
  shell.openExternal(url);
});
