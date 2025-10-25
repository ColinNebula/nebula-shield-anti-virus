import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  Button,
  Tabs,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  LinearProgress,
  Alert,
  AlertTitle,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Switch,
  FormControlLabel,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider
} from '@mui/material';
import {
  Shield,
  Folder,
  Database,
  Activity,
  AlertTriangle,
  Lock,
  Unlock,
  Play,
  Pause,
  RefreshCw,
  Plus,
  Trash2,
  Download,
  Upload,
  CheckCircle,
  XCircle,
  Clock
} from 'lucide-react';
import * as ransomwareService from '../services/ransomwareProtection';

function RansomwareProtection() {
  const [activeTab, setActiveTab] = useState(0);
  const [status, setStatus] = useState(null);
  const [protectedFolders, setProtectedFolders] = useState([]);
  const [honeypots, setHoneypots] = useState([]);
  const [backups, setBackups] = useState([]);
  const [activityLog, setActivityLog] = useState([]);
  const [quarantined, setQuarantined] = useState([]);
  const [scanning, setScanning] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  
  // Dialogs
  const [addFolderDialog, setAddFolderDialog] = useState(false);
  const [backupDialog, setBackupDialog] = useState(false);
  const [restoreDialog, setRestoreDialog] = useState(false);
  const [threatActionDialog, setThreatActionDialog] = useState(false);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [availableActions, setAvailableActions] = useState([]);
  const [newFolderPath, setNewFolderPath] = useState('');
  const [selectedBackup, setSelectedBackup] = useState(null);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000); // Refresh every 5 seconds
    return () => clearInterval(interval);
  }, []);

  const loadData = () => {
    setStatus(ransomwareService.getProtectionStatus());
    setProtectedFolders(ransomwareService.getProtectedFolders());
    setHoneypots(ransomwareService.getHoneypotStatus());
    setBackups(ransomwareService.getBackupSchedules());
    setActivityLog(ransomwareService.getActivityLog(20));
    setQuarantined(ransomwareService.getQuarantinedProcesses());
  };

  const handleScan = async () => {
    setScanning(true);
    setScanResults(null);
    
    setTimeout(() => {
      const results = ransomwareService.scanForRansomware();
      setScanResults(results);
      setScanning(false);
      loadData();
    }, 3000);
  };

  const handleToggleMonitoring = () => {
    ransomwareService.toggleMonitoring();
    loadData();
  };

  const handleCheckHoneypots = () => {
    ransomwareService.checkHoneypots();
    loadData();
  };

  const handleAddFolder = () => {
    if (newFolderPath.trim()) {
      ransomwareService.addProtectedFolder(newFolderPath);
      setNewFolderPath('');
      setAddFolderDialog(false);
      loadData();
    }
  };

  const handleRemoveFolder = (folderId) => {
    ransomwareService.removeProtectedFolder(folderId);
    loadData();
  };

  const handleCreateBackup = () => {
    const selectedFolders = protectedFolders.map(f => f.path);
    ransomwareService.createManualBackup(selectedFolders, {
      name: `Manual Backup - ${new Date().toLocaleString()}`,
      encrypted: true,
      compression: 'high'
    });
    setBackupDialog(false);
    loadData();
  };

  const handleRestore = () => {
    if (selectedBackup) {
      ransomwareService.restoreFromBackup(selectedBackup.id, selectedBackup.folders[0]);
      setRestoreDialog(false);
      setSelectedBackup(null);
      loadData();
    }
  };

  const handleThreatClick = (threat) => {
    setSelectedThreat(threat);
    const actions = ransomwareService.getAvailableActions(threat);
    setAvailableActions(actions);
    setThreatActionDialog(true);
  };

  const handleThreatAction = (action) => {
    if (selectedThreat) {
      const result = ransomwareService.handleThreat(selectedThreat, action);
      
      if (result.success) {
        alert(`✅ ${result.message}\n\n${result.recommendation || ''}`);
      } else {
        alert(`❌ ${result.error || 'Action failed'}\n\n${result.recommendation || ''}`);
      }
      
      setThreatActionDialog(false);
      setSelectedThreat(null);
      loadData();
    }
  };

  const handleQuarantineAll = () => {
    if (scanResults && scanResults.threats.length > 0) {
      const result = ransomwareService.handleMultipleThreats(scanResults.threats, 'quarantine');
      alert(`Quarantined ${result.successful} of ${result.total} threats`);
      setScanResults(null);
      loadData();
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'error';
      case 'high': return 'error';
      case 'medium': return 'warning';
      case 'low': return 'info';
      default: return 'default';
    }
  };

  const getStatusColor = (statusText) => {
    switch (statusText) {
      case 'protected': return 'success';
      case 'active': return 'success';
      case 'deployed': return 'success';
      case 'triggered': return 'error';
      case 'quarantined': return 'error';
      case 'in_progress': return 'info';
      default: return 'default';
    }
  };

  if (!status) {
    return (
      <Box sx={{ p: 3, textAlign: 'center' }}>
        <LinearProgress />
        <Typography sx={{ mt: 2 }}>Loading Ransomware Protection...</Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Box>
          <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Shield size={32} />
            Ransomware Protection
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Advanced protection with honeypots, behavioral monitoring, and automatic backups
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button
            variant="contained"
            startIcon={scanning ? <RefreshCw className="animate-spin" /> : <Play />}
            onClick={handleScan}
            disabled={scanning}
          >
            {scanning ? 'Scanning...' : 'Scan Now'}
          </Button>
          <Button
            variant="outlined"
            startIcon={status.monitoring ? <Pause /> : <Play />}
            onClick={handleToggleMonitoring}
            color={status.monitoring ? 'error' : 'success'}
          >
            {status.monitoring ? 'Disable' : 'Enable'} Monitoring
          </Button>
        </Box>
      </Box>

      {/* Summary Cards */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Box>
                  <Typography color="text.secondary" variant="body2">
                    Monitoring Status
                  </Typography>
                  <Typography variant="h5">
                    {status.monitoring ? 'Active' : 'Inactive'}
                  </Typography>
                </Box>
                {status.monitoring ? (
                  <CheckCircle size={40} color="#4caf50" />
                ) : (
                  <XCircle size={40} color="#f44336" />
                )}
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Box>
                  <Typography color="text.secondary" variant="body2">
                    Protected Folders
                  </Typography>
                  <Typography variant="h5">
                    {status.protectedFolders}
                  </Typography>
                </Box>
                <Folder size={40} color="#2196f3" />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Box>
                  <Typography color="text.secondary" variant="body2">
                    Honeypot Status
                  </Typography>
                  <Typography variant="h5">
                    {status.honeypots.active}/{status.honeypots.total}
                  </Typography>
                </Box>
                <AlertTriangle 
                  size={40} 
                  color={status.honeypots.triggered > 0 ? "#f44336" : "#4caf50"} 
                />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Box>
                  <Typography color="text.secondary" variant="body2">
                    Active Backups
                  </Typography>
                  <Typography variant="h5">
                    {status.backups.active}
                  </Typography>
                </Box>
                <Database size={40} color="#ff9800" />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Scan Results Alert */}
      {scanResults && (
        <Alert 
          severity={scanResults.threats.length > 0 ? 'error' : 'success'}
          sx={{ mb: 3 }}
          action={
            scanResults.threats.length > 0 && (
              <Box sx={{ display: 'flex', gap: 1 }}>
                <Button 
                  size="small" 
                  variant="contained" 
                  color="error"
                  onClick={handleQuarantineAll}
                >
                  Quarantine All
                </Button>
                <Button size="small" onClick={() => setScanResults(null)}>
                  Dismiss
                </Button>
              </Box>
            )
          }
        >
          <AlertTitle>Scan Complete</AlertTitle>
          Scanned {scanResults.scanned.toLocaleString()} files in {scanResults.duration.toFixed(1)}s - 
          Found {scanResults.threats.length} threat{scanResults.threats.length !== 1 ? 's' : ''}
          
          {scanResults.threats.length > 0 && (
            <Box sx={{ mt: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                Detected Threats:
              </Typography>
              <List dense>
                {scanResults.threats.slice(0, 5).map((threat, index) => (
                  <ListItem 
                    key={index}
                    sx={{ 
                      bgcolor: 'rgba(255,255,255,0.05)', 
                      borderRadius: 1, 
                      mb: 0.5,
                      cursor: 'pointer',
                      '&:hover': { bgcolor: 'rgba(255,255,255,0.1)' }
                    }}
                    onClick={() => handleThreatClick(threat)}
                  >
                    <ListItemText
                      primary={
                        <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>
                          {threat.file}
                        </Typography>
                      }
                      secondary={`Type: ${threat.type} | Severity: ${threat.severity}`}
                    />
                    <Button size="small" variant="outlined">
                      Take Action
                    </Button>
                  </ListItem>
                ))}
              </List>
              {scanResults.threats.length > 5 && (
                <Typography variant="caption" color="text.secondary">
                  ... and {scanResults.threats.length - 5} more
                </Typography>
              )}
            </Box>
          )}
        </Alert>
      )}

      {/* Critical Alerts */}
      {status.honeypots.triggered > 0 && (
        <Alert severity="error" sx={{ mb: 3 }}>
          <AlertTitle>⚠️ RANSOMWARE DETECTED!</AlertTitle>
          {status.honeypots.triggered} honeypot file{status.honeypots.triggered > 1 ? 's' : ''} triggered. 
          Suspicious processes have been quarantined and emergency backup initiated.
        </Alert>
      )}

      {/* Tabs */}
      <Card>
        <Tabs value={activeTab} onChange={(e, newValue) => setActiveTab(newValue)}>
          <Tab label="Protected Folders" />
          <Tab label="Honeypots" />
          <Tab label="Backups" />
          <Tab label="Activity Log" />
        </Tabs>

        {/* Tab 1: Protected Folders */}
        {activeTab === 0 && (
          <CardContent>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
              <Typography variant="h6">Protected Folders</Typography>
              <Button
                startIcon={<Plus />}
                variant="contained"
                size="small"
                onClick={() => setAddFolderDialog(true)}
              >
                Add Folder
              </Button>
            </Box>

            <TableContainer component={Paper} variant="outlined">
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Folder Path</TableCell>
                    <TableCell>Files</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Last Backup</TableCell>
                    <TableCell>Snapshots</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {protectedFolders.map((folder) => (
                    <TableRow key={folder.id}>
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Folder size={20} />
                          {folder.path}
                        </Box>
                      </TableCell>
                      <TableCell>{folder.fileCount.toLocaleString()}</TableCell>
                      <TableCell>
                        <Chip
                          label={folder.status}
                          color={getStatusColor(folder.status)}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        {new Date(folder.lastBackup).toLocaleString()}
                      </TableCell>
                      <TableCell>{folder.snapshotCount}</TableCell>
                      <TableCell>
                        <Button
                          size="small"
                          startIcon={<Trash2 size={16} />}
                          color="error"
                          onClick={() => handleRemoveFolder(folder.id)}
                        >
                          Remove
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        )}

        {/* Tab 2: Honeypots */}
        {activeTab === 1 && (
          <CardContent>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
              <Typography variant="h6">Honeypot Files</Typography>
              <Button
                startIcon={<RefreshCw />}
                variant="outlined"
                size="small"
                onClick={handleCheckHoneypots}
              >
                Check Status
              </Button>
            </Box>

            <Alert severity="info" sx={{ mb: 2 }}>
              Honeypot files are decoy files that detect ransomware by monitoring for unauthorized access.
            </Alert>

            <TableContainer component={Paper} variant="outlined">
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>File Name</TableCell>
                    <TableCell>Folder</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Last Checked</TableCell>
                    <TableCell>Accessed</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {honeypots.map((honeypot) => (
                    <TableRow 
                      key={honeypot.id}
                      sx={{ 
                        backgroundColor: honeypot.status === 'triggered' ? '#ffebee' : 'inherit'
                      }}
                    >
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          {honeypot.status === 'triggered' ? (
                            <AlertTriangle size={20} color="#f44336" />
                          ) : (
                            <Lock size={20} color="#4caf50" />
                          )}
                          {honeypot.name}
                        </Box>
                      </TableCell>
                      <TableCell>{honeypot.folder}</TableCell>
                      <TableCell>{honeypot.type}</TableCell>
                      <TableCell>
                        <Chip
                          label={honeypot.status}
                          color={getStatusColor(honeypot.status)}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        {new Date(honeypot.lastChecked).toLocaleString()}
                      </TableCell>
                      <TableCell>
                        {honeypot.accessed ? (
                          <Chip label="YES" color="error" size="small" />
                        ) : (
                          <Chip label="No" color="success" size="small" />
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        )}

        {/* Tab 3: Backups */}
        {activeTab === 2 && (
          <CardContent>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
              <Typography variant="h6">Backup Schedules</Typography>
              <Box sx={{ display: 'flex', gap: 1 }}>
                <Button
                  startIcon={<Upload />}
                  variant="contained"
                  size="small"
                  onClick={() => setBackupDialog(true)}
                >
                  Create Backup
                </Button>
                <Button
                  startIcon={<Download />}
                  variant="outlined"
                  size="small"
                  onClick={() => setRestoreDialog(true)}
                >
                  Restore
                </Button>
              </Box>
            </Box>

            <TableContainer component={Paper} variant="outlined">
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Backup Name</TableCell>
                    <TableCell>Schedule</TableCell>
                    <TableCell>Last Run</TableCell>
                    <TableCell>Next Run</TableCell>
                    <TableCell>Retention</TableCell>
                    <TableCell>Status</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {backups.map((backup) => (
                    <TableRow key={backup.id}>
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Database size={20} />
                          {backup.name}
                          {backup.encrypted && <Lock size={16} color="#4caf50" />}
                        </Box>
                      </TableCell>
                      <TableCell>{backup.schedule}</TableCell>
                      <TableCell>
                        {new Date(backup.lastRun).toLocaleString()}
                      </TableCell>
                      <TableCell>
                        {new Date(backup.nextRun).toLocaleString()}
                      </TableCell>
                      <TableCell>{backup.retentionDays} days</TableCell>
                      <TableCell>
                        <Chip
                          label={backup.status}
                          color={getStatusColor(backup.status)}
                          size="small"
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        )}

        {/* Tab 4: Activity Log */}
        {activeTab === 3 && (
          <CardContent>
            <Typography variant="h6" sx={{ mb: 2 }}>Recent Activity</Typography>

            <List>
              {activityLog.map((activity) => (
                <React.Fragment key={activity.id}>
                  <ListItem>
                    <ListItemIcon>
                      <Activity size={20} color={
                        activity.severity === 'critical' || activity.severity === 'high' ? '#f44336' :
                        activity.severity === 'medium' ? '#ff9800' : '#2196f3'
                      } />
                    </ListItemIcon>
                    <ListItemText
                      primary={activity.message}
                      secondary={
                        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', mt: 0.5 }}>
                          <Chip label={activity.type} size="small" />
                          <Chip 
                            label={activity.severity} 
                            color={getSeverityColor(activity.severity)}
                            size="small"
                          />
                          <Typography variant="caption">
                            {activity.timestampStr}
                          </Typography>
                        </Box>
                      }
                    />
                  </ListItem>
                  <Divider />
                </React.Fragment>
              ))}
            </List>
          </CardContent>
        )}
      </Card>

      {/* Add Folder Dialog */}
      <Dialog open={addFolderDialog} onClose={() => setAddFolderDialog(false)}>
        <DialogTitle>Add Protected Folder</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            margin="dense"
            label="Folder Path"
            fullWidth
            value={newFolderPath}
            onChange={(e) => setNewFolderPath(e.target.value)}
            placeholder="C:\Users\Documents"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAddFolderDialog(false)}>Cancel</Button>
          <Button onClick={handleAddFolder} variant="contained">Add</Button>
        </DialogActions>
      </Dialog>

      {/* Create Backup Dialog */}
      <Dialog open={backupDialog} onClose={() => setBackupDialog(false)}>
        <DialogTitle>Create Manual Backup</DialogTitle>
        <DialogContent>
          <Alert severity="info" sx={{ mt: 1, mb: 2 }}>
            This will create an encrypted backup of all protected folders.
          </Alert>
          <Typography variant="body2">
            Protected folders: {protectedFolders.length}
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setBackupDialog(false)}>Cancel</Button>
          <Button onClick={handleCreateBackup} variant="contained">Create Backup</Button>
        </DialogActions>
      </Dialog>

      {/* Restore Dialog */}
      <Dialog open={restoreDialog} onClose={() => setRestoreDialog(false)}>
        <DialogTitle>Restore from Backup</DialogTitle>
        <DialogContent>
          <Alert severity="warning" sx={{ mt: 1, mb: 2 }}>
            Restoring will replace current files with backup versions.
          </Alert>
          <Typography variant="body2" sx={{ mb: 2 }}>Select a backup:</Typography>
          <List>
            {backups.map((backup) => (
              <ListItem
                key={backup.id}
                button
                selected={selectedBackup?.id === backup.id}
                onClick={() => setSelectedBackup(backup)}
              >
                <ListItemIcon>
                  <Database size={20} />
                </ListItemIcon>
                <ListItemText
                  primary={backup.name}
                  secondary={`Last run: ${new Date(backup.lastRun).toLocaleString()}`}
                />
              </ListItem>
            ))}
          </List>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRestoreDialog(false)}>Cancel</Button>
          <Button 
            onClick={handleRestore} 
            variant="contained"
            disabled={!selectedBackup}
          >
            Restore
          </Button>
        </DialogActions>
      </Dialog>

      {/* Threat Action Dialog */}
      <Dialog 
        open={threatActionDialog} 
        onClose={() => setThreatActionDialog(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <AlertTriangle size={24} color="#ff9800" />
            Handle Ransomware Threat
          </Box>
        </DialogTitle>
        <DialogContent>
          {selectedThreat && (
            <>
              <Alert severity="error" sx={{ mb: 2 }}>
                <AlertTitle>Threat Detected</AlertTitle>
                <Typography variant="body2" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                  {selectedThreat.file || selectedThreat.process}
                </Typography>
                <Typography variant="caption" display="block" sx={{ mt: 1 }}>
                  Type: {selectedThreat.type} | Severity: {selectedThreat.severity}
                </Typography>
              </Alert>

              <Typography variant="subtitle2" sx={{ mb: 2 }}>
                Choose an action:
              </Typography>

              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                {availableActions.map((action) => (
                  <Button
                    key={action.id}
                    variant={action.recommended ? "contained" : "outlined"}
                    color={action.severity === 'high' ? 'error' : action.severity === 'medium' ? 'warning' : 'primary'}
                    fullWidth
                    onClick={() => handleThreatAction(action.id)}
                    sx={{ justifyContent: 'flex-start', textAlign: 'left', py: 1.5 }}
                  >
                    <Box sx={{ width: '100%' }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                        <Typography variant="button">
                          {action.label}
                        </Typography>
                        {action.recommended && (
                          <Chip label="Recommended" size="small" color="success" />
                        )}
                      </Box>
                      <Typography variant="caption" sx={{ opacity: 0.8 }}>
                        {action.description}
                      </Typography>
                    </Box>
                  </Button>
                ))}
              </Box>
            </>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setThreatActionDialog(false)}>Cancel</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

export default RansomwareProtection;
