import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Paper,
  Switch,
  FormControlLabel,
  Grid,
  Card,
  CardContent,
  Chip,
  LinearProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Alert,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Tab,
  Tabs
} from '@mui/material';
import {
  Shield as ShieldIcon,
  Cloud as CloudIcon,
  Security as SecurityIcon,
  BugReport as BugIcon,
  CheckCircle as CheckIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Visibility as ViewIcon,
  Delete as DeleteIcon,
  Refresh as RefreshIcon,
  Storage as StorageIcon,
  NetworkCheck as NetworkIcon,
  FolderOpen as FolderIcon,
  Edit as EditIcon,
  Computer as ComputerIcon,
  Memory as MemoryIcon,
  Code as CodeIcon,
  VpnKey as VpnKeyIcon,
  Psychology as PsychologyIcon,
  Assessment as AssessmentIcon
} from '@mui/icons-material';
import {
  getCaptureStats,
  getCaptureHistory,
  getSessionDetails,
  setCaptureEnabled,
  clearCaptureHistory,
  getAdvancedStats,
  generateAnalysisReport,
  getMLModelInfo
} from '../services/cyberCapture';

function CyberCapture() {
  const [enabled, setEnabled] = useState(true);
  const [stats, setStats] = useState(null);
  const [advancedStats, setAdvancedStats] = useState(null);
  const [history, setHistory] = useState([]);
  const [selectedSession, setSelectedSession] = useState(null);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [mlModel, setMlModel] = useState(null);
  const [detailsTab, setDetailsTab] = useState(0);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 3000);
    return () => clearInterval(interval);
  }, []);

  const loadData = () => {
    const captureStats = getCaptureStats();
    const captureHistory = getCaptureHistory(50);
    const advStats = getAdvancedStats();
    const modelInfo = getMLModelInfo();
    
    setStats(captureStats);
    setAdvancedStats(advStats);
    setHistory(captureHistory);
    setEnabled(captureStats.enabled);
    setMlModel(modelInfo);
  };

  const handleToggleEnabled = () => {
    const newEnabled = !enabled;
    setCaptureEnabled(newEnabled);
    setEnabled(newEnabled);
  };

  const handleViewDetails = (session) => {
    const details = getSessionDetails(session.id);
    setSelectedSession(details);
    setDetailsOpen(true);
  };

  const handleClearHistory = () => {
    clearCaptureHistory();
    loadData();
  };

  const getThreatIcon = (verdict) => {
    switch (verdict) {
      case 'malicious':
        return <ErrorIcon color="error" />;
      case 'suspicious':
        return <WarningIcon color="warning" />;
      default:
        return <CheckIcon color="success" />;
    }
  };

  const getThreatColor = (verdict) => {
    switch (verdict) {
      case 'malicious':
        return 'error';
      case 'suspicious':
        return 'warning';
      default:
        return 'success';
    }
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  const formatDuration = (ms) => {
    if (!ms) return 'N/A';
    const seconds = Math.floor(ms / 1000);
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    return `${minutes}m ${seconds % 60}s`;
  };

  return (
    <Box>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
          <CloudIcon sx={{ fontSize: 40, mr: 2, color: 'primary.main' }} />
          <Box sx={{ flex: 1 }}>
            <Typography variant="h4" gutterBottom>
              CyberCapture
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Cloud-based sandbox analysis for unknown files
            </Typography>
          </Box>
          <FormControlLabel
            control={
              <Switch
                checked={enabled}
                onChange={handleToggleEnabled}
                color="primary"
              />
            }
            label={enabled ? 'Enabled' : 'Disabled'}
          />
        </Box>

        <Alert severity="info" icon={<SecurityIcon />}>
          CyberCapture automatically intercepts unknown or suspicious files and analyzes them in a secure sandbox environment before allowing execution.
        </Alert>
      </Box>

      {/* Statistics Cards */}
      {stats && (
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <StorageIcon sx={{ mr: 1, color: 'primary.main' }} />
                  <Typography variant="h6">{stats.totalAnalyzed}</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  Files Analyzed
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <ErrorIcon sx={{ mr: 1, color: 'error.main' }} />
                  <Typography variant="h6">{stats.maliciousDetected}</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  Malicious Detected
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <WarningIcon sx={{ mr: 1, color: 'warning.main' }} />
                  <Typography variant="h6">{stats.suspiciousDetected}</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  Suspicious Files
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  <ShieldIcon sx={{ mr: 1, color: 'success.main' }} />
                  <Typography variant="h6">{stats.detectionRate}%</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">
                  Detection Rate
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Active Analysis */}
      {stats && stats.activeAnalysis > 0 && (
        <Paper sx={{ p: 3, mb: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
            <BugIcon sx={{ mr: 1, color: 'info.main' }} />
            <Typography variant="h6">
              Active Sandbox Analysis ({stats.activeAnalysis})
            </Typography>
          </Box>
          <LinearProgress />
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            Analyzing files in secure sandbox environment...
          </Typography>
        </Paper>
      )}

      {/* History Table */}
      <Paper sx={{ p: 3 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
          <Typography variant="h6">
            Analysis History
          </Typography>
          <Box>
            <Tooltip title="Refresh">
              <IconButton onClick={loadData} size="small" sx={{ mr: 1 }}>
                <RefreshIcon />
              </IconButton>
            </Tooltip>
            <Tooltip title="Clear History">
              <IconButton onClick={handleClearHistory} size="small" color="error">
                <DeleteIcon />
              </IconButton>
            </Tooltip>
          </Box>
        </Box>

        {history.length === 0 ? (
          <Alert severity="info">
            No files have been analyzed yet. CyberCapture will automatically scan unknown files.
          </Alert>
        ) : (
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Status</TableCell>
                  <TableCell>File Name</TableCell>
                  <TableCell>Size</TableCell>
                  <TableCell>Analysis Time</TableCell>
                  <TableCell>Duration</TableCell>
                  <TableCell>Behaviors</TableCell>
                  <TableCell>Confidence</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {history.map((session) => (
                  <TableRow key={session.id} hover>
                    <TableCell>
                      <Chip
                        icon={getThreatIcon(session.verdict)}
                        label={session.verdict.toUpperCase()}
                        color={getThreatColor(session.verdict)}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                        {session.fileName}
                      </Typography>
                    </TableCell>
                    <TableCell>{formatBytes(session.fileSize)}</TableCell>
                    <TableCell>
                      {new Date(session.startTime).toLocaleString()}
                    </TableCell>
                    <TableCell>{formatDuration(session.duration)}</TableCell>
                    <TableCell>
                      <Chip
                        label={session.behaviorCount}
                        size="small"
                        color={session.behaviorCount > 0 ? 'warning' : 'default'}
                      />
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center' }}>
                        <Box sx={{ minWidth: 35 }}>
                          <Typography variant="body2">
                            {(session.confidence * 100).toFixed(0)}%
                          </Typography>
                        </Box>
                        <Box sx={{ width: '100%', ml: 1 }}>
                          <LinearProgress
                            variant="determinate"
                            value={session.confidence * 100}
                            color={getThreatColor(session.verdict)}
                          />
                        </Box>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Tooltip title="View Details">
                        <IconButton
                          size="small"
                          onClick={() => handleViewDetails(session)}
                        >
                          <ViewIcon />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Paper>

      {/* Details Dialog */}
      <Dialog
        open={detailsOpen}
        onClose={() => setDetailsOpen(false)}
        maxWidth="md"
        fullWidth
      >
        {selectedSession && (
          <>
            <DialogTitle>
              <Box sx={{ display: 'flex', alignItems: 'center' }}>
                {getThreatIcon(selectedSession.threat ? 'malicious' : 'clean')}
                <Typography variant="h6" sx={{ ml: 1 }}>
                  Sandbox Analysis Details
                </Typography>
              </Box>
            </DialogTitle>
            <DialogContent>
              {/* File Info */}
              <Paper sx={{ p: 2, mb: 2, bgcolor: 'background.default' }}>
                <Typography variant="subtitle2" gutterBottom>
                  File Information
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={6}>
                    <Typography variant="body2" color="text.secondary">
                      File Name
                    </Typography>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                      {selectedSession.fileName}
                    </Typography>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="body2" color="text.secondary">
                      File Size
                    </Typography>
                    <Typography variant="body2">
                      {formatBytes(selectedSession.fileSize)}
                    </Typography>
                  </Grid>
                  <Grid item xs={12}>
                    <Typography variant="body2" color="text.secondary">
                      File Hash (SHA-256)
                    </Typography>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                      {selectedSession.fileHash}
                    </Typography>
                  </Grid>
                </Grid>
              </Paper>

              {/* Threat Info */}
              {selectedSession.threat && (
                <Alert severity={selectedSession.threat.type === 'MALWARE' ? 'error' : 'warning'} sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Threat Detected: {selectedSession.threat.name}
                  </Typography>
                  <Typography variant="body2">
                    Confidence: {(selectedSession.confidence * 100).toFixed(1)}%
                  </Typography>
                  <Typography variant="body2">
                    Recommended Action: {selectedSession.threat.action.replace(/_/g, ' ').toUpperCase()}
                  </Typography>
                </Alert>
              )}

              {/* Behaviors */}
              {selectedSession.behaviors && selectedSession.behaviors.length > 0 && (
                <Paper sx={{ p: 2, mb: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Detected Behaviors ({selectedSession.behaviors.length})
                  </Typography>
                  <List dense>
                    {selectedSession.behaviors.map((behavior, index) => (
                      <ListItem key={index}>
                        <ListItemIcon>
                          {behavior.severity === 'critical' ? <ErrorIcon color="error" /> : <WarningIcon color="warning" />}
                        </ListItemIcon>
                        <ListItemText
                          primary={behavior.description}
                          secondary={`Type: ${behavior.type} | Risk: ${(behavior.risk * 100).toFixed(0)}%`}
                        />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              )}

              {/* Network Activity */}
              {selectedSession.networkActivity && selectedSession.networkActivity.length > 0 && (
                <Paper sx={{ p: 2, mb: 2 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <NetworkIcon sx={{ mr: 1 }} />
                    <Typography variant="subtitle2">
                      Network Activity ({selectedSession.networkActivity.length})
                    </Typography>
                  </Box>
                  <List dense>
                    {selectedSession.networkActivity.map((activity, index) => (
                      <ListItem key={index}>
                        <ListItemText
                          primary={`${activity.type}: ${activity.destination}:${activity.port}`}
                          secondary={`Protocol: ${activity.protocol} | Data: ${formatBytes(activity.data_sent)} | Risk: ${(activity.risk * 100).toFixed(0)}%`}
                        />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              )}

              {/* File Activity */}
              {selectedSession.fileActivity && selectedSession.fileActivity.length > 0 && (
                <Paper sx={{ p: 2, mb: 2 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <FolderIcon sx={{ mr: 1 }} />
                    <Typography variant="subtitle2">
                      File System Activity ({selectedSession.fileActivity.length})
                    </Typography>
                  </Box>
                  <List dense>
                    {selectedSession.fileActivity.map((activity, index) => (
                      <ListItem key={index}>
                        <ListItemText
                          primary={`${activity.action.toUpperCase()}: ${activity.path}`}
                          secondary={`Risk: ${(activity.risk * 100).toFixed(0)}%`}
                        />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              )}

              {/* Registry Activity */}
              {selectedSession.registryActivity && selectedSession.registryActivity.length > 0 && (
                <Paper sx={{ p: 2 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    <EditIcon sx={{ mr: 1 }} />
                    <Typography variant="subtitle2">
                      Registry Activity ({selectedSession.registryActivity.length})
                    </Typography>
                  </Box>
                  <List dense>
                    {selectedSession.registryActivity.map((activity, index) => (
                      <ListItem key={index}>
                        <ListItemText
                          primary={`${activity.action.toUpperCase()}: ${activity.key}`}
                          secondary={`Risk: ${(activity.risk * 100).toFixed(0)}%`}
                        />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              )}
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setDetailsOpen(false)}>Close</Button>
            </DialogActions>
          </>
        )}
      </Dialog>
    </Box>
  );
}

export default CyberCapture;
