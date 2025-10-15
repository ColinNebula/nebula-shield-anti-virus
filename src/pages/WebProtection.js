import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Alert,
  Card,
  CardContent,
  Grid,
  Chip,
  LinearProgress,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider,
  Switch,
  FormControlLabel
} from '@mui/material';
import {
  Security as SecurityIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Block as BlockIcon,
  Link as LinkIcon,
  Shield as ShieldIcon,
  Speed as SpeedIcon
} from '@mui/icons-material';
import webProtection from '../services/webProtection';
import { toast } from 'react-hot-toast';

function WebProtection() {
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [stats, setStats] = useState(null);
  const [protectionEnabled, setProtectionEnabled] = useState(true);
  const [recentScans, setRecentScans] = useState([]);

  useEffect(() => {
    loadStats();
    loadRecentScans();
  }, []);

  const loadStats = () => {
    const currentStats = webProtection.getStats();
    setStats(currentStats);
  };

  const loadRecentScans = () => {
    // Load from localStorage
    const saved = localStorage.getItem('webProtection_recentScans');
    if (saved) {
      setRecentScans(JSON.parse(saved));
    }
  };

  const saveRecentScan = (result) => {
    const updated = [result, ...recentScans].slice(0, 10); // Keep last 10
    setRecentScans(updated);
    localStorage.setItem('webProtection_recentScans', JSON.stringify(updated));
  };

  const handleScanURL = async () => {
    if (!url.trim()) {
      toast.error('Please enter a URL to scan');
      return;
    }

    setScanning(true);
    setScanResult(null);

    try {
      const result = await webProtection.scanURL(url);
      setScanResult(result);
      saveRecentScan(result);
      loadStats();

      if (result.safe) {
        toast.success('✅ URL is safe!');
      } else {
        toast.error(`⚠️ ${result.threats.length} threat(s) detected!`);
      }
    } catch (error) {
      toast.error('Scan failed: ' + error.message);
    } finally {
      setScanning(false);
    }
  };

  const handleToggleProtection = (event) => {
    const enabled = event.target.checked;
    setProtectionEnabled(enabled);
    webProtection.setEnabled(enabled);
    toast.success(enabled ? 'Web Protection Enabled' : 'Web Protection Disabled');
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  const getRiskColor = (score) => {
    if (score >= 75) return 'error';
    if (score >= 50) return 'warning';
    if (score >= 25) return 'info';
    return 'success';
  };

  return (
    <Box>
      {/* Header */}
      <Box mb={3} display="flex" justifyContent="space-between" alignItems="center">
        <Box>
          <Typography variant="h4" gutterBottom>
            <ShieldIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
            Web Protection
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Real-time URL scanning and malicious website blocking
          </Typography>
        </Box>
        <FormControlLabel
          control={
            <Switch
              checked={protectionEnabled}
              onChange={handleToggleProtection}
              color="primary"
            />
          }
          label="Protection Enabled"
        />
      </Box>

      {/* Statistics Cards */}
      {stats && (
        <Grid container spacing={3} mb={3}>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  URLs Scanned
                </Typography>
                <Typography variant="h4">{stats.scannedURLs}</Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  Threats Blocked
                </Typography>
                <Typography variant="h4" color="error">
                  {stats.blockedAttempts}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  Phishing Detected
                </Typography>
                <Typography variant="h4" color="warning.main">
                  {stats.phishingDetected}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="text.secondary" gutterBottom>
                  Malware Detected
                </Typography>
                <Typography variant="h4" color="error">
                  {stats.malwareDetected}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* URL Scanner */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          <LinkIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
          Scan URL
        </Typography>
        
        <Box display="flex" gap={2} mt={2}>
          <TextField
            fullWidth
            label="Enter URL to scan"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            disabled={scanning || !protectionEnabled}
            onKeyPress={(e) => {
              if (e.key === 'Enter') {
                handleScanURL();
              }
            }}
          />
          <Button
            variant="contained"
            onClick={handleScanURL}
            disabled={scanning || !protectionEnabled}
            sx={{ minWidth: 120 }}
          >
            {scanning ? 'Scanning...' : 'Scan URL'}
          </Button>
        </Box>

        {scanning && (
          <Box mt={2}>
            <LinearProgress />
            <Typography variant="body2" color="text.secondary" mt={1}>
              Analyzing URL for threats...
            </Typography>
          </Box>
        )}
      </Paper>

      {/* Scan Results */}
      {scanResult && (
        <Paper sx={{ p: 3, mb: 3 }}>
          <Typography variant="h6" gutterBottom>
            Scan Results
          </Typography>

          <Alert 
            severity={scanResult.safe ? 'success' : getRiskColor(scanResult.riskScore)}
            icon={scanResult.safe ? <CheckCircleIcon /> : <WarningIcon />}
            sx={{ mb: 2 }}
          >
            {scanResult.safe ? (
              <Typography variant="body1">
                <strong>✅ Safe</strong> - No threats detected
              </Typography>
            ) : (
              <Typography variant="body1">
                <strong>⚠️ Dangerous</strong> - {scanResult.threats.length} threat(s) detected
              </Typography>
            )}
          </Alert>

          <Box mb={2}>
            <Typography variant="body2" color="text.secondary" gutterBottom>
              Risk Score
            </Typography>
            <Box display="flex" alignItems="center" gap={2}>
              <Box sx={{ flexGrow: 1 }}>
                <LinearProgress
                  variant="determinate"
                  value={scanResult.riskScore}
                  color={getRiskColor(scanResult.riskScore)}
                  sx={{ height: 10, borderRadius: 5 }}
                />
              </Box>
              <Typography variant="h6" color={getRiskColor(scanResult.riskScore) + '.main'}>
                {scanResult.riskScore}/100
              </Typography>
            </Box>
          </Box>

          {scanResult.threats.length > 0 && (
            <Box>
              <Typography variant="subtitle1" gutterBottom>
                Detected Threats:
              </Typography>
              <List>
                {scanResult.threats.map((threat, index) => (
                  <ListItem key={index} sx={{ bgcolor: 'background.default', mb: 1, borderRadius: 1 }}>
                    <ListItemIcon>
                      <WarningIcon color={getSeverityColor(threat.severity)} />
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <Box display="flex" alignItems="center" gap={1}>
                          <Typography variant="body1">{threat.description}</Typography>
                          <Chip
                            label={threat.severity.toUpperCase()}
                            size="small"
                            color={getSeverityColor(threat.severity)}
                          />
                        </Box>
                      }
                      secondary={`Type: ${threat.type}`}
                    />
                  </ListItem>
                ))}
              </List>
            </Box>
          )}

          <Typography variant="caption" color="text.secondary">
            Scanned at: {new Date(scanResult.scannedAt).toLocaleString()}
          </Typography>
        </Paper>
      )}

      {/* Recent Scans */}
      {recentScans.length > 0 && (
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" gutterBottom>
            <SpeedIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
            Recent Scans
          </Typography>
          <List>
            {recentScans.map((scan, index) => (
              <React.Fragment key={index}>
                <ListItem>
                  <ListItemIcon>
                    {scan.safe ? (
                      <CheckCircleIcon color="success" />
                    ) : (
                      <BlockIcon color="error" />
                    )}
                  </ListItemIcon>
                  <ListItemText
                    primary={scan.url}
                    secondary={
                      <Box>
                        <Typography variant="caption" display="block">
                          {new Date(scan.scannedAt).toLocaleString()}
                        </Typography>
                        {!scan.safe && (
                          <Typography variant="caption" color="error">
                            {scan.threats.length} threat(s) - Risk: {scan.riskScore}/100
                          </Typography>
                        )}
                      </Box>
                    }
                  />
                </ListItem>
                {index < recentScans.length - 1 && <Divider />}
              </React.Fragment>
            ))}
          </List>
        </Paper>
      )}
    </Box>
  );
}

export default WebProtection;
