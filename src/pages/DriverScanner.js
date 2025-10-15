import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Button,
  LinearProgress,
  Alert,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  IconButton,
  Collapse,
  Grid,
  Tooltip,
  Link
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Download as DownloadIcon,
  Security as SecurityIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Shield as ShieldIcon,
  Backup as BackupIcon
} from '@mui/icons-material';
import { scanDrivers, getUpdateRecommendations, getRestorePointAdvice } from '../services/driverScanner';

const DriverScanner = () => {
  const [scanning, setScanning] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const [expandedRows, setExpandedRows] = useState(new Set());
  const [showRestoreAdvice, setShowRestoreAdvice] = useState(false);

  useEffect(() => {
    // Auto-scan on component mount
    handleScan();
  }, []);

  const handleScan = async () => {
    setScanning(true);
    setScanResults(null);
    
    try {
      const results = await scanDrivers();
      setScanResults(results);
    } catch (error) {
      console.error('Driver scan failed:', error);
    } finally {
      setScanning(false);
    }
  };

  const toggleRow = (driverId) => {
    const newExpanded = new Set(expandedRows);
    if (newExpanded.has(driverId)) {
      newExpanded.delete(driverId);
    } else {
      newExpanded.add(driverId);
    }
    setExpandedRows(newExpanded);
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'critical':
        return <ErrorIcon color="error" />;
      case 'high':
        return <WarningIcon sx={{ color: '#ff9800' }} />;
      case 'medium':
        return <InfoIcon color="info" />;
      case 'success':
        return <CheckCircleIcon color="success" />;
      default:
        return <InfoIcon />;
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical':
        return 'error';
      case 'high':
        return 'warning';
      case 'medium':
        return 'info';
      case 'success':
        return 'success';
      default:
        return 'default';
    }
  };

  const restoreAdvice = getRestorePointAdvice();
  const recommendations = scanResults ? getUpdateRecommendations(scanResults.drivers.filter(d => d.updateAvailable)) : null;

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <ShieldIcon fontSize="large" color="primary" />
            Driver Scanner
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Scan for outdated drivers and security vulnerabilities
          </Typography>
        </Box>
        <Button
          variant="contained"
          startIcon={<RefreshIcon />}
          onClick={handleScan}
          disabled={scanning}
        >
          {scanning ? 'Scanning...' : 'Scan Drivers'}
        </Button>
      </Box>

      {/* Scanning Progress */}
      {scanning && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Scanning System Drivers...
            </Typography>
            <LinearProgress />
            <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
              Detecting installed drivers and checking for updates...
            </Typography>
          </CardContent>
        </Card>
      )}

      {/* System Restore Point Advice */}
      {scanResults && scanResults.summary.critical > 0 && (
        <Alert 
          severity="warning" 
          sx={{ mb: 3 }}
          action={
            <Button color="inherit" size="small" onClick={() => setShowRestoreAdvice(!showRestoreAdvice)}>
              {showRestoreAdvice ? 'Hide' : 'Show Details'}
            </Button>
          }
          icon={<BackupIcon />}
        >
          <Typography variant="subtitle2" gutterBottom>
            <strong>Important:</strong> Create a system restore point before updating drivers
          </Typography>
          <Collapse in={showRestoreAdvice}>
            <Box sx={{ mt: 2 }}>
              <Typography variant="body2" gutterBottom>
                <strong>How to create a restore point:</strong>
              </Typography>
              <ol style={{ margin: '8px 0', paddingLeft: '20px' }}>
                {restoreAdvice.howTo.map((step, idx) => (
                  <li key={idx}>
                    <Typography variant="body2">{step}</Typography>
                  </li>
                ))}
              </ol>
              <Typography variant="body2" sx={{ mt: 1 }}>
                <strong>PowerShell command:</strong>
              </Typography>
              <Paper sx={{ p: 1, bgcolor: '#f5f5f5', fontFamily: 'monospace', fontSize: '0.85rem', mt: 0.5 }}>
                {restoreAdvice.automaticCommand}
              </Paper>
            </Box>
          </Collapse>
        </Alert>
      )}

      {/* Summary Cards */}
      {scanResults && (
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography variant="h4" color="primary">
                      {scanResults.summary.totalDrivers}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Total Drivers
                    </Typography>
                  </Box>
                  <ShieldIcon fontSize="large" color="primary" />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography variant="h4" color="success.main">
                      {scanResults.summary.upToDate}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Up to Date
                    </Typography>
                  </Box>
                  <CheckCircleIcon fontSize="large" color="success" />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography variant="h4" color="warning.main">
                      {scanResults.summary.outdated}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Updates Available
                    </Typography>
                  </Box>
                  <InfoIcon fontSize="large" color="warning" />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography variant="h4" color="error.main">
                      {scanResults.summary.critical}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Critical Updates
                    </Typography>
                  </Box>
                  <ErrorIcon fontSize="large" color="error" />
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Update Recommendations */}
      {recommendations && recommendations.priorities.length > 0 && (
        <Alert severity="info" sx={{ mb: 3 }} icon={<SecurityIcon />}>
          <Typography variant="subtitle2" gutterBottom>
            <strong>Update Recommendations:</strong>
          </Typography>
          <Typography variant="body2">
            {recommendations.immediate.length > 0 && (
              <span>🔴 <strong>{recommendations.immediate.length}</strong> critical update(s) requiring immediate attention. </span>
            )}
            {recommendations.recommended.length > 0 && (
              <span>🟠 <strong>{recommendations.recommended.length}</strong> highly recommended update(s). </span>
            )}
            {recommendations.optional.length > 0 && (
              <span>🔵 <strong>{recommendations.optional.length}</strong> optional update(s) available.</span>
            )}
          </Typography>
        </Alert>
      )}

      {/* Driver Table */}
      {scanResults && (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow sx={{ bgcolor: '#f5f5f5' }}>
                <TableCell width="40"></TableCell>
                <TableCell><strong>Driver Name</strong></TableCell>
                <TableCell><strong>Category</strong></TableCell>
                <TableCell><strong>Current Version</strong></TableCell>
                <TableCell><strong>Latest Version</strong></TableCell>
                <TableCell><strong>Status</strong></TableCell>
                <TableCell align="center"><strong>Actions</strong></TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {scanResults.drivers.map((driver) => (
                <React.Fragment key={driver.id}>
                  <TableRow hover>
                    <TableCell>
                      <IconButton
                        size="small"
                        onClick={() => toggleRow(driver.id)}
                      >
                        {expandedRows.has(driver.id) ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                      </IconButton>
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        {getSeverityIcon(driver.severity)}
                        <Box>
                          <Typography variant="body2">
                            {driver.name}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {driver.manufacturer}
                          </Typography>
                        </Box>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Chip label={driver.category} size="small" variant="outlined" />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                        {driver.currentVersion}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                        {driver.latestVersion || 'N/A'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={driver.statusText}
                        color={getSeverityColor(driver.severity)}
                        size="small"
                      />
                      {driver.vulnerabilities && driver.vulnerabilities.length > 0 && (
                        <Tooltip title={`${driver.vulnerabilities.length} security vulnerability(ies)`}>
                          <Chip
                            icon={<SecurityIcon />}
                            label="CVE"
                            color="error"
                            size="small"
                            sx={{ ml: 1 }}
                          />
                        </Tooltip>
                      )}
                    </TableCell>
                    <TableCell align="center">
                      {driver.updateAvailable && (
                        <Tooltip title="Download from official website">
                          <IconButton
                            color="primary"
                            size="small"
                            component={Link}
                            href={driver.downloadUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                          >
                            <DownloadIcon />
                          </IconButton>
                        </Tooltip>
                      )}
                    </TableCell>
                  </TableRow>

                  {/* Expanded Row Details */}
                  <TableRow>
                    <TableCell colSpan={7} sx={{ p: 0, border: 0 }}>
                      <Collapse in={expandedRows.has(driver.id)} timeout="auto" unmountOnExit>
                        <Box sx={{ p: 3, bgcolor: '#fafafa' }}>
                          <Grid container spacing={3}>
                            <Grid item xs={12} md={6}>
                              <Typography variant="subtitle2" gutterBottom>
                                Driver Information
                              </Typography>
                              <Box sx={{ pl: 2 }}>
                                <Typography variant="body2">
                                  <strong>Hardware ID:</strong> {driver.hardwareId}
                                </Typography>
                                <Typography variant="body2">
                                  <strong>Device Class:</strong> {driver.deviceClass}
                                </Typography>
                                <Typography variant="body2">
                                  <strong>Installed:</strong> {driver.installedDate}
                                </Typography>
                                {driver.releaseDate && (
                                  <Typography variant="body2">
                                    <strong>Latest Release:</strong> {driver.releaseDate}
                                  </Typography>
                                )}
                              </Box>
                            </Grid>

                            {driver.vulnerabilities && driver.vulnerabilities.length > 0 && (
                              <Grid item xs={12} md={6}>
                                <Typography variant="subtitle2" gutterBottom color="error">
                                  Security Vulnerabilities
                                </Typography>
                                {driver.vulnerabilities.map((vuln, idx) => (
                                  <Alert severity="error" key={idx} sx={{ mb: 1 }}>
                                    <Typography variant="body2">
                                      <strong>{vuln.cve}</strong> ({vuln.severity})
                                    </Typography>
                                    <Typography variant="caption">
                                      {vuln.description}
                                    </Typography>
                                    <Typography variant="caption" display="block" sx={{ mt: 1 }}>
                                      <strong>Recommendation:</strong> {vuln.recommendation}
                                    </Typography>
                                  </Alert>
                                ))}
                              </Grid>
                            )}

                            <Grid item xs={12}>
                              <Box sx={{ display: 'flex', gap: 2 }}>
                                {driver.updateAvailable && (
                                  <Button
                                    variant="contained"
                                    startIcon={<DownloadIcon />}
                                    component={Link}
                                    href={driver.downloadUrl}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    size="small"
                                  >
                                    Download Update
                                  </Button>
                                )}
                                <Button
                                  variant="outlined"
                                  component={Link}
                                  href={driver.supportUrl}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  size="small"
                                >
                                  Manufacturer Support
                                </Button>
                              </Box>
                            </Grid>
                          </Grid>
                        </Box>
                      </Collapse>
                    </TableCell>
                  </TableRow>
                </React.Fragment>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* No Results */}
      {!scanning && !scanResults && (
        <Card>
          <CardContent sx={{ textAlign: 'center', py: 5 }}>
            <ShieldIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary">
              Click "Scan Drivers" to check for outdated drivers
            </Typography>
          </CardContent>
        </Card>
      )}
    </Box>
  );
};

export default DriverScanner;
