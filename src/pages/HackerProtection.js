import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  Button,
  IconButton,
  LinearProgress,
  Alert,
  AlertTitle,
  Tabs,
  Tab,
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
  Block,
  Warning,
  CheckCircle,
  Refresh,
  Security,
  Lock,
  VpnLock,
  BugReport,
  Close,
  Visibility
} from '@mui/icons-material';
import {
  getSecurityDashboard,
  getAttackLog,
  getBlockedIPs,
  unblockIP,
  getHoneypots,
  validateInput,
  checkRateLimit,
  detectBruteForce,
  detectDDoS,
  checkGeoBlock,
  analyzeUserBehavior,
  getMachineLearningInsights,
  checkThreatIntelligence,
  getIPReputation,
  detectBotnet,
  predictAttack
} from '../services/hackerProtection';

function TabPanel({ children, value, index }) {
  return (
    <div hidden={value !== index} style={{ marginTop: '20px' }}>
      {value === index && children}
    </div>
  );
}

export default function HackerProtection() {
  const [activeTab, setActiveTab] = useState(0);
  const [dashboard, setDashboard] = useState(null);
  const [loading, setLoading] = useState(true);
  const [testDialogOpen, setTestDialogOpen] = useState(false);
  const [testInput, setTestInput] = useState('');
  const [testResult, setTestResult] = useState(null);
  const [detailsDialog, setDetailsDialog] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  useEffect(() => {
    loadDashboard();
    
    const interval = autoRefresh ? setInterval(loadDashboard, 5000) : null;
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [autoRefresh]);

  const loadDashboard = () => {
    setLoading(true);
    setTimeout(() => {
      const data = getSecurityDashboard();
      setDashboard(data);
      setLoading(false);
    }, 300);
  };

  const handleUnblockIP = (ip) => {
    if (window.confirm(`Are you sure you want to unblock ${ip}?`)) {
      unblockIP(ip);
      loadDashboard();
    }
  };

  const handleTestInput = () => {
    const result = validateInput(testInput, '192.168.1.100', 'test');
    setTestResult(result);
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'Critical': return 'error';
      case 'High': return 'warning';
      case 'Medium': return 'info';
      case 'Low': return 'default';
      default: return 'default';
    }
  };

  const getStatusColor = (status) => {
    return status === 'Active' ? 'success' : 'default';
  };

  if (!dashboard) {
    return (
      <Box sx={{ p: 3 }}>
        <LinearProgress />
        <Typography sx={{ mt: 2, textAlign: 'center' }}>
          Loading Security Dashboard...
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Shield color="error" />
            Hacker Attack Protection
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Advanced protection against DDoS, brute force, injection attacks, and more
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
          <FormControlLabel
            control={
              <Switch
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
                color="primary"
              />
            }
            label="Auto-refresh"
          />
          <Button
            variant="outlined"
            startIcon={<Refresh />}
            onClick={loadDashboard}
          >
            Refresh
          </Button>
          <Button
            variant="contained"
            color="primary"
            startIcon={<BugReport />}
            onClick={() => setTestDialogOpen(true)}
          >
            Test Protection
          </Button>
        </Box>
      </Box>

      {/* Real-time Status Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)', color: 'white' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <Warning sx={{ mr: 1 }} />
                <Typography variant="h6">Active Threats</Typography>
              </Box>
              <Typography variant="h3">{dashboard.realTimeStatus.activeThreats}</Typography>
              <Typography variant="body2" sx={{ opacity: 0.9 }}>
                Last 5 minutes
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ background: 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)', color: 'white' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <Block sx={{ mr: 1 }} />
                <Typography variant="h6">Blocked IPs</Typography>
              </Box>
              <Typography variant="h3">{dashboard.realTimeStatus.blockedIPs}</Typography>
              <Typography variant="body2" sx={{ opacity: 0.9 }}>
                Currently blocked
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ background: 'linear-gradient(135deg, #fa709a 0%, #fee140 100%)', color: 'white' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <BugReport sx={{ mr: 1 }} />
                <Typography variant="h6">Honeypot Hits</Typography>
              </Box>
              <Typography variant="h3">{dashboard.realTimeStatus.honeypotHits}</Typography>
              <Typography variant="body2" sx={{ opacity: 0.9 }}>
                Attacker traps triggered
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ background: 'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)', color: 'white' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <Security sx={{ mr: 1 }} />
                <Typography variant="h6">Rate Limited</Typography>
              </Box>
              <Typography variant="h3">{dashboard.realTimeStatus.rateLimitedIPs}</Typography>
              <Typography variant="body2" sx={{ opacity: 0.9 }}>
                IPs being throttled
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ background: 'linear-gradient(135deg, #a8edea 0%, #fed6e3 100%)', color: '#333' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <VpnLock sx={{ mr: 1 }} />
                <Typography variant="h6">High Risk Users</Typography>
              </Box>
              <Typography variant="h3">{dashboard.realTimeStatus.highRiskUsers || 0}</Typography>
              <Typography variant="body2" sx={{ opacity: 0.9 }}>
                AI-detected anomalies
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ background: 'linear-gradient(135deg, #ff9a9e 0%, #fecfef 100%)', color: '#333' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <BugReport sx={{ mr: 1 }} />
                <Typography variant="h6">Botnets</Typography>
              </Box>
              <Typography variant="h3">{dashboard.realTimeStatus.detectedBotnets || 0}</Typography>
              <Typography variant="body2" sx={{ opacity: 0.9 }}>
                Detected botnets
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ background: 'linear-gradient(135deg, #fbc2eb 0%, #a6c1ee 100%)', color: '#333' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <Shield sx={{ mr: 1 }} />
                <Typography variant="h6">Threat Intel</Typography>
              </Box>
              <Typography variant="h3">{dashboard.realTimeStatus.threatIntelMatches || 0}</Typography>
              <Typography variant="body2" sx={{ opacity: 0.9 }}>
                Malicious IPs detected
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Protection Status */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <CheckCircle color="success" />
            Protection Modules Status
          </Typography>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            {Object.entries(dashboard.protectionStatus).map(([module, status]) => (
              <Grid item xs={12} sm={6} md={4} lg={3} key={module}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Chip
                    label={status}
                    color={getStatusColor(status)}
                    size="small"
                    icon={status === 'Active' ? <CheckCircle /> : <Warning />}
                  />
                  <Typography variant="body2">
                    {module.replace(/([A-Z])/g, ' $1').trim()}
                  </Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </CardContent>
      </Card>

      {/* AI/ML Insights Card */}
      {dashboard.mlInsights && (
        <Card sx={{ mb: 3, background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.1) 0%, rgba(168, 85, 247, 0.1) 100%)' }}>
          <CardContent>
            <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <VpnLock color="primary" />
              🤖 AI/ML Behavioral Analysis
            </Typography>
            <Grid container spacing={3} sx={{ mt: 1 }}>
              <Grid item xs={12} md={4}>
                <Box>
                  <Typography variant="body2" color="text.secondary">User Profiles</Typography>
                  <Typography variant="h4">{dashboard.mlInsights.totalProfiles}</Typography>
                  <Typography variant="caption">Active behavioral profiles</Typography>
                </Box>
              </Grid>
              <Grid item xs={12} md={4}>
                <Box>
                  <Typography variant="body2" color="text.secondary">High Risk Users</Typography>
                  <Typography variant="h4" color="error">{dashboard.mlInsights.highRiskUsers.length}</Typography>
                  <Typography variant="caption">Anomaly score &gt; 75</Typography>
                </Box>
              </Grid>
              <Grid item xs={12} md={4}>
                <Box>
                  <Typography variant="body2" color="text.secondary">Average Login Time</Typography>
                  <Typography variant="h4">{dashboard.mlInsights.behaviorPatterns.avgLoginTime}:00</Typography>
                  <Typography variant="caption">Typical user activity hour</Typography>
                </Box>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      )}

      {/* Threat Intelligence Card */}
      {dashboard.threatIntelligence && (
        <Card sx={{ mb: 3, background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.1) 0%, rgba(251, 146, 60, 0.1) 100%)' }}>
          <CardContent>
            <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Security color="error" />
              🌐 Advanced Threat Intelligence
            </Typography>
            <Grid container spacing={3} sx={{ mt: 1 }}>
              <Grid item xs={12} md={3}>
                <Box>
                  <Typography variant="body2" color="text.secondary">Known Threats</Typography>
                  <Typography variant="h4">{dashboard.threatIntelligence.knownThreats}</Typography>
                  <Typography variant="caption">Threat database entries</Typography>
                </Box>
              </Grid>
              <Grid item xs={12} md={3}>
                <Box>
                  <Typography variant="body2" color="text.secondary">Active Botnets</Typography>
                  <Typography variant="h4" color="error">{dashboard.threatIntelligence.botnets.length}</Typography>
                  <Typography variant="caption">Detected botnet IPs</Typography>
                </Box>
              </Grid>
              <Grid item xs={12} md={3}>
                <Box>
                  <Typography variant="body2" color="text.secondary">C2 Servers</Typography>
                  <Typography variant="h4" color="warning.main">{dashboard.threatIntelligence.c2Servers.length}</Typography>
                  <Typography variant="caption">Command & Control IPs</Typography>
                </Box>
              </Grid>
              <Grid item xs={12} md={3}>
                <Box>
                  <Typography variant="body2" color="text.secondary">Low Reputation IPs</Typography>
                  <Typography variant="h4">{dashboard.threatIntelligence.reputationCache.length}</Typography>
                  <Typography variant="caption">Score &lt; 70</Typography>
                </Box>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      )}

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
        <Tabs value={activeTab} onChange={(e, val) => setActiveTab(val)}>
          <Tab label="Attack Log" icon={<Warning />} iconPosition="start" />
          <Tab label="Blocked IPs" icon={<Block />} iconPosition="start" />
          <Tab label="Honeypots" icon={<BugReport />} iconPosition="start" />
          <Tab label="AI/ML Insights" icon={<VpnLock />} iconPosition="start" />
          <Tab label="Threat Intel" icon={<Security />} iconPosition="start" />
        </Tabs>
      </Box>

      {/* Tab 1: Attack Log */}
      <TabPanel value={activeTab} index={0}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Recent Attack Attempts (Last 24 hours)
            </Typography>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Time</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>IP Address</TableCell>
                    <TableCell>Action Taken</TableCell>
                    <TableCell>Details</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {dashboard.recentAttacks.map((attack) => (
                    <TableRow key={attack.id} hover>
                      <TableCell>{attack.timestamp}</TableCell>
                      <TableCell>
                        <Chip label={attack.type} size="small" />
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={attack.severity}
                          color={getSeverityColor(attack.severity)}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        <code>{attack.ip}</code>
                      </TableCell>
                      <TableCell>{attack.action}</TableCell>
                      <TableCell>
                        <IconButton
                          size="small"
                          onClick={() => setDetailsDialog(attack)}
                        >
                          <Visibility fontSize="small" />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        </Card>
      </TabPanel>

      {/* Tab 2: Blocked IPs */}
      <TabPanel value={activeTab} index={1}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Currently Blocked IP Addresses
            </Typography>
            {dashboard.blockedIPs.length === 0 ? (
              <Alert severity="success">
                <AlertTitle>All Clear!</AlertTitle>
                No IP addresses are currently blocked.
              </Alert>
            ) : (
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>IP Address</TableCell>
                      <TableCell>Reason</TableCell>
                      <TableCell>Blocked At</TableCell>
                      <TableCell>Expires At</TableCell>
                      <TableCell>Remaining Time</TableCell>
                      <TableCell>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {dashboard.blockedIPs.map((block) => (
                      <TableRow key={block.ip} hover>
                        <TableCell>
                          <code style={{ fontWeight: 'bold' }}>{block.ip}</code>
                        </TableCell>
                        <TableCell>{block.reason}</TableCell>
                        <TableCell>{block.blockedAt}</TableCell>
                        <TableCell>{block.expiresAt}</TableCell>
                        <TableCell>
                          <Chip
                            label={`${block.remainingMinutes} min`}
                            size="small"
                            color="warning"
                          />
                        </TableCell>
                        <TableCell>
                          <Button
                            size="small"
                            color="error"
                            startIcon={<Close />}
                            onClick={() => handleUnblockIP(block.ip)}
                          >
                            Unblock
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </CardContent>
        </Card>
      </TabPanel>

      {/* Tab 3: Honeypots */}
      <TabPanel value={activeTab} index={2}>
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Honeypot Decoy Services
            </Typography>
            <Typography variant="body2" color="text.secondary" paragraph>
              Honeypots are fake vulnerable endpoints that trap attackers. Any access triggers immediate blocking.
            </Typography>
            <Grid container spacing={2}>
              {dashboard.honeypots.map((honeypot) => (
                <Grid item xs={12} md={6} key={honeypot.id}>
                  <Card variant="outlined">
                    <CardContent>
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                        <Box>
                          <Typography variant="h6">{honeypot.name}</Typography>
                          <Typography variant="body2" color="text.secondary">
                            {honeypot.description}
                          </Typography>
                        </Box>
                        <Chip
                          label={honeypot.status}
                          color={honeypot.status === 'active' ? 'success' : 'default'}
                          size="small"
                        />
                      </Box>
                      <Divider sx={{ my: 2 }} />
                      <Grid container spacing={2}>
                        <Grid item xs={6}>
                          <Typography variant="caption" color="text.secondary">
                            Type
                          </Typography>
                          <Typography variant="body2">
                            {honeypot.type}
                          </Typography>
                        </Grid>
                        <Grid item xs={6}>
                          <Typography variant="caption" color="text.secondary">
                            Total Hits
                          </Typography>
                          <Typography variant="body2" sx={{ fontWeight: 'bold', color: honeypot.hits > 0 ? 'error.main' : 'text.primary' }}>
                            {honeypot.hits}
                          </Typography>
                        </Grid>
                        <Grid item xs={12}>
                          <Typography variant="caption" color="text.secondary">
                            Last Hit
                          </Typography>
                          <Typography variant="body2">
                            {honeypot.lastHit}
                          </Typography>
                        </Grid>
                        {honeypot.endpoint && (
                          <Grid item xs={12}>
                            <Typography variant="caption" color="text.secondary">
                              Endpoint
                            </Typography>
                            <Typography variant="body2">
                              <code>{honeypot.endpoint}</code>
                            </Typography>
                          </Grid>
                        )}
                        {honeypot.port && (
                          <Grid item xs={12}>
                            <Typography variant="caption" color="text.secondary">
                              Port
                            </Typography>
                            <Typography variant="body2">
                              <code>{honeypot.port}</code>
                            </Typography>
                          </Grid>
                        )}
                      </Grid>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </CardContent>
        </Card>
      </TabPanel>

      {/* Tab 4: Statistics */}
      <TabPanel value={activeTab} index={3}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Attacks by Type (24h)
                </Typography>
                <List>
                  {Object.entries(dashboard.attackStats.byType).map(([type, count]) => (
                    <ListItem key={type}>
                      <ListItemIcon>
                        <Warning color="error" />
                      </ListItemIcon>
                      <ListItemText
                        primary={type}
                        secondary={`${count} attacks`}
                      />
                      <Chip label={count} color="error" />
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Attacks by Severity (24h)
                </Typography>
                <List>
                  {Object.entries(dashboard.attackStats.bySeverity).map(([severity, count]) => (
                    <ListItem key={severity}>
                      <ListItemIcon>
                        <Shield color={getSeverityColor(severity)} />
                      </ListItemIcon>
                      <ListItemText
                        primary={severity}
                        secondary={`${count} attacks`}
                      />
                      <Chip label={count} color={getSeverityColor(severity)} />
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Top Attackers (24h)
                </Typography>
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>Rank</TableCell>
                        <TableCell>IP Address</TableCell>
                        <TableCell>Attack Count</TableCell>
                        <TableCell>Status</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {dashboard.attackStats.topAttackers.map((attacker, index) => (
                        <TableRow key={attacker.ip}>
                          <TableCell>#{index + 1}</TableCell>
                          <TableCell>
                            <code style={{ fontWeight: 'bold' }}>{attacker.ip}</code>
                          </TableCell>
                          <TableCell>
                            <Chip label={attacker.count} color="error" size="small" />
                          </TableCell>
                          <TableCell>
                            {dashboard.blockedIPs.find(b => b.ip === attacker.ip) ? (
                              <Chip label="Blocked" color="error" size="small" icon={<Block />} />
                            ) : (
                              <Chip label="Active" color="warning" size="small" />
                            )}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Test Protection Dialog */}
      <Dialog open={testDialogOpen} onClose={() => setTestDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Test Attack Protection</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" paragraph>
            Test the injection detection system by entering potentially malicious input below.
          </Typography>
          <TextField
            fullWidth
            multiline
            rows={4}
            label="Test Input"
            value={testInput}
            onChange={(e) => setTestInput(e.target.value)}
            placeholder="Try: SELECT * FROM users WHERE 1=1; --"
            sx={{ mb: 2 }}
          />
          <Button
            variant="contained"
            onClick={handleTestInput}
            fullWidth
          >
            Test Input
          </Button>
          {testResult && (
            <Alert
              severity={testResult.valid ? 'success' : 'error'}
              sx={{ mt: 2 }}
            >
              <AlertTitle>{testResult.valid ? 'Input Valid' : 'Attack Detected!'}</AlertTitle>
              {testResult.valid ? (
                'No malicious patterns detected.'
              ) : (
                <Box>
                  <Typography variant="body2">
                    The following threats were detected:
                  </Typography>
                  <ul>
                    {testResult.threats.map((threat, i) => (
                      <li key={i}>
                        <strong>{threat.type}</strong>
                      </li>
                    ))}
                  </ul>
                  <Typography variant="body2" sx={{ mt: 1 }}>
                    Action: <strong>{testResult.action}</strong>
                  </Typography>
                </Box>
              )}
            </Alert>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setTestDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Attack Details Dialog */}
      <Dialog
        open={!!detailsDialog}
        onClose={() => setDetailsDialog(null)}
        maxWidth="sm"
        fullWidth
      >
        {detailsDialog && (
          <>
            <DialogTitle>Attack Details</DialogTitle>
            <DialogContent>
              <List>
                <ListItem>
                  <ListItemText primary="Type" secondary={detailsDialog.type} />
                </ListItem>
                <ListItem>
                  <ListItemText primary="Severity" secondary={detailsDialog.severity} />
                </ListItem>
                <ListItem>
                  <ListItemText primary="IP Address" secondary={<code>{detailsDialog.ip}</code>} />
                </ListItem>
                <ListItem>
                  <ListItemText primary="Timestamp" secondary={detailsDialog.timestamp} />
                </ListItem>
                <ListItem>
                  <ListItemText primary="Action Taken" secondary={detailsDialog.action} />
                </ListItem>
                <ListItem>
                  <ListItemText primary="Details" secondary={detailsDialog.details} />
                </ListItem>
              </List>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setDetailsDialog(null)}>Close</Button>
            </DialogActions>
          </>
        )}
      </Dialog>
    </Box>
  );
}
