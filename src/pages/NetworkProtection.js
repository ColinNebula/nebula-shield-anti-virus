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
  Grid,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Switch,
  FormControlLabel,
  Tabs,
  Tab,
  Badge
} from '@mui/material';
import {
  Refresh as RefreshIcon,
  Block as BlockIcon,
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Add as AddIcon,
  Delete as DeleteIcon,
  Edit as EditIcon,
  Shield as ShieldIcon,
  NetworkCheck as NetworkCheckIcon,
  Security as SecurityIcon,
  Public as PublicIcon,
  Computer as ComputerIcon,
  Speed as SpeedIcon
} from '@mui/icons-material';
import {
  getActiveConnections,
  scanOpenPorts,
  getFirewallRules,
  addFirewallRule,
  updateFirewallRule,
  deleteFirewallRule,
  applySecurityProfile,
  blockIP,
  getNetworkStats
} from '../services/networkProtection';

const NetworkProtection = () => {
  const [activeTab, setActiveTab] = useState(0);
  const [loading, setLoading] = useState(false);
  const [connections, setConnections] = useState(null);
  const [openPorts, setOpenPorts] = useState(null);
  const [firewallRules, setFirewallRules] = useState(null);
  const [networkStats, setNetworkStats] = useState(null);
  const [showAddRuleDialog, setShowAddRuleDialog] = useState(false);
  const [showBlockIPDialog, setShowBlockIPDialog] = useState(false);
  const [selectedConnection, setSelectedConnection] = useState(null);
  const [newRule, setNewRule] = useState({
    name: '',
    direction: 'outbound',
    action: 'block',
    protocol: 'TCP',
    ports: '',
    description: ''
  });
  const [ipToBlock, setIpToBlock] = useState('');
  const [blockReason, setBlockReason] = useState('');

  useEffect(() => {
    loadAllData();
    const interval = setInterval(loadAllData, 10000); // Refresh every 10 seconds
    return () => clearInterval(interval);
  }, []);

  const loadAllData = async () => {
    const [connData, statsData, rulesData] = await Promise.all([
      getActiveConnections(),
      getNetworkStats(),
      getFirewallRules()
    ]);
    
    if (connData.success) setConnections(connData);
    if (statsData.success) setNetworkStats(statsData);
    if (rulesData.success) setFirewallRules(rulesData);
  };

  const handleScanPorts = async () => {
    setLoading(true);
    const result = await scanOpenPorts();
    if (result.success) {
      setOpenPorts(result);
    }
    setLoading(false);
  };

  const handleApplyProfile = async (profile) => {
    setLoading(true);
    const result = await applySecurityProfile(profile);
    if (result.success) {
      setFirewallRules(result);
      alert(`${profile} security profile applied!`);
    }
    setLoading(false);
    await loadAllData();
  };

  const handleBlockIP = async () => {
    if (!ipToBlock) return;
    
    const result = await blockIP(ipToBlock, blockReason);
    if (result.success) {
      setShowBlockIPDialog(false);
      setIpToBlock('');
      setBlockReason('');
      await loadAllData();
      alert(`IP ${ipToBlock} has been blocked!`);
    }
  };

  const handleAddRule = async () => {
    const ports = newRule.ports.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p));
    
    const result = await addFirewallRule({
      ...newRule,
      ports: ports.length > 0 ? ports : ['*'],
      ips: ['*']
    });
    
    if (result.success) {
      setShowAddRuleDialog(false);
      setNewRule({
        name: '',
        direction: 'outbound',
        action: 'block',
        protocol: 'TCP',
        ports: '',
        description: ''
      });
      await loadAllData();
      alert('Firewall rule added successfully!');
    }
  };

  const handleToggleRule = async (ruleId, enabled) => {
    await updateFirewallRule(ruleId, { enabled });
    await loadAllData();
  };

  const handleDeleteRule = async (ruleId) => {
    if (window.confirm('Are you sure you want to delete this rule?')) {
      await deleteFirewallRule(ruleId);
      await loadAllData();
    }
  };

  const getThreatColor = (level) => {
    switch (level) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      default: return 'default';
    }
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
  };

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <ShieldIcon fontSize="large" color="primary" />
            Network Protection
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Real-time network monitoring and firewall management
          </Typography>
        </Box>
        <Button
          variant="contained"
          startIcon={<RefreshIcon />}
          onClick={loadAllData}
          disabled={loading}
        >
          Refresh
        </Button>
      </Box>

      {/* Summary Cards */}
      {connections && networkStats && (
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography variant="h4" color="primary">
                      {connections.summary.established}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Active Connections
                    </Typography>
                  </Box>
                  <NetworkCheckIcon fontSize="large" color="primary" />
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
                      {connections.summary.threats}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Threats Detected
                    </Typography>
                  </Box>
                  <ErrorIcon fontSize="large" color="error" />
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
                      {networkStats.stats.packetsBlocked}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Packets Blocked
                    </Typography>
                  </Box>
                  <BlockIcon fontSize="large" color="success" />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <Box>
                    <Typography variant="h4" color="info.main">
                      {networkStats.stats.bandwidthUsage.current.toFixed(1)} Mbps
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Bandwidth Usage
                    </Typography>
                  </Box>
                  <SpeedIcon fontSize="large" color="info" />
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs value={activeTab} onChange={(e, v) => setActiveTab(v)}>
          <Tab 
            label={
              <Badge badgeContent={connections?.summary.threats || 0} color="error">
                Active Connections
              </Badge>
            } 
          />
          <Tab label="Open Ports" />
          <Tab label="Firewall Rules" />
          <Tab label="Security Profiles" />
        </Tabs>
      </Paper>

      {/* Active Connections Tab */}
      {activeTab === 0 && (
        <Box>
          {connections?.summary.threats > 0 && (
            <Alert severity="error" sx={{ mb: 2 }} icon={<SecurityIcon />}>
              <Typography variant="subtitle2">
                <strong>⚠️ {connections.summary.threats} suspicious connection(s) detected!</strong>
              </Typography>
              <Typography variant="body2">
                Review the connections below and block suspicious IPs if necessary.
              </Typography>
            </Alert>
          )}

          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow sx={{ bgcolor: '#f5f5f5' }}>
                  <TableCell><strong>Status</strong></TableCell>
                  <TableCell><strong>Process</strong></TableCell>
                  <TableCell><strong>Protocol</strong></TableCell>
                  <TableCell><strong>Local Address</strong></TableCell>
                  <TableCell><strong>Remote Address</strong></TableCell>
                  <TableCell><strong>Location</strong></TableCell>
                  <TableCell><strong>Traffic</strong></TableCell>
                  <TableCell align="center"><strong>Actions</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {connections?.connections.map((conn) => (
                  <TableRow 
                    key={conn.id} 
                    hover
                    sx={{ bgcolor: conn.threat ? 'rgba(255, 0, 0, 0.05)' : 'inherit' }}
                  >
                    <TableCell>
                      {conn.threat ? (
                        <Tooltip title={conn.threat.description}>
                          <Chip
                            icon={<ErrorIcon />}
                            label={conn.threat.type}
                            color={getThreatColor(conn.threat.level)}
                            size="small"
                          />
                        </Tooltip>
                      ) : (
                        <Chip
                          icon={<CheckCircleIcon />}
                          label={conn.state}
                          color="success"
                          size="small"
                          variant="outlined"
                        />
                      )}
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">{conn.process}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        PID: {conn.pid}
                      </Typography>
                    </TableCell>
                    <TableCell>{conn.protocol}</TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                        {conn.localAddress}:{conn.localPort}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                        {conn.remoteAddress}:{conn.remotePort}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      {conn.geo && (
                        <Box>
                          <Typography variant="body2">
                            {conn.geo.flag} {conn.geo.country}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {conn.geo.org}
                          </Typography>
                        </Box>
                      )}
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption" display="block">
                        ↑ {formatBytes(conn.bandwidth.sent)}
                      </Typography>
                      <Typography variant="caption" display="block">
                        ↓ {formatBytes(conn.bandwidth.received)}
                      </Typography>
                    </TableCell>
                    <TableCell align="center">
                      {conn.threat && conn.remoteAddress !== '*' && (
                        <Tooltip title="Block this IP">
                          <IconButton
                            color="error"
                            size="small"
                            onClick={() => {
                              setIpToBlock(conn.remoteAddress);
                              setBlockReason(conn.threat.description);
                              setShowBlockIPDialog(true);
                            }}
                          >
                            <BlockIcon />
                          </IconButton>
                        </Tooltip>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Box>
      )}

      {/* Open Ports Tab */}
      {activeTab === 1 && (
        <Box>
          <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Typography variant="h6">Port Scan Results</Typography>
            <Button
              variant="contained"
              startIcon={<NetworkCheckIcon />}
              onClick={handleScanPorts}
              disabled={loading}
            >
              {loading ? 'Scanning...' : 'Scan Ports'}
            </Button>
          </Box>

          {loading && <LinearProgress sx={{ mb: 2 }} />}

          {openPorts && (
            <>
              <Alert severity="info" sx={{ mb: 2 }}>
                Found {openPorts.summary.total} open ports - 
                <strong style={{ color: '#d32f2f', marginLeft: 4 }}>{openPorts.summary.high} high risk</strong>,
                <strong style={{ color: '#ed6c02', marginLeft: 4 }}>{openPorts.summary.medium} medium risk</strong>,
                <strong style={{ color: '#0288d1', marginLeft: 4 }}>{openPorts.summary.low} low risk</strong>
              </Alert>

              <TableContainer component={Paper}>
                <Table>
                  <TableHead>
                    <TableRow sx={{ bgcolor: '#f5f5f5' }}>
                      <TableCell><strong>Port</strong></TableCell>
                      <TableCell><strong>Service</strong></TableCell>
                      <TableCell><strong>State</strong></TableCell>
                      <TableCell><strong>Process</strong></TableCell>
                      <TableCell><strong>Risk Level</strong></TableCell>
                      <TableCell><strong>Recommendation</strong></TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {openPorts.ports.map((port) => (
                      <TableRow key={port.port} hover>
                        <TableCell>
                          <Typography variant="h6" sx={{ fontFamily: 'monospace' }}>
                            {port.port}
                          </Typography>
                        </TableCell>
                        <TableCell>{port.service}</TableCell>
                        <TableCell>
                          <Chip label={port.state} size="small" color="info" variant="outlined" />
                        </TableCell>
                        <TableCell>{port.process}</TableCell>
                        <TableCell>
                          <Chip
                            label={port.risk.toUpperCase()}
                            color={
                              port.risk === 'high' ? 'error' :
                              port.risk === 'medium' ? 'warning' : 'success'
                            }
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">{port.recommendation}</Typography>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </>
          )}

          {!openPorts && !loading && (
            <Card>
              <CardContent sx={{ textAlign: 'center', py: 5 }}>
                <NetworkCheckIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
                <Typography variant="h6" color="text.secondary">
                  Click "Scan Ports" to check for open ports on your system
                </Typography>
              </CardContent>
            </Card>
          )}
        </Box>
      )}

      {/* Firewall Rules Tab */}
      {activeTab === 2 && firewallRules && (
        <Box>
          <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <Typography variant="h6">
              Firewall Rules ({firewallRules.summary.enabled} enabled / {firewallRules.summary.total} total)
            </Typography>
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={() => setShowAddRuleDialog(true)}
            >
              Add Rule
            </Button>
          </Box>

          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow sx={{ bgcolor: '#f5f5f5' }}>
                  <TableCell><strong>Enabled</strong></TableCell>
                  <TableCell><strong>Name</strong></TableCell>
                  <TableCell><strong>Direction</strong></TableCell>
                  <TableCell><strong>Action</strong></TableCell>
                  <TableCell><strong>Protocol</strong></TableCell>
                  <TableCell><strong>Ports</strong></TableCell>
                  <TableCell><strong>Description</strong></TableCell>
                  <TableCell align="center"><strong>Actions</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {firewallRules.rules.map((rule) => (
                  <TableRow key={rule.id} hover>
                    <TableCell>
                      <Switch
                        checked={rule.enabled}
                        onChange={(e) => handleToggleRule(rule.id, e.target.checked)}
                        color="primary"
                      />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">{rule.name}</Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={rule.direction}
                        size="small"
                        variant="outlined"
                        color={rule.direction === 'inbound' ? 'warning' : 'info'}
                      />
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={rule.action}
                        size="small"
                        color={rule.action === 'block' ? 'error' : 'success'}
                      />
                    </TableCell>
                    <TableCell>{rule.protocol}</TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                        {Array.isArray(rule.ports) ? rule.ports.join(', ') : rule.ports}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" color="text.secondary">
                        {rule.description}
                      </Typography>
                    </TableCell>
                    <TableCell align="center">
                      <IconButton
                        size="small"
                        color="error"
                        onClick={() => handleDeleteRule(rule.id)}
                      >
                        <DeleteIcon />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Box>
      )}

      {/* Security Profiles Tab */}
      {activeTab === 3 && (
        <Grid container spacing={3}>
          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom color="error">
                  🛡️ Maximum Security
                </Typography>
                <Typography variant="body2" color="text.secondary" paragraph>
                  Blocks all inbound connections and allows only essential outbound traffic (web browsing).
                  Best for public Wi-Fi or high-risk environments.
                </Typography>
                <Typography variant="caption" display="block" gutterBottom>
                  • Blocks all inbound traffic
                </Typography>
                <Typography variant="caption" display="block" gutterBottom>
                  • Allows HTTP/HTTPS only
                </Typography>
                <Typography variant="caption" display="block" gutterBottom>
                  • Blocks file sharing
                </Typography>
                <Button
                  variant="contained"
                  color="error"
                  fullWidth
                  sx={{ mt: 2 }}
                  onClick={() => handleApplyProfile('maximum')}
                  disabled={loading}
                >
                  Apply Profile
                </Button>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom color="primary">
                  ⚖️ Balanced
                </Typography>
                <Typography variant="body2" color="text.secondary" paragraph>
                  Recommended for most users. Blocks common exploit ports while allowing standard services.
                </Typography>
                <Typography variant="caption" display="block" gutterBottom>
                  • Blocks SMB, RDP, Telnet
                </Typography>
                <Typography variant="caption" display="block" gutterBottom>
                  • Allows web, email, FTP
                </Typography>
                <Typography variant="caption" display="block" gutterBottom>
                  • Moderate protection
                </Typography>
                <Button
                  variant="contained"
                  color="primary"
                  fullWidth
                  sx={{ mt: 2 }}
                  onClick={() => handleApplyProfile('balanced')}
                  disabled={loading}
                >
                  Apply Profile
                </Button>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={4}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom color="success.main">
                  🎮 Gaming
                </Typography>
                <Typography variant="body2" color="text.secondary" paragraph>
                  Optimized for gaming. Opens common gaming ports and allows all outbound traffic.
                </Typography>
                <Typography variant="caption" display="block" gutterBottom>
                  • Opens Xbox/PlayStation ports
                </Typography>
                <Typography variant="caption" display="block" gutterBottom>
                  • Opens Steam ports
                </Typography>
                <Typography variant="caption" display="block" gutterBottom>
                  • All outbound allowed
                </Typography>
                <Button
                  variant="contained"
                  color="success"
                  fullWidth
                  sx={{ mt: 2 }}
                  onClick={() => handleApplyProfile('gaming')}
                  disabled={loading}
                >
                  Apply Profile
                </Button>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Add Rule Dialog */}
      <Dialog open={showAddRuleDialog} onClose={() => setShowAddRuleDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Add Firewall Rule</DialogTitle>
        <DialogContent>
          <TextField
            label="Rule Name"
            fullWidth
            margin="normal"
            value={newRule.name}
            onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
          />
          <FormControl fullWidth margin="normal">
            <InputLabel>Direction</InputLabel>
            <Select
              value={newRule.direction}
              onChange={(e) => setNewRule({ ...newRule, direction: e.target.value })}
            >
              <MenuItem value="inbound">Inbound</MenuItem>
              <MenuItem value="outbound">Outbound</MenuItem>
              <MenuItem value="both">Both</MenuItem>
            </Select>
          </FormControl>
          <FormControl fullWidth margin="normal">
            <InputLabel>Action</InputLabel>
            <Select
              value={newRule.action}
              onChange={(e) => setNewRule({ ...newRule, action: e.target.value })}
            >
              <MenuItem value="allow">Allow</MenuItem>
              <MenuItem value="block">Block</MenuItem>
            </Select>
          </FormControl>
          <FormControl fullWidth margin="normal">
            <InputLabel>Protocol</InputLabel>
            <Select
              value={newRule.protocol}
              onChange={(e) => setNewRule({ ...newRule, protocol: e.target.value })}
            >
              <MenuItem value="TCP">TCP</MenuItem>
              <MenuItem value="UDP">UDP</MenuItem>
              <MenuItem value="ICMP">ICMP</MenuItem>
            </Select>
          </FormControl>
          <TextField
            label="Ports (comma-separated, e.g., 80,443)"
            fullWidth
            margin="normal"
            value={newRule.ports}
            onChange={(e) => setNewRule({ ...newRule, ports: e.target.value })}
            helperText="Leave empty for all ports"
          />
          <TextField
            label="Description"
            fullWidth
            margin="normal"
            multiline
            rows={2}
            value={newRule.description}
            onChange={(e) => setNewRule({ ...newRule, description: e.target.value })}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowAddRuleDialog(false)}>Cancel</Button>
          <Button onClick={handleAddRule} variant="contained" color="primary">
            Add Rule
          </Button>
        </DialogActions>
      </Dialog>

      {/* Block IP Dialog */}
      <Dialog open={showBlockIPDialog} onClose={() => setShowBlockIPDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Block IP Address</DialogTitle>
        <DialogContent>
          <TextField
            label="IP Address"
            fullWidth
            margin="normal"
            value={ipToBlock}
            onChange={(e) => setIpToBlock(e.target.value)}
            placeholder="192.168.1.1"
          />
          <TextField
            label="Reason"
            fullWidth
            margin="normal"
            multiline
            rows={2}
            value={blockReason}
            onChange={(e) => setBlockReason(e.target.value)}
            placeholder="Why are you blocking this IP?"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowBlockIPDialog(false)}>Cancel</Button>
          <Button onClick={handleBlockIP} variant="contained" color="error">
            Block IP
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default NetworkProtection;
