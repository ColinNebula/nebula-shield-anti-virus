import React, { useState, useEffect } from 'react';
import {
  Box,
  Container,
  Grid,
  Card,
  CardContent,
  Typography,
  LinearProgress,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Alert,
  AlertTitle,
  Divider,
  IconButton,
  Tooltip,
  Switch,
  FormControlLabel,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions
} from '@mui/material';
import {
  Psychology,
  ShowChart,
  Security,
  Warning,
  TrendingUp,
  TrendingDown,
  Speed,
  Memory,
  CloudQueue,
  BubbleChart,
  Info,
  Refresh,
  Download,
  Upload,
  Settings
} from '@mui/icons-material';
import mlAnomalyDetector from '../services/mlAnomalyDetection';

const MLDashboard = () => {
  const [statistics, setStatistics] = useState(null);
  const [trends, setTrends] = useState(null);
  const [zeroDayCandidates, setZeroDayCandidates] = useState([]);
  const [autoLearn, setAutoLearn] = useState(true);
  const [explainDialogOpen, setExplainDialogOpen] = useState(false);
  const [selectedExplanation, setSelectedExplanation] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDashboardData();
    const interval = setInterval(loadDashboardData, 5000); // Refresh every 5 seconds
    return () => clearInterval(interval);
  }, []);

  const loadDashboardData = () => {
    try {
      const stats = mlAnomalyDetector.getStatistics();
      const trendData = mlAnomalyDetector.getThreatTrends(24);
      const candidates = mlAnomalyDetector.getZeroDayCandidates();
      
      setStatistics(stats);
      setTrends(trendData);
      setZeroDayCandidates(candidates);
      setLoading(false);
    } catch (error) {
      console.error('Failed to load ML dashboard data:', error);
      setLoading(false);
    }
  };

  const handleAutoLearnToggle = () => {
    mlAnomalyDetector.autoLearnEnabled = !autoLearn;
    setAutoLearn(!autoLearn);
  };

  const handleExportModels = () => {
    const modelData = mlAnomalyDetector.exportModels();
    const blob = new Blob([JSON.stringify(modelData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ml-models-${new Date().toISOString()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleImportModels = (event) => {
    const file = event.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const modelData = JSON.parse(e.target.result);
          mlAnomalyDetector.importModels(modelData);
          loadDashboardData();
          alert('Models imported successfully!');
        } catch (error) {
          alert('Failed to import models: ' + error.message);
        }
      };
      reader.readAsText(file);
    }
  };

  const handleRefresh = () => {
    setLoading(true);
    loadDashboardData();
  };

  if (loading || !statistics) {
    return (
      <Container maxWidth="xl" sx={{ mt: 4 }}>
        <Box sx={{ textAlign: 'center', py: 8 }}>
          <Psychology sx={{ fontSize: 80, color: 'primary.main', mb: 2 }} />
          <Typography variant="h5" gutterBottom>
            Loading ML Dashboard...
          </Typography>
          <LinearProgress sx={{ mt: 2, maxWidth: 400, mx: 'auto' }} />
        </Box>
      </Container>
    );
  }

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      {/* Header */}
      <Box sx={{ mb: 4, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <Psychology sx={{ fontSize: 48, color: 'primary.main' }} />
          <Box>
            <Typography variant="h4" fontWeight="bold">
              Machine Learning Detection Dashboard
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Deep Learning • Ensemble Models • Threat Intelligence
            </Typography>
          </Box>
        </Box>
        
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="Refresh Data">
            <IconButton onClick={handleRefresh} color="primary">
              <Refresh />
            </IconButton>
          </Tooltip>
          <Tooltip title="Export Models">
            <IconButton onClick={handleExportModels} color="primary">
              <Download />
            </IconButton>
          </Tooltip>
          <Tooltip title="Import Models">
            <IconButton component="label" color="primary">
              <Upload />
              <input type="file" hidden accept=".json" onChange={handleImportModels} />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>

      {/* Statistics Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} md={3}>
          <Card sx={{ background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography variant="h3" color="white" fontWeight="bold">
                    {statistics.totalDetections}
                  </Typography>
                  <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.9)' }}>
                    Total Detections
                  </Typography>
                </Box>
                <ShowChart sx={{ fontSize: 48, color: 'rgba(255,255,255,0.8)' }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card sx={{ background: 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography variant="h3" color="white" fontWeight="bold">
                    {statistics.anomalyCount}
                  </Typography>
                  <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.9)' }}>
                    Anomalies ({statistics.anomalyRate}%)
                  </Typography>
                </Box>
                <Warning sx={{ fontSize: 48, color: 'rgba(255,255,255,0.8)' }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card sx={{ background: 'linear-gradient(135deg, #fa709a 0%, #fee140 100%)' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography variant="h3" color="white" fontWeight="bold">
                    {statistics.zeroDayCount}
                  </Typography>
                  <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.9)' }}>
                    Zero-Day Candidates
                  </Typography>
                </Box>
                <Security sx={{ fontSize: 48, color: 'rgba(255,255,255,0.8)' }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card sx={{ background: 'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box>
                  <Typography variant="h3" color="white" fontWeight="bold">
                    {(parseFloat(statistics.avgConfidence) * 100).toFixed(0)}%
                  </Typography>
                  <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.9)' }}>
                    Avg Confidence
                  </Typography>
                </Box>
                <Speed sx={{ fontSize: 48, color: 'rgba(255,255,255,0.8)' }} />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Model Status */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} lg={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Psychology /> Active ML Models
              </Typography>
              <Divider sx={{ my: 2 }} />
              
              <Grid container spacing={2}>
                {/* Statistical Models */}
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" color="primary" gutterBottom>
                    Statistical Models
                  </Typography>
                  {Object.entries({
                    'Network Analysis': statistics.modelsStatus.network,
                    'Process Analysis': statistics.modelsStatus.process,
                    'Behavior Analysis': statistics.modelsStatus.behavior
                  }).map(([name, trained]) => (
                    <Box key={name} sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', py: 0.5 }}>
                      <Typography variant="body2">{name}</Typography>
                      <Chip
                        label={trained ? 'TRAINED' : 'NOT TRAINED'}
                        color={trained ? 'success' : 'default'}
                        size="small"
                      />
                    </Box>
                  ))}
                </Grid>

                {/* Traditional ML */}
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" color="primary" gutterBottom>
                    Traditional ML
                  </Typography>
                  {Object.entries({
                    'Isolation Forest': statistics.modelsStatus.isolationForest,
                    'Random Forest': statistics.modelsStatus.randomForest,
                    'Gradient Boosting': statistics.modelsStatus.gradientBoosting,
                    'Temporal Analysis': statistics.modelsStatus.temporal
                  }).map(([name, trained]) => (
                    <Box key={name} sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', py: 0.5 }}>
                      <Typography variant="body2">{name}</Typography>
                      <Chip
                        label={trained ? 'TRAINED' : 'NOT TRAINED'}
                        color={trained ? 'success' : 'default'}
                        size="small"
                      />
                    </Box>
                  ))}
                </Grid>

                {/* Deep Learning */}
                <Grid item xs={12}>
                  <Typography variant="subtitle2" color="secondary" gutterBottom sx={{ mt: 1 }}>
                    🧠 Deep Learning Models
                  </Typography>
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={4}>
                      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', py: 0.5 }}>
                        <Typography variant="body2">Deep Neural Network</Typography>
                        <Chip
                          label={statistics.modelsStatus.deepNN ? 'TRAINED' : 'NOT TRAINED'}
                          color={statistics.modelsStatus.deepNN ? 'success' : 'default'}
                          size="small"
                        />
                      </Box>
                      <Typography variant="caption" color="text.secondary">
                        {statistics.advancedFeatures.deepNNArchitecture}
                      </Typography>
                    </Grid>
                    <Grid item xs={12} md={4}>
                      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', py: 0.5 }}>
                        <Typography variant="body2">AutoEncoder</Typography>
                        <Chip
                          label={statistics.modelsStatus.autoEncoder ? 'TRAINED' : 'NOT TRAINED'}
                          color={statistics.modelsStatus.autoEncoder ? 'success' : 'default'}
                          size="small"
                        />
                      </Box>
                      <Typography variant="caption" color="text.secondary">
                        {statistics.advancedFeatures.autoEncoderCompression}
                      </Typography>
                    </Grid>
                    <Grid item xs={12} md={4}>
                      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', py: 0.5 }}>
                        <Typography variant="body2">LSTM Network</Typography>
                        <Chip
                          label={statistics.modelsStatus.lstm ? 'TRAINED' : 'NOT TRAINED'}
                          color={statistics.modelsStatus.lstm ? 'success' : 'default'}
                          size="small"
                        />
                      </Box>
                      <Typography variant="caption" color="text.secondary">
                        {statistics.advancedFeatures.lstmArchitecture}
                      </Typography>
                    </Grid>
                  </Grid>
                </Grid>
              </Grid>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} lg={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Settings /> Configuration
              </Typography>
              <Divider sx={{ my: 2 }} />
              
              <FormControlLabel
                control={<Switch checked={autoLearn} onChange={handleAutoLearnToggle} />}
                label="Auto-Learning Enabled"
              />
              <Typography variant="caption" color="text.secondary" display="block" sx={{ ml: 4, mb: 2 }}>
                Automatically adapt to reduce false positives
              </Typography>

              <Typography variant="body2" gutterBottom>
                <strong>Ensemble Strategy:</strong> {statistics.advancedFeatures.ensembleVoting}
              </Typography>
              
              <Box sx={{ mt: 2 }}>
                <Typography variant="body2" color="text.secondary">
                  Data Samples: {statistics.advancedFeatures.recentSamplesCount}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Event Sequences: {statistics.advancedFeatures.eventSequencesCount}
                </Typography>
              </Box>

              <Divider sx={{ my: 2 }} />
              
              <Typography variant="subtitle2" gutterBottom>
                Threat Intelligence
              </Typography>
              <Typography variant="body2" color="text.secondary">
                IOCs: {statistics.threatIntelligence.iocCount}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Known Patterns: {statistics.threatIntelligence.knownPatterns}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Model Performance */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <TrendingUp /> Model Performance Metrics
              </Typography>
              <Divider sx={{ my: 2 }} />
              
              <Grid container spacing={2}>
                {Object.entries(statistics.modelPerformance).map(([model, metrics]) => (
                  <Grid item xs={12} sm={6} md={3} key={model}>
                    <Box sx={{ p: 2, border: '1px solid', borderColor: 'divider', borderRadius: 1 }}>
                      <Typography variant="subtitle2" gutterBottom>
                        {model.replace(/([A-Z])/g, ' $1').trim()}
                      </Typography>
                      <Typography variant="h6" color="primary">
                        {(metrics.accuracy * 100).toFixed(1)}%
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        Detections: {metrics.detections}
                      </Typography>
                      <LinearProgress
                        variant="determinate"
                        value={metrics.accuracy * 100}
                        sx={{ mt: 1 }}
                      />
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Zero-Day Candidates */}
      {zeroDayCandidates.length > 0 && (
        <Card sx={{ mb: 4 }}>
          <CardContent>
            <Alert severity="error" sx={{ mb: 2 }}>
              <AlertTitle>🚨 Zero-Day Exploit Candidates Detected</AlertTitle>
              High-confidence anomalies that may represent previously unknown threats
            </Alert>

            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Timestamp</TableCell>
                    <TableCell>Ensemble Score</TableCell>
                    <TableCell>Zero-Day Score</TableCell>
                    <TableCell>Models Detected</TableCell>
                    <TableCell>Action</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {zeroDayCandidates.slice(0, 10).map((candidate, idx) => (
                    <TableRow key={idx}>
                      <TableCell>
                        {new Date(candidate.timestamp).toLocaleString()}
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={candidate.ensembleScore.toFixed(3)}
                          color="error"
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        <LinearProgress
                          variant="determinate"
                          value={candidate.zeroDayScore * 100}
                          color="error"
                          sx={{ height: 8, borderRadius: 4 }}
                        />
                      </TableCell>
                      <TableCell>
                        {candidate.results.length} models
                      </TableCell>
                      <TableCell>
                        <Button size="small" variant="outlined" startIcon={<Info />}>
                          Details
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        </Card>
      )}

      {/* Threat Trends */}
      {trends && trends.timeline.length > 0 && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <ShowChart /> Threat Detection Trends (Last 24 Hours)
            </Typography>
            <Divider sx={{ my: 2 }} />
            
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>
                  Attack Vector Distribution
                </Typography>
                <Box sx={{ mt: 2 }}>
                  {Object.entries(trends.attackVectors).map(([vector, count]) => (
                    <Box key={vector} sx={{ mb: 1 }}>
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                        <Typography variant="body2">{vector}</Typography>
                        <Typography variant="body2">{count}</Typography>
                      </Box>
                      <LinearProgress
                        variant="determinate"
                        value={(count / statistics.totalDetections) * 100}
                      />
                    </Box>
                  ))}
                </Box>
              </Grid>

              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>
                  Severity Distribution
                </Typography>
                <Box sx={{ mt: 2 }}>
                  {Object.entries(trends.severityDistribution).map(([severity, count]) => (
                    <Box key={severity} sx={{ mb: 1 }}>
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                        <Typography variant="body2" sx={{ textTransform: 'capitalize' }}>
                          {severity}
                        </Typography>
                        <Typography variant="body2">{count}</Typography>
                      </Box>
                      <LinearProgress
                        variant="determinate"
                        value={(count / statistics.totalDetections) * 100}
                        color={
                          severity === 'critical' ? 'error' :
                          severity === 'high' ? 'warning' :
                          severity === 'medium' ? 'info' : 'success'
                        }
                      />
                    </Box>
                  ))}
                </Box>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      )}
    </Container>
  );
};

export default MLDashboard;
