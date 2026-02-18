/**
 * React component for Forensics & Reporting dashboard
 */

import React, { useState, useEffect } from 'react';
import {
  Shield,
  FileText,
  Download,
  Camera,
  Play,
  AlertTriangle,
  CheckCircle,
  Activity,
  Database,
  Clock
} from 'lucide-react';

const ForensicsReporting = () => {
  const [incidents, setIncidents] = useState([]);
  const [pcapSessions, setPcapSessions] = useState([]);
  const [activeCapture, setActiveCapture] = useState(null);
  const [complianceReports, setComplianceReports] = useState([]);
  const [stats, setStats] = useState({
    totalIncidents: 0,
    byType: {},
    bySeverity: {},
    pcapCaptures: 0,
    reportsGenerated: 0
  });
  const [selectedIncident, setSelectedIncident] = useState(null);

  useEffect(() => {
    loadForensicsData();
    const interval = setInterval(loadForensicsData, 5000);
    return () => clearInterval(interval);
  }, []);

  const loadForensicsData = async () => {
    try {
      const response = await fetch('/api/forensics/stats');
      const data = await response.json();
      setStats(data.stats);
      setIncidents(data.incidents.slice(0, 50)); // Last 50 incidents
      setPcapSessions(data.pcapSessions);
      setActiveCapture(data.activeCapture);
    } catch (error) {
      console.error('Failed to load forensics data:', error);
    }
  };

  const startPCAPCapture = async () => {
    try {
      const response = await fetch('/api/forensics/pcap/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          interface: 'all',
          maxDuration: 3600000,
          maxSize: 100 * 1024 * 1024
        })
      });
      const capture = await response.json();
      setActiveCapture(capture);
    } catch (error) {
      console.error('Failed to start PCAP capture:', error);
    }
  };

  const stopPCAPCapture = async () => {
    try {
      const response = await fetch('/api/forensics/pcap/stop', {
        method: 'POST'
      });
      const session = await response.json();
      setActiveCapture(null);
      setPcapSessions([session, ...pcapSessions]);
    } catch (error) {
      console.error('Failed to stop PCAP capture:', error);
    }
  };

  const replayAttack = async (incidentId) => {
    try {
      const response = await fetch(`/api/forensics/replay/${incidentId}`, {
        method: 'POST'
      });
      const replay = await response.json();
      setSelectedIncident({ ...incidents.find(i => i.id === incidentId), replay });
    } catch (error) {
      console.error('Failed to replay attack:', error);
    }
  };

  const generateComplianceReport = async (standard) => {
    try {
      const response = await fetch('/api/forensics/compliance', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ standard })
      });
      const report = await response.json();
      setComplianceReports([report, ...complianceReports]);
    } catch (error) {
      console.error('Failed to generate compliance report:', error);
    }
  };

  const exportToSIEM = async (format) => {
    try {
      const response = await fetch('/api/forensics/siem/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ format })
      });
      const result = await response.json();
      
      // Download file
      const blob = await fetch(result.file).then(r => r.blob());
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `siem_export_${format}_${Date.now()}.log`;
      a.click();
    } catch (error) {
      console.error('Failed to export to SIEM:', error);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'text-red-600 bg-red-100',
      high: 'text-orange-600 bg-orange-100',
      medium: 'text-yellow-600 bg-yellow-100',
      low: 'text-blue-600 bg-blue-100',
      info: 'text-gray-600 bg-gray-100'
    };
    return colors[severity] || colors.info;
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 flex items-center gap-2">
            <FileText className="text-blue-600" />
            Forensics & Reporting
          </h1>
          <p className="text-gray-600 mt-1">
            Advanced security analysis and compliance reporting
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => generateComplianceReport('SOC2')}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
          >
            Generate Report
          </button>
          <button
            onClick={() => exportToSIEM('CEF')}
            className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700"
          >
            Export to SIEM
          </button>
        </div>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white p-6 rounded-lg shadow-md">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-600 text-sm">Total Incidents</p>
              <p className="text-3xl font-bold text-gray-900">{stats.totalIncidents}</p>
            </div>
            <AlertTriangle className="text-red-600" size={32} />
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg shadow-md">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-600 text-sm">PCAP Captures</p>
              <p className="text-3xl font-bold text-gray-900">{stats.pcapCaptures}</p>
            </div>
            <Camera className="text-blue-600" size={32} />
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg shadow-md">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-600 text-sm">Reports Generated</p>
              <p className="text-3xl font-bold text-gray-900">{stats.reportsGenerated}</p>
            </div>
            <FileText className="text-green-600" size={32} />
          </div>
        </div>

        <div className="bg-white p-6 rounded-lg shadow-md">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-600 text-sm">Active Capture</p>
              <p className="text-3xl font-bold text-gray-900">
                {activeCapture ? '1' : '0'}
              </p>
            </div>
            <Activity className={activeCapture ? 'text-green-600' : 'text-gray-400'} size={32} />
          </div>
        </div>
      </div>

      {/* PCAP Capture Control */}
      <div className="bg-white p-6 rounded-lg shadow-md">
        <h2 className="text-xl font-bold text-gray-900 mb-4 flex items-center gap-2">
          <Camera className="text-blue-600" />
          Network Packet Capture
        </h2>
        
        {activeCapture ? (
          <div className="space-y-4">
            <div className="flex items-center gap-4 p-4 bg-green-50 rounded-lg">
              <Activity className="text-green-600 animate-pulse" size={24} />
              <div className="flex-1">
                <p className="font-semibold text-gray-900">Capture in Progress</p>
                <p className="text-sm text-gray-600">
                  Started: {new Date(activeCapture.startTime).toLocaleString()}
                </p>
                <p className="text-sm text-gray-600">
                  File: {activeCapture.file}
                </p>
              </div>
              <button
                onClick={stopPCAPCapture}
                className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700"
              >
                Stop Capture
              </button>
            </div>
          </div>
        ) : (
          <button
            onClick={startPCAPCapture}
            className="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 flex items-center gap-2"
          >
            <Camera size={20} />
            Start PCAP Capture
          </button>
        )}
      </div>

      {/* Recent Incidents */}
      <div className="bg-white p-6 rounded-lg shadow-md">
        <h2 className="text-xl font-bold text-gray-900 mb-4 flex items-center gap-2">
          <Shield className="text-blue-600" />
          Recent Security Incidents
        </h2>
        
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b">
                <th className="text-left py-3 px-4">ID</th>
                <th className="text-left py-3 px-4">Time</th>
                <th className="text-left py-3 px-4">Type</th>
                <th className="text-left py-3 px-4">Severity</th>
                <th className="text-left py-3 px-4">Source</th>
                <th className="text-left py-3 px-4">Action</th>
                <th className="text-left py-3 px-4">Operations</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map((incident) => (
                <tr key={incident.id} className="border-b hover:bg-gray-50">
                  <td className="py-3 px-4 font-mono text-sm">{incident.id}</td>
                  <td className="py-3 px-4 text-sm">
                    {new Date(incident.timestamp).toLocaleString()}
                  </td>
                  <td className="py-3 px-4">
                    <span className="text-sm font-medium">{incident.type}</span>
                  </td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-1 rounded text-xs font-semibold ${getSeverityColor(incident.severity)}`}>
                      {incident.severity.toUpperCase()}
                    </span>
                  </td>
                  <td className="py-3 px-4 font-mono text-sm">{incident.source?.ip}</td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-1 rounded text-xs font-semibold ${
                      incident.action === 'BLOCKED' ? 'text-green-600 bg-green-100' : 'text-red-600 bg-red-100'
                    }`}>
                      {incident.action}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <button
                      onClick={() => replayAttack(incident.id)}
                      className="text-blue-600 hover:text-blue-800 flex items-center gap-1"
                      title="Replay Attack"
                    >
                      <Play size={16} />
                      Replay
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Compliance Reports */}
      <div className="bg-white p-6 rounded-lg shadow-md">
        <h2 className="text-xl font-bold text-gray-900 mb-4 flex items-center gap-2">
          <CheckCircle className="text-green-600" />
          Compliance Reports
        </h2>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          {['SOC2', 'PCI-DSS', 'HIPAA', 'GDPR', 'ISO27001'].map((standard) => (
            <button
              key={standard}
              onClick={() => generateComplianceReport(standard)}
              className="p-4 border-2 border-gray-300 rounded-lg hover:border-blue-600 hover:bg-blue-50 transition-colors"
            >
              <p className="font-semibold text-gray-900">{standard}</p>
              <p className="text-sm text-gray-600">Generate Report</p>
            </button>
          ))}
        </div>

        {complianceReports.length > 0 && (
          <div className="space-y-2">
            <h3 className="font-semibold text-gray-900">Recent Reports</h3>
            {complianceReports.map((report, index) => (
              <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded">
                <div>
                  <p className="font-medium">{report.standard}</p>
                  <p className="text-sm text-gray-600">
                    Generated: {new Date(report.generatedAt).toLocaleString()}
                  </p>
                </div>
                <button className="text-blue-600 hover:text-blue-800">
                  <Download size={20} />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* SIEM Export */}
      <div className="bg-white p-6 rounded-lg shadow-md">
        <h2 className="text-xl font-bold text-gray-900 mb-4 flex items-center gap-2">
          <Database className="text-purple-600" />
          SIEM Integration
        </h2>
        
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {['CEF', 'LEEF', 'JSON', 'Syslog', 'Splunk', 'QRadar'].map((format) => (
            <button
              key={format}
              onClick={() => exportToSIEM(format)}
              className="p-3 border-2 border-gray-300 rounded-lg hover:border-purple-600 hover:bg-purple-50 transition-colors text-center"
            >
              <p className="font-semibold text-gray-900">{format}</p>
              <p className="text-xs text-gray-600">Export</p>
            </button>
          ))}
        </div>
      </div>

      {/* Attack Replay Modal */}
      {selectedIncident?.replay && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-auto">
            <div className="p-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-2xl font-bold text-gray-900">Attack Replay Analysis</h2>
                <button
                  onClick={() => setSelectedIncident(null)}
                  className="text-gray-600 hover:text-gray-900"
                >
                  ×
                </button>
              </div>

              <div className="space-y-4">
                <div className="p-4 bg-blue-50 rounded-lg">
                  <p className="font-semibold text-gray-900">Incident ID: {selectedIncident.id}</p>
                  <p className="text-sm text-gray-600">Type: {selectedIncident.type}</p>
                  <p className="text-sm text-gray-600">
                    Original Time: {new Date(selectedIncident.timestamp).toLocaleString()}
                  </p>
                </div>

                <div>
                  <h3 className="font-semibold text-gray-900 mb-2">Attack Vector Analysis</h3>
                  <div className="p-4 bg-gray-50 rounded-lg space-y-2">
                    <p><strong>Vulnerability:</strong> {selectedIncident.replay.analysis.vulnerability}</p>
                    <p><strong>Attack Vector:</strong> {selectedIncident.replay.analysis.attackVector}</p>
                    <p><strong>Impact:</strong> {selectedIncident.replay.analysis.impact}</p>
                  </div>
                </div>

                <div>
                  <h3 className="font-semibold text-gray-900 mb-2">Recommendations</h3>
                  <ul className="list-disc list-inside space-y-1">
                    {selectedIncident.replay.analysis.recommendations.map((rec, index) => (
                      <li key={index} className="text-gray-700">{rec}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ForensicsReporting;
