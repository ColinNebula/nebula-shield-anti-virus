// PDF Report Generation Service
import { jsPDF } from 'jspdf';
import 'jspdf-autotable';

class PDFReportService {
  constructor() {
    this.brandColor = [138, 43, 226]; // Purple
    this.headerColor = [138, 43, 226];
    this.textColor = [31, 41, 55];
    this.lightGray = [249, 250, 251];
  }

  // Generate scan report
  async generateScanReport(scanData) {
    const doc = new jsPDF();
    
    // Debug: Check if autoTable is available
    if (typeof doc.autoTable !== 'function') {
      console.error('jspdf-autotable not loaded! doc.autoTable is:', typeof doc.autoTable);
      console.error('Available doc methods:', Object.keys(doc).filter(k => typeof doc[k] === 'function'));
      throw new Error('PDF library not initialized. Please refresh your browser (Ctrl+Shift+R)');
    }
    
    const pageWidth = doc.internal.pageSize.width;

    // Header
    this.addHeader(doc, 'NEBULA SHIELD - Scan Report');
    
    // Scan Summary
    let yPos = 40;
    doc.setFontSize(16);
    doc.setTextColor(...this.brandColor);
    doc.text('Scan Summary', 14, yPos);
    
    yPos += 10;
    doc.setFontSize(10);
    doc.setTextColor(...this.textColor);
    
    const summaryData = [
      ['Scan Date:', new Date(scanData.scanDate || Date.now()).toLocaleString()],
      ['Scan Type:', scanData.scanType || 'Quick Scan'],
      ['Files Scanned:', (scanData.filesScanned || 0).toLocaleString()],
      ['Threats Detected:', scanData.threatsDetected || 0],
      ['Scan Duration:', this.formatDuration(scanData.duration || 0)],
      ['Status:', scanData.status || 'Completed']
    ];

    doc.autoTable({
      startY: yPos,
      head: [],
      body: summaryData,
      theme: 'plain',
      styles: { fontSize: 10 },
      columnStyles: {
        0: { fontStyle: 'bold', cellWidth: 40 },
        1: { cellWidth: 'auto' }
      },
      margin: { left: 14 }
    });

    yPos = doc.lastAutoTable.finalY + 15;

    // Threats Detected
    if (scanData.threats && scanData.threats.length > 0) {
      doc.setFontSize(16);
      doc.setTextColor(...this.brandColor);
      doc.text('Detected Threats', 14, yPos);
      yPos += 10;

      const threatRows = scanData.threats.map((threat, index) => [
        index + 1,
        threat.file || threat.path || 'Unknown',
        threat.type || 'Malware',
        threat.severity || 'High',
        threat.action || 'Quarantined'
      ]);

      doc.autoTable({
        startY: yPos,
        head: [['#', 'File Path', 'Threat Type', 'Severity', 'Action']],
        body: threatRows,
        theme: 'striped',
        headStyles: { fillColor: this.headerColor, textColor: [255, 255, 255] },
        styles: { fontSize: 9, cellPadding: 3 },
        columnStyles: {
          0: { cellWidth: 10 },
          1: { cellWidth: 80 },
          2: { cellWidth: 30 },
          3: { cellWidth: 25 },
          4: { cellWidth: 30 }
        },
        margin: { left: 14, right: 14 }
      });

      yPos = doc.lastAutoTable.finalY + 15;
    } else {
      doc.setFontSize(12);
      doc.setTextColor(16, 185, 129); // Green
      doc.text('✓ No threats detected - System is clean', 14, yPos);
      yPos += 15;
    }

    // Recommendations
    this.addRecommendations(doc, yPos, scanData.threats?.length || 0);

    // Footer
    this.addFooter(doc);

    return doc;
  }

  // Generate system health report
  async generateSystemHealthReport(healthData) {
    const doc = new jsPDF();
    
    // Debug: Check if autoTable is available
    if (typeof doc.autoTable !== 'function') {
      console.error('jspdf-autotable not loaded! doc.autoTable is:', typeof doc.autoTable);
      throw new Error('PDF library not initialized. Please refresh your browser (Ctrl+Shift+R)');
    }

    // Header
    this.addHeader(doc, 'NEBULA SHIELD - System Health Report');

    let yPos = 40;

    // Overall Health Status
    doc.setFontSize(16);
    doc.setTextColor(...this.brandColor);
    doc.text('System Health Status', 14, yPos);
    yPos += 12;

    const healthScore = healthData.healthScore || 85;
    const statusColor = healthScore >= 80 ? [16, 185, 129] : healthScore >= 60 ? [245, 158, 11] : [239, 68, 68];
    
    doc.setFontSize(24);
    doc.setTextColor(...statusColor);
    doc.text(`${healthScore}%`, 14, yPos);
    doc.setFontSize(12);
    doc.setTextColor(...this.textColor);
    doc.text('Overall Health Score', 40, yPos);
    yPos += 15;

    // Protection Status
    doc.setFontSize(14);
    doc.setTextColor(...this.brandColor);
    doc.text('Protection Status', 14, yPos);
    yPos += 10;

    const protectionData = [
      ['Real-Time Protection:', healthData.realtimeProtection ? '✓ Enabled' : '✗ Disabled'],
      ['Firewall Status:', healthData.firewallStatus || 'Active'],
      ['Last Scan:', healthData.lastScan ? new Date(healthData.lastScan).toLocaleString() : 'Never'],
      ['Signature Database:', `${healthData.signatures || '0'} signatures`],
      ['Last Update:', healthData.lastUpdate ? new Date(healthData.lastUpdate).toLocaleString() : 'Never']
    ];

    doc.autoTable({
      startY: yPos,
      head: [],
      body: protectionData,
      theme: 'plain',
      styles: { fontSize: 10 },
      columnStyles: {
        0: { fontStyle: 'bold', cellWidth: 50 },
        1: { cellWidth: 'auto' }
      },
      margin: { left: 14 }
    });

    yPos = doc.lastAutoTable.finalY + 15;

    // Recent Activity
    doc.setFontSize(14);
    doc.setTextColor(...this.brandColor);
    doc.text('Recent Activity (Last 7 Days)', 14, yPos);
    yPos += 10;

    const activityData = [
      ['Scans Performed:', healthData.scansPerformed || 0],
      ['Threats Blocked:', healthData.threatsBlocked || 0],
      ['Files Quarantined:', healthData.filesQuarantined || 0],
      ['Updates Applied:', healthData.updatesApplied || 0]
    ];

    doc.autoTable({
      startY: yPos,
      head: [],
      body: activityData,
      theme: 'plain',
      styles: { fontSize: 10 },
      columnStyles: {
        0: { fontStyle: 'bold', cellWidth: 50 },
        1: { cellWidth: 'auto' }
      },
      margin: { left: 14 }
    });

    yPos = doc.lastAutoTable.finalY + 15;

    // System Resources
    if (healthData.systemResources) {
      doc.setFontSize(14);
      doc.setTextColor(...this.brandColor);
      doc.text('System Resources', 14, yPos);
      yPos += 10;

      const resourceData = [
        ['CPU Usage:', `${healthData.systemResources.cpu || 0}%`],
        ['Memory Usage:', `${healthData.systemResources.memory || 0}%`],
        ['Disk Space:', `${healthData.systemResources.disk || 0}% used`]
      ];

      doc.autoTable({
        startY: yPos,
        head: [],
        body: resourceData,
        theme: 'plain',
        styles: { fontSize: 10 },
        columnStyles: {
          0: { fontStyle: 'bold', cellWidth: 50 },
          1: { cellWidth: 'auto' }
        },
        margin: { left: 14 }
      });
    }

    // Footer
    this.addFooter(doc);

    return doc;
  }

  // Generate threat analysis report
  async generateThreatAnalysisReport(threatData) {
    const doc = new jsPDF();
    
    // Debug: Check if autoTable is available
    if (typeof doc.autoTable !== 'function') {
      console.error('jspdf-autotable not loaded! doc.autoTable is:', typeof doc.autoTable);
      throw new Error('PDF library not initialized. Please refresh your browser (Ctrl+Shift+R)');
    }

    // Header
    this.addHeader(doc, 'NEBULA SHIELD - Threat Analysis Report');

    let yPos = 40;

    // Threat Overview
    doc.setFontSize(16);
    doc.setTextColor(...this.brandColor);
    doc.text('Threat Analysis', 14, yPos);
    yPos += 12;

    const overviewData = [
      ['Report Period:', `${threatData.startDate || 'N/A'} - ${threatData.endDate || 'N/A'}`],
      ['Total Threats:', threatData.totalThreats || 0],
      ['Quarantined:', threatData.quarantined || 0],
      ['Removed:', threatData.removed || 0],
      ['Critical Threats:', threatData.critical || 0]
    ];

    doc.autoTable({
      startY: yPos,
      head: [],
      body: overviewData,
      theme: 'plain',
      styles: { fontSize: 10 },
      columnStyles: {
        0: { fontStyle: 'bold', cellWidth: 50 },
        1: { cellWidth: 'auto' }
      },
      margin: { left: 14 }
    });

    yPos = doc.lastAutoTable.finalY + 15;

    // Threat Breakdown by Type
    doc.setFontSize(14);
    doc.setTextColor(...this.brandColor);
    doc.text('Threat Distribution by Type', 14, yPos);
    yPos += 10;

    const threatTypes = threatData.threatTypes || [
      { type: 'Trojan', count: 5 },
      { type: 'Virus', count: 3 },
      { type: 'Spyware', count: 2 },
      { type: 'Adware', count: 1 }
    ];

    const typeRows = threatTypes.map(t => [t.type, t.count]);

    doc.autoTable({
      startY: yPos,
      head: [['Threat Type', 'Count']],
      body: typeRows,
      theme: 'striped',
      headStyles: { fillColor: this.headerColor, textColor: [255, 255, 255] },
      styles: { fontSize: 10 },
      margin: { left: 14 }
    });

    yPos = doc.lastAutoTable.finalY + 15;

    // Top Threats
    if (threatData.topThreats && threatData.topThreats.length > 0) {
      doc.setFontSize(14);
      doc.setTextColor(...this.brandColor);
      doc.text('Most Critical Threats', 14, yPos);
      yPos += 10;

      const threatRows = threatData.topThreats.map((threat, index) => [
        index + 1,
        threat.name || 'Unknown Threat',
        threat.type || 'Malware',
        threat.severity || 'High',
        threat.firstSeen ? new Date(threat.firstSeen).toLocaleDateString() : 'Unknown'
      ]);

      doc.autoTable({
        startY: yPos,
        head: [['#', 'Threat Name', 'Type', 'Severity', 'First Detected']],
        body: threatRows,
        theme: 'striped',
        headStyles: { fillColor: this.headerColor, textColor: [255, 255, 255] },
        styles: { fontSize: 9 },
        margin: { left: 14, right: 14 }
      });
    }

    // Footer
    this.addFooter(doc);

    return doc;
  }

  // Add report header
  addHeader(doc, title) {
    const pageWidth = doc.internal.pageSize.width;
    
    // Logo area (purple box)
    doc.setFillColor(...this.brandColor);
    doc.rect(0, 0, pageWidth, 25, 'F');
    
    // Title
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(18);
    doc.setFont(undefined, 'bold');
    doc.text(title, 14, 16);
    
    // Report date
    doc.setFontSize(10);
    doc.setFont(undefined, 'normal');
    const dateStr = new Date().toLocaleDateString('en-US', { 
      year: 'numeric', 
      month: 'long', 
      day: 'numeric' 
    });
    doc.text(`Generated: ${dateStr}`, pageWidth - 14, 16, { align: 'right' });
  }

  // Add report footer
  addFooter(doc) {
    const pageHeight = doc.internal.pageSize.height;
    const pageWidth = doc.internal.pageSize.width;
    
    doc.setFontSize(8);
    doc.setTextColor(107, 114, 128);
    doc.text('Nebula Shield Anti-Virus - Powered by Advanced Threat Detection', pageWidth / 2, pageHeight - 10, { align: 'center' });
    doc.text(`Page ${doc.internal.getCurrentPageInfo().pageNumber}`, pageWidth - 14, pageHeight - 10, { align: 'right' });
  }

  // Add recommendations section
  addRecommendations(doc, yPos, threatCount) {
    // Check if we need a new page
    if (yPos > 240) {
      doc.addPage();
      yPos = 20;
    }

    doc.setFontSize(16);
    doc.setTextColor(...this.brandColor);
    doc.text('Recommendations', 14, yPos);
    yPos += 10;

    const recommendations = threatCount > 0 ? [
      '• Review and remove all quarantined threats immediately',
      '• Run a full system scan to ensure complete detection',
      '• Update your antivirus signatures to the latest version',
      '• Enable real-time protection for continuous monitoring',
      '• Schedule regular automatic scans (daily recommended)',
      '• Avoid opening suspicious files or email attachments'
    ] : [
      '• Continue running regular scans to maintain security',
      '• Keep your antivirus signatures up to date',
      '• Enable real-time protection if not already active',
      '• Schedule automatic scans for convenience',
      '• Practice safe browsing habits',
      '• Keep your operating system and software updated'
    ];

    doc.setFontSize(10);
    doc.setTextColor(...this.textColor);
    recommendations.forEach(rec => {
      doc.text(rec, 14, yPos);
      yPos += 7;
    });
  }

  // Format duration in human-readable form
  formatDuration(seconds) {
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${minutes}m ${secs}s`;
  }

  // Save PDF with filename
  savePDF(doc, filename) {
    doc.save(filename);
  }

  // Download scan report
  async downloadScanReport(scanData, filename = 'scan-report.pdf') {
    const doc = await this.generateScanReport(scanData);
    this.savePDF(doc, filename);
  }

  // Download system health report
  async downloadHealthReport(healthData, filename = 'system-health-report.pdf') {
    const doc = await this.generateSystemHealthReport(healthData);
    this.savePDF(doc, filename);
  }

  // Download threat analysis report
  async downloadThreatReport(threatData, filename = 'threat-analysis-report.pdf') {
    const doc = await this.generateThreatAnalysisReport(threatData);
    this.savePDF(doc, filename);
  }
}

// Export singleton instance
const pdfReportService = new PDFReportService();
export default pdfReportService;
