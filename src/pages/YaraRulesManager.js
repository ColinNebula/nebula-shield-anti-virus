import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Shield, Plus, Download, Upload, Trash2, Eye, Code,
  CheckCircle, AlertCircle, Search, Filter, BarChart3, Copy
} from 'lucide-react';
import enhancedScanner from '../services/enhancedScanner';
import toast from 'react-hot-toast';
import './YaraRulesManager.css';

const YaraRulesManager = () => {
  const [rules, setRules] = useState([]);
  const [stats, setStats] = useState(null);
  const [selectedRule, setSelectedRule] = useState(null);
  const [showAddRule, setShowAddRule] = useState(false);
  const [newRuleText, setNewRuleText] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [filterFamily, setFilterFamily] = useState('all');

  useEffect(() => {
    loadRules();
    loadStats();
  }, []);

  const loadRules = () => {
    const ruleNames = enhancedScanner.listYaraRules();
    const loadedRules = ruleNames.map(name => enhancedScanner.getYaraRule(name));
    setRules(loadedRules);
  };

  const loadStats = () => {
    const statistics = enhancedScanner.getYaraStats();
    setStats(statistics);
  };

  const handleAddRule = () => {
    if (!newRuleText.trim()) {
      toast.error('Please enter a YARA rule');
      return;
    }

    const result = enhancedScanner.compileYaraRule(newRuleText);
    if (result.success) {
      toast.success(`Rule "${result.rule}" compiled successfully!`);
      setNewRuleText('');
      setShowAddRule(false);
      loadRules();
      loadStats();
    } else {
      toast.error(`Failed to compile rule: ${result.error}`);
    }
  };

  const handleDeleteRule = (ruleName) => {
    if (window.confirm(`Delete rule "${ruleName}"?`)) {
      enhancedScanner.deleteYaraRule(ruleName);
      toast.success(`Rule "${ruleName}" deleted`);
      loadRules();
      loadStats();
      setSelectedRule(null);
    }
  };

  const handleImportRules = (event) => {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target.result;
      const result = enhancedScanner.importYaraRules(content);
      
      if (result.success > 0) {
        toast.success(`Imported ${result.success} rules successfully!`);
        if (result.failed > 0) {
          toast.error(`${result.failed} rules failed to import`);
        }
        loadRules();
        loadStats();
      } else {
        toast.error('Failed to import rules');
      }
    };
    reader.readAsText(file);
  };

  const handleExportRules = () => {
    const rulesText = enhancedScanner.exportYaraRules();
    const blob = new Blob([rulesText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'nebula-shield-rules.yar';
    a.click();
    URL.revokeObjectURL(url);
    toast.success('Rules exported successfully!');
  };

  const handleCopyRule = (ruleText) => {
    navigator.clipboard.writeText(ruleText);
    toast.success('Rule copied to clipboard!');
  };

  const filteredRules = rules.filter(rule => {
    const matchesSearch = rule.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         rule.meta?.description?.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesFamily = filterFamily === 'all' || rule.meta?.malware_family === filterFamily;
    return matchesSearch && matchesFamily;
  });

  const malwareFamilies = ['all', ...new Set(rules.map(r => r.meta?.malware_family).filter(Boolean))];

  const ruleTemplate = `rule Example_Rule {
  meta:
    description = "Example malware detection"
    author = "Your Name"
    severity = "high"
    malware_family = "Trojan"
    date = "${new Date().toISOString().split('T')[0]}"
    
  strings:
    $s1 = "malicious_string" nocase
    $s2 = { 4D 5A 90 00 }  // MZ header
    $s3 = /suspicious.*pattern/i
    
  condition:
    any of them
}`;

  return (
    <div className="yara-manager">
      <div className="yara-header">
        <div className="header-title">
          <Shield size={32} />
          <div>
            <h1>YARA Rules Manager</h1>
            <p>Custom malware detection rules</p>
          </div>
        </div>

        <div className="header-actions">
          <button className="btn btn-primary" onClick={() => setShowAddRule(true)}>
            <Plus size={18} />
            Add Rule
          </button>
          <button className="btn btn-secondary" onClick={handleExportRules}>
            <Download size={18} />
            Export
          </button>
          <label className="btn btn-secondary">
            <Upload size={18} />
            Import
            <input
              type="file"
              accept=".yar,.yara,.txt"
              onChange={handleImportRules}
              style={{ display: 'none' }}
            />
          </label>
        </div>
      </div>

      {/* Statistics */}
      {stats && (
        <div className="yara-stats">
          <div className="stat-card">
            <div className="stat-icon">
              <Shield />
            </div>
            <div className="stat-content">
              <div className="stat-value">{stats.totalRules}</div>
              <div className="stat-label">Total Rules</div>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon">
              <AlertCircle />
            </div>
            <div className="stat-content">
              <div className="stat-value">{stats.totalMatches}</div>
              <div className="stat-label">Total Matches</div>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon">
              <BarChart3 />
            </div>
            <div className="stat-content">
              <div className="stat-value">{Object.keys(stats.rulesByFamily).length}</div>
              <div className="stat-label">Malware Families</div>
            </div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="yara-filters">
        <div className="search-box">
          <Search size={18} />
          <input
            type="text"
            placeholder="Search rules..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>

        <div className="filter-box">
          <Filter size={18} />
          <select value={filterFamily} onChange={(e) => setFilterFamily(e.target.value)}>
            {malwareFamilies.map(family => (
              <option key={family} value={family}>
                {family === 'all' ? 'All Families' : family}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Rules List */}
      <div className="yara-content">
        <div className="rules-list">
          <h3>Rules ({filteredRules.length})</h3>
          
          {filteredRules.length === 0 ? (
            <div className="empty-state">
              <Code size={48} />
              <p>No rules found</p>
              <button className="btn btn-primary" onClick={() => setShowAddRule(true)}>
                Add Your First Rule
              </button>
            </div>
          ) : (
            <div className="rules-grid">
              {filteredRules.map((rule, index) => (
                <motion.div
                  key={rule.name}
                  className={`rule-card ${selectedRule?.name === rule.name ? 'selected' : ''}`}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.05 }}
                  onClick={() => setSelectedRule(rule)}
                >
                  <div className="rule-header">
                    <div className="rule-name">{rule.name}</div>
                    <div className={`severity-badge severity-${rule.meta?.severity || 'medium'}`}>
                      {rule.meta?.severity || 'medium'}
                    </div>
                  </div>

                  <div className="rule-meta">
                    {rule.meta?.description && (
                      <p className="rule-description">{rule.meta.description}</p>
                    )}
                    {rule.meta?.malware_family && (
                      <span className="family-tag">{rule.meta.malware_family}</span>
                    )}
                  </div>

                  <div className="rule-stats">
                    <span>{Object.keys(rule.strings).length} patterns</span>
                    {rule.meta?.author && <span>by {rule.meta.author}</span>}
                  </div>

                  <div className="rule-actions">
                    <button
                      className="btn-icon"
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedRule(rule);
                      }}
                    >
                      <Eye size={16} />
                    </button>
                    <button
                      className="btn-icon"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleCopyRule(rule.rawRule);
                      }}
                    >
                      <Copy size={16} />
                    </button>
                    <button
                      className="btn-icon btn-danger"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleDeleteRule(rule.name);
                      }}
                    >
                      <Trash2 size={16} />
                    </button>
                  </div>
                </motion.div>
              ))}
            </div>
          )}
        </div>

        {/* Rule Details */}
        {selectedRule && (
          <div className="rule-details">
            <div className="details-header">
              <h3>{selectedRule.name}</h3>
              <button className="btn-close" onClick={() => setSelectedRule(null)}>×</button>
            </div>

            <div className="details-content">
              {/* Metadata */}
              <div className="details-section">
                <h4>Metadata</h4>
                <table className="meta-table">
                  <tbody>
                    {Object.entries(selectedRule.meta).map(([key, value]) => (
                      <tr key={key}>
                        <td className="meta-key">{key}</td>
                        <td className="meta-value">{value}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Strings */}
              <div className="details-section">
                <h4>String Patterns ({Object.keys(selectedRule.strings).length})</h4>
                <div className="strings-list">
                  {Object.entries(selectedRule.strings).map(([varName, pattern]) => (
                    <div key={varName} className="pattern-item">
                      <span className="pattern-var">${varName}</span>
                      <span className="pattern-type">[{pattern.type}]</span>
                      <code className="pattern-value">{pattern.value}</code>
                      {pattern.modifiers && Object.keys(pattern.modifiers).length > 0 && (
                        <span className="pattern-modifiers">
                          {Object.keys(pattern.modifiers).join(', ')}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Condition */}
              <div className="details-section">
                <h4>Condition</h4>
                <code className="condition-code">{selectedRule.condition}</code>
              </div>

              {/* Raw Rule */}
              <div className="details-section">
                <h4>Raw Rule</h4>
                <pre className="rule-code">{selectedRule.rawRule}</pre>
                <button
                  className="btn btn-secondary"
                  onClick={() => handleCopyRule(selectedRule.rawRule)}
                >
                  <Copy size={16} />
                  Copy to Clipboard
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Add Rule Modal */}
      {showAddRule && (
        <div className="modal-overlay" onClick={() => setShowAddRule(false)}>
          <motion.div
            className="modal-content yara-editor-modal"
            onClick={(e) => e.stopPropagation()}
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
          >
            <div className="modal-header">
              <h2>Add YARA Rule</h2>
              <button className="btn-close" onClick={() => setShowAddRule(false)}>×</button>
            </div>

            <div className="modal-body">
              <div className="editor-help">
                <p>Enter your YARA rule below. Use the template as a starting point:</p>
                <button
                  className="btn btn-secondary btn-sm"
                  onClick={() => setNewRuleText(ruleTemplate)}
                >
                  Load Template
                </button>
              </div>

              <textarea
                className="yara-editor"
                value={newRuleText}
                onChange={(e) => setNewRuleText(e.target.value)}
                placeholder={ruleTemplate}
                rows={20}
              />
            </div>

            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setShowAddRule(false)}>
                Cancel
              </button>
              <button className="btn btn-primary" onClick={handleAddRule}>
                <CheckCircle size={18} />
                Compile Rule
              </button>
            </div>
          </motion.div>
        </div>
      )}
    </div>
  );
};

export default YaraRulesManager;
