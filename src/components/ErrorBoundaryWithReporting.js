/**
 * Enhanced Error Boundary with Reporting
 * Catches React errors and reports them to the analytics service
 */

import React, { Component } from 'react';
import { AlertTriangle, RefreshCw, Home } from 'lucide-react';
import './ErrorBoundaryWithReporting.css';

// In development with React dev server, use proxy (relative URLs)
// In Electron or production, use direct backend URLs
const isElectron = typeof window !== 'undefined' && window.electronAPI?.isElectron;
const API_BASE_URL = isElectron ? 'http://localhost:8080' : '';

class ErrorBoundaryWithReporting extends Component {
  constructor(props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      errorId: null
    };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    const errorId = `ERR-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    this.setState({
      error,
      errorInfo,
      errorId
    });

    // Report error to analytics service
    this.reportError(error, errorInfo, errorId);

    // Log to console in development
    if (process.env.NODE_ENV === 'development') {
      console.error('Error Boundary Caught:', error, errorInfo);
    }
  }

  reportError = async (error, errorInfo, errorId) => {
    try {
      const errorReport = {
        errorId,
        errorType: error.name || 'UnknownError',
        errorMessage: error.message || 'Unknown error occurred',
        errorStack: error.stack || '',
        componentStack: errorInfo.componentStack || '',
        componentName: this.getComponentName(errorInfo),
        pageUrl: window.location.href,
        severity: this.getErrorSeverity(error),
        userAgent: navigator.userAgent,
        timestamp: new Date().toISOString(),
        metadata: {
          props: this.sanitizeProps(this.props),
          state: this.sanitizeState(this.state)
        }
      };

      // Send to backend
      await fetch(`${API_BASE_URL}/api/analytics/error`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(errorReport)
      });

      // Also log locally
      this.logErrorLocally(errorReport);
    } catch (err) {
      console.error('Failed to report error:', err);
    }
  };

  getComponentName = (errorInfo) => {
    if (!errorInfo || !errorInfo.componentStack) return 'Unknown';
    
    const match = errorInfo.componentStack.match(/in (\w+)/);
    return match ? match[1] : 'Unknown';
  };

  getErrorSeverity = (error) => {
    if (error.message && error.message.toLowerCase().includes('fatal')) {
      return 'critical';
    }
    if (error.name === 'TypeError' || error.name === 'ReferenceError') {
      return 'high';
    }
    return 'medium';
  };

  sanitizeProps = (props) => {
    // Remove sensitive data and circular references
    try {
      return JSON.parse(JSON.stringify(props, (key, value) => {
        if (key === 'password' || key === 'token' || key === 'apiKey') {
          return '[REDACTED]';
        }
        return value;
      }));
    } catch {
      return { error: 'Could not serialize props' };
    }
  };

  sanitizeState = (state) => {
    // Remove sensitive data
    try {
      return JSON.parse(JSON.stringify(state, (key, value) => {
        if (key === 'password' || key === 'token') {
          return '[REDACTED]';
        }
        return value;
      }));
    } catch {
      return { error: 'Could not serialize state' };
    }
  };

  logErrorLocally = (errorReport) => {
    const errors = JSON.parse(localStorage.getItem('errorLogs') || '[]');
    errors.push(errorReport);
    
    // Keep only last 50 errors
    if (errors.length > 50) {
      errors.shift();
    }
    
    localStorage.setItem('errorLogs', JSON.stringify(errors));
  };

  handleReload = () => {
    window.location.reload();
  };

  handleGoHome = () => {
    window.location.href = '/';
  };

  handleCopyError = () => {
    const errorText = `
Error ID: ${this.state.errorId}
Error: ${this.state.error?.message}
Stack: ${this.state.error?.stack}
Component: ${this.getComponentName(this.state.errorInfo)}
URL: ${window.location.href}
Time: ${new Date().toISOString()}
    `.trim();

    navigator.clipboard.writeText(errorText);
    alert('Error details copied to clipboard');
  };

  render() {
    if (this.state.hasError) {
      const isDevelopment = import.meta.env.DEV;

      return (
        <div className="error-boundary-container">
          <div className="error-boundary-content">
            <div className="error-icon">
              <AlertTriangle size={64} color="#ef4444" />
            </div>

            <h1 className="error-title">Oops! Something went wrong</h1>
            <p className="error-subtitle">
              We're sorry for the inconvenience. The error has been reported to our team.
            </p>

            {this.state.errorId && (
              <div className="error-id">
                <span className="error-id-label">Error ID:</span>
                <code className="error-id-code">{this.state.errorId}</code>
              </div>
            )}

            {isDevelopment && this.state.error && (
              <div className="error-details">
                <h3>Error Details (Development Only)</h3>
                <div className="error-message">
                  <strong>Message:</strong> {this.state.error.message}
                </div>
                <div className="error-stack">
                  <strong>Stack Trace:</strong>
                  <pre>{this.state.error.stack}</pre>
                </div>
                {this.state.errorInfo && (
                  <div className="component-stack">
                    <strong>Component Stack:</strong>
                    <pre>{this.state.errorInfo.componentStack}</pre>
                  </div>
                )}
              </div>
            )}

            <div className="error-actions">
              <button onClick={this.handleReload} className="btn btn-primary">
                <RefreshCw size={20} />
                Reload Page
              </button>
              <button onClick={this.handleGoHome} className="btn btn-secondary">
                <Home size={20} />
                Go Home
              </button>
              {isDevelopment && (
                <button onClick={this.handleCopyError} className="btn btn-outline">
                  Copy Error Details
                </button>
              )}
            </div>

            <div className="error-footer">
              <p>
                If this problem persists, please contact support with the error ID above.
              </p>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundaryWithReporting;
