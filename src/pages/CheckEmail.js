import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Mail, RefreshCw, ArrowRight, CheckCircle } from 'lucide-react';
import emailVerificationService from '../services/emailVerification';
import toast from 'react-hot-toast';
import './Auth.css';

const CheckEmail = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState('');
  const [resending, setResending] = useState(false);
  const [canResend, setCanResend] = useState(true);
  const [countdown, setCountdown] = useState(0);
  const [verificationLink, setVerificationLink] = useState('');

  useEffect(() => {
    // Get email from navigation state
    if (location.state?.email) {
      setEmail(location.state.email);
      setVerificationLink(location.state.verificationLink || '');
    } else {
      // If no email in state, redirect to register
      navigate('/register');
    }
  }, [location, navigate]);

  useEffect(() => {
    // Countdown timer for resend button
    if (countdown > 0) {
      const timer = setTimeout(() => setCountdown(countdown - 1), 1000);
      return () => clearTimeout(timer);
    } else {
      setCanResend(true);
    }
  }, [countdown]);

  const handleResend = async () => {
    if (!canResend) return;
    
    setResending(true);
    const result = await emailVerificationService.resendVerificationEmail(email);
    
    if (result.success) {
      toast.success('Verification email resent! Check your inbox.');
      setCanResend(false);
      setCountdown(60); // 60 second cooldown
      
      // Update verification link for development
      if (result.verificationLink) {
        setVerificationLink(result.verificationLink);
      }
    } else {
      toast.error(result.message);
    }
    
    setResending(false);
  };

  const handleOpenLink = () => {
    if (verificationLink) {
      window.location.href = verificationLink;
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-box check-email-box">
        <div className="auth-header">
          <div className="logo">
            <span className="logo-icon">🛡️</span>
            <h1>Nebula Shield</h1>
          </div>
          
          <div className="email-icon">
            <Mail size={64} />
          </div>
          
          <h2>Check Your Email</h2>
          <p>We've sent a verification link to:</p>
          <p className="email-address">{email}</p>
        </div>

        <div className="check-email-content">
          <div className="instructions">
            <h3>Next Steps:</h3>
            <ol>
              <li>
                <CheckCircle size={18} />
                <span>Open your email inbox</span>
              </li>
              <li>
                <CheckCircle size={18} />
                <span>Find the email from Nebula Shield</span>
              </li>
              <li>
                <CheckCircle size={18} />
                <span>Click the verification link</span>
              </li>
              <li>
                <CheckCircle size={18} />
                <span>Log in to your account</span>
              </li>
            </ol>
          </div>

          {/* Development Mode - Show verification link */}
          {verificationLink && (
            <div className="dev-mode-notice">
              <h4>🔧 Development Mode</h4>
              <p>Click below to verify your email (since email sending is simulated):</p>
              <button 
                className="btn-primary verify-now-btn"
                onClick={handleOpenLink}
              >
                <ArrowRight size={18} />
                Verify Email Now
              </button>
              <p className="small-text">
                In production, users would click the link in their email inbox.
              </p>
            </div>
          )}

          <div className="resend-section">
            <p>Didn't receive the email?</p>
            <button 
              className="btn-secondary"
              onClick={handleResend}
              disabled={!canResend || resending}
            >
              <RefreshCw size={18} className={resending ? 'spinning' : ''} />
              {resending ? 'Resending...' : canResend ? 'Resend Email' : `Resend in ${countdown}s`}
            </button>
          </div>

          <div className="help-section">
            <h4>Having trouble?</h4>
            <ul>
              <li>Check your spam or junk folder</li>
              <li>Make sure {email} is correct</li>
              <li>Wait a few minutes for the email to arrive</li>
              <li>Contact <a href="mailto:support@nebulashield.com">support@nebulashield.com</a> if problems persist</li>
            </ul>
          </div>

          <div className="back-to-login">
            <button 
              className="btn-text"
              onClick={() => navigate('/login')}
            >
              ← Back to Login
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default CheckEmail;
