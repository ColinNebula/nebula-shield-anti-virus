import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { CheckCircle, XCircle, Mail, Loader } from 'lucide-react';
import emailVerificationService from '../services/emailVerification';
import toast from 'react-hot-toast';
import './Auth.css';

const VerifyEmail = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [status, setStatus] = useState('verifying'); // verifying, success, error
  const [message, setMessage] = useState('');
  const [email, setEmail] = useState('');

  useEffect(() => {
    const verifyEmail = async () => {
      const token = searchParams.get('token');
      
      if (!token) {
        setStatus('error');
        setMessage('Invalid verification link. No token provided.');
        return;
      }

      try {
        const result = await emailVerificationService.verifyToken(token);
        
        if (result.success) {
          setStatus('success');
          setMessage(result.message);
          setEmail(result.email);
          toast.success('Email verified successfully! You can now log in.');
          
          // Redirect to login after 3 seconds
          setTimeout(() => {
            navigate('/login');
          }, 3000);
        } else {
          setStatus('error');
          setMessage(result.message);
        }
      } catch (error) {
        setStatus('error');
        setMessage('An error occurred during verification. Please try again.');
        console.error('Verification error:', error);
      }
    };

    verifyEmail();
  }, [searchParams, navigate]);

  return (
    <div className="auth-container">
      <div className="auth-box verify-email-box">
        <div className="auth-header">
          <div className="logo">
            <span className="logo-icon">🛡️</span>
            <h1>Nebula Shield</h1>
          </div>
          
          {status === 'verifying' && (
            <>
              <div className="verify-icon verifying">
                <Loader size={64} className="spinner-icon" />
              </div>
              <h2>Verifying Your Email</h2>
              <p>Please wait while we verify your email address...</p>
            </>
          )}
          
          {status === 'success' && (
            <>
              <div className="verify-icon success">
                <CheckCircle size={64} />
              </div>
              <h2>Email Verified!</h2>
              <p>{message}</p>
              {email && <p className="verified-email">✅ {email}</p>}
              <p className="redirect-message">Redirecting to login page...</p>
            </>
          )}
          
          {status === 'error' && (
            <>
              <div className="verify-icon error">
                <XCircle size={64} />
              </div>
              <h2>Verification Failed</h2>
              <p>{message}</p>
            </>
          )}
        </div>

        {status === 'error' && (
          <div className="verify-actions">
            <button 
              className="btn-primary"
              onClick={() => navigate('/login')}
            >
              <Mail size={18} />
              Go to Login
            </button>
            
            <p className="help-text">
              Need help? <a href="mailto:support@nebulashield.com">Contact Support</a>
            </p>
          </div>
        )}

        {status === 'success' && (
          <div className="verify-actions">
            <button 
              className="btn-primary"
              onClick={() => navigate('/login')}
            >
              Continue to Login
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default VerifyEmail;
