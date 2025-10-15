import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import axios from 'axios';
import toast from 'react-hot-toast';
import './PaymentSuccess.css';

const PaymentSuccess = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { user, token } = useAuth();
  const [verifying, setVerifying] = useState(true);
  const [verified, setVerified] = useState(false);

  useEffect(() => {
    const verifyPayment = async () => {
      const sessionId = searchParams.get('session_id');
      
      if (!sessionId) {
        toast.error('Invalid payment session');
        navigate('/premium');
        return;
      }

      try {
        const response = await axios.post(
          '/api/payment/stripe/verify',
          { sessionId },
          { headers: { Authorization: `Bearer ${token}` } }
        );

        if (response.data.success) {
          setVerified(true);
          toast.success('🎉 Payment successful! Welcome to Premium!');
        } else {
          toast.error('Payment verification failed');
          navigate('/premium');
        }
      } catch (error) {
        console.error('Verification error:', error);
        toast.error('Failed to verify payment');
        navigate('/premium');
      } finally {
        setVerifying(false);
      }
    };

    if (token) {
      verifyPayment();
    }
  }, [searchParams, token, navigate]);

  if (verifying) {
    return (
      <div className="payment-container">
        <div className="payment-card">
          <div className="spinner"></div>
          <h2>Verifying your payment...</h2>
          <p>Please wait while we confirm your purchase.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="payment-container">
      <div className="payment-card success">
        <div className="success-icon">✓</div>
        <h1>Payment Successful!</h1>
        <p className="subtitle">Welcome to Nebula Shield Premium</p>
        
        <div className="success-details">
          <div className="detail-box">
            <span className="icon">📧</span>
            <div>
              <h3>Check Your Email</h3>
              <p>We've sent a confirmation email to <strong>{user?.email}</strong> with your purchase details and next steps.</p>
            </div>
          </div>

          <div className="detail-box">
            <span className="icon">✨</span>
            <div>
              <h3>Premium Features Activated</h3>
              <p>You now have access to all premium features including scheduled scans, custom paths, and PDF reports.</p>
            </div>
          </div>

          <div className="detail-box">
            <span className="icon">🛡️</span>
            <div>
              <h3>Protection Upgraded</h3>
              <p>Your account has been upgraded to Premium with advanced threat detection and priority support.</p>
            </div>
          </div>
        </div>

        <div className="action-buttons">
          <button 
            className="primary-btn"
            onClick={() => navigate('/dashboard')}
          >
            Go to Dashboard
          </button>
          <button 
            className="secondary-btn"
            onClick={() => navigate('/scanner')}
          >
            Start Scanning
          </button>
        </div>

        <div className="next-steps">
          <h3>What's Next?</h3>
          <ol>
            <li>Check your email for purchase confirmation</li>
            <li>Explore premium features in your dashboard</li>
            <li>Set up scheduled scans in Settings</li>
            <li>Run a comprehensive scan with PDF reports</li>
          </ol>
        </div>
      </div>
    </div>
  );
};

export default PaymentSuccess;
