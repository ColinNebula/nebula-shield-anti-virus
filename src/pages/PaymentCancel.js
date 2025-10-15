import React from 'react';
import { useNavigate } from 'react-router-dom';
import './PaymentCancel.css';

const PaymentCancel = () => {
  const navigate = useNavigate();

  return (
    <div className="payment-container">
      <div className="payment-card cancel">
        <div className="cancel-icon">✕</div>
        <h1>Payment Cancelled</h1>
        <p className="subtitle">Your payment was not completed</p>
        
        <div className="cancel-details">
          <p>Don't worry! No charges were made to your account.</p>
          <p>You can try again whenever you're ready to upgrade to Premium.</p>
        </div>

        <div className="action-buttons">
          <button 
            className="primary-btn"
            onClick={() => navigate('/premium')}
          >
            Try Again
          </button>
          <button 
            className="secondary-btn"
            onClick={() => navigate('/dashboard')}
          >
            Back to Dashboard
          </button>
        </div>

        <div className="help-box">
          <h3>Need Help?</h3>
          <p>If you experienced any issues during checkout, please contact our support team.</p>
        </div>
      </div>
    </div>
  );
};

export default PaymentCancel;
