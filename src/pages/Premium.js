import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import toast from 'react-hot-toast';
import './Premium.css';

const Premium = () => {
  const { user, token, isPremium, upgradeToPremium } = useAuth();
  const navigate = useNavigate();
  const [upgrading, setUpgrading] = useState(false);
  const [paymentMethod, setPaymentMethod] = useState(null);

  // Stripe payment
  const handleStripePayment = async () => {
    setUpgrading(true);
    setPaymentMethod('stripe');

    try {
      const response = await axios.post(
        '/api/payment/stripe/create-session',
        {},
        { headers: { Authorization: `Bearer ${token}` } }
      );

      if (response.data.success) {
        // Redirect to Stripe Checkout
        window.location.href = response.data.url;
      } else {
        toast.error('Failed to create payment session');
        setUpgrading(false);
      }
    } catch (error) {
      console.error('Stripe payment error:', error);
      toast.error('Payment initialization failed');
      setUpgrading(false);
    }
  };

  // PayPal payment
  const handlePayPalPayment = async () => {
    setUpgrading(true);
    setPaymentMethod('paypal');

    try {
      const response = await axios.post(
        '/api/payment/paypal/create-order',
        {},
        { headers: { Authorization: `Bearer ${token}` } }
      );

      if (response.data.success) {
        // Redirect to PayPal
        window.location.href = response.data.approvalUrl;
      } else {
        toast.error('Failed to create PayPal order');
        setUpgrading(false);
      }
    } catch (error) {
      console.error('PayPal payment error:', error);
      toast.error('Payment initialization failed');
      setUpgrading(false);
    }
  };

  // Keep the old upgrade function for testing
  const handleQuickUpgrade = async () => {
    setUpgrading(true);
    
    const result = await upgradeToPremium();
    
    if (result.success) {
      toast.success('🎉 ' + result.message);
      setTimeout(() => navigate('/dashboard'), 1500);
    } else {
      toast.error(result.message);
    }
    
    setUpgrading(false);
  };

  const freeFeatures = [
    '✓ Real-time malware protection',
    '✓ Manual file scanning',
    '✓ Threat history (last 30 days)',
    '✓ Basic scan reports',
    '✗ Scheduled automatic scans',
    '✗ Custom scan paths',
    '✗ Advanced PDF reports',
    '✗ Priority support'
  ];

  const premiumFeatures = [
    '✓ Everything in Free',
    '✓ Scheduled automatic scans',
    '✓ Custom scan paths & folders',
    '✓ Advanced PDF reports with charts',
    '✓ Unlimited threat history',
    '✓ Priority 24/7 support',
    '✓ Advanced threat detection',
    '✓ Early access to new features'
  ];

  return (
    <div className="premium-container">
      <div className="premium-header">
        <h1>Choose Your Protection Level</h1>
        <p>Upgrade to Premium for advanced features and priority support</p>
      </div>

      <div className="pricing-cards">
        {/* Free Plan */}
        <div className={`pricing-card ${!isPremium ? 'current-plan' : ''}`}>
          <div className="plan-badge">
            {!isPremium && <span className="badge">CURRENT PLAN</span>}
          </div>
          <div className="plan-header">
            <h2>Free</h2>
            <div className="price">
              <span className="amount">$0</span>
              <span className="period">/forever</span>
            </div>
          </div>
          <ul className="features-list">
            {freeFeatures.map((feature, index) => (
              <li 
                key={index}
                className={feature.startsWith('✗') ? 'unavailable' : ''}
              >
                {feature}
              </li>
            ))}
          </ul>
          <button className="plan-button free" disabled>
            {!isPremium ? 'Current Plan' : 'Downgrade Not Available'}
          </button>
        </div>

        {/* Premium Plan */}
        <div className={`pricing-card premium ${isPremium ? 'current-plan' : ''}`}>
          <div className="plan-badge popular">
            <span className="badge">MOST POPULAR</span>
          </div>
          <div className="plan-header">
            <h2>Premium</h2>
            <div className="price">
              <span className="amount">$49</span>
              <span className="period">/year</span>
            </div>
            <p className="save-badge">Save $59/year vs monthly</p>
          </div>
          <ul className="features-list">
            {premiumFeatures.map((feature, index) => (
              <li key={index}>{feature}</li>
            ))}
          </ul>
          {isPremium ? (
            <button className="plan-button active" disabled>
              ✓ Active Premium
            </button>
          ) : (
            <div className="payment-options">
              <button 
                className="plan-button stripe-btn"
                onClick={handleStripePayment}
                disabled={upgrading}
              >
                {upgrading && paymentMethod === 'stripe' ? (
                  'Redirecting...'
                ) : (
                  <>
                    <span className="payment-icon">💳</span>
                    Pay with Card (Stripe)
                  </>
                )}
              </button>
              <button 
                className="plan-button paypal-btn"
                onClick={handlePayPalPayment}
                disabled={upgrading}
              >
                {upgrading && paymentMethod === 'paypal' ? (
                  'Redirecting...'
                ) : (
                  <>
                    <span className="payment-icon">P</span>
                    Pay with PayPal
                  </>
                )}
              </button>
              <div className="payment-divider">
                <span>or</span>
              </div>
              <button 
                className="plan-button demo-btn"
                onClick={handleQuickUpgrade}
                disabled={upgrading}
                title="Instant upgrade for testing (no payment required)"
              >
                {upgrading && !paymentMethod ? 'Processing...' : 'Quick Upgrade (Demo)'}
              </button>
            </div>
          )}
        </div>
      </div>

      {!isPremium && (
        <div className="premium-footer">
          <div className="guarantee">
            <span className="icon">🔒</span>
            <div>
              <h3>30-Day Money-Back Guarantee</h3>
              <p>Not satisfied? Get a full refund within 30 days, no questions asked.</p>
            </div>
          </div>
        </div>
      )}

      <button 
        className="back-button"
        onClick={() => navigate('/dashboard')}
      >
        ← Back to Dashboard
      </button>
    </div>
  );
};

export default Premium;
