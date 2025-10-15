import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import emailVerificationService from '../services/emailVerification';
import toast from 'react-hot-toast';
import './Auth.css';

const Register = () => {
  const navigate = useNavigate();
  const { register } = useAuth();
  const [formData, setFormData] = useState({
    fullName: '',
    email: '',
    password: '',
    confirmPassword: ''
  });
  const [loading, setLoading] = useState(false);

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (formData.password !== formData.confirmPassword) {
      toast.error('Passwords do not match');
      return;
    }

    if (formData.password.length < 6) {
      toast.error('Password must be at least 6 characters');
      return;
    }

    setLoading(true);

    // Create the user account (but don't log them in yet)
    const result = await register(
      formData.email,
      formData.password,
      formData.fullName,
      false // Don't auto-login, require email verification
    );
    
    if (result.success) {
      // Create email verification
      const verificationResult = await emailVerificationService.createVerification(
        formData.email,
        formData.fullName
      );
      
      if (verificationResult.success) {
        toast.success('Account created! Please check your email to verify your account.');
        // Navigate to check email page
        navigate('/check-email', { 
          state: { 
            email: formData.email,
            verificationLink: verificationResult.verificationLink 
          } 
        });
      } else {
        toast.error('Account created but verification email failed. Please contact support.');
      }
    } else {
      toast.error(result.message);
    }
    
    setLoading(false);
  };

  return (
    <div className="auth-container">
      <div className="auth-box">
        <div className="auth-header">
          <div className="logo">
            <span className="logo-icon">🛡️</span>
            <h1>Nebula Shield</h1>
          </div>
          <h2>Create Free Account</h2>
          <p>Get started with enterprise-grade antivirus protection</p>
        </div>

        <form className="auth-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="fullName">Full Name</label>
            <input
              type="text"
              id="fullName"
              name="fullName"
              value={formData.fullName}
              onChange={handleChange}
              placeholder="John Doe"
              required
              minLength="2"
            />
          </div>

          <div className="form-group">
            <label htmlFor="email">Email Address</label>
            <input
              type="email"
              id="email"
              name="email"
              value={formData.email}
              onChange={handleChange}
              placeholder="you@example.com"
              required
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              type="password"
              id="password"
              name="password"
              value={formData.password}
              onChange={handleChange}
              placeholder="At least 6 characters"
              required
              minLength="6"
            />
          </div>

          <div className="form-group">
            <label htmlFor="confirmPassword">Confirm Password</label>
            <input
              type="password"
              id="confirmPassword"
              name="confirmPassword"
              value={formData.confirmPassword}
              onChange={handleChange}
              placeholder="Re-enter password"
              required
            />
          </div>

          <button 
            type="submit" 
            className="auth-button"
            disabled={loading}
          >
            {loading ? 'Creating account...' : 'Create Free Account'}
          </button>
        </form>

        <div className="auth-footer">
          <p>
            Already have an account?{' '}
            <Link to="/login">Sign in</Link>
          </p>
        </div>

        <div className="features-preview">
          <h3>✨ Free Plan Includes:</h3>
          <ul>
            <li>✓ Real-time malware protection</li>
            <li>✓ Manual file scanning</li>
            <li>✓ Threat history tracking</li>
            <li>✓ Basic reporting</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default Register;
