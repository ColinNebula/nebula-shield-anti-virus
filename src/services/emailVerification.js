/**
 * Email Verification Service
 * Handles email verification for new user registrations
 */

import { openDB } from 'idb';

const DB_NAME = 'NebulaShield_EmailVerification';
const DB_VERSION = 1;
const STORE_NAME = 'verifications';

/**
 * Initialize IndexedDB for email verification
 */
async function initDB() {
  return openDB(DB_NAME, DB_VERSION, {
    upgrade(db) {
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        const store = db.createObjectStore(STORE_NAME, { keyPath: 'email' });
        store.createIndex('token', 'token', { unique: true });
        store.createIndex('createdAt', 'createdAt');
      }
    },
  });
}

/**
 * Generate a verification token
 */
function generateVerificationToken() {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Send verification email (simulated - in production, use a real email service)
 */
async function sendVerificationEmail(email, token, userName) {
  // In production, this would call your backend API to send the email
  // For now, we'll simulate it and log to console
  
  const verificationLink = `${window.location.origin}/verify-email?token=${token}`;
  
  console.log('📧 ========== VERIFICATION EMAIL ==========');
  console.log(`To: ${email}`);
  console.log(`Subject: Verify Your Nebula Shield Account`);
  console.log('\n--- Email Content ---');
  console.log(`Hi ${userName},\n`);
  console.log('Welcome to Nebula Shield! 🛡️\n');
  console.log('Please verify your email address by clicking the link below:\n');
  console.log(`${verificationLink}\n`);
  console.log('This link will expire in 24 hours.\n');
  console.log('If you didn\'t create this account, you can safely ignore this email.\n');
  console.log('Best regards,');
  console.log('The Nebula Shield Team');
  console.log('==========================================\n');
  
  // Store the verification link in localStorage for easy access during development
  const verificationData = {
    email,
    token,
    link: verificationLink,
    timestamp: new Date().toISOString()
  };
  
  // Store last 5 verification emails for development purposes
  const storedEmails = JSON.parse(localStorage.getItem('dev_verification_emails') || '[]');
  storedEmails.unshift(verificationData);
  if (storedEmails.length > 5) storedEmails.pop();
  localStorage.setItem('dev_verification_emails', JSON.stringify(storedEmails));
  
  return {
    success: true,
    message: 'Verification email sent',
    verificationLink // Only returned in development
  };
}

/**
 * Create a verification record
 */
async function createVerification(email, userName) {
  try {
    const db = await initDB();
    const token = generateVerificationToken();
    const expiresAt = Date.now() + (24 * 60 * 60 * 1000); // 24 hours
    
    const verification = {
      email,
      token,
      userName,
      verified: false,
      createdAt: Date.now(),
      expiresAt,
      attempts: 0
    };
    
    await db.put(STORE_NAME, verification);
    
    // Send the verification email
    const emailResult = await sendVerificationEmail(email, token, userName);
    
    return {
      success: true,
      message: 'Verification email sent successfully',
      verificationLink: emailResult.verificationLink
    };
  } catch (error) {
    console.error('Failed to create verification:', error);
    return {
      success: false,
      message: 'Failed to send verification email'
    };
  }
}

/**
 * Verify a token
 */
async function verifyToken(token) {
  try {
    const db = await initDB();
    const index = db.transaction(STORE_NAME).store.index('token');
    const verification = await index.get(token);
    
    if (!verification) {
      return {
        success: false,
        message: 'Invalid verification token'
      };
    }
    
    if (verification.verified) {
      return {
        success: false,
        message: 'Email already verified'
      };
    }
    
    if (Date.now() > verification.expiresAt) {
      return {
        success: false,
        message: 'Verification token has expired'
      };
    }
    
    // Mark as verified
    verification.verified = true;
    verification.verifiedAt = Date.now();
    await db.put(STORE_NAME, verification);
    
    return {
      success: true,
      message: 'Email verified successfully',
      email: verification.email
    };
  } catch (error) {
    console.error('Verification failed:', error);
    return {
      success: false,
      message: 'Verification failed'
    };
  }
}

/**
 * Check if email is verified
 */
async function isEmailVerified(email) {
  try {
    const db = await initDB();
    const verification = await db.get(STORE_NAME, email);
    
    return verification?.verified === true;
  } catch (error) {
    console.error('Failed to check verification status:', error);
    return false;
  }
}

/**
 * Resend verification email
 */
async function resendVerificationEmail(email) {
  try {
    const db = await initDB();
    const verification = await db.get(STORE_NAME, email);
    
    if (!verification) {
      return {
        success: false,
        message: 'No verification record found'
      };
    }
    
    if (verification.verified) {
      return {
        success: false,
        message: 'Email already verified'
      };
    }
    
    // Check if too many attempts
    if (verification.attempts >= 5) {
      return {
        success: false,
        message: 'Too many attempts. Please contact support.'
      };
    }
    
    // Generate new token and extend expiry
    const newToken = generateVerificationToken();
    verification.token = newToken;
    verification.expiresAt = Date.now() + (24 * 60 * 60 * 1000);
    verification.attempts += 1;
    verification.lastResent = Date.now();
    
    await db.put(STORE_NAME, verification);
    
    // Send the new verification email
    const emailResult = await sendVerificationEmail(email, newToken, verification.userName);
    
    return {
      success: true,
      message: 'Verification email resent successfully',
      verificationLink: emailResult.verificationLink
    };
  } catch (error) {
    console.error('Failed to resend verification:', error);
    return {
      success: false,
      message: 'Failed to resend verification email'
    };
  }
}

/**
 * Get verification status
 */
async function getVerificationStatus(email) {
  try {
    const db = await initDB();
    const verification = await db.get(STORE_NAME, email);
    
    if (!verification) {
      return {
        exists: false,
        verified: false
      };
    }
    
    return {
      exists: true,
      verified: verification.verified,
      email: verification.email,
      createdAt: verification.createdAt,
      expiresAt: verification.expiresAt,
      expired: Date.now() > verification.expiresAt,
      attempts: verification.attempts
    };
  } catch (error) {
    console.error('Failed to get verification status:', error);
    return {
      exists: false,
      verified: false
    };
  }
}

/**
 * Delete verification record (cleanup after successful verification)
 */
async function deleteVerification(email) {
  try {
    const db = await initDB();
    await db.delete(STORE_NAME, email);
    return true;
  } catch (error) {
    console.error('Failed to delete verification:', error);
    return false;
  }
}

/**
 * Get all pending verifications (for development/debugging)
 */
async function getAllPendingVerifications() {
  try {
    const db = await initDB();
    const all = await db.getAll(STORE_NAME);
    return all.filter(v => !v.verified);
  } catch (error) {
    console.error('Failed to get pending verifications:', error);
    return [];
  }
}

const emailVerificationService = {
  createVerification,
  verifyToken,
  isEmailVerified,
  resendVerificationEmail,
  getVerificationStatus,
  deleteVerification,
  getAllPendingVerifications
};

export default emailVerificationService;
