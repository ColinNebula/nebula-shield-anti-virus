const nodemailer = require('nodemailer');
require('dotenv').config();

// Create email transporter
const createTransporter = () => {
  return nodemailer.createTransporter({
    service: process.env.EMAIL_SERVICE || 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD
    }
  });
};

// Email templates
const emailTemplates = {
  purchaseConfirmation: (userData, purchaseData) => {
    return {
      subject: '🎉 Welcome to Nebula Shield Premium!',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
            .header h1 { margin: 0; font-size: 28px; }
            .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
            .purchase-details { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; }
            .detail-row { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #eee; }
            .detail-row:last-child { border-bottom: none; }
            .label { font-weight: bold; color: #667eea; }
            .features { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; }
            .features ul { list-style: none; padding: 0; }
            .features li { padding: 8px 0; padding-left: 25px; position: relative; }
            .features li:before { content: "✓"; position: absolute; left: 0; color: #4CAF50; font-weight: bold; }
            .cta-button { display: inline-block; background: #667eea; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; font-weight: bold; }
            .footer { text-align: center; color: #666; font-size: 12px; margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>🛡️ Nebula Shield Premium</h1>
              <p style="margin: 10px 0 0 0; font-size: 18px;">Thank you for your purchase!</p>
            </div>
            <div class="content">
              <h2>Hi ${userData.fullName},</h2>
              <p>Welcome to Nebula Shield Premium! Your account has been successfully upgraded.</p>
              
              <div class="purchase-details">
                <h3 style="margin-top: 0; color: #667eea;">📄 Purchase Details</h3>
                <div class="detail-row">
                  <span class="label">Order ID:</span>
                  <span>${purchaseData.orderId}</span>
                </div>
                <div class="detail-row">
                  <span class="label">Plan:</span>
                  <span>Premium (Annual)</span>
                </div>
                <div class="detail-row">
                  <span class="label">Amount Paid:</span>
                  <span>$${purchaseData.amount}</span>
                </div>
                <div class="detail-row">
                  <span class="label">Payment Method:</span>
                  <span>${purchaseData.paymentMethod}</span>
                </div>
                <div class="detail-row">
                  <span class="label">Purchase Date:</span>
                  <span>${purchaseData.date}</span>
                </div>
                <div class="detail-row">
                  <span class="label">Valid Until:</span>
                  <span>${purchaseData.expiresAt}</span>
                </div>
              </div>

              <div class="features">
                <h3 style="margin-top: 0; color: #667eea;">✨ Your Premium Features</h3>
                <ul>
                  <li>Scheduled automatic scans</li>
                  <li>Custom scan paths & folders</li>
                  <li>Advanced PDF reports with charts</li>
                  <li>Unlimited threat history</li>
                  <li>Priority 24/7 support</li>
                  <li>Advanced threat detection</li>
                  <li>Early access to new features</li>
                </ul>
              </div>

              <h3 style="color: #667eea;">🚀 What's Next?</h3>
              <ol>
                <li><strong>Login to your account</strong> - Your premium features are already active!</li>
                <li><strong>Explore the dashboard</strong> - Check out the new scheduled scans feature</li>
                <li><strong>Run a comprehensive scan</strong> - Use custom paths and get detailed PDF reports</li>
                <li><strong>Configure settings</strong> - Set up automatic scans and customize your protection</li>
              </ol>

              <div style="text-align: center;">
                <a href="${process.env.APP_URL}/login" class="cta-button">Access Your Dashboard</a>
              </div>

              <p style="margin-top: 30px; color: #666; font-size: 14px;">
                <strong>Need help?</strong><br>
                Our premium support team is available 24/7 to assist you.<br>
                Reply to this email or visit our support portal.
              </p>
            </div>
            
            <div class="footer">
              <p>This is an automated receipt for your Nebula Shield Premium subscription.</p>
              <p>Nebula Shield Antivirus | Premium Protection for Your Digital Life</p>
              <p style="margin-top: 10px;">
                <a href="${process.env.APP_URL}" style="color: #667eea; text-decoration: none;">Dashboard</a> | 
                <a href="${process.env.APP_URL}/settings" style="color: #667eea; text-decoration: none;">Settings</a> | 
                <a href="${process.env.APP_URL}/support" style="color: #667eea; text-decoration: none;">Support</a>
              </p>
            </div>
          </div>
        </body>
        </html>
      `
    };
  },

  paymentFailed: (userData, errorDetails) => {
    return {
      subject: '⚠️ Payment Issue - Nebula Shield Premium',
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
            .container { max-width: 600px; margin: 0 auto; padding: 20px; }
            .header { background: #f44336; color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
            .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; }
            .error-box { background: #fff3cd; border-left: 4px solid #f44336; padding: 15px; margin: 20px 0; }
            .cta-button { display: inline-block; background: #667eea; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>⚠️ Payment Issue</h1>
            </div>
            <div class="content">
              <h2>Hi ${userData.fullName},</h2>
              <p>We encountered an issue processing your payment for Nebula Shield Premium.</p>
              
              <div class="error-box">
                <strong>Error:</strong> ${errorDetails.message}
              </div>

              <h3>What to do next:</h3>
              <ol>
                <li>Check your payment method details</li>
                <li>Ensure sufficient funds are available</li>
                <li>Try again with a different payment method</li>
                <li>Contact your bank if the issue persists</li>
              </ol>

              <div style="text-align: center;">
                <a href="${process.env.APP_URL}/premium" class="cta-button">Try Again</a>
              </div>

              <p style="margin-top: 20px;">If you need assistance, please contact our support team.</p>
            </div>
          </div>
        </body>
        </html>
      `
    };
  }
};

// Send email function
const sendEmail = async (to, template) => {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
    console.log('📧 Email not configured. Would have sent:');
    console.log(`   To: ${to}`);
    console.log(`   Subject: ${template.subject}`);
    return { success: true, message: 'Email simulation (not configured)' };
  }

  try {
    const transporter = createTransporter();
    
    const mailOptions = {
      from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
      to: to,
      subject: template.subject,
      html: template.html
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('✅ Email sent:', info.messageId);
    
    return { success: true, messageId: info.messageId };
  } catch (error) {
    console.error('❌ Email send failed:', error);
    return { success: false, error: error.message };
  }
};

module.exports = {
  sendEmail,
  emailTemplates
};
