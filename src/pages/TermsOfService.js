import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { 
  FileText, Shield, Scale, Lock, AlertTriangle, 
  CheckCircle, X, Download, Printer, Mail
} from 'lucide-react';
import './TermsOfService.css';

const TermsOfService = ({ onAccept, onDecline, embedded = false }) => {
  const [scrolledToBottom, setScrolledToBottom] = useState(false);
  const [accepted, setAccepted] = useState(false);

  const handleScroll = (e) => {
    const bottom = e.target.scrollHeight - e.target.scrollTop === e.target.clientHeight;
    if (bottom) {
      setScrolledToBottom(true);
    }
  };

  const handleAccept = () => {
    setAccepted(true);
    if (onAccept) {
      onAccept();
    }
  };

  const handlePrint = () => {
    window.print();
  };

  const handleDownload = () => {
    const element = document.createElement('a');
    const content = document.getElementById('tos-content').innerText;
    const file = new Blob([content], { type: 'text/plain' });
    element.href = URL.createObjectURL(file);
    element.download = 'Nebula-Shield-Terms-of-Service.txt';
    element.click();
  };

  return (
    <div className={`tos-container ${embedded ? 'embedded' : ''}`}>
      <div className="tos-header">
        <div className="header-content">
          <FileText size={32} className="header-icon" />
          <div>
            <h1>Terms of Service</h1>
            <p>Effective Date: October 14, 2025 • Version 1.0</p>
          </div>
        </div>
        <div className="header-actions">
          <button onClick={handlePrint} className="action-btn">
            <Printer size={18} />
            Print
          </button>
          <button onClick={handleDownload} className="action-btn">
            <Download size={18} />
            Download
          </button>
        </div>
      </div>

      <div className="tos-content" id="tos-content" onScroll={handleScroll}>
        <section className="tos-section">
          <h2><Scale size={24} /> 1. Agreement to Terms</h2>
          <p>
            By accessing or using Nebula Shield Anti-Virus ("the Software"), you agree to be bound 
            by these Terms of Service ("Terms"). If you do not agree to these Terms, you must not 
            use the Software.
          </p>
          <p>
            These Terms constitute a legally binding agreement between you ("User," "you," or "your") 
            and Nebula Shield Corporation ("we," "us," or "our").
          </p>
        </section>

        <section className="tos-section">
          <h2><Shield size={24} /> 2. License Grant</h2>
          <h3>2.1 Free Edition</h3>
          <p>
            Subject to your compliance with these Terms, we grant you a limited, non-exclusive, 
            non-transferable, revocable license to use the free version of the Software for personal, 
            non-commercial purposes on a single device.
          </p>
          
          <h3>2.2 Paid Licenses</h3>
          <p>
            Paid licenses (Personal, Premium, Business, Enterprise) grant you additional rights 
            as specified in your license tier:
          </p>
          <ul>
            <li><strong>Personal:</strong> Up to 3 devices for personal use</li>
            <li><strong>Premium:</strong> Up to 5 devices for personal or commercial use</li>
            <li><strong>Business:</strong> Up to 25 devices for commercial use</li>
            <li><strong>Enterprise:</strong> Unlimited devices with custom terms</li>
          </ul>

          <h3>2.3 License Restrictions</h3>
          <p>You may NOT:</p>
          <ul>
            <li>Reverse engineer, decompile, or disassemble the Software</li>
            <li>Remove or modify any proprietary notices or labels</li>
            <li>Share your license key with unauthorized parties</li>
            <li>Use the Software for illegal or malicious purposes</li>
            <li>Circumvent any license validation or protection mechanisms</li>
            <li>Resell, sublicense, or redistribute the Software</li>
          </ul>
        </section>

        <section className="tos-section">
          <h2><Lock size={24} /> 3. Subscription and Payment</h2>
          <h3>3.1 Subscription Plans</h3>
          <p>
            Paid subscriptions are billed annually unless otherwise specified. Prices are subject 
            to change with 30 days' notice.
          </p>

          <h3>3.2 Payment Terms</h3>
          <ul>
            <li>Payment is required in advance for the subscription period</li>
            <li>All fees are non-refundable except as required by law</li>
            <li>Failure to pay will result in license suspension or termination</li>
            <li>We use secure third-party payment processors (Stripe, PayPal)</li>
          </ul>

          <h3>3.3 Auto-Renewal</h3>
          <p>
            Subscriptions automatically renew at the end of each billing period unless you cancel 
            before the renewal date. You will be charged the then-current subscription rate.
          </p>

          <h3>3.4 Cancellation</h3>
          <p>
            You may cancel your subscription at any time through your account settings. Cancellation 
            takes effect at the end of the current billing period. No refunds are provided for 
            partial periods.
          </p>
        </section>

        <section className="tos-section">
          <h2><AlertTriangle size={24} /> 4. Software Warranties and Disclaimers</h2>
          <h3>4.1 Limited Warranty</h3>
          <p>
            We warrant that the Software will perform substantially in accordance with the 
            documentation for a period of 90 days from the date of purchase.
          </p>

          <h3>4.2 DISCLAIMER</h3>
          <div className="warning-box">
            <p>
              <strong>THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.</strong> While 
              we strive to detect and remove malware, we cannot guarantee 100% detection or prevention 
              of all threats.
            </p>
            <p>
              TO THE MAXIMUM EXTENT PERMITTED BY LAW, WE DISCLAIM ALL WARRANTIES, EXPRESS OR IMPLIED, 
              INCLUDING BUT NOT LIMITED TO IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
              PARTICULAR PURPOSE, AND NON-INFRINGEMENT.
            </p>
          </div>

          <h3>4.3 No Guarantee of Protection</h3>
          <p>
            Anti-virus software is one component of a comprehensive security strategy. We do not 
            guarantee that the Software will:
          </p>
          <ul>
            <li>Detect or prevent all malware, viruses, or cyber threats</li>
            <li>Prevent all data breaches or unauthorized access</li>
            <li>Be error-free or uninterrupted</li>
            <li>Meet all your security requirements</li>
          </ul>
        </section>

        <section className="tos-section">
          <h2>5. Limitation of Liability</h2>
          <div className="warning-box">
            <p>
              <strong>IN NO EVENT SHALL WE BE LIABLE FOR:</strong>
            </p>
            <ul>
              <li>Any indirect, incidental, special, consequential, or punitive damages</li>
              <li>Loss of data, revenue, profits, or business opportunities</li>
              <li>Damages resulting from malware infection or cyber attacks</li>
              <li>System downtime or data corruption</li>
              <li>Third-party claims or liabilities</li>
            </ul>
            <p>
              <strong>OUR TOTAL LIABILITY SHALL NOT EXCEED THE AMOUNT YOU PAID FOR THE SOFTWARE 
              IN THE 12 MONTHS PRECEDING THE CLAIM.</strong>
            </p>
          </div>
        </section>

        <section className="tos-section">
          <h2>6. Privacy and Data Collection</h2>
          <h3>6.1 Data We Collect</h3>
          <p>
            The Software collects:
          </p>
          <ul>
            <li>Threat signatures and malware samples</li>
            <li>Scan results and detection statistics</li>
            <li>System information (OS version, hardware specs)</li>
            <li>Usage analytics and performance metrics</li>
            <li>License and subscription information</li>
          </ul>

          <h3>6.2 How We Use Data</h3>
          <p>
            We use collected data to:
          </p>
          <ul>
            <li>Improve threat detection and update virus definitions</li>
            <li>Enhance software performance and user experience</li>
            <li>Provide customer support and license management</li>
            <li>Comply with legal obligations</li>
          </ul>

          <h3>6.3 Data Sharing</h3>
          <p>
            We do NOT sell your personal data. We may share anonymized threat data with security 
            research communities to improve global cybersecurity.
          </p>

          <p>
            For complete details, see our <a href="/privacy-policy">Privacy Policy</a>.
          </p>
        </section>

        <section className="tos-section">
          <h2>7. Acceptable Use</h2>
          <p>You agree to use the Software only for lawful purposes. You may NOT:</p>
          <ul>
            <li>Use the Software to develop, distribute, or assist in creating malware</li>
            <li>Perform unauthorized security testing on third-party systems</li>
            <li>Violate any applicable laws or regulations</li>
            <li>Interfere with the operation of the Software or our services</li>
            <li>Attempt to gain unauthorized access to our systems or other users' accounts</li>
          </ul>
        </section>

        <section className="tos-section">
          <h2>8. Intellectual Property</h2>
          <p>
            All rights, title, and interest in the Software, including all intellectual property 
            rights, belong to us and our licensors. This license does not grant you any ownership 
            rights.
          </p>
          <p>
            The Nebula Shield name, logo, and all related marks are trademarks of Nebula Shield 
            Corporation. You may not use these marks without our prior written consent.
          </p>
        </section>

        <section className="tos-section">
          <h2>9. Updates and Modifications</h2>
          <h3>9.1 Software Updates</h3>
          <p>
            We regularly release updates, including virus definition updates, feature enhancements, 
            and security patches. Some updates may be automatic.
          </p>

          <h3>9.2 Changes to Terms</h3>
          <p>
            We may modify these Terms at any time. We will notify you of material changes via 
            email or in-app notification. Continued use of the Software after changes constitutes 
            acceptance of the modified Terms.
          </p>
        </section>

        <section className="tos-section">
          <h2>10. Termination</h2>
          <h3>10.1 Termination by You</h3>
          <p>
            You may terminate this agreement at any time by uninstalling the Software and ceasing 
            all use.
          </p>

          <h3>10.2 Termination by Us</h3>
          <p>
            We may terminate or suspend your license immediately if you:
          </p>
          <ul>
            <li>Violate these Terms</li>
            <li>Fail to pay subscription fees</li>
            <li>Use the Software for illegal purposes</li>
            <li>Engage in fraudulent activity</li>
          </ul>

          <h3>10.3 Effect of Termination</h3>
          <p>
            Upon termination, you must immediately uninstall the Software and destroy all copies. 
            Provisions regarding warranties, liability limitations, and dispute resolution survive 
            termination.
          </p>
        </section>

        <section className="tos-section">
          <h2>11. Governing Law and Disputes</h2>
          <h3>11.1 Governing Law</h3>
          <p>
            These Terms are governed by the laws of [Your Jurisdiction], without regard to 
            conflict of law principles.
          </p>

          <h3>11.2 Dispute Resolution</h3>
          <p>
            Any disputes arising from these Terms shall be resolved through binding arbitration 
            in accordance with the rules of the American Arbitration Association. You waive any 
            right to participate in class actions.
          </p>
        </section>

        <section className="tos-section">
          <h2>12. Miscellaneous</h2>
          <h3>12.1 Entire Agreement</h3>
          <p>
            These Terms constitute the entire agreement between you and us regarding the Software 
            and supersede all prior agreements.
          </p>

          <h3>12.2 Severability</h3>
          <p>
            If any provision of these Terms is found invalid or unenforceable, the remaining 
            provisions remain in full force.
          </p>

          <h3>12.3 No Waiver</h3>
          <p>
            Our failure to enforce any right or provision does not constitute a waiver of that 
            right or provision.
          </p>

          <h3>12.4 Export Compliance</h3>
          <p>
            You agree to comply with all applicable export and import laws and regulations.
          </p>
        </section>

        <section className="tos-section">
          <h2>13. Contact Information</h2>
          <p>
            For questions about these Terms, please contact us:
          </p>
          <div className="contact-info">
            <p><Mail size={18} /> <strong>Email:</strong> legal@nebulashield.com</p>
            <p><FileText size={18} /> <strong>Mailing Address:</strong> Nebula Shield Corporation, 
            123 Security Boulevard, Suite 500, Tech City, TC 12345</p>
            <p><strong>Support:</strong> support@nebulashield.com</p>
          </div>
        </section>

        <section className="tos-section acknowledgment">
          <h2><CheckCircle size={24} /> Acknowledgment</h2>
          <p>
            BY CLICKING "I ACCEPT" OR BY INSTALLING, ACCESSING, OR USING THE SOFTWARE, YOU 
            ACKNOWLEDGE THAT YOU HAVE READ, UNDERSTOOD, AND AGREE TO BE BOUND BY THESE TERMS 
            OF SERVICE.
          </p>
          <p>
            IF YOU DO NOT AGREE TO THESE TERMS, YOU MUST NOT USE THE SOFTWARE.
          </p>
        </section>

        {!scrolledToBottom && !embedded && (
          <div className="scroll-indicator">
            <p>↓ Please scroll to the bottom to continue ↓</p>
          </div>
        )}
      </div>

      {!embedded && (
        <div className="tos-footer">
          <div className="acceptance-checkbox">
            <input 
              type="checkbox" 
              id="accept-tos" 
              checked={accepted}
              onChange={(e) => setAccepted(e.target.checked)}
              disabled={!scrolledToBottom}
            />
            <label htmlFor="accept-tos">
              I have read and agree to the Terms of Service
            </label>
          </div>
          
          <div className="action-buttons">
            {onDecline && (
              <motion.button
                className="btn-decline"
                onClick={onDecline}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                <X size={18} />
                Decline
              </motion.button>
            )}
            <motion.button
              className="btn-accept"
              onClick={handleAccept}
              disabled={!scrolledToBottom || !accepted}
              whileHover={{ scale: scrolledToBottom && accepted ? 1.05 : 1 }}
              whileTap={{ scale: scrolledToBottom && accepted ? 0.95 : 1 }}
            >
              <CheckCircle size={18} />
              I Accept
            </motion.button>
          </div>
        </div>
      )}
    </div>
  );
};

export default TermsOfService;
