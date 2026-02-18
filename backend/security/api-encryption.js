/**
 * API Request/Response Encryption Module
 * Provides end-to-end encryption for sensitive data transfers
 */

const crypto = require('crypto');

class APIEncryption {
    constructor() {
        // Use environment variable or generate ephemeral keys
        this.algorithm = 'aes-256-gcm';
        this.keyLength = 32; // 256 bits
        this.ivLength = 16;  // 128 bits
        this.authTagLength = 16; // 128 bits
        this.saltLength = 64;
        
        // Master encryption key (should be in environment variable)
        this.masterKey = process.env.API_ENCRYPTION_KEY 
            ? Buffer.from(process.env.API_ENCRYPTION_KEY, 'hex')
            : this.generateKey();

        if (!process.env.API_ENCRYPTION_KEY) {
            console.warn('⚠️  API_ENCRYPTION_KEY not set. Using generated key (not persistent across restarts)');
            console.log('🔑 Generated key:', this.masterKey.toString('hex'));
            console.log('💡 Add to .env: API_ENCRYPTION_KEY=' + this.masterKey.toString('hex'));
        }
    }

    /**
     * Generate encryption key
     */
    generateKey() {
        return crypto.randomBytes(this.keyLength);
    }

    /**
     * Derive key from password using PBKDF2
     */
    deriveKey(password, salt) {
        return crypto.pbkdf2Sync(
            password,
            salt,
            100000, // iterations
            this.keyLength,
            'sha512'
        );
    }

    /**
     * Encrypt data
     */
    encrypt(data, usePassword = null) {
        try {
            // Convert data to string if object
            const plaintext = typeof data === 'string' 
                ? data 
                : JSON.stringify(data);

            // Generate IV
            const iv = crypto.randomBytes(this.ivLength);

            // Determine encryption key
            let key;
            let salt = null;

            if (usePassword) {
                // Derive key from password
                salt = crypto.randomBytes(this.saltLength);
                key = this.deriveKey(usePassword, salt);
            } else {
                // Use master key
                key = this.masterKey;
            }

            // Create cipher
            const cipher = crypto.createCipheriv(this.algorithm, key, iv);

            // Encrypt data
            let encrypted = cipher.update(plaintext, 'utf8', 'hex');
            encrypted += cipher.final('hex');

            // Get authentication tag
            const authTag = cipher.getAuthTag();

            // Build result object
            const result = {
                encrypted: encrypted,
                iv: iv.toString('hex'),
                authTag: authTag.toString('hex'),
                algorithm: this.algorithm
            };

            // Include salt if password-based
            if (salt) {
                result.salt = salt.toString('hex');
            }

            return result;
        } catch (error) {
            console.error('Encryption error:', error);
            throw new Error('Encryption failed');
        }
    }

    /**
     * Decrypt data
     */
    decrypt(encryptedData, usePassword = null) {
        try {
            const {
                encrypted,
                iv,
                authTag,
                salt = null,
                algorithm = this.algorithm
            } = encryptedData;

            // Validate required fields
            if (!encrypted || !iv || !authTag) {
                throw new Error('Invalid encrypted data format');
            }

            // Determine decryption key
            let key;

            if (usePassword && salt) {
                // Derive key from password
                key = this.deriveKey(usePassword, Buffer.from(salt, 'hex'));
            } else {
                // Use master key
                key = this.masterKey;
            }

            // Create decipher
            const decipher = crypto.createDecipheriv(
                algorithm,
                key,
                Buffer.from(iv, 'hex')
            );

            // Set authentication tag
            decipher.setAuthTag(Buffer.from(authTag, 'hex'));

            // Decrypt data
            let decrypted = decipher.update(encrypted, 'hex', 'utf8');
            decrypted += decipher.final('utf8');

            // Try to parse as JSON
            try {
                return JSON.parse(decrypted);
            } catch {
                // Return as string if not JSON
                return decrypted;
            }
        } catch (error) {
            console.error('Decryption error:', error);
            throw new Error('Decryption failed');
        }
    }

    /**
     * Encrypt request body
     */
    encryptRequest(body, password = null) {
        const encrypted = this.encrypt(body, password);
        
        return {
            encrypted: true,
            data: encrypted,
            timestamp: Date.now()
        };
    }

    /**
     * Decrypt request body
     */
    decryptRequest(encryptedBody, password = null) {
        if (!encryptedBody.encrypted || !encryptedBody.data) {
            throw new Error('Not an encrypted request');
        }

        return this.decrypt(encryptedBody.data, password);
    }

    /**
     * Encrypt response
     */
    encryptResponse(response, password = null) {
        const encrypted = this.encrypt(response, password);
        
        return {
            encrypted: true,
            data: encrypted,
            timestamp: Date.now()
        };
    }

    /**
     * Decrypt response
     */
    decryptResponse(encryptedResponse, password = null) {
        if (!encryptedResponse.encrypted || !encryptedResponse.data) {
            throw new Error('Not an encrypted response');
        }

        return this.decrypt(encryptedResponse.data, password);
    }

    /**
     * Hash sensitive data (one-way)
     */
    hash(data) {
        return crypto
            .createHash('sha256')
            .update(typeof data === 'string' ? data : JSON.stringify(data))
            .digest('hex');
    }

    /**
     * Create HMAC signature
     */
    sign(data, secret = null) {
        const key = secret || this.masterKey;
        const dataString = typeof data === 'string' ? data : JSON.stringify(data);
        
        return crypto
            .createHmac('sha256', key)
            .update(dataString)
            .digest('hex');
    }

    /**
     * Verify HMAC signature
     */
    verify(data, signature, secret = null) {
        const expectedSignature = this.sign(data, secret);
        return crypto.timingSafeEqual(
            Buffer.from(signature),
            Buffer.from(expectedSignature)
        );
    }

    /**
     * Middleware for encrypting responses
     */
    createEncryptResponseMiddleware(options = {}) {
        const {
            enabled = true,
            encryptPaths = ['/api/auth/', '/api/payment/'],
            excludePaths = [],
            usePassword = false
        } = options;

        return (req, res, next) => {
            if (!enabled) return next();

            // Check if path should be encrypted
            const shouldEncrypt = encryptPaths.some(path => req.path.startsWith(path)) &&
                                 !excludePaths.some(path => req.path.startsWith(path));

            if (!shouldEncrypt) return next();

            // Store original send function
            const originalSend = res.send;

            // Override send function
            res.send = function(data) {
                try {
                    // Parse JSON if string
                    let parsedData = data;
                    if (typeof data === 'string') {
                        try {
                            parsedData = JSON.parse(data);
                        } catch {
                            parsedData = data;
                        }
                    }

                    // Encrypt response
                    const password = usePassword ? req.user?.userId?.toString() : null;
                    const encrypted = this.encryptResponse(parsedData, password);

                    // Set encryption header
                    res.setHeader('X-Response-Encrypted', 'true');

                    // Send encrypted data
                    return originalSend.call(this, JSON.stringify(encrypted));
                } catch (error) {
                    console.error('Response encryption error:', error);
                    return originalSend.call(this, data);
                }
            }.bind(this);

            next();
        };
    }

    /**
     * Middleware for decrypting requests
     */
    createDecryptRequestMiddleware(options = {}) {
        const {
            enabled = true,
            decryptPaths = ['/api/auth/', '/api/payment/'],
            excludePaths = [],
            usePassword = false
        } = options;

        return (req, res, next) => {
            if (!enabled) return next();

            // Check if path should be decrypted
            const shouldDecrypt = decryptPaths.some(path => req.path.startsWith(path)) &&
                                 !excludePaths.some(path => req.path.startsWith(path));

            if (!shouldDecrypt) return next();

            // Check if request is encrypted
            if (req.body && req.body.encrypted === true) {
                try {
                    const password = usePassword ? req.user?.userId?.toString() : null;
                    req.body = this.decryptRequest(req.body, password);
                    req.isDecrypted = true;
                } catch (error) {
                    console.error('Request decryption error:', error);
                    return res.status(400).json({
                        success: false,
                        message: 'Failed to decrypt request'
                    });
                }
            }

            next();
        };
    }

    /**
     * Middleware for request signing (integrity verification)
     */
    createSigningMiddleware(options = {}) {
        const {
            enabled = true,
            signPaths = ['/api/'],
            excludePaths = []
        } = options;

        return (req, res, next) => {
            if (!enabled) return next();

            // Check if path should be signed
            const shouldSign = signPaths.some(path => req.path.startsWith(path)) &&
                              !excludePaths.some(path => req.path.startsWith(path));

            if (!shouldSign) return next();

            // Store original send function
            const originalSend = res.send;

            // Override send function to add signature
            res.send = function(data) {
                try {
                    let parsedData = data;
                    if (typeof data === 'string') {
                        try {
                            parsedData = JSON.parse(data);
                        } catch {
                            parsedData = data;
                        }
                    }

                    // Generate signature
                    const signature = this.sign(parsedData);

                    // Add signature to response
                    if (typeof parsedData === 'object') {
                        parsedData._signature = signature;
                    }

                    // Set signature header
                    res.setHeader('X-Response-Signature', signature);

                    return originalSend.call(this, JSON.stringify(parsedData));
                } catch (error) {
                    console.error('Response signing error:', error);
                    return originalSend.call(this, data);
                }
            }.bind(this);

            next();
        };
    }

    /**
     * Middleware for signature verification
     */
    createVerificationMiddleware(options = {}) {
        const {
            enabled = true,
            verifyPaths = ['/api/'],
            excludePaths = [],
            requireSignature = false
        } = options;

        return (req, res, next) => {
            if (!enabled) return next();

            // Check if path should be verified
            const shouldVerify = verifyPaths.some(path => req.path.startsWith(path)) &&
                                !excludePaths.some(path => req.path.startsWith(path));

            if (!shouldVerify) return next();

            // Get signature from header or body
            const signature = req.headers['x-request-signature'] || req.body?._signature;

            if (!signature) {
                if (requireSignature) {
                    return res.status(400).json({
                        success: false,
                        message: 'Request signature required'
                    });
                }
                return next();
            }

            try {
                // Remove signature from body before verification
                const bodyForVerification = { ...req.body };
                delete bodyForVerification._signature;

                // Verify signature
                const isValid = this.verify(bodyForVerification, signature);

                if (!isValid) {
                    console.warn('[SECURITY] Invalid request signature:', {
                        path: req.path,
                        ip: req.ip
                    });

                    return res.status(400).json({
                        success: false,
                        message: 'Invalid request signature'
                    });
                }

                req.isVerified = true;
                next();
            } catch (error) {
                console.error('Signature verification error:', error);
                res.status(400).json({
                    success: false,
                    message: 'Signature verification failed'
                });
            }
        };
    }

    /**
     * Generate client encryption key pair (for asymmetric encryption)
     */
    generateKeyPair() {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });

        return { publicKey, privateKey };
    }

    /**
     * Encrypt with RSA public key
     */
    encryptWithPublicKey(data, publicKey) {
        const dataString = typeof data === 'string' ? data : JSON.stringify(data);
        const encrypted = crypto.publicEncrypt(
            {
                key: publicKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            },
            Buffer.from(dataString)
        );

        return encrypted.toString('base64');
    }

    /**
     * Decrypt with RSA private key
     */
    decryptWithPrivateKey(encryptedData, privateKey) {
        const decrypted = crypto.privateDecrypt(
            {
                key: privateKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            },
            Buffer.from(encryptedData, 'base64')
        );

        const dataString = decrypted.toString('utf8');

        try {
            return JSON.parse(dataString);
        } catch {
            return dataString;
        }
    }
}

module.exports = new APIEncryption();
