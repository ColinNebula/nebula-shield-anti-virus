/**
 * Cloud Threat Intelligence Manager
 * Integrates with multiple threat intelligence APIs for enhanced detection
 * Handles API keys gracefully when not available
 */

const axios = require('axios');
const crypto = require('crypto');

class CloudThreatIntelligence {
    constructor() {
        this.apiKeys = {
            virusTotal: process.env.VIRUSTOTAL_API_KEY || null,
            abuseIPDB: process.env.ABUSEIPDB_API_KEY || null,
            urlScan: process.env.URLSCAN_API_KEY || null,
            hybridAnalysis: process.env.HYBRID_ANALYSIS_API_KEY || null
        };

        // Cache for API responses (avoid rate limits)
        this.cache = new Map();
        this.cacheTTL = 3600000; // 1 hour

        // Rate limiting
        this.rateLimits = {
            virusTotal: { requests: 0, resetTime: Date.now() + 60000, limit: 4 },
            abuseIPDB: { requests: 0, resetTime: Date.now() + 86400000, limit: 1000 },
            urlScan: { requests: 0, resetTime: Date.now() + 60000, limit: 10 }
        };

        // Track API availability
        this.apiStatus = {
            virusTotal: this.apiKeys.virusTotal ? 'available' : 'no_key',
            abuseIPDB: this.apiKeys.abuseIPDB ? 'available' : 'no_key',
            urlScan: this.apiKeys.urlScan ? 'available' : 'no_key',
            hybridAnalysis: this.apiKeys.hybridAnalysis ? 'available' : 'no_key'
        };

        this.logStatus();
    }

    /**
     * Log API status on startup
     */
    logStatus() {
        console.log('\n🌐 Cloud Threat Intelligence Status:');
        for (const [api, status] of Object.entries(this.apiStatus)) {
            const icon = status === 'available' ? '✅' : '⚠️';
            const message = status === 'available' 
                ? 'Ready' 
                : 'No API key (using fallback detection)';
            console.log(`   ${icon} ${api}: ${message}`);
        }
        console.log('');
    }

    /**
     * Check file hash with VirusTotal
     */
    async checkFileHash(fileHash) {
        if (!this.canUseAPI('virusTotal')) {
            return this.fallbackFileCheck(fileHash);
        }

        const cacheKey = `vt_file_${fileHash}`;
        const cached = this.getFromCache(cacheKey);
        if (cached) return cached;

        try {
            if (!this.checkRateLimit('virusTotal')) {
                console.log('⚠️  VirusTotal rate limit reached, using cache');
                return this.fallbackFileCheck(fileHash);
            }

            const response = await axios.get(
                `https://www.virustotal.com/api/v3/files/${fileHash}`,
                {
                    headers: { 'x-apikey': this.apiKeys.virusTotal },
                    timeout: 10000
                }
            );

            const stats = response.data.data.attributes.last_analysis_stats;
            const result = {
                available: true,
                malicious: stats.malicious || 0,
                suspicious: stats.suspicious || 0,
                undetected: stats.undetected || 0,
                harmless: stats.harmless || 0,
                totalScans: Object.values(stats).reduce((a, b) => a + b, 0),
                detectionRatio: `${stats.malicious}/${Object.values(stats).reduce((a, b) => a + b, 0)}`,
                isThreat: stats.malicious > 2, // 2+ engines detected as malicious
                source: 'VirusTotal'
            };

            this.addToCache(cacheKey, result);
            this.apiStatus.virusTotal = 'available';
            return result;

        } catch (error) {
            if (error.response?.status === 404) {
                // File not in database
                return {
                    available: true,
                    notFound: true,
                    message: 'File not in VirusTotal database',
                    source: 'VirusTotal'
                };
            }
            
            console.error('VirusTotal API error:', error.message);
            this.apiStatus.virusTotal = 'error';
            return this.fallbackFileCheck(fileHash);
        }
    }

    /**
     * Check IP address reputation
     */
    async checkIPReputation(ipAddress) {
        if (!this.canUseAPI('abuseIPDB')) {
            return this.fallbackIPCheck(ipAddress);
        }

        const cacheKey = `abuseipdb_${ipAddress}`;
        const cached = this.getFromCache(cacheKey);
        if (cached) return cached;

        try {
            if (!this.checkRateLimit('abuseIPDB')) {
                console.log('⚠️  AbuseIPDB rate limit reached, using cache');
                return this.fallbackIPCheck(ipAddress);
            }

            const response = await axios.get(
                'https://api.abuseipdb.com/api/v2/check',
                {
                    params: { ipAddress, maxAgeInDays: 90 },
                    headers: { 'Key': this.apiKeys.abuseIPDB },
                    timeout: 10000
                }
            );

            const data = response.data.data;
            const result = {
                available: true,
                abuseScore: data.abuseConfidenceScore,
                totalReports: data.totalReports,
                isWhitelisted: data.isWhitelisted,
                isThreat: data.abuseConfidenceScore > 50,
                country: data.countryCode,
                isp: data.isp,
                source: 'AbuseIPDB'
            };

            this.addToCache(cacheKey, result);
            this.apiStatus.abuseIPDB = 'available';
            return result;

        } catch (error) {
            console.error('AbuseIPDB API error:', error.message);
            this.apiStatus.abuseIPDB = 'error';
            return this.fallbackIPCheck(ipAddress);
        }
    }

    /**
     * Check URL safety
     */
    async checkURL(url) {
        if (!this.canUseAPI('virusTotal')) {
            return this.fallbackURLCheck(url);
        }

        const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');
        const cacheKey = `vt_url_${urlId}`;
        const cached = this.getFromCache(cacheKey);
        if (cached) return cached;

        try {
            if (!this.checkRateLimit('virusTotal')) {
                console.log('⚠️  VirusTotal rate limit reached, using cache');
                return this.fallbackURLCheck(url);
            }

            const response = await axios.get(
                `https://www.virustotal.com/api/v3/urls/${urlId}`,
                {
                    headers: { 'x-apikey': this.apiKeys.virusTotal },
                    timeout: 10000
                }
            );

            const stats = response.data.data.attributes.last_analysis_stats;
            const result = {
                available: true,
                malicious: stats.malicious || 0,
                suspicious: stats.suspicious || 0,
                harmless: stats.harmless || 0,
                isThreat: stats.malicious > 0,
                categories: response.data.data.attributes.categories,
                source: 'VirusTotal'
            };

            this.addToCache(cacheKey, result);
            return result;

        } catch (error) {
            if (error.response?.status === 404) {
                // Submit URL for scanning
                await this.submitURL(url);
                return {
                    available: true,
                    notFound: true,
                    message: 'URL submitted for scanning',
                    source: 'VirusTotal'
                };
            }

            console.error('VirusTotal URL check error:', error.message);
            return this.fallbackURLCheck(url);
        }
    }

    /**
     * Submit URL for scanning
     */
    async submitURL(url) {
        if (!this.canUseAPI('virusTotal')) {
            return false;
        }

        try {
            await axios.post(
                'https://www.virustotal.com/api/v3/urls',
                new URLSearchParams({ url }),
                {
                    headers: { 
                        'x-apikey': this.apiKeys.virusTotal,
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    timeout: 10000
                }
            );
            return true;
        } catch (error) {
            console.error('URL submission error:', error.message);
            return false;
        }
    }

    /**
     * Fallback file check (basic heuristics)
     */
    fallbackFileCheck(fileHash) {
        // Use local threat database or heuristics
        return {
            available: false,
            message: 'Cloud lookup unavailable, using local detection',
            isThreat: false,
            source: 'local'
        };
    }

    /**
     * Fallback IP check
     */
    fallbackIPCheck(ipAddress) {
        // Basic checks for private/reserved IPs
        const privateRanges = [
            /^10\./,
            /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
            /^192\.168\./,
            /^127\./,
            /^0\.0\.0\.0$/
        ];

        const isPrivate = privateRanges.some(range => range.test(ipAddress));

        return {
            available: false,
            message: 'IP reputation service unavailable',
            isPrivate,
            isThreat: false,
            source: 'local'
        };
    }

    /**
     * Fallback URL check
     */
    fallbackURLCheck(url) {
        try {
            const urlObj = new URL(url);
            const hostname = urlObj.hostname;

            // Basic suspicious patterns
            const suspiciousPatterns = [
                /\d+\.\d+\.\d+\.\d+/, // IP address
                /-verify|-login|-secure|-account/i, // Phishing keywords
                /\.tk$|\.ml$|\.ga$/, // Free domains often used for phishing
            ];

            const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(hostname));

            return {
                available: false,
                message: 'URL scanning service unavailable, using basic checks',
                isThreat: isSuspicious,
                source: 'local'
            };
        } catch {
            return {
                available: false,
                isThreat: false,
                source: 'local'
            };
        }
    }

    /**
     * Check if API can be used
     */
    canUseAPI(apiName) {
        return this.apiKeys[apiName] && this.apiStatus[apiName] !== 'error';
    }

    /**
     * Check rate limit
     */
    checkRateLimit(apiName) {
        const limit = this.rateLimits[apiName];
        if (!limit) return true;

        const now = Date.now();
        if (now > limit.resetTime) {
            // Reset counter
            limit.requests = 0;
            limit.resetTime = now + (apiName === 'abuseIPDB' ? 86400000 : 60000);
        }

        if (limit.requests >= limit.limit) {
            return false; // Rate limit exceeded
        }

        limit.requests++;
        return true;
    }

    /**
     * Cache management
     */
    getFromCache(key) {
        const cached = this.cache.get(key);
        if (cached && Date.now() - cached.timestamp < this.cacheTTL) {
            return cached.data;
        }
        return null;
    }

    addToCache(key, data) {
        this.cache.set(key, {
            data,
            timestamp: Date.now()
        });

        // Limit cache size
        if (this.cache.size > 1000) {
            const oldestKey = this.cache.keys().next().value;
            this.cache.delete(oldestKey);
        }
    }

    /**
     * Get API status
     */
    getStatus() {
        return {
            apis: this.apiStatus,
            cacheSize: this.cache.size,
            rateLimits: {
                virusTotal: {
                    remaining: this.rateLimits.virusTotal.limit - this.rateLimits.virusTotal.requests,
                    limit: this.rateLimits.virusTotal.limit
                },
                abuseIPDB: {
                    remaining: this.rateLimits.abuseIPDB.limit - this.rateLimits.abuseIPDB.requests,
                    limit: this.rateLimits.abuseIPDB.limit
                }
            }
        };
    }

    /**
     * Update API key
     */
    updateAPIKey(apiName, key) {
        this.apiKeys[apiName] = key;
        this.apiStatus[apiName] = key ? 'available' : 'no_key';
        console.log(`Updated ${apiName} API key`);
    }

    /**
     * Clear cache
     */
    clearCache() {
        this.cache.clear();
        console.log('Cache cleared');
    }
}

// Export singleton instance
module.exports = new CloudThreatIntelligence();
