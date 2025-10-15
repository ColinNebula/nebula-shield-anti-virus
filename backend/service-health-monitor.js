const axios = require('axios');
const { PORTS, API_ENDPOINTS, HEALTH_CHECK } = require('../config/app-config');

class ServiceHealthMonitor {
  constructor() {
    this.services = {
      frontend: {
        name: 'React Frontend',
        url: `http://localhost:${PORTS.FRONTEND}`,
        status: 'unknown',
        lastCheck: null,
        uptime: 0
      },
      authServer: {
        name: 'Auth Server',
        url: `http://localhost:${PORTS.AUTH_SERVER}/test`,
        status: 'unknown',
        lastCheck: null,
        uptime: 0
      },
      backend: {
        name: 'C++ Backend',
        url: `http://localhost:${PORTS.BACKEND_API}/api/protection/status`,
        status: 'unknown',
        lastCheck: null,
        uptime: 0
      }
    };
    
    this.monitoring = false;
    this.interval = null;
  }

  async checkService(serviceKey) {
    const service = this.services[serviceKey];
    const startTime = Date.now();
    
    try {
      const response = await axios.get(service.url, {
        timeout: HEALTH_CHECK.TIMEOUT
      });
      
      const responseTime = Date.now() - startTime;
      
      service.status = 'online';
      service.lastCheck = new Date().toISOString();
      service.responseTime = responseTime;
      service.uptime++;
      
      return {
        service: serviceKey,
        name: service.name,
        status: 'online',
        responseTime: `${responseTime}ms`
      };
    } catch (error) {
      service.status = 'offline';
      service.lastCheck = new Date().toISOString();
      service.uptime = 0;
      
      return {
        service: serviceKey,
        name: service.name,
        status: 'offline',
        error: error.message
      };
    }
  }

  async checkAllServices() {
    const results = await Promise.all([
      this.checkService('authServer'),
      this.checkService('backend'),
      this.checkService('frontend')
    ]);
    
    return results;
  }

  startMonitoring(callback) {
    if (this.monitoring) {
      console.log('⚠️  Monitoring already running');
      return;
    }

    console.log('🔄 Starting service health monitoring...');
    console.log(`⏱️  Check interval: ${HEALTH_CHECK.INTERVAL}ms\n`);
    
    this.monitoring = true;
    
    // Initial check
    this.checkAllServices().then(results => {
      if (callback) callback(results);
      this.displayStatus(results);
    });
    
    // Periodic checks
    this.interval = setInterval(async () => {
      const results = await this.checkAllServices();
      if (callback) callback(results);
    }, HEALTH_CHECK.INTERVAL);
  }

  stopMonitoring() {
    if (this.interval) {
      clearInterval(this.interval);
      this.monitoring = false;
      console.log('\n🛑 Monitoring stopped');
    }
  }

  displayStatus(results) {
    console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('🏥 SERVICE HEALTH STATUS');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
    
    results.forEach(result => {
      const icon = result.status === 'online' ? '✅' : '❌';
      const statusColor = result.status === 'online' ? '\x1b[32m' : '\x1b[31m';
      const resetColor = '\x1b[0m';
      
      console.log(`${icon} ${result.name}`);
      console.log(`   Status: ${statusColor}${result.status.toUpperCase()}${resetColor}`);
      if (result.responseTime) {
        console.log(`   Response Time: ${result.responseTime}`);
      }
      if (result.error) {
        console.log(`   Error: ${result.error}`);
      }
      console.log('');
    });
    
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  }

  getStatus() {
    return this.services;
  }

  isAllHealthy() {
    return Object.values(this.services).every(s => s.status === 'online');
  }
}

// CLI Usage
if (require.main === module) {
  const monitor = new ServiceHealthMonitor();
  
  console.log('🛡️  Nebula Shield - Service Health Monitor\n');
  
  monitor.startMonitoring((results) => {
    // Only display if there's a status change
    const hasOffline = results.some(r => r.status === 'offline');
    if (hasOffline) {
      monitor.displayStatus(results);
    }
  });
  
  // Handle exit
  process.on('SIGINT', () => {
    monitor.stopMonitoring();
    process.exit(0);
  });
}

module.exports = ServiceHealthMonitor;
