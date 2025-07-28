# Troubleshooting Guide

This guide covers common issues, debugging techniques, and solutions for the SOC Dashboard in production environments.

## 🚨 Common Issues and Solutions

### 1. Authentication and Authorization Issues

#### Issue: JWT Token Expired or Invalid
```
Error: JWT token expired or invalid
Status: 401 Unauthorized
```

**Diagnosis:**
```bash
# Check JWT configuration
echo $JWT_SECRET | base64 -d | wc -c  # Should be 32+ characters

# Verify token in browser console
localStorage.getItem('auth_token')

# Check server logs
docker-compose logs backend | grep -i jwt
```

**Solutions:**
```typescript
// 1. Increase token expiration time
const jwtConfig = {
  expiresIn: '24h', // Increase from default 8h
  refreshThreshold: '1h' // Add refresh logic
};

// 2. Implement token refresh
const refreshToken = async () => {
  try {
    const response = await fetch('/api/auth/refresh', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${currentToken}` }
    });
    const { token } = await response.json();
    localStorage.setItem('auth_token', token);
    return token;
  } catch (error) {
    // Redirect to login
    window.location.href = '/login';
  }
};
```

#### Issue: Role-Based Access Control Not Working
```
Error: User does not have required permissions
Status: 403 Forbidden
```

**Diagnosis:**
```bash
# Check user roles in database
docker-compose exec mongodb mongo secops --eval "db.users.find({}, {email:1, role:1})"

# Verify permission middleware
curl -H "Authorization: Bearer $TOKEN" http://localhost:3001/api/users
```

**Solutions:**
```typescript
// 1. Fix permission checking middleware
export const requirePermission = (permission: string) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const userRole = req.user?.role;
    const userPermissions = permissions[userRole] || [];
    
    // Debug logging
    console.log('User role:', userRole);
    console.log('Required permission:', permission);
    console.log('User permissions:', userPermissions);
    
    if (userPermissions.includes('*') || userPermissions.includes(permission)) {
      next();
    } else {
      res.status(403).json({ 
        error: 'Insufficient permissions',
        required: permission,
        userRole: userRole
      });
    }
  };
};

// 2. Update user role in database
db.users.updateOne(
  { email: "user@example.com" },
  { $set: { role: "admin" } }
);
```

### 2. Database Connection Issues

#### Issue: MongoDB Connection Failed
```
Error: MongoNetworkError: failed to connect to server
```

**Diagnosis:**
```bash
# Check MongoDB status
docker-compose ps mongodb
docker-compose logs mongodb

# Test connection
docker-compose exec mongodb mongo --eval "db.adminCommand('ismaster')"

# Check network connectivity
docker-compose exec backend nc -zv mongodb 27017
```

**Solutions:**
```bash
# 1. Restart MongoDB service
docker-compose restart mongodb

# 2. Check MongoDB configuration
# mongo/mongod.conf
net:
  port: 27017
  bindIp: 0.0.0.0  # Allow connections from containers

# 3. Verify authentication
docker-compose exec mongodb mongo -u admin -p $MONGO_PASSWORD --authenticationDatabase admin

# 4. Check disk space
docker-compose exec mongodb df -h /data/db
```

#### Issue: Redis Connection Timeout
```
Error: Redis connection timeout
```

**Diagnosis:**
```bash
# Check Redis status
docker-compose ps redis
docker-compose logs redis

# Test Redis connection
docker-compose exec redis redis-cli ping

# Check memory usage
docker-compose exec redis redis-cli info memory
```

**Solutions:**
```bash
# 1. Increase Redis memory limit
# docker-compose.yml
command: redis-server --maxmemory 1gb --maxmemory-policy allkeys-lru

# 2. Clear Redis cache if needed
docker-compose exec redis redis-cli flushall

# 3. Check Redis configuration
docker-compose exec redis redis-cli config get "*"
```

### 3. SIEM Integration Issues

#### Issue: Splunk Connection Failed
```
Error: Unable to connect to Splunk server
Status: SSL_ERROR_SYSCALL
```

**Diagnosis:**
```bash
# Test network connectivity
curl -k https://your-splunk-server:8089/services/server/info

# Verify SSL certificate
openssl s_client -connect your-splunk-server:8089 -servername your-splunk-server

# Check authentication
curl -k -u username:password https://your-splunk-server:8089/services/auth/login
```

**Solutions:**
```typescript
// 1. Disable SSL verification for development
const splunkConfig = {
  url: 'https://your-splunk-server:8089',
  rejectUnauthorized: false, // Only for development
  timeout: 30000
};

// 2. Add custom CA certificate
const https = require('https');
const fs = require('fs');

const agent = new https.Agent({
  ca: fs.readFileSync('path/to/ca-certificate.pem')
});

// 3. Implement retry logic
const retrySplunkRequest = async (request: () => Promise<any>, maxRetries = 3) => {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await request();
    } catch (error) {
      if (i === maxRetries - 1) throw error;
      await new Promise(resolve => setTimeout(resolve, 1000 * Math.pow(2, i)));
    }
  }
};
```

#### Issue: Elasticsearch Query Timeout
```
Error: Request timeout of 30000ms exceeded
```

**Diagnosis:**
```bash
# Check Elasticsearch cluster health
curl http://localhost:9200/_cluster/health

# Check query performance
curl -X GET "localhost:9200/_cat/pending_tasks?v"

# Monitor slow queries
curl -X GET "localhost:9200/_cat/thread_pool/search?v&h=name,active,rejected,completed"
```

**Solutions:**
```typescript
// 1. Increase timeout
const elasticClient = new Client({
  node: 'http://localhost:9200',
  requestTimeout: 60000, // Increase to 60 seconds
  maxRetries: 3,
  resurrectStrategy: 'ping'
});

// 2. Optimize queries
const optimizedQuery = {
  index: 'security-*',
  body: {
    query: {
      bool: {
        filter: [ // Use filter instead of must for better performance
          { range: { '@timestamp': { gte: 'now-1h' } } },
          { term: { 'event.category': 'security' } }
        ]
      }
    },
    size: 100,
    _source: ['@timestamp', 'severity', 'message'], // Limit fields
    sort: [{ '@timestamp': { order: 'desc' } }]
  }
};

// 3. Implement pagination
const searchWithPagination = async (query: any, size = 100) => {
  const results = [];
  let searchAfter;
  
  do {
    const searchQuery = {
      ...query,
      body: {
        ...query.body,
        size,
        search_after: searchAfter
      }
    };
    
    const response = await elasticClient.search(searchQuery);
    const hits = response.body.hits.hits;
    results.push(...hits);
    
    if (hits.length < size) break;
    searchAfter = hits[hits.length - 1].sort;
  } while (results.length < 1000); // Limit total results
  
  return results;
};
```

### 4. Performance Issues

#### Issue: High Memory Usage
```
Warning: Memory usage above 90%
Container: secops_backend_1
```

**Diagnosis:**
```bash
# Check container memory usage
docker stats --no-stream

# Monitor Node.js memory
docker-compose exec backend node -e "console.log(process.memoryUsage())"

# Check for memory leaks
docker-compose exec backend node --inspect=0.0.0.0:9229 app.js
```

**Solutions:**
```typescript
// 1. Implement memory monitoring
const monitorMemory = () => {
  const usage = process.memoryUsage();
  const mbUsage = {
    rss: Math.round(usage.rss / 1024 / 1024),
    heapTotal: Math.round(usage.heapTotal / 1024 / 1024),
    heapUsed: Math.round(usage.heapUsed / 1024 / 1024),
    external: Math.round(usage.external / 1024 / 1024)
  };
  
  console.log('Memory usage:', mbUsage);
  
  // Alert if memory usage is high
  if (mbUsage.heapUsed > 500) { // 500MB threshold
    console.warn('High memory usage detected');
  }
};

setInterval(monitorMemory, 60000); // Check every minute

// 2. Implement garbage collection
if (global.gc) {
  setInterval(() => {
    global.gc();
  }, 300000); // Force GC every 5 minutes
}

// 3. Optimize data structures
// Use Map instead of Object for large datasets
const alertCache = new Map();

// Clear old entries periodically
setInterval(() => {
  const cutoff = Date.now() - 3600000; // 1 hour ago
  for (const [key, value] of alertCache.entries()) {
    if (value.timestamp < cutoff) {
      alertCache.delete(key);
    }
  }
}, 600000); // Clean every 10 minutes
```

#### Issue: Slow Database Queries
```
Warning: Query execution time > 1000ms
Collection: alerts
```

**Diagnosis:**
```bash
# Enable MongoDB profiling
docker-compose exec mongodb mongo secops --eval "db.setProfilingLevel(2, {slowms: 100})"

# Check slow queries
docker-compose exec mongodb mongo secops --eval "db.system.profile.find().sort({ts: -1}).limit(5).pretty()"

# Analyze query performance
docker-compose exec mongodb mongo secops --eval "db.alerts.find({severity: 'critical'}).explain('executionStats')"
```

**Solutions:**
```javascript
// 1. Add missing indexes
db.alerts.createIndex({ "timestamp": -1, "severity": 1 });
db.alerts.createIndex({ "source": 1, "status": 1 });
db.alerts.createIndex({ "tags": 1 });
db.cases.createIndex({ "assignee": 1, "status": 1 });

// 2. Optimize queries
// Bad: Full collection scan
db.alerts.find({ severity: { $in: ['high', 'critical'] } });

// Good: Use compound index
db.alerts.find({ 
  severity: { $in: ['high', 'critical'] },
  timestamp: { $gte: new Date(Date.now() - 86400000) }
}).sort({ timestamp: -1 });

// 3. Implement query result caching
const queryCache = new Map();

const getCachedQuery = async (key: string, queryFn: () => Promise<any>, ttl = 300000) => {
  const cached = queryCache.get(key);
  if (cached && Date.now() - cached.timestamp < ttl) {
    return cached.data;
  }
  
  const data = await queryFn();
  queryCache.set(key, { data, timestamp: Date.now() });
  return data;
};
```

### 5. WebSocket Connection Issues

#### Issue: WebSocket Connection Drops
```
Error: WebSocket connection closed unexpectedly
Code: 1006
```

**Diagnosis:**
```bash
# Check WebSocket server status
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: test" http://localhost:3001/socket.io/

# Monitor connection logs
docker-compose logs backend | grep -i websocket

# Check network connectivity
netstat -an | grep 3001
```

**Solutions:**
```typescript
// 1. Implement robust reconnection logic
class WebSocketService {
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 10;
  private reconnectInterval = 1000;
  
  connect(token?: string) {
    try {
      this.ws = new WebSocket(`${config.websocket.url}?token=${token}`);
      
      this.ws.onopen = () => {
        console.log('WebSocket connected');
        this.reconnectAttempts = 0;
        this.reconnectInterval = 1000; // Reset interval
      };
      
      this.ws.onclose = (event) => {
        console.log('WebSocket closed:', event.code, event.reason);
        this.attemptReconnect();
      };
      
      this.ws.onerror = (error) => {
        console.error('WebSocket error:', error);
      };
      
    } catch (error) {
      console.error('WebSocket connection failed:', error);
      this.attemptReconnect();
    }
  }
  
  private attemptReconnect() {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      this.reconnectInterval = Math.min(this.reconnectInterval * 1.5, 30000); // Exponential backoff
      
      console.log(`Reconnecting in ${this.reconnectInterval}ms (attempt ${this.reconnectAttempts})`);
      
      setTimeout(() => {
        this.connect();
      }, this.reconnectInterval);
    } else {
      console.error('Max reconnection attempts reached');
      this.emit('maxReconnectAttemptsReached', {});
    }
  }
}

// 2. Add heartbeat mechanism
const heartbeatInterval = setInterval(() => {
  if (this.ws && this.ws.readyState === WebSocket.OPEN) {
    this.ws.send(JSON.stringify({ type: 'ping' }));
  }
}, 30000); // Send ping every 30 seconds

// 3. Handle server-side WebSocket issues
// backend/websocket.js
io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  
  // Set up ping/pong
  const pingInterval = setInterval(() => {
    socket.emit('ping');
  }, 30000);
  
  socket.on('pong', () => {
    console.log('Received pong from', socket.id);
  });
  
  socket.on('disconnect', (reason) => {
    console.log('Client disconnected:', socket.id, reason);
    clearInterval(pingInterval);
  });
  
  socket.on('error', (error) => {
    console.error('Socket error:', error);
  });
});
```

### 6. Threat Intelligence API Issues

#### Issue: VirusTotal Rate Limit Exceeded
```
Error: Rate limit exceeded
Status: 429 Too Many Requests
```

**Diagnosis:**
```bash
# Check API usage
curl -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/users/$VT_API_KEY"

# Monitor rate limit headers
curl -I -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
```

**Solutions:**
```typescript
// 1. Implement rate limiting
class RateLimiter {
  private requests: number[] = [];
  private maxRequests: number;
  private timeWindow: number;
  
  constructor(maxRequests: number, timeWindow: number) {
    this.maxRequests = maxRequests;
    this.timeWindow = timeWindow;
  }
  
  async checkLimit(): Promise<void> {
    const now = Date.now();
    this.requests = this.requests.filter(time => now - time < this.timeWindow);
    
    if (this.requests.length >= this.maxRequests) {
      const oldestRequest = Math.min(...this.requests);
      const waitTime = this.timeWindow - (now - oldestRequest);
      await new Promise(resolve => setTimeout(resolve, waitTime));
      return this.checkLimit();
    }
    
    this.requests.push(now);
  }
}

const vtRateLimiter = new RateLimiter(4, 60000); // 4 requests per minute

// 2. Implement caching
const threatIntelCache = new Map();

const getCachedThreatIntel = async (ioc: string, type: string) => {
  const cacheKey = `${type}:${ioc}`;
  const cached = threatIntelCache.get(cacheKey);
  
  if (cached && Date.now() - cached.timestamp < 3600000) { // 1 hour cache
    return cached.data;
  }
  
  await vtRateLimiter.checkLimit();
  const data = await queryVirusTotal(ioc, type);
  
  threatIntelCache.set(cacheKey, {
    data,
    timestamp: Date.now()
  });
  
  return data;
};

// 3. Implement batch processing
const batchThreatIntelRequests = async (iocs: Array<{value: string, type: string}>) => {
  const results = [];
  
  for (const ioc of iocs) {
    try {
      const result = await getCachedThreatIntel(ioc.value, ioc.type);
      results.push(result);
    } catch (error) {
      console.error(`Failed to process IOC ${ioc.value}:`, error);
      results.push(null);
    }
  }
  
  return results;
};
```

## 🔧 Debugging Tools and Techniques

### 1. Application Debugging

#### Enable Debug Logging
```typescript
// Set debug environment variable
process.env.DEBUG = 'secops:*';

// Use debug module
import debug from 'debug';
const log = debug('secops:api');

log('Processing alert:', alertId);
log('User permissions:', userPermissions);
```

#### Performance Profiling
```typescript
// Add performance markers
const performanceMarker = (name: string) => {
  const start = Date.now();
  return () => {
    const duration = Date.now() - start;
    console.log(`${name} took ${duration}ms`);
  };
};

// Usage
const endTimer = performanceMarker('Database Query');
const results = await db.alerts.find(query);
endTimer();
```

### 2. Database Debugging

#### MongoDB Query Analysis
```javascript
// Enable profiling
db.setProfilingLevel(2, { slowms: 100 });

// Analyze query execution
db.alerts.find({ severity: 'critical' }).explain('executionStats');

// Check index usage
db.alerts.getIndexes();

// Monitor current operations
db.currentOp();
```

#### Redis Debugging
```bash
# Monitor Redis commands
redis-cli monitor

# Check memory usage by key pattern
redis-cli --bigkeys

# Analyze slow queries
redis-cli slowlog get 10
```

### 3. Network Debugging

#### Container Network Issues
```bash
# Check container networking
docker network ls
docker network inspect secops_secops-network

# Test connectivity between containers
docker-compose exec backend nc -zv mongodb 27017
docker-compose exec backend nslookup mongodb

# Check port bindings
docker-compose ps
netstat -tulpn | grep :3001
```

#### SSL/TLS Issues
```bash
# Test SSL certificate
openssl s_client -connect your-domain.com:443 -servername your-domain.com

# Check certificate expiration
echo | openssl s_client -connect your-domain.com:443 2>/dev/null | openssl x509 -noout -dates

# Verify certificate chain
curl -vI https://your-domain.com
```

## 📊 Monitoring and Alerting

### 1. Health Check Implementation
```typescript
// Comprehensive health check endpoint
app.get('/api/health', async (req, res) => {
  const checks = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    services: {}
  };
  
  try {
    // Database check
    await mongoose.connection.db.admin().ping();
    checks.services.mongodb = { status: 'healthy', responseTime: 0 };
  } catch (error) {
    checks.services.mongodb = { status: 'unhealthy', error: error.message };
    checks.status = 'degraded';
  }
  
  try {
    // Redis check
    const start = Date.now();
    await redisClient.ping();
    checks.services.redis = { 
      status: 'healthy', 
      responseTime: Date.now() - start 
    };
  } catch (error) {
    checks.services.redis = { status: 'unhealthy', error: error.message };
    checks.status = 'degraded';
  }
  
  // Add more service checks...
  
  const statusCode = checks.status === 'healthy' ? 200 : 503;
  res.status(statusCode).json(checks);
});
```

### 2. Custom Metrics
```typescript
// Custom Prometheus metrics
const customMetrics = {
  alertProcessingTime: new prometheus.Histogram({
    name: 'alert_processing_duration_seconds',
    help: 'Time spent processing alerts',
    labelNames: ['severity', 'source']
  }),
  
  threatIntelRequests: new prometheus.Counter({
    name: 'threat_intel_requests_total',
    help: 'Total threat intelligence requests',
    labelNames: ['provider', 'status']
  }),
  
  activeConnections: new prometheus.Gauge({
    name: 'websocket_connections_active',
    help: 'Number of active WebSocket connections'
  })
};

// Usage
const timer = customMetrics.alertProcessingTime.startTimer({ 
  severity: alert.severity, 
  source: alert.source 
});

// Process alert...

timer();
```

## 🚀 Recovery Procedures

### 1. Database Recovery
```bash
# MongoDB backup and restore
# Backup
docker-compose exec mongodb mongodump --db secops --out /backup

# Restore
docker-compose exec mongodb mongorestore --db secops /backup/secops

# Point-in-time recovery
docker-compose exec mongodb mongorestore --db secops --oplogReplay /backup
```

### 2. Service Recovery
```bash
# Restart specific service
docker-compose restart backend

# Rebuild and restart
docker-compose up -d --build backend

# Scale service
docker-compose up -d --scale backend=3

# Check service logs
docker-compose logs -f --tail=100 backend
```

### 3. Data Recovery
```typescript
// Recover lost alerts from logs
const recoverAlertsFromLogs = async () => {
  const logFiles = await fs.readdir('/var/log/secops');
  const alerts = [];
  
  for (const file of logFiles) {
    const content = await fs.readFile(`/var/log/secops/${file}`, 'utf8');
    const lines = content.split('\n');
    
    for (const line of lines) {
      if (line.includes('ALERT:')) {
        try {
          const alertData = JSON.parse(line.split('ALERT:')[1]);
          alerts.push(alertData);
        } catch (error) {
          console.error('Failed to parse alert from log:', error);
        }
      }
    }
  }
  
  // Restore alerts to database
  for (const alert of alerts) {
    try {
      await Alert.create(alert);
    } catch (error) {
      console.error('Failed to restore alert:', error);
    }
  }
  
  console.log(`Recovered ${alerts.length} alerts from logs`);
};
```

This comprehensive troubleshooting guide covers the most common issues you'll encounter in production and provides practical solutions for each scenario.