# Production SOC Dashboard Setup Guide

This comprehensive guide will walk you through setting up the SOC Dashboard in a production environment with real SIEM integration, threat intelligence feeds, and enterprise-grade monitoring.

## 📋 Prerequisites

### System Requirements
- **CPU**: 4+ cores recommended
- **RAM**: 8GB minimum, 16GB recommended
- **Storage**: 100GB+ for logs and data
- **Network**: Stable internet connection for threat intel feeds

### Required Software
- Docker 20.10+ and Docker Compose 2.0+
- Node.js 18+ (for development)
- Git for version control
- SSL certificates for production deployment

## 🔧 1. SIEM Integration Setup

### Splunk Integration

#### Step 1: Splunk Configuration
```bash
# 1. Log into your Splunk instance as admin
# 2. Navigate to Settings > Data inputs > HTTP Event Collector

# 3. Create new HEC token
curl -k -X POST https://your-splunk-server:8089/services/data/inputs/http \
  -H "Authorization: Splunk your-admin-token" \
  -d name=secops-dashboard \
  -d token=your-hec-token-here
```

#### Step 2: Environment Configuration
```env
# Add to .env file
VITE_SPLUNK_URL=https://your-splunk-server.com:8089
VITE_SPLUNK_TOKEN=your-hec-token-here
VITE_SPLUNK_INDEX=security
```

#### Step 3: Test Connection
```typescript
// Test Splunk connectivity
import { siemService } from './src/services/siemIntegration';

const testSplunk = async () => {
  try {
    const results = await siemService.querySplunk(
      'index=security | head 10',
      { earliest: '-1h', latest: 'now' }
    );
    console.log('Splunk connection successful:', results);
  } catch (error) {
    console.error('Splunk connection failed:', error);
  }
};
```

#### Step 4: Common Splunk Queries
```splunk
# Security alerts from last 24 hours
index=security sourcetype=alert earliest=-24h | stats count by severity

# Failed login attempts
index=security sourcetype=auth action=failure | stats count by src_ip

# Malware detections
index=security sourcetype=antivirus signature=* | dedup signature | table _time, signature, src_host
```

### Elasticsearch Integration

#### Step 1: Elasticsearch Setup
```bash
# 1. Create API key in Kibana
# Dev Tools > Console:
POST /_security/api_key
{
  "name": "secops-dashboard",
  "role_descriptors": {
    "secops_role": {
      "cluster": ["monitor"],
      "indices": [
        {
          "names": ["security-*", "logs-*"],
          "privileges": ["read", "view_index_metadata"]
        }
      ]
    }
  }
}
```

#### Step 2: Environment Configuration
```env
# Add to .env file
VITE_ELASTIC_URL=https://your-elasticsearch-cluster.com:9200
VITE_ELASTIC_API_KEY=base64-encoded-api-key
VITE_ELASTIC_INDEX_PATTERN=security-*
```

#### Step 3: Index Mapping Setup
```json
PUT /security-alerts
{
  "mappings": {
    "properties": {
      "@timestamp": { "type": "date" },
      "severity": { "type": "keyword" },
      "source_ip": { "type": "ip" },
      "destination_ip": { "type": "ip" },
      "event_type": { "type": "keyword" },
      "message": { "type": "text" },
      "tags": { "type": "keyword" }
    }
  }
}
```

#### Step 4: Test Elasticsearch Connection
```typescript
const testElastic = async () => {
  try {
    const query = {
      query: {
        bool: {
          must: [
            { range: { "@timestamp": { gte: "now-1h" } } },
            { term: { event_type: "alert" } }
          ]
        }
      },
      size: 10,
      sort: [{ "@timestamp": { order: "desc" } }]
    };
    
    const results = await siemService.queryElasticsearch(query, 'security-*');
    console.log('Elasticsearch connection successful:', results);
  } catch (error) {
    console.error('Elasticsearch connection failed:', error);
  }
};
```

### QRadar Integration

#### Step 1: QRadar API Setup
```bash
# 1. Log into QRadar Console
# 2. Go to Admin > Security Tokens
# 3. Create new authorized service token

# Test API access
curl -X GET "https://your-qradar-server/api/siem/offenses" \
  -H "SEC: your-api-token" \
  -H "Version: 12.0" \
  -H "Accept: application/json"
```

#### Step 2: Environment Configuration
```env
# Add to .env file
VITE_QRADAR_URL=https://your-qradar-server.com
VITE_QRADAR_TOKEN=your-api-token
VITE_QRADAR_VERSION=12.0
```

#### Step 3: Common QRadar AQL Queries
```sql
-- Recent high-severity offenses
SELECT id, description, severity, start_time 
FROM offenses 
WHERE severity > 7 
LAST 24 HOURS

-- Top source IPs by event count
SELECT sourceip, COUNT(*) as event_count 
FROM events 
WHERE severity > 5 
GROUP BY sourceip 
ORDER BY event_count DESC 
LAST 1 HOURS
```

## 🧠 2. Threat Intelligence Integration

### MISP Integration

#### Step 1: MISP Server Setup
```bash
# If setting up your own MISP instance
git clone https://github.com/MISP/misp-docker
cd misp-docker
docker-compose up -d

# Access MISP at https://localhost
# Default credentials: admin@admin.test / admin
```

#### Step 2: API Key Generation
```bash
# 1. Log into MISP web interface
# 2. Go to Administration > List Auth Keys
# 3. Add new auth key for API access
# 4. Copy the generated key
```

#### Step 3: Environment Configuration
```env
VITE_MISP_URL=https://your-misp-instance.com
VITE_MISP_API_KEY=your-misp-api-key
VITE_MISP_VERIFY_SSL=false  # Set to true in production
```

#### Step 4: Test MISP Integration
```typescript
const testMISP = async () => {
  try {
    const result = await threatIntelService.queryMISP('8.8.8.8', 'ip');
    console.log('MISP integration successful:', result);
  } catch (error) {
    console.error('MISP integration failed:', error);
  }
};
```

### AlienVault OTX Integration

#### Step 1: OTX Account Setup
```bash
# 1. Register at https://otx.alienvault.com
# 2. Go to Settings > API Integration
# 3. Copy your API key
```

#### Step 2: Environment Configuration
```env
VITE_OTX_API_KEY=your-otx-api-key
```

#### Step 3: Test OTX Integration
```typescript
const testOTX = async () => {
  try {
    const result = await threatIntelService.queryOTX('malicious.com', 'domain');
    console.log('OTX integration successful:', result);
  } catch (error) {
    console.error('OTX integration failed:', error);
  }
};
```

### VirusTotal Integration

#### Step 1: VirusTotal API Setup
```bash
# 1. Register at https://www.virustotal.com
# 2. Go to your profile settings
# 3. Copy your API key
```

#### Step 2: Environment Configuration
```env
VITE_VT_API_KEY=your-virustotal-api-key
```

#### Step 3: Rate Limiting Configuration
```typescript
// VirusTotal has strict rate limits
// Free tier: 4 requests/minute
// Premium: 1000 requests/minute

const vtConfig = {
  rateLimit: {
    requests: 4,
    per: 60000, // 1 minute
  }
};
```

## 🔔 3. Multi-Channel Notifications

### Slack Integration

#### Step 1: Slack App Creation
```bash
# 1. Go to https://api.slack.com/apps
# 2. Create new app "SecOps Dashboard"
# 3. Go to Incoming Webhooks
# 4. Activate and create webhook for your channel
```

#### Step 2: Environment Configuration
```env
VITE_SLACK_WEBHOOK=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
VITE_SLACK_CHANNEL=#security-alerts
```

#### Step 3: Test Slack Notifications
```typescript
const testSlack = async () => {
  try {
    await notificationService.sendSlackNotification({
      title: 'Test Alert',
      message: 'This is a test notification from SecOps Dashboard',
      severity: 'medium',
      source: 'Test System'
    });
    console.log('Slack notification sent successfully');
  } catch (error) {
    console.error('Slack notification failed:', error);
  }
};
```

### Microsoft Teams Integration

#### Step 1: Teams Webhook Setup
```bash
# 1. Open Microsoft Teams
# 2. Go to your security channel
# 3. Click "..." > Connectors > Incoming Webhook
# 4. Configure and copy webhook URL
```

#### Step 2: Environment Configuration
```env
VITE_TEAMS_WEBHOOK=https://your-org.webhook.office.com/webhookb2/your-webhook-url
```

### Email Notifications

#### Step 1: SMTP Configuration
```env
VITE_SMTP_HOST=smtp.your-domain.com
VITE_SMTP_PORT=587
VITE_SMTP_USER=alerts@your-domain.com
VITE_SMTP_PASS=your-smtp-password
VITE_SMTP_FROM=SecOps Dashboard <alerts@your-domain.com>
```

#### Step 2: Email Template Customization
```html
<!-- Customize email templates in src/services/notifications.ts -->
<div style="background: #1e293b; color: white; padding: 20px;">
  <h1>🚨 Security Alert</h1>
  <p><strong>Severity:</strong> {{severity}}</p>
  <p><strong>Message:</strong> {{message}}</p>
  <p><strong>Time:</strong> {{timestamp}}</p>
</div>
```

## 🐳 4. Docker & Kubernetes Deployment

### Docker Compose Production Setup

#### Step 1: Production Docker Compose
```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  frontend:
    build:
      context: .
      dockerfile: Dockerfile.prod
    ports:
      - "443:443"
      - "80:80"
    environment:
      - NODE_ENV=production
    volumes:
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - backend

  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    environment:
      - NODE_ENV=production
      - MONGODB_URI=mongodb://mongodb:27017/secops
      - REDIS_URL=redis://redis:6379
    depends_on:
      - mongodb
      - redis
      - elasticsearch

  mongodb:
    image: mongo:6.0
    volumes:
      - mongodb_data:/data/db
    environment:
      - MONGO_INITDB_ROOT_USERNAME=admin
      - MONGO_INITDB_ROOT_PASSWORD=${MONGO_PASSWORD}

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
    command: redis-server --requirepass ${REDIS_PASSWORD}

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.8.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=true
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data

volumes:
  mongodb_data:
  redis_data:
  elasticsearch_data:
```

#### Step 2: SSL Certificate Setup
```bash
# Generate SSL certificates
mkdir ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ssl/private.key \
  -out ssl/certificate.crt \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=your-domain.com"

# Or use Let's Encrypt
certbot certonly --standalone -d your-domain.com
cp /etc/letsencrypt/live/your-domain.com/* ssl/
```

### Kubernetes Deployment

#### Step 1: Kubernetes Manifests
```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: secops

---
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: secops-config
  namespace: secops
data:
  NODE_ENV: "production"
  MONGODB_URI: "mongodb://mongodb:27017/secops"
  REDIS_URL: "redis://redis:6379"

---
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secops-frontend
  namespace: secops
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secops-frontend
  template:
    metadata:
      labels:
        app: secops-frontend
    spec:
      containers:
      - name: frontend
        image: secops/frontend:latest
        ports:
        - containerPort: 80
        envFrom:
        - configMapRef:
            name: secops-config
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"

---
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: secops-frontend-service
  namespace: secops
spec:
  selector:
    app: secops-frontend
  ports:
  - port: 80
    targetPort: 80
  type: LoadBalancer
```

#### Step 2: Deploy to Kubernetes
```bash
# Apply all manifests
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -n secops

# Get service URL
kubectl get svc -n secops

# Scale deployment
kubectl scale deployment secops-frontend --replicas=5 -n secops
```

## 🔐 5. Enterprise Security Setup

### JWT Configuration

#### Step 1: Generate Secure JWT Secret
```bash
# Generate strong JWT secret
openssl rand -base64 64

# Add to environment
echo "VITE_JWT_SECRET=$(openssl rand -base64 64)" >> .env
```

#### Step 2: JWT Security Settings
```typescript
// src/config/jwt.ts
export const jwtConfig = {
  secret: process.env.VITE_JWT_SECRET,
  expiresIn: '8h', // 8 hour sessions
  algorithm: 'HS256',
  issuer: 'secops-dashboard',
  audience: 'secops-users'
};
```

### Role-Based Access Control (RBAC)

#### Step 1: Define Permissions
```typescript
// src/config/permissions.ts
export const permissions = {
  soc_analyst: [
    'alerts:read',
    'alerts:acknowledge',
    'cases:read',
    'cases:create',
    'logs:read'
  ],
  incident_manager: [
    'alerts:read',
    'alerts:acknowledge',
    'alerts:assign',
    'cases:read',
    'cases:create',
    'cases:update',
    'cases:assign',
    'incidents:read',
    'incidents:create',
    'incidents:escalate',
    'logs:read',
    'reports:generate'
  ],
  admin: [
    '*' // Full access
  ]
};
```

#### Step 2: Implement Permission Middleware
```typescript
// Backend middleware for permission checking
export const requirePermission = (permission: string) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const userRole = req.user?.role;
    const userPermissions = permissions[userRole] || [];
    
    if (userPermissions.includes('*') || userPermissions.includes(permission)) {
      next();
    } else {
      res.status(403).json({ error: 'Insufficient permissions' });
    }
  };
};
```

### Audit Logging

#### Step 1: Audit Log Schema
```typescript
// src/models/AuditLog.ts
interface AuditLog {
  id: string;
  userId: string;
  action: string;
  resource: string;
  resourceId?: string;
  timestamp: Date;
  ipAddress: string;
  userAgent: string;
  success: boolean;
  details?: any;
}
```

#### Step 2: Audit Middleware
```typescript
export const auditLogger = (action: string, resource: string) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const originalSend = res.send;
    
    res.send = function(data) {
      // Log the action after response
      logAuditEvent({
        userId: req.user?.id,
        action,
        resource,
        resourceId: req.params.id,
        timestamp: new Date(),
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        success: res.statusCode < 400,
        details: { method: req.method, url: req.url }
      });
      
      return originalSend.call(this, data);
    };
    
    next();
  };
};
```

## 📊 6. Performance Monitoring

### Prometheus Setup

#### Step 1: Prometheus Configuration
```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'secops-dashboard'
    static_configs:
      - targets: ['localhost:3001']
    metrics_path: '/metrics'
    scrape_interval: 5s

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['localhost:9100']

  - job_name: 'mongodb-exporter'
    static_configs:
      - targets: ['localhost:9216']
```

#### Step 2: Application Metrics
```typescript
// src/middleware/metrics.ts
import prometheus from 'prom-client';

// Create metrics
const httpRequestDuration = new prometheus.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code']
});

const alertsProcessed = new prometheus.Counter({
  name: 'alerts_processed_total',
  help: 'Total number of alerts processed',
  labelNames: ['severity', 'source']
});

const activeUsers = new prometheus.Gauge({
  name: 'active_users_current',
  help: 'Current number of active users'
});

// Middleware to collect metrics
export const metricsMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = (Date.now() - start) / 1000;
    httpRequestDuration
      .labels(req.method, req.route?.path || req.path, res.statusCode.toString())
      .observe(duration);
  });
  
  next();
};
```

### Grafana Dashboard Setup

#### Step 1: Grafana Configuration
```yaml
# grafana/datasources/prometheus.yml
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
```

#### Step 2: SOC Dashboard JSON
```json
{
  "dashboard": {
    "title": "SecOps Dashboard Metrics",
    "panels": [
      {
        "title": "Alert Processing Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(alerts_processed_total[5m])",
            "legendFormat": "{{severity}} alerts/sec"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Active Users",
        "type": "singlestat",
        "targets": [
          {
            "expr": "active_users_current",
            "legendFormat": "Users"
          }
        ]
      }
    ]
  }
}
```

## 🚀 7. Production Deployment Checklist

### Pre-Deployment
- [ ] Environment variables configured
- [ ] SSL certificates installed
- [ ] Database migrations completed
- [ ] SIEM connections tested
- [ ] Threat intel feeds verified
- [ ] Notification channels tested
- [ ] Backup strategy implemented
- [ ] Monitoring dashboards configured

### Security Checklist
- [ ] JWT secrets are secure and rotated
- [ ] Database credentials are encrypted
- [ ] API rate limiting enabled
- [ ] CORS properly configured
- [ ] Security headers implemented
- [ ] Audit logging enabled
- [ ] User permissions tested

### Performance Checklist
- [ ] Load testing completed
- [ ] Database indexes optimized
- [ ] Caching strategy implemented
- [ ] CDN configured for static assets
- [ ] Monitoring alerts configured
- [ ] Auto-scaling rules defined

### Monitoring Checklist
- [ ] Application metrics collected
- [ ] Infrastructure monitoring enabled
- [ ] Log aggregation configured
- [ ] Alert thresholds defined
- [ ] Incident response procedures documented
- [ ] Backup and recovery tested

## 🔧 Troubleshooting

### Common Issues

#### SIEM Connection Failures
```bash
# Test network connectivity
telnet your-splunk-server 8089
curl -k https://your-elastic-cluster:9200/_cluster/health

# Check authentication
curl -H "Authorization: Bearer your-token" https://your-siem/api/test
```

#### WebSocket Connection Issues
```javascript
// Debug WebSocket connections
wsService.subscribe('connection', (status) => {
  console.log('WebSocket status:', status);
});

wsService.subscribe('error', (error) => {
  console.error('WebSocket error:', error);
});
```

#### Performance Issues
```bash
# Monitor resource usage
docker stats
kubectl top pods -n secops

# Check database performance
db.alerts.explain("executionStats").find({severity: "critical"})
```

### Log Analysis
```bash
# Application logs
docker-compose logs -f backend

# System logs
journalctl -u docker -f

# Kubernetes logs
kubectl logs -f deployment/secops-frontend -n secops
```

## 📞 Support

For additional support:
- Check the troubleshooting section
- Review application logs
- Contact your system administrator
- Create an issue in the project repository

---

This completes the production setup guide. Follow each section carefully and test thoroughly before deploying to production.