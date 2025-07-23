# SecOps - Production Security Operations Center Dashboard

A comprehensive, production-ready Security Operations Center (SOC) dashboard built with React, TypeScript, and Tailwind CSS. This application provides real-time security monitoring, incident management, and threat intelligence capabilities.

## 🚀 Features

### Core Security Operations
- **Real-time Alert Dashboard** - Live security alerts with severity-based prioritization
- **Incident Timeline** - Event correlation and incident tracking
- **Case Management** - Workflow-driven investigation management
- **Live Log Feed** - Real-time security event streaming
- **KPI Metrics** - MTTR, detection rates, and performance analytics
- **User Management** - Role-based access control (SOC Analyst, Incident Manager, Admin)

### Production Integrations
- **SIEM Integration** - Splunk, Elasticsearch, QRadar support
- **Threat Intelligence** - MISP, AlienVault OTX, VirusTotal integration
- **Notifications** - Slack, Microsoft Teams, Email alerts
- **Real-time Updates** - WebSocket-based live data streaming
- **Authentication** - JWT-based secure authentication

### Advanced Features
- **IOC Enrichment** - Automatic threat intelligence lookup
- **Automated Response** - Configurable response triggers
- **GeoIP Mapping** - IP address geolocation and visualization
- **Export Capabilities** - Data export for compliance and reporting

## 🛠 Tech Stack

### Frontend
- **React 18** with TypeScript
- **Tailwind CSS** for styling
- **Lucide React** for icons
- **WebSocket** for real-time updates

### Backend (Production Setup)
- **Node.js** with Express
- **MongoDB** for case/incident data
- **Redis** for caching and queues
- **Elasticsearch** for log storage and search

### Infrastructure
- **Docker & Docker Compose** for containerization
- **NGINX** reverse proxy with SSL
- **Prometheus & Grafana** for monitoring

## 🚀 Quick Start

### Development Mode
```bash
# Clone the repository
git clone <repository-url>
cd secops-dashboard

# Install dependencies
npm install

# Start development server
npm run dev
```

### Production Deployment
```bash
# Copy environment configuration
cp .env.example .env

# Edit .env with your configuration
nano .env

# Start with Docker Compose
docker-compose up -d

# Access the dashboard
open http://localhost
```

## 🔧 Configuration

### Environment Variables
Create a `.env` file based on `.env.example`:

```env
# API Configuration
VITE_API_BASE_URL=http://localhost:3001/api
VITE_WS_URL=ws://localhost:3001

# SIEM Integration
VITE_SPLUNK_URL=https://your-splunk-instance.com
VITE_SPLUNK_TOKEN=your-splunk-token
VITE_ELASTIC_URL=https://your-elasticsearch-instance.com
VITE_ELASTIC_API_KEY=your-elastic-api-key

# Threat Intelligence
VITE_MISP_URL=https://your-misp-instance.com
VITE_MISP_API_KEY=your-misp-api-key
VITE_OTX_API_KEY=your-otx-api-key
VITE_VT_API_KEY=your-virustotal-api-key

# Notifications
VITE_SLACK_WEBHOOK=https://hooks.slack.com/services/your/webhook/url
VITE_TEAMS_WEBHOOK=https://your-teams-webhook-url.com
```

### SIEM Integration Setup

#### Splunk
1. Create a new app in Splunk
2. Generate an authentication token
3. Configure search permissions
4. Update `VITE_SPLUNK_URL` and `VITE_SPLUNK_TOKEN`

#### Elasticsearch
1. Create an API key with search permissions
2. Configure index patterns for security logs
3. Update `VITE_ELASTIC_URL` and `VITE_ELASTIC_API_KEY`

#### QRadar
1. Generate an authorized service token
2. Configure API access permissions
3. Update `VITE_QRADAR_URL` and `VITE_QRADAR_TOKEN`

## 🔐 Authentication & Authorization

### Demo Accounts
- **SOC Analyst**: `analyst@secops.com` / `analyst123`
- **Incident Manager**: `manager@secops.com` / `manager123`
- **System Administrator**: `admin@secops.com` / `admin123`

### Role Permissions
- **SOC Analyst**: View alerts, acknowledge alerts, create cases
- **Incident Manager**: All analyst permissions + assign cases, escalate incidents
- **Admin**: Full system access + user management

## 📊 Monitoring & Observability

### Application Metrics
- Response times and error rates
- Alert processing performance
- User activity and session metrics
- System resource utilization

### Security Metrics
- Mean Time to Detection (MTTD)
- Mean Time to Response (MTTR)
- Alert volume and severity distribution
- False positive rates

### Health Checks
- `/health` - Application health status
- WebSocket connection monitoring
- External service connectivity

## 🔧 API Integration

### Alert Management
```typescript
// Get alerts with filtering
const alerts = await apiClient.getAlerts({
  severity: 'critical',
  status: 'new',
  limit: 50
});

// Acknowledge an alert
await apiClient.acknowledgeAlert(alertId, userId);

// Update alert status
await apiClient.updateAlertStatus(alertId, 'investigating');
```

### Threat Intelligence
```typescript
// Enrich IOC with threat intelligence
const threatData = await threatIntelService.enrichIOC('192.168.1.100', 'ip');

// Bulk IOC enrichment
const results = await threatIntelService.enrichIOCs([
  { value: '192.168.1.100', type: 'ip' },
  { value: 'malicious.com', type: 'domain' }
]);
```

### Real-time Updates
```typescript
// Subscribe to real-time alerts
wsService.subscribe('alert', (alert) => {
  console.log('New alert received:', alert);
});

// Subscribe to connection status
wsService.subscribe('connection', (status) => {
  console.log('Connection status:', status);
});
```

## 🚀 Deployment Options

### Docker Deployment
```bash
# Build and run with Docker Compose
docker-compose up -d

# Scale services
docker-compose up -d --scale backend=3

# View logs
docker-compose logs -f
```

### Kubernetes Deployment
```bash
# Apply Kubernetes manifests
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -n secops

# Access via port-forward
kubectl port-forward svc/secops-frontend 3000:80
```

### Cloud Deployment
- **AWS**: ECS, EKS, or Elastic Beanstalk
- **Azure**: Container Instances or AKS
- **GCP**: Cloud Run or GKE

## 🔒 Security Considerations

### Data Protection
- All sensitive data encrypted at rest and in transit
- JWT tokens with configurable expiration
- Rate limiting on API endpoints
- Input validation and sanitization

### Network Security
- HTTPS/TLS encryption
- CORS configuration
- CSP headers for XSS protection
- Secure WebSocket connections

### Access Control
- Role-based permissions
- Session management
- Audit logging
- Multi-factor authentication support

## 📈 Performance Optimization

### Frontend
- Code splitting and lazy loading
- Efficient re-rendering with React hooks
- Optimized bundle size
- CDN integration for static assets

### Backend
- Connection pooling
- Redis caching
- Database indexing
- Horizontal scaling support

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue on GitHub
- Check the documentation
- Contact the development team

## 🗺 Roadmap

### Upcoming Features
- Machine learning-based anomaly detection
- Advanced threat hunting capabilities
- Mobile application
- API rate limiting and throttling
- Advanced reporting and dashboards
- Integration with additional SIEM platforms

### Performance Improvements
- Real-time data streaming optimization
- Enhanced caching strategies
- Database query optimization
- UI/UX enhancements