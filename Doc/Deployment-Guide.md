# Production Deployment Guide

This guide covers deploying the SOC Dashboard in various production environments with high availability, security, and scalability.

## 🏗️ Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Load Balancer │    │   Web Servers   │    │   API Servers   │
│    (NGINX)      │────│   (React App)   │────│   (Node.js)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │              ┌─────────────────┐    ┌─────────────────┐
         │              │     Redis       │    │    MongoDB      │
         │              │   (Cache/Queue) │    │  (Cases/Users)  │
         │              └─────────────────┘    └─────────────────┘
         │                       │                       │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Elasticsearch  │    │   Prometheus    │    │     Grafana     │
│   (Log Search)  │    │   (Metrics)     │    │  (Dashboards)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🐳 Docker Production Deployment

### 1. Production Docker Setup

#### Docker Compose Production Configuration
```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  # NGINX Load Balancer & SSL Termination
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
      - ./nginx/logs:/var/log/nginx
    depends_on:
      - frontend
    restart: unless-stopped
    networks:
      - secops-network

  # Frontend Application
  frontend:
    build:
      context: .
      dockerfile: Dockerfile.prod
      args:
        - NODE_ENV=production
    environment:
      - NODE_ENV=production
    volumes:
      - frontend_logs:/app/logs
    restart: unless-stopped
    networks:
      - secops-network
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 256M

  # Backend API Server
  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    environment:
      - NODE_ENV=production
      - MONGODB_URI=mongodb://mongodb:27017/secops
      - REDIS_URL=redis://redis:6379
      - ELASTICSEARCH_URL=http://elasticsearch:9200
      - JWT_SECRET=${JWT_SECRET}
      - ENCRYPTION_KEY=${ENCRYPTION_KEY}
    volumes:
      - backend_logs:/app/logs
      - ./config:/app/config:ro
    depends_on:
      - mongodb
      - redis
      - elasticsearch
    restart: unless-stopped
    networks:
      - secops-network
    deploy:
      replicas: 2
      resources:
        limits:
          cpus: '1.0'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 512M

  # MongoDB Database
  mongodb:
    image: mongo:6.0
    environment:
      - MONGO_INITDB_ROOT_USERNAME=${MONGO_ROOT_USER}
      - MONGO_INITDB_ROOT_PASSWORD=${MONGO_ROOT_PASSWORD}
      - MONGO_INITDB_DATABASE=secops
    volumes:
      - mongodb_data:/data/db
      - mongodb_config:/data/configdb
      - ./mongo/init:/docker-entrypoint-initdb.d:ro
      - ./mongo/mongod.conf:/etc/mongod.conf:ro
    command: mongod --config /etc/mongod.conf
    restart: unless-stopped
    networks:
      - secops-network
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 1G

  # Redis Cache & Queue
  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD} --appendonly yes --maxmemory 512mb --maxmemory-policy allkeys-lru
    volumes:
      - redis_data:/data
      - ./redis/redis.conf:/usr/local/etc/redis/redis.conf:ro
    restart: unless-stopped
    networks:
      - secops-network
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 256M

  # Elasticsearch for Log Storage
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.8.0
    environment:
      - node.name=es01
      - cluster.name=secops-cluster
      - discovery.type=single-node
      - bootstrap.memory_lock=true
      - "ES_JAVA_OPTS=-Xms2g -Xmx2g"
      - xpack.security.enabled=true
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data
      - ./elasticsearch/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml:ro
    restart: unless-stopped
    networks:
      - secops-network
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          cpus: '1.0'
          memory: 2G

  # Kibana for Elasticsearch Management
  kibana:
    image: docker.elastic.co/kibana/kibana:8.8.0
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=elastic
      - ELASTICSEARCH_PASSWORD=${ELASTIC_PASSWORD}
    volumes:
      - ./kibana/kibana.yml:/usr/share/kibana/config/kibana.yml:ro
    depends_on:
      - elasticsearch
    restart: unless-stopped
    networks:
      - secops-network

  # Prometheus Monitoring
  prometheus:
    image: prom/prometheus:latest
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=30d'
      - '--web.enable-lifecycle'
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ./prometheus/rules:/etc/prometheus/rules:ro
      - prometheus_data:/prometheus
    restart: unless-stopped
    networks:
      - secops-network

  # Grafana Dashboards
  grafana:
    image: grafana/grafana:latest
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
      - GF_USERS_ALLOW_SIGN_UP=false
      - GF_SECURITY_SECRET_KEY=${GRAFANA_SECRET_KEY}
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning:ro
      - ./grafana/dashboards:/var/lib/grafana/dashboards:ro
    depends_on:
      - prometheus
    restart: unless-stopped
    networks:
      - secops-network

  # Log Aggregation
  filebeat:
    image: docker.elastic.co/beats/filebeat:8.8.0
    user: root
    volumes:
      - ./filebeat/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - frontend_logs:/var/log/frontend:ro
      - backend_logs:/var/log/backend:ro
    depends_on:
      - elasticsearch
    restart: unless-stopped
    networks:
      - secops-network

volumes:
  mongodb_data:
    driver: local
  mongodb_config:
    driver: local
  redis_data:
    driver: local
  elasticsearch_data:
    driver: local
  prometheus_data:
    driver: local
  grafana_data:
    driver: local
  frontend_logs:
    driver: local
  backend_logs:
    driver: local

networks:
  secops-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

#### Production Environment Variables
```bash
# .env.prod
# Database Configuration
MONGO_ROOT_USER=admin
MONGO_ROOT_PASSWORD=your-secure-mongo-password
REDIS_PASSWORD=your-secure-redis-password
ELASTIC_PASSWORD=your-secure-elastic-password

# Application Security
JWT_SECRET=your-256-bit-jwt-secret-key
ENCRYPTION_KEY=your-256-bit-encryption-key
SESSION_SECRET=your-session-secret-key

# Monitoring
GRAFANA_PASSWORD=your-grafana-admin-password
GRAFANA_SECRET_KEY=your-grafana-secret-key

# External Services
SPLUNK_TOKEN=your-splunk-token
ELASTIC_API_KEY=your-elastic-api-key
MISP_API_KEY=your-misp-api-key
VT_API_KEY=your-virustotal-api-key

# Notification Services
SLACK_WEBHOOK=your-slack-webhook-url
TEAMS_WEBHOOK=your-teams-webhook-url
SMTP_PASSWORD=your-smtp-password
```

### 2. SSL/TLS Configuration

#### NGINX SSL Configuration
```nginx
# nginx/nginx.conf
events {
    worker_connections 1024;
}

http {
    upstream frontend {
        server frontend:3000;
    }
    
    upstream backend {
        server backend:3001;
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=auth:10m rate=1r/s;

    # SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' ws: wss:;" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # HTTP to HTTPS Redirect
    server {
        listen 80;
        server_name your-domain.com;
        return 301 https://$server_name$request_uri;
    }

    # Main HTTPS Server
    server {
        listen 443 ssl http2;
        server_name your-domain.com;

        ssl_certificate /etc/nginx/ssl/certificate.crt;
        ssl_certificate_key /etc/nginx/ssl/private.key;

        # Frontend
        location / {
            proxy_pass http://frontend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_cache_bypass $http_upgrade;
        }

        # API Routes
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Authentication Routes (Stricter Rate Limiting)
        location /api/auth/ {
            limit_req zone=auth burst=5 nodelay;
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # WebSocket Support
        location /socket.io/ {
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        # Health Check
        location /health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }
    }
}
```

### 3. Database Configuration

#### MongoDB Production Configuration
```yaml
# mongo/mongod.conf
storage:
  dbPath: /data/db
  journal:
    enabled: true
  wiredTiger:
    engineConfig:
      cacheSizeGB: 1
      journalCompressor: snappy
      directoryForIndexes: false
    collectionConfig:
      blockCompressor: snappy
    indexConfig:
      prefixCompression: true

systemLog:
  destination: file
  logAppend: true
  path: /var/log/mongodb/mongod.log
  logRotate: reopen

net:
  port: 27017
  bindIp: 0.0.0.0

security:
  authorization: enabled

replication:
  replSetName: secops-rs

operationProfiling:
  slowOpThresholdMs: 100
  mode: slowOp
```

#### MongoDB Initialization Script
```javascript
// mongo/init/01-init-users.js
db = db.getSiblingDB('secops');

db.createUser({
  user: 'secops_app',
  pwd: 'your-app-password',
  roles: [
    {
      role: 'readWrite',
      db: 'secops'
    }
  ]
});

// Create indexes for performance
db.alerts.createIndex({ "timestamp": -1 });
db.alerts.createIndex({ "severity": 1, "status": 1 });
db.alerts.createIndex({ "source": 1, "timestamp": -1 });
db.cases.createIndex({ "createdAt": -1 });
db.cases.createIndex({ "assignee": 1, "status": 1 });
db.incidents.createIndex({ "timestamp": -1 });
db.users.createIndex({ "email": 1 }, { unique: true });
```

## ☸️ Kubernetes Deployment

### 1. Kubernetes Manifests

#### Namespace and ConfigMap
```yaml
# k8s/01-namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: secops
  labels:
    name: secops

---
# k8s/02-configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: secops-config
  namespace: secops
data:
  NODE_ENV: "production"
  MONGODB_URI: "mongodb://mongodb:27017/secops"
  REDIS_URL: "redis://redis:6379"
  ELASTICSEARCH_URL: "http://elasticsearch:9200"

---
# k8s/03-secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: secops-secrets
  namespace: secops
type: Opaque
data:
  jwt-secret: <base64-encoded-jwt-secret>
  mongo-password: <base64-encoded-mongo-password>
  redis-password: <base64-encoded-redis-password>
  elastic-password: <base64-encoded-elastic-password>
```

#### Frontend Deployment
```yaml
# k8s/04-frontend-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secops-frontend
  namespace: secops
  labels:
    app: secops-frontend
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
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 80
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 80
          initialDelaySeconds: 5
          periodSeconds: 5

---
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
  type: ClusterIP
```

#### Backend Deployment
```yaml
# k8s/05-backend-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secops-backend
  namespace: secops
  labels:
    app: secops-backend
spec:
  replicas: 2
  selector:
    matchLabels:
      app: secops-backend
  template:
    metadata:
      labels:
        app: secops-backend
    spec:
      containers:
      - name: backend
        image: secops/backend:latest
        ports:
        - containerPort: 3001
        envFrom:
        - configMapRef:
            name: secops-config
        env:
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: secops-secrets
              key: jwt-secret
        - name: MONGO_PASSWORD
          valueFrom:
            secretKeyRef:
              name: secops-secrets
              key: mongo-password
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /api/health
            port: 3001
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/health
            port: 3001
          initialDelaySeconds: 10
          periodSeconds: 5

---
apiVersion: v1
kind: Service
metadata:
  name: secops-backend-service
  namespace: secops
spec:
  selector:
    app: secops-backend
  ports:
  - port: 3001
    targetPort: 3001
  type: ClusterIP
```

#### Database StatefulSets
```yaml
# k8s/06-mongodb-statefulset.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: mongodb
  namespace: secops
spec:
  serviceName: mongodb
  replicas: 1
  selector:
    matchLabels:
      app: mongodb
  template:
    metadata:
      labels:
        app: mongodb
    spec:
      containers:
      - name: mongodb
        image: mongo:6.0
        ports:
        - containerPort: 27017
        env:
        - name: MONGO_INITDB_ROOT_USERNAME
          value: "admin"
        - name: MONGO_INITDB_ROOT_PASSWORD
          valueFrom:
            secretKeyRef:
              name: secops-secrets
              key: mongo-password
        volumeMounts:
        - name: mongodb-data
          mountPath: /data/db
        resources:
          requests:
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
  volumeClaimTemplates:
  - metadata:
      name: mongodb-data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 20Gi

---
apiVersion: v1
kind: Service
metadata:
  name: mongodb
  namespace: secops
spec:
  selector:
    app: mongodb
  ports:
  - port: 27017
    targetPort: 27017
  type: ClusterIP
```

#### Ingress Configuration
```yaml
# k8s/07-ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: secops-ingress
  namespace: secops
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/rate-limit-window: "1m"
spec:
  tls:
  - hosts:
    - your-domain.com
    secretName: secops-tls
  rules:
  - host: your-domain.com
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: secops-backend-service
            port:
              number: 3001
      - path: /
        pathType: Prefix
        backend:
          service:
            name: secops-frontend-service
            port:
              number: 80
```

### 2. Horizontal Pod Autoscaling
```yaml
# k8s/08-hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: secops-frontend-hpa
  namespace: secops
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: secops-frontend
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80

---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: secops-backend-hpa
  namespace: secops
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: secops-backend
  minReplicas: 2
  maxReplicas: 8
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

## 🔧 Deployment Scripts

### 1. Docker Deployment Script
```bash
#!/bin/bash
# deploy-docker.sh

set -e

echo "🚀 Starting SOC Dashboard Production Deployment"

# Check prerequisites
command -v docker >/dev/null 2>&1 || { echo "Docker is required but not installed. Aborting." >&2; exit 1; }
command -v docker-compose >/dev/null 2>&1 || { echo "Docker Compose is required but not installed. Aborting." >&2; exit 1; }

# Load environment variables
if [ -f .env.prod ]; then
    export $(cat .env.prod | grep -v '#' | xargs)
else
    echo "❌ .env.prod file not found. Please create it from .env.example"
    exit 1
fi

# Create necessary directories
mkdir -p nginx/ssl nginx/logs
mkdir -p prometheus grafana/dashboards
mkdir -p elasticsearch/data mongodb/data redis/data

# Generate SSL certificates if they don't exist
if [ ! -f nginx/ssl/certificate.crt ]; then
    echo "🔐 Generating SSL certificates..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout nginx/ssl/private.key \
        -out nginx/ssl/certificate.crt \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
fi

# Build and start services
echo "🏗️ Building and starting services..."
docker-compose -f docker-compose.prod.yml build --no-cache
docker-compose -f docker-compose.prod.yml up -d

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."
sleep 30

# Health checks
echo "🏥 Performing health checks..."
services=("nginx:80" "backend:3001" "mongodb:27017" "redis:6379" "elasticsearch:9200")

for service in "${services[@]}"; do
    IFS=':' read -r name port <<< "$service"
    if docker-compose -f docker-compose.prod.yml exec -T $name nc -z localhost $port; then
        echo "✅ $name is healthy"
    else
        echo "❌ $name is not responding"
        exit 1
    fi
done

# Initialize database
echo "🗄️ Initializing database..."
docker-compose -f docker-compose.prod.yml exec -T mongodb mongo --eval "
db = db.getSiblingDB('secops');
db.createUser({
    user: 'secops_app',
    pwd: '$MONGO_APP_PASSWORD',
    roles: [{ role: 'readWrite', db: 'secops' }]
});
"

# Setup Elasticsearch indices
echo "🔍 Setting up Elasticsearch indices..."
curl -X PUT "localhost:9200/security-alerts" -H 'Content-Type: application/json' -d'
{
  "mappings": {
    "properties": {
      "@timestamp": { "type": "date" },
      "severity": { "type": "keyword" },
      "source": { "type": "keyword" },
      "message": { "type": "text" },
      "source_ip": { "type": "ip" },
      "destination_ip": { "type": "ip" }
    }
  }
}'

echo "🎉 Deployment completed successfully!"
echo "📊 Dashboard: https://localhost"
echo "📈 Grafana: http://localhost:3000 (admin/$GRAFANA_PASSWORD)"
echo "🔍 Kibana: http://localhost:5601"
```

### 2. Kubernetes Deployment Script
```bash
#!/bin/bash
# deploy-k8s.sh

set -e

echo "🚀 Starting Kubernetes Deployment"

# Check prerequisites
command -v kubectl >/dev/null 2>&1 || { echo "kubectl is required but not installed. Aborting." >&2; exit 1; }
command -v helm >/dev/null 2>&1 || { echo "Helm is required but not installed. Aborting." >&2; exit 1; }

# Check cluster connection
if ! kubectl cluster-info >/dev/null 2>&1; then
    echo "❌ Cannot connect to Kubernetes cluster"
    exit 1
fi

# Create namespace
echo "📦 Creating namespace..."
kubectl apply -f k8s/01-namespace.yaml

# Create secrets
echo "🔐 Creating secrets..."
kubectl create secret generic secops-secrets \
    --from-literal=jwt-secret="$JWT_SECRET" \
    --from-literal=mongo-password="$MONGO_PASSWORD" \
    --from-literal=redis-password="$REDIS_PASSWORD" \
    --from-literal=elastic-password="$ELASTIC_PASSWORD" \
    --namespace=secops \
    --dry-run=client -o yaml | kubectl apply -f -

# Apply all manifests
echo "🏗️ Applying Kubernetes manifests..."
kubectl apply -f k8s/

# Wait for deployments
echo "⏳ Waiting for deployments to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment/secops-frontend -n secops
kubectl wait --for=condition=available --timeout=300s deployment/secops-backend -n secops

# Install monitoring stack with Helm
echo "📊 Installing monitoring stack..."
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

helm install prometheus prometheus-community/kube-prometheus-stack \
    --namespace secops \
    --set grafana.adminPassword="$GRAFANA_PASSWORD" \
    --set grafana.persistence.enabled=true \
    --set prometheus.prometheusSpec.retention=30d

# Get service URLs
echo "🌐 Getting service information..."
kubectl get services -n secops
kubectl get ingress -n secops

echo "🎉 Kubernetes deployment completed!"
echo "Use 'kubectl port-forward' to access services locally"
```

## 📊 Monitoring and Alerting

### 1. Prometheus Configuration
```yaml
# prometheus/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "rules/*.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  - job_name: 'secops-backend'
    static_configs:
      - targets: ['backend:3001']
    metrics_path: '/metrics'
    scrape_interval: 5s

  - job_name: 'secops-frontend'
    static_configs:
      - targets: ['frontend:80']
    metrics_path: '/metrics'
    scrape_interval: 10s

  - job_name: 'mongodb'
    static_configs:
      - targets: ['mongodb-exporter:9216']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']

  - job_name: 'elasticsearch'
    static_configs:
      - targets: ['elasticsearch-exporter:9114']

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
```

### 2. Alerting Rules
```yaml
# prometheus/rules/secops-alerts.yml
groups:
  - name: secops.rules
    rules:
    - alert: HighErrorRate
      expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
      for: 5m
      labels:
        severity: critical
      annotations:
        summary: "High error rate detected"
        description: "Error rate is {{ $value }} errors per second"

    - alert: HighResponseTime
      expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 1
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "High response time detected"
        description: "95th percentile response time is {{ $value }} seconds"

    - alert: DatabaseConnectionFailure
      expr: up{job="mongodb"} == 0
      for: 1m
      labels:
        severity: critical
      annotations:
        summary: "Database connection failure"
        description: "MongoDB is not responding"

    - alert: HighMemoryUsage
      expr: (node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes > 0.9
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "High memory usage"
        description: "Memory usage is {{ $value | humanizePercentage }}"

    - alert: DiskSpaceLow
      expr: (node_filesystem_size_bytes - node_filesystem_free_bytes) / node_filesystem_size_bytes > 0.8
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "Disk space low"
        description: "Disk usage is {{ $value | humanizePercentage }}"
```

## 🔒 Security Hardening

### 1. Container Security
```dockerfile
# Dockerfile.prod - Security hardened
FROM node:18-alpine AS builder

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nextjs -u 1001

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

COPY . .
RUN npm run build

# Production stage
FROM nginx:alpine

# Install security updates
RUN apk update && apk upgrade && apk add --no-cache curl

# Remove unnecessary packages
RUN apk del --purge wget

# Create non-root user for nginx
RUN adduser -D -s /bin/sh nginx-user

# Copy built assets
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Set proper permissions
RUN chown -R nginx-user:nginx-user /usr/share/nginx/html
RUN chown -R nginx-user:nginx-user /var/cache/nginx
RUN chown -R nginx-user:nginx-user /var/log/nginx

# Switch to non-root user
USER nginx-user

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost/health || exit 1

CMD ["nginx", "-g", "daemon off;"]
```

### 2. Network Security
```yaml
# k8s/network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: secops-network-policy
  namespace: secops
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    - podSelector:
        matchLabels:
          app: secops-frontend
    - podSelector:
        matchLabels:
          app: secops-backend
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: mongodb
    ports:
    - protocol: TCP
      port: 27017
  - to:
    - podSelector:
        matchLabels:
          app: redis
    ports:
    - protocol: TCP
      port: 6379
  - to:
    - podSelector:
        matchLabels:
          app: elasticsearch
    ports:
    - protocol: TCP
      port: 9200
```

This completes the comprehensive production deployment guide with Docker, Kubernetes, monitoring, and security configurations.