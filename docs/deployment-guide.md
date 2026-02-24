# AADE Deployment Guide

## Overview

This guide covers deploying the Adaptive Risk-Based Authentication & Device Trust Engine (AADE) to production environments. It includes infrastructure requirements, deployment strategies, and scaling considerations.

## Table of Contents

- [Infrastructure Requirements](#infrastructure-requirements)
- [Deployment Options](#deployment-options)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Cloud Deployments](#cloud-deployments)
- [Scaling Considerations](#scaling-considerations)
- [Monitoring and Observability](#monitoring-and-observability)
- [Security Hardening](#security-hardening)
- [Backup and Recovery](#backup-and-recovery)
- [Performance Tuning](#performance-tuning)

---

## Infrastructure Requirements

### Minimum Requirements (Single Instance)

- **CPU**: 2 cores
- **RAM**: 4 GB
- **Storage**: 20 GB SSD
- **Network**: 100 Mbps
- **OS**: Linux (Ubuntu 20.04+, CentOS 8+, or similar)

### Recommended Production Setup

- **Application Servers**: 3+ instances (for high availability)
- **CPU**: 4 cores per instance
- **RAM**: 8 GB per instance
- **Storage**: 50 GB SSD per instance
- **Network**: 1 Gbps

### Database Requirements

**PostgreSQL 14+**:
- **CPU**: 4 cores
- **RAM**: 16 GB
- **Storage**: 100 GB SSD (with room for growth)
- **IOPS**: 3000+ (for optimal performance)

**Redis 6+**:
- **CPU**: 2 cores
- **RAM**: 4 GB
- **Storage**: 10 GB SSD
- **Persistence**: AOF or RDB enabled

### Load Balancer

- **Type**: Application Load Balancer (Layer 7)
- **SSL/TLS**: Required for production
- **Health Checks**: HTTP GET /health
- **Session Affinity**: Not required (stateless design)

---

## Deployment Options

### Option 1: Traditional VM Deployment

Deploy AADE on virtual machines with systemd service management.

### Option 2: Docker Deployment

Deploy AADE as Docker containers for consistency and portability.

### Option 3: Kubernetes Deployment

Deploy AADE on Kubernetes for orchestration, scaling, and high availability.

### Option 4: Serverless Deployment

Deploy AADE on serverless platforms (AWS Lambda, Google Cloud Functions) with API Gateway.

---

## Docker Deployment

### Dockerfile

Create a `Dockerfile` in the project root:

```dockerfile
# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY . .

# Build TypeScript
RUN npm run build

# Production stage
FROM node:20-alpine

WORKDIR /app

# Install dumb-init for proper signal handling
RUN apk add --no-cache dumb-init

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Copy built application
COPY --from=builder --chown=nodejs:nodejs /app/dist ./dist
COPY --from=builder --chown=nodejs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nodejs:nodejs /app/package*.json ./

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=40s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Start application
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/index.js"]
```

### Docker Compose

Create a `docker-compose.yml` for local development and testing:

```yaml
version: '3.8'

services:
  aade:
    build: .
    ports:
      - "3000:3000"
    environment:
      NODE_ENV: production
      PORT: 3000
      DB_HOST: postgres
      DB_PORT: 5432
      DB_NAME: aade_db
      DB_USER: postgres
      DB_PASSWORD: ${DB_PASSWORD}
      REDIS_HOST: redis
      REDIS_PORT: 6379
      JWT_ACCESS_SECRET: ${JWT_ACCESS_SECRET}
      JWT_REFRESH_SECRET: ${JWT_REFRESH_SECRET}
    depends_on:
      - postgres
      - redis
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "node", "-e", "require('http').get('http://localhost:3000/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"]
      interval: 30s
      timeout: 3s
      retries: 3

  postgres:
    image: postgres:14-alpine
    environment:
      POSTGRES_DB: aade_db
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./migrations:/docker-entrypoint-initdb.d
    ports:
      - "5432:5432"
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:6-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 3

volumes:
  postgres_data:
  redis_data:
```

### Build and Run

```bash
# Build image
docker build -t aade:latest .

# Run with docker-compose
docker-compose up -d

# View logs
docker-compose logs -f aade

# Stop services
docker-compose down
```

### Production Docker Deployment

```bash
# Build for production
docker build -t aade:1.0.0 .

# Tag for registry
docker tag aade:1.0.0 your-registry.com/aade:1.0.0

# Push to registry
docker push your-registry.com/aade:1.0.0

# Run on production server
docker run -d \
  --name aade \
  --restart unless-stopped \
  -p 3000:3000 \
  -e NODE_ENV=production \
  -e DB_HOST=your-db-host \
  -e REDIS_HOST=your-redis-host \
  --env-file .env.production \
  your-registry.com/aade:1.0.0
```

---

## Kubernetes Deployment

### Prerequisites

- Kubernetes cluster (1.20+)
- kubectl configured
- Helm 3+ (optional but recommended)

### Kubernetes Manifests

#### 1. Namespace

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: aade
```

#### 2. ConfigMap

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: aade-config
  namespace: aade
data:
  NODE_ENV: "production"
  PORT: "3000"
  DB_HOST: "postgres-service"
  DB_PORT: "5432"
  DB_NAME: "aade_db"
  REDIS_HOST: "redis-service"
  REDIS_PORT: "6379"
  LOG_LEVEL: "info"
```

#### 3. Secrets

```yaml
# secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: aade-secrets
  namespace: aade
type: Opaque
stringData:
  DB_PASSWORD: "your-db-password"
  JWT_ACCESS_SECRET: "your-jwt-access-secret"
  JWT_REFRESH_SECRET: "your-jwt-refresh-secret"
  REDIS_PASSWORD: "your-redis-password"
```

#### 4. Deployment

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: aade
  namespace: aade
  labels:
    app: aade
spec:
  replicas: 3
  selector:
    matchLabels:
      app: aade
  template:
    metadata:
      labels:
        app: aade
    spec:
      containers:
      - name: aade
        image: your-registry.com/aade:1.0.0
        ports:
        - containerPort: 3000
          name: http
        envFrom:
        - configMapRef:
            name: aade-config
        - secretRef:
            name: aade-secrets
        resources:
          requests:
            cpu: 500m
            memory: 512Mi
          limits:
            cpu: 2000m
            memory: 2Gi
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 3
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 10
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: app
                  operator: In
                  values:
                  - aade
              topologyKey: kubernetes.io/hostname
```

#### 5. Service

```yaml
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: aade-service
  namespace: aade
spec:
  type: ClusterIP
  selector:
    app: aade
  ports:
  - port: 80
    targetPort: 3000
    protocol: TCP
    name: http
```

#### 6. Ingress

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: aade-ingress
  namespace: aade
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/rate-limit: "100"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - api.example.com
    secretName: aade-tls
  rules:
  - host: api.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: aade-service
            port:
              number: 80
```

#### 7. HorizontalPodAutoscaler

```yaml
# hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: aade-hpa
  namespace: aade
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: aade
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
```

### Deploy to Kubernetes

```bash
# Create namespace
kubectl apply -f namespace.yaml

# Create secrets (use kubectl create secret or sealed-secrets)
kubectl create secret generic aade-secrets \
  --from-literal=DB_PASSWORD=your-password \
  --from-literal=JWT_ACCESS_SECRET=your-secret \
  --from-literal=JWT_REFRESH_SECRET=your-secret \
  -n aade

# Apply configurations
kubectl apply -f configmap.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
kubectl apply -f ingress.yaml
kubectl apply -f hpa.yaml

# Check deployment status
kubectl get pods -n aade
kubectl get svc -n aade
kubectl get ingress -n aade

# View logs
kubectl logs -f deployment/aade -n aade

# Scale manually
kubectl scale deployment aade --replicas=5 -n aade
```

### Helm Chart

Create a Helm chart for easier deployment:

```bash
# Create chart structure
helm create aade-chart

# Install chart
helm install aade ./aade-chart \
  --namespace aade \
  --create-namespace \
  --set image.tag=1.0.0 \
  --set replicaCount=3

# Upgrade
helm upgrade aade ./aade-chart \
  --namespace aade \
  --set image.tag=1.1.0

# Rollback
helm rollback aade 1 --namespace aade
```

---

## Cloud Deployments

### AWS Deployment

#### Using ECS (Elastic Container Service)

```bash
# Create ECS cluster
aws ecs create-cluster --cluster-name aade-cluster

# Create task definition
aws ecs register-task-definition --cli-input-json file://task-definition.json

# Create service
aws ecs create-service \
  --cluster aade-cluster \
  --service-name aade-service \
  --task-definition aade:1 \
  --desired-count 3 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx],securityGroups=[sg-xxx],assignPublicIp=ENABLED}"
```

#### Using EKS (Elastic Kubernetes Service)

```bash
# Create EKS cluster
eksctl create cluster \
  --name aade-cluster \
  --region us-east-1 \
  --nodegroup-name standard-workers \
  --node-type t3.medium \
  --nodes 3 \
  --nodes-min 3 \
  --nodes-max 10

# Deploy to EKS
kubectl apply -f k8s/
```

### Google Cloud Platform

#### Using Cloud Run

```bash
# Build and push image
gcloud builds submit --tag gcr.io/PROJECT_ID/aade

# Deploy to Cloud Run
gcloud run deploy aade \
  --image gcr.io/PROJECT_ID/aade \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --min-instances 3 \
  --max-instances 10 \
  --cpu 2 \
  --memory 2Gi
```

#### Using GKE (Google Kubernetes Engine)

```bash
# Create GKE cluster
gcloud container clusters create aade-cluster \
  --num-nodes 3 \
  --machine-type n1-standard-2 \
  --region us-central1

# Deploy to GKE
kubectl apply -f k8s/
```

### Azure Deployment

#### Using Azure Container Instances

```bash
# Create resource group
az group create --name aade-rg --location eastus

# Create container instance
az container create \
  --resource-group aade-rg \
  --name aade \
  --image your-registry.azurecr.io/aade:1.0.0 \
  --cpu 2 \
  --memory 4 \
  --ports 3000 \
  --environment-variables NODE_ENV=production
```

#### Using AKS (Azure Kubernetes Service)

```bash
# Create AKS cluster
az aks create \
  --resource-group aade-rg \
  --name aade-cluster \
  --node-count 3 \
  --node-vm-size Standard_D2s_v3 \
  --enable-managed-identity

# Deploy to AKS
kubectl apply -f k8s/
```

---

## Scaling Considerations

### Horizontal Scaling

AADE is designed to scale horizontally:

1. **Stateless Design**: No session state stored in application memory
2. **Distributed Caching**: Redis for shared session data
3. **Database Connection Pooling**: Efficient database connections
4. **Load Balancing**: Round-robin or least-connections

**Scaling Strategy**:
- Start with 3 instances for high availability
- Scale to 5-10 instances for moderate load (1000-5000 req/s)
- Scale to 10+ instances for high load (5000+ req/s)

### Vertical Scaling

Increase resources per instance:

- **CPU**: 2-4 cores per instance
- **RAM**: 4-8 GB per instance
- **Network**: 1 Gbps+ for high throughput

### Database Scaling

**PostgreSQL**:
- Use read replicas for read-heavy workloads
- Implement connection pooling (PgBouncer)
- Partition large tables (audit_logs, risk_evaluations)
- Consider managed services (AWS RDS, Google Cloud SQL)

**Redis**:
- Use Redis Cluster for horizontal scaling
- Enable persistence (AOF or RDB)
- Consider managed services (AWS ElastiCache, Google Memorystore)

### Auto-Scaling Configuration

**Kubernetes HPA**:
```yaml
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
```

**AWS Auto Scaling**:
```bash
aws autoscaling create-auto-scaling-group \
  --auto-scaling-group-name aade-asg \
  --min-size 3 \
  --max-size 10 \
  --desired-capacity 3 \
  --target-group-arns arn:aws:elasticloadbalancing:... \
  --health-check-type ELB \
  --health-check-grace-period 300
```

---

## Monitoring and Observability

### Metrics Collection

AADE exposes Prometheus metrics at `/metrics`:

```yaml
# prometheus.yaml
scrape_configs:
  - job_name: 'aade'
    static_configs:
      - targets: ['aade-service:3000']
    metrics_path: '/metrics'
```

**Key Metrics**:
- `http_requests_total`: Total HTTP requests
- `http_request_duration_seconds`: Request latency
- `auth_attempts_total`: Authentication attempts
- `risk_evaluation_duration_seconds`: Risk evaluation latency
- `session_creation_total`: Session creations
- `token_refresh_total`: Token refreshes

### Logging

Configure structured logging:

```javascript
// Winston logger configuration
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
});
```

**Log Aggregation**:
- Use ELK Stack (Elasticsearch, Logstash, Kibana)
- Use Loki + Grafana
- Use cloud-native solutions (AWS CloudWatch, Google Cloud Logging)

### Health Checks

**Liveness Probe**: `/health`
- Checks if application is running
- Returns 200 OK if healthy

**Readiness Probe**: `/ready`
- Checks if application can serve traffic
- Verifies database and Redis connectivity

### Alerting

Configure alerts for:
- High error rate (>5%)
- High latency (>500ms p95)
- Database connection failures
- Redis connection failures
- High CPU/memory usage (>80%)
- Failed authentication rate spike

**Example Prometheus Alert**:
```yaml
groups:
- name: aade
  rules:
  - alert: HighErrorRate
    expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.05
    for: 5m
    annotations:
      summary: "High error rate detected"
```

---

## Security Hardening

### Network Security

1. **Use HTTPS/TLS**: Always use TLS 1.2+ in production
2. **Firewall Rules**: Restrict access to database and Redis
3. **VPC/Private Network**: Deploy in private network
4. **WAF**: Use Web Application Firewall (AWS WAF, Cloudflare)

### Application Security

1. **Environment Variables**: Never commit secrets to version control
2. **Secret Management**: Use secret managers (AWS Secrets Manager, HashiCorp Vault)
3. **Rate Limiting**: Implement at load balancer and application level
4. **Input Validation**: Validate all inputs server-side
5. **CORS**: Configure appropriate CORS policies

### Database Security

1. **Encryption at Rest**: Enable database encryption
2. **Encryption in Transit**: Use SSL/TLS for connections
3. **Least Privilege**: Use separate database users with minimal permissions
4. **Regular Backups**: Automated daily backups with retention policy

### Container Security

1. **Non-Root User**: Run containers as non-root user
2. **Minimal Base Image**: Use Alpine or distroless images
3. **Vulnerability Scanning**: Scan images for vulnerabilities
4. **Image Signing**: Sign and verify container images

---

## Backup and Recovery

### Database Backups

**Automated Backups**:
```bash
# PostgreSQL backup script
#!/bin/bash
BACKUP_DIR="/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
pg_dump -h $DB_HOST -U $DB_USER $DB_NAME | gzip > $BACKUP_DIR/aade_$TIMESTAMP.sql.gz

# Retain last 30 days
find $BACKUP_DIR -name "aade_*.sql.gz" -mtime +30 -delete
```

**Restore**:
```bash
gunzip -c aade_20240115_120000.sql.gz | psql -h $DB_HOST -U $DB_USER $DB_NAME
```

### Redis Backups

Enable persistence:
```bash
# redis.conf
save 900 1
save 300 10
save 60 10000
appendonly yes
```

### Disaster Recovery

1. **Multi-Region Deployment**: Deploy in multiple regions
2. **Database Replication**: Use streaming replication
3. **Backup Testing**: Regularly test backup restoration
4. **Runbook**: Document recovery procedures

---

## Performance Tuning

### Application Tuning

1. **Connection Pooling**: Configure appropriate pool sizes
```javascript
// PostgreSQL pool configuration
const pool = new Pool({
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000
});
```

2. **Caching**: Use Redis for frequently accessed data
3. **Async Operations**: Use async/await for I/O operations
4. **Compression**: Enable gzip compression for responses

### Database Tuning

```sql
-- PostgreSQL configuration
shared_buffers = 4GB
effective_cache_size = 12GB
maintenance_work_mem = 1GB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200
work_mem = 20MB
min_wal_size = 1GB
max_wal_size = 4GB
```

### Redis Tuning

```bash
# redis.conf
maxmemory 4gb
maxmemory-policy allkeys-lru
tcp-backlog 511
timeout 0
tcp-keepalive 300
```

---

## Deployment Checklist

### Pre-Deployment

- [ ] Review and test all configuration
- [ ] Generate and secure JWT keys
- [ ] Set up database with proper indexes
- [ ] Configure Redis with persistence
- [ ] Set up SSL/TLS certificates
- [ ] Configure monitoring and alerting
- [ ] Set up log aggregation
- [ ] Test backup and restore procedures
- [ ] Review security hardening
- [ ] Load test the application

### Deployment

- [ ] Deploy database and Redis first
- [ ] Run database migrations
- [ ] Deploy application instances
- [ ] Configure load balancer
- [ ] Set up health checks
- [ ] Enable auto-scaling
- [ ] Verify monitoring is working
- [ ] Test all endpoints
- [ ] Perform smoke tests

### Post-Deployment

- [ ] Monitor application metrics
- [ ] Check error logs
- [ ] Verify database performance
- [ ] Test authentication flows
- [ ] Monitor resource usage
- [ ] Document deployment
- [ ] Update runbooks

---

## Support

For deployment assistance:
- Review the [Setup Guide](./setup-guide.md)
- Check the [API Reference](./api-reference.md)
- Open an issue on GitHub
- Contact support@example.com
