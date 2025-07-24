# Kube-Policies Deployment Guide

This guide provides comprehensive instructions for deploying Kube-Policies in production environments.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Helm Deployment](#helm-deployment)
4. [Manual Deployment](#manual-deployment)
5. [Monitoring Setup](#monitoring-setup)
6. [Configuration](#configuration)
7. [Troubleshooting](#troubleshooting)

## Prerequisites

### Kubernetes Cluster Requirements

- Kubernetes 1.20+ (recommended 1.24+)
- RBAC enabled
- Admission controllers enabled
- Minimum 3 worker nodes (for HA deployment)

### Resource Requirements

| Component | CPU | Memory | Storage |
|-----------|-----|--------|---------|
| Admission Webhook | 100m-500m | 128Mi-512Mi | - |
| Policy Manager | 100m-500m | 128Mi-512Mi | 10Gi |
| Prometheus | 200m-1000m | 1Gi-2Gi | 50Gi |
| Grafana | 250m-500m | 750Mi-1Gi | 10Gi |

### Required Tools

- `kubectl` 1.20+
- `helm` 3.8+
- `openssl` (for certificate generation)

## Quick Start

### 1. Add Helm Repository

```bash
helm repo add kube-policies https://charts.kube-policies.io
helm repo update
```

### 2. Install with Default Configuration

```bash
# Create namespace
kubectl create namespace kube-policies-system

# Install Kube-Policies
helm install kube-policies kube-policies/kube-policies \
  --namespace kube-policies-system \
  --set monitoring.enabled=true
```

### 3. Verify Installation

```bash
# Check pod status
kubectl get pods -n kube-policies-system

# Check admission webhook
kubectl get validatingadmissionwebhooks
kubectl get mutatingadmissionwebhooks

# Test policy enforcement
kubectl apply -f examples/policies/security-baseline.yaml
```

## Helm Deployment

### Production Configuration

Create a `values-production.yaml` file:

```yaml
# Production values for kube-policies
global:
  imageRegistry: "your-registry.com"
  imagePullSecrets:
    - name: registry-secret

admissionWebhook:
  replicaCount: 3
  resources:
    requests:
      cpu: 200m
      memory: 256Mi
    limits:
      cpu: 500m
      memory: 512Mi
  
  affinity:
    podAntiAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
      - labelSelector:
          matchExpressions:
          - key: app.kubernetes.io/component
            operator: In
            values:
            - admission-webhook
        topologyKey: kubernetes.io/hostname

policyManager:
  replicaCount: 2
  resources:
    requests:
      cpu: 200m
      memory: 256Mi
    limits:
      cpu: 500m
      memory: 512Mi

monitoring:
  enabled: true
  prometheus:
    enabled: true
    external: false
  grafana:
    enabled: true
    external: false
    adminPassword: "secure-password"

persistence:
  enabled: true
  storageClass: "fast-ssd"
  size: 20Gi

audit:
  enabled: true
  backend:
    type: elasticsearch
    elasticsearch:
      url: "https://elasticsearch.monitoring.svc.cluster.local:9200"
      index: "kube-policies-audit"

compliance:
  enabled: true
  frameworks:
    cis:
      enabled: true
    nist:
      enabled: true
```

### Deploy with Production Configuration

```bash
helm install kube-policies kube-policies/kube-policies \
  --namespace kube-policies-system \
  --values values-production.yaml \
  --wait --timeout=10m
```

### Upgrade Deployment

```bash
# Upgrade to latest version
helm upgrade kube-policies kube-policies/kube-policies \
  --namespace kube-policies-system \
  --values values-production.yaml \
  --wait --timeout=10m

# Rollback if needed
helm rollback kube-policies 1 --namespace kube-policies-system
```

## Manual Deployment

### 1. Deploy CRDs

```bash
kubectl apply -f deployments/kubernetes/crds/
```

### 2. Create Namespace and RBAC

```bash
kubectl create namespace kube-policies-system
kubectl apply -f deployments/kubernetes/rbac/
```

### 3. Generate Certificates

```bash
# Generate CA and server certificates
./scripts/generate-certs.sh kube-policies-system
```

### 4. Deploy Components

```bash
# Deploy admission webhook
kubectl apply -f deployments/kubernetes/base/admission-webhook.yaml

# Deploy policy manager
kubectl apply -f deployments/kubernetes/base/policy-manager.yaml

# Deploy monitoring stack
kubectl apply -f deployments/kubernetes/monitoring/
```

### 5. Configure Admission Webhooks

```bash
# Apply webhook configurations
kubectl apply -f deployments/kubernetes/webhooks/
```

## Monitoring Setup

### Prometheus Configuration

The monitoring stack includes:

- **Prometheus**: Metrics collection and alerting
- **Grafana**: Visualization and dashboards
- **Alertmanager**: Alert routing and notification

### Access Monitoring Dashboards

```bash
# Port-forward to Grafana
kubectl port-forward -n kube-policies-monitoring svc/grafana 3000:3000

# Access Grafana at http://localhost:3000
# Default credentials: admin/admin
```

### Available Dashboards

1. **Kube-Policies Overview**: System health and performance
2. **Security Dashboard**: Policy violations and compliance
3. **Performance Dashboard**: Resource usage and latency

### Configure Alerting

Edit the Alertmanager configuration:

```bash
kubectl edit configmap alertmanager-config -n kube-policies-monitoring
```

Update notification channels:

```yaml
receivers:
- name: 'slack-alerts'
  slack_configs:
  - api_url: 'YOUR_SLACK_WEBHOOK_URL'
    channel: '#kube-policies-alerts'
    title: 'Kube-Policies Alert'
    text: '{{ range .Alerts }}{{ .Annotations.description }}{{ end }}'
```

## Configuration

### Policy Configuration

Create custom policies:

```yaml
apiVersion: policies.kube-policies.io/v1
kind: Policy
metadata:
  name: custom-security-policy
spec:
  description: "Custom security requirements"
  enabled: true
  rules:
    - name: require-non-root
      severity: HIGH
      rego: |
        package custom.security
        deny[msg] {
          input.spec.securityContext.runAsUser == 0
          msg := "Containers must not run as root"
        }
```

### Exception Management

Create policy exceptions:

```yaml
apiVersion: policies.kube-policies.io/v1
kind: PolicyException
metadata:
  name: legacy-app-exception
spec:
  policy: security-baseline
  rules: ["require-non-root"]
  selector:
    matchLabels:
      app: legacy-application
  duration: "30d"
  justification: "Legacy application requires root access"
```

### Audit Configuration

Configure audit backends:

```yaml
# File backend
audit:
  backend:
    type: file
    file:
      path: "/var/log/kube-policies"
      maxSize: "100Mi"

# Elasticsearch backend
audit:
  backend:
    type: elasticsearch
    elasticsearch:
      url: "https://elasticsearch:9200"
      index: "kube-policies-audit"
      username: "elastic"
      password: "password"
```

## Troubleshooting

### Common Issues

#### 1. Admission Webhook Not Working

```bash
# Check webhook status
kubectl get validatingadmissionwebhooks kube-policies-admission-webhook -o yaml

# Check certificate validity
kubectl get secret kube-policies-admission-webhook-certs -o yaml

# Check webhook logs
kubectl logs -n kube-policies-system deployment/kube-policies-admission-webhook
```

#### 2. Policy Evaluation Failures

```bash
# Check policy manager logs
kubectl logs -n kube-policies-system deployment/kube-policies-policy-manager

# Validate policy syntax
kubectl apply --dry-run=server -f your-policy.yaml

# Check policy status
kubectl get policies -A
```

#### 3. High Latency Issues

```bash
# Check resource usage
kubectl top pods -n kube-policies-system

# Review metrics
kubectl port-forward -n kube-policies-system svc/kube-policies-admission-webhook 8080:8080
curl http://localhost:8080/metrics

# Check for resource constraints
kubectl describe pods -n kube-policies-system
```

#### 4. Certificate Issues

```bash
# Regenerate certificates
./scripts/generate-certs.sh kube-policies-system

# Update webhook configuration
kubectl patch validatingadmissionwebhook kube-policies-admission-webhook \
  --type='json' -p='[{"op": "replace", "path": "/webhooks/0/clientConfig/caBundle", "value":"NEW_CA_BUNDLE"}]'
```

### Debug Mode

Enable debug logging:

```bash
# Update deployment with debug logging
kubectl patch deployment kube-policies-admission-webhook -n kube-policies-system \
  -p='{"spec":{"template":{"spec":{"containers":[{"name":"admission-webhook","env":[{"name":"LOG_LEVEL","value":"debug"}]}]}}}}'
```

### Health Checks

```bash
# Check component health
kubectl get pods -n kube-policies-system
kubectl get endpoints -n kube-policies-system

# Test admission webhook
curl -k https://kube-policies-admission-webhook.kube-policies-system.svc.cluster.local:8443/healthz

# Test policy manager
curl http://kube-policies-policy-manager.kube-policies-system.svc.cluster.local:8080/healthz
```

### Performance Tuning

#### Webhook Performance

```yaml
# Increase replicas
admissionWebhook:
  replicaCount: 5

# Optimize resource allocation
admissionWebhook:
  resources:
    requests:
      cpu: 500m
      memory: 512Mi
    limits:
      cpu: 1000m
      memory: 1Gi
```

#### Policy Caching

```yaml
# Enable policy caching
policyManager:
  cache:
    enabled: true
    ttl: "5m"
    maxSize: 1000
```

### Backup and Recovery

#### Backup Policies

```bash
# Export all policies
kubectl get policies -A -o yaml > policies-backup.yaml

# Export exceptions
kubectl get policyexceptions -A -o yaml > exceptions-backup.yaml
```

#### Restore Policies

```bash
# Restore policies
kubectl apply -f policies-backup.yaml
kubectl apply -f exceptions-backup.yaml
```

## Support

For additional support:

- Documentation: https://docs.kube-policies.io
- GitHub Issues: https://github.com/kube-policies/kube-policies/issues
- Community Slack: https://slack.kube-policies.io
- Email: support@kube-policies.io

