# Kube-Policies

Enterprise-grade Kubernetes policy enforcement system providing comprehensive security guardrails, compliance monitoring, and governance for containerized applications at scale.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Report Card](https://goreportcard.com/badge/github.com/jibbscript/kube-policies)](https://goreportcard.com/report/github.com/Jibbscript/kube-policies)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.20%2B-blue.svg)](https://kubernetes.io/)
[![Helm](https://img.shields.io/badge/Helm-3.8%2B-blue.svg)](https://helm.sh/)

## Overview

Kube-Policies is a comprehensive policy enforcement platform designed to address the critical security and compliance challenges faced by enterprise organizations operating in cloud-native environments. Built on the foundation of [Block's pioneering implementation](https://developer.squareup.com/blog/kube-policies-guardrails-for-apps-running-in-kubernetes/), this solution extends and enhances the original concept to create a production-ready, enterprise-grade system.

### Key Features

- **Real-time Policy Enforcement**: Sub-millisecond policy evaluation with OPA-based engine
- **Enterprise Security**: Comprehensive security controls with CIS, NIST, and custom compliance frameworks
- **Multi-Tenant Architecture**: Hierarchical policy inheritance with tenant-specific customizations
- **Advanced Monitoring**: Prometheus metrics, Grafana dashboards, and comprehensive audit logging
- **High Performance**: Intelligent caching and horizontal scaling for enterprise workloads
- **Zero Trust Security**: mTLS communication, encryption at rest/transit, and minimal privilege access
- **Exception Management**: Structured exception handling with approval workflows
- **Policy as Code**: GitOps-enabled policy management with version control

## Quick Start

### Prerequisites

- Kubernetes 1.20+ (recommended 1.24+)
- Helm 3.8+
- RBAC enabled cluster

### Installation

```bash
# Add Helm repository
helm repo add kube-policies https://charts.kube-policies.io
helm repo update

# Create namespace
kubectl create namespace kube-policies-system

# Install with monitoring enabled
helm install kube-policies kube-policies/kube-policies \
  --namespace kube-policies-system \
  --set monitoring.enabled=true \
  --set policies.enableDefaults=true
```

### Verify Installation

```bash
# Check components
kubectl get pods -n kube-policies-system

# Verify admission webhooks
kubectl get validatingadmissionwebhooks
kubectl get mutatingadmissionwebhooks

# Test policy enforcement
kubectl apply -f examples/policies/security-baseline.yaml
```

## Repository Structure

```
kube-policies/
├── cmd/                           # Application entry points
│   ├── admission-webhook/         # Admission webhook service
│   └── policy-manager/            # Policy management service
├── internal/                      # Internal application code
│   ├── admission/                 # Admission controller logic
│   ├── config/                    # Configuration management
│   ├── metrics/                   # Metrics collection
│   ├── policy/                    # Policy engine
│   └── policymanager/             # Policy manager implementation
├── pkg/                           # Public packages
│   ├── audit/                     # Audit logging
│   └── logger/                    # Structured logging
├── charts/                        # Helm charts
│   └── kube-policies/             # Main Helm chart
│       ├── templates/             # Kubernetes manifests
│       ├── Chart.yaml             # Chart metadata
│       └── values.yaml            # Default configuration
├── deployments/                   # Deployment manifests
│   └── kubernetes/                # Kubernetes deployments
│       ├── base/                  # Base manifests
│       ├── crds/                  # Custom Resource Definitions
│       └── monitoring/            # Monitoring stack
├── monitoring/                    # Monitoring configurations
│   ├── grafana/                   # Grafana dashboards
│   │   └── dashboards/            # Dashboard definitions
│   ├── prometheus/                # Prometheus configuration
│   └── alertmanager/              # Alertmanager configuration
├── examples/                      # Example configurations
│   ├── policies/                  # Sample policies
│   └── exceptions/                # Sample exceptions
├── build/                         # Build configurations
│   └── docker/                    # Dockerfiles
├── docs/                          # Documentation
├── scripts/                       # Utility scripts
├── DEPLOYMENT.md                  # Deployment guide
├── CONTRIBUTING.md                # Contribution guidelines
└── README.md                      # This file
```

## Architecture

### System Components

1. **Admission Webhook**: Validates and mutates Kubernetes resources in real-time
2. **Policy Manager**: Manages policy lifecycle, exceptions, and compliance reporting
3. **Policy Engine**: OPA-based evaluation engine with sub-millisecond performance
4. **Audit System**: Comprehensive audit logging with multiple backend support
5. **Monitoring Stack**: Prometheus, Grafana, and Alertmanager integration

### Core Subsystems

- **Policy Engine Subsystem**: Real-time admission control with OPA-based evaluation
- **Policy Management Subsystem**: Comprehensive policy lifecycle management
- **Audit & Compliance Subsystem**: Tamper-evident audit logging and compliance reporting
- **Exception Management Subsystem**: Structured exception handling with approval workflows
- **Observability Subsystem**: Comprehensive monitoring, metrics, and alerting

## Monitoring & Observability

### Grafana Dashboards

- **Overview Dashboard**: System health, performance, and policy enforcement metrics
- **Security Dashboard**: Policy violations, threat detection, and compliance metrics
- **Performance Dashboard**: Resource usage, latency, and throughput monitoring

### Prometheus Metrics

- Policy evaluation latency and throughput
- Admission webhook performance metrics
- Policy violation rates by severity
- System resource utilization
- Compliance framework scores

### Alerting Rules

- High latency alerts (>100ms 95th percentile)
- High error rate alerts (>5% error rate)
- Service availability monitoring
- Policy violation rate monitoring
- Resource usage alerts

## Configuration

### Basic Policy Example

```yaml
apiVersion: policies.kube-policies.io/v1
kind: Policy
metadata:
  name: security-baseline
spec:
  description: "Basic security requirements"
  enabled: true
  rules:
    - name: no-privileged-containers
      severity: HIGH
      rego: |
        deny[msg] {
          input.spec.securityContext.privileged
          msg := "Privileged containers are not allowed"
        }
```

### Exception Management

A `PolicyException` CR grants a targeted carve-out from a Policy. The webhook
consults its in-cluster exception index on every admission request; matching
exceptions suppress otherwise-denied verdicts. Suppressions are observable via
the Prometheus counter `kube_policies_policy_exception_suppressions_total{policy_id, rule_id}`,
the structured audit log (`suppressed_by` field), and an `info`-level
admission log line.

```yaml
apiVersion: policies.kube-policies.io/v1
kind: PolicyException
metadata:
  name: emergency-deployment
  namespace: emergency-ns       # exception is namespaced; create it in the
                                # same namespace as the workload or in
                                # kube-policies-system
spec:
  policy_id: security-baseline           # required: id of the Policy to waive
  rule_id: no-privileged-containers      # optional: empty = applies to all
                                         # rules of the parent policy
  justification: "Emergency security patch deployment"
  approver: security-team
  expires_at: "2030-01-01T00:00:00Z"     # RFC3339, e.g. far-future or
                                         # `<incident-end>+24h`; omit for no expiry
  scope:
    # All four dimensions act as strict allow-lists; an unset dimension is
    # unconstrained but does not widen the match. Omitting `scope` entirely
    # produces a wildcard match for the named policy/rule.
    namespaces: ["emergency-ns"]
    resources:  ["pods"]
    # users / groups also supported.
```

**Eventual-consistency note.** Exception propagation runs through the
controller-runtime watch in each webhook replica; there is a brief window
(typically < 1 s on healthy clusters, longer under load) between
`kubectl apply` and the webhook honoring the exception. Operators applying an
emergency carve-out should either re-apply the affected workload after a short
pause, or wait for `status.phase=Active` on the `PolicyException` CR before
proceeding. The CRD intentionally does NOT support a synchronous "wait for
suppression" mode — blocking admission until the index converges would create
a worse failure mode (admission stalls on reconciler outages).

**Scope semantics (security-sensitive).** An exception whose `scope` is
entirely absent (no `namespaces`, `resources`, `users`, or `groups` set)
matches **every** request for the named policy/rule. An explicitly-empty
list inside an otherwise-populated `scope` (e.g. `namespaces: []`) is treated
as "this dimension is unconstrained" — NOT "no namespaces match." Operators
who genuinely want "no resources match" must omit the CR entirely rather
than create one with empty allow-lists. See `cmd/admission-webhook/AGENTS.md`
for the full matcher predicate documentation.

## Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/kube-policies/kube-policies.git
cd kube-policies

# Build binaries
make build

# Build Docker images
make docker-build

# Run tests
make test

# Run linting
make lint
```

### Local Development

```bash
# Start local development environment
make dev-setup

# Run admission webhook locally
make run-webhook

# Run policy manager locally
make run-policy-manager
```

## Documentation

- [Deployment Guide](DEPLOYMENT.md) - Comprehensive deployment instructions
- [Architecture Documentation](docs/architecture.md) - Detailed system architecture
- [Policy Development Guide](docs/policy-development.md) - Creating custom policies
- [API Reference](docs/api-reference.md) - Complete API documentation
- [Troubleshooting Guide](docs/troubleshooting.md) - Common issues and solutions

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details on:

- Code of conduct
- Development setup
- Submission process
- Testing requirements
- Documentation standards

### Development Workflow

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests and documentation
5. Submit a pull request

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [https://docs.kube-policies.io](https://docs.kube-policies.io)
- **GitHub Issues**: [https://github.com/kube-policies/kube-policies/issues](https://github.com/kube-policies/kube-policies/issues)
- **Community Slack**: [https://slack.kube-policies.io](https://slack.kube-policies.io)
- **Email Support**: [support@kube-policies.io](mailto:support@kube-policies.io)

## Acknowledgments

- Inspired by [Block's Kube-Policies implementation](https://developer.squareup.com/blog/kube-policies-guardrails-for-apps-running-in-kubernetes/)
- Built on [Open Policy Agent (OPA)](https://www.openpolicyagent.org/)
- Kubernetes community for admission controller patterns
- CNCF projects for cloud-native best practices

## Related Projects

- [Open Policy Agent](https://github.com/open-policy-agent/opa)
- [Gatekeeper](https://github.com/open-policy-agent/gatekeeper)
- [Falco](https://github.com/falcosecurity/falco)
- [Polaris](https://github.com/FairwindsOps/polaris)

---

**Kube-Policies** - Securing Kubernetes at Enterprise Scale

