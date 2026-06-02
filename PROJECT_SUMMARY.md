# Kube-Policies: Enterprise Kubernetes Policy Enforcement - Project Summary

## Overview

This repository contains a **Proof-of-Concept / reference implementation** of **Kube-Policies**, a Kubernetes admission-control and policy-management system inspired by Block's (Square) blog post on Kubernetes guardrails. It demonstrates admission-time policy enforcement, exception handling, audit, and a read-only dashboard. It is **not yet production-ready or authorized**: it is being driven to **FedRAMP-Moderate** (NIST SP 800-53 Rev 5) and **CIS** readiness, with most security controls currently **Planned** or **Partial**. See the compliance evidence package under [`docs/compliance/`](docs/compliance/README.md) — in particular the [FIPS-199 categorization](docs/compliance/categorization/FIPS-199.md), the [control matrix](docs/compliance/control-matrix.csv), and the [POA&M](docs/compliance/POAM.md) of open weaknesses — for the authoritative, evidence-backed status.

## Architecture Highlights

### Core Design Targets

> These are the intended design properties; current per-control status is tracked in [`docs/compliance/control-matrix.csv`](docs/compliance/control-matrix.csv). Several are aspirational and are being phased in across P1–P12 — they are not asserted as currently implemented.

- **Defense in Depth**: admission control today; runtime monitoring and broader controls *(Planned — P9/P10)*
- **Zero Trust** *(Target — P2/P3/P4)*: mTLS between services, encryption in transit/at-rest, and least-privilege are Planned; today only the admission webhook serves TLS 1.3
- **Cloud Native**: Kubernetes-native via CRDs, admission webhook, and controllers (no separate operator today)
- **Enterprise Readiness** *(Target)*: high availability, scalability, durable audit, and SSO/integrations are Planned/Partial (P3/P7/P8)

### System Components

1. **Policy Engine Subsystem**
   - Admission Webhook Controller (`cmd/admission-webhook/`)
   - Policy Evaluation Engine (`internal/policy/`)
   - OPA-based policy evaluation with caching
   - Resource mutation capabilities

2. **Policy Management Subsystem**
   - Policy Manager Service (`cmd/policy-manager/`)
   - REST API for policy CRUD operations (`internal/policymanager/`)
   - Policy testing and validation framework
   - GitOps-enabled policy deployment

3. **Audit and Compliance Subsystem**
   - Audit logging (`internal/audit/`)
   - Pluggable backend support (file, stdout)
   - Tamper-evidence, durable storage, and SIEM forwarding *(Planned — P7)*
   - Compliance status tracked in [`docs/compliance/`](docs/compliance/README.md) (NIST 800-53 / FedRAMP-Moderate target; CIS mapping Planned — P10)

4. **Observability and Monitoring**
   - Prometheus metrics (`internal/metrics/`)
   - Structured logging (`pkg/logger/`)
   - Performance monitoring and alerting
   - Distributed tracing support

5. **Configuration Management**
   - Centralized configuration (`internal/config/`)
   - Environment-specific settings
   - Security-first defaults

## Key Features (PoC status: Implemented / Partial / Planned)

> Status reflects the honest control posture in [`docs/compliance/control-matrix.csv`](docs/compliance/control-matrix.csv); open gaps are tracked in the [POA&M](docs/compliance/POAM.md).

### Security Controls
- **Real-time Policy Enforcement** *(Implemented)*: OPA/Rego policy evaluation at admission
- **CIS / Pod Security policy pack** *(Planned — P10)*: the bundled rule set is currently minimal and does not yet traverse `spec.template.spec`
- **Multi-Tenant Support** *(Partial)*: namespaced `Policy`/`PolicyException` CRDs; tenant-isolation hardening Planned
- **Exception Management** *(Implemented)*: structured `PolicyException` handling with attribution
- **Security Hardening** *(Partial)*: TLS 1.3 on the webhook; mTLS, encryption-at-rest, and zero-trust are Planned (P2/P3/P4)

### Enterprise Capabilities
- **High Availability** *(Planned — P8)*: PDB, anti-affinity, and HA policy-manager are not yet in the chart
- **Scalability** *(Partial)*: prepared-query caching today; horizontal scaling / HPA Planned (P8)
- **Audit logging** *(Partial)*: file/stdout backends today; durability, integrity, and retention Planned (P7)
- **API-First Design** *(Implemented)*: REST APIs for management operations (authentication Planned — P3)
- **Integration** *(Partial)*: admission webhook support Implemented; OIDC SSO and application RBAC Planned (P3)

### Developer Experience
- **Policy as Code**: Git-managed policy resources
- **Testing Framework**: policy unit/integration tests (coverage gates Planned — P11)
- **Documentation**: architecture/operations docs under [`docs/`](docs/) and the compliance package under [`docs/compliance/`](docs/compliance/README.md)
- **CI/CD**: build/test/deploy pipelines (toolchain-trust + security gates Planned — P1/P6/P11)

## Repository Structure

```
kube-policies/
├── cmd/                           # Application entry points
│   ├── admission-webhook/         # Admission webhook service
│   └── policy-manager/            # Policy management service
├── internal/                      # Private application code
│   ├── admission/                 # Admission controller logic
│   ├── config/                    # Configuration management
│   ├── metrics/                   # Metrics collection
│   ├── policy/                    # Policy engine implementation
│   └── policymanager/             # Policy management API
├── pkg/                           # Public library code
│   ├── audit/                     # Audit logging framework
│   └── logger/                    # Structured logging
├── deployments/                   # Deployment configurations
│   ├── kubernetes/                # Kubernetes manifests
│   │   ├── crds/                  # Custom Resource Definitions
│   │   ├── rbac/                  # RBAC configurations
│   │   ├── base/                  # Base deployment manifests
│   │   ├── production/            # Production configurations
│   │   └── monitoring/            # Monitoring stack
│   ├── helm/                      # Helm charts
│   └── docker-compose/            # Local development
├── build/                         # Build configurations
│   └── docker/                    # Dockerfiles
├── configs/                       # Configuration files
│   ├── local/                     # Local development configs
│   └── production/                # Production configs
├── scripts/                       # Build and deployment scripts
├── docs/                          # Documentation
└── tests/                         # Test suites
```

## Technical Implementation

### Technology Stack
- **Language**: Go 1.25 (see `go.mod`)
- **Policy Engine**: Open Policy Agent (OPA) with Rego for flexible policy definition
- **Web Framework**: Gin for high-performance HTTP services
- **Metrics**: Prometheus for comprehensive observability
- **Logging**: Zap for structured, high-performance logging
- **Configuration**: Viper for flexible configuration management
- **Container Runtime**: Distroless images for security and minimal attack surface

### Security Architecture (target vs. current)
- **Network Security**: TLS 1.3 on the admission webhook today; mTLS between services and default-deny NetworkPolicy are **Planned (P3/P4)** — see [POA&M](docs/compliance/POAM.md)
- **Identity Management**: Kubernetes RBAC today (least-privilege split **Planned — P3**); OIDC SSO for the API/dashboard **Planned (P3)**
- **Data Protection**: TLS 1.3 in transit on the webhook; encryption-at-rest is **CSP-inherited / Planned (P2)** — KP does not implement at-rest encryption itself
- **Vulnerability Management**: **Planned (P6/P11)** — gating image/dependency scanning is not yet enforced in CI
- **Audit Integrity**: **Planned (P7)** — tamper-evident audit logging with integrity chaining is not yet implemented

### Performance Characteristics (design targets — not yet independently benchmarked)
- **Latency**: low-latency policy evaluation with prepared-query caching
- **Throughput**: target of high admission-request throughput (not yet load-tested — see P11)
- **Scalability**: horizontal scaling / HPA *(Planned — P8)*
- **Resource Efficiency**: resource requests/limits to be enforced in the chart *(Planned — P5)*
- **High Availability**: PDB, anti-affinity, and HA policy-manager *(Planned — P8)*

## Compliance Posture (PoC — in progress)

This system is being driven toward **FIPS-199 Moderate** under **NIST SP 800-53 Rev 5 (FedRAMP Moderate baseline)** and **CIS** readiness. It is **not yet authorized** and makes no claim of completed compliance with any framework. Status is tracked honestly in the compliance evidence package; most controls are currently **Planned** or **Partial**. See the [compliance index](docs/compliance/README.md) for the full artifact set.

### Target frameworks and current status
- **NIST SP 800-53 Rev 5 / FedRAMP Moderate**: target baseline. Control-by-control status (Implemented | Partial | Planned | Inherited | Customer | Not-Applicable) is recorded in the [control matrix](docs/compliance/control-matrix.csv) and summarized in [control-matrix.md](docs/compliance/control-matrix.md).
- **FIPS-199**: categorized **Moderate** — see the [FIPS-199 / FIPS-200 categorization](docs/compliance/categorization/FIPS-199.md).
- **CIS Kubernetes Benchmark v1.8 / NIST SP 800-190**: the per-control self-assessment crosswalk (DOC-WU-29) is authored at [`docs/compliance/cis-k8s-800-190-mapping.md`](docs/compliance/cis-k8s-800-190-mapping.md). kube-policies covers CIS Section 5 (Policies) via its 30 bundled Rego admission rules; CIS Sections 1–4 (control-plane/etcd/node config) are cluster-operator responsibilities outside the admission-controller boundary. Summary: **20 Covered, 6 Partial, 5 Not-Covered** across CIS Section 5 leaf controls (see the mapping document for per-control status and POA&M entries).

### Open weaknesses and remediation
- Known foundational gaps are tracked in the [POA&M](docs/compliance/POAM.md) and remediated across phases **P1–P12** (see `.omc/plans/PRODUCTION-READINESS-FEDRAMP-CIS.md`).
- Shared, customer, and inherited responsibilities are described in the [Customer Responsibility Matrix (CRM)](docs/compliance/CRM.md).

## Deployment Options

### Deployment (reference / PoC)
- **Kubernetes Native**: deployment via CRDs, the admission webhook, and controllers (no separate operator today)
- **Helm Charts**: parameterized deployment with environment-specific values
- **GitOps**: chart is GitOps-compatible (ArgoCD/Flux) for managed environments
- **Multi-Cluster**: cross-cluster policy distribution *(Planned — not implemented)*

### Development Environment
- **Local Development**: Docker Compose for local testing
- **Kind/Minikube**: Local Kubernetes development clusters
- **CI/CD Integration**: GitHub Actions, Jenkins, and GitLab CI support

## Getting Started

### Quick Start
```bash
# Clone the repository
git clone https://github.com/Jibbscript/kube-policies.git
cd kube-policies

# Build the project
make build

# Deploy to Kubernetes
kubectl apply -f deployments/kubernetes/crds/
kubectl apply -f deployments/kubernetes/base/

# Verify deployment
kubectl get pods -n kube-policies-system
```

### Development Setup
```bash
# Set up development environment
make dev-setup

# Run tests
make test-all

# Start local development
make dev-start
```

## Documentation

### Architecture Documentation
- **Security Architecture**: see [docs/compliance/security-architecture.md](docs/compliance/security-architecture.md) and the [authorization-boundary](docs/compliance/diagrams/authorization-boundary.md) / [data-flow](docs/compliance/diagrams/data-flow.md) diagrams
- **System Context**: high-level overview and external interfaces (see [system-facts](docs/compliance/system-facts.md))
- **Component Architecture**: component design and interactions
- **arc42 architecture document** *(Planned)*: not yet authored

### API Documentation
- **Kubernetes API**: Custom Resource Definitions and API extensions
- **Policy Language**: Rego policy development guide
- **REST API**: OpenAPI/Swagger specification *(Planned — P3/P11)*: not yet published
- **Integration Guide** *(Planned)*

### Operational Documentation
- **Installation Guide**: Step-by-step deployment instructions
- **Configuration Reference**: Complete configuration options
- **Monitoring Guide**: Observability and alerting setup
- **Troubleshooting**: Common issues and resolution procedures

## Quality Assurance

### Testing Strategy
- **Unit Tests**: present across most packages; an enforced coverage gate is *(Planned — P11)* (no verified ≥90% claim today)
- **Integration Tests**: component integration validation
- **End-to-End Tests**: Kind-based workflow testing
- **Policy Tests**: policy validation/testing (golden-file harness expanded in P10)
- **Performance Tests** *(Planned — P11)*: load testing and benchmarking

### Security Validation (mostly Planned — see phases P6/P11)
- **Static Analysis** *(Planned — P11)*: gating SAST (CodeQL/gosec) not yet enforced
- **Dependency Scanning** *(Planned — P6/P11)*: govulncheck/SCA gating not yet enforced
- **Container Scanning** *(Planned — P6)*: image scan present but not gating
- **Penetration Testing** *(Planned — P12)*: plan authored in P0; execution not yet staffed
- **Compliance Validation**: offline artifact checks via `make validate-compliance` (Implemented); control-level assessment *(Planned — P12)*

### Code Quality
- **Linting**: Automated code quality checks
- **Formatting**: Consistent code formatting
- **Documentation**: Comprehensive code documentation
- **Review Process**: Mandatory peer review for all changes

## Future Roadmap

### Short Term (3-6 months)
- Enhanced policy testing framework
- Additional compliance framework support
- Performance optimizations
- Extended monitoring capabilities

### Medium Term (6-12 months)
- Multi-cluster policy federation
- Advanced exception workflows
- Machine learning-based policy recommendations
- Enhanced developer tooling

### Long Term (12+ months)
- Policy marketplace and sharing
- Advanced threat detection
- Automated remediation capabilities
- Cloud provider native integrations

## Contributing

We welcome contributions from the community! Please see our [Contributing Guide](CONTRIBUTING.md) for details on:
- Development setup and workflow
- Coding standards and best practices
- Testing requirements
- Documentation standards
- Security considerations

## Support and Community

- **Documentation**: [https://docs.kube-policies.io](https://docs.kube-policies.io)
- **Community Forum**: [https://community.kube-policies.io](https://community.kube-policies.io)
- **Issue Tracker**: [GitHub Issues](https://github.com/Jibbscript/kube-policies/issues)
- **Enterprise Support**: [support@kube-policies.io](mailto:support@kube-policies.io)

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

---

**Kube-Policies** - Securing Kubernetes at Enterprise Scale

