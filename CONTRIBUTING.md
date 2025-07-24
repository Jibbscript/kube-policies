# Contributing to Kube-Policies

Thank you for your interest in contributing to Kube-Policies! This document provides guidelines and information for contributors to help ensure a smooth and effective contribution process.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Contribution Workflow](#contribution-workflow)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation Standards](#documentation-standards)
- [Security Considerations](#security-considerations)
- [Community and Communication](#community-and-communication)

## Code of Conduct

This project adheres to the [CNCF Code of Conduct](https://github.com/cncf/foundation/blob/master/code-of-conduct.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to conduct@kube-policies.io.

## Getting Started

### Prerequisites

Before contributing, ensure you have the following tools installed:

- **Go 1.21+**: For building and testing the Go components
- **Docker**: For building container images and running integration tests
- **Kubernetes cluster**: For testing (kind, minikube, or cloud cluster)
- **kubectl**: For interacting with Kubernetes
- **make**: For running build and test commands
- **git**: For version control

### Setting Up Your Development Environment

1. **Fork the Repository**
   ```bash
   # Fork the repository on GitHub, then clone your fork
   git clone https://github.com/YOUR_USERNAME/kube-policies.git
   cd kube-policies
   
   # Add the upstream repository as a remote
   git remote add upstream https://github.com/Jibbscript/kube-policies.git
   ```

2. **Install Development Dependencies**
   ```bash
   # Install development tools and dependencies
   make dev-setup
   
   # Verify installation
   make verify-setup
   ```

3. **Build the Project**
   ```bash
   # Build all components
   make build
   
   # Build specific components
   make build-admission-webhook
   make build-policy-manager
   ```

4. **Run Tests**
   ```bash
   # Run unit tests
   make test
   
   # Run integration tests
   make test-integration
   
   # Run end-to-end tests
   make test-e2e
   ```

## Development Environment

### Local Development Setup

For local development, you can run Kube-Policies components outside of Kubernetes:

```bash
# Start local development environment
make dev-start

# Run admission webhook locally
make run-admission-webhook

# Run policy manager locally
make run-policy-manager

# Stop local development environment
make dev-stop
```

### Kubernetes Development Setup

For testing in a Kubernetes environment:

```bash
# Create development cluster (using kind)
make cluster-create

# Deploy development version
make deploy-dev

# Port forward for local access
make port-forward

# Clean up
make cluster-delete
```

## Contribution Workflow

### 1. Planning Your Contribution

Before starting work on a significant contribution:

1. **Check existing issues**: Look for related issues or feature requests
2. **Create an issue**: If none exists, create an issue describing your proposed changes
3. **Discuss the approach**: Engage with maintainers and community members
4. **Get approval**: For significant changes, get approval before starting implementation

### 2. Making Changes

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Follow the coding standards outlined below
   - Include appropriate tests
   - Update documentation as needed

3. **Commit your changes**
   ```bash
   # Use conventional commit format
   git commit -m "feat: add new policy validation feature"
   ```

### 3. Testing Your Changes

Before submitting a pull request:

```bash
# Run all tests
make test-all

# Run linting
make lint

# Check code formatting
make fmt-check

# Run security scanning
make security-scan

# Test policy examples
make test-policies
```

### 4. Submitting a Pull Request

1. **Push your changes**
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Create a pull request**
   - Use the pull request template
   - Provide a clear description of changes
   - Reference related issues
   - Include testing instructions

3. **Address review feedback**
   - Respond to reviewer comments
   - Make requested changes
   - Update tests and documentation as needed

## Coding Standards

### Go Code Standards

We follow standard Go conventions with some additional requirements:

#### Code Formatting
```bash
# Format code using gofmt
make fmt

# Run golangci-lint
make lint
```

#### Naming Conventions
- Use descriptive names for variables, functions, and types
- Follow Go naming conventions (camelCase for private, PascalCase for public)
- Use meaningful package names that reflect their purpose

#### Error Handling
```go
// Always handle errors explicitly
result, err := someFunction()
if err != nil {
    return fmt.Errorf("failed to perform operation: %w", err)
}

// Use structured logging for errors
logger.Error("Operation failed", 
    zap.Error(err),
    zap.String("operation", "policy_evaluation"),
)
```

#### Documentation
```go
// Package documentation
// Package policy provides policy evaluation and management capabilities
// for the Kube-Policies system.
package policy

// Function documentation
// EvaluatePolicy evaluates a policy against the provided input and returns
// the evaluation result including any violations or required mutations.
func EvaluatePolicy(ctx context.Context, policy *Policy, input *Input) (*Result, error) {
    // Implementation
}
```

### Rego Policy Standards

For Rego policies, follow these conventions:

#### Package Structure
```rego
package kube_policies.security.containers

# Use descriptive package names that reflect the policy domain
```

#### Rule Naming
```rego
# Use descriptive rule names
deny_privileged_containers[msg] {
    input.request.kind.kind == "Pod"
    input.request.object.spec.securityContext.privileged == true
    msg := "Privileged containers are not allowed"
}
```

#### Documentation
```rego
# METADATA
# title: No Privileged Containers
# description: Ensures that containers do not run in privileged mode
# severity: HIGH
# frameworks: ["CIS", "NIST"]
```

## Testing Guidelines

### Unit Tests

Write comprehensive unit tests for all new functionality:

```go
func TestPolicyEvaluation(t *testing.T) {
    tests := []struct {
        name     string
        policy   *Policy
        input    *Input
        expected *Result
        wantErr  bool
    }{
        {
            name: "privileged container denied",
            policy: &Policy{
                // Test policy definition
            },
            input: &Input{
                // Test input
            },
            expected: &Result{
                Allowed: false,
                Reason:  "PolicyViolation",
            },
            wantErr: false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := EvaluatePolicy(context.Background(), tt.policy, tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("EvaluatePolicy() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if !reflect.DeepEqual(result, tt.expected) {
                t.Errorf("EvaluatePolicy() = %v, want %v", result, tt.expected)
            }
        })
    }
}
```

### Integration Tests

Integration tests should verify component interactions:

```go
func TestAdmissionWebhookIntegration(t *testing.T) {
    // Set up test environment
    testEnv := setupTestEnvironment(t)
    defer testEnv.Cleanup()

    // Test admission webhook functionality
    response := testEnv.SendAdmissionRequest(testPod)
    assert.False(t, response.Allowed)
    assert.Contains(t, response.Result.Message, "privileged containers")
}
```

### Policy Tests

Test policies using the policy testing framework:

```yaml
# tests/policies/security-baseline_test.yaml
tests:
  - name: "deny privileged container"
    policy: "security-baseline"
    input:
      request:
        kind:
          kind: "Pod"
        object:
          spec:
            securityContext:
              privileged: true
    expected:
      allowed: false
      violations:
        - policy_id: "security-baseline"
          rule_id: "no-privileged-containers"
```

## Documentation Standards

### Code Documentation

- Document all public APIs with clear descriptions
- Include examples for complex functions
- Document error conditions and return values
- Use godoc format for Go documentation

### User Documentation

- Write clear, concise documentation for end users
- Include practical examples and use cases
- Provide troubleshooting guides
- Keep documentation up to date with code changes

### Architecture Documentation

- Document design decisions and rationale
- Include architecture diagrams and flow charts
- Explain component interactions and dependencies
- Document configuration options and their impact

## Security Considerations

### Security Review Process

All contributions undergo security review:

1. **Automated Security Scanning**: All code is scanned for vulnerabilities
2. **Manual Security Review**: Security-sensitive changes receive manual review
3. **Threat Modeling**: Significant architectural changes undergo threat modeling
4. **Penetration Testing**: Major releases include penetration testing

### Security Best Practices

When contributing, follow these security practices:

#### Input Validation
```go
// Validate all inputs
func ValidatePolicy(policy *Policy) error {
    if policy == nil {
        return errors.New("policy cannot be nil")
    }
    if policy.Name == "" {
        return errors.New("policy name is required")
    }
    // Additional validation
}
```

#### Secure Defaults
```go
// Use secure defaults
config := &Config{
    TLS: TLSConfig{
        MinVersion: "1.3",
        CipherSuites: []string{
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
        },
    },
}
```

#### Error Handling
```go
// Don't leak sensitive information in errors
if err := authenticateUser(token); err != nil {
    // Don't expose authentication details
    return errors.New("authentication failed")
}
```

### Reporting Security Issues

If you discover a security vulnerability:

1. **Do not create a public issue**
2. **Email security@kube-policies.io** with details
3. **Include steps to reproduce** if applicable
4. **Wait for acknowledgment** before public disclosure

## Community and Communication

### Communication Channels

- **GitHub Issues**: For bug reports and feature requests
- **GitHub Discussions**: For general questions and discussions
- **Slack**: Join #kube-policies on CNCF Slack
- **Mailing List**: kube-policies-dev@googlegroups.com
- **Community Meetings**: Weekly community calls (see calendar)

### Getting Help

If you need help with your contribution:

1. **Check the documentation**: Start with the docs directory
2. **Search existing issues**: Someone may have faced the same problem
3. **Ask in discussions**: Use GitHub Discussions for questions
4. **Join community calls**: Attend weekly community meetings
5. **Reach out to maintainers**: Tag maintainers in issues or discussions

### Maintainer Responsibilities

Maintainers are responsible for:

- Reviewing and merging pull requests
- Triaging and responding to issues
- Maintaining code quality and security standards
- Facilitating community discussions
- Planning releases and roadmap

### Recognition

We recognize contributors through:

- **Contributor list**: All contributors are listed in CONTRIBUTORS.md
- **Release notes**: Significant contributions are highlighted in release notes
- **Community recognition**: Outstanding contributors are recognized in community calls
- **Maintainer nomination**: Active contributors may be nominated as maintainers

## Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **Major version**: Breaking changes
- **Minor version**: New features (backward compatible)
- **Patch version**: Bug fixes (backward compatible)

### Release Schedule

- **Major releases**: Every 6 months
- **Minor releases**: Monthly
- **Patch releases**: As needed for critical fixes

### Contributing to Releases

- **Feature freeze**: 2 weeks before major/minor releases
- **Release candidates**: 1 week before major releases
- **Testing period**: Community testing of release candidates
- **Release notes**: Contributors help write release notes

Thank you for contributing to Kube-Policies! Your contributions help make Kubernetes more secure for everyone.

