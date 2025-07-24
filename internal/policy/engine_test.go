package policy

import (
	"context"
	"testing"

	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestPolicyEngine_Evaluate(t *testing.T) {
	engine := NewPolicyEngine()

	tests := []struct {
		name           string
		resource       interface{}
		policies       []Policy
		expectedDenies []string
		expectError    bool
	}{
		{
			name: "pod with no violations",
			resource: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						RunAsUser:    &[]int64{1000}[0],
						RunAsNonRoot: &[]bool{true}[0],
					},
					Containers: []corev1.Container{
						{
							Name:  "test-container",
							Image: "nginx:1.20",
							SecurityContext: &corev1.SecurityContext{
								RunAsUser:    &[]int64{1000}[0],
								RunAsNonRoot: &[]bool{true}[0],
							},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    parseQuantity("100m"),
									corev1.ResourceMemory: parseQuantity("128Mi"),
								},
							},
						},
					},
				},
			},
			policies: []Policy{
				{
					Name:        "no-privileged-containers",
					Description: "Deny privileged containers",
					Rego: `
						package kube_policies.security
						deny[msg] {
							input.spec.securityContext.privileged == true
							msg := "Privileged containers are not allowed"
						}
						deny[msg] {
							input.spec.containers[_].securityContext.privileged == true
							msg := "Privileged containers are not allowed"
						}
					`,
				},
				{
					Name:        "no-root-user",
					Description: "Deny root user",
					Rego: `
						package kube_policies.security
						deny[msg] {
							input.spec.securityContext.runAsUser == 0
							msg := "Containers must not run as root user"
						}
						deny[msg] {
							input.spec.containers[_].securityContext.runAsUser == 0
							msg := "Containers must not run as root user"
						}
					`,
				},
			},
			expectedDenies: []string{},
			expectError:    false,
		},
		{
			name: "pod with privileged container",
			resource: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "privileged-pod",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						Privileged: &[]bool{true}[0],
					},
					Containers: []corev1.Container{
						{
							Name:  "privileged-container",
							Image: "nginx:latest",
							SecurityContext: &corev1.SecurityContext{
								Privileged: &[]bool{true}[0],
							},
						},
					},
				},
			},
			policies: []Policy{
				{
					Name:        "no-privileged-containers",
					Description: "Deny privileged containers",
					Rego: `
						package kube_policies.security
						deny[msg] {
							input.spec.securityContext.privileged == true
							msg := "Privileged containers are not allowed"
						}
						deny[msg] {
							input.spec.containers[_].securityContext.privileged == true
							msg := "Privileged containers are not allowed"
						}
					`,
				},
			},
			expectedDenies: []string{"Privileged containers are not allowed"},
			expectError:    false,
		},
		{
			name: "pod with root user",
			resource: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "root-pod",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						RunAsUser: &[]int64{0}[0],
					},
					Containers: []corev1.Container{
						{
							Name:  "root-container",
							Image: "nginx:1.20",
							SecurityContext: &corev1.SecurityContext{
								RunAsUser: &[]int64{0}[0],
							},
						},
					},
				},
			},
			policies: []Policy{
				{
					Name:        "no-root-user",
					Description: "Deny root user",
					Rego: `
						package kube_policies.security
						deny[msg] {
							input.spec.securityContext.runAsUser == 0
							msg := "Containers must not run as root user"
						}
						deny[msg] {
							input.spec.containers[_].securityContext.runAsUser == 0
							msg := "Containers must not run as root user"
						}
					`,
				},
			},
			expectedDenies: []string{"Containers must not run as root user"},
			expectError:    false,
		},
		{
			name: "pod with latest image tag",
			resource: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "latest-pod",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "latest-container",
							Image: "nginx:latest",
						},
					},
				},
			},
			policies: []Policy{
				{
					Name:        "no-latest-tag",
					Description: "Deny latest image tag",
					Rego: `
						package kube_policies.security
						import future.keywords.contains
						import future.keywords.if
						
						deny[msg] {
							container := input.spec.containers[_]
							endswith(container.image, ":latest")
							msg := sprintf("Container '%s' must not use 'latest' image tag", [container.name])
						}
						
						deny[msg] {
							container := input.spec.containers[_]
							not contains(container.image, ":")
							msg := sprintf("Container '%s' must specify explicit image tag", [container.name])
						}
					`,
				},
			},
			expectedDenies: []string{"Container 'latest-container' must not use 'latest' image tag"},
			expectError:    false,
		},
		{
			name: "invalid rego policy",
			resource: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: "default",
				},
			},
			policies: []Policy{
				{
					Name:        "invalid-policy",
					Description: "Invalid rego syntax",
					Rego:        `invalid rego syntax {{{`,
				},
			},
			expectedDenies: []string{},
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			denies, err := engine.Evaluate(ctx, tt.resource, tt.policies)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.ElementsMatch(t, tt.expectedDenies, denies)
			}
		})
	}
}

func TestPolicyEngine_ValidatePolicy(t *testing.T) {
	engine := NewPolicyEngine()

	tests := []struct {
		name        string
		policy      Policy
		expectError bool
	}{
		{
			name: "valid policy",
			policy: Policy{
				Name:        "valid-policy",
				Description: "A valid policy",
				Rego: `
					package kube_policies.test
					deny[msg] {
						input.spec.containers[_].securityContext.privileged == true
						msg := "Privileged containers are not allowed"
					}
				`,
			},
			expectError: false,
		},
		{
			name: "invalid rego syntax",
			policy: Policy{
				Name:        "invalid-policy",
				Description: "Invalid rego syntax",
				Rego:        `invalid rego syntax {{{`,
			},
			expectError: true,
		},
		{
			name: "empty rego",
			policy: Policy{
				Name:        "empty-policy",
				Description: "Empty rego",
				Rego:        "",
			},
			expectError: true,
		},
		{
			name: "policy with syntax error",
			policy: Policy{
				Name:        "syntax-error-policy",
				Description: "Policy with syntax error",
				Rego: `
					package kube_policies.test
					deny[msg] {
						input.spec.containers[_].securityContext.privileged == true
						msg := "Missing closing brace"
				`,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := engine.ValidatePolicy(tt.policy)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPolicyEngine_CompilePolicy(t *testing.T) {
	engine := NewPolicyEngine()

	tests := []struct {
		name        string
		policy      Policy
		expectError bool
	}{
		{
			name: "compile valid policy",
			policy: Policy{
				Name:        "compile-test",
				Description: "Test policy compilation",
				Rego: `
					package kube_policies.compile_test
					deny[msg] {
						input.spec.containers[_].securityContext.privileged == true
						msg := "Privileged containers are not allowed"
					}
				`,
			},
			expectError: false,
		},
		{
			name: "compile invalid policy",
			policy: Policy{
				Name:        "compile-invalid",
				Description: "Invalid policy for compilation",
				Rego:        `invalid rego`,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiled, err := engine.compilePolicy(tt.policy)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, compiled)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, compiled)
				assert.IsType(t, &rego.PreparedEvalQuery{}, compiled)
			}
		})
	}
}

func TestPolicyEngine_EvaluateWithCache(t *testing.T) {
	engine := NewPolicyEngine()
	engine.enableCache = true

	policy := Policy{
		Name:        "cache-test",
		Description: "Test policy caching",
		Rego: `
			package kube_policies.cache_test
			deny[msg] {
				input.spec.containers[_].securityContext.privileged == true
				msg := "Privileged containers are not allowed"
			}
		`,
	}

	resource := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cache-test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "test-container",
					Image: "nginx:1.20",
					SecurityContext: &corev1.SecurityContext{
						Privileged: &[]bool{false}[0],
					},
				},
			},
		},
	}

	ctx := context.Background()

	// First evaluation - should compile and cache
	denies1, err1 := engine.Evaluate(ctx, resource, []Policy{policy})
	require.NoError(t, err1)

	// Second evaluation - should use cache
	denies2, err2 := engine.Evaluate(ctx, resource, []Policy{policy})
	require.NoError(t, err2)

	assert.Equal(t, denies1, denies2)
	assert.Empty(t, denies1) // No violations expected
}

func TestPolicyEngine_EvaluateComplexPolicies(t *testing.T) {
	engine := NewPolicyEngine()

	// Complex policy with multiple rules
	complexPolicy := Policy{
		Name:        "complex-security-policy",
		Description: "Complex security policy with multiple rules",
		Rego: `
			package kube_policies.complex_security
			import future.keywords.contains
			import future.keywords.if
			
			# Deny privileged containers
			deny[msg] {
				input.spec.containers[_].securityContext.privileged == true
				msg := "Privileged containers are not allowed"
			}
			
			# Deny root user
			deny[msg] {
				input.spec.containers[_].securityContext.runAsUser == 0
				msg := "Containers must not run as root user"
			}
			
			# Require resource limits
			deny[msg] {
				container := input.spec.containers[_]
				not container.resources.limits
				msg := sprintf("Container '%s' must have resource limits defined", [container.name])
			}
			
			# Deny latest image tag
			deny[msg] {
				container := input.spec.containers[_]
				endswith(container.image, ":latest")
				msg := sprintf("Container '%s' must not use 'latest' image tag", [container.name])
			}
			
			# Require security context
			deny[msg] {
				container := input.spec.containers[_]
				not container.securityContext
				msg := sprintf("Container '%s' must have security context defined", [container.name])
			}
		`,
	}

	tests := []struct {
		name           string
		resource       *corev1.Pod
		expectedDenies int
	}{
		{
			name: "compliant pod",
			resource: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "compliant-pod",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "compliant-container",
							Image: "nginx:1.20",
							SecurityContext: &corev1.SecurityContext{
								RunAsUser:    &[]int64{1000}[0],
								RunAsNonRoot: &[]bool{true}[0],
								Privileged:   &[]bool{false}[0],
							},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    parseQuantity("100m"),
									corev1.ResourceMemory: parseQuantity("128Mi"),
								},
							},
						},
					},
				},
			},
			expectedDenies: 0,
		},
		{
			name: "non-compliant pod",
			resource: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "non-compliant-pod",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "non-compliant-container",
							Image: "nginx:latest", // Latest tag violation
							SecurityContext: &corev1.SecurityContext{
								RunAsUser:  &[]int64{0}[0],     // Root user violation
								Privileged: &[]bool{true}[0],   // Privileged violation
							},
							// Missing resource limits violation
						},
					},
				},
			},
			expectedDenies: 4, // latest tag, root user, privileged, missing limits
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			denies, err := engine.Evaluate(ctx, tt.resource, []Policy{complexPolicy})

			require.NoError(t, err)
			assert.Len(t, denies, tt.expectedDenies)
		})
	}
}

// Benchmark tests
func BenchmarkPolicyEngine_Evaluate(b *testing.B) {
	engine := NewPolicyEngine()

	policy := Policy{
		Name:        "benchmark-policy",
		Description: "Benchmark policy",
		Rego: `
			package kube_policies.benchmark
			deny[msg] {
				input.spec.containers[_].securityContext.privileged == true
				msg := "Privileged containers are not allowed"
			}
		`,
	}

	resource := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "benchmark-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "benchmark-container",
					Image: "nginx:1.20",
					SecurityContext: &corev1.SecurityContext{
						Privileged: &[]bool{false}[0],
					},
				},
			},
		},
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.Evaluate(ctx, resource, []Policy{policy})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPolicyEngine_EvaluateWithCache(b *testing.B) {
	engine := NewPolicyEngine()
	engine.enableCache = true

	policy := Policy{
		Name:        "benchmark-cache-policy",
		Description: "Benchmark policy with cache",
		Rego: `
			package kube_policies.benchmark_cache
			deny[msg] {
				input.spec.containers[_].securityContext.privileged == true
				msg := "Privileged containers are not allowed"
			}
		`,
	}

	resource := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "benchmark-cache-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "benchmark-cache-container",
					Image: "nginx:1.20",
					SecurityContext: &corev1.SecurityContext{
						Privileged: &[]bool{false}[0],
					},
				},
			},
		},
	}

	ctx := context.Background()

	// Warm up cache
	_, _ = engine.Evaluate(ctx, resource, []Policy{policy})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.Evaluate(ctx, resource, []Policy{policy})
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Helper function to parse resource quantities
func parseQuantity(s string) resource.Quantity {
	q, _ := resource.ParseQuantity(s)
	return q
}

