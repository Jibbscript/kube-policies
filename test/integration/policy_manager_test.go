package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

type PolicyManagerIntegrationTestSuite struct {
	suite.Suite
	testEnv       *envtest.Environment
	cfg           *rest.Config
	k8sClient     kubernetes.Interface
	dynamicClient dynamic.Interface
	ctx           context.Context
	cancel        context.CancelFunc
}

func (suite *PolicyManagerIntegrationTestSuite) SetupSuite() {
	suite.ctx, suite.cancel = context.WithCancel(context.TODO())

	// Setup test environment
	suite.testEnv = &envtest.Environment{
		CRDDirectoryPaths: []string{
			"../../deployments/kubernetes/crds",
		},
		ErrorIfCRDPathMissing: false,
	}

	var err error
	suite.cfg, err = suite.testEnv.Start()
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), suite.cfg)

	// Create Kubernetes clients
	suite.k8sClient, err = kubernetes.NewForConfig(suite.cfg)
	require.NoError(suite.T(), err)

	suite.dynamicClient, err = dynamic.NewForConfig(suite.cfg)
	require.NoError(suite.T(), err)
}

func (suite *PolicyManagerIntegrationTestSuite) TearDownSuite() {
	suite.cancel()
	err := suite.testEnv.Stop()
	require.NoError(suite.T(), err)
}

func (suite *PolicyManagerIntegrationTestSuite) TestPolicyManager_CreatePolicy() {
	// Define policy resource
	policyGVR := schema.GroupVersionResource{
		Group:    "policies.kube-policies.io",
		Version:  "v1",
		Resource: "policies",
	}

	// Create test policy
	policy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "policies.kube-policies.io/v1",
			"kind":       "Policy",
			"metadata": map[string]interface{}{
				"name":      "test-security-policy",
				"namespace": "kube-policies-system",
			},
			"spec": map[string]interface{}{
				"description": "Test security policy",
				"enabled":     true,
				"enforcement": true,
				"match": []interface{}{
					map[string]interface{}{
						"apiGroups":   []interface{}{""},
						"apiVersions": []interface{}{"v1"},
						"resources":   []interface{}{"pods"},
					},
				},
				"rules": []interface{}{
					map[string]interface{}{
						"name":        "no-privileged-containers",
						"severity":    "HIGH",
						"description": "Privileged containers are not allowed",
						"rego": `
							package kube_policies.security
							deny[msg] {
								input.spec.containers[_].securityContext.privileged == true
								msg := "Privileged containers are not allowed"
							}
						`,
					},
				},
			},
		},
	}

	// Create policy via Kubernetes API
	createdPolicy, err := suite.dynamicClient.Resource(policyGVR).Namespace("kube-policies-system").Create(
		suite.ctx, policy, metav1.CreateOptions{})
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), createdPolicy)

	// Verify policy was created
	assert.Equal(suite.T(), "test-security-policy", createdPolicy.GetName())
	assert.Equal(suite.T(), "kube-policies-system", createdPolicy.GetNamespace())

	// Verify policy manager picked up the policy
	time.Sleep(2 * time.Second) // Allow time for policy manager to process

	// Query policy manager API
	policies := suite.getPoliciesFromManager()
	assert.Len(suite.T(), policies, 1)
	assert.Equal(suite.T(), "test-security-policy", policies[0]["name"])

	// Clean up
	err = suite.dynamicClient.Resource(policyGVR).Namespace("kube-policies-system").Delete(
		suite.ctx, "test-security-policy", metav1.DeleteOptions{})
	require.NoError(suite.T(), err)
}

func (suite *PolicyManagerIntegrationTestSuite) TestPolicyManager_UpdatePolicy() {
	// Define policy resource
	policyGVR := schema.GroupVersionResource{
		Group:    "policies.kube-policies.io",
		Version:  "v1",
		Resource: "policies",
	}

	// Create initial policy
	policy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "policies.kube-policies.io/v1",
			"kind":       "Policy",
			"metadata": map[string]interface{}{
				"name":      "update-test-policy",
				"namespace": "kube-policies-system",
			},
			"spec": map[string]interface{}{
				"description": "Initial description",
				"enabled":     true,
				"enforcement": true,
				"rules": []interface{}{
					map[string]interface{}{
						"name":        "test-rule",
						"severity":    "MEDIUM",
						"description": "Test rule",
						"rego":        `package test; deny[msg] { false; msg := "never deny" }`,
					},
				},
			},
		},
	}

	// Create policy
	createdPolicy, err := suite.dynamicClient.Resource(policyGVR).Namespace("kube-policies-system").Create(
		suite.ctx, policy, metav1.CreateOptions{})
	require.NoError(suite.T(), err)

	// Wait for policy manager to process
	time.Sleep(2 * time.Second)

	// Update policy
	createdPolicy.Object["spec"].(map[string]interface{})["description"] = "Updated description"
	rules := createdPolicy.Object["spec"].(map[string]interface{})["rules"].([]interface{})
	rules[0].(map[string]interface{})["severity"] = "HIGH"

	updatedPolicy, err := suite.dynamicClient.Resource(policyGVR).Namespace("kube-policies-system").Update(
		suite.ctx, createdPolicy, metav1.UpdateOptions{})
	require.NoError(suite.T(), err)

	// Wait for policy manager to process update
	time.Sleep(2 * time.Second)

	// Verify update was processed
	policies := suite.getPoliciesFromManager()
	found := false
	for _, p := range policies {
		if p["name"] == "update-test-policy" {
			found = true
			assert.Equal(suite.T(), "Updated description", p["description"])
			rules := p["rules"].([]interface{})
			assert.Equal(suite.T(), "HIGH", rules[0].(map[string]interface{})["severity"])
			break
		}
	}
	assert.True(suite.T(), found, "Updated policy not found")

	// Clean up
	err = suite.dynamicClient.Resource(policyGVR).Namespace("kube-policies-system").Delete(
		suite.ctx, "update-test-policy", metav1.DeleteOptions{})
	require.NoError(suite.T(), err)
}

func (suite *PolicyManagerIntegrationTestSuite) TestPolicyManager_DeletePolicy() {
	// Define policy resource
	policyGVR := schema.GroupVersionResource{
		Group:    "policies.kube-policies.io",
		Version:  "v1",
		Resource: "policies",
	}

	// Create test policy
	policy := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "policies.kube-policies.io/v1",
			"kind":       "Policy",
			"metadata": map[string]interface{}{
				"name":      "delete-test-policy",
				"namespace": "kube-policies-system",
			},
			"spec": map[string]interface{}{
				"description": "Policy to be deleted",
				"enabled":     true,
				"rules": []interface{}{
					map[string]interface{}{
						"name": "test-rule",
						"rego": `package test; deny[msg] { false; msg := "never deny" }`,
					},
				},
			},
		},
	}

	// Create policy
	_, err := suite.dynamicClient.Resource(policyGVR).Namespace("kube-policies-system").Create(
		suite.ctx, policy, metav1.CreateOptions{})
	require.NoError(suite.T(), err)

	// Wait for policy manager to process
	time.Sleep(2 * time.Second)

	// Verify policy exists
	policies := suite.getPoliciesFromManager()
	found := false
	for _, p := range policies {
		if p["name"] == "delete-test-policy" {
			found = true
			break
		}
	}
	assert.True(suite.T(), found, "Policy should exist before deletion")

	// Delete policy
	err = suite.dynamicClient.Resource(policyGVR).Namespace("kube-policies-system").Delete(
		suite.ctx, "delete-test-policy", metav1.DeleteOptions{})
	require.NoError(suite.T(), err)

	// Wait for policy manager to process deletion
	time.Sleep(2 * time.Second)

	// Verify policy was removed
	policies = suite.getPoliciesFromManager()
	found = false
	for _, p := range policies {
		if p["name"] == "delete-test-policy" {
			found = true
			break
		}
	}
	assert.False(suite.T(), found, "Policy should be deleted")
}

func (suite *PolicyManagerIntegrationTestSuite) TestPolicyManager_PolicyException() {
	// Define exception resource
	exceptionGVR := schema.GroupVersionResource{
		Group:    "policies.kube-policies.io",
		Version:  "v1",
		Resource: "policyexceptions",
	}

	// Create test exception
	exception := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "policies.kube-policies.io/v1",
			"kind":       "PolicyException",
			"metadata": map[string]interface{}{
				"name":      "test-exception",
				"namespace": "default",
			},
			"spec": map[string]interface{}{
				"description":   "Test exception",
				"policy":        "security-baseline",
				"rules":         []interface{}{"no-privileged-containers"},
				"duration":      "24h",
				"justification": "Emergency deployment",
				"selector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app": "emergency-app",
					},
				},
			},
		},
	}

	// Create exception
	createdException, err := suite.dynamicClient.Resource(exceptionGVR).Namespace("default").Create(
		suite.ctx, exception, metav1.CreateOptions{})
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), createdException)

	// Wait for policy manager to process
	time.Sleep(2 * time.Second)

	// Verify exception was processed
	exceptions := suite.getExceptionsFromManager()
	found := false
	for _, e := range exceptions {
		if e["name"] == "test-exception" {
			found = true
			assert.Equal(suite.T(), "security-baseline", e["policy"])
			assert.Equal(suite.T(), "Emergency deployment", e["justification"])
			break
		}
	}
	assert.True(suite.T(), found, "Exception should be processed")

	// Clean up
	err = suite.dynamicClient.Resource(exceptionGVR).Namespace("default").Delete(
		suite.ctx, "test-exception", metav1.DeleteOptions{})
	require.NoError(suite.T(), err)
}

func (suite *PolicyManagerIntegrationTestSuite) TestPolicyManager_PolicyValidation() {
	// Test policy validation endpoint
	invalidPolicy := map[string]interface{}{
		"name":        "invalid-policy",
		"description": "Policy with invalid Rego",
		"rules": []interface{}{
			map[string]interface{}{
				"name": "invalid-rule",
				"rego": "invalid rego syntax {{{",
			},
		},
	}

	// Send validation request
	response := suite.sendPolicyValidationRequest(invalidPolicy)
	assert.False(suite.T(), response["valid"].(bool))
	assert.Contains(suite.T(), response["error"].(string), "syntax")

	// Test valid policy
	validPolicy := map[string]interface{}{
		"name":        "valid-policy",
		"description": "Policy with valid Rego",
		"rules": []interface{}{
			map[string]interface{}{
				"name": "valid-rule",
				"rego": `
					package kube_policies.test
					deny[msg] {
						input.spec.containers[_].securityContext.privileged == true
						msg := "Privileged containers are not allowed"
					}
				`,
			},
		},
	}

	response = suite.sendPolicyValidationRequest(validPolicy)
	assert.True(suite.T(), response["valid"].(bool))
	assert.Empty(suite.T(), response["error"])
}

func (suite *PolicyManagerIntegrationTestSuite) TestPolicyManager_PolicyEvaluation() {
	// Test policy evaluation endpoint
	testResource := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":      "test-pod",
			"namespace": "default",
		},
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":  "test-container",
					"image": "nginx:latest",
					"securityContext": map[string]interface{}{
						"privileged": true,
					},
				},
			},
		},
	}

	testPolicy := map[string]interface{}{
		"name":        "test-evaluation-policy",
		"description": "Policy for evaluation test",
		"rules": []interface{}{
			map[string]interface{}{
				"name": "no-privileged",
				"rego": `
					package kube_policies.test
					deny[msg] {
						input.spec.containers[_].securityContext.privileged == true
						msg := "Privileged containers are not allowed"
					}
				`,
			},
			map[string]interface{}{
				"name": "no-latest-tag",
				"rego": `
					package kube_policies.test
					import future.keywords.contains
					deny[msg] {
						container := input.spec.containers[_]
						endswith(container.image, ":latest")
						msg := "Latest image tag is not allowed"
					}
				`,
			},
		},
	}

	evaluationRequest := map[string]interface{}{
		"resource": testResource,
		"policy":   testPolicy,
	}

	// Send evaluation request
	response := suite.sendPolicyEvaluationRequest(evaluationRequest)
	violations := response["violations"].([]interface{})

	// Should have violations for both privileged container and latest tag
	assert.Len(suite.T(), violations, 2)
	violationMessages := make([]string, len(violations))
	for i, v := range violations {
		violationMessages[i] = v.(string)
	}
	assert.Contains(suite.T(), violationMessages, "Privileged containers are not allowed")
	assert.Contains(suite.T(), violationMessages, "Latest image tag is not allowed")
}

func (suite *PolicyManagerIntegrationTestSuite) TestPolicyManager_Metrics() {
	// Test metrics endpoint
	metricsResponse := suite.getMetricsFromManager()

	// Should contain basic metrics
	assert.Contains(suite.T(), metricsResponse, "kube_policies_active_policies_total")
	assert.Contains(suite.T(), metricsResponse, "kube_policies_policy_evaluations_total")
}

func (suite *PolicyManagerIntegrationTestSuite) TestPolicyManager_HealthCheck() {
	// Test health check endpoint
	healthResponse := suite.getHealthFromManager()

	assert.Equal(suite.T(), "ok", healthResponse["status"])
	assert.NotEmpty(suite.T(), healthResponse["timestamp"])
}

func (suite *PolicyManagerIntegrationTestSuite) TestPolicyManager_ConcurrentOperations() {
	// Test concurrent policy operations
	numGoroutines := 5
	numPoliciesPerGoroutine := 3
	results := make(chan error, numGoroutines*numPoliciesPerGoroutine)

	policyGVR := schema.GroupVersionResource{
		Group:    "policies.kube-policies.io",
		Version:  "v1",
		Resource: "policies",
	}

	// Launch concurrent policy creation
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < numPoliciesPerGoroutine; j++ {
				policyName := fmt.Sprintf("concurrent-policy-%d-%d", id, j)
				policy := &unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "policies.kube-policies.io/v1",
						"kind":       "Policy",
						"metadata": map[string]interface{}{
							"name":      policyName,
							"namespace": "kube-policies-system",
						},
						"spec": map[string]interface{}{
							"description": fmt.Sprintf("Concurrent test policy %d-%d", id, j),
							"enabled":     true,
							"rules": []interface{}{
								map[string]interface{}{
									"name": "test-rule",
									"rego": `package test; deny[msg] { false; msg := "never deny" }`,
								},
							},
						},
					},
				}

				_, err := suite.dynamicClient.Resource(policyGVR).Namespace("kube-policies-system").Create(
					suite.ctx, policy, metav1.CreateOptions{})
				results <- err
			}
		}(i)
	}

	// Collect results
	errorCount := 0
	for i := 0; i < numGoroutines*numPoliciesPerGoroutine; i++ {
		if err := <-results; err != nil {
			errorCount++
			suite.T().Logf("Error creating policy: %v", err)
		}
	}

	// Most operations should succeed
	assert.Less(suite.T(), errorCount, numGoroutines*numPoliciesPerGoroutine/2, "Too many errors in concurrent operations")

	// Clean up created policies
	time.Sleep(2 * time.Second)
	for i := 0; i < numGoroutines; i++ {
		for j := 0; j < numPoliciesPerGoroutine; j++ {
			policyName := fmt.Sprintf("concurrent-policy-%d-%d", i, j)
			_ = suite.dynamicClient.Resource(policyGVR).Namespace("kube-policies-system").Delete(
				suite.ctx, policyName, metav1.DeleteOptions{})
		}
	}
}

// Helper methods

func (suite *PolicyManagerIntegrationTestSuite) getPoliciesFromManager() []map[string]interface{} {
	resp, err := http.Get("http://localhost:8080/api/v1/policies")
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(suite.T(), err)

	policies, ok := response["policies"].([]interface{})
	if !ok {
		return []map[string]interface{}{}
	}

	result := make([]map[string]interface{}, len(policies))
	for i, p := range policies {
		result[i] = p.(map[string]interface{})
	}
	return result
}

func (suite *PolicyManagerIntegrationTestSuite) getExceptionsFromManager() []map[string]interface{} {
	resp, err := http.Get("http://localhost:8080/api/v1/exceptions")
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(suite.T(), err)

	exceptions, ok := response["exceptions"].([]interface{})
	if !ok {
		return []map[string]interface{}{}
	}

	result := make([]map[string]interface{}, len(exceptions))
	for i, e := range exceptions {
		result[i] = e.(map[string]interface{})
	}
	return result
}

func (suite *PolicyManagerIntegrationTestSuite) sendPolicyValidationRequest(policy map[string]interface{}) map[string]interface{} {
	reqBody, err := json.Marshal(policy)
	require.NoError(suite.T(), err)

	resp, err := http.Post("http://localhost:8080/api/v1/policies/validate", "application/json", bytes.NewReader(reqBody))
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(suite.T(), err)

	return response
}

func (suite *PolicyManagerIntegrationTestSuite) sendPolicyEvaluationRequest(request map[string]interface{}) map[string]interface{} {
	reqBody, err := json.Marshal(request)
	require.NoError(suite.T(), err)

	resp, err := http.Post("http://localhost:8080/api/v1/policies/evaluate", "application/json", bytes.NewReader(reqBody))
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(suite.T(), err)

	return response
}

func (suite *PolicyManagerIntegrationTestSuite) getMetricsFromManager() string {
	resp, err := http.Get("http://localhost:8080/metrics")
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	var buf bytes.Buffer
	_, err = buf.ReadFrom(resp.Body)
	require.NoError(suite.T(), err)

	return buf.String()
}

func (suite *PolicyManagerIntegrationTestSuite) getHealthFromManager() map[string]interface{} {
	resp, err := http.Get("http://localhost:8080/healthz")
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	var response map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&response)
	require.NoError(suite.T(), err)

	return response
}

func TestPolicyManagerIntegrationTestSuite(t *testing.T) {
	suite.Run(t, new(PolicyManagerIntegrationTestSuite))
}
