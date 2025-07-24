package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// MockPolicyEngine is a mock implementation of the policy engine
type MockPolicyEngine struct {
	mock.Mock
}

func (m *MockPolicyEngine) Evaluate(ctx context.Context, resource interface{}, policies []interface{}) ([]string, error) {
	args := m.Called(ctx, resource, policies)
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockPolicyEngine) ValidatePolicy(policy interface{}) error {
	args := m.Called(policy)
	return args.Error(0)
}

// MockAuditLogger is a mock implementation of the audit logger
type MockAuditLogger struct {
	mock.Mock
}

func (m *MockAuditLogger) LogAdmission(ctx context.Context, req *admissionv1.AdmissionRequest, resp *admissionv1.AdmissionResponse, violations []string) error {
	args := m.Called(ctx, req, resp, violations)
	return args.Error(0)
}

func (m *MockAuditLogger) LogPolicyViolation(ctx context.Context, resource interface{}, policy string, violation string) error {
	args := m.Called(ctx, resource, policy, violation)
	return args.Error(0)
}

func TestAdmissionController_HandleValidate(t *testing.T) {
	tests := []struct {
		name           string
		admissionReq   *admissionv1.AdmissionRequest
		policyResult   []string
		policyError    error
		expectedAllow  bool
		expectedResult string
	}{
		{
			name: "valid pod with no violations",
			admissionReq: &admissionv1.AdmissionRequest{
				UID: "test-uid",
				Kind: metav1.GroupVersionKind{
					Group:   "",
					Version: "v1",
					Kind:    "Pod",
				},
				Object: runtime.RawExtension{
					Raw: []byte(`{
						"apiVersion": "v1",
						"kind": "Pod",
						"metadata": {
							"name": "test-pod",
							"namespace": "default"
						},
						"spec": {
							"containers": [{
								"name": "test-container",
								"image": "nginx:1.20",
								"resources": {
									"limits": {
										"cpu": "100m",
										"memory": "128Mi"
									}
								},
								"securityContext": {
									"runAsUser": 1000,
									"runAsNonRoot": true
								}
							}],
							"securityContext": {
								"runAsUser": 1000,
								"runAsNonRoot": true
							}
						}
					}`),
				},
			},
			policyResult:   []string{},
			policyError:    nil,
			expectedAllow:  true,
			expectedResult: "",
		},
		{
			name: "pod with policy violations",
			admissionReq: &admissionv1.AdmissionRequest{
				UID: "test-uid-2",
				Kind: metav1.GroupVersionKind{
					Group:   "",
					Version: "v1",
					Kind:    "Pod",
				},
				Object: runtime.RawExtension{
					Raw: []byte(`{
						"apiVersion": "v1",
						"kind": "Pod",
						"metadata": {
							"name": "privileged-pod",
							"namespace": "default"
						},
						"spec": {
							"containers": [{
								"name": "privileged-container",
								"image": "nginx:latest",
								"securityContext": {
									"privileged": true
								}
							}]
						}
					}`),
				},
			},
			policyResult:   []string{"Privileged containers are not allowed", "Latest image tag is not allowed"},
			policyError:    nil,
			expectedAllow:  false,
			expectedResult: "Policy violations: Privileged containers are not allowed; Latest image tag is not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			mockEngine := new(MockPolicyEngine)
			mockAuditor := new(MockAuditLogger)

			// Configure mock expectations
			mockEngine.On("Evaluate", mock.Anything, mock.Anything, mock.Anything).Return(tt.policyResult, tt.policyError)
			mockAuditor.On("LogAdmission", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

			// Create controller
			controller := &AdmissionController{
				policyEngine: mockEngine,
				auditLogger:  mockAuditor,
			}

			// Create admission review
			admissionReview := &admissionv1.AdmissionReview{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "admission.k8s.io/v1",
					Kind:       "AdmissionReview",
				},
				Request: tt.admissionReq,
			}

			// Marshal to JSON
			reqBody, err := json.Marshal(admissionReview)
			require.NoError(t, err)

			// Create HTTP request
			req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(reqBody))
			req.Header.Set("Content-Type", "application/json")

			// Create response recorder
			w := httptest.NewRecorder()

			// Setup Gin context
			gin.SetMode(gin.TestMode)
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			// Call handler
			controller.HandleValidate(c)

			// Verify response
			assert.Equal(t, http.StatusOK, w.Code)

			var response admissionv1.AdmissionReview
			err = json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedAllow, response.Response.Allowed)
			if !tt.expectedAllow {
				assert.Contains(t, response.Response.Result.Message, tt.expectedResult)
			}

			// Verify mock calls
			mockEngine.AssertExpectations(t)
			mockAuditor.AssertExpectations(t)
		})
	}
}

func TestAdmissionController_HandleMutate(t *testing.T) {
	tests := []struct {
		name         string
		admissionReq *admissionv1.AdmissionRequest
		expectedPatch bool
	}{
		{
			name: "pod without security context gets mutated",
			admissionReq: &admissionv1.AdmissionRequest{
				UID: "test-uid",
				Kind: metav1.GroupVersionKind{
					Group:   "",
					Version: "v1",
					Kind:    "Pod",
				},
				Object: runtime.RawExtension{
					Raw: []byte(`{
						"apiVersion": "v1",
						"kind": "Pod",
						"metadata": {
							"name": "test-pod",
							"namespace": "default"
						},
						"spec": {
							"containers": [{
								"name": "test-container",
								"image": "nginx:1.20"
							}]
						}
					}`),
				},
			},
			expectedPatch: true,
		},
		{
			name: "pod with security context is not mutated",
			admissionReq: &admissionv1.AdmissionRequest{
				UID: "test-uid-2",
				Kind: metav1.GroupVersionKind{
					Group:   "",
					Version: "v1",
					Kind:    "Pod",
				},
				Object: runtime.RawExtension{
					Raw: []byte(`{
						"apiVersion": "v1",
						"kind": "Pod",
						"metadata": {
							"name": "test-pod",
							"namespace": "default"
						},
						"spec": {
							"containers": [{
								"name": "test-container",
								"image": "nginx:1.20",
								"securityContext": {
									"runAsUser": 1000
								}
							}],
							"securityContext": {
								"runAsUser": 1000
							}
						}
					}`),
				},
			},
			expectedPatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			mockAuditor := new(MockAuditLogger)
			mockAuditor.On("LogAdmission", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

			// Create controller
			controller := &AdmissionController{
				auditLogger: mockAuditor,
			}

			// Create admission review
			admissionReview := &admissionv1.AdmissionReview{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "admission.k8s.io/v1",
					Kind:       "AdmissionReview",
				},
				Request: tt.admissionReq,
			}

			// Marshal to JSON
			reqBody, err := json.Marshal(admissionReview)
			require.NoError(t, err)

			// Create HTTP request
			req := httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader(reqBody))
			req.Header.Set("Content-Type", "application/json")

			// Create response recorder
			w := httptest.NewRecorder()

			// Setup Gin context
			gin.SetMode(gin.TestMode)
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			// Call handler
			controller.HandleMutate(c)

			// Verify response
			assert.Equal(t, http.StatusOK, w.Code)

			var response admissionv1.AdmissionReview
			err = json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(t, err)

			assert.True(t, response.Response.Allowed)

			if tt.expectedPatch {
				assert.NotNil(t, response.Response.Patch)
				assert.NotEmpty(t, response.Response.Patch)
			} else {
				assert.Nil(t, response.Response.Patch)
			}

			// Verify mock calls
			mockAuditor.AssertExpectations(t)
		})
	}
}

func TestAdmissionController_parseAdmissionRequest(t *testing.T) {
	controller := &AdmissionController{}

	tests := []struct {
		name        string
		body        string
		expectError bool
	}{
		{
			name: "valid admission review",
			body: `{
				"apiVersion": "admission.k8s.io/v1",
				"kind": "AdmissionReview",
				"request": {
					"uid": "test-uid",
					"kind": {"group": "", "version": "v1", "kind": "Pod"},
					"object": {"apiVersion": "v1", "kind": "Pod"}
				}
			}`,
			expectError: false,
		},
		{
			name:        "invalid JSON",
			body:        `{invalid json}`,
			expectError: true,
		},
		{
			name: "missing request",
			body: `{
				"apiVersion": "admission.k8s.io/v1",
				"kind": "AdmissionReview"
			}`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(tt.body)))
			req.Header.Set("Content-Type", "application/json")

			gin.SetMode(gin.TestMode)
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = req

			admissionReq, err := controller.parseAdmissionRequest(c)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, admissionReq)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, admissionReq)
			}
		})
	}
}

func TestAdmissionController_shouldSkipResource(t *testing.T) {
	controller := &AdmissionController{}

	tests := []struct {
		name      string
		namespace string
		kind      string
		expected  bool
	}{
		{
			name:      "kube-system namespace should be skipped",
			namespace: "kube-system",
			kind:      "Pod",
			expected:  true,
		},
		{
			name:      "kube-public namespace should be skipped",
			namespace: "kube-public",
			kind:      "Pod",
			expected:  true,
		},
		{
			name:      "kube-policies-system namespace should be skipped",
			namespace: "kube-policies-system",
			kind:      "Pod",
			expected:  true,
		},
		{
			name:      "regular namespace should not be skipped",
			namespace: "default",
			kind:      "Pod",
			expected:  false,
		},
		{
			name:      "Event kind should be skipped",
			namespace: "default",
			kind:      "Event",
			expected:  true,
		},
		{
			name:      "Node kind should be skipped",
			namespace: "",
			kind:      "Node",
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &admissionv1.AdmissionRequest{
				Namespace: tt.namespace,
				Kind: metav1.GroupVersionKind{
					Kind: tt.kind,
				},
			}

			result := controller.shouldSkipResource(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAdmissionController_generateSecurityContextPatch(t *testing.T) {
	controller := &AdmissionController{}

	tests := []struct {
		name          string
		pod           *corev1.Pod
		expectedPatch bool
	}{
		{
			name: "pod without security context",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "test-container",
							Image: "nginx:1.20",
						},
					},
				},
			},
			expectedPatch: true,
		},
		{
			name: "pod with security context",
			pod: &corev1.Pod{
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						RunAsUser: &[]int64{1000}[0],
					},
					Containers: []corev1.Container{
						{
							Name:  "test-container",
							Image: "nginx:1.20",
							SecurityContext: &corev1.SecurityContext{
								RunAsUser: &[]int64{1000}[0],
							},
						},
					},
				},
			},
			expectedPatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patch := controller.generateSecurityContextPatch(tt.pod)

			if tt.expectedPatch {
				assert.NotNil(t, patch)
				assert.NotEmpty(t, patch)
			} else {
				assert.Nil(t, patch)
			}
		})
	}
}

// Benchmark tests
func BenchmarkAdmissionController_HandleValidate(b *testing.B) {
	mockEngine := new(MockPolicyEngine)
	mockAuditor := new(MockAuditLogger)

	mockEngine.On("Evaluate", mock.Anything, mock.Anything, mock.Anything).Return([]string{}, nil)
	mockAuditor.On("LogAdmission", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	controller := &AdmissionController{
		policyEngine: mockEngine,
		auditLogger:  mockAuditor,
	}

	admissionReview := &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Request: &admissionv1.AdmissionRequest{
			UID: "test-uid",
			Kind: metav1.GroupVersionKind{
				Group:   "",
				Version: "v1",
				Kind:    "Pod",
			},
			Object: runtime.RawExtension{
				Raw: []byte(`{
					"apiVersion": "v1",
					"kind": "Pod",
					"metadata": {"name": "test-pod", "namespace": "default"},
					"spec": {"containers": [{"name": "test", "image": "nginx:1.20"}]}
				}`),
			},
		},
	}

	reqBody, _ := json.Marshal(admissionReview)

	gin.SetMode(gin.TestMode)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req

		controller.HandleValidate(c)
	}
}

