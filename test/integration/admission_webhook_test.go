package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

type AdmissionWebhookIntegrationTestSuite struct {
	suite.Suite
	testEnv   *envtest.Environment
	cfg       *rest.Config
	k8sClient kubernetes.Interface
	ctx       context.Context
	cancel    context.CancelFunc
}

func (suite *AdmissionWebhookIntegrationTestSuite) SetupSuite() {
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

	// Create Kubernetes client
	suite.k8sClient, err = kubernetes.NewForConfig(suite.cfg)
	require.NoError(suite.T(), err)
}

func (suite *AdmissionWebhookIntegrationTestSuite) TearDownSuite() {
	suite.cancel()
	err := suite.testEnv.Stop()
	require.NoError(suite.T(), err)
}

func (suite *AdmissionWebhookIntegrationTestSuite) TestAdmissionWebhook_ValidatingWebhook() {
	tests := []struct {
		name           string
		pod            *corev1.Pod
		expectedAllow  bool
		expectedReason string
	}{
		{
			name: "valid pod should be allowed",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "valid-pod",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						RunAsUser:    &[]int64{1000}[0],
						RunAsNonRoot: &[]bool{true}[0],
					},
					Containers: []corev1.Container{
						{
							Name:  "valid-container",
							Image: "nginx:1.20",
							SecurityContext: &corev1.SecurityContext{
								RunAsUser:    &[]int64{1000}[0],
								RunAsNonRoot: &[]bool{true}[0],
								Privileged:   &[]bool{false}[0],
							},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("50m"),
									corev1.ResourceMemory: resource.MustParse("64Mi"),
								},
							},
						},
					},
				},
			},
			expectedAllow:  true,
			expectedReason: "",
		},
		{
			name: "privileged pod should be denied",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "privileged-pod",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
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
			expectedAllow:  false,
			expectedReason: "Privileged containers are not allowed",
		},
		{
			name: "root user pod should be denied",
			pod: &corev1.Pod{
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
			expectedAllow:  false,
			expectedReason: "Containers must not run as root user",
		},
		{
			name: "pod with latest tag should be denied",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "latest-tag-pod",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "latest-container",
							Image: "nginx:latest",
							SecurityContext: &corev1.SecurityContext{
								RunAsUser:    &[]int64{1000}[0],
								RunAsNonRoot: &[]bool{true}[0],
							},
						},
					},
				},
			},
			expectedAllow:  false,
			expectedReason: "must not use 'latest' image tag",
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			// Create admission request
			podBytes, err := json.Marshal(tt.pod)
			require.NoError(suite.T(), err)

			admissionReq := &admissionv1.AdmissionRequest{
				UID: "test-uid",
				Kind: metav1.GroupVersionKind{
					Group:   "",
					Version: "v1",
					Kind:    "Pod",
				},
				Namespace: tt.pod.Namespace,
				Name:      tt.pod.Name,
				Object: runtime.RawExtension{
					Raw: podBytes,
				},
				Operation: admissionv1.Create,
			}

			admissionReview := &admissionv1.AdmissionReview{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "admission.k8s.io/v1",
					Kind:       "AdmissionReview",
				},
				Request: admissionReq,
			}

			// Send request to webhook
			response := suite.sendAdmissionRequest(admissionReview, "/validate")

			// Verify response
			assert.Equal(suite.T(), tt.expectedAllow, response.Response.Allowed)
			if !tt.expectedAllow {
				assert.Contains(suite.T(), response.Response.Result.Message, tt.expectedReason)
			}
		})
	}
}

func (suite *AdmissionWebhookIntegrationTestSuite) TestAdmissionWebhook_MutatingWebhook() {
	tests := []struct {
		name          string
		pod           *corev1.Pod
		expectMutated bool
		expectedPatch string
	}{
		{
			name: "pod without security context should be mutated",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "no-security-context-pod",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "no-security-container",
							Image: "nginx:1.20",
						},
					},
				},
			},
			expectMutated: true,
			expectedPatch: "securityContext",
		},
		{
			name: "pod with security context should not be mutated",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "with-security-context-pod",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						RunAsUser:    &[]int64{1000}[0],
						RunAsNonRoot: &[]bool{true}[0],
					},
					Containers: []corev1.Container{
						{
							Name:  "with-security-container",
							Image: "nginx:1.20",
							SecurityContext: &corev1.SecurityContext{
								RunAsUser:    &[]int64{1000}[0],
								RunAsNonRoot: &[]bool{true}[0],
							},
						},
					},
				},
			},
			expectMutated: false,
			expectedPatch: "",
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			// Create admission request
			podBytes, err := json.Marshal(tt.pod)
			require.NoError(suite.T(), err)

			admissionReq := &admissionv1.AdmissionRequest{
				UID: "test-uid",
				Kind: metav1.GroupVersionKind{
					Group:   "",
					Version: "v1",
					Kind:    "Pod",
				},
				Namespace: tt.pod.Namespace,
				Name:      tt.pod.Name,
				Object: runtime.RawExtension{
					Raw: podBytes,
				},
				Operation: admissionv1.Create,
			}

			admissionReview := &admissionv1.AdmissionReview{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "admission.k8s.io/v1",
					Kind:       "AdmissionReview",
				},
				Request: admissionReq,
			}

			// Send request to webhook
			response := suite.sendAdmissionRequest(admissionReview, "/mutate")

			// Verify response
			assert.True(suite.T(), response.Response.Allowed)

			if tt.expectMutated {
				assert.NotNil(suite.T(), response.Response.Patch)
				assert.NotEmpty(suite.T(), response.Response.Patch)
				if tt.expectedPatch != "" {
					patchStr := string(response.Response.Patch)
					assert.Contains(suite.T(), patchStr, tt.expectedPatch)
				}
			} else {
				assert.Nil(suite.T(), response.Response.Patch)
			}
		})
	}
}

func (suite *AdmissionWebhookIntegrationTestSuite) TestAdmissionWebhook_NamespaceExclusion() {
	systemNamespaces := []string{"kube-system", "kube-public", "kube-policies-system"}

	for _, namespace := range systemNamespaces {
		suite.Run(fmt.Sprintf("system namespace %s should be excluded", namespace), func() {
			// Create a privileged pod in system namespace
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "privileged-system-pod",
					Namespace: namespace,
				},
				Spec: corev1.PodSpec{
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
			}

			// Create admission request
			podBytes, err := json.Marshal(pod)
			require.NoError(suite.T(), err)

			admissionReq := &admissionv1.AdmissionRequest{
				UID: "test-uid",
				Kind: metav1.GroupVersionKind{
					Group:   "",
					Version: "v1",
					Kind:    "Pod",
				},
				Namespace: namespace,
				Name:      pod.Name,
				Object: runtime.RawExtension{
					Raw: podBytes,
				},
				Operation: admissionv1.Create,
			}

			admissionReview := &admissionv1.AdmissionReview{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "admission.k8s.io/v1",
					Kind:       "AdmissionReview",
				},
				Request: admissionReq,
			}

			// Send request to webhook
			response := suite.sendAdmissionRequest(admissionReview, "/validate")

			// System namespaces should be allowed even with policy violations
			assert.True(suite.T(), response.Response.Allowed)
		})
	}
}

func (suite *AdmissionWebhookIntegrationTestSuite) TestAdmissionWebhook_Performance() {
	// Test webhook performance under load
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "performance-test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsUser:    &[]int64{1000}[0],
				RunAsNonRoot: &[]bool{true}[0],
			},
			Containers: []corev1.Container{
				{
					Name:  "performance-container",
					Image: "nginx:1.20",
					SecurityContext: &corev1.SecurityContext{
						RunAsUser:    &[]int64{1000}[0],
						RunAsNonRoot: &[]bool{true}[0],
					},
				},
			},
		},
	}

	podBytes, err := json.Marshal(pod)
	require.NoError(suite.T(), err)

	admissionReq := &admissionv1.AdmissionRequest{
		UID: "performance-test-uid",
		Kind: metav1.GroupVersionKind{
			Group:   "",
			Version: "v1",
			Kind:    "Pod",
		},
		Namespace: pod.Namespace,
		Name:      pod.Name,
		Object: runtime.RawExtension{
			Raw: podBytes,
		},
		Operation: admissionv1.Create,
	}

	admissionReview := &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Request: admissionReq,
	}

	// Measure response time for multiple requests
	numRequests := 100
	totalDuration := time.Duration(0)

	for i := 0; i < numRequests; i++ {
		start := time.Now()
		response := suite.sendAdmissionRequest(admissionReview, "/validate")
		duration := time.Since(start)
		totalDuration += duration

		assert.True(suite.T(), response.Response.Allowed)
	}

	avgDuration := totalDuration / time.Duration(numRequests)
	suite.T().Logf("Average response time: %v", avgDuration)

	// Assert that average response time is under 100ms
	assert.Less(suite.T(), avgDuration, 100*time.Millisecond, "Webhook response time should be under 100ms")
}

func (suite *AdmissionWebhookIntegrationTestSuite) TestAdmissionWebhook_ConcurrentRequests() {
	// Test webhook handling concurrent requests
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "concurrent-test-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsUser:    &[]int64{1000}[0],
				RunAsNonRoot: &[]bool{true}[0],
			},
			Containers: []corev1.Container{
				{
					Name:  "concurrent-container",
					Image: "nginx:1.20",
					SecurityContext: &corev1.SecurityContext{
						RunAsUser:    &[]int64{1000}[0],
						RunAsNonRoot: &[]bool{true}[0],
					},
				},
			},
		},
	}

	podBytes, err := json.Marshal(pod)
	require.NoError(suite.T(), err)

	numGoroutines := 10
	numRequestsPerGoroutine := 10
	results := make(chan bool, numGoroutines*numRequestsPerGoroutine)

	// Launch concurrent requests
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < numRequestsPerGoroutine; j++ {
				admissionReq := &admissionv1.AdmissionRequest{
					UID: fmt.Sprintf("concurrent-test-uid-%d-%d", id, j),
					Kind: metav1.GroupVersionKind{
						Group:   "",
						Version: "v1",
						Kind:    "Pod",
					},
					Namespace: pod.Namespace,
					Name:      fmt.Sprintf("%s-%d-%d", pod.Name, id, j),
					Object: runtime.RawExtension{
						Raw: podBytes,
					},
					Operation: admissionv1.Create,
				}

				admissionReview := &admissionv1.AdmissionReview{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "admission.k8s.io/v1",
						Kind:       "AdmissionReview",
					},
					Request: admissionReq,
				}

				response := suite.sendAdmissionRequest(admissionReview, "/validate")
				results <- response.Response.Allowed
			}
		}(i)
	}

	// Collect results
	successCount := 0
	for i := 0; i < numGoroutines*numRequestsPerGoroutine; i++ {
		if <-results {
			successCount++
		}
	}

	// All requests should succeed
	assert.Equal(suite.T(), numGoroutines*numRequestsPerGoroutine, successCount)
}

func (suite *AdmissionWebhookIntegrationTestSuite) sendAdmissionRequest(admissionReview *admissionv1.AdmissionReview, endpoint string) *admissionv1.AdmissionReview {
	// Marshal admission review
	reqBody, err := json.Marshal(admissionReview)
	require.NoError(suite.T(), err)

	// Create HTTP client with TLS config
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}

	// Send request to webhook (assuming webhook is running on localhost:8443)
	webhookURL := fmt.Sprintf("https://localhost:8443%s", endpoint)
	req, err := http.NewRequest("POST", webhookURL, bytes.NewReader(reqBody))
	require.NoError(suite.T(), err)

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	// Parse response
	var responseReview admissionv1.AdmissionReview
	err = json.NewDecoder(resp.Body).Decode(&responseReview)
	require.NoError(suite.T(), err)

	return &responseReview
}

func TestAdmissionWebhookIntegrationTestSuite(t *testing.T) {
	suite.Run(t, new(AdmissionWebhookIntegrationTestSuite))
}

