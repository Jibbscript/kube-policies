package audit

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestFileAuditLogger_LogAdmission(t *testing.T) {
	// Create temporary directory for test logs
	tempDir, err := ioutil.TempDir("", "audit-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	logFile := filepath.Join(tempDir, "audit.log")

	config := FileBackendConfig{
		Path:     logFile,
		MaxSize:  "10MB",
		MaxFiles: 5,
	}

	logger, err := NewFileAuditLogger(config)
	require.NoError(t, err)
	defer logger.Close()

	// Test admission request
	req := &admissionv1.AdmissionRequest{
		UID: "test-uid",
		Kind: metav1.GroupVersionKind{
			Group:   "",
			Version: "v1",
			Kind:    "Pod",
		},
		Namespace: "default",
		Name:      "test-pod",
		Object: runtime.RawExtension{
			Raw: []byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test-pod"}}`),
		},
		UserInfo: authenticationv1.UserInfo{
			Username: "test-user",
			Groups:   []string{"system:authenticated"},
		},
	}

	// Test admission response
	resp := &admissionv1.AdmissionResponse{
		UID:     req.UID,
		Allowed: false,
		Result: &metav1.Status{
			Code:    403,
			Message: "Policy violation",
		},
	}

	violations := []string{"Privileged containers are not allowed"}

	// Log admission
	ctx := context.Background()
	err = logger.LogAdmission(ctx, req, resp, violations)
	require.NoError(t, err)

	// Verify log file exists and contains expected content
	assert.FileExists(t, logFile)

	content, err := ioutil.ReadFile(logFile)
	require.NoError(t, err)

	var logEntry map[string]interface{}
	err = json.Unmarshal(content, &logEntry)
	require.NoError(t, err)

	assert.Equal(t, "admission", logEntry["event_type"])
	assert.Equal(t, "test-uid", logEntry["request_uid"])
	assert.Equal(t, "Pod", logEntry["resource_kind"])
	assert.Equal(t, "default", logEntry["resource_namespace"])
	assert.Equal(t, "test-pod", logEntry["resource_name"])
	assert.Equal(t, false, logEntry["allowed"])
	assert.Equal(t, "test-user", logEntry["user"])
	assert.Contains(t, logEntry["violations"], "Privileged containers are not allowed")
}

func TestFileAuditLogger_LogPolicyViolation(t *testing.T) {
	// Create temporary directory for test logs
	tempDir, err := ioutil.TempDir("", "audit-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	logFile := filepath.Join(tempDir, "audit.log")

	config := FileBackendConfig{
		Path:     logFile,
		MaxSize:  "10MB",
		MaxFiles: 5,
	}

	logger, err := NewFileAuditLogger(config)
	require.NoError(t, err)
	defer logger.Close()

	// Test resource
	resource := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":      "test-pod",
			"namespace": "default",
		},
	}

	// Log policy violation
	ctx := context.Background()
	err = logger.LogPolicyViolation(ctx, resource, "security-baseline", "Privileged containers are not allowed")
	require.NoError(t, err)

	// Verify log file exists and contains expected content
	assert.FileExists(t, logFile)

	content, err := ioutil.ReadFile(logFile)
	require.NoError(t, err)

	var logEntry map[string]interface{}
	err = json.Unmarshal(content, &logEntry)
	require.NoError(t, err)

	assert.Equal(t, "policy_violation", logEntry["event_type"])
	assert.Equal(t, "security-baseline", logEntry["policy"])
	assert.Equal(t, "Privileged containers are not allowed", logEntry["violation"])
	assert.Equal(t, "Pod", logEntry["resource_kind"])
	assert.Equal(t, "default", logEntry["resource_namespace"])
	assert.Equal(t, "test-pod", logEntry["resource_name"])
}

func TestFileAuditLogger_Rotation(t *testing.T) {
	// Create temporary directory for test logs
	tempDir, err := ioutil.TempDir("", "audit-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	logFile := filepath.Join(tempDir, "audit.log")

	config := FileBackendConfig{
		Path:     logFile,
		MaxSize:  "1KB", // Very small size to trigger rotation
		MaxFiles: 3,
	}

	logger, err := NewFileAuditLogger(config)
	require.NoError(t, err)
	defer logger.Close()

	// Generate enough log entries to trigger rotation
	ctx := context.Background()
	for i := 0; i < 100; i++ {
		resource := map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]interface{}{
				"name":      "test-pod-" + string(rune(i)),
				"namespace": "default",
			},
		}

		err = logger.LogPolicyViolation(ctx, resource, "test-policy", "Test violation message that is long enough to trigger rotation")
		require.NoError(t, err)
	}

	// Check that rotation occurred
	files, err := filepath.Glob(filepath.Join(tempDir, "audit.log*"))
	require.NoError(t, err)
	assert.True(t, len(files) > 1, "Expected log rotation to create multiple files")
}

func TestWebhookAuditLogger_LogAdmission(t *testing.T) {
	// Mock webhook server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		body, err := ioutil.ReadAll(r.Body)
		require.NoError(t, err)

		var logEntry map[string]interface{}
		err = json.Unmarshal(body, &logEntry)
		require.NoError(t, err)

		assert.Equal(t, "admission", logEntry["event_type"])
		assert.Equal(t, "test-uid", logEntry["request_uid"])

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := WebhookBackendConfig{
		URL: server.URL,
		Headers: map[string]string{
			"Authorization": "Bearer test-token",
		},
		Timeout: 5 * time.Second,
	}

	logger, err := NewWebhookAuditLogger(config)
	require.NoError(t, err)

	// Test admission request
	req := &admissionv1.AdmissionRequest{
		UID: "test-uid",
		Kind: metav1.GroupVersionKind{
			Group:   "",
			Version: "v1",
			Kind:    "Pod",
		},
		Namespace: "default",
		Name:      "test-pod",
	}

	resp := &admissionv1.AdmissionResponse{
		UID:     req.UID,
		Allowed: true,
	}

	violations := []string{}

	// Log admission
	ctx := context.Background()
	err = logger.LogAdmission(ctx, req, resp, violations)
	require.NoError(t, err)
}

func TestWebhookAuditLogger_LogPolicyViolation(t *testing.T) {
	// Mock webhook server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		body, err := ioutil.ReadAll(r.Body)
		require.NoError(t, err)

		var logEntry map[string]interface{}
		err = json.Unmarshal(body, &logEntry)
		require.NoError(t, err)

		assert.Equal(t, "policy_violation", logEntry["event_type"])
		assert.Equal(t, "test-policy", logEntry["policy"])

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := WebhookBackendConfig{
		URL:     server.URL,
		Timeout: 5 * time.Second,
	}

	logger, err := NewWebhookAuditLogger(config)
	require.NoError(t, err)

	resource := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":      "test-pod",
			"namespace": "default",
		},
	}

	// Log policy violation
	ctx := context.Background()
	err = logger.LogPolicyViolation(ctx, resource, "test-policy", "Test violation")
	require.NoError(t, err)
}

func TestElasticsearchAuditLogger_LogAdmission(t *testing.T) {
	// Skip if no Elasticsearch available
	if testing.Short() {
		t.Skip("Skipping Elasticsearch test in short mode")
	}

	// Mock Elasticsearch server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Contains(t, r.URL.Path, "/kube-policies-audit")
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		body, err := ioutil.ReadAll(r.Body)
		require.NoError(t, err)

		var logEntry map[string]interface{}
		err = json.Unmarshal(body, &logEntry)
		require.NoError(t, err)

		assert.Equal(t, "admission", logEntry["event_type"])

		// Mock successful response
		response := map[string]interface{}{
			"_index":   "kube-policies-audit",
			"_type":    "_doc",
			"_id":      "test-id",
			"_version": 1,
			"result":   "created",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := ElasticsearchBackendConfig{
		URL:      server.URL,
		Index:    "kube-policies-audit",
		Username: "elastic",
		Password: "password",
		Timeout:  5 * time.Second,
	}

	logger, err := NewElasticsearchAuditLogger(config)
	require.NoError(t, err)

	// Test admission request
	req := &admissionv1.AdmissionRequest{
		UID: "test-uid",
		Kind: metav1.GroupVersionKind{
			Group:   "",
			Version: "v1",
			Kind:    "Pod",
		},
		Namespace: "default",
		Name:      "test-pod",
	}

	resp := &admissionv1.AdmissionResponse{
		UID:     req.UID,
		Allowed: true,
	}

	violations := []string{}

	// Log admission
	ctx := context.Background()
	err = logger.LogAdmission(ctx, req, resp, violations)
	require.NoError(t, err)
}

func TestMultiBackendAuditLogger(t *testing.T) {
	// Create temporary directory for file backend
	tempDir, err := ioutil.TempDir("", "audit-test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	logFile := filepath.Join(tempDir, "audit.log")

	// Create file backend
	fileConfig := FileBackendConfig{
		Path:     logFile,
		MaxSize:  "10MB",
		MaxFiles: 5,
	}

	fileLogger, err := NewFileAuditLogger(fileConfig)
	require.NoError(t, err)
	defer fileLogger.Close()

	// Create webhook backend
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	webhookConfig := WebhookBackendConfig{
		URL:     server.URL,
		Timeout: 5 * time.Second,
	}

	webhookLogger, err := NewWebhookAuditLogger(webhookConfig)
	require.NoError(t, err)

	// Create multi-backend logger
	multiLogger := NewMultiBackendAuditLogger([]AuditLogger{fileLogger, webhookLogger})

	// Test logging
	resource := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":      "test-pod",
			"namespace": "default",
		},
	}

	ctx := context.Background()
	err = multiLogger.LogPolicyViolation(ctx, resource, "test-policy", "Test violation")
	require.NoError(t, err)

	// Verify file backend received the log
	assert.FileExists(t, logFile)
	content, err := ioutil.ReadFile(logFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "policy_violation")
}

// Benchmark tests
func BenchmarkFileAuditLogger_LogAdmission(b *testing.B) {
	tempDir, err := ioutil.TempDir("", "audit-bench")
	require.NoError(b, err)
	defer os.RemoveAll(tempDir)

	logFile := filepath.Join(tempDir, "audit.log")

	config := FileBackendConfig{
		Path:     logFile,
		MaxSize:  "100MB",
		MaxFiles: 5,
	}

	logger, err := NewFileAuditLogger(config)
	require.NoError(b, err)
	defer logger.Close()

	req := &admissionv1.AdmissionRequest{
		UID: "benchmark-uid",
		Kind: metav1.GroupVersionKind{
			Group:   "",
			Version: "v1",
			Kind:    "Pod",
		},
		Namespace: "default",
		Name:      "benchmark-pod",
	}

	resp := &admissionv1.AdmissionResponse{
		UID:     req.UID,
		Allowed: true,
	}

	violations := []string{}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := logger.LogAdmission(ctx, req, resp, violations)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWebhookAuditLogger_LogAdmission(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := WebhookBackendConfig{
		URL:     server.URL,
		Timeout: 5 * time.Second,
	}

	logger, err := NewWebhookAuditLogger(config)
	require.NoError(b, err)

	req := &admissionv1.AdmissionRequest{
		UID: "benchmark-uid",
		Kind: metav1.GroupVersionKind{
			Group:   "",
			Version: "v1",
			Kind:    "Pod",
		},
		Namespace: "default",
		Name:      "benchmark-pod",
	}

	resp := &admissionv1.AdmissionResponse{
		UID:     req.UID,
		Allowed: true,
	}

	violations := []string{}
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := logger.LogAdmission(ctx, req, resp, violations)
		if err != nil {
			b.Fatal(err)
		}
	}
}

