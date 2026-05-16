package policymanager

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/Jibbscript/kube-policies/internal/config"
	"github.com/Jibbscript/kube-policies/internal/policy"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// privilegedRule denies pods whose spec.securityContext.privileged is true.
// Matches the engine.evaluatePolicy contract (data.kube_policies.evaluate
// returns {allowed, message, path}).
const privilegedRego = `
package kube_policies

evaluate = result {
	input.object.spec.securityContext.privileged == true
	result := {
		"allowed": false,
		"message": "Privileged containers are not allowed",
		"path": "spec.securityContext.privileged"
	}
}

evaluate = result {
	not input.object.spec.securityContext.privileged
	result := {"allowed": true}
}
`

func newTestManagerWithPolicy(t *testing.T, p *policy.Policy) *Manager {
	t.Helper()
	cfg := &config.Config{}
	m, err := NewManager(cfg, zap.NewNop())
	require.NoError(t, err)
	if p != nil {
		m.policies[p.ID] = p
	}
	return m
}

func newPrivilegedPolicy() *policy.Policy {
	now := time.Now()
	return &policy.Policy{
		ID:          "test-no-privileged",
		Name:        "no privileged",
		Description: "deny privileged containers",
		Version:     "1.0.0",
		Enabled:     true,
		Rules: []policy.Rule{
			{
				ID:       "no-privileged-containers",
				Name:     "no privileged",
				Rego:     privilegedRego,
				Severity: "HIGH",
				Category: "Security",
			},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func doTestRequest(t *testing.T, m *Manager, policyID string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = gin.Params{{Key: "id", Value: policyID}}
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/policies/"+policyID+"/test", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	m.TestPolicy(c)
	return w
}

func TestTestPolicy_BarePodPrivilegedDenied(t *testing.T) {
	m := newTestManagerWithPolicy(t, newPrivilegedPolicy())

	body := []byte(`{
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "bad", "namespace": "default"},
		"spec": {
			"securityContext": {"privileged": true},
			"containers": [{"name": "c", "image": "nginx"}]
		}
	}`)

	w := doTestRequest(t, m, "test-no-privileged", body)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var resp TestResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Allowed)
	assert.Equal(t, "DENY", resp.Decision)
	require.Len(t, resp.Violations, 1)
	assert.Equal(t, "no-privileged-containers", resp.Violations[0].RuleID)
	assert.Equal(t, "test-no-privileged", resp.Violations[0].PolicyID)
	assert.Equal(t, "opa-1.4.0", resp.Metadata.EngineVersion)
	assert.Equal(t, 1, resp.Metadata.RulesEvaluated)
	assert.GreaterOrEqual(t, resp.Metadata.ElapsedMs, int64(0))
}

func TestTestPolicy_BarePodCompliantAllowed(t *testing.T) {
	m := newTestManagerWithPolicy(t, newPrivilegedPolicy())

	body := []byte(`{
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "good", "namespace": "default"},
		"spec": {
			"securityContext": {"privileged": false},
			"containers": [{"name": "c", "image": "nginx:1.25"}]
		}
	}`)

	w := doTestRequest(t, m, "test-no-privileged", body)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var resp TestResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Allowed)
	assert.Equal(t, "ALLOW", resp.Decision)
	assert.Empty(t, resp.Violations)
}

func TestTestPolicy_FullAdmissionReviewPrivilegedDenied(t *testing.T) {
	m := newTestManagerWithPolicy(t, newPrivilegedPolicy())

	podRaw := []byte(`{
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "bad", "namespace": "default"},
		"spec": {
			"securityContext": {"privileged": true},
			"containers": [{"name": "c", "image": "nginx"}]
		}
	}`)
	review := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID:       "abc-123",
			Operation: admissionv1.Create,
			Kind:      metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"},
			Namespace: "default",
			UserInfo:  authenticationv1.UserInfo{Username: "kubectl"},
			Object:    runtime.RawExtension{Raw: podRaw},
		},
	}
	body, err := json.Marshal(review)
	require.NoError(t, err)

	w := doTestRequest(t, m, "test-no-privileged", body)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var resp TestResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Allowed)
	require.Len(t, resp.Violations, 1)
	assert.Equal(t, "no-privileged-containers", resp.Violations[0].RuleID)
}

func TestTestPolicy_NotFound(t *testing.T) {
	m := newTestManagerWithPolicy(t, nil)
	w := doTestRequest(t, m, "does-not-exist", []byte(`{"apiVersion":"v1","kind":"Pod"}`))
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestTestPolicy_InvalidJSON(t *testing.T) {
	m := newTestManagerWithPolicy(t, newPrivilegedPolicy())
	w := doTestRequest(t, m, "test-no-privileged", []byte(`{not json`))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTestPolicy_EmptyBody(t *testing.T) {
	m := newTestManagerWithPolicy(t, newPrivilegedPolicy())
	w := doTestRequest(t, m, "test-no-privileged", []byte(``))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTestPolicy_BareObjectMissingKind(t *testing.T) {
	m := newTestManagerWithPolicy(t, newPrivilegedPolicy())
	w := doTestRequest(t, m, "test-no-privileged", []byte(`{"apiVersion":"v1"}`))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSplitAPIVersion(t *testing.T) {
	cases := []struct {
		in      string
		group   string
		version string
	}{
		{"v1", "", "v1"},
		{"apps/v1", "apps", "v1"},
		{"networking.k8s.io/v1", "networking.k8s.io", "v1"},
	}
	for _, tc := range cases {
		g, v := splitAPIVersion(tc.in)
		assert.Equal(t, tc.group, g, "input=%q", tc.in)
		assert.Equal(t, tc.version, v, "input=%q", tc.in)
	}
}
