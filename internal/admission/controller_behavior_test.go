package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Jibbscript/kube-policies/internal/config"
	"github.com/Jibbscript/kube-policies/internal/metrics"
	"github.com/Jibbscript/kube-policies/internal/policy"
	"github.com/Jibbscript/kube-policies/internal/audit"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// stubEvaluator lets tests force the engine into specific behaviors,
// including the error path that the real OPA engine never produces.
type stubEvaluator struct {
	result *policy.EvaluationResult
	err    error
}

func (s *stubEvaluator) Evaluate(_ context.Context, _ *policy.EvaluationRequest) (*policy.EvaluationResult, error) {
	return s.result, s.err
}

// metrics.Collector registers against the global Prometheus registry, so we
// build it exactly once for the whole package to avoid duplicate-registration panics.
var sharedMetrics = metrics.NewCollector()

func newControllerWithStub(t *testing.T, eval policy.Evaluator) *Controller {
	t.Helper()
	auditLogger, err := audit.NewLogger(&config.AuditConfig{Enabled: false})
	require.NoError(t, err)
	return NewController(eval, auditLogger, sharedMetrics, zap.NewNop(), nil)
}

func newControllerWithEngine(t *testing.T) (*Controller, *policy.Engine) {
	t.Helper()
	engine, err := policy.NewEngine(&config.PolicyConfig{FailureMode: "fail-closed"}, zap.NewNop())
	require.NoError(t, err)
	auditLogger, err := audit.NewLogger(&config.AuditConfig{Enabled: false})
	require.NoError(t, err)
	return NewController(engine, auditLogger, sharedMetrics, zap.NewNop(), nil), engine
}

func postAdmissionReview(t *testing.T, handler gin.HandlerFunc, review admissionv1.AdmissionReview) admissionv1.AdmissionReview {
	t.Helper()
	body, err := json.Marshal(review)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/", handler)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var out admissionv1.AdmissionReview
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.NotNil(t, out.Response)
	return out
}

func privilegedPodAdmissionRequest(t *testing.T) admissionv1.AdmissionReview {
	t.Helper()
	pod := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      "privileged-pod",
			"namespace": "default",
		},
		"spec": map[string]any{
			"securityContext": map[string]any{
				"privileged": true,
			},
		},
	}
	raw, err := json.Marshal(pod)
	require.NoError(t, err)

	return admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:       types.UID("test-priv-1"),
			Kind:      metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"},
			Namespace: "default",
			Name:      "privileged-pod",
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: raw},
		},
	}
}

func unlabeledPodAdmissionRequest(t *testing.T) admissionv1.AdmissionReview {
	t.Helper()
	pod := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      "unlabeled-pod",
			"namespace": "default",
			"labels":    map[string]any{},
		},
		"spec": map[string]any{},
	}
	raw, err := json.Marshal(pod)
	require.NoError(t, err)

	return admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:       types.UID("test-mut-1"),
			Kind:      metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"},
			Namespace: "default",
			Name:      "unlabeled-pod",
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: raw},
		},
	}
}

// TestValidateHandler_DeniesPrivilegedPod locks the marketed default-deny behavior.
// A Pod with spec.securityContext.privileged=true must be rejected by the bundled security-baseline policy.
func TestValidateHandler_DeniesPrivilegedPod(t *testing.T) {
	ctrl, _ := newControllerWithEngine(t)
	out := postAdmissionReview(t, ctrl.ValidateHandler, privilegedPodAdmissionRequest(t))

	assert.False(t, out.Response.Allowed, "privileged Pod must be denied by the default policy")
	require.NotNil(t, out.Response.Result)
	assert.Equal(t, int32(http.StatusForbidden), out.Response.Result.Code)
	assert.Contains(t, out.Response.Result.Message, "privileged")
}

// TestMutateHandler_ReturnsValidJSONPatch verifies that when a policy emits patches,
// the response carries a JSONPatch-typed body that decodes into a non-empty patch list.
func TestMutateHandler_ReturnsValidJSONPatch(t *testing.T) {
	ctrl, engine := newControllerWithEngine(t)

	// Replace the default policy with one that emits a patch.
	require.NoError(t, engine.RemovePolicy("security-baseline"))
	patcher := &policy.Policy{
		ID: "label-injector", Name: "Label Injector", Enabled: true,
		Rules: []policy.Rule{{
			ID:   "add-managed-by",
			Name: "Add managed-by label",
			Rego: `package kube_policies

evaluate = result {
	not input.object.metadata.labels["managed-by"]
	result := {
		"allowed": true,
		"patches": [{
			"op": "add",
			"path": "/metadata/labels/managed-by",
			"value": "kube-policies",
		}],
	}
}

evaluate = result {
	input.object.metadata.labels["managed-by"]
	result := {"allowed": true}
}
`,
		}},
	}
	require.NoError(t, engine.LoadPolicy(patcher))

	out := postAdmissionReview(t, ctrl.MutateHandler, unlabeledPodAdmissionRequest(t))

	assert.True(t, out.Response.Allowed)
	require.NotNil(t, out.Response.PatchType, "PatchType must be set when patches are returned")
	assert.Equal(t, admissionv1.PatchTypeJSONPatch, *out.Response.PatchType)

	var patches []map[string]any
	require.NoError(t, json.Unmarshal(out.Response.Patch, &patches))
	require.NotEmpty(t, patches)
	assert.Equal(t, "add", patches[0]["op"])
	assert.Equal(t, "/metadata/labels/managed-by", patches[0]["path"])
}

// TestValidateHandler_FailSafeOnEngineError locks the fail-closed contract for validate:
// when the engine returns an error, the response must deny the request.
func TestValidateHandler_FailSafeOnEngineError(t *testing.T) {
	ctrl := newControllerWithStub(t, &stubEvaluator{err: errors.New("engine boom")})
	out := postAdmissionReview(t, ctrl.ValidateHandler, privilegedPodAdmissionRequest(t))

	assert.False(t, out.Response.Allowed, "validate must deny when the engine errors")
	require.NotNil(t, out.Response.Result)
	assert.Equal(t, int32(http.StatusInternalServerError), out.Response.Result.Code)
}

// TestMutateHandler_FailSafeOnEngineError locks the fail-open-for-mutation contract:
// when the engine errors, mutate must allow the request through without patches
// rather than blocking writes on a transient policy bug.
func TestMutateHandler_FailSafeOnEngineError(t *testing.T) {
	ctrl := newControllerWithStub(t, &stubEvaluator{err: errors.New("engine boom")})
	out := postAdmissionReview(t, ctrl.MutateHandler, privilegedPodAdmissionRequest(t))

	assert.True(t, out.Response.Allowed, "mutate must allow when the engine errors")
	assert.Empty(t, out.Response.Patch, "no patches should be returned on engine error")
	assert.Nil(t, out.Response.PatchType)
}

// Compile-time guards that *policy.Engine and the stub both satisfy the Evaluator interface.
var (
	_ policy.Evaluator = (*policy.Engine)(nil)
	_ policy.Evaluator = (*stubEvaluator)(nil)
)
