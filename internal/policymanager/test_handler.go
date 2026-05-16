package policymanager

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Jibbscript/kube-policies/internal/policy"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// bundledEngineVersion is the hardcoded OPA version for M1, sourced from go.mod
// (github.com/open-policy-agent/opa v1.4.0). When OPA is upgraded, bump this.
const bundledEngineVersion = "opa-1.4.0"

// TestResponse is the response shape for POST /api/v1/policies/:id/test.
// Mirrors plan §6 (svelte-dashboard.md). The Svelte SPA's lib/types.ts
// should match this shape exactly.
type TestResponse struct {
	Allowed    bool                     `json:"allowed"`
	Decision   string                   `json:"decision"`
	Reason     string                   `json:"reason"`
	Message    string                   `json:"message"`
	Violations []policy.PolicyViolation `json:"violations"`
	Patches    []policy.JSONPatch       `json:"patches,omitempty"`
	Metadata   TestResponseMetadata     `json:"metadata"`
}

// TestResponseMetadata captures evaluator-level metadata exposed to the UI.
type TestResponseMetadata struct {
	EngineVersion  string `json:"engine_version"`
	ElapsedMs      int64  `json:"elapsed_ms"`
	RulesEvaluated int    `json:"rules_evaluated"`
}

// testPolicyImpl handles POST /api/v1/policies/:id/test.
//
// Body shape: either
//   - a bare K8s object (top-level `apiVersion` + `kind`, e.g. a Pod), or
//   - a full `admissionv1.AdmissionReview` (top-level `request: {...}`).
//
// Bare objects are wrapped into a synthesized AdmissionRequest with a
// playground UserInfo so users can paste manifests directly.
//
// Evaluation is scoped to the picked policy only via
// `policy.NewEvaluatorForPolicy` — bundled defaults are NOT evaluated.
func (m *Manager) testPolicyImpl(c *gin.Context) {
	start := time.Now()

	id := c.Param("id")
	m.mutex.RLock()
	p, exists := m.policies[id]
	m.mutex.RUnlock()
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
		return
	}

	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("failed to read request body: %v", err)})
		return
	}
	if len(bodyBytes) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "request body is empty"})
		return
	}

	req, err := parseAdmissionBody(bodyBytes)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	engine, err := policy.NewEvaluatorForPolicy(p, &m.config.Policy, m.logger)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to build evaluator: %v", err)})
		return
	}

	result, err := engine.Evaluate(c.Request.Context(), &policy.EvaluationRequest{
		AdmissionRequest: req,
		Operation:        "test",
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("evaluation failed: %v", err)})
		return
	}

	resp := TestResponse{
		Allowed:    result.Allowed,
		Decision:   result.Decision,
		Reason:     result.Reason,
		Message:    result.Message,
		Violations: result.Violations,
		Patches:    result.Patches,
		Metadata: TestResponseMetadata{
			EngineVersion:  bundledEngineVersion,
			ElapsedMs:      time.Since(start).Milliseconds(),
			RulesEvaluated: len(p.Rules),
		},
	}
	if resp.Violations == nil {
		resp.Violations = []policy.PolicyViolation{}
	}

	c.JSON(http.StatusOK, resp)
}

// parseAdmissionBody inspects a raw JSON body and returns an AdmissionRequest.
//
// If the body has a top-level `request` field, it is treated as a full
// AdmissionReview. Otherwise it is treated as a bare K8s object and wrapped
// into a synthesized request (UID=uuid, Operation=CREATE,
// UserInfo=playground/system:unauthenticated, Kind inferred from
// apiVersion+kind).
func parseAdmissionBody(bodyBytes []byte) (*admissionv1.AdmissionRequest, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(bodyBytes, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %v", err)
	}

	if _, isReview := raw["request"]; isReview {
		var review admissionv1.AdmissionReview
		if err := json.Unmarshal(bodyBytes, &review); err != nil {
			return nil, fmt.Errorf("invalid AdmissionReview: %v", err)
		}
		if review.Request == nil {
			return nil, fmt.Errorf("AdmissionReview.request is null")
		}
		return review.Request, nil
	}

	// Bare object — synthesize.
	var obj map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &obj); err != nil {
		return nil, fmt.Errorf("invalid object JSON: %v", err)
	}

	apiVersion, _ := obj["apiVersion"].(string)
	kind, _ := obj["kind"].(string)
	if apiVersion == "" || kind == "" {
		return nil, fmt.Errorf("bare object missing apiVersion or kind")
	}
	group, version := splitAPIVersion(apiVersion)

	namespace := ""
	if md, ok := obj["metadata"].(map[string]interface{}); ok {
		if ns, ok := md["namespace"].(string); ok {
			namespace = ns
		}
	}

	return &admissionv1.AdmissionRequest{
		UID:       types.UID(uuid.New().String()),
		Operation: admissionv1.Create,
		Kind:      metav1.GroupVersionKind{Group: group, Version: version, Kind: kind},
		Namespace: namespace,
		UserInfo: authenticationv1.UserInfo{
			Username: "playground",
			Groups:   []string{"system:unauthenticated"},
		},
		Object: runtime.RawExtension{Raw: bodyBytes},
	}, nil
}

// splitAPIVersion parses a Kubernetes apiVersion string.
// "apps/v1"  → group="apps", version="v1"
// "v1"       → group="",     version="v1"
func splitAPIVersion(apiVersion string) (group, version string) {
	if i := strings.IndexByte(apiVersion, '/'); i >= 0 {
		return apiVersion[:i], apiVersion[i+1:]
	}
	return "", apiVersion
}
