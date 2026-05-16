package policymanager

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/Jibbscript/kube-policies/internal/policy"
)

// EvaluateRequest is the body shape for POST /api/v1/policies/evaluate.
//
// `policy` is an inline policy spec evaluated against `resource` — neither is
// persisted. This is the ad-hoc playground/CI path that does not require a
// pre-existing policy ID (use /policies/:id/test if the policy is already
// stored in the manager).
type EvaluateRequest struct {
	Resource map[string]interface{} `json:"resource"`
	Policy   policy.Policy          `json:"policy"`
}

// EvaluateResponse is the response shape for POST /api/v1/policies/evaluate.
//
// `violations` is a list of human-readable messages (one per matching rule)
// so callers can render results without knowing the engine's internal
// PolicyViolation shape; `details` preserves the structured violations for
// callers that want rule IDs, severities, and paths.
type EvaluateResponse struct {
	Allowed    bool                     `json:"allowed"`
	Decision   string                   `json:"decision"`
	Violations []string                 `json:"violations"`
	Details    []policy.PolicyViolation `json:"details"`
	Message    string                   `json:"message"`
}

// EvaluatePolicy handles POST /api/v1/policies/evaluate.
//
// Body: {resource: <K8s object>, policy: <Policy spec>}.
//
// The handler builds a one-shot evaluator scoped to the supplied policy
// (NewEvaluatorForPolicy — no bundled defaults bleed through), wraps the
// resource into a synthesized AdmissionRequest with a playground UserInfo,
// and returns the evaluator's verdict. Nothing is persisted.
func (m *Manager) EvaluatePolicy(c *gin.Context) {
	var req EvaluateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid request body: %v", err)})
		return
	}
	if req.Resource == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "resource is required"})
		return
	}
	if len(req.Policy.Rules) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "policy must include at least one rule"})
		return
	}

	// Compile every rule before evaluation: a malformed Rego would otherwise
	// produce a cryptic engine error mid-evaluate. Returning 400 with the
	// compile message keeps the contract symmetric with /policies/validate.
	for i := range req.Policy.Rules {
		if err := compileRego(req.Policy.ID, &req.Policy.Rules[i]); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"allowed": false,
				"error":   err.Error(),
			})
			return
		}
	}

	// Build a synthesized AdmissionRequest from the bare resource. The
	// playground UserInfo mirrors testPolicyImpl so engine.prepareInput sees a
	// non-nil request.userInfo.
	apiVersion, _ := req.Resource["apiVersion"].(string)
	kind, _ := req.Resource["kind"].(string)
	if apiVersion == "" || kind == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "resource missing apiVersion or kind"})
		return
	}
	group, version := splitAPIVersion(apiVersion)
	namespace := ""
	if md, ok := req.Resource["metadata"].(map[string]interface{}); ok {
		if ns, ok := md["namespace"].(string); ok {
			namespace = ns
		}
	}
	rawObject, err := json.Marshal(req.Resource)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("failed to encode resource: %v", err)})
		return
	}

	admReq := &admissionv1.AdmissionRequest{
		UID:       types.UID(uuid.New().String()),
		Operation: admissionv1.Create,
		Kind:      metav1.GroupVersionKind{Group: group, Version: version, Kind: kind},
		Namespace: namespace,
		UserInfo: authenticationv1.UserInfo{
			Username: "playground",
			Groups:   []string{"system:unauthenticated"},
		},
		Object: runtime.RawExtension{Raw: rawObject},
	}

	// Assign an ID for the synthetic policy so evaluator caching keys are
	// stable across the single Evaluate() call.
	if req.Policy.ID == "" {
		req.Policy.ID = "evaluate-" + uuid.New().String()
	}
	now := time.Now()
	req.Policy.CreatedAt = now
	req.Policy.UpdatedAt = now
	// Enabled defaults to false on JSON omit; force-on so engine.Evaluate
	// doesn't silently skip the rule set.
	req.Policy.Enabled = true

	engine, err := policy.NewEvaluatorForPolicy(&req.Policy, &m.config.Policy, m.logger)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to build evaluator: %v", err)})
		return
	}
	result, err := engine.Evaluate(c.Request.Context(), &policy.EvaluationRequest{
		AdmissionRequest: admReq,
		Operation:        "evaluate",
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("evaluation failed: %v", err)})
		return
	}

	messages := make([]string, 0, len(result.Violations))
	for _, v := range result.Violations {
		messages = append(messages, v.Message)
	}
	resp := EvaluateResponse{
		Allowed:    result.Allowed,
		Decision:   result.Decision,
		Violations: messages,
		Details:    result.Violations,
		Message:    result.Message,
	}
	c.JSON(http.StatusOK, resp)
}
