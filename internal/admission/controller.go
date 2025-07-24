package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Jibbscript/kube-policies/internal/metrics"
	"github.com/Jibbscript/kube-policies/internal/policy"
	"github.com/Jibbscript/kube-policies/pkg/audit"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Controller handles admission webhook requests
type Controller struct {
	policyEngine *policy.Engine
	auditLogger  *audit.Logger
	metrics      *metrics.Collector
	logger       *zap.Logger
}

// NewController creates a new admission controller
func NewController(
	policyEngine *policy.Engine,
	auditLogger *audit.Logger,
	metrics *metrics.Collector,
	logger *zap.Logger,
) *Controller {
	return &Controller{
		policyEngine: policyEngine,
		auditLogger:  auditLogger,
		metrics:      metrics,
		logger:       logger,
	}
}

// ValidateHandler handles validation admission requests
func (c *Controller) ValidateHandler(ctx *gin.Context) {
	startTime := time.Now()

	var admissionReview admissionv1.AdmissionReview
	if err := ctx.ShouldBindJSON(&admissionReview); err != nil {
		c.logger.Error("Failed to decode admission review", zap.Error(err))
		c.metrics.IncAdmissionRequests("validate", "error", "decode_error")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid admission review"})
		return
	}

	req := admissionReview.Request
	if req == nil {
		c.logger.Error("Admission review request is nil")
		c.metrics.IncAdmissionRequests("validate", "error", "nil_request")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Admission review request is nil"})
		return
	}

	// Create audit context
	auditCtx := &audit.Context{
		RequestID: string(req.UID),
		UserInfo:  req.UserInfo,
		Namespace: req.Namespace,
		Kind:      req.Kind,
		Name:      req.Name,
		Operation: string(req.Operation),
		Object:    &req.Object,
		OldObject: &req.OldObject,
		Timestamp: time.Now(),
	}

	// Evaluate policies
	decision, err := c.policyEngine.Evaluate(context.Background(), &policy.EvaluationRequest{
		AdmissionRequest: req,
		Operation:        "validate",
	})

	if err != nil {
		c.logger.Error("Policy evaluation failed",
			zap.Error(err),
			zap.String("request_id", string(req.UID)),
		)
		c.metrics.IncAdmissionRequests("validate", "error", "evaluation_error")

		// Log audit event for evaluation error
		auditCtx.Decision = "ERROR"
		auditCtx.Reason = fmt.Sprintf("Policy evaluation failed: %v", err)
		c.auditLogger.LogDecision(auditCtx)

		// Fail-safe behavior - deny by default
		response := &admissionv1.AdmissionResponse{
			UID:     req.UID,
			Allowed: false,
			Result: &metav1.Status{
				Code:    http.StatusInternalServerError,
				Message: "Policy evaluation failed",
			},
		}

		admissionReview.Response = response
		ctx.JSON(http.StatusOK, admissionReview)
		return
	}

	// Create admission response
	response := &admissionv1.AdmissionResponse{
		UID:     req.UID,
		Allowed: decision.Allowed,
	}

	if !decision.Allowed {
		response.Result = &metav1.Status{
			Code:    http.StatusForbidden,
			Message: decision.Message,
			Reason:  metav1.StatusReason(decision.Reason),
		}
	}

	// Log audit event
	auditCtx.Decision = decision.Decision
	auditCtx.Reason = decision.Reason
	auditCtx.Message = decision.Message
	auditCtx.PolicyViolations = decision.Violations
	auditCtx.ProcessingTime = time.Since(startTime)
	c.auditLogger.LogDecision(auditCtx)

	// Record metrics
	status := "allowed"
	if !decision.Allowed {
		status = "denied"
	}
	c.metrics.IncAdmissionRequests("validate", status, decision.Reason)
	c.metrics.ObserveEvaluationDuration("validate", time.Since(startTime))

	admissionReview.Response = response
	ctx.JSON(http.StatusOK, admissionReview)
}

// MutateHandler handles mutation admission requests
func (c *Controller) MutateHandler(ctx *gin.Context) {
	startTime := time.Now()

	var admissionReview admissionv1.AdmissionReview
	if err := ctx.ShouldBindJSON(&admissionReview); err != nil {
		c.logger.Error("Failed to decode admission review", zap.Error(err))
		c.metrics.IncAdmissionRequests("mutate", "error", "decode_error")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid admission review"})
		return
	}

	req := admissionReview.Request
	if req == nil {
		c.logger.Error("Admission review request is nil")
		c.metrics.IncAdmissionRequests("mutate", "error", "nil_request")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Admission review request is nil"})
		return
	}

	// Create audit context
	auditCtx := &audit.Context{
		RequestID: string(req.UID),
		UserInfo:  req.UserInfo,
		Namespace: req.Namespace,
		Kind:      req.Kind,
		Name:      req.Name,
		Operation: string(req.Operation),
		Object:    &req.Object,
		OldObject: &req.OldObject,
		Timestamp: time.Now(),
	}

	// Evaluate policies for mutations
	decision, err := c.policyEngine.Evaluate(context.Background(), &policy.EvaluationRequest{
		AdmissionRequest: req,
		Operation:        "mutate",
	})

	if err != nil {
		c.logger.Error("Policy evaluation failed",
			zap.Error(err),
			zap.String("request_id", string(req.UID)),
		)
		c.metrics.IncAdmissionRequests("mutate", "error", "evaluation_error")

		// Log audit event for evaluation error
		auditCtx.Decision = "ERROR"
		auditCtx.Reason = fmt.Sprintf("Policy evaluation failed: %v", err)
		c.auditLogger.LogDecision(auditCtx)

		// Fail-safe behavior - allow without mutations
		response := &admissionv1.AdmissionResponse{
			UID:     req.UID,
			Allowed: true,
		}

		admissionReview.Response = response
		ctx.JSON(http.StatusOK, admissionReview)
		return
	}

	// Create admission response
	response := &admissionv1.AdmissionResponse{
		UID:     req.UID,
		Allowed: decision.Allowed,
	}

	// Add patches if mutations are required
	if len(decision.Patches) > 0 {
		patchBytes, err := json.Marshal(decision.Patches)
		if err != nil {
			c.logger.Error("Failed to marshal patches", zap.Error(err))
			c.metrics.IncAdmissionRequests("mutate", "error", "patch_marshal_error")

			// Allow without mutations on patch error
			response.Allowed = true
		} else {
			response.Patch = patchBytes
			patchType := admissionv1.PatchTypeJSONPatch
			response.PatchType = &patchType
		}
	}

	if !decision.Allowed {
		response.Result = &metav1.Status{
			Code:    http.StatusForbidden,
			Message: decision.Message,
			Reason:  metav1.StatusReason(decision.Reason),
		}
	}

	// Log audit event
	auditCtx.Decision = decision.Decision
	auditCtx.Reason = decision.Reason
	auditCtx.Message = decision.Message
	auditCtx.PolicyViolations = decision.Violations
	auditCtx.Mutations = decision.Patches
	auditCtx.ProcessingTime = time.Since(startTime)
	c.auditLogger.LogDecision(auditCtx)

	// Record metrics
	status := "allowed"
	if !decision.Allowed {
		status = "denied"
	}
	c.metrics.IncAdmissionRequests("mutate", status, decision.Reason)
	c.metrics.ObserveEvaluationDuration("mutate", time.Since(startTime))

	admissionReview.Response = response
	ctx.JSON(http.StatusOK, admissionReview)
}
