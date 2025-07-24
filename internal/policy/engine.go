package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/Jibbscript/kube-policies/internal/config"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
)

// Engine represents the policy evaluation engine
type Engine struct {
	store    storage.Store
	policies map[string]*Policy
	mutex    sync.RWMutex
	logger   *zap.Logger
	config   *config.PolicyConfig
}

// Policy represents a security policy
type Policy struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Version     string                 `json:"version"`
	Enabled     bool                   `json:"enabled"`
	Rules       []Rule                 `json:"rules"`
	Metadata    map[string]interface{} `json:"metadata"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// Rule represents a policy rule
type Rule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Rego        string                 `json:"rego"`
	Severity    string                 `json:"severity"`
	Category    string                 `json:"category"`
	Frameworks  []string               `json:"frameworks"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// EvaluationRequest represents a policy evaluation request
type EvaluationRequest struct {
	AdmissionRequest *admissionv1.AdmissionRequest
	Operation        string
	Context          map[string]interface{}
}

// EvaluationResult represents the result of policy evaluation
type EvaluationResult struct {
	Allowed    bool                   `json:"allowed"`
	Decision   string                 `json:"decision"`
	Reason     string                 `json:"reason"`
	Message    string                 `json:"message"`
	Violations []PolicyViolation      `json:"violations"`
	Patches    []JSONPatch            `json:"patches,omitempty"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// PolicyViolation represents a policy violation
type PolicyViolation struct {
	PolicyID    string                 `json:"policy_id"`
	RuleID      string                 `json:"rule_id"`
	Severity    string                 `json:"severity"`
	Category    string                 `json:"category"`
	Message     string                 `json:"message"`
	Path        string                 `json:"path"`
	Frameworks  []string               `json:"frameworks"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// JSONPatch represents a JSON patch operation
type JSONPatch struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

// NewEngine creates a new policy engine
func NewEngine(config *config.PolicyConfig, logger *zap.Logger) (*Engine, error) {
	store := inmem.New()
	
	engine := &Engine{
		store:    store,
		policies: make(map[string]*Policy),
		logger:   logger,
		config:   config,
	}

	// Load default policies
	if err := engine.loadDefaultPolicies(); err != nil {
		return nil, fmt.Errorf("failed to load default policies: %w", err)
	}

	return engine, nil
}

// Evaluate evaluates policies against an admission request
func (e *Engine) Evaluate(ctx context.Context, req *EvaluationRequest) (*EvaluationResult, error) {
	startTime := time.Now()
	defer func() {
		e.logger.Debug("Policy evaluation completed",
			zap.Duration("duration", time.Since(startTime)),
			zap.String("operation", req.Operation),
		)
	}()

	// Prepare input for OPA
	input, err := e.prepareInput(req)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare input: %w", err)
	}

	result := &EvaluationResult{
		Allowed:    true,
		Decision:   "ALLOW",
		Violations: []PolicyViolation{},
		Patches:    []JSONPatch{},
		Metadata:   make(map[string]interface{}),
	}

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	// Evaluate each enabled policy
	for _, policy := range e.policies {
		if !policy.Enabled {
			continue
		}

		policyResult, err := e.evaluatePolicy(ctx, policy, input)
		if err != nil {
			e.logger.Error("Failed to evaluate policy",
				zap.String("policy_id", policy.ID),
				zap.Error(err),
			)
			continue
		}

		// Merge results
		if !policyResult.Allowed {
			result.Allowed = false
			result.Decision = "DENY"
		}

		result.Violations = append(result.Violations, policyResult.Violations...)
		result.Patches = append(result.Patches, policyResult.Patches...)

		// Merge metadata
		for k, v := range policyResult.Metadata {
			result.Metadata[k] = v
		}
	}

	// Set final message and reason
	if !result.Allowed {
		result.Reason = "PolicyViolation"
		result.Message = e.buildViolationMessage(result.Violations)
	} else {
		result.Reason = "PolicyCompliant"
		result.Message = "Request complies with all policies"
	}

	return result, nil
}

// evaluatePolicy evaluates a single policy
func (e *Engine) evaluatePolicy(ctx context.Context, policy *Policy, input map[string]interface{}) (*EvaluationResult, error) {
	result := &EvaluationResult{
		Allowed:    true,
		Violations: []PolicyViolation{},
		Patches:    []JSONPatch{},
		Metadata:   make(map[string]interface{}),
	}

	for _, rule := range policy.Rules {
		ruleResult, err := e.evaluateRule(ctx, policy, &rule, input)
		if err != nil {
			e.logger.Error("Failed to evaluate rule",
				zap.String("policy_id", policy.ID),
				zap.String("rule_id", rule.ID),
				zap.Error(err),
			)
			continue
		}

		// Merge rule results
		if !ruleResult.Allowed {
			result.Allowed = false
		}

		result.Violations = append(result.Violations, ruleResult.Violations...)
		result.Patches = append(result.Patches, ruleResult.Patches...)
	}

	return result, nil
}

// evaluateRule evaluates a single rule using OPA
func (e *Engine) evaluateRule(ctx context.Context, policy *Policy, rule *Rule, input map[string]interface{}) (*EvaluationResult, error) {
	// Create Rego query
	query, err := rego.New(
		rego.Query("data.kube_policies.evaluate"),
		rego.Module(fmt.Sprintf("%s_%s", policy.ID, rule.ID), rule.Rego),
		rego.Store(e.store),
		rego.Input(input),
	).PrepareForEval(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed to prepare rego query: %w", err)
	}

	// Evaluate the rule
	results, err := query.Eval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate rego query: %w", err)
	}

	// Parse results
	result := &EvaluationResult{
		Allowed:    true,
		Violations: []PolicyViolation{},
		Patches:    []JSONPatch{},
		Metadata:   make(map[string]interface{}),
	}

	if len(results) > 0 && len(results[0].Expressions) > 0 {
		evalResult := results[0].Expressions[0].Value.(map[string]interface{})
		
		if allowed, ok := evalResult["allowed"].(bool); ok {
			result.Allowed = allowed
		}

		if !result.Allowed {
			violation := PolicyViolation{
				PolicyID:   policy.ID,
				RuleID:     rule.ID,
				Severity:   rule.Severity,
				Category:   rule.Category,
				Frameworks: rule.Frameworks,
				Metadata:   rule.Metadata,
			}

			if message, ok := evalResult["message"].(string); ok {
				violation.Message = message
			}

			if path, ok := evalResult["path"].(string); ok {
				violation.Path = path
			}

			result.Violations = append(result.Violations, violation)
		}

		// Extract patches for mutation
		if patches, ok := evalResult["patches"].([]interface{}); ok {
			for _, patch := range patches {
				if patchMap, ok := patch.(map[string]interface{}); ok {
					jsonPatch := JSONPatch{}
					if op, ok := patchMap["op"].(string); ok {
						jsonPatch.Op = op
					}
					if path, ok := patchMap["path"].(string); ok {
						jsonPatch.Path = path
					}
					if value, ok := patchMap["value"]; ok {
						jsonPatch.Value = value
					}
					result.Patches = append(result.Patches, jsonPatch)
				}
			}
		}
	}

	return result, nil
}

// prepareInput prepares the input for OPA evaluation
func (e *Engine) prepareInput(req *EvaluationRequest) (map[string]interface{}, error) {
	input := map[string]interface{}{
		"request": map[string]interface{}{
			"uid":       req.AdmissionRequest.UID,
			"kind":      req.AdmissionRequest.Kind,
			"namespace": req.AdmissionRequest.Namespace,
			"name":      req.AdmissionRequest.Name,
			"operation": req.AdmissionRequest.Operation,
			"userInfo":  req.AdmissionRequest.UserInfo,
		},
		"operation": req.Operation,
	}

	// Add object if present
	if req.AdmissionRequest.Object.Raw != nil {
		var obj interface{}
		if err := json.Unmarshal(req.AdmissionRequest.Object.Raw, &obj); err == nil {
			input["object"] = obj
		}
	}

	// Add old object if present
	if req.AdmissionRequest.OldObject.Raw != nil {
		var oldObj interface{}
		if err := json.Unmarshal(req.AdmissionRequest.OldObject.Raw, &oldObj); err == nil {
			input["oldObject"] = oldObj
		}
	}

	// Add context if present
	if req.Context != nil {
		input["context"] = req.Context
	}

	return input, nil
}

// buildViolationMessage builds a human-readable violation message
func (e *Engine) buildViolationMessage(violations []PolicyViolation) string {
	if len(violations) == 0 {
		return "No policy violations"
	}

	if len(violations) == 1 {
		return violations[0].Message
	}

	return fmt.Sprintf("Multiple policy violations detected (%d violations)", len(violations))
}

// loadDefaultPolicies loads default security policies
func (e *Engine) loadDefaultPolicies() error {
	// Load default policies from configuration or embedded policies
	defaultPolicies := []*Policy{
		{
			ID:          "security-baseline",
			Name:        "Security Baseline",
			Description: "Basic security requirements for all workloads",
			Version:     "1.0.0",
			Enabled:     true,
			Rules: []Rule{
				{
					ID:          "no-privileged-containers",
					Name:        "No Privileged Containers",
					Description: "Containers must not run in privileged mode",
					Severity:    "HIGH",
					Category:    "Security",
					Frameworks:  []string{"CIS", "NIST"},
					Rego: `
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
	result := {
		"allowed": true
	}
}`,
				},
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}

	for _, policy := range defaultPolicies {
		e.policies[policy.ID] = policy
	}

	return nil
}

// LoadPolicy loads a policy into the engine
func (e *Engine) LoadPolicy(policy *Policy) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	e.policies[policy.ID] = policy
	e.logger.Info("Policy loaded",
		zap.String("policy_id", policy.ID),
		zap.String("policy_name", policy.Name),
	)

	return nil
}

// RemovePolicy removes a policy from the engine
func (e *Engine) RemovePolicy(policyID string) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	delete(e.policies, policyID)
	e.logger.Info("Policy removed",
		zap.String("policy_id", policyID),
	)

	return nil
}

// ListPolicies returns all loaded policies
func (e *Engine) ListPolicies() []*Policy {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	policies := make([]*Policy, 0, len(e.policies))
	for _, policy := range e.policies {
		policies = append(policies, policy)
	}

	return policies
}

