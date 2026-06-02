package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"

	"github.com/Jibbscript/kube-policies/internal/config"
)

// Evaluator is the minimal interface the admission controller depends on.
// Allows test doubles without coupling to the OPA-backed Engine.
type Evaluator interface {
	Evaluate(ctx context.Context, req *EvaluationRequest) (*EvaluationResult, error)
}

// Engine represents the policy evaluation engine
type Engine struct {
	store             storage.Store
	policies          map[string]*Policy
	preparedQueries   sync.Map // map[policyID+"/"+ruleID]rego.PreparedEvalQuery
	mutex             sync.RWMutex
	logger            *zap.Logger
	config            *config.PolicyConfig
	exceptionRegistry ExceptionRegistry // nil disables the suppression pass
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
	// Parameters are operator-supplied configuration for the policy's rules
	// (e.g. an image-registry allowlist or the set of mandatory labels). They
	// are exposed to every rule in the policy at input.parameters so a single
	// rule body can be reused with different configuration (POL-WU-13/POL-WU-20)
	// instead of hardcoding values. Mirrors the Policy CRD spec.parameters
	// (map[string]string).
	Parameters map[string]string `json:"parameters,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
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

	// TargetKinds restricts which Kubernetes object Kinds this rule is
	// evaluated against (POL-WU-21). An empty/nil slice means the rule applies
	// to every kind (back-compatible default). A non-empty slice means the rule
	// is only evaluated when the admitted object's Kind matches one entry
	// (case-insensitive). This prevents a pod-shaped rule from firing — or, for
	// a malformed rule, erroring and fail-closing the whole request — on an
	// unrelated kind such as a ClusterRole, and it is what lets RBAC,
	// NetworkPolicy, Ingress, Secret, and ConfigMap rule packs coexist with the
	// pod rules in one engine.
	TargetKinds []string `json:"targetKinds,omitempty"`
}

// EvaluationRequest represents a policy evaluation request
type EvaluationRequest struct {
	AdmissionRequest *admissionv1.AdmissionRequest
	Operation        string
	Context          map[string]interface{}
}

// EvaluationResult represents the result of policy evaluation
type EvaluationResult struct {
	Allowed      bool                   `json:"allowed"`
	Decision     string                 `json:"decision"`
	Reason       string                 `json:"reason"`
	Message      string                 `json:"message"`
	Violations   []PolicyViolation      `json:"violations"`
	Patches      []JSONPatch            `json:"patches,omitempty"`
	Metadata     map[string]interface{} `json:"metadata"`
	SuppressedBy []ExceptionRef         `json:"suppressed_by,omitempty"`
}

// PolicyViolation represents a policy violation
type PolicyViolation struct {
	PolicyID   string                 `json:"policy_id"`
	RuleID     string                 `json:"rule_id"`
	Severity   string                 `json:"severity"`
	Category   string                 `json:"category"`
	Message    string                 `json:"message"`
	Path       string                 `json:"path"`
	Frameworks []string               `json:"frameworks"`
	Metadata   map[string]interface{} `json:"metadata"`
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

	// Load default policies unless explicitly disabled
	if config.DisableDefaults {
		logger.Info("default policies disabled; skipping bundled policy load")
	} else {
		if err := engine.loadDefaultPolicies(); err != nil {
			return nil, fmt.Errorf("failed to load default policies: %w", err)
		}
	}

	// Apply enforcement profiles (POL-WU-23): when profiles are configured, the
	// enabled set becomes exactly the union of the selected profiles' policies.
	if len(config.Profiles) > 0 {
		if err := engine.applyProfiles(config.Profiles); err != nil {
			return nil, fmt.Errorf("failed to apply enforcement profiles: %w", err)
		}
		logger.Info("enforcement profiles applied",
			zap.Strings("profiles", config.Profiles),
			zap.Strings("enabled_policies", engine.EnabledPolicyIDs()),
		)
	}

	return engine, nil
}

// NewEngineWithExceptions creates a new policy engine wired to an
// ExceptionRegistry. The registry MUST be non-nil; pass through NewEngine
// (which leaves the field nil) for the disabled-suppression code path.
//
// The disabled-mode path (no registry) is the live production code path
// under --disable-controllers and during boot before the cache warms;
// it keeps the original deny/allow behavior unchanged (Principle 5).
func NewEngineWithExceptions(config *config.PolicyConfig, logger *zap.Logger, registry ExceptionRegistry) (*Engine, error) {
	if registry == nil {
		panic("policy.NewEngineWithExceptions: registry must not be nil; use NewEngine for the disabled-suppression path")
	}
	engine, err := NewEngine(config, logger)
	if err != nil {
		return nil, err
	}
	engine.exceptionRegistry = registry
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

	// The admitted object's Kind drives per-rule kind routing (POL-WU-21).
	// req.AdmissionRequest is guaranteed non-nil here: prepareInput returns an
	// error above when it (or req) is nil.
	kind := req.AdmissionRequest.Kind.Kind

	e.mutex.RLock()
	defer e.mutex.RUnlock()

	// Evaluate each enabled policy
	for _, policy := range e.policies {
		if !policy.Enabled {
			continue
		}

		policyResult, err := e.evaluatePolicy(ctx, policy, input, kind)
		if err != nil {
			e.logger.Error("Failed to evaluate policy",
				zap.String("policy_id", policy.ID),
				zap.Error(err),
			)
			return nil, fmt.Errorf("failed to evaluate policy %q: %w", policy.ID, err)
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

	// Exception suppression pass. Only runs when the binary wired a registry;
	// nil is the live production code path under --disable-controllers and
	// during cache warmup (Principle 5). See plan §3.1 W2 and Step 5.5.
	if e.exceptionRegistry != nil && !result.Allowed {
		surviving := make([]PolicyViolation, 0, len(result.Violations))
		sawRegistryError := false
		for _, v := range result.Violations {
			key := MatchKey{
				PolicyID:  v.PolicyID,
				RuleID:    v.RuleID,
				Namespace: req.AdmissionRequest.Namespace,
				Resource:  strings.ToLower(req.AdmissionRequest.Resource.Resource),
				User:      req.AdmissionRequest.UserInfo.Username,
				Groups:    req.AdmissionRequest.UserInfo.Groups,
			}
			suppressed, refs, err := e.exceptionRegistry.Suppresses(ctx, key)
			if err != nil {
				// Fail-CLOSED on registry error: original deny stands.
				// See pre-mortem §4.2.
				sawRegistryError = true
				e.logger.Warn("exception registry error; preserving deny",
					zap.String("policy_id", v.PolicyID),
					zap.String("rule_id", v.RuleID),
					zap.Error(err),
				)
				surviving = append(surviving, v)
				continue
			}
			if suppressed {
				result.SuppressedBy = append(result.SuppressedBy, refs...)
				// Structured audit log on suppression (Principle 3).
				e.logger.Info("policy violation suppressed by exception",
					zap.String("policy_id", v.PolicyID),
					zap.String("rule_id", v.RuleID),
					zap.String("namespace", key.Namespace),
					zap.String("resource", key.Resource),
					zap.String("user", key.User),
					zap.Any("exception_refs", refs),
				)
				continue
			}
			surviving = append(surviving, v)
		}

		// Replace Violations with the surviving (un-suppressed) slice.
		// Using a fresh slice (NOT result.Violations[:0]) avoids aliasing the
		// original backing array so any caller-retained reference is preserved.
		result.Violations = surviving

		if len(result.Violations) == 0 && !sawRegistryError {
			// Every violation suppressed and no error path was taken; flip the verdict.
			result.Allowed = true
			result.Decision = "ALLOW"
		}
	}

	// Set final reason/message. Three cases:
	//   (1) Deny preserved: existing behavior.
	//   (2) Allow with no suppressions (today's happy path): existing behavior.
	//   (3) Allow because every violation was suppressed: explicit message so
	//       downstream consumers reading only Message are not misled into
	//       thinking the resource was compliant when it actually triggered N
	//       violations that an operator-authored exception waived.
	switch {
	case !result.Allowed:
		result.Reason = "PolicyViolation"
		result.Message = e.buildViolationMessage(result.Violations)
	case len(result.SuppressedBy) > 0:
		result.Reason = "PolicyViolationSuppressedByException"
		result.Message = fmt.Sprintf(
			"%d policy violation(s) suppressed by %d exception(s); see suppressed_by for details",
			len(result.SuppressedBy), distinctExceptionCount(result.SuppressedBy),
		)
	default:
		result.Reason = "PolicyCompliant"
		result.Message = "Request complies with all policies"
	}

	return result, nil
}

// distinctExceptionCount returns the number of unique ExceptionRef.ID values
// in refs. Used to render an honest "N suppressed by M exception(s)" message
// when multiple violations were waived by the same operator-authored
// exception.
func distinctExceptionCount(refs []ExceptionRef) int {
	if len(refs) == 0 {
		return 0
	}
	seen := make(map[string]struct{}, len(refs))
	for _, r := range refs {
		seen[r.ID] = struct{}{}
	}
	return len(seen)
}

// podWorkloadKinds is the set of Kubernetes kinds whose spec carries (or
// templates) a PodSpec. The shared podspec library (rego/podspec.rego) extracts
// the effective pod spec for each of these, so pod-shaped rules target them all.
var podWorkloadKinds = []string{
	"Pod",
	"Deployment",
	"ReplicaSet",
	"DaemonSet",
	"StatefulSet",
	"Job",
	"CronJob",
	"ReplicationController",
}

// ruleAppliesToKind reports whether a rule should be evaluated against an object
// of the given Kubernetes Kind (POL-WU-21). A rule with no TargetKinds applies
// to every kind (back-compatible default). A rule with TargetKinds applies only
// when kind matches one entry (case-insensitive). An empty kind — a request
// that does not carry a Kind — matches every rule so behavior is unchanged in
// that edge case.
func ruleAppliesToKind(rule *Rule, kind string) bool {
	if len(rule.TargetKinds) == 0 || kind == "" {
		return true
	}
	for _, k := range rule.TargetKinds {
		if strings.EqualFold(k, kind) {
			return true
		}
	}
	return false
}

// evaluatePolicy evaluates a single policy. kind is the admitted object's
// Kubernetes Kind; rules whose TargetKinds do not match are skipped (POL-WU-21).
func (e *Engine) evaluatePolicy(ctx context.Context, policy *Policy, input map[string]interface{}, kind string) (*EvaluationResult, error) {
	result := &EvaluationResult{
		Allowed:    true,
		Violations: []PolicyViolation{},
		Patches:    []JSONPatch{},
		Metadata:   make(map[string]interface{}),
	}

	// Expose this policy's parameters to its rules at input.parameters
	// (POL-WU-13/POL-WU-20). input.parameters is ALWAYS set (at least an empty
	// object): a rule's object.get(input.parameters, key, default) only returns
	// its in-Rego default when input.parameters is a defined object — if the key
	// is absent entirely, object.get over an UNDEFINED value yields undefined,
	// silently disabling a parameter-defaulted rule (e.g. require-labels would
	// fail OPEN). The base input is shared across policies and is never mutated;
	// policyInput is a fresh shallow copy.
	policyInput := make(map[string]interface{}, len(input)+1)
	for k, v := range input {
		policyInput[k] = v
	}
	params := make(map[string]interface{}, len(policy.Parameters))
	for k, v := range policy.Parameters {
		params[k] = v
	}
	policyInput["parameters"] = params

	for i := range policy.Rules {
		rule := policy.Rules[i]
		// Kind routing: skip rules that do not target this object's Kind so a
		// pod rule never evaluates (and never errors) against an RBAC/Network/
		// Secret object, and vice versa.
		if !ruleAppliesToKind(&rule, kind) {
			continue
		}
		ruleResult, err := e.evaluateRule(ctx, policy, &rule, policyInput)
		if err != nil {
			e.logger.Error("Failed to evaluate rule",
				zap.String("policy_id", policy.ID),
				zap.String("rule_id", rule.ID),
				zap.Error(err),
			)
			return nil, fmt.Errorf("failed to evaluate rule %q: %w", rule.ID, err)
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
	query, err := e.preparedQueryFor(ctx, policy, rule)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare rego query: %w", err)
	}

	// Evaluate with per-request input. The prepared query is cached and reused
	// across requests so compilation cost is paid once per (policyID, ruleID).
	results, err := query.Eval(ctx, rego.EvalInput(input))
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

	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return nil, fmt.Errorf("rego result must define data.kube_policies.evaluate")
	}

	evalResult, ok := results[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("rego result must be an object with boolean allowed field, got %T", results[0].Expressions[0].Value)
	}

	allowed, ok := evalResult["allowed"].(bool)
	if !ok {
		return nil, fmt.Errorf("rego result must include boolean allowed field")
	}
	result.Allowed = allowed

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

	return result, nil
}

// prepareInput prepares the input for OPA evaluation
func (e *Engine) prepareInput(req *EvaluationRequest) (map[string]interface{}, error) {
	if req == nil || req.AdmissionRequest == nil {
		return nil, fmt.Errorf("admission request is required")
	}

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
		if err := json.Unmarshal(req.AdmissionRequest.Object.Raw, &obj); err != nil {
			return nil, fmt.Errorf("invalid admission object JSON: %w", err)
		}
		input["object"] = obj
	}

	// Add old object if present
	if req.AdmissionRequest.OldObject.Raw != nil {
		var oldObj interface{}
		if err := json.Unmarshal(req.AdmissionRequest.OldObject.Raw, &oldObj); err != nil {
			return nil, fmt.Errorf("invalid admission oldObject JSON: %w", err)
		}
		input["oldObject"] = oldObj
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

// loadDefaultPolicies loads default security policies.
//
// The Go literal below is the canonical source of the bundled defaults;
// the YAML samples under examples/policies/ are illustrative for users
// authoring their own policies and are NOT loaded automatically.
//
// Each rule's Rego is authored against the engine contract enforced in
// evaluateRule():
//   - Query: data.kube_policies.evaluate
//   - Input: the K8s object lives at input.object.* (see prepareInput).
//   - Output: a map with {allowed: bool}; when allowed=false, also
//     {message: string, path: string}.
//
// Rules use OPA v1 syntax (`import rego.v1`). When multiple potential
// denials match (e.g. several containers violate the same rule) each
// rule deterministically reports the lowest-indexed violation so the
// engine's single-violation-per-rule contract is preserved without
// triggering complete-doc conflicts.
func (e *Engine) loadDefaultPolicies() error {
	now := time.Now()
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
					Frameworks:  []string{"CIS-1.8.0", "NIST-800-53"},
					Rego: `package kube_policies

import rego.v1

import data.kube_policies.lib as lib

default evaluate := {"allowed": true}

evaluate := {
	"allowed": false,
	"message": "Pod must not run in privileged mode",
	"path": sprintf("%s.securityContext.privileged", [lib.container_path_prefix]),
} if {
	lib.pod_security_context.privileged == true
}

evaluate := {
	"allowed": false,
	"message": sprintf("Container '%s' must not run in privileged mode", [entry.container.name]),
	"path": sprintf("%s.securityContext.privileged", [entry.path]),
} if {
	not pod_privileged
	indexes := [j |
		some j
		lib.containers_with_paths[j].container.securityContext.privileged == true
	]
	count(indexes) > 0
	i := indexes[0]
	entry := lib.containers_with_paths[i]
}

pod_privileged if lib.pod_security_context.privileged == true
`,
				},
				{
					ID:          "no-host-path-volumes",
					Name:        "No HostPath Volumes",
					Description: "HostPath volumes are not allowed",
					Severity:    "HIGH",
					Category:    "Security",
					Frameworks:  []string{"CIS-1.8.0"},
					Rego: `package kube_policies

import rego.v1

import data.kube_policies.lib as lib

default evaluate := {"allowed": true}

evaluate := {
	"allowed": false,
	"message": "hostPath volumes are not allowed",
	"path": sprintf("%s.volumes[%d].hostPath", [lib.container_path_prefix, i]),
} if {
	indexes := [j |
		some j
		lib.volumes[j].hostPath
	]
	count(indexes) > 0
	i := indexes[0]
}
`,
				},
				{
					ID:          "no-latest-image-tag",
					Name:        "No Latest Image Tag",
					Description: "Container images must not use ':latest' or an implicit latest tag",
					Severity:    "MEDIUM",
					Category:    "Security",
					Frameworks:  []string{"CIS-1.8.0"},
					Rego: `package kube_policies

import rego.v1

import data.kube_policies.lib as lib

default evaluate := {"allowed": true}

evaluate := {
	"allowed": false,
	"message": sprintf("Container image '%s' must specify an explicit non-':latest' tag", [entry.container.image]),
	"path": sprintf("%s.image", [entry.path]),
} if {
	indexes := [j |
		some j
		bad_image(lib.containers_with_paths[j].container.image)
	]
	count(indexes) > 0
	i := indexes[0]
	entry := lib.containers_with_paths[i]
}

bad_image(image) if endswith(image, ":latest")

bad_image(image) if not contains(image, ":")
`,
				},
				{
					ID:          "required-security-context",
					Name:        "Required Security Context",
					Description: "Containers must declare a securityContext that runs as non-root and disallows privilege escalation",
					Severity:    "MEDIUM",
					Category:    "Security",
					Frameworks:  []string{"CIS-1.8.0", "PSS-restricted"},
					Rego: `package kube_policies

import rego.v1

import data.kube_policies.lib as lib

default evaluate := {"allowed": true}

evaluate := {
	"allowed": false,
	"message": sprintf("Container '%s' must declare runAsNonRoot=true and allowPrivilegeEscalation!=true in securityContext", [entry.container.name]),
	"path": sprintf("%s.securityContext", [entry.path]),
} if {
	indexes := [j |
		some j
		missing_required_sc(lib.containers_with_paths[j].container)
	]
	count(indexes) > 0
	i := indexes[0]
	entry := lib.containers_with_paths[i]
}

missing_required_sc(c) if not c.securityContext

missing_required_sc(c) if not c.securityContext.runAsNonRoot

missing_required_sc(c) if c.securityContext.runAsNonRoot == false

missing_required_sc(c) if c.securityContext.allowPrivilegeEscalation == true
`,
				},
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
	}

	// Route the bundled pod-shaped rules to pod-bearing kinds (POL-WU-21) so
	// they never evaluate against an RBAC/Network/Secret/ConfigMap object once
	// those rule packs and webhook coverage land.
	for _, p := range defaultPolicies {
		if p.ID == "security-baseline" {
			for i := range p.Rules {
				p.Rules[i].TargetKinds = podWorkloadKinds
			}
		}
	}

	for _, policy := range defaultPolicies {
		e.policies[policy.ID] = policy
	}

	// SUP-WU-07 / CFG-WU-15: register the opt-in image-provenance policy. It is
	// DISABLED BY DEFAULT so it never breaks existing deployments; operators
	// enable it (or load examples/policies/image-provenance.yaml with their own
	// registry allowlist) once images are published and digest-pinned.
	ip := imageProvenancePolicy()
	e.policies[ip.ID] = ip

	// P10 rule packs (POL-WU-03..20). All ship DISABLED by default; an
	// enforcement profile (POL-WU-23) activates the curated set an operator
	// selects, so a deploy that only wants security-baseline is never broken on
	// upgrade.
	for _, p := range []*Policy{
		pssBaselinePolicy(),
		pssRestrictedPolicy(),
		nsaHardeningPolicy(),
		governanceBaselinePolicy(),
		rbacBaselinePolicy(),
		secretsBaselinePolicy(),
		networkBaselinePolicy(),
		mutatingHardeningPolicy(),
	} {
		e.policies[p.ID] = p
	}

	return nil
}

// imageProvenancePolicy returns the bundled, opt-in supply-chain admission
// policy (SUP-WU-07, NIST CM-14/SR-4/SR-11, NIST SP 800-190 §4.3).
//
// It enforces two strong, in-process provenance signals at admission time:
//  1. allowed-registries     — images must come from an allowlisted registry.
//  2. require-image-digest   — images must be pinned by an immutable @sha256:
//     digest (a mutable tag is not verifiable provenance).
//
// Full CRYPTOGRAPHIC cosign signature verification is intentionally NOT done on
// the synchronous admission hot path; it is delegated to the Sigstore
// policy-controller / Kyverno verifyImages policy shipped with the chart
// (CFG-WU-15, charts/kube-policies/templates/image-verification-policy.yaml).
// See docs/policies/image-signing.md. Like the sibling bundled rules, these
// evaluate a Pod spec (spec.containers); workload-controller template traversal
// is tracked separately in P10.
func imageProvenancePolicy() *Policy {
	now := time.Now()
	return &Policy{
		ID:          "image-provenance",
		Name:        "Image Provenance",
		Description: "Require images from an allowlisted registry and pinned by immutable digest",
		Version:     "1.0.0",
		Enabled:     false, // opt-in; see CFG-WU-15 / docs/policies/image-signing.md
		// allowedRegistries is a comma-separated allowlist of trusted registry
		// prefixes (POL-WU-13). Operators override it via the Policy CRD
		// spec.parameters to match the registries they trust; it defaults to this
		// project's own published registry so the bundled policy is usable as-is.
		Parameters: map[string]string{
			"allowedRegistries": "ghcr.io/jibbscript/",
		},
		Rules: []Rule{
			{
				ID:          "allowed-registries",
				Name:        "Allowed Registries",
				Description: "Container images must come from an allowlisted registry",
				Severity:    "HIGH",
				Category:    "SupplyChain",
				Frameworks:  []string{"NIST-800-53", "NIST-800-190", "CIS-1.8.0", "NSA-Hardening-SupplyChain", "NIST SP 800-190 4.1.1"},
				TargetKinds: podWorkloadKinds,
				Rego: `package kube_policies

import rego.v1

import data.kube_policies.lib as lib

default evaluate := {"allowed": true}

# Allowlisted registry prefixes are parameter-driven (POL-WU-13): operators set
# spec.parameters.allowedRegistries (comma-separated) in their Policy CR. With no
# allowlist configured the set is empty and every image is denied (fail-secure);
# the bundled default ships this project's own published registry.
allowed_registries := {trim_space(p) |
	some p in split(object.get(input.parameters, "allowedRegistries", ""), ",")
	trim_space(p) != ""
}

evaluate := {
	"allowed": false,
	"message": sprintf("Container image '%s' is not from an allowed registry", [entry.container.image]),
	"path": sprintf("%s.image", [entry.path]),
} if {
	offending := [e |
		some e in lib.containers_with_paths
		not registry_allowed(e.container.image)
	]
	count(offending) > 0
	entry := offending[0]
}

registry_allowed(image) if {
	some prefix in allowed_registries
	# Match on a path-segment boundary so a registry/namespace that merely STARTS
	# WITH an allowed prefix cannot satisfy it (e.g. ghcr.io/jibbscript.evil.com/x
	# must NOT pass an allowlist of ghcr.io/jibbscript/). Normalize the prefix to a
	# single trailing slash, then require the image to begin with "<prefix>/".
	# Case-insensitive: registry/repository paths are case-insensitive on GHCR.
	norm := trim_suffix(lower(prefix), "/")
	startswith(lower(image), concat("", [norm, "/"]))
}
`,
			},
			{
				ID:          "require-image-digest",
				Name:        "Require Image Digest",
				Description: "Container images must be pinned by immutable digest (@sha256:...)",
				Severity:    "HIGH",
				Category:    "SupplyChain",
				Frameworks:  []string{"NIST-800-53", "NIST-800-190", "SLSA", "NSA-Hardening-SupplyChain", "NIST SR-4"},
				TargetKinds: podWorkloadKinds,
				Rego: `package kube_policies

import rego.v1

import data.kube_policies.lib as lib

default evaluate := {"allowed": true}

evaluate := {
	"allowed": false,
	"message": sprintf("Container image '%s' must be pinned by immutable digest (@sha256:...) for verifiable provenance", [entry.container.image]),
	"path": sprintf("%s.image", [entry.path]),
} if {
	offending := [e |
		some e in lib.containers_with_paths
		not contains(e.container.image, "@sha256:")
	]
	count(offending) > 0
	entry := offending[0]
}
`,
			},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// LoadPolicy loads a policy into the engine. Any cached prepared queries for
// rules belonging to this policy ID are invalidated so subsequent evaluations
// recompile from the (possibly updated) rule bodies.
func (e *Engine) LoadPolicy(policy *Policy) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	e.policies[policy.ID] = policy
	e.evictPreparedLocked(policy.ID)
	e.logger.Info("Policy loaded",
		zap.String("policy_id", policy.ID),
		zap.String("policy_name", policy.Name),
	)

	return nil
}

// RemovePolicy removes a policy from the engine and evicts any cached
// prepared queries for it.
func (e *Engine) RemovePolicy(policyID string) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	delete(e.policies, policyID)
	e.evictPreparedLocked(policyID)
	e.logger.Info("Policy removed",
		zap.String("policy_id", policyID),
	)

	return nil
}

// preparedQueryFor returns a cached PreparedEvalQuery for (policy, rule),
// compiling and storing one on first use. Concurrent callers may race to
// compile the same key; that is acceptable — last writer wins and both
// queries are functionally equivalent.
func (e *Engine) preparedQueryFor(ctx context.Context, policy *Policy, rule *Rule) (rego.PreparedEvalQuery, error) {
	key := policy.ID + "/" + rule.ID
	if v, ok := e.preparedQueries.Load(key); ok {
		if q, ok := v.(rego.PreparedEvalQuery); ok {
			return q, nil
		}
	}
	// Compile the rule together with the shared Rego library modules
	// (POL-WU-01) so rules can `import data.kube_policies.lib as lib` and
	// evaluate the effective pod spec across workload controllers,
	// initContainers, and ephemeralContainers.
	opts := []func(*rego.Rego){
		rego.Query("data.kube_policies.evaluate"),
		rego.Module(fmt.Sprintf("%s_%s", policy.ID, rule.ID), rule.Rego),
		rego.Store(e.store),
	}
	opts = append(opts, libModuleOptions()...)
	q, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return rego.PreparedEvalQuery{}, err
	}
	e.preparedQueries.Store(key, q)
	return q, nil
}

// evictPreparedLocked removes all cached queries for a given policy ID.
// Caller must hold e.mutex (write).
func (e *Engine) evictPreparedLocked(policyID string) {
	prefix := policyID + "/"
	e.preparedQueries.Range(func(k, _ any) bool {
		if s, ok := k.(string); ok && strings.HasPrefix(s, prefix) {
			e.preparedQueries.Delete(k)
		}
		return true
	})
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
