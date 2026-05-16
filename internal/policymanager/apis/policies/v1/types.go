package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Policy is the typed Go representation of policies.policies.kube-policies.io v1.
// Fields are kept aligned with the OpenAPI schema in
// deployments/kubernetes/crds/policies.yaml. When you add a field to the CRD,
// add it here and regenerate the DeepCopy methods.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type Policy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PolicySpec   `json:"spec,omitempty"`
	Status PolicyStatus `json:"status,omitempty"`
}

// PolicyList is the standard k8s list wrapper required so we can use the typed
// controller-runtime client.List call. controller-runtime registers it via
// SchemeBuilder.Register in register.go.
//
// +kubebuilder:object:root=true
type PolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Policy `json:"items"`
}

// PolicySpec mirrors the spec section of the Policy CRD. Fields outside the
// rule body (severity, category, frameworks, targets) are advisory metadata
// that the policy-manager surfaces through its REST API; only `Rules` is
// strictly required by the engine.
type PolicySpec struct {
	Description string `json:"description,omitempty"`
	// Enabled defaults to true on the CRD side. Go zero-value here is false,
	// so the reconciler treats a missing flag as enabled — see controller.go.
	Enabled    *bool        `json:"enabled,omitempty"`
	Severity   string       `json:"severity,omitempty"`
	Category   string       `json:"category,omitempty"`
	Frameworks []string     `json:"frameworks,omitempty"`
	Rules      []PolicyRule `json:"rules"`
	Targets    *Targets     `json:"targets,omitempty"`
	// Metadata is intentionally string→string; the CRD uses
	// additionalProperties: { type: string } in the OpenAPI schema.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// PolicyRule is one Rego rule. Name + Rego are required; everything else is
// advisory. The Rego body must implement the `data.kube_policies.evaluate`
// contract documented in internal/policy/engine.go::loadDefaultPolicies.
type PolicyRule struct {
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Severity    string            `json:"severity,omitempty"`
	Category    string            `json:"category,omitempty"`
	Frameworks  []string          `json:"frameworks,omitempty"`
	Rego        string            `json:"rego"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Targets narrows which apiserver objects a policy should apply to. The
// admission-webhook today does not consume Targets — the in-memory registry
// surfaces them so the dashboard SPA can render them, but enforcement is
// universal until a future change wires Targets through engine.evaluatePolicy.
type Targets struct {
	Kinds             []TargetKind `json:"kinds,omitempty"`
	Namespaces        []string     `json:"namespaces,omitempty"`
	ExcludeNamespaces []string     `json:"excludeNamespaces,omitempty"`
}

// TargetKind is an explicit GVK; the CRD requires both fields, so neither is
// marked omitempty.
type TargetKind struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
}

// PolicyStatus is the observed state of a Policy. The reconciler updates
// Phase/Conditions on every reconcile pass. ViolationCount and LastEvaluated
// are surfaced through /api/v1/policies/:id/status once that runtime
// telemetry is wired (it is a stub today — manager.go::GetPolicyStatus).
type PolicyStatus struct {
	Phase          string             `json:"phase,omitempty"`
	Conditions     []metav1.Condition `json:"conditions,omitempty"`
	ViolationCount int                `json:"violationCount,omitempty"`
	LastEvaluated  *metav1.Time       `json:"lastEvaluated,omitempty"`
}

// PolicyException grants a targeted carve-out from a Policy. It is the typed
// counterpart of deployments/kubernetes/crds/policyexceptions.yaml.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type PolicyException struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PolicyExceptionSpec   `json:"spec,omitempty"`
	Status PolicyExceptionStatus `json:"status,omitempty"`
}

// PolicyExceptionList is the list wrapper for typed List calls.
//
// +kubebuilder:object:root=true
type PolicyExceptionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PolicyException `json:"items"`
}

// PolicyExceptionSpec defines the exception's scope. PolicyID is required;
// RuleID narrows the exception to a single rule of the parent policy.
//
// JSON tags use snake_case to match the existing
// internal/policymanager.Exception struct so the dashboard SPA can render
// CRD-sourced and API-sourced exceptions without separate handling code.
type PolicyExceptionSpec struct {
	Description   string               `json:"description,omitempty"`
	PolicyID      string               `json:"policy_id"`
	RuleID        string               `json:"rule_id,omitempty"`
	Justification string               `json:"justification,omitempty"`
	Approver      string               `json:"approver,omitempty"`
	ExpiresAt     *metav1.Time         `json:"expires_at,omitempty"`
	Scope         PolicyExceptionScope `json:"scope,omitempty"`
}

// PolicyExceptionScope is a selector for the resources covered by the exception.
type PolicyExceptionScope struct {
	Namespaces []string `json:"namespaces,omitempty"`
	Resources  []string `json:"resources,omitempty"`
	Users      []string `json:"users,omitempty"`
	Groups     []string `json:"groups,omitempty"`
}

// PolicyExceptionStatus mirrors the structure of PolicyStatus so that the
// controller can use the same condition-publishing helpers for both kinds.
type PolicyExceptionStatus struct {
	Phase      string             `json:"phase,omitempty"`
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}
