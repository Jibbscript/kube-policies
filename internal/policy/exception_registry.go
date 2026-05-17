package policy

import "context"

// ExceptionRegistry is the engine's read-only view of policy exceptions.
// The webhook's composition root wires an implementation that is fed by a
// controller-runtime watch; tests use in-memory fakes.
//
// Error contract: the in-memory implementation shipped in this PR never
// returns a non-nil error. The error return is retained in the signature
// so future implementations MAY surface transient failures (e.g. context
// cancellation mid-evaluation, future cache invalidation, future remote
// backends). The engine's contract on receiving a non-nil error is
// FAIL-CLOSED: the original deny stands; no suppression is applied; a
// warning is logged with the policy_id/rule_id/error. This is the deliberate
// mitigation for pre-mortem §4.2 (registry stale / error path → operators
// losing access to exceptions get more denial, not less). The
// engine-side fail-closed branch is a live production code path tested by
// TestEngine_RegistryError_FailClosed (Step 5.3 case 4); it is not dead
// code, so the error return is retained.
type ExceptionRegistry interface {
	Suppresses(ctx context.Context, key MatchKey) (bool, []ExceptionRef, error)
}

// MatchKey is the input the engine hands to the registry on each
// violation. The registry decides whether any exception matches.
//
// Resource is lowercased plural form ("pods", "deployments") to match
// the AdmissionRequest.Resource.Resource field. User and Groups carry
// the caller identity for user/group-scoped exceptions.
type MatchKey struct {
	PolicyID  string
	RuleID    string
	Namespace string
	Resource  string
	User      string
	Groups    []string
}

// ExceptionRef is a stable, audit-friendly handle to an exception that
// suppressed a violation. Embedded on EvaluationResult.SuppressedBy so
// downstream consumers (audit log, decisions publisher, response message)
// can attribute the suppression without needing to re-query the registry.
type ExceptionRef struct {
	ID            string
	Name          string
	PolicyID      string
	RuleID        string
	Justification string
}
