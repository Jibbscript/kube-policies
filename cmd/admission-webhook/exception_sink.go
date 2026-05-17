package main

import (
	"context"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/Jibbscript/kube-policies/internal/policy"
	"github.com/Jibbscript/kube-policies/internal/policymanager"
	policiesv1 "github.com/Jibbscript/kube-policies/internal/policymanager/apis/policies/v1"
)

// exceptionSink is the webhook's dual-role adapter.
//
//   - WRITE SIDE: satisfies policymanager.ExceptionSink so the embedded
//     PolicyExceptionReconciler can push CRD upserts/removes into it via
//     UpsertExceptionFromCRD / RemoveExceptionByID.
//   - READ SIDE: satisfies policy.ExceptionRegistry so the engine can call
//     Suppresses(ctx, MatchKey) on the hot path.
//
// Same composition-root pattern as engineSink (crd_sink.go) — keeps the
// engine package agnostic of transport. The dual-interface trick is
// intentional: one struct, two named interfaces, both wired by main.go.
type exceptionSink struct {
	log  *zap.Logger
	mu   sync.RWMutex
	byID map[string]*policymanager.Exception // canonical store; keyed by CRDExceptionID
	// byPolicy indexes ex.PolicyID -> []*Exception for O(matches-in-policy) lookup.
	// Rebuilt under mu.Lock on every upsert/remove. O(N) rebuild is acceptable
	// at the planned scale (tens-hundreds of exceptions); revisit if N grows to
	// thousands per Architect Synthesis S7 / follow-up.
	byPolicy map[string][]*policymanager.Exception
}

// Compile-time interface assertions — both lines MUST appear in the file so a
// future refactor that breaks either contract fails at build time.
var (
	_ policymanager.ExceptionSink = (*exceptionSink)(nil)
	_ policy.ExceptionRegistry    = (*exceptionSink)(nil)
)

func newExceptionSink(log *zap.Logger) *exceptionSink {
	return &exceptionSink{
		log:      log,
		byID:     make(map[string]*policymanager.Exception),
		byPolicy: make(map[string][]*policymanager.Exception),
	}
}

// --- policymanager.ExceptionSink (write side) ---

// UpsertExceptionFromCRD converts the CRD into an internal Exception via the
// shared converter and stores it in the index. The byPolicy secondary index
// is rebuilt under the write lock to keep read-path lookups branch-free.
func (s *exceptionSink) UpsertExceptionFromCRD(crd *policiesv1.PolicyException) *policymanager.Exception {
	ex := policymanager.ExceptionFromCRD(crd)
	s.mu.Lock()
	s.byID[ex.ID] = ex
	s.rebuildIndexLocked()
	s.mu.Unlock()
	s.log.Info("exception loaded into webhook index",
		zap.String("internal_id", ex.ID),
		zap.String("policy_id", ex.PolicyID),
	)
	return ex
}

// RemoveExceptionByID drops the exception with the given ID. Returns true
// iff the ID was present in the store before the call (matches the
// policymanager.ExceptionSink contract).
func (s *exceptionSink) RemoveExceptionByID(id string) bool {
	s.mu.Lock()
	_, ok := s.byID[id]
	if ok {
		delete(s.byID, id)
		s.rebuildIndexLocked()
	}
	s.mu.Unlock()
	return ok
}

// --- policy.ExceptionRegistry (read side) ---

// Suppresses returns (true, refs, nil) when at least one stored exception
// matches key. Returns (false, nil, nil) when no exception matches or the
// store is empty. NEVER returns a non-nil error in this in-memory
// implementation — the error return is reserved for future implementations
// per the ExceptionRegistry godoc. The engine's contract on error is
// fail-closed; tested by TestEngine_RegistryError_FailClosed.
func (s *exceptionSink) Suppresses(_ context.Context, key policy.MatchKey) (bool, []policy.ExceptionRef, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	candidates := s.byPolicy[key.PolicyID]
	if len(candidates) == 0 {
		return false, nil, nil
	}
	var refs []policy.ExceptionRef
	now := time.Now()
	for _, ex := range candidates {
		if !matches(ex, key, now) {
			continue
		}
		refs = append(refs, policy.ExceptionRef{
			ID:            ex.ID,
			Name:          ex.Name,
			PolicyID:      ex.PolicyID,
			RuleID:        ex.RuleID,
			Justification: ex.Justification,
		})
	}
	return len(refs) > 0, refs, nil
}

// rebuildIndexLocked recomputes byPolicy from byID. Caller must hold mu.
func (s *exceptionSink) rebuildIndexLocked() {
	next := make(map[string][]*policymanager.Exception, len(s.byID))
	for _, ex := range s.byID {
		next[ex.PolicyID] = append(next[ex.PolicyID], ex)
	}
	s.byPolicy = next
}

// matches reports whether ex applies to the request described by key at
// time `now`. This is THE security-sensitive predicate; every rule below is
// load-bearing. Each rule has a corresponding test row in Step 5.6.
//
// Reads PolicyExceptionScope fields by name (per internal/policymanager/apis/
// policies/v1/types.go): Namespaces, Resources, Users, Groups.
// PolicyExceptionScope has no matchLabels / labelSelector field today.
//
// Comparison semantics (every field):
//   - Strings compare case-SENSITIVELY for Namespace, User, Group (Kubernetes
//     identifiers are case-sensitive per DNS-1123 / RFC 1035).
//   - Resource compares case-INSENSITIVELY: key.Resource is lower-cased by the
//     engine (Step 5.2 uses strings.ToLower), and the matcher additionally
//     lower-cases ex.Scope.Resources entries before comparing. This makes
//     "Pods", "pods", "POdS" all match identically.
//   - Time compare: ex.ExpiresAt is compared against the supplied `now`. If
//     ExpiresAt is in the past, no match (regardless of any other field).
//
// Scope-presence rule (anchors pre-mortem §4.1):
//   - "Scope entirely absent" means ALL four slices (Namespaces, Resources,
//     Users, Groups) have len==0. This represents the operator's explicit
//     "blanket carve-out for the named policy/rule" intent and MATCHES any
//     request. This is the ONE wildcard case.
//   - "Scope partially populated" means at least one of the four slices has
//     len>0. In this case EVERY populated slice acts as a strict allow-list
//     for its dimension: the request's value MUST appear in the list. An
//     UN-populated slice (len==0) in a partially-populated scope is
//     UNCONSTRAINED for that dimension — i.e. it does NOT filter requests
//     out, but it also does NOT widen the match. This is the standard k8s
//     selector convention.
//   - The dangerous antipattern this prevents: an operator writing
//     `scope: { namespaces: [] }` thinking it means "no namespaces" and
//     getting "all namespaces" instead. Under our rule, an explicitly-empty
//     `namespaces:` list inside an otherwise-populated scope means "namespace
//     dimension is unconstrained"; combined with all-other-dimensions also
//     unset, the scope counts as "entirely absent" and matches everything.
//     Operators who genuinely want "no namespaces" must omit the
//     PolicyException CR entirely. This is documented in the CRD schema as
//     a follow-up (OQ tracker).
//
// RuleID semantics:
//   - ex.RuleID == "" matches any rule of the parent policy (CRD field is
//     optional per types.go).
//   - ex.RuleID != "" matches only the named rule.
//
// Groups semantics (intersection-non-empty):
//   - ex.Scope.Groups is the allow-list; key.Groups is the request user's
//     group membership. Match if the intersection is non-empty.
//   - Empty key.Groups (anonymous/unset) never matches a populated
//     ex.Scope.Groups (cannot intersect with the empty set).
//
//nolint:gocyclo // straight-line list of allow-list checks; intentional shape.
func matches(ex *policymanager.Exception, key policy.MatchKey, now time.Time) bool {
	// (1) Expired = no match, regardless of any other field.
	if ex.ExpiresAt != nil && ex.ExpiresAt.Before(now) {
		return false
	}

	// (2) RuleID filter: empty in CRD = applies to all rules; populated = exact match required.
	if ex.RuleID != "" && ex.RuleID != key.RuleID {
		return false
	}

	// (3) Scope-presence: count populated dimensions. Scope-entirely-absent
	// is the only wildcard case and matches any request.
	populatedDimensions := 0
	if len(ex.Scope.Namespaces) > 0 {
		populatedDimensions++
	}
	if len(ex.Scope.Resources) > 0 {
		populatedDimensions++
	}
	if len(ex.Scope.Users) > 0 {
		populatedDimensions++
	}
	if len(ex.Scope.Groups) > 0 {
		populatedDimensions++
	}
	if populatedDimensions == 0 {
		return true // scope entirely absent → blanket carve-out for this policy/rule
	}

	// (4) Per-dimension allow-list checks. An unset dimension within a
	// partially-populated scope is unconstrained and does NOT cause a failure.
	if len(ex.Scope.Namespaces) > 0 && !contains(ex.Scope.Namespaces, key.Namespace) {
		return false
	}
	if len(ex.Scope.Resources) > 0 && !containsFold(ex.Scope.Resources, strings.ToLower(key.Resource)) {
		return false
	}
	if len(ex.Scope.Users) > 0 && !contains(ex.Scope.Users, key.User) {
		return false
	}
	if len(ex.Scope.Groups) > 0 && !anyIntersects(ex.Scope.Groups, key.Groups) {
		return false
	}
	return true
}

// contains is the case-sensitive set-membership check used for namespaces,
// users, and individual groups.
func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

// containsFold is the case-insensitive variant used for the Resource
// dimension. Callers pass an already-lower-cased v.
func containsFold(set []string, v string) bool {
	for _, s := range set {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}

// anyIntersects reports whether set and vs share at least one element
// (case-sensitive). Used for group-intersection matching.
func anyIntersects(set, vs []string) bool {
	if len(set) == 0 || len(vs) == 0 {
		return false
	}
	// Linear scan; both sides are small (groups per user typically <10; groups
	// per exception typically <5). Promote to map if N grows.
	for _, v := range vs {
		if contains(set, v) {
			return true
		}
	}
	return false
}
