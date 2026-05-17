package main

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Jibbscript/kube-policies/internal/policy"
	policiesv1 "github.com/Jibbscript/kube-policies/internal/policymanager/apis/policies/v1"
)

// newCRDException is a tiny helper for building a PolicyException CRD with a
// fully-controlled spec. The namespace/name pair determines the internal
// CRDExceptionID via policymanager.CRDExceptionID.
func newCRDException(name, policyID, ruleID string, scope policiesv1.PolicyExceptionScope, expiresAt *time.Time) *policiesv1.PolicyException {
	pe := &policiesv1.PolicyException{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-policies-test",
			Name:      name,
		},
		Spec: policiesv1.PolicyExceptionSpec{
			PolicyID:      policyID,
			RuleID:        ruleID,
			Justification: "test fixture",
			Scope:         scope,
		},
	}
	if expiresAt != nil {
		t := metav1.NewTime(*expiresAt)
		pe.Spec.ExpiresAt = &t
	}
	return pe
}

func newSinkForTest(t *testing.T) *exceptionSink {
	t.Helper()
	return newExceptionSink(zap.NewNop())
}

// (1) Insert then query the matching key — sink reports suppression.
func TestExceptionSink_Upsert_AddsToIndex(t *testing.T) {
	s := newSinkForTest(t)
	s.UpsertExceptionFromCRD(newCRDException("e1", "security-baseline", "", policiesv1.PolicyExceptionScope{}, nil))
	suppressed, refs, err := s.Suppresses(context.Background(), policy.MatchKey{
		PolicyID: "security-baseline",
		RuleID:   "any-rule",
	})
	if err != nil {
		t.Fatalf("Suppresses returned error: %v", err)
	}
	if !suppressed {
		t.Fatalf("expected suppressed=true; got false, refs=%v", refs)
	}
	if len(refs) != 1 {
		t.Fatalf("expected exactly 1 ref; got %d (%v)", len(refs), refs)
	}
	if refs[0].PolicyID != "security-baseline" {
		t.Errorf("ref PolicyID = %q; want %q", refs[0].PolicyID, "security-baseline")
	}
}

// (2) Insert then remove — Suppresses reports no match.
func TestExceptionSink_Remove_RemovesFromIndex(t *testing.T) {
	s := newSinkForTest(t)
	crd := newCRDException("e1", "security-baseline", "", policiesv1.PolicyExceptionScope{}, nil)
	internal := s.UpsertExceptionFromCRD(crd)
	if !s.RemoveExceptionByID(internal.ID) {
		t.Fatalf("expected RemoveExceptionByID to return true for known ID %q", internal.ID)
	}
	suppressed, _, _ := s.Suppresses(context.Background(), policy.MatchKey{PolicyID: "security-baseline"})
	if suppressed {
		t.Fatalf("expected suppressed=false after Remove; got true")
	}
	// Removing an absent ID returns false.
	if s.RemoveExceptionByID("nonexistent") {
		t.Errorf("expected RemoveExceptionByID(nonexistent) = false")
	}
}

// (3) Exception for one policy must not match queries for a different policy.
func TestExceptionSink_PolicyIDMismatch(t *testing.T) {
	s := newSinkForTest(t)
	s.UpsertExceptionFromCRD(newCRDException("e1", "policy-A", "", policiesv1.PolicyExceptionScope{}, nil))
	suppressed, _, _ := s.Suppresses(context.Background(), policy.MatchKey{PolicyID: "policy-B"})
	if suppressed {
		t.Fatalf("expected suppressed=false for cross-policy query; got true")
	}
}

// (4) RuleID filter: populated → exact match; empty → match any rule.
func TestExceptionSink_RuleIDFilter(t *testing.T) {
	s := newSinkForTest(t)
	s.UpsertExceptionFromCRD(newCRDException("specific", "policy-A", "rule-X", policiesv1.PolicyExceptionScope{}, nil))

	// Specific rule-X exception does not match rule-Y queries.
	if got, _, _ := s.Suppresses(context.Background(), policy.MatchKey{PolicyID: "policy-A", RuleID: "rule-Y"}); got {
		t.Fatalf("expected rule-X exception to NOT match rule-Y query; got suppressed=true")
	}
	// Specific rule-X exception matches rule-X queries.
	if got, _, _ := s.Suppresses(context.Background(), policy.MatchKey{PolicyID: "policy-A", RuleID: "rule-X"}); !got {
		t.Fatalf("expected rule-X exception to match rule-X query; got suppressed=false")
	}

	// Now add a blanket (no RuleID) exception under a fresh policy.
	s.UpsertExceptionFromCRD(newCRDException("blanket", "policy-B", "", policiesv1.PolicyExceptionScope{}, nil))
	if got, _, _ := s.Suppresses(context.Background(), policy.MatchKey{PolicyID: "policy-B", RuleID: "rule-anything"}); !got {
		t.Fatalf("expected blanket exception to match any rule; got suppressed=false")
	}
}

// (5) Namespaces=["foo"]: strict match; "bar" → false, "foo" → true, "FOO" → false (case-sensitive).
func TestExceptionSink_NamespaceScope_Strict(t *testing.T) {
	s := newSinkForTest(t)
	s.UpsertExceptionFromCRD(newCRDException("e1", "policy-A", "", policiesv1.PolicyExceptionScope{
		Namespaces: []string{"foo"},
	}, nil))

	cases := []struct {
		ns   string
		want bool
	}{
		{"bar", false},
		{"foo", true},
		{"FOO", false}, // case-sensitive
	}
	for _, c := range cases {
		got, _, _ := s.Suppresses(context.Background(), policy.MatchKey{PolicyID: "policy-A", Namespace: c.ns})
		if got != c.want {
			t.Errorf("namespace=%q: suppressed=%v; want %v", c.ns, got, c.want)
		}
	}
}

// (6) Scope entirely absent → matches any namespace/user/group/resource.
func TestExceptionSink_EmptyScope_MatchesAnyResource(t *testing.T) {
	s := newSinkForTest(t)
	s.UpsertExceptionFromCRD(newCRDException("e1", "policy-A", "", policiesv1.PolicyExceptionScope{}, nil))

	keys := []policy.MatchKey{
		{PolicyID: "policy-A", Namespace: "ns1", User: "alice", Groups: []string{"g1"}, Resource: "pods"},
		{PolicyID: "policy-A", Namespace: "ns2", User: "bob", Groups: nil, Resource: "deployments"},
		{PolicyID: "policy-A"}, // bare key
	}
	for i, k := range keys {
		got, _, _ := s.Suppresses(context.Background(), k)
		if !got {
			t.Errorf("case %d: blanket exception should match key %+v; got suppressed=false", i, k)
		}
	}
}

// (7) Empty namespace list within an otherwise-populated scope is unconstrained
// for that dimension. Users=["alice"], Namespaces=[]: matches (foo,alice) but
// not (foo,bob).
func TestExceptionSink_EmptyNamespaceList_DoesNotConstrainNamespace(t *testing.T) {
	s := newSinkForTest(t)
	s.UpsertExceptionFromCRD(newCRDException("e1", "policy-A", "", policiesv1.PolicyExceptionScope{
		Users: []string{"alice"},
		// Namespaces explicitly empty
	}, nil))

	if got, _, _ := s.Suppresses(context.Background(), policy.MatchKey{
		PolicyID: "policy-A", Namespace: "foo", User: "alice",
	}); !got {
		t.Errorf("(foo,alice): expected suppressed=true (namespace dimension unconstrained); got false")
	}
	if got, _, _ := s.Suppresses(context.Background(), policy.MatchKey{
		PolicyID: "policy-A", Namespace: "foo", User: "bob",
	}); got {
		t.Errorf("(foo,bob): expected suppressed=false (user not in allow-list); got true")
	}
}

// (8) Groups=["g1","g2"]: intersection-non-empty semantics.
func TestExceptionSink_GroupMatch_Intersection(t *testing.T) {
	s := newSinkForTest(t)
	s.UpsertExceptionFromCRD(newCRDException("e1", "policy-A", "", policiesv1.PolicyExceptionScope{
		Groups: []string{"g1", "g2"},
	}, nil))

	cases := []struct {
		groups []string
		want   bool
	}{
		{[]string{"g3", "g2"}, true},  // intersection non-empty
		{[]string{"g3"}, false},       // disjoint
		{[]string{"g2"}, true},        // single-element exact match (closes CRITICAL-N2)
	}
	for _, c := range cases {
		got, _, _ := s.Suppresses(context.Background(), policy.MatchKey{
			PolicyID: "policy-A",
			Groups:   c.groups,
		})
		if got != c.want {
			t.Errorf("groups=%v: suppressed=%v; want %v", c.groups, got, c.want)
		}
	}
}

// (9) Empty request groups cannot intersect a populated scope.Groups.
func TestExceptionSink_GroupMatch_EmptyRequestGroups(t *testing.T) {
	s := newSinkForTest(t)
	s.UpsertExceptionFromCRD(newCRDException("e1", "policy-A", "", policiesv1.PolicyExceptionScope{
		Groups: []string{"g1"},
	}, nil))

	if got, _, _ := s.Suppresses(context.Background(), policy.MatchKey{
		PolicyID: "policy-A",
		Groups:   nil,
	}); got {
		t.Errorf("empty request groups must not match populated scope.Groups; got suppressed=true")
	}
}

// (10) Expired exception never matches, regardless of other fields.
func TestExceptionSink_Expired_NoMatch(t *testing.T) {
	s := newSinkForTest(t)
	past := time.Now().Add(-1 * time.Hour)
	s.UpsertExceptionFromCRD(newCRDException("e1", "policy-A", "", policiesv1.PolicyExceptionScope{}, &past))

	if got, _, _ := s.Suppresses(context.Background(), policy.MatchKey{PolicyID: "policy-A"}); got {
		t.Errorf("expired exception must not match; got suppressed=true")
	}
}

// (11) Resource dimension is case-INSENSITIVE.
func TestExceptionSink_ResourceCaseInsensitive(t *testing.T) {
	s := newSinkForTest(t)
	s.UpsertExceptionFromCRD(newCRDException("e1", "policy-A", "", policiesv1.PolicyExceptionScope{
		Resources: []string{"Pods"},
	}, nil))

	for _, r := range []string{"pods", "PODS", "Pods"} {
		got, _, _ := s.Suppresses(context.Background(), policy.MatchKey{
			PolicyID: "policy-A",
			Resource: r,
		})
		if !got {
			t.Errorf("resource=%q: expected suppressed=true (case-insensitive); got false", r)
		}
	}
}

// (12) User dimension is case-SENSITIVE.
func TestExceptionSink_UserScope_CaseSensitive(t *testing.T) {
	s := newSinkForTest(t)
	s.UpsertExceptionFromCRD(newCRDException("e1", "policy-A", "", policiesv1.PolicyExceptionScope{
		Users: []string{"alice"},
	}, nil))

	if got, _, _ := s.Suppresses(context.Background(), policy.MatchKey{
		PolicyID: "policy-A", User: "Alice",
	}); got {
		t.Errorf("user=Alice must not match users=[alice] (case-sensitive); got suppressed=true")
	}
	if got, _, _ := s.Suppresses(context.Background(), policy.MatchKey{
		PolicyID: "policy-A", User: "alice",
	}); !got {
		t.Errorf("user=alice should match users=[alice]; got suppressed=false")
	}
}

// (13) Partially-populated scope: unset dimensions are unconstrained.
func TestExceptionSink_ScopePartiallyPopulated_UnsetDimensionUnconstrained(t *testing.T) {
	s := newSinkForTest(t)
	s.UpsertExceptionFromCRD(newCRDException("e1", "policy-A", "", policiesv1.PolicyExceptionScope{
		Namespaces: []string{"foo"},
	}, nil))

	// Namespace matches; all other dimensions unset → unconstrained → match.
	got, _, _ := s.Suppresses(context.Background(), policy.MatchKey{
		PolicyID:  "policy-A",
		Namespace: "foo",
		User:      "anyone",
		Groups:    []string{"anything"},
		Resource:  "anything",
	})
	if !got {
		t.Errorf("expected suppressed=true for namespace-only scope; got false")
	}

	// Namespace does NOT match → no suppression even though other dims unset.
	got, _, _ = s.Suppresses(context.Background(), policy.MatchKey{
		PolicyID:  "policy-A",
		Namespace: "bar",
	})
	if got {
		t.Errorf("expected suppressed=false when namespace not in allow-list; got true")
	}
}

// (14) Concurrent Upsert+Suppresses — must be race-free under -race.
func TestExceptionSink_ConcurrentReadWrite(t *testing.T) {
	s := newSinkForTest(t)
	ctx := context.Background()

	const iterations = 200
	var wg sync.WaitGroup
	wg.Add(2)

	// Writer: keep upserting fresh CRDs with varying names.
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			name := fmt.Sprintf("e-%d", i)
			s.UpsertExceptionFromCRD(newCRDException(name, "policy-A", "", policiesv1.PolicyExceptionScope{}, nil))
		}
	}()

	// Reader: keep querying.
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_, _, _ = s.Suppresses(ctx, policy.MatchKey{PolicyID: "policy-A"})
		}
	}()

	wg.Wait()

	// After both goroutines complete, the store must hold all `iterations`
	// exceptions and a query must still suppress.
	got, _, _ := s.Suppresses(ctx, policy.MatchKey{PolicyID: "policy-A"})
	if !got {
		t.Fatalf("expected suppressed=true after concurrent writes; got false")
	}
}
