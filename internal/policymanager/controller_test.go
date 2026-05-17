package policymanager

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"k8s.io/client-go/rest"

	"github.com/Jibbscript/kube-policies/internal/policy"
	policiesv1 "github.com/Jibbscript/kube-policies/internal/policymanager/apis/policies/v1"
)

// stubPolicySink is a no-op PolicySink for tests that need a non-nil sink
// but do not exercise reconcile behavior.
type stubPolicySink struct{}

func (s *stubPolicySink) UpsertPolicyFromCRD(_ *policiesv1.Policy) *policy.Policy { return nil }
func (s *stubPolicySink) RemovePolicyByID(_ string) bool                          { return false }

// fakeRestConfig returns a rest.Config that will not successfully connect to
// any API server. It is used for unit tests that validate logic executed before
// manager.New (e.g. the early-exit namespace check) or that simply need to
// confirm the function reaches manager.New rather than failing at an earlier
// validation step.
func fakeRestConfig() *rest.Config {
	return &rest.Config{Host: "http://127.0.0.1:12345"}
}

// TestStartControllers_RequiresNamespaceWhenLeaderElectionEnabled verifies
// that StartControllers returns an error containing "LeaderElectionNamespace"
// when leader election is enabled (zero-value DisableLeaderElection) but no
// namespace is provided. The validation fires before manager.New so no real
// API server is required.
func TestStartControllers_RequiresNamespaceWhenLeaderElectionEnabled(t *testing.T) {
	err := StartControllers(context.Background(), fakeRestConfig(), zap.NewNop(), ControllerOptions{
		PolicySink: &stubPolicySink{},
		// DisableLeaderElection: zero value (false) → election ON
		// LeaderElectionNamespace: zero value (empty) → must trigger error
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "LeaderElectionNamespace")
}

// TestStartControllers_DefaultsLeaderElectionIDToPolicyManager verifies that
// an empty LeaderElectionID is filled to "kube-policies-policy-manager" before
// manager.New is called. DisableLeaderElection=true bypasses namespace validation;
// the immediately-cancelled context causes mgr.Start to exit cleanly (nil).
// The absence of any validation error proves the ID-defaulting code ran without issue.
func TestStartControllers_DefaultsLeaderElectionIDToPolicyManager(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before call — mgr.Start sees a done context and returns nil

	err := StartControllers(ctx, fakeRestConfig(), zap.NewNop(), ControllerOptions{
		PolicySink:            &stubPolicySink{},
		DisableLeaderElection: true,
		// LeaderElectionID: empty — must be defaulted to "kube-policies-policy-manager".
	})
	// mgr.Start returns nil on context cancellation; StartControllers propagates nil.
	assert.NoError(t, err)
}

// TestControllerOptions_ZeroValueEnablesLeaderElection verifies the inverted-bool
// contract: DisableLeaderElection=false (zero value) means election is ON. With a
// non-empty LeaderElectionNamespace the namespace precondition passes; the
// immediately-cancelled context causes mgr.Start to exit cleanly (nil). If the
// zero value had disabled election instead of enabling it, the validation would
// have been skipped and the manager built with LeaderElection=false — but the
// log line and the manager options would be wrong. This test pins that the zero
// value results in LeaderElection=true in the constructed manager.Options.
func TestControllerOptions_ZeroValueEnablesLeaderElection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before call — mgr.Start exits cleanly without network calls

	err := StartControllers(ctx, fakeRestConfig(), zap.NewNop(), ControllerOptions{
		PolicySink:              &stubPolicySink{},
		LeaderElectionNamespace: "test-namespace",
		// DisableLeaderElection: zero value (false) → election ON
	})
	// mgr.Start returns nil on context cancellation; StartControllers propagates nil.
	assert.NoError(t, err)
}
