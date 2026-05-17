package policy

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/Jibbscript/kube-policies/internal/config"
)

// fakeRegistry is the engine-side test double for ExceptionRegistry. It records
// each MatchKey it was asked about and returns the (suppressed, refs, err)
// triple produced by the supplied responder. Concurrent-safe so race-detector
// runs are clean.
type fakeRegistry struct {
	mu        sync.Mutex
	calls     []MatchKey
	responder func(key MatchKey) (bool, []ExceptionRef, error)
}

func (f *fakeRegistry) Suppresses(_ context.Context, key MatchKey) (bool, []ExceptionRef, error) {
	f.mu.Lock()
	f.calls = append(f.calls, key)
	f.mu.Unlock()
	if f.responder == nil {
		return false, nil, nil
	}
	return f.responder(key)
}

func (f *fakeRegistry) recorded() []MatchKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]MatchKey, len(f.calls))
	copy(out, f.calls)
	return out
}

// privilegedPodJSON is a minimal Pod manifest that trips ONLY the bundled
// `no-privileged-containers` rule — explicit non-:latest tag, runAsNonRoot,
// and allowPrivilegeEscalation=false keep the other default rules clear.
const privilegedPodJSON = `{
  "spec":{
    "containers":[{
      "name":"c",
      "image":"nginx:1.0",
      "securityContext":{
        "privileged":true,
        "runAsNonRoot":true,
        "allowPrivilegeEscalation":false
      }
    }]
  }
}`

// triViolationPodJSON trips EXACTLY three bundled rules:
//   - no-privileged-containers (privileged=true)
//   - no-host-path-volumes (volume.hostPath set)
//   - required-security-context (runAsNonRoot missing)
//
// The image carries an explicit non-:latest tag to keep the
// `no-latest-image-tag` rule clear; the test fakes scope their responses
// to the three rules above.
const triViolationPodJSON = `{
  "spec":{
    "containers":[{"name":"c","image":"nginx:1.0","securityContext":{"privileged":true}}],
    "volumes":[{"name":"v","hostPath":{"path":"/etc"}}]
  }
}`

func newEvaluationRequest(raw []byte) *EvaluationRequest {
	return &EvaluationRequest{
		AdmissionRequest: &admissionv1.AdmissionRequest{
			UID:       types.UID("exc-test"),
			Kind:      metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
			Resource:  metav1.GroupVersionResource{Version: "v1", Resource: "Pods"}, // intentionally mixed-case to verify lowercasing
			Namespace: "team-a",
			Operation: admissionv1.Create,
			UserInfo: authenticationv1.UserInfo{
				Username: "alice",
				Groups:   []string{"devs", "team-a"},
			},
			Object: runtime.RawExtension{Raw: raw},
		},
		Operation: "test",
	}
}

// TestEngine_NoRegistry_BehaviorUnchanged anchors Principle 5: NewEngine
// (nil registry) must produce the exact same deny verdict and message
// as before the feature landed.
func TestEngine_NoRegistry_BehaviorUnchanged(t *testing.T) {
	engine, err := NewEngine(&config.PolicyConfig{FailureMode: "fail-closed"}, zap.NewNop())
	require.NoError(t, err)

	res, err := engine.Evaluate(context.Background(), newEvaluationRequest([]byte(privilegedPodJSON)))
	require.NoError(t, err)

	assert.False(t, res.Allowed)
	assert.Equal(t, "PolicyViolation", res.Reason)
	assert.Empty(t, res.SuppressedBy)
	assert.NotEmpty(t, res.Violations)
	assert.NotContains(t, res.Message, "suppressed")
}

// TestEngine_RegistrySuppresses_FlipsDeny_MessageStatesSuppression covers
// the happy suppression path: registry says yes, every violation is waived,
// verdict flips to ALLOW with the new explicit message.
func TestEngine_RegistrySuppresses_FlipsDeny_MessageStatesSuppression(t *testing.T) {
	reg := &fakeRegistry{
		responder: func(key MatchKey) (bool, []ExceptionRef, error) {
			if key.PolicyID == "security-baseline" && key.RuleID == "no-privileged-containers" {
				return true, []ExceptionRef{{
					ID:       "e1",
					Name:     "team-a-allow-privileged",
					PolicyID: "security-baseline",
					RuleID:   "no-privileged-containers",
				}}, nil
			}
			return false, nil, nil
		},
	}
	engine, err := NewEngineWithExceptions(&config.PolicyConfig{FailureMode: "fail-closed"}, zap.NewNop(), reg)
	require.NoError(t, err)

	res, err := engine.Evaluate(context.Background(), newEvaluationRequest([]byte(privilegedPodJSON)))
	require.NoError(t, err)

	assert.True(t, res.Allowed)
	assert.Equal(t, "ALLOW", res.Decision)
	assert.Equal(t, "PolicyViolationSuppressedByException", res.Reason)
	assert.Contains(t, res.Message, "suppressed")
	require.Len(t, res.SuppressedBy, 1)
	assert.Equal(t, "e1", res.SuppressedBy[0].ID)
	assert.Empty(t, res.Violations)
}

// TestEngine_RegistryMismatch_DenyIntact verifies that a registry returning
// (false, nil, nil) leaves the original deny untouched.
func TestEngine_RegistryMismatch_DenyIntact(t *testing.T) {
	reg := &fakeRegistry{
		responder: func(_ MatchKey) (bool, []ExceptionRef, error) { return false, nil, nil },
	}
	engine, err := NewEngineWithExceptions(&config.PolicyConfig{FailureMode: "fail-closed"}, zap.NewNop(), reg)
	require.NoError(t, err)

	res, err := engine.Evaluate(context.Background(), newEvaluationRequest([]byte(privilegedPodJSON)))
	require.NoError(t, err)

	assert.False(t, res.Allowed)
	assert.Equal(t, "PolicyViolation", res.Reason)
	assert.Empty(t, res.SuppressedBy)
	assert.NotEmpty(t, res.Violations)
}

// TestEngine_RegistryError_FailClosed asserts the fail-closed contract:
// a registry error preserves the original deny.
func TestEngine_RegistryError_FailClosed(t *testing.T) {
	reg := &fakeRegistry{
		responder: func(_ MatchKey) (bool, []ExceptionRef, error) { return false, nil, errors.New("boom") },
	}
	engine, err := NewEngineWithExceptions(&config.PolicyConfig{FailureMode: "fail-closed"}, zap.NewNop(), reg)
	require.NoError(t, err)

	res, err := engine.Evaluate(context.Background(), newEvaluationRequest([]byte(privilegedPodJSON)))
	require.NoError(t, err)

	assert.False(t, res.Allowed, "registry error must preserve the original deny")
	assert.Equal(t, "PolicyViolation", res.Reason)
	assert.Len(t, res.Violations, 1)
	assert.Empty(t, res.SuppressedBy)
}

// TestEngine_PartialSuppression_DenyRemains exercises the partial-suppression
// path: one rule waived, others survive. Verdict stays DENY.
func TestEngine_PartialSuppression_DenyRemains(t *testing.T) {
	reg := &fakeRegistry{
		responder: func(key MatchKey) (bool, []ExceptionRef, error) {
			// Suppress only the privileged-containers rule; let hostPath and
			// required-security-context survive.
			if key.RuleID == "no-privileged-containers" {
				return true, []ExceptionRef{{ID: "e-priv", RuleID: key.RuleID, PolicyID: key.PolicyID}}, nil
			}
			return false, nil, nil
		},
	}
	engine, err := NewEngineWithExceptions(&config.PolicyConfig{FailureMode: "fail-closed"}, zap.NewNop(), reg)
	require.NoError(t, err)

	res, err := engine.Evaluate(context.Background(), newEvaluationRequest([]byte(triViolationPodJSON)))
	require.NoError(t, err)

	assert.False(t, res.Allowed)
	assert.Equal(t, "PolicyViolation", res.Reason)
	require.NotEmpty(t, res.Violations)
	for _, v := range res.Violations {
		assert.NotEqual(t, "no-privileged-containers", v.RuleID, "privileged rule should have been suppressed")
	}
	require.Len(t, res.SuppressedBy, 1)
	assert.Equal(t, "e-priv", res.SuppressedBy[0].ID)
}

// TestEngine_MatchKey_PopulatedFromAdmissionRequest checks the engine
// constructs MatchKey correctly: namespace, user, groups passed through,
// and the resource gets lowercased.
func TestEngine_MatchKey_PopulatedFromAdmissionRequest(t *testing.T) {
	reg := &fakeRegistry{
		responder: func(_ MatchKey) (bool, []ExceptionRef, error) { return false, nil, nil },
	}
	engine, err := NewEngineWithExceptions(&config.PolicyConfig{FailureMode: "fail-closed"}, zap.NewNop(), reg)
	require.NoError(t, err)

	_, err = engine.Evaluate(context.Background(), newEvaluationRequest([]byte(privilegedPodJSON)))
	require.NoError(t, err)

	calls := reg.recorded()
	require.NotEmpty(t, calls, "registry must be consulted on a denial")
	got := calls[0]
	assert.Equal(t, "team-a", got.Namespace)
	assert.Equal(t, "alice", got.User)
	assert.Equal(t, []string{"devs", "team-a"}, got.Groups)
	assert.Equal(t, "pods", got.Resource, "resource must be lowercased")
	assert.NotEmpty(t, got.PolicyID)
	assert.NotEmpty(t, got.RuleID)
	// Belt-and-braces: the resource is always all-lowercase regardless of
	// what kube-apiserver hands us.
	assert.Equal(t, strings.ToLower(got.Resource), got.Resource)
}

// TestEngine_MixedSuppressionAndError_DenyStands anchors the sawRegistryError
// guard: even when every non-erroring violation was cleanly suppressed, a
// single error on the pass holds the verdict at DENY.
func TestEngine_MixedSuppressionAndError_DenyStands(t *testing.T) {
	reg := &fakeRegistry{
		responder: func(key MatchKey) (bool, []ExceptionRef, error) {
			switch key.RuleID {
			case "no-privileged-containers":
				return true, []ExceptionRef{{ID: "e-priv", RuleID: key.RuleID, PolicyID: key.PolicyID}}, nil
			case "no-host-path-volumes":
				return true, []ExceptionRef{{ID: "e-host", RuleID: key.RuleID, PolicyID: key.PolicyID}}, nil
			case "required-security-context":
				return false, nil, errors.New("registry transient error")
			}
			return false, nil, nil
		},
	}
	engine, err := NewEngineWithExceptions(&config.PolicyConfig{FailureMode: "fail-closed"}, zap.NewNop(), reg)
	require.NoError(t, err)

	res, err := engine.Evaluate(context.Background(), newEvaluationRequest([]byte(triViolationPodJSON)))
	require.NoError(t, err)

	assert.False(t, res.Allowed, "any registry error must hold the verdict at DENY")
	assert.Equal(t, "PolicyViolation", res.Reason)
	require.Len(t, res.SuppressedBy, 2)
	require.Len(t, res.Violations, 1, "only the erroring violation survives")
	assert.Equal(t, "required-security-context", res.Violations[0].RuleID)
}

// TestEngine_DistinctExceptionCount is a table-driven check on the
// distinct-ID helper used to render the suppression message.
func TestEngine_DistinctExceptionCount(t *testing.T) {
	cases := []struct {
		name string
		in   []ExceptionRef
		want int
	}{
		{"empty", nil, 0},
		{"single", []ExceptionRef{{ID: "a"}}, 1},
		{"duplicate IDs collapse", []ExceptionRef{{ID: "a"}, {ID: "a"}}, 1},
		{"three distinct", []ExceptionRef{{ID: "a"}, {ID: "b"}, {ID: "c"}}, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, distinctExceptionCount(tc.in))
		})
	}
}
