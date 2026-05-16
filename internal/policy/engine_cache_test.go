package policy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/Jibbscript/kube-policies/internal/config"
)

// preparedQueryCount returns how many entries are currently cached.
// Test-only helper.
func (e *Engine) preparedQueryCount() int {
	count := 0
	e.preparedQueries.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}

func mustNewBenchEngine(t testing.TB) *Engine {
	t.Helper()
	engine, err := NewEngine(&config.PolicyConfig{FailureMode: "fail-closed"}, zap.NewNop())
	require.NoError(t, err)
	return engine
}

func nonPrivilegedPodReq(t testing.TB) *EvaluationRequest {
	t.Helper()
	pod, err := json.Marshal(map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "p", "namespace": "default"},
		"spec":       map[string]any{"securityContext": map[string]any{"privileged": false}},
	})
	require.NoError(t, err)
	return &EvaluationRequest{
		AdmissionRequest: &admissionv1.AdmissionRequest{
			UID:       types.UID("bench-1"),
			Kind:      metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: pod},
		},
		Operation: "validate",
	}
}

// TestEngine_PreparedQueryCachedOnce verifies that repeated evaluation of the same
// rules does not recompile the Rego queries. The default security-baseline policy
// has 4 rules (no-privileged-containers, no-host-path-volumes, no-latest-image-tag,
// required-security-context), so after N evaluations the cache must hold exactly
// 4 entries — one per rule, not one per evaluation.
func TestEngine_PreparedQueryCachedOnce(t *testing.T) {
	engine := mustNewBenchEngine(t)
	req := nonPrivilegedPodReq(t)

	const evals = 25
	const expectedRules = 4
	for i := 0; i < evals; i++ {
		_, err := engine.Evaluate(context.Background(), req)
		require.NoError(t, err)
	}

	assert.Equal(t, expectedRules, engine.preparedQueryCount(),
		"expected exactly %d cached prepared queries (one per default rule) after %d evaluations, got %d",
		expectedRules, evals, engine.preparedQueryCount())
}

// TestEngine_LoadPolicy_EvictsCache verifies that re-loading a policy invalidates
// any cached prepared queries, so updated rule bodies actually take effect.
func TestEngine_LoadPolicy_EvictsCache(t *testing.T) {
	engine := mustNewBenchEngine(t)
	req := nonPrivilegedPodReq(t)

	_, err := engine.Evaluate(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, 4, engine.preparedQueryCount(),
		"default security-baseline policy has 4 rules; expected 4 cached queries after one evaluation")

	// Re-load the same policy ID with a different rule body.
	require.NoError(t, engine.LoadPolicy(&Policy{
		ID: "security-baseline", Name: "Security Baseline", Enabled: true,
		Rules: []Rule{{
			ID: "no-privileged-containers", Name: "No Privileged Containers",
			Rego: `package kube_policies
evaluate = result {
	result := {"allowed": true}
}
`,
		}},
	}))

	assert.Equal(t, 0, engine.preparedQueryCount(),
		"LoadPolicy must evict cached queries for the policy")
}

func BenchmarkEngine_EvaluateCacheHit(b *testing.B) {
	engine := mustNewBenchEngine(b)
	req := nonPrivilegedPodReq(b)

	// Warm the cache once before timing.
	if _, err := engine.Evaluate(context.Background(), req); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := engine.Evaluate(context.Background(), req); err != nil {
			b.Fatal(err)
		}
	}
}
