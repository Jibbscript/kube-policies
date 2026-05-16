package policy

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
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

// fixtureDir resolves the JSON fixture directory shared with the Svelte SPA.
// Tests use these to keep the playground UI and the engine in lockstep on
// what each sample should produce.
func fixtureDir(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "web", "src", "fixtures")
}

// readFixture returns the raw bytes of a fixture file, or signals to skip
// the test if the file does not exist (e.g. T3's web/ scaffold hasn't landed yet).
func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join(fixtureDir(t), name)
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			t.Skipf("fixture not present at %s; expected from T3 web/", path)
		}
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return b
}

// TestBundledDefaults_FixtureVerdicts (acceptance #11): boots the real engine
// and asserts each of the 4 Playground fixtures resolves to the expected
// verdict against the bundled default rules.
func TestBundledDefaults_FixtureVerdicts(t *testing.T) {
	engine, err := NewEngine(&config.PolicyConfig{FailureMode: "fail-closed"}, zap.NewNop())
	require.NoError(t, err)

	cases := []struct {
		fixture     string
		wantAllowed bool
		wantRuleID  string // expected rule ID in violations (empty for compliant)
	}{
		{"sample-pod-privileged.json", false, "no-privileged-containers"},
		{"sample-pod-hostpath.json", false, "no-host-path-volumes"},
		{"sample-pod-latest-tag.json", false, "no-latest-image-tag"},
		{"sample-pod-compliant.json", true, ""},
	}

	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			raw := readFixture(t, tc.fixture)

			// Validate fixture is parseable JSON before sending to OPA.
			var obj map[string]any
			require.NoError(t, json.Unmarshal(raw, &obj), "fixture %s is not valid JSON", tc.fixture)

			res, err := engine.Evaluate(context.Background(), &EvaluationRequest{
				AdmissionRequest: &admissionv1.AdmissionRequest{
					UID:       types.UID("bundled-" + tc.fixture),
					Kind:      metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
					Operation: admissionv1.Create,
					Object:    runtime.RawExtension{Raw: raw},
				},
				Operation: "test",
			})
			require.NoError(t, err)
			assert.Equal(t, tc.wantAllowed, res.Allowed,
				"verdict mismatch for %s; violations=%+v", tc.fixture, res.Violations)

			if tc.wantAllowed {
				assert.Empty(t, res.Violations,
					"compliant fixture %s should have zero violations", tc.fixture)
				return
			}

			fired := make(map[string]bool, len(res.Violations))
			for _, v := range res.Violations {
				fired[v.RuleID] = true
			}
			assert.True(t, fired[tc.wantRuleID],
				"expected rule %q to fire for %s; fired=%v", tc.wantRuleID, tc.fixture, fired)
		})
	}
}

// TestNewEvaluatorForPolicy_ScopesToSinglePolicy verifies that
// NewEvaluatorForPolicy does NOT load the bundled defaults: a policy
// containing a rule that never fires must accept a payload that the
// bundled `no-privileged-containers` rule would otherwise reject.
func TestNewEvaluatorForPolicy_ScopesToSinglePolicy(t *testing.T) {
	// Custom policy: a rule whose evaluate block always returns allowed=true.
	// If bundled defaults bled in, the privileged pod would still be denied.
	neverFiresPolicy := &Policy{
		ID:      "scope-test",
		Name:    "scope test",
		Enabled: true,
		Rules: []Rule{
			{
				ID:   "never-fires",
				Name: "never fires",
				Rego: `
package kube_policies

evaluate = result {
	result := {"allowed": true}
}
`,
			},
		},
	}

	engine, err := NewEvaluatorForPolicy(neverFiresPolicy, &config.PolicyConfig{}, zap.NewNop())
	require.NoError(t, err)

	// Privileged pod — would be denied by bundled no-privileged-containers
	// if loadDefaultPolicies had been called.
	privilegedPod := []byte(`{
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "p", "namespace": "default"},
		"spec": {
			"securityContext": {"privileged": true},
			"containers": [{"name": "c", "image": "nginx:1.25"}]
		}
	}`)

	res, err := engine.Evaluate(context.Background(), &EvaluationRequest{
		AdmissionRequest: &admissionv1.AdmissionRequest{
			UID:       "scope-test-1",
			Kind:      metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: privilegedPod},
		},
		Operation: "test",
	})
	require.NoError(t, err)
	assert.True(t, res.Allowed,
		"NewEvaluatorForPolicy must not load bundled defaults; got violations=%+v", res.Violations)
	assert.Empty(t, res.Violations,
		"scoped evaluator should produce zero violations against a never-fires rule")
}
