package policy

import (
	"context"
	"fmt"
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

// podWithImage renders a minimal, otherwise-compliant Pod whose single
// container uses the given image. Used to isolate the image-provenance rules.
func podWithImage(image string) []byte {
	return []byte(fmt.Sprintf(`{
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "p", "namespace": "default"},
		"spec": {
			"containers": [{
				"name": "c",
				"image": %q,
				"securityContext": {"runAsNonRoot": true, "allowPrivilegeEscalation": false}
			}]
		}
	}`, image))
}

func evalImage(t *testing.T, eng *Engine, image string) *EvaluationResult {
	t.Helper()
	res, err := eng.Evaluate(context.Background(), &EvaluationRequest{
		AdmissionRequest: &admissionv1.AdmissionRequest{
			UID:       types.UID("img-prov-" + image),
			Kind:      metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: podWithImage(image)},
		},
		Operation: "test",
	})
	require.NoError(t, err)
	return res
}

func firedRules(res *EvaluationResult) map[string]bool {
	m := make(map[string]bool, len(res.Violations))
	for _, v := range res.Violations {
		m[v.RuleID] = true
	}
	return m
}

// TestImageProvenance_DisabledByDefault proves the bundled policy is strictly
// opt-in: a fully untrusted image (bad registry, no digest) is ADMITTED by the
// default engine because image-provenance ships Enabled:false (SUP-WU-07). This
// guarantees the new rule cannot silently break existing deployments.
func TestImageProvenance_DisabledByDefault(t *testing.T) {
	eng, err := NewEngine(&config.PolicyConfig{FailureMode: "fail-closed"}, zap.NewNop())
	require.NoError(t, err)

	// Sanity: the policy is registered but disabled.
	p, ok := eng.policies["image-provenance"]
	require.True(t, ok, "image-provenance policy must be bundled")
	assert.False(t, p.Enabled, "image-provenance must be disabled by default (opt-in)")

	res := evalImage(t, eng, "docker.io/library/nginx:1.25")
	assert.True(t, res.Allowed,
		"disabled image-provenance must not deny; violations=%+v", res.Violations)
	assert.False(t, firedRules(res)["allowed-registries"])
	assert.False(t, firedRules(res)["require-image-digest"])
}

// TestImageProvenance_EnforcesRegistryAndDigest exercises the two rules in
// isolation (via NewEvaluatorForPolicy with the policy ENABLED) and asserts the
// deny/allow matrix required by SUP-WU-07's "Done when".
func TestImageProvenance_EnforcesRegistryAndDigest(t *testing.T) {
	p := imageProvenancePolicy()
	p.Enabled = true
	eng, err := NewEvaluatorForPolicy(p, &config.PolicyConfig{FailureMode: "fail-closed"}, zap.NewNop())
	require.NoError(t, err)

	const goodDigest = "sha256:0123456789012345678901234567890123456789012345678901234567890123"

	cases := []struct {
		name        string
		image       string
		wantAllowed bool
		wantRule    string // rule expected to fire when denied
	}{
		{
			name:        "trusted registry + digest is admitted",
			image:       "ghcr.io/jibbscript/kube-policies/admission-webhook@" + goodDigest,
			wantAllowed: true,
		},
		{
			// GHCR paths are case-insensitive; the as-published mixed-case ref
			// (capital J) must still be admitted against the lowercase allowlist.
			name:        "trusted registry with mixed-case is admitted",
			image:       "ghcr.io/Jibbscript/kube-policies/admission-webhook@" + goodDigest,
			wantAllowed: true,
		},
		{
			name:        "untrusted registry is denied",
			image:       "docker.io/library/nginx@" + goodDigest,
			wantAllowed: false,
			wantRule:    "allowed-registries",
		},
		{
			name:        "trusted registry without digest is denied",
			image:       "ghcr.io/jibbscript/kube-policies/admission-webhook:1.0.0",
			wantAllowed: false,
			wantRule:    "require-image-digest",
		},
		{
			name:        "untrusted registry without digest is denied",
			image:       "evil.example.com/malware:latest",
			wantAllowed: false,
			wantRule:    "allowed-registries",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := evalImage(t, eng, tc.image)
			assert.Equal(t, tc.wantAllowed, res.Allowed,
				"verdict mismatch for %q; violations=%+v", tc.image, res.Violations)
			if !tc.wantAllowed {
				assert.True(t, firedRules(res)[tc.wantRule],
					"expected rule %q to fire for %q; fired=%v", tc.wantRule, tc.image, firedRules(res))
			} else {
				assert.Empty(t, res.Violations, "admitted image must have zero violations")
			}
		})
	}
}
