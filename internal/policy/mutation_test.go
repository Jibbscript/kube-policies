package policy

import (
	"context"
	"encoding/json"
	"testing"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/Jibbscript/kube-policies/internal/config"
)

// TestMutatingHardening_PatchesAreValidAndPass is the POL-WU-22 proof:
//   - an unhardened Pod produces JSONPatches (incl. a seccomp RuntimeDefault),
//   - the patches decode + apply cleanly as RFC6902, and
//   - the mutated object then passes the PSS-Restricted and PSS-Baseline deny
//     rules that would have rejected the original.
func TestMutatingHardening_PatchesAreValidAndPass(t *testing.T) {
	mp := mutatingHardeningPolicy()
	mp.Enabled = true
	mutEng, err := NewEvaluatorForPolicy(mp, &config.PolicyConfig{FailureMode: "fail-open"}, zap.NewNop())
	require.NoError(t, err)

	original := []byte(`{
		"apiVersion":"v1","kind":"Pod",
		"metadata":{"name":"p","namespace":"app"},
		"spec":{"containers":[{"name":"c","image":"nginx:1.25.3"}]}
	}`)

	res, err := mutEng.Evaluate(context.Background(), &EvaluationRequest{
		AdmissionRequest: &admissionv1.AdmissionRequest{
			UID:       types.UID("mut-1"),
			Kind:      metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: original},
		},
		Operation: "mutate",
	})
	require.NoError(t, err)
	require.True(t, res.Allowed, "mutation rule must never deny")
	require.NotEmpty(t, res.Patches, "expected hardening patches for an unhardened pod")

	// A seccomp RuntimeDefault patch must be present.
	var sawSeccomp bool
	for _, p := range res.Patches {
		if p.Path == "/spec/securityContext" || p.Path == "/spec/securityContext/seccompProfile" {
			sawSeccomp = true
		}
	}
	assert.True(t, sawSeccomp, "expected a seccomp default patch; patches=%+v", res.Patches)

	// Patches must be valid RFC6902 and apply cleanly.
	patchBytes, err := json.Marshal(res.Patches)
	require.NoError(t, err)
	patch, err := jsonpatch.DecodePatch(patchBytes)
	require.NoError(t, err, "engine patches must decode as RFC6902")
	mutated, err := patch.Apply(original)
	require.NoError(t, err, "engine patches must apply cleanly to the source object")

	// The mutated object must now pass the deny rules that rejected the original.
	for _, ctor := range []func() *Policy{pssRestrictedPolicy, pssBaselinePolicy} {
		p := ctor()
		res := evalScoped(t, p, "", "v1", "Pod", string(mutated))
		assert.Truef(t, res.Allowed,
			"mutated pod must pass %s; violations=%+v", p.ID, res.Violations)
	}

	// Sanity: the ORIGINAL pod is rejected by pss-restricted (proving the
	// mutation actually changed the verdict).
	before := evalScoped(t, pssRestrictedPolicy(), "", "v1", "Pod", string(original))
	assert.False(t, before.Allowed, "unhardened pod should fail pss-restricted before mutation")
}

// TestMutatingHardening_RespectsExplicitSettings proves the mutation defaults
// only MISSING fields and never clobbers an explicit operator choice.
func TestMutatingHardening_RespectsExplicitSettings(t *testing.T) {
	mp := mutatingHardeningPolicy()
	mp.Enabled = true
	mutEng, err := NewEvaluatorForPolicy(mp, &config.PolicyConfig{FailureMode: "fail-open"}, zap.NewNop())
	require.NoError(t, err)

	// Pod already fully hardened + automount false + seccomp set → no patches.
	original := []byte(`{
		"apiVersion":"v1","kind":"Pod",
		"metadata":{"name":"p","namespace":"app"},
		"spec":{
			"securityContext":{"seccompProfile":{"type":"RuntimeDefault"}},
			"automountServiceAccountToken":false,
			"containers":[{"name":"c","image":"nginx:1.25.3","securityContext":{
				"allowPrivilegeEscalation":false,"runAsNonRoot":true,
				"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}
			}}]
		}
	}`)

	res, err := mutEng.Evaluate(context.Background(), &EvaluationRequest{
		AdmissionRequest: &admissionv1.AdmissionRequest{
			UID:       types.UID("mut-2"),
			Kind:      metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: original},
		},
		Operation: "mutate",
	})
	require.NoError(t, err)
	assert.True(t, res.Allowed)
	assert.Empty(t, res.Patches, "already-hardened pod must receive no patches")
}
