package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// evalObjectOp is evalObject with an explicit admission operation and optional
// oldObject, for exercising UPDATE flows (POL-WU-30).
func evalObjectOp(t *testing.T, eng *Engine, group, version, kind string, op admissionv1.Operation, obj, oldObj []byte) *EvaluationResult {
	t.Helper()
	req := &admissionv1.AdmissionRequest{
		UID:       types.UID("upd-" + kind),
		Kind:      metav1.GroupVersionKind{Group: group, Version: version, Kind: kind},
		Operation: op,
		Object:    runtime.RawExtension{Raw: obj},
	}
	if oldObj != nil {
		req.OldObject = runtime.RawExtension{Raw: oldObj}
	}
	res, err := eng.Evaluate(context.Background(), &EvaluationRequest{
		AdmissionRequest: req,
		Operation:        "validate",
	})
	require.NoError(t, err)
	return res
}

// TestUpdateOperation_DeniesNonCompliantChange proves rules evaluate UPDATE the
// same as CREATE: introducing a privileged container via an UPDATE to an
// existing Deployment is denied (POL-WU-30).
func TestUpdateOperation_DeniesNonCompliantChange(t *testing.T) {
	eng := newDefaultEngine(t)

	oldObj := []byte(`{
		"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"d","namespace":"app"},
		"spec":{"template":{"spec":{"containers":[
			{"name":"c","image":"nginx:1.25.3","securityContext":{"runAsNonRoot":true,"allowPrivilegeEscalation":false}}
		]}}}
	}`)
	newObj := []byte(`{
		"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"d","namespace":"app"},
		"spec":{"template":{"spec":{"containers":[
			{"name":"c","image":"nginx:1.25.3","securityContext":{"privileged":true,"runAsNonRoot":true,"allowPrivilegeEscalation":false}}
		]}}}
	}`)

	res := evalObjectOp(t, eng, "apps", "v1", "Deployment", admissionv1.Update, newObj, oldObj)
	assert.False(t, res.Allowed, "privileged change via UPDATE must be denied; violations=%+v", res.Violations)
	assert.True(t, firedRuleIDs(res)["no-privileged-containers"])
}

// TestUpdateOperation_DeploymentReplicaSetPodChain proves a compliant workload
// is admitted at every link of the Deployment->ReplicaSet->Pod chain and never
// falsely denied (POL-WU-30).
func TestUpdateOperation_DeploymentReplicaSetPodChain(t *testing.T) {
	eng := newDefaultEngine(t)

	compliantTemplate := `{"spec":{"containers":[{"name":"c","image":"nginx:1.25.3","securityContext":{"runAsNonRoot":true,"allowPrivilegeEscalation":false}}]}}`

	deployment := []byte(`{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"d","namespace":"app"},"spec":{"template":` + compliantTemplate + `}}`)
	replicaSet := []byte(`{"apiVersion":"apps/v1","kind":"ReplicaSet","metadata":{"name":"d-abc123","namespace":"app","labels":{"pod-template-hash":"abc123"}},"spec":{"template":` + compliantTemplate + `}}`)
	pod := []byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"d-abc123-xyz","namespace":"app","labels":{"pod-template-hash":"abc123"}},"spec":{"containers":[{"name":"c","image":"nginx:1.25.3","securityContext":{"runAsNonRoot":true,"allowPrivilegeEscalation":false}}]}}`)

	for _, tc := range []struct {
		kind  string
		group string
		raw   []byte
	}{
		{"Deployment", "apps", deployment},
		{"ReplicaSet", "apps", replicaSet},
		{"Pod", "", pod},
	} {
		// Both CREATE and UPDATE must admit the compliant object.
		for _, op := range []admissionv1.Operation{admissionv1.Create, admissionv1.Update} {
			res := evalObjectOp(t, eng, tc.group, "v1", tc.kind, op, tc.raw, nil)
			assert.Truef(t, res.Allowed,
				"compliant %s (%s) must be admitted; violations=%+v", tc.kind, op, res.Violations)
		}
	}
}
