// Package v1 contains API Schema definitions for the policies.kube-policies.io
// v1 API group. The Go types here are the typed counterparts of the YAML CRDs
// under deployments/kubernetes/crds/ and are registered with controller-runtime
// schemes so reconcilers can `Get`/`List`/`Watch` Policy and PolicyException
// objects without falling back to unstructured.Unstructured.
//
// DeepCopy methods (zz_generated_deepcopy.go) are hand-written rather than
// generated via controller-gen — the repo intentionally does not run k8s
// codegen in CI, so the methods live next to the types they cover. When you
// add or remove fields, update zz_generated_deepcopy.go in the same change.
package v1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// GroupVersion is the canonical group/version pair for the policies.kube-policies.io API.
// The string values match the apiVersion declared in deployments/kubernetes/crds/policies.yaml,
// so any mismatch here would cause the apiserver to reject Get/Create on registered objects.
var GroupVersion = schema.GroupVersion{Group: "policies.kube-policies.io", Version: "v1"}

// SchemeBuilder collects the registration of every Go type defined in this package.
// Reconcilers call AddToScheme during ctrl.Manager wiring so the controller knows
// how to (de)serialize Policy / PolicyException between Go and the apiserver wire format.
var SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

// AddToScheme adds the API types defined here to the supplied runtime.Scheme.
// cmd/policy-manager/main.go and the integration test suite both call this on
// the manager scheme before starting controllers.
var AddToScheme = SchemeBuilder.AddToScheme

func init() {
	SchemeBuilder.Register(&Policy{}, &PolicyList{}, &PolicyException{}, &PolicyExceptionList{})
}
