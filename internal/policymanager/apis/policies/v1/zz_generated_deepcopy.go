// Hand-written DeepCopy methods for the policies.kube-policies.io v1 types.
// The file name follows controller-gen's `zz_generated_*` convention so future
// codegen runs (if introduced) replace the file cleanly rather than colliding
// with hand-written code under a different name.
//
// Keep methods in lockstep with types.go: every new pointer/slice/map field
// needs an explicit copy here, or the controller cache will hand out shared
// references and reconcile loops will mutate each other.

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto copies receiver into out. Pointer/slice/map fields are
// deep-copied; scalar fields are copied by assignment via `*out = *in`.
func (in *Policy) DeepCopyInto(out *Policy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy returns a deep copy of the receiver.
func (in *Policy) DeepCopy() *Policy {
	if in == nil {
		return nil
	}
	out := new(Policy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject satisfies runtime.Object so the type can be registered with
// the controller-runtime scheme.
func (in *Policy) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

func (in *PolicyList) DeepCopyInto(out *PolicyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]Policy, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

func (in *PolicyList) DeepCopy() *PolicyList {
	if in == nil {
		return nil
	}
	out := new(PolicyList)
	in.DeepCopyInto(out)
	return out
}

func (in *PolicyList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

func (in *PolicySpec) DeepCopyInto(out *PolicySpec) {
	*out = *in
	if in.Enabled != nil {
		out.Enabled = new(bool)
		*out.Enabled = *in.Enabled
	}
	if in.Frameworks != nil {
		out.Frameworks = append([]string(nil), in.Frameworks...)
	}
	if in.Rules != nil {
		out.Rules = make([]PolicyRule, len(in.Rules))
		for i := range in.Rules {
			in.Rules[i].DeepCopyInto(&out.Rules[i])
		}
	}
	if in.Targets != nil {
		out.Targets = new(Targets)
		in.Targets.DeepCopyInto(out.Targets)
	}
	if in.Metadata != nil {
		out.Metadata = make(map[string]string, len(in.Metadata))
		for k, v := range in.Metadata {
			out.Metadata[k] = v
		}
	}
}

func (in *PolicyRule) DeepCopyInto(out *PolicyRule) {
	*out = *in
	if in.Frameworks != nil {
		out.Frameworks = append([]string(nil), in.Frameworks...)
	}
	if in.Metadata != nil {
		out.Metadata = make(map[string]string, len(in.Metadata))
		for k, v := range in.Metadata {
			out.Metadata[k] = v
		}
	}
}

func (in *Targets) DeepCopyInto(out *Targets) {
	*out = *in
	if in.Kinds != nil {
		out.Kinds = make([]TargetKind, len(in.Kinds))
		copy(out.Kinds, in.Kinds)
	}
	if in.Namespaces != nil {
		out.Namespaces = append([]string(nil), in.Namespaces...)
	}
	if in.ExcludeNamespaces != nil {
		out.ExcludeNamespaces = append([]string(nil), in.ExcludeNamespaces...)
	}
}

func (in *PolicyStatus) DeepCopyInto(out *PolicyStatus) {
	*out = *in
	if in.Conditions != nil {
		out.Conditions = make([]metav1.Condition, len(in.Conditions))
		for i := range in.Conditions {
			in.Conditions[i].DeepCopyInto(&out.Conditions[i])
		}
	}
	if in.LastEvaluated != nil {
		out.LastEvaluated = in.LastEvaluated.DeepCopy()
	}
}

func (in *PolicyException) DeepCopyInto(out *PolicyException) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

func (in *PolicyException) DeepCopy() *PolicyException {
	if in == nil {
		return nil
	}
	out := new(PolicyException)
	in.DeepCopyInto(out)
	return out
}

func (in *PolicyException) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

func (in *PolicyExceptionList) DeepCopyInto(out *PolicyExceptionList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]PolicyException, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

func (in *PolicyExceptionList) DeepCopy() *PolicyExceptionList {
	if in == nil {
		return nil
	}
	out := new(PolicyExceptionList)
	in.DeepCopyInto(out)
	return out
}

func (in *PolicyExceptionList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

func (in *PolicyExceptionSpec) DeepCopyInto(out *PolicyExceptionSpec) {
	*out = *in
	if in.ExpiresAt != nil {
		out.ExpiresAt = in.ExpiresAt.DeepCopy()
	}
	in.Scope.DeepCopyInto(&out.Scope)
}

func (in *PolicyExceptionScope) DeepCopyInto(out *PolicyExceptionScope) {
	*out = *in
	if in.Namespaces != nil {
		out.Namespaces = append([]string(nil), in.Namespaces...)
	}
	if in.Resources != nil {
		out.Resources = append([]string(nil), in.Resources...)
	}
	if in.Users != nil {
		out.Users = append([]string(nil), in.Users...)
	}
	if in.Groups != nil {
		out.Groups = append([]string(nil), in.Groups...)
	}
}

func (in *PolicyExceptionStatus) DeepCopyInto(out *PolicyExceptionStatus) {
	*out = *in
	if in.Conditions != nil {
		out.Conditions = make([]metav1.Condition, len(in.Conditions))
		for i := range in.Conditions {
			in.Conditions[i].DeepCopyInto(&out.Conditions[i])
		}
	}
}
