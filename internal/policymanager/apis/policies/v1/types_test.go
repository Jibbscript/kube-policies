package v1

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"
)

// newTime returns a metav1.Time anchored at a whole second so JSON round-trips
// (which truncate sub-second precision) compare equal to the original.
func newTime(sec int64) metav1.Time {
	return metav1.NewTime(time.Unix(sec, 0).UTC())
}

// fullyPopulatedPolicy returns a Policy with every field set so that DeepCopy
// and serialization tests exercise every code path.
func fullyPopulatedPolicy() Policy {
	enabled := true
	lastEval := newTime(1700000000)
	return Policy{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Policy",
			APIVersion: "policies.kube-policies.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
			Labels:    map[string]string{"env": "test"},
		},
		Spec: PolicySpec{
			Description: "A test policy",
			Enabled:     &enabled,
			Severity:    "HIGH",
			Category:    "security",
			Frameworks:  []string{"CIS", "NIST"},
			Rules: []PolicyRule{
				{
					Name:        "rule-1",
					Description: "first rule",
					Severity:    "HIGH",
					Category:    "network",
					Frameworks:  []string{"CIS"},
					Rego:        `package test\ndefault allow = false`,
					Metadata:    map[string]string{"author": "test"},
				},
				{
					Name:     "rule-2",
					Rego:     `package test2\ndefault allow = true`,
					Metadata: map[string]string{"tag": "val"},
				},
			},
			Targets: &Targets{
				Kinds:             []TargetKind{{APIVersion: "v1", Kind: "Pod"}},
				Namespaces:        []string{"default", "kube-system"},
				ExcludeNamespaces: []string{"kube-public"},
			},
			Metadata: map[string]string{"owner": "team-a", "tier": "core"},
		},
		Status: PolicyStatus{
			Phase:          "Active",
			ViolationCount: 3,
			LastEvaluated:  &lastEval,
			Conditions: []metav1.Condition{
				{
					Type:               "Ready",
					Status:             metav1.ConditionTrue,
					Reason:             "PolicyLoaded",
					Message:            "policy loaded successfully",
					LastTransitionTime: newTime(1700000001),
				},
			},
		},
	}
}

// fullyPopulatedException returns a PolicyException with every field set.
func fullyPopulatedException() PolicyException {
	expiresAt := newTime(1800000000)
	return PolicyException{
		TypeMeta: metav1.TypeMeta{
			Kind:       "PolicyException",
			APIVersion: "policies.kube-policies.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-exception",
			Namespace: "default",
			Labels:    map[string]string{"managed-by": "ops"},
		},
		Spec: PolicyExceptionSpec{
			Description:   "allow legacy workload",
			PolicyID:      "policy-abc",
			RuleID:        "rule-1",
			Justification: "grandfathered workload pending migration",
			Approver:      "security-team",
			ExpiresAt:     &expiresAt,
			Scope: PolicyExceptionScope{
				Namespaces: []string{"legacy"},
				Resources:  []string{"deploy/old-app"},
				Users:      []string{"svc-account"},
				Groups:     []string{"ops-group"},
			},
		},
		Status: PolicyExceptionStatus{
			Phase:              "Approved",
			ObservedGeneration: 5,
			Conditions: []metav1.Condition{
				{
					Type:               "Approved",
					Status:             metav1.ConditionTrue,
					Reason:             "ManualApproval",
					Message:            "approved by security-team",
					LastTransitionTime: newTime(1700000002),
				},
			},
		},
	}
}

// ---- DeepCopy round-trip -----------------------------------------------

func TestPolicyDeepCopy_RoundTrip(t *testing.T) {
	orig := fullyPopulatedPolicy()
	cp := orig.DeepCopy()

	if !reflect.DeepEqual(orig, *cp) {
		t.Fatalf("DeepCopy: copy does not equal original")
	}
}

func TestPolicyDeepCopy_Independence(t *testing.T) {
	orig := fullyPopulatedPolicy()
	cp := orig.DeepCopy()

	// Mutate slices/maps/pointers in the copy — original must be unaffected.
	cp.Spec.Frameworks[0] = "MUTATED"
	if orig.Spec.Frameworks[0] == "MUTATED" {
		t.Error("Spec.Frameworks: copy shares backing array with original")
	}

	cp.Spec.Rules[0].Frameworks[0] = "MUTATED"
	if orig.Spec.Rules[0].Frameworks[0] == "MUTATED" {
		t.Error("Spec.Rules[0].Frameworks: copy shares backing array with original")
	}

	cp.Spec.Rules[0].Metadata["author"] = "MUTATED"
	if orig.Spec.Rules[0].Metadata["author"] == "MUTATED" {
		t.Error("Spec.Rules[0].Metadata: copy shares map with original")
	}

	cp.Spec.Metadata["owner"] = "MUTATED"
	if orig.Spec.Metadata["owner"] == "MUTATED" {
		t.Error("Spec.Metadata: copy shares map with original")
	}

	cp.Spec.Targets.Namespaces[0] = "MUTATED"
	if orig.Spec.Targets.Namespaces[0] == "MUTATED" {
		t.Error("Spec.Targets.Namespaces: copy shares backing array with original")
	}

	newBool := false
	cp.Spec.Enabled = &newBool
	if *orig.Spec.Enabled == false {
		t.Error("Spec.Enabled: copy pointer aliases original")
	}

	cp.Status.Conditions[0].Message = "MUTATED"
	if orig.Status.Conditions[0].Message == "MUTATED" {
		t.Error("Status.Conditions: copy shares slice with original")
	}
}

func TestPolicyExceptionDeepCopy_RoundTrip(t *testing.T) {
	orig := fullyPopulatedException()
	cp := orig.DeepCopy()

	if !reflect.DeepEqual(orig, *cp) {
		t.Fatalf("PolicyException DeepCopy: copy does not equal original")
	}
}

func TestPolicyExceptionDeepCopy_Independence(t *testing.T) {
	orig := fullyPopulatedException()
	cp := orig.DeepCopy()

	cp.Spec.Scope.Namespaces[0] = "MUTATED"
	if orig.Spec.Scope.Namespaces[0] == "MUTATED" {
		t.Error("Spec.Scope.Namespaces: copy shares backing array with original")
	}

	cp.Spec.Scope.Resources[0] = "MUTATED"
	if orig.Spec.Scope.Resources[0] == "MUTATED" {
		t.Error("Spec.Scope.Resources: copy shares backing array with original")
	}

	cp.Spec.Scope.Users[0] = "MUTATED"
	if orig.Spec.Scope.Users[0] == "MUTATED" {
		t.Error("Spec.Scope.Users: copy shares backing array with original")
	}

	cp.Spec.Scope.Groups[0] = "MUTATED"
	if orig.Spec.Scope.Groups[0] == "MUTATED" {
		t.Error("Spec.Scope.Groups: copy shares backing array with original")
	}

	cp.Status.Conditions[0].Reason = "MUTATED"
	if orig.Status.Conditions[0].Reason == "MUTATED" {
		t.Error("Status.Conditions: copy shares slice with original")
	}
}

// ---- DeepCopyObject ----------------------------------------------------

func TestDeepCopyObject(t *testing.T) {
	tests := []struct {
		name string
		obj  runtime.Object
	}{
		{"Policy", func() runtime.Object { p := fullyPopulatedPolicy(); return &p }()},
		{
			"PolicyList",
			func() runtime.Object {
				p := fullyPopulatedPolicy()
				return &PolicyList{
					TypeMeta: metav1.TypeMeta{Kind: "PolicyList", APIVersion: "policies.kube-policies.io/v1"},
					Items:    []Policy{p},
				}
			}(),
		},
		{"PolicyException", func() runtime.Object { e := fullyPopulatedException(); return &e }()},
		{
			"PolicyExceptionList",
			func() runtime.Object {
				e := fullyPopulatedException()
				return &PolicyExceptionList{
					TypeMeta: metav1.TypeMeta{Kind: "PolicyExceptionList", APIVersion: "policies.kube-policies.io/v1"},
					Items:    []PolicyException{e},
				}
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cp := tc.obj.DeepCopyObject()
			if cp == nil {
				t.Fatal("DeepCopyObject returned nil")
			}
			if !reflect.DeepEqual(tc.obj, cp) {
				t.Fatalf("DeepCopyObject result does not equal original")
			}
			if tc.obj == cp {
				t.Fatal("DeepCopyObject returned the same pointer (not a copy)")
			}
		})
	}
}

// normMetav1Time returns a copy of t with the underlying time normalized to UTC.
// JSON round-trips preserve the instant but may produce a different *Location
// pointer (e.g. a fixed zone vs time.UTC) depending on the Go runtime version
// and local timezone; normalizing both sides to UTC makes DeepEqual reliable.
func normMetav1Time(t metav1.Time) metav1.Time {
	return metav1.NewTime(t.UTC())
}

// normConditions returns a copy of the conditions slice with every
// LastTransitionTime normalized to UTC.
func normConditions(cs []metav1.Condition) []metav1.Condition {
	out := make([]metav1.Condition, len(cs))
	for i, c := range cs {
		c.LastTransitionTime = normMetav1Time(c.LastTransitionTime)
		out[i] = c
	}
	return out
}

// normPolicy normalizes all time fields in p to UTC so reflect.DeepEqual works
// after a JSON/YAML round-trip.
func normPolicy(p *Policy) {
	p.Status.Conditions = normConditions(p.Status.Conditions)
	if p.Status.LastEvaluated != nil {
		t := normMetav1Time(*p.Status.LastEvaluated)
		p.Status.LastEvaluated = &t
	}
}

// normException normalizes all time fields in e to UTC.
func normException(e *PolicyException) {
	e.Status.Conditions = normConditions(e.Status.Conditions)
	if e.Spec.ExpiresAt != nil {
		t := normMetav1Time(*e.Spec.ExpiresAt)
		e.Spec.ExpiresAt = &t
	}
}

// ---- JSON round-trip ---------------------------------------------------

func TestPolicyJSON_RoundTrip(t *testing.T) {
	orig := fullyPopulatedPolicy()
	normPolicy(&orig)

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var got Policy
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	normPolicy(&got)

	if !reflect.DeepEqual(orig, got) {
		t.Fatalf("JSON round-trip: got != original\norig: %+v\ngot:  %+v", orig, got)
	}
}

func TestPolicyExceptionJSON_RoundTrip(t *testing.T) {
	orig := fullyPopulatedException()
	normException(&orig)

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var got PolicyException
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	normException(&got)

	if !reflect.DeepEqual(orig, got) {
		t.Fatalf("JSON round-trip: got != original\norig: %+v\ngot:  %+v", orig, got)
	}
}

// ---- YAML round-trip ---------------------------------------------------

func TestPolicyYAML_RoundTrip(t *testing.T) {
	orig := fullyPopulatedPolicy()
	normPolicy(&orig)

	data, err := yaml.Marshal(orig)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}

	var got Policy
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	normPolicy(&got)

	if !reflect.DeepEqual(orig, got) {
		t.Fatalf("YAML round-trip: got != original\norig: %+v\ngot:  %+v", orig, got)
	}
}

func TestPolicyExceptionYAML_RoundTrip(t *testing.T) {
	orig := fullyPopulatedException()
	normException(&orig)

	data, err := yaml.Marshal(orig)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}

	var got PolicyException
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("yaml.Unmarshal: %v", err)
	}
	normException(&got)

	if !reflect.DeepEqual(orig, got) {
		t.Fatalf("YAML round-trip: got != original\norig: %+v\ngot:  %+v", orig, got)
	}
}

// ---- AddToScheme -------------------------------------------------------

func TestAddToScheme(t *testing.T) {
	s := runtime.NewScheme()
	if err := AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme returned error: %v", err)
	}

	// Verify that both root types are registered.
	for _, gvk := range []struct{ kind string }{
		{"Policy"},
		{"PolicyList"},
		{"PolicyException"},
		{"PolicyExceptionList"},
	} {
		gvk2 := GroupVersion.WithKind(gvk.kind)
		obj, err := s.New(gvk2)
		if err != nil {
			t.Errorf("scheme.New(%s): %v", gvk.kind, err)
			continue
		}
		if obj == nil {
			t.Errorf("scheme.New(%s) returned nil object", gvk.kind)
		}
	}
}
