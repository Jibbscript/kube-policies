package policy

import (
	"context"
	"testing"

	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/Jibbscript/kube-policies/internal/config"
)

// FuzzEngineEvaluate drives the OPA-backed Engine with arbitrary, untrusted
// bytes in the admitted object's Object.Raw (and fuzzed Kind/Operation) and
// asserts the evaluator is fail-safe under any input: it MUST NOT panic, and it
// MUST always return a defined verdict — either a non-nil *EvaluationResult or a
// non-nil error, never both nil. This is defense-in-depth for SI-10 (input
// validation) on the policy-evaluated payload: a malformed Kubernetes object,
// non-object JSON, or a hostile blob must never crash the admission webhook or
// leave it without a decision (which would otherwise drive the fail-open /
// fail-closed handling in the caller off an undefined state).
//
// Construction mirrors the bundled-defaults smoke test
// (engine_defaults_smoke_test.go): a real Engine with the bundled default
// policies loaded, so the fuzzer exercises actual Rego compilation and
// evaluation rather than an empty rule set.
func FuzzEngineEvaluate(f *testing.F) {
	engine, err := NewEngine(&config.PolicyConfig{FailureMode: "fail-closed"}, zap.NewNop())
	if err != nil {
		f.Fatalf("NewEngine: %v", err)
	}

	// Seed corpus: a representative spread of valid, malformed, truncated,
	// non-object, deeply-nested, and oversized payloads.
	f.Add([]byte(`{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p","namespace":"default"},"spec":{"containers":[{"name":"c","image":"nginx:1.25.3","securityContext":{"runAsNonRoot":true,"allowPrivilegeEscalation":false}}]}}`))
	f.Add([]byte(``))                                                                   // empty
	f.Add([]byte(`{`))                                                                  // lone brace
	f.Add([]byte(`{"apiVersion":"v1","kind":"Pod","spec":{"co`))                        // truncated JSON
	f.Add([]byte(`{"metadata":{"labels":{"a":{"b":{"c":{"d":{"e":{"f":"deep"}}}}}}}}`)) // deeply-nested labels
	f.Add([]byte(`[]`))                                                                 // non-object: array
	f.Add([]byte(`"str"`))                                                              // non-object: string
	f.Add([]byte(`123`))                                                                // non-object: number
	f.Add([]byte(`{"metadata":{"name":"` + makeHugeString(64*1024) + `"}}`))            // huge string

	f.Fuzz(func(t *testing.T, raw []byte) {
		// Derive a Kind and Operation from the input so the fuzzer also varies
		// kind-routing (POL-WU-21) and the operation field. Both are bounded to a
		// small, valid-ish set plus an empty/garbage case to exercise the
		// kind=="" "matches every rule" branch.
		kind := fuzzKind(raw)
		op := fuzzOperation(raw)

		req := &EvaluationRequest{
			AdmissionRequest: &admissionv1.AdmissionRequest{
				UID:       "fuzz",
				Kind:      metav1.GroupVersionKind{Version: "v1", Kind: kind},
				Operation: op,
				Object:    runtime.RawExtension{Raw: raw},
			},
			Operation: "validate",
		}

		// The defined-verdict contract: a panic fails the test outright (no
		// recover here — a panic is precisely the failure we are hunting). The
		// only acceptable outcomes are (result!=nil, err==nil) or
		// (result==nil, err!=nil); (nil, nil) is a contract violation.
		res, err := engine.Evaluate(context.Background(), req)
		if res == nil && err == nil {
			t.Fatalf("Evaluate returned (nil, nil): no defined verdict for raw=%q kind=%q op=%q", raw, kind, op)
		}
		if res != nil && err != nil {
			t.Fatalf("Evaluate returned both result and error for raw=%q kind=%q op=%q: result=%+v err=%v", raw, kind, op, res, err)
		}
	})
}

// fuzzKind maps the first input byte to a Kind so the fuzzer varies kind routing,
// including the empty-kind ("matches every rule") edge case.
func fuzzKind(raw []byte) string {
	kinds := []string{"Pod", "Deployment", "ClusterRole", "Secret", "NetworkPolicy", ""}
	if len(raw) == 0 {
		return "Pod"
	}
	return kinds[int(raw[0])%len(kinds)]
}

// fuzzOperation maps the last input byte to an admission operation.
func fuzzOperation(raw []byte) admissionv1.Operation {
	ops := []admissionv1.Operation{
		admissionv1.Create,
		admissionv1.Update,
		admissionv1.Delete,
		admissionv1.Connect,
		admissionv1.Operation("GARBAGE"),
	}
	if len(raw) == 0 {
		return admissionv1.Create
	}
	return ops[int(raw[len(raw)-1])%len(ops)]
}

// makeHugeString returns a string of n 'x' bytes for the oversized seed.
func makeHugeString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'x'
	}
	return string(b)
}
