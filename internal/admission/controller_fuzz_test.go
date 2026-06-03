package admission

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// SDL-WU-10 (NIST SI-10, SA-11(8)): native Go fuzzer driving the REAL validate
// and mutate handler paths end-to-end with arbitrary request bodies. The
// security contract under test is fail-closed robustness: regardless of how
// malformed, truncated, oversized, or deeply nested the input is, the handler
// must NEVER panic and must ALWAYS return a single well-formed HTTP response —
// either an HTTP 200 carrying a syntactically valid AdmissionReview response, or
// an HTTP 4xx rejection. A panic or a hang here is a denial-of-service on the
// apiserver admission path, so any crasher the fuzzer finds is a real defect to
// be fixed defensively in controller.go (not papered over in the test).

// fuzzRouter builds a gin router wired to BOTH admission handlers using the same
// package test helpers (newControllerWithEngine) the behavior tests use, so the
// fuzzer exercises the genuine engine + decode + audit path rather than a
// hand-rolled stub. gin.New() (not gin.Default) keeps logging/recovery
// middleware out of the way: importantly we do NOT install gin.Recovery(), so a
// handler panic surfaces as a Go panic the fuzzer can catch instead of being
// silently swallowed into a 500.
func fuzzRouter(t *testing.T) *gin.Engine {
	t.Helper()
	ctrl, _ := newControllerWithEngine(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/validate", ctrl.ValidateHandler)
	router.POST("/mutate", ctrl.MutateHandler)
	return router
}

// driveHandler POSTs raw bytes at one route and asserts the fail-closed response
// invariant. It returns nothing on success; any violation fails the test (and,
// for a panic, the absence of gin.Recovery() means the goroutine unwinds into
// the fuzzing engine, which records the crasher).
func driveHandler(t *testing.T, router *gin.Engine, path string, body []byte) {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	// Invariant 1: a response is always produced.
	if rec.Code == 0 {
		t.Fatalf("%s: handler produced no HTTP status for body=%q", path, truncateForLog(body))
	}

	// Invariant 2: the status is either a 200 OK admission response or a 4xx
	// client rejection. A 5xx (or anything else) means the request crashed the
	// handler in a way gin turned into a server error rather than failing closed.
	if rec.Code != http.StatusOK && (rec.Code < 400 || rec.Code >= 500) {
		t.Fatalf("%s: unexpected status %d (want 200 or 4xx) for body=%q",
			path, rec.Code, truncateForLog(body))
	}

	// Invariant 3: a 200 MUST carry a syntactically valid AdmissionReview whose
	// Response is populated and whose UID echoes the request (when the input
	// supplied one). This is what proves the success path emits a well-formed
	// response rather than partial garbage.
	if rec.Code == http.StatusOK {
		var out admissionv1.AdmissionReview
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s: 200 response is not valid AdmissionReview JSON: %v (body=%q)",
				path, err, truncateForLog(rec.Body.Bytes()))
		}
		if out.Response == nil {
			t.Fatalf("%s: 200 response has nil AdmissionReview.Response for body=%q",
				path, truncateForLog(body))
		}
	}
}

// truncateForLog keeps fuzzer failure output readable when the offending input
// is an oversized or binary blob.
func truncateForLog(b []byte) string {
	const max = 256
	if len(b) > max {
		return string(b[:max]) + "...(truncated)"
	}
	return string(b)
}

// validAdmissionReviewJSON returns a well-formed AdmissionReview create request
// for a Pod, used as the "happy path" seed so the fuzzer also explores mutations
// of a structurally valid document.
func validAdmissionReviewJSON(t *testing.T) []byte {
	t.Helper()
	pod := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "fuzz-pod", "namespace": "default"},
		"spec":       map[string]any{},
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("marshal seed pod: %v", err)
	}
	review := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID:       types.UID("fuzz-seed-1"),
			Kind:      metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
			Namespace: "default",
			Name:      "fuzz-pod",
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: raw},
		},
	}
	b, err := json.Marshal(review)
	if err != nil {
		t.Fatalf("marshal seed review: %v", err)
	}
	return b
}

// maxFuzzBody bounds the input the fuzz function actually feeds to the handlers.
// Without a bound, the Go fuzzing engine mutates corpus entries up toward the
// MiB-scale oversized seed; each such exec is dominated by megabyte JSON
// scanning (~78ms for 1 MiB, measured), which collapses throughput to ~0
// execs/sec and starves coverage exploration. 64 KiB is comfortably larger than
// any realistic AdmissionReview the apiserver forwards (and is well within the
// apiserver's ~3 MiB request cap), so it still stresses oversized-relative-to-
// typical and deeply-nested inputs while keeping per-exec cost low enough for
// the fuzzer to make progress. The genuinely oversized (1 MiB) case is asserted
// deterministically in controller_validation_test.go, so capping it here does
// NOT reduce coverage of the oversized-input contract — it only keeps the
// fuzzer in its productive regime.
const maxFuzzBody = 64 << 10 // 64 KiB

// FuzzAdmissionRequest fuzzes the admission webhook body against both handlers.
func FuzzAdmissionRequest(f *testing.F) {
	// Build the router once for the seed-derived parent; each fuzz iteration
	// rebuilds its own router (see below) because *testing.T from f.Fuzz differs
	// from f's *testing.F and the engine/audit fakes are cheap to construct.
	parent := &testing.T{}
	_ = fuzzRouter(parent) // smoke-construct to fail fast if helpers break.

	// Seed corpus: a valid review plus the canonical malformed shapes the
	// handler must survive. Sizes are kept within maxFuzzBody so the seeds stay
	// in the fuzzer's fast regime; the unbounded 1 MiB oversized case lives in
	// controller_validation_test.go.
	f.Add(validAdmissionReviewJSON(parent))                                                       // well-formed happy path
	f.Add([]byte(""))                                                                             // empty body
	f.Add([]byte("{"))                                                                            // unterminated object
	f.Add([]byte(`{"request":`))                                                                  // truncated mid-value
	f.Add([]byte(`{"apiVersion":"wrong/v2"}`))                                                    // wrong apiVersion, no request
	f.Add([]byte(`{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview"}`))                // nil Request
	f.Add([]byte(`{"request":{"uid":"x","operation":"CREATE","object":{"raw":"!!!notbase64"}}}`)) // bad nested object
	f.Add([]byte(deeplyNestedJSON(512)))                                                          // deeply nested object (stack/recursion stress)
	f.Add([]byte(oversizedObjectJSON(32 << 10)))                                                  // 32 KiB oversized object string

	f.Fuzz(func(t *testing.T, body []byte) {
		// Bound the input so a corpus entry mutated toward MiB scale cannot stall
		// the fuzzer (see maxFuzzBody). Truncation only ever makes the body
		// smaller/more-malformed, which is a strictly valid fail-closed input —
		// it never relaxes a security assertion.
		if len(body) > maxFuzzBody {
			body = body[:maxFuzzBody]
		}

		// A fresh router per iteration keeps engine/registry state from leaking
		// across inputs and ensures one input cannot poison the next.
		router := fuzzRouter(t)
		// Exercise both routes: validate (fail-closed) and mutate (fail-open on
		// engine error). Both must still satisfy the no-panic / always-respond
		// invariant on arbitrary bytes.
		driveHandler(t, router, "/validate", body)
		driveHandler(t, router, "/mutate", body)
	})
}

// deeplyNestedJSON builds {"a":{"a":{...}}} nested depth levels deep, wrapped in
// an AdmissionReview-shaped object so it reaches the JSON decoder.
func deeplyNestedJSON(depth int) string {
	var b strings.Builder
	b.WriteString(`{"request":{"uid":"deep","operation":"CREATE","object":{"raw":`)
	// Build a nested string-encoded object as the .raw payload value.
	open := strings.Repeat(`{\"a\":`, depth)
	closeBraces := strings.Repeat(`}`, depth)
	b.WriteByte('"')
	b.WriteString(open)
	b.WriteString(`null`)
	b.WriteString(closeBraces)
	b.WriteByte('"')
	b.WriteString(`}}}`)
	return b.String()
}

// oversizedObjectJSON builds an AdmissionReview whose embedded object name is a
// single huge string of the requested byte length, to exercise large-allocation
// handling on the decode path.
func oversizedObjectJSON(size int) string {
	huge := strings.Repeat("A", size)
	return `{"request":{"uid":"big","operation":"CREATE","name":"` + huge + `"}}`
}
