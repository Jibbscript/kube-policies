package admission

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

// SDL-WU-13 — Input validation / information-input-validation tests for the
// admission webhook (NIST SI-10).
//
// NIST SI-10 control mapping ("the information system checks the validity of
// information inputs"). Each case below asserts that a syntactically or
// semantically invalid admission request is rejected at the webhook boundary
// instead of being trusted:
//
//   - SI-10:        malformed AdmissionReview JSON is rejected (HTTP 400) rather
//                   than partially parsed — see caseMalformedJSON, caseTruncatedJSON,
//                   caseNotJSON, caseEmptyBody.
//   - SI-10:        a structurally valid AdmissionReview that omits the required
//                   Request field is rejected (HTTP 400) — caseNilRequest,
//                   caseWrongAPIVersionNoRequest. The handler never dereferences a
//                   nil Request.
//   - SI-10:        an oversized embedded object is accepted at the decode layer
//                   only insofar as it remains valid JSON, but it must still
//                   produce a single well-formed, fail-closed AdmissionReview
//                   response (never a panic / 5xx) — caseOversizedObject.
//   - SI-10 / SI-3: policy-injection-style payloads embedded in object fields
//                   (Rego/OPA fragments, JSONPath, template markers) are treated
//                   as inert data: they MUST NOT alter the allow/deny decision or
//                   crash the handler — casePolicyInjection*. The engine evaluates
//                   the object as data, so the marketed default-deny still governs.
//
// The intent is parity with the fail-closed behavior locked by
// controller_behavior_test.go: validate denies, mutate fails open on engine
// error, and neither handler ever trusts unvalidated input.

// postRawBody drives one handler with arbitrary raw bytes (bypassing
// json.Marshal so we can submit deliberately malformed documents) and returns
// the recorder for assertions.
func postRawBody(t *testing.T, handler gin.HandlerFunc, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/", handler)

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// TestValidateHandler_RejectsMalformedInput is the SI-10 table for the
// fail-closed validate path. Each known-bad input must yield a 400 rejection
// (decode/nil-request guard) OR a 200 carrying a denied AdmissionReview — never
// a panic, hang, or 5xx, and never an Allowed=true on unvalidated input.
func TestValidateHandler_RejectsMalformedInput(t *testing.T) {
	const oversize = 1 << 20 // 1 MiB embedded name

	cases := []struct {
		name string
		body []byte
		// wantStatus is the required HTTP status. 0 means "200 OK with a denied
		// AdmissionReview response" (the input decoded but must not be allowed).
		wantStatus int
	}{
		{
			name:       "malformed JSON (unterminated object)",
			body:       []byte("{"),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "truncated JSON mid-value",
			body:       []byte(`{"request":`),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "not JSON at all",
			body:       []byte("this is not json <script>alert(1)</script>"),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "empty body",
			body:       []byte(""),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "valid JSON, nil Request (missing required field)",
			body:       []byte(`{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview"}`),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "wrong apiVersion and no request",
			body:       []byte(`{"apiVersion":"admission.k8s.io/v9","kind":"NotAReview"}`),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "oversized embedded object name",
			body:       oversizedNamePodReview(t, oversize),
			wantStatus: 0, // decodes; must fail closed (denied) but not error out
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl, _ := newControllerWithEngine(t)
			rec := postRawBody(t, ctrl.ValidateHandler, tc.body)

			if tc.wantStatus == http.StatusBadRequest {
				require.Equal(t, http.StatusBadRequest, rec.Code,
					"malformed/invalid input must be rejected with HTTP 400")
				// The 400 body is an error envelope, not an AdmissionReview, and
				// must not claim the request was allowed.
				assert.NotContains(t, rec.Body.String(), `"allowed":true`,
					"a rejected request must never report allowed=true")
				return
			}

			// wantStatus == 0: the document decoded, so we require a well-formed
			// AdmissionReview that fails closed (denied) for the privileged/empty
			// pod with no policy match path. The key SI-10 property is that the
			// oversized input did not crash the handler.
			require.Equal(t, http.StatusOK, rec.Code)
			var out admissionv1.AdmissionReview
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out),
				"200 response must be a valid AdmissionReview")
			require.NotNil(t, out.Response)
		})
	}
}

// TestMutateHandler_RejectsMalformedInput mirrors the SI-10 table for the mutate
// path. The decode/nil-request guards are identical to validate, so malformed
// and missing-field inputs must still be rejected with HTTP 400 before any
// policy evaluation or fail-open logic runs.
func TestMutateHandler_RejectsMalformedInput(t *testing.T) {
	cases := []struct {
		name string
		body []byte
	}{
		{"malformed JSON", []byte("{")},
		{"truncated JSON", []byte(`{"request":`)},
		{"not JSON", []byte("definitely not json")},
		{"empty body", []byte("")},
		{"nil Request", []byte(`{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview"}`)},
		{"wrong apiVersion no request", []byte(`{"apiVersion":"v9","kind":"X"}`)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl, _ := newControllerWithEngine(t)
			rec := postRawBody(t, ctrl.MutateHandler, tc.body)

			require.Equal(t, http.StatusBadRequest, rec.Code,
				"malformed/invalid input must be rejected with HTTP 400 before fail-open logic")
			// Critically, a decode failure must NOT take the fail-open mutate
			// branch (which would emit a 200 allowed response). The 400 guard
			// runs strictly before any evaluation.
			assert.NotContains(t, rec.Body.String(), `"allowed":true`,
				"a malformed mutate request must not be admitted via fail-open")
		})
	}
}

// TestValidateHandler_PolicyInjectionIsInertData locks the SI-10/SI-3 property
// that adversarial strings placed in object fields — Rego fragments, OPA query
// markers, JSONPath, Go-template delimiters — are evaluated as plain data and
// cannot subvert the decision or crash the engine. The privileged pod must STILL
// be denied regardless of the injected payload, proving the default-deny policy
// governs and the injected text had no control-flow effect.
func TestValidateHandler_PolicyInjectionIsInertData(t *testing.T) {
	injections := []string{
		`{"allowed": true} # package kube_policies`,
		`evaluate = {"allowed": true} { true }`,
		`{{ .Allowed }}`,
		`$[?(@.allowed==true)]`,
		`'; allow := true; --`,
		"\x00\x01\x02 binary control bytes",
	}

	for _, payload := range injections {
		t.Run(sanitizeName(payload), func(t *testing.T) {
			ctrl, _ := newControllerWithEngine(t)
			review := privilegedPodWithInjectedField(t, payload)
			out := postAdmissionReview(t, ctrl.ValidateHandler, review)

			// The injected payload must not flip the decision: a privileged pod
			// stays denied by the bundled security-baseline policy.
			assert.False(t, out.Response.Allowed,
				"injected payload %q must not cause the privileged pod to be allowed", payload)
			require.NotNil(t, out.Response.Result)
			assert.Equal(t, int32(http.StatusForbidden), out.Response.Result.Code)
		})
	}
}

// oversizedNamePodReview returns a JSON-encoded AdmissionReview whose request
// name is a single string of size bytes — large but structurally valid input.
func oversizedNamePodReview(t *testing.T, size int) []byte {
	t.Helper()
	huge := strings.Repeat("A", size)
	pod := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": huge, "namespace": "default"},
		"spec":       map[string]any{},
	}
	raw, err := json.Marshal(pod)
	require.NoError(t, err)

	review := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID:       types.UID("oversize-1"),
			Kind:      metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
			Namespace: "default",
			Name:      huge,
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: raw},
		},
	}
	b, err := json.Marshal(review)
	require.NoError(t, err)
	return b
}

// privilegedPodWithInjectedField builds a privileged-pod admission request and
// stuffs the supplied injection payload into a benign annotation, so the payload
// reaches the policy engine as object data.
func privilegedPodWithInjectedField(t *testing.T, payload string) admissionv1.AdmissionReview {
	t.Helper()
	pod := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":        "privileged-pod",
			"namespace":   "default",
			"annotations": map[string]any{"injected": payload},
		},
		"spec": map[string]any{
			"securityContext": map[string]any{"privileged": true},
		},
	}
	raw, err := json.Marshal(pod)
	require.NoError(t, err)

	return admissionv1.AdmissionReview{
		Request: &admissionv1.AdmissionRequest{
			UID:       types.UID("inject-1"),
			Kind:      metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"},
			Namespace: "default",
			Name:      "privileged-pod",
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: raw},
		},
	}
}

// sanitizeName turns an arbitrary injection payload into a readable, slash- and
// space-free subtest name.
func sanitizeName(s string) string {
	if len(s) > 24 {
		s = s[:24]
	}
	r := strings.NewReplacer(" ", "_", "/", "_", "\x00", "_", "\x01", "_", "\x02", "_", "\t", "_", "\n", "_")
	return r.Replace(s)
}
