package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/Jibbscript/kube-policies/internal/admission"
	"github.com/Jibbscript/kube-policies/internal/audit"
	"github.com/Jibbscript/kube-policies/internal/config"
	"github.com/Jibbscript/kube-policies/internal/policy"
	"github.com/Jibbscript/kube-policies/internal/policymanager"
	policiesv1 "github.com/Jibbscript/kube-policies/internal/policymanager/apis/policies/v1"
)

// WebhookExceptionSuppressionTestSuite proves that the admission-webhook's
// exceptionSink wires PolicyException CRD reconciliation through to live
// admission decisions. Mirrors WebhookCRDIntegrationTestSuite (see
// webhook_crd_test.go) — both suites exercise the controller-runtime →
// reconciler → sink → engine chain end-to-end against an envtest apiserver.
//
// The chain under test:
//
//	kubectl apply -f exception.yaml
//	  -> envtest apiserver stores PolicyException CRD
//	  -> controller-runtime watch fires
//	  -> PolicyExceptionReconciler.Reconcile() calls excSink.UpsertExceptionFromCRD()
//	  -> exception lands in the registry
//	  -> next /validate evaluation calls registry.Suppresses()
//	  -> matching deny is flipped to allow (or preserved if no match)
//
// Bundled defaults (security-baseline/no-privileged-containers — see
// internal/policy/engine.go::loadDefaultPolicies) provide the denying policy;
// the test does not need to apply a Policy CRD.
type WebhookExceptionSuppressionTestSuite struct {
	suite.Suite

	testEnv     *envtest.Environment
	cfg         *rest.Config
	k8sClient   client.Client
	engine      *policy.Engine
	auditLogger *audit.Logger
	controller  *admission.Controller
	ginHandler  *gin.Engine
	excSink     *testExceptionSink // implements both ExceptionSink and ExceptionRegistry
	panicSink   *panicOnceSink     // wraps excSink to inject one reconcile-time panic

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	controllerErr error
}

const (
	// Bundled-default policy targeted by every test in this suite.
	bundledPolicyID = "security-baseline"
	bundledRuleID   = "no-privileged-containers"

	// Reuse the constants from webhook_crd_test.go style.
	exceptionEventuallyTimeout  = 10 * time.Second
	exceptionEventuallyInterval = 100 * time.Millisecond
)

func (suite *WebhookExceptionSuppressionTestSuite) SetupSuite() {
	suite.ctx, suite.cancel = context.WithCancel(context.TODO())

	suite.testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{"../../deployments/kubernetes/crds"},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := suite.testEnv.Start()
	require.NoError(suite.T(), err)
	suite.cfg = cfg

	k8sClient, err := client.New(cfg, client.Options{})
	require.NoError(suite.T(), err)
	require.NoError(suite.T(), policiesv1.AddToScheme(k8sClient.Scheme()))
	k8sClient, err = client.New(cfg, client.Options{Scheme: k8sClient.Scheme()})
	require.NoError(suite.T(), err)
	suite.k8sClient = k8sClient

	appCfg := &config.Config{
		Policy: config.PolicyConfig{FailureMode: "fail-closed"},
		Audit:  config.AuditConfig{Enabled: false},
	}

	// Dual-interface sink: read side feeds the engine's ExceptionRegistry;
	// write side is fed by the PolicyExceptionReconciler via panicSink.
	suite.excSink = newTestExceptionSink()
	suite.panicSink = &panicOnceSink{inner: suite.excSink}

	suite.engine, err = policy.NewEngineWithExceptions(&appCfg.Policy, zap.NewNop(), suite.excSink)
	require.NoError(suite.T(), err)

	suite.auditLogger, err = audit.NewLogger(&appCfg.Audit, audit.WithLogger(zap.NewNop()))
	require.NoError(suite.T(), err)

	// sharedMetricsCollector() (policy_manager_test.go) is the package-level
	// once-allocated metrics.Collector; using NewCollector() here would panic
	// on duplicate Prometheus descriptors when this suite runs after others.
	suite.controller = admission.NewController(suite.engine, suite.auditLogger, sharedMetricsCollector(), zap.NewNop(), nil)

	gin.SetMode(gin.TestMode)
	suite.ginHandler = gin.New()
	suite.ginHandler.POST("/validate", suite.controller.ValidateHandler)
	suite.ginHandler.POST("/mutate", suite.controller.MutateHandler)

	// PolicySink is required by StartControllers even though the tests in this
	// suite drive their policy state through bundled defaults rather than CRDs.
	// Using the testEngineSink shape from webhook_crd_test.go keeps the
	// reconciler shape consistent across suites.
	polSink := newEngineSinkForTest(suite.engine, zap.NewNop())

	suite.wg.Add(1)
	go func() {
		defer suite.wg.Done()
		err := policymanager.StartControllers(suite.ctx, cfg, zap.NewNop(), policymanager.ControllerOptions{
			LeaderElectionID:      "kube-policies-webhook-exception-test",
			PolicySink:            polSink,
			ExceptionSink:         suite.panicSink,
			DisableLeaderElection: true,
		})
		if err != nil && err != context.Canceled {
			suite.controllerErr = err
		}
	}()

	suite.waitForControllerReady()
}

// waitForControllerReady performs the same round-trip readiness check as
// WebhookCRDIntegrationTestSuite — but uses a PolicyException probe so we
// directly confirm the exception reconciler is live (the Policy reconciler
// readiness is incidentally proven by the same wiring).
func (suite *WebhookExceptionSuppressionTestSuite) waitForControllerReady() {
	probeName := "exception-readiness-probe"
	probe := &policiesv1.PolicyException{
		ObjectMeta: metav1.ObjectMeta{Name: probeName, Namespace: "default"},
		Spec: policiesv1.PolicyExceptionSpec{
			PolicyID:      "never-matches-policy",
			Description:   "controller-runtime watch readiness probe",
			Justification: "readiness",
		},
	}
	require.NoError(suite.T(), suite.k8sClient.Create(suite.ctx, probe))
	probeID := policymanager.CRDExceptionID("default", probeName)

	require.Eventuallyf(suite.T(), func() bool {
		if suite.controllerErr != nil {
			suite.T().Logf("controller goroutine failed: %v", suite.controllerErr)
			return false
		}
		return suite.excSink.has(probeID)
	}, 30*time.Second, 100*time.Millisecond, "exception-readiness probe never reconciled — controller goroutine err=%v", suite.controllerErr)

	require.NoError(suite.T(), suite.k8sClient.Delete(suite.ctx, probe))
	require.Eventuallyf(suite.T(), func() bool {
		return !suite.excSink.has(probeID)
	}, exceptionEventuallyTimeout, exceptionEventuallyInterval, "exception-readiness probe never cleared from sink")
}

func (suite *WebhookExceptionSuppressionTestSuite) TearDownSuite() {
	if suite.cancel != nil {
		suite.cancel()
	}
	suite.wg.Wait()
	if suite.testEnv != nil {
		_ = suite.testEnv.Stop()
	}
}

func (suite *WebhookExceptionSuppressionTestSuite) SetupTest() {
	suite.deleteAllExceptions()
}

func (suite *WebhookExceptionSuppressionTestSuite) deleteAllExceptions() {
	var list policiesv1.PolicyExceptionList
	if err := suite.k8sClient.List(suite.ctx, &list); err != nil {
		return
	}
	for i := range list.Items {
		_ = suite.k8sClient.Delete(suite.ctx, &list.Items[i])
	}
	// Wait for the sink to drain so subsequent tests see a clean state.
	require.Eventually(suite.T(), func() bool {
		return suite.excSink.count() == 0
	}, exceptionEventuallyTimeout, exceptionEventuallyInterval)
}

// TestWebhookException_SuppressesMatchingDenial — core happy path. The
// bundled `security-baseline/no-privileged-containers` rule denies a
// privileged pod. A matching PolicyException flips the verdict to allow.
//
// Note: the admission response only carries `Result.Message` when
// `Allowed=false` (see internal/admission/controller.go:122-126); on the
// success path the engine's "N suppressed by M exception(s)" Message is
// observable in audit logs and the decisions-publisher payload, but not in
// the AdmissionReview response body. The unit-test lane covers Message
// wording (TestEngine_RegistrySuppresses_FlipsDeny_MessageStatesSuppression
// — Step 5.3); this integration test asserts the verdict flip end-to-end.
func (suite *WebhookExceptionSuppressionTestSuite) TestWebhookException_SuppressesMatchingDenial() {
	// Without any exception, the privileged pod is denied by bundled defaults.
	allowed, msg := suite.admitPrivilegedPod("default")
	require.False(suite.T(), allowed, "privileged pod must be denied before exception applies; msg=%s", msg)

	// Apply a blanket exception (no scope ⇒ match-all) for the bundled rule.
	exc := newPolicyException("blanket-suppress", "default", bundledPolicyID, bundledRuleID, policiesv1.PolicyExceptionScope{}, nil)
	require.NoError(suite.T(), suite.k8sClient.Create(suite.ctx, exc))

	// Wait for the reconciler to land the exception in the sink so the next
	// admit-cycle assertion isn't racing the CRD watch.
	require.Eventuallyf(suite.T(), func() bool {
		return suite.excSink.has(policymanager.CRDExceptionID("default", "blanket-suppress"))
	}, exceptionEventuallyTimeout, exceptionEventuallyInterval,
		"blanket-suppress exception never reconciled into the sink")

	require.Eventuallyf(suite.T(), func() bool {
		ok, _ := suite.admitPrivilegedPod("default")
		return ok
	}, exceptionEventuallyTimeout, exceptionEventuallyInterval,
		"privileged pod was never suppressed after PolicyException applied (verdict did not flip to Allowed=true)")
}

// TestWebhookException_NonMatchingException_PreservesDenial — a scope that
// does not match the request must NOT suppress the deny.
func (suite *WebhookExceptionSuppressionTestSuite) TestWebhookException_NonMatchingException_PreservesDenial() {
	// Apply an exception scoped to "other-ns".
	exc := newPolicyException("scoped-other", "default", bundledPolicyID, bundledRuleID,
		policiesv1.PolicyExceptionScope{Namespaces: []string{"other-ns"}}, nil)
	require.NoError(suite.T(), suite.k8sClient.Create(suite.ctx, exc))

	// Wait for the sink to see it (so we're not racing the reconciler before asserting).
	require.Eventually(suite.T(), func() bool {
		return suite.excSink.has(policymanager.CRDExceptionID("default", "scoped-other"))
	}, exceptionEventuallyTimeout, exceptionEventuallyInterval, "scoped-other exception never reconciled")

	// Consistently: privileged pods in "default" stay denied — the exception
	// applies only to "other-ns".
	require.Never(suite.T(), func() bool {
		ok, _ := suite.admitPrivilegedPod("default")
		return ok
	}, 2*time.Second, 200*time.Millisecond, "namespace-scoped exception should not have suppressed deny in 'default'")
}

// TestWebhookException_DeletedException_RestoresDenial — deleting the
// exception un-suppresses subsequent requests.
func (suite *WebhookExceptionSuppressionTestSuite) TestWebhookException_DeletedException_RestoresDenial() {
	exc := newPolicyException("temp-blanket", "default", bundledPolicyID, bundledRuleID, policiesv1.PolicyExceptionScope{}, nil)
	require.NoError(suite.T(), suite.k8sClient.Create(suite.ctx, exc))

	// Wait until the exception suppresses the deny.
	require.Eventuallyf(suite.T(), func() bool {
		ok, _ := suite.admitPrivilegedPod("default")
		return ok
	}, exceptionEventuallyTimeout, exceptionEventuallyInterval, "exception never took effect")

	// Delete the exception; deny must come back.
	require.NoError(suite.T(), suite.k8sClient.Delete(suite.ctx, exc))
	require.Eventuallyf(suite.T(), func() bool {
		ok, _ := suite.admitPrivilegedPod("default")
		return !ok
	}, exceptionEventuallyTimeout, exceptionEventuallyInterval,
		"deny was never restored after exception deletion")
}

// TestWebhookException_ExpiredException_DenyRestored — an exception with
// ExpiresAt in the past must never suppress (matches predicate gate (1)).
func (suite *WebhookExceptionSuppressionTestSuite) TestWebhookException_ExpiredException_DenyRestored() {
	expired := metav1.NewTime(time.Now().Add(-time.Hour))
	exc := newPolicyException("expired-blanket", "default", bundledPolicyID, bundledRuleID, policiesv1.PolicyExceptionScope{}, &expired)
	require.NoError(suite.T(), suite.k8sClient.Create(suite.ctx, exc))

	// Wait for the reconciler to load it.
	require.Eventually(suite.T(), func() bool {
		return suite.excSink.has(policymanager.CRDExceptionID("default", "expired-blanket"))
	}, exceptionEventuallyTimeout, exceptionEventuallyInterval, "expired exception never reconciled into the sink")

	// Even with the exception loaded, the deny must stand because it's expired.
	require.Never(suite.T(), func() bool {
		ok, _ := suite.admitPrivilegedPod("default")
		return ok
	}, 2*time.Second, 200*time.Millisecond, "expired exception should not have suppressed deny")
}

// TestWebhookException_ReconcilerPanicRecovered — pre-mortem §4.4. Inject a
// panic during reconcile of a CR whose name starts with "panic-trigger-";
// assert (a) the test process survives (controller-runtime built-in panic
// recovery does its job), (b) /validate continues to serve, and (c) a
// subsequent non-trigger exception still reconciles to the sink.
//
// Note: the panic-trigger CR targets a non-existent policy id so that, after
// controller-runtime's recovery + retry lands the CR in the sink, it does NOT
// accidentally suppress real-policy denials and confuse the post-panic
// assertions.
func (suite *WebhookExceptionSuppressionTestSuite) TestWebhookException_ReconcilerPanicRecovered() {
	require.False(suite.T(), suite.panicSink.didPanic(), "panic-once sentinel should be clean at test start")

	// Step 1: Create the panic-trigger CR. The wrapped sink panics on first
	// Upsert; controller-runtime's reconcileHandler must recover and the
	// reconcile loop must remain healthy.
	trigger := newPolicyException("panic-trigger-1", "default", "no-such-policy", "no-such-rule", policiesv1.PolicyExceptionScope{}, nil)
	require.NoError(suite.T(), suite.k8sClient.Create(suite.ctx, trigger))

	// The panic flag flips on the first Upsert attempt. Wait for it so we
	// know the panic path was exercised.
	require.Eventuallyf(suite.T(), func() bool {
		return suite.panicSink.didPanic()
	}, exceptionEventuallyTimeout, exceptionEventuallyInterval,
		"panic path was never exercised — wrapped sink expected an Upsert call")

	// Step 2: Webhook still serves. The panic-trigger CR targets a
	// non-existent policy_id, so even if controller-runtime retries past the
	// panic and lands it in the sink, no real deny should be suppressed.
	require.Eventuallyf(suite.T(), func() bool {
		allowed, _ := suite.admitPrivilegedPod("default")
		return !allowed
	}, 2*time.Second, 100*time.Millisecond,
		"/validate should still serve and deny privileged pods post-panic")

	// Step 3: A non-trigger exception still reconciles. controller-runtime
	// will also retry the original trigger CR after the panic; the wrapper
	// now passes through (panicked sentinel is set), so it eventually lands
	// too. Both paths feed the sink.
	post := newPolicyException("post-panic-blanket", "default", bundledPolicyID, bundledRuleID, policiesv1.PolicyExceptionScope{}, nil)
	require.NoError(suite.T(), suite.k8sClient.Create(suite.ctx, post))

	require.Eventuallyf(suite.T(), func() bool {
		return suite.excSink.has(policymanager.CRDExceptionID("default", "post-panic-blanket"))
	}, exceptionEventuallyTimeout, exceptionEventuallyInterval,
		"post-panic exception never reconciled — controller-runtime panic recovery may have stopped the worker")

	// And the exception is honored end-to-end.
	require.Eventuallyf(suite.T(), func() bool {
		ok, _ := suite.admitPrivilegedPod("default")
		return ok
	}, exceptionEventuallyTimeout, exceptionEventuallyInterval,
		"post-panic exception was reconciled but did not suppress deny")
}

// admitPrivilegedPod posts an AdmissionReview for a privileged pod in the
// given namespace and returns (Allowed, ResponseMessage). The pod is
// constructed to violate ONLY the bundled `no-privileged-containers` rule
// (image has explicit tag; runAsNonRoot=true; allowPrivilegeEscalation=false)
// so the deny is unambiguously about the privileged setting.
func (suite *WebhookExceptionSuppressionTestSuite) admitPrivilegedPod(namespace string) (bool, string) {
	privileged := true
	apeFalse := false
	runAsNonRoot := true
	runAsUser := int64(1000)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "exception-test-pod", Namespace: namespace},
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: &runAsNonRoot,
				RunAsUser:    &runAsUser,
			},
			Containers: []corev1.Container{{
				Name:  "c",
				Image: "nginx:1.20",
				SecurityContext: &corev1.SecurityContext{
					Privileged:               &privileged,
					RunAsNonRoot:             &runAsNonRoot,
					RunAsUser:                &runAsUser,
					AllowPrivilegeEscalation: &apeFalse,
				},
			}},
		},
	}
	podBytes, err := json.Marshal(pod)
	require.NoError(suite.T(), err)

	review := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID:       types.UID(fmt.Sprintf("exception-test-uid-%d", time.Now().UnixNano())),
			Operation: admissionv1.Create,
			Kind:      metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"},
			Resource:  metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"},
			Namespace: namespace,
			Name:      pod.Name,
			Object:    runtime.RawExtension{Raw: podBytes},
		},
	}
	body, err := json.Marshal(review)
	require.NoError(suite.T(), err)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	suite.ginHandler.ServeHTTP(w, req)

	require.Equal(suite.T(), http.StatusOK, w.Code, "validate handler should return 200, got %d: %s", w.Code, w.Body.String())

	var resp admissionv1.AdmissionReview
	require.NoError(suite.T(), json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotNil(suite.T(), resp.Response)

	msg := ""
	if resp.Response.Result != nil {
		msg = resp.Response.Result.Message
	}
	return resp.Response.Allowed, msg
}

// newPolicyException builds an unsigned PolicyException CR with the supplied
// fields. The CRD's spec.expires_at is *metav1.Time; pass nil for never-expires.
func newPolicyException(name, namespace, policyID, ruleID string, scope policiesv1.PolicyExceptionScope, expiresAt *metav1.Time) *policiesv1.PolicyException {
	return &policiesv1.PolicyException{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: policiesv1.PolicyExceptionSpec{
			Description:   fmt.Sprintf("integration test exception: %s", name),
			PolicyID:      policyID,
			RuleID:        ruleID,
			Justification: "integration test",
			Scope:         scope,
			ExpiresAt:     expiresAt,
		},
	}
}

// --- test-local sink (mirrors cmd/admission-webhook/exception_sink.go in
// minimal form; the production sink lives in package main and is not
// importable from tests).

// testExceptionSink satisfies BOTH policymanager.ExceptionSink (write side,
// fed by the reconciler) AND policy.ExceptionRegistry (read side, consumed
// by the engine). Faithfulness to the production matches predicate is
// limited — the unit-test suite (cmd/admission-webhook/exception_sink_test.go,
// 14 cases per plan §5.6) owns predicate correctness. This implementation
// covers expiry, RuleID, and the four scope dimensions, which is what the
// integration tests in this file exercise.
type testExceptionSink struct {
	mu   sync.RWMutex
	byID map[string]*policymanager.Exception
}

func newTestExceptionSink() *testExceptionSink {
	return &testExceptionSink{byID: make(map[string]*policymanager.Exception)}
}

func (s *testExceptionSink) UpsertExceptionFromCRD(crd *policiesv1.PolicyException) *policymanager.Exception {
	ex := policymanager.ExceptionFromCRD(crd)
	s.mu.Lock()
	s.byID[ex.ID] = ex
	s.mu.Unlock()
	return ex
}

func (s *testExceptionSink) RemoveExceptionByID(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.byID[id]
	if ok {
		delete(s.byID, id)
	}
	return ok
}

func (s *testExceptionSink) Suppresses(_ context.Context, key policy.MatchKey) (bool, []policy.ExceptionRef, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var refs []policy.ExceptionRef
	now := time.Now()
	for _, ex := range s.byID {
		if ex.PolicyID != key.PolicyID {
			continue
		}
		if !testMatches(ex, key, now) {
			continue
		}
		refs = append(refs, policy.ExceptionRef{
			ID:            ex.ID,
			Name:          ex.Name,
			PolicyID:      ex.PolicyID,
			RuleID:        ex.RuleID,
			Justification: ex.Justification,
		})
	}
	return len(refs) > 0, refs, nil
}

func (s *testExceptionSink) has(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.byID[id]
	return ok
}

func (s *testExceptionSink) count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID)
}

// testMatches mirrors the production matches predicate's high-level shape:
// expiry gate, optional rule-id filter, then per-dimension scope checks with
// the scope-entirely-absent wildcard rule.
func testMatches(ex *policymanager.Exception, key policy.MatchKey, now time.Time) bool {
	if ex.ExpiresAt != nil && ex.ExpiresAt.Before(now) {
		return false
	}
	if ex.RuleID != "" && ex.RuleID != key.RuleID {
		return false
	}
	populated := 0
	if len(ex.Scope.Namespaces) > 0 {
		populated++
	}
	if len(ex.Scope.Resources) > 0 {
		populated++
	}
	if len(ex.Scope.Users) > 0 {
		populated++
	}
	if len(ex.Scope.Groups) > 0 {
		populated++
	}
	if populated == 0 {
		return true // blanket carve-out
	}
	if len(ex.Scope.Namespaces) > 0 && !containsString(ex.Scope.Namespaces, key.Namespace) {
		return false
	}
	if len(ex.Scope.Resources) > 0 && !containsStringFold(ex.Scope.Resources, key.Resource) {
		return false
	}
	if len(ex.Scope.Users) > 0 && !containsString(ex.Scope.Users, key.User) {
		return false
	}
	if len(ex.Scope.Groups) > 0 && !anyIntersect(ex.Scope.Groups, key.Groups) {
		return false
	}
	return true
}

func containsString(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

func containsStringFold(set []string, v string) bool {
	for _, s := range set {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}

func anyIntersect(a, b []string) bool {
	for _, v := range b {
		if containsString(a, v) {
			return true
		}
	}
	return false
}

// panicOnceSink wraps an ExceptionSink and panics on the first Upsert whose
// CR's metadata.name starts with "panic-trigger-". Subsequent calls (and any
// Upserts for other names) pass through. Used to verify controller-runtime's
// built-in reconcileHandler panic recovery prevents process death.
type panicOnceSink struct {
	inner    policymanager.ExceptionSink
	panicked atomic.Bool
}

func (p *panicOnceSink) UpsertExceptionFromCRD(crd *policiesv1.PolicyException) *policymanager.Exception {
	if strings.HasPrefix(crd.Name, "panic-trigger-") && p.panicked.CompareAndSwap(false, true) {
		panic(fmt.Sprintf("intentional reconcile-time panic for CR %s/%s", crd.Namespace, crd.Name))
	}
	return p.inner.UpsertExceptionFromCRD(crd)
}

func (p *panicOnceSink) RemoveExceptionByID(id string) bool {
	return p.inner.RemoveExceptionByID(id)
}

func (p *panicOnceSink) didPanic() bool { return p.panicked.Load() }

func TestWebhookExceptionSuppressionTestSuite(t *testing.T) {
	suite.Run(t, new(WebhookExceptionSuppressionTestSuite))
}
