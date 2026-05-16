package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
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

// WebhookCRDIntegrationTestSuite proves that the admission-webhook's
// engineSink wires CRD reconciliation through to live admission decisions.
//
// The chain under test:
//
//	kubectl apply -f new-policy.yaml
//	  -> envtest apiserver stores Policy CRD
//	  -> controller-runtime watch fires
//	  -> PolicyReconciler.Reconcile() calls engineSink.UpsertPolicyFromCRD()
//	  -> engine.LoadPolicy() updates the engine's policies map + evicts prepared queries
//	  -> POST /validate evaluates against the new rule
//
// Test strategy: register a CRD whose Rego rejects pods carrying a unique
// label our test owns ("kube-policies-crd-test: deny-me"). Pods that the
// bundled defaults would happily allow get denied by the CRD; once the CRD
// is deleted, the same pod is allowed again.
type WebhookCRDIntegrationTestSuite struct {
	suite.Suite

	testEnv     *envtest.Environment
	cfg         *rest.Config
	k8sClient   client.Client
	engine      *policy.Engine
	auditLogger *audit.Logger
	controller  *admission.Controller
	ginHandler  *gin.Engine

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// controllerErr captures any error returned by StartControllers so the
	// readiness probe can surface "manager failed to start" instead of
	// timing out generically.
	controllerErr error
}

const webhookEventuallyTimeout = 10 * time.Second
const webhookEventuallyInterval = 100 * time.Millisecond

// crdDenyOnLabelRego denies any pod that carries the marker label this test
// owns. Bundled defaults don't reference this label, so the pod is allowed
// until the CRD lands and denied while the CRD exists.
const crdDenyOnLabelRego = `package kube_policies

import rego.v1

default evaluate := {"allowed": true}

evaluate := {
	"allowed": false,
	"message": "pod carries the kube-policies-crd-test=deny-me marker",
	"path": "metadata.labels[\"kube-policies-crd-test\"]",
} if {
	input.object.metadata.labels["kube-policies-crd-test"] == "deny-me"
}
`

func (suite *WebhookCRDIntegrationTestSuite) SetupSuite() {
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
	suite.engine, err = policy.NewEngine(&appCfg.Policy, zap.NewNop())
	require.NoError(suite.T(), err)

	// The audit logger here is a noop wrapper since AuditConfig.Enabled=false.
	suite.auditLogger, err = audit.NewLogger(&appCfg.Audit, audit.WithLogger(zap.NewNop()))
	require.NoError(suite.T(), err)

	// Reuse the once-registered Prometheus collector so the controller can
	// record admission metrics without a nil-pointer panic. metrics.NewCollector
	// panics on second invocation (duplicate descriptors), so the package-level
	// sync.Once in policy_manager_test.go is the canonical accessor.
	suite.controller = admission.NewController(suite.engine, suite.auditLogger, sharedMetricsCollector(), zap.NewNop(), nil)

	gin.SetMode(gin.TestMode)
	suite.ginHandler = gin.New()
	suite.ginHandler.POST("/validate", suite.controller.ValidateHandler)
	suite.ginHandler.POST("/mutate", suite.controller.MutateHandler)

	// Start CRD controllers pointed at envtest with the engineSink.
	// Capture the controller error so a failed controller.Start() doesn't
	// silently leave the test polling a stopped controller. Previously this
	// error was swallowed, which masked package-level singleton conflicts
	// (e.g. between two controller-runtime managers in the same test binary).
	sink := newEngineSinkForTest(suite.engine, zap.NewNop())
	suite.wg.Add(1)
	go func() {
		defer suite.wg.Done()
		err := policymanager.StartControllers(suite.ctx, cfg, zap.NewNop(), policymanager.ControllerOptions{
			LeaderElectionID: "kube-policies-webhook-crd-test",
			PolicySink:       sink,
		})
		if err != nil && err != context.Canceled {
			suite.controllerErr = err
		}
	}()

	// Wait for the controller's cache to be ready before the first test
	// fires a CRD create. Without this, when this suite runs after another
	// envtest-backed suite, the controller-runtime cache+informer bootstrap
	// can take several seconds, and Eventually() in the test races ahead.
	// We use a probe CRD as a black-box readiness check: create, wait for
	// the engine to see it, then delete.
	suite.waitForControllerReady()
}

// waitForControllerReady creates a throwaway Policy CRD, waits until the
// engineSink has loaded it, then deletes it. The round-trip proves the
// controller-runtime watch is connected and the reconciler is firing —
// independent of the controller manager's internal cache.WaitForCacheSync
// (which we don't have a handle to from StartControllers).
func (suite *WebhookCRDIntegrationTestSuite) waitForControllerReady() {
	probe := &policiesv1.Policy{
		ObjectMeta: metav1.ObjectMeta{Name: "controller-readiness-probe", Namespace: "default"},
		Spec: policiesv1.PolicySpec{
			Rules: []policiesv1.PolicyRule{
				{Name: "probe", Rego: `package kube_policies
import rego.v1
default evaluate := {"allowed": true}
`},
			},
		},
	}
	require.NoError(suite.T(), suite.k8sClient.Create(suite.ctx, probe))
	probeID := policymanager.CRDPolicyID("default", "controller-readiness-probe")

	require.Eventuallyf(suite.T(), func() bool {
		if suite.controllerErr != nil {
			suite.T().Logf("controller goroutine failed: %v", suite.controllerErr)
			return false
		}
		for _, p := range suite.engine.ListPolicies() {
			if p.ID == probeID {
				return true
			}
		}
		return false
	}, 30*time.Second, 100*time.Millisecond, "controller-readiness probe never reconciled — controller goroutine err=%v", suite.controllerErr)

	require.NoError(suite.T(), suite.k8sClient.Delete(suite.ctx, probe))
	require.Eventuallyf(suite.T(), func() bool {
		for _, p := range suite.engine.ListPolicies() {
			if p.ID == probeID {
				return false
			}
		}
		return true
	}, 10*time.Second, 100*time.Millisecond, "controller-readiness probe never cleared from engine")
}

func (suite *WebhookCRDIntegrationTestSuite) TearDownSuite() {
	if suite.cancel != nil {
		suite.cancel()
	}
	suite.wg.Wait()
	if suite.testEnv != nil {
		_ = suite.testEnv.Stop()
	}
}

func (suite *WebhookCRDIntegrationTestSuite) SetupTest() {
	suite.deleteAllPolicies()
}

func (suite *WebhookCRDIntegrationTestSuite) deleteAllPolicies() {
	var list policiesv1.PolicyList
	if err := suite.k8sClient.List(suite.ctx, &list); err != nil {
		return
	}
	for i := range list.Items {
		_ = suite.k8sClient.Delete(suite.ctx, &list.Items[i])
	}
	// Wait for the engine to drop CRD-derived policies before the next test.
	require.Eventually(suite.T(), func() bool {
		for _, p := range suite.engine.ListPolicies() {
			if policymanager.IsCRDDerivedID(p.ID) {
				return false
			}
		}
		return true
	}, webhookEventuallyTimeout, webhookEventuallyInterval)
}

// TestWebhookCRD_NewCRDChangesAdmissionDecision is the core regression test.
// A pod with the marker label is allowed before the CRD is applied, denied
// after it lands, and allowed again once it's deleted — proving the
// engineSink and reconciler actually drive enforcement, not just registry
// listings.
func (suite *WebhookCRDIntegrationTestSuite) TestWebhookCRD_NewCRDChangesAdmissionDecision() {
	// Step 1: Without any CRD, the marker pod should be ALLOWED. The bundled
	// defaults don't look at labels, and the pod is otherwise compliant
	// (non-privileged, non-:latest, runAsNonRoot).
	allowed, _ := suite.admitMarkerPod()
	require.True(suite.T(), allowed, "marker pod must be allowed before the CRD is applied (bundled defaults should not reject it)")

	// Step 2: Apply the CRD. The reconciler will compile-check, then
	// engine.LoadPolicy() will install it.
	enabled := true
	crd := &policiesv1.Policy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-marker", Namespace: "default"},
		Spec: policiesv1.PolicySpec{
			Description: "deny pods carrying the kube-policies-crd-test marker",
			Enabled:     &enabled,
			Rules: []policiesv1.PolicyRule{
				{Name: "deny-marker", Rego: crdDenyOnLabelRego},
			},
		},
	}
	require.NoError(suite.T(), suite.k8sClient.Create(suite.ctx, crd))

	// Step 3: Eventually the engine carries the new policy and admission
	// flips to DENY.
	require.Eventuallyf(suite.T(), func() bool {
		ok, _ := suite.admitMarkerPod()
		return !ok
	}, webhookEventuallyTimeout, webhookEventuallyInterval, "marker pod was never denied after CRD apply — engineSink did not propagate")

	// Step 4: Delete the CRD. The pod becomes allowed again once the engine
	// drops the policy.
	require.NoError(suite.T(), suite.k8sClient.Delete(suite.ctx, crd))
	require.Eventuallyf(suite.T(), func() bool {
		ok, _ := suite.admitMarkerPod()
		return ok
	}, webhookEventuallyTimeout, webhookEventuallyInterval, "marker pod was never re-allowed after CRD delete — engineSink did not propagate delete")
}

// TestWebhookCRD_UpdatePropagates verifies engine.LoadPolicy evicts cached
// prepared queries when the same CRD is updated with a different rule body.
func (suite *WebhookCRDIntegrationTestSuite) TestWebhookCRD_UpdatePropagates() {
	enabled := true

	// First version: denies pods labeled "v1".
	crd := &policiesv1.Policy{
		ObjectMeta: metav1.ObjectMeta{Name: "mutating-rule", Namespace: "default"},
		Spec: policiesv1.PolicySpec{
			Enabled: &enabled,
			Rules: []policiesv1.PolicyRule{
				{Name: "v1", Rego: `package kube_policies
import rego.v1
default evaluate := {"allowed": true}
evaluate := {"allowed": false, "message": "v1 match", "path": "labels"} if {
	input.object.metadata.labels["kube-policies-crd-test"] == "v1"
}
`},
			},
		},
	}
	require.NoError(suite.T(), suite.k8sClient.Create(suite.ctx, crd))

	// Wait until the v1 rule rejects v1-labeled pods.
	require.Eventuallyf(suite.T(), func() bool {
		ok, _ := suite.admitPodWithLabel("v1")
		return !ok
	}, webhookEventuallyTimeout, webhookEventuallyInterval, "v1 rule never installed")

	// v2-labeled pod must still be allowed under the v1 rule.
	ok, _ := suite.admitPodWithLabel("v2")
	assert.True(suite.T(), ok, "v2 pod should be allowed under the v1 rule")

	// Update the CRD to a rule that denies v2 instead of v1.
	var latest policiesv1.Policy
	require.NoError(suite.T(), suite.k8sClient.Get(suite.ctx, types.NamespacedName{Name: "mutating-rule", Namespace: "default"}, &latest))
	latest.Spec.Rules[0].Rego = `package kube_policies
import rego.v1
default evaluate := {"allowed": true}
evaluate := {"allowed": false, "message": "v2 match", "path": "labels"} if {
	input.object.metadata.labels["kube-policies-crd-test"] == "v2"
}
`
	require.NoError(suite.T(), suite.k8sClient.Update(suite.ctx, &latest))

	// After reconcile, v2 must be denied and v1 must be allowed again. This
	// is the prepared-query eviction we care about — without it the engine
	// would still match the old "v1" rule body.
	require.Eventuallyf(suite.T(), func() bool {
		v1ok, _ := suite.admitPodWithLabel("v1")
		v2ok, _ := suite.admitPodWithLabel("v2")
		return v1ok && !v2ok
	}, webhookEventuallyTimeout, webhookEventuallyInterval, "CRD update did not flip the deny target from v1 to v2")
}

// admitMarkerPod sends a /validate request for a compliant pod carrying the
// "kube-policies-crd-test: deny-me" marker label and returns (allowed,
// response-message).
func (suite *WebhookCRDIntegrationTestSuite) admitMarkerPod() (bool, string) {
	return suite.admitPodWithLabel("deny-me")
}

// admitPodWithLabel builds a compliant Pod with metadata.labels["kube-policies-crd-test"]
// set to the supplied value, then POSTs an admission review to the gin
// handler and returns the response's Allowed bit + message.
func (suite *WebhookCRDIntegrationTestSuite) admitPodWithLabel(labelValue string) (bool, string) {
	runAsNonRoot := true
	runAsUser := int64(1000)
	privileged := false

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "crd-test-pod",
			Namespace: "default",
			Labels:    map[string]string{"kube-policies-crd-test": labelValue},
		},
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: &runAsNonRoot,
				RunAsUser:    &runAsUser,
			},
			Containers: []corev1.Container{
				{
					Name:  "c",
					Image: "nginx:1.20",
					SecurityContext: &corev1.SecurityContext{
						RunAsNonRoot: &runAsNonRoot,
						RunAsUser:    &runAsUser,
						Privileged:   &privileged,
					},
				},
			},
		},
	}
	podBytes, err := json.Marshal(pod)
	require.NoError(suite.T(), err)

	review := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID:       types.UID("test-uid"),
			Operation: admissionv1.Create,
			Kind:      metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"},
			Namespace: "default",
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

// newEngineSinkForTest is the test's local accessor for the cmd/admission-webhook
// engineSink type. The constructor isn't exported (it lives in package main),
// so the test re-derives the same shape using the shared converter and the
// engine's public LoadPolicy/RemovePolicy methods.
func newEngineSinkForTest(engine *policy.Engine, log *zap.Logger) policymanager.PolicySink {
	return &testEngineSink{engine: engine, log: log}
}

type testEngineSink struct {
	engine *policy.Engine
	log    *zap.Logger
}

func (s *testEngineSink) UpsertPolicyFromCRD(crd *policiesv1.Policy) *policy.Policy {
	internal := policymanager.PolicyFromCRD(crd)
	if err := s.engine.LoadPolicy(internal); err != nil {
		s.log.Error("engine LoadPolicy failed", zap.String("id", internal.ID), zap.Error(err))
	}
	return internal
}

func (s *testEngineSink) RemovePolicyByID(id string) bool {
	return s.engine.RemovePolicy(id) == nil
}

func TestWebhookCRDIntegrationTestSuite(t *testing.T) {
	suite.Run(t, new(WebhookCRDIntegrationTestSuite))
}
