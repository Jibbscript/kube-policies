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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/Jibbscript/kube-policies/internal/config"
	"github.com/Jibbscript/kube-policies/internal/metrics"
	"github.com/Jibbscript/kube-policies/internal/policymanager"
	policiesv1 "github.com/Jibbscript/kube-policies/internal/policymanager/apis/policies/v1"
)

// PolicyManagerIntegrationTestSuite exercises the full CRD → controller →
// HTTP-API loop end-to-end. envtest spins up a real apiserver+etcd with the
// Policy and PolicyException CRDs installed; the policy-manager runs
// in-process pointed at that apiserver via controller-runtime; tests create
// CRDs via the typed client and assert the HTTP API reflects them after the
// reconciler runs.
//
// This is the canonical "is the operator working" suite — replacing the
// earlier HTTP-only suite that bypassed the reconciler entirely.
type PolicyManagerIntegrationTestSuite struct {
	suite.Suite

	testEnv       *envtest.Environment
	cfg           *rest.Config
	k8sClient     client.Client
	manager       *policymanager.Manager
	apiServer     *httptest.Server
	metricsServer *httptest.Server

	ctx          context.Context
	cancel       context.CancelFunc
	controllerWG sync.WaitGroup
}

// suiteMetricsOnce + suiteMetricsCollector gate the Prometheus collector
// registration so re-running the suite (test count > 1, or alongside other
// suites that also call metrics.NewCollector()) doesn't panic on duplicate
// descriptor registration. sharedMetricsCollector() is the public accessor;
// every test suite in this package must use it instead of calling
// metrics.NewCollector() directly.
var (
	suiteMetricsOnce      sync.Once
	suiteMetricsCollector *metrics.Collector
)

func sharedMetricsCollector() *metrics.Collector {
	suiteMetricsOnce.Do(func() {
		suiteMetricsCollector = metrics.NewCollector()
	})
	return suiteMetricsCollector
}

// eventuallyTimeout is the upper bound for a reconcile to land in the
// in-memory registry. On a healthy envtest the watch latency is ~50ms;
// pad generously for slow CI runners.
const (
	eventuallyTimeout  = 10 * time.Second
	eventuallyInterval = 100 * time.Millisecond
)

func (suite *PolicyManagerIntegrationTestSuite) SetupSuite() {
	suite.ctx, suite.cancel = context.WithCancel(context.TODO())

	// Start envtest. CRDDirectoryPaths makes envtest install both
	// policies.yaml and policyexceptions.yaml before the apiserver becomes
	// available, so the controller's typed clients can resolve the GVK on
	// startup.
	suite.testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{"../../deployments/kubernetes/crds"},
		ErrorIfCRDPathMissing: true,
	}

	cfg, err := suite.testEnv.Start()
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), cfg)
	suite.cfg = cfg

	// Build a typed Kubernetes client for the tests to use directly. The
	// scheme is the same one the controller uses, so Get/Create/Update/Delete
	// all round-trip through the same typed encoding.
	scheme := ctrl.GetConfigOrDie
	_ = scheme // keep import warm; we use the per-call scheme below
	k8sClient, err := client.New(cfg, client.Options{Scheme: nil})
	require.NoError(suite.T(), err)
	// Register our types on the default scheme so the client can address them.
	require.NoError(suite.T(), policiesv1.AddToScheme(k8sClient.Scheme()))
	// Recreate the client now that the scheme has our types.
	k8sClient, err = client.New(cfg, client.Options{Scheme: k8sClient.Scheme()})
	require.NoError(suite.T(), err)
	suite.k8sClient = k8sClient

	_ = sharedMetricsCollector()

	appCfg := &config.Config{
		Policy: config.PolicyConfig{FailureMode: "fail-closed"},
	}
	mgr, err := policymanager.NewManager(appCfg, zap.NewNop())
	require.NoError(suite.T(), err)
	suite.manager = mgr
	go mgr.Start(suite.ctx)

	// Run the CRD controllers pointed at the same envtest apiserver. The
	// goroutine exits when suite.cancel is called in TearDownSuite.
	suite.controllerWG.Add(1)
	go func() {
		defer suite.controllerWG.Done()
		_ = policymanager.StartControllers(suite.ctx, cfg, zap.NewNop(), policymanager.ControllerOptions{
			PolicySink:            mgr,
			ExceptionSink:         mgr,
			DisableLeaderElection: true,
		})
	}()

	suite.apiServer = httptest.NewServer(policymanager.NewAPIRouter(mgr))
	suite.metricsServer = httptest.NewServer(policymanager.NewMetricsRouter())
}

func (suite *PolicyManagerIntegrationTestSuite) TearDownSuite() {
	if suite.apiServer != nil {
		suite.apiServer.Close()
	}
	if suite.metricsServer != nil {
		suite.metricsServer.Close()
	}
	if suite.cancel != nil {
		suite.cancel()
	}
	suite.controllerWG.Wait()
	if suite.testEnv != nil {
		_ = suite.testEnv.Stop()
	}
}

// SetupTest deletes all CRD-derived Policy and PolicyException resources at
// the apiserver, then waits for the reconciler to clear them from the
// in-memory registry. Bundled defaults remain untouched.
func (suite *PolicyManagerIntegrationTestSuite) SetupTest() {
	suite.deleteAllCRDPolicies()
	suite.deleteAllCRDExceptions()

	require.Eventuallyf(suite.T(), func() bool {
		for _, p := range suite.listPoliciesViaAPI() {
			id, _ := p["id"].(string)
			if policymanager.IsCRDDerivedID(id) {
				return false
			}
		}
		for _, e := range suite.listExceptionsViaAPI() {
			id, _ := e["id"].(string)
			if policymanager.IsCRDDerivedID(id) {
				return false
			}
		}
		return true
	}, eventuallyTimeout, eventuallyInterval, "CRD-derived registry entries did not clear between tests")
}

// validRego is a syntactically valid Rego module matching the engine's
// data.kube_policies.evaluate contract — used wherever a test needs a rule
// that compiles but does nothing interesting.
const validRego = `package kube_policies

import rego.v1

default evaluate := {"allowed": true}
`

const privilegedRego = `package kube_policies

import rego.v1

default evaluate := {"allowed": true}

evaluate := {
	"allowed": false,
	"message": "Privileged containers are not allowed",
	"path": "spec.containers[0].securityContext.privileged",
} if {
	input.object.spec.containers[_].securityContext.privileged == true
}
`

const latestTagRego = `package kube_policies

import rego.v1

default evaluate := {"allowed": true}

evaluate := {
	"allowed": false,
	"message": "Latest image tag is not allowed",
	"path": "spec.containers[0].image",
} if {
	endswith(input.object.spec.containers[_].image, ":latest")
}
`

// TestPolicyManager_CreatePolicy creates a Policy CRD and asserts the HTTP
// API surfaces it after one reconcile pass.
func (suite *PolicyManagerIntegrationTestSuite) TestPolicyManager_CreatePolicy() {
	enabled := true
	policy := &policiesv1.Policy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "create-test",
			Namespace: "default",
		},
		Spec: policiesv1.PolicySpec{
			Description: "create-via-crd",
			Enabled:     &enabled,
			Severity:    "HIGH",
			Rules: []policiesv1.PolicyRule{
				{Name: "no-privileged-containers", Rego: privilegedRego, Severity: "HIGH"},
			},
		},
	}
	require.NoError(suite.T(), suite.k8sClient.Create(suite.ctx, policy))

	expectedID := policymanager.CRDPolicyID("default", "create-test")
	suite.eventuallyPolicyVisible(expectedID, func(p map[string]interface{}) bool {
		return p["name"] == "create-test"
	})
}

// TestPolicyManager_UpdatePolicy updates a Policy CRD's description and rule
// severity, then asserts both changes reach the HTTP API.
func (suite *PolicyManagerIntegrationTestSuite) TestPolicyManager_UpdatePolicy() {
	enabled := true
	policy := &policiesv1.Policy{
		ObjectMeta: metav1.ObjectMeta{Name: "update-test", Namespace: "default"},
		Spec: policiesv1.PolicySpec{
			Description: "initial",
			Enabled:     &enabled,
			Severity:    "MEDIUM",
			Rules: []policiesv1.PolicyRule{
				{Name: "no-privileged-containers", Rego: privilegedRego, Severity: "MEDIUM"},
			},
		},
	}
	require.NoError(suite.T(), suite.k8sClient.Create(suite.ctx, policy))

	expectedID := policymanager.CRDPolicyID("default", "update-test")
	suite.eventuallyPolicyVisible(expectedID, func(p map[string]interface{}) bool {
		return p["description"] == "initial"
	})

	// Re-fetch to get the latest resourceVersion, mutate, and Update.
	var latest policiesv1.Policy
	require.NoError(suite.T(), suite.k8sClient.Get(suite.ctx, types.NamespacedName{Name: "update-test", Namespace: "default"}, &latest))
	latest.Spec.Description = "updated"
	latest.Spec.Rules[0].Severity = "HIGH"
	require.NoError(suite.T(), suite.k8sClient.Update(suite.ctx, &latest))

	suite.eventuallyPolicyVisible(expectedID, func(p map[string]interface{}) bool {
		if p["description"] != "updated" {
			return false
		}
		rules, ok := p["rules"].([]interface{})
		if !ok || len(rules) == 0 {
			return false
		}
		first, _ := rules[0].(map[string]interface{})
		return first["severity"] == "HIGH"
	})
}

// TestPolicyManager_DeletePolicy creates a CRD, waits for it to appear,
// deletes it, and asserts the registry drops it.
func (suite *PolicyManagerIntegrationTestSuite) TestPolicyManager_DeletePolicy() {
	enabled := true
	policy := &policiesv1.Policy{
		ObjectMeta: metav1.ObjectMeta{Name: "delete-test", Namespace: "default"},
		Spec: policiesv1.PolicySpec{
			Enabled: &enabled,
			Rules: []policiesv1.PolicyRule{
				{Name: "no-privileged-containers", Rego: privilegedRego},
			},
		},
	}
	require.NoError(suite.T(), suite.k8sClient.Create(suite.ctx, policy))

	expectedID := policymanager.CRDPolicyID("default", "delete-test")
	suite.eventuallyPolicyVisible(expectedID, nil)

	require.NoError(suite.T(), suite.k8sClient.Delete(suite.ctx, policy))

	require.Eventuallyf(suite.T(), func() bool {
		return !suite.policyExistsByID(expectedID)
	}, eventuallyTimeout, eventuallyInterval, "deleted Policy CRD did not disappear from /api/v1/policies")
}

// TestPolicyManager_PolicyException creates a PolicyException CRD and asserts
// the registry exposes it via /api/v1/exceptions.
func (suite *PolicyManagerIntegrationTestSuite) TestPolicyManager_PolicyException() {
	exception := &policiesv1.PolicyException{
		ObjectMeta: metav1.ObjectMeta{Name: "test-exception", Namespace: "default"},
		Spec: policiesv1.PolicyExceptionSpec{
			Description:   "Emergency carve-out",
			PolicyID:      "security-baseline",
			RuleID:        "no-privileged-containers",
			Justification: "Emergency deployment",
			Scope: policiesv1.PolicyExceptionScope{
				Namespaces: []string{"default"},
				Resources:  []string{"pods"},
			},
		},
	}
	require.NoError(suite.T(), suite.k8sClient.Create(suite.ctx, exception))

	expectedID := policymanager.CRDExceptionID("default", "test-exception")
	require.Eventuallyf(suite.T(), func() bool {
		for _, e := range suite.listExceptionsViaAPI() {
			if e["id"] == expectedID {
				return e["policy_id"] == "security-baseline" && e["justification"] == "Emergency deployment"
			}
		}
		return false
	}, eventuallyTimeout, eventuallyInterval, "PolicyException CRD did not surface on /api/v1/exceptions")
}

// TestPolicyManager_PolicyValidation drives the /api/v1/policies/validate
// endpoint directly — it's an RPC, not a CRD operation, so it stays HTTP.
// This proves the Rego-compile path agrees with the controller's compile gate.
func (suite *PolicyManagerIntegrationTestSuite) TestPolicyManager_PolicyValidation() {
	invalid := suite.sendPolicyValidationRequest(map[string]interface{}{
		"name":  "invalid",
		"rules": []map[string]interface{}{{"name": "r", "rego": "invalid rego {{{"}},
	})
	assert.False(suite.T(), invalid["valid"].(bool))
	errMsg, _ := invalid["error"].(string)
	assert.True(suite.T(), strings.Contains(errMsg, "syntax") || strings.Contains(errMsg, "rego"),
		"validate error should mention syntax/rego (got %q)", errMsg)

	valid := suite.sendPolicyValidationRequest(map[string]interface{}{
		"name":  "valid",
		"rules": []map[string]interface{}{{"name": "r", "rego": validRego}},
	})
	assert.True(suite.T(), valid["valid"].(bool), "valid Rego should pass validation: %v", valid)
}

// TestPolicyManager_PolicyEvaluation drives /api/v1/policies/evaluate with an
// inline resource+policy. CRDs aren't involved — this is the ad-hoc
// "evaluate before commit" path for CI/playground.
func (suite *PolicyManagerIntegrationTestSuite) TestPolicyManager_PolicyEvaluation() {
	request := map[string]interface{}{
		"resource": map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata":   map[string]interface{}{"name": "test-pod", "namespace": "default"},
			"spec": map[string]interface{}{
				"containers": []interface{}{
					map[string]interface{}{
						"name":            "c",
						"image":           "nginx:latest",
						"securityContext": map[string]interface{}{"privileged": true},
					},
				},
			},
		},
		"policy": map[string]interface{}{
			"id":      "eval-adhoc",
			"name":    "eval-adhoc",
			"enabled": true,
			"rules": []map[string]interface{}{
				{"id": "no-privileged", "name": "no-privileged", "rego": privilegedRego},
				{"id": "no-latest-tag", "name": "no-latest-tag", "rego": latestTagRego},
			},
		},
	}
	response := suite.sendPolicyEvaluationRequest(request)
	violations, ok := response["violations"].([]interface{})
	require.True(suite.T(), ok, "violations must decode as a JSON array (got %T)", response["violations"])
	require.Len(suite.T(), violations, 2)

	messages := make([]string, len(violations))
	for i, v := range violations {
		messages[i] = v.(string)
	}
	assert.Contains(suite.T(), messages, "Privileged containers are not allowed")
	assert.Contains(suite.T(), messages, "Latest image tag is not allowed")
	assert.Equal(suite.T(), false, response["allowed"])
	assert.Equal(suite.T(), "DENY", response["decision"])
}

// TestPolicyManager_Metrics asserts the descriptors Prometheus emits on /metrics.
// See the previous test-suite incarnation for the full reasoning on why
// CounterVec descriptors aren't asserted here — they only appear after first Inc().
func (suite *PolicyManagerIntegrationTestSuite) TestPolicyManager_Metrics() {
	metricsResponse := suite.getMetricsFromManager()
	assert.Contains(suite.T(), metricsResponse, "kube_policies_policy_loaded_total")
	assert.Contains(suite.T(), metricsResponse, "kube_policies_audit_buffer_size")
	assert.Contains(suite.T(), metricsResponse, "kube_policies_webhook_decision_publish_dropped_total")
}

// TestPolicyManager_HealthCheck verifies the HTTP server's liveness probe.
func (suite *PolicyManagerIntegrationTestSuite) TestPolicyManager_HealthCheck() {
	healthResponse := suite.getHealthFromManager()
	assert.Equal(suite.T(), "healthy", healthResponse["status"])
}

// TestPolicyManager_ConcurrentOperations creates many Policy CRDs in parallel
// and asserts every one of them surfaces on the HTTP API, proving the
// reconciler scales across concurrent watch events.
func (suite *PolicyManagerIntegrationTestSuite) TestPolicyManager_ConcurrentOperations() {
	numGoroutines := 5
	numPoliciesPerGoroutine := 3
	type result struct {
		err error
		id  string
	}
	results := make(chan result, numGoroutines*numPoliciesPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		go func(g int) {
			for j := 0; j < numPoliciesPerGoroutine; j++ {
				name := fmt.Sprintf("concurrent-%d-%d", g, j)
				enabled := true
				p := &policiesv1.Policy{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
					Spec: policiesv1.PolicySpec{
						Description: name,
						Enabled:     &enabled,
						Rules: []policiesv1.PolicyRule{
							{Name: "r", Rego: validRego},
						},
					},
				}
				if err := suite.k8sClient.Create(suite.ctx, p); err != nil {
					results <- result{err: err}
					continue
				}
				results <- result{id: policymanager.CRDPolicyID("default", name)}
			}
		}(i)
	}

	createdIDs := make([]string, 0, numGoroutines*numPoliciesPerGoroutine)
	errorCount := 0
	for i := 0; i < numGoroutines*numPoliciesPerGoroutine; i++ {
		r := <-results
		if r.err != nil {
			errorCount++
			suite.T().Logf("concurrent create error: %v", r.err)
			continue
		}
		createdIDs = append(createdIDs, r.id)
	}
	assert.Less(suite.T(), errorCount, numGoroutines*numPoliciesPerGoroutine/2, "too many create failures")

	// Every successfully-created CRD must reconcile into the registry.
	for _, id := range createdIDs {
		suite.eventuallyPolicyVisible(id, nil)
	}
}

// TestPolicyManager_InvalidRegoRejected confirms the CRD reconciler enforces
// the same Rego compile check as /api/v1/policies/validate — a malformed CRD
// must NOT land in the registry, even though apiserver-level OpenAPI
// validation accepted it.
func (suite *PolicyManagerIntegrationTestSuite) TestPolicyManager_InvalidRegoRejected() {
	enabled := true
	bad := &policiesv1.Policy{
		ObjectMeta: metav1.ObjectMeta{Name: "bad-rego", Namespace: "default"},
		Spec: policiesv1.PolicySpec{
			Enabled: &enabled,
			Rules: []policiesv1.PolicyRule{
				{Name: "broken", Rego: "this is not valid rego {{{"},
			},
		},
	}
	require.NoError(suite.T(), suite.k8sClient.Create(suite.ctx, bad))

	expectedID := policymanager.CRDPolicyID("default", "bad-rego")
	// Allow the controller a moment to process the create + reject it.
	require.Eventuallyf(suite.T(), func() bool {
		// The CRD itself should still exist (the reconciler doesn't delete
		// the user's resource; it just declines to publish to the registry
		// and marks status.Ready=False).
		var crd policiesv1.Policy
		err := suite.k8sClient.Get(suite.ctx, types.NamespacedName{Name: "bad-rego", Namespace: "default"}, &crd)
		if apierrors.IsNotFound(err) {
			return false
		}
		// The registry must NOT include the broken policy.
		return !suite.policyExistsByID(expectedID)
	}, eventuallyTimeout, eventuallyInterval, "broken-Rego CRD was incorrectly published to the registry")
}

// ----------------- Helpers -----------------

func (suite *PolicyManagerIntegrationTestSuite) eventuallyPolicyVisible(id string, predicate func(map[string]interface{}) bool) {
	require.Eventuallyf(suite.T(), func() bool {
		for _, p := range suite.listPoliciesViaAPI() {
			if p["id"] != id {
				continue
			}
			if predicate == nil {
				return true
			}
			return predicate(p)
		}
		return false
	}, eventuallyTimeout, eventuallyInterval, "policy %s never satisfied the predicate", id)
}

func (suite *PolicyManagerIntegrationTestSuite) policyExistsByID(id string) bool {
	for _, p := range suite.listPoliciesViaAPI() {
		if p["id"] == id {
			return true
		}
	}
	return false
}

func (suite *PolicyManagerIntegrationTestSuite) listPoliciesViaAPI() []map[string]interface{} {
	resp, err := http.Get(suite.apiServer.URL + "/api/v1/policies")
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	var response map[string]interface{}
	require.NoError(suite.T(), json.NewDecoder(resp.Body).Decode(&response))
	raw, ok := response["policies"].([]interface{})
	if !ok {
		return nil
	}
	result := make([]map[string]interface{}, 0, len(raw))
	for _, p := range raw {
		if m, ok := p.(map[string]interface{}); ok {
			result = append(result, m)
		}
	}
	return result
}

func (suite *PolicyManagerIntegrationTestSuite) listExceptionsViaAPI() []map[string]interface{} {
	resp, err := http.Get(suite.apiServer.URL + "/api/v1/exceptions")
	require.NoError(suite.T(), err)
	defer resp.Body.Close()

	var response map[string]interface{}
	require.NoError(suite.T(), json.NewDecoder(resp.Body).Decode(&response))
	raw, ok := response["exceptions"].([]interface{})
	if !ok {
		return nil
	}
	result := make([]map[string]interface{}, 0, len(raw))
	for _, e := range raw {
		if m, ok := e.(map[string]interface{}); ok {
			result = append(result, m)
		}
	}
	return result
}

func (suite *PolicyManagerIntegrationTestSuite) sendPolicyValidationRequest(p map[string]interface{}) map[string]interface{} {
	body, err := json.Marshal(p)
	require.NoError(suite.T(), err)
	resp, err := http.Post(suite.apiServer.URL+"/api/v1/policies/validate", "application/json", bytes.NewReader(body))
	require.NoError(suite.T(), err)
	defer resp.Body.Close()
	var out map[string]interface{}
	require.NoError(suite.T(), json.NewDecoder(resp.Body).Decode(&out))
	return out
}

func (suite *PolicyManagerIntegrationTestSuite) sendPolicyEvaluationRequest(req map[string]interface{}) map[string]interface{} {
	body, err := json.Marshal(req)
	require.NoError(suite.T(), err)
	resp, err := http.Post(suite.apiServer.URL+"/api/v1/policies/evaluate", "application/json", bytes.NewReader(body))
	require.NoError(suite.T(), err)
	defer resp.Body.Close()
	require.Equal(suite.T(), http.StatusOK, resp.StatusCode, "evaluate should return 200")
	var out map[string]interface{}
	require.NoError(suite.T(), json.NewDecoder(resp.Body).Decode(&out))
	return out
}

func (suite *PolicyManagerIntegrationTestSuite) getMetricsFromManager() string {
	resp, err := http.Get(suite.metricsServer.URL + "/metrics")
	require.NoError(suite.T(), err)
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, err = buf.ReadFrom(resp.Body)
	require.NoError(suite.T(), err)
	return buf.String()
}

func (suite *PolicyManagerIntegrationTestSuite) getHealthFromManager() map[string]interface{} {
	resp, err := http.Get(suite.apiServer.URL + "/healthz")
	require.NoError(suite.T(), err)
	defer resp.Body.Close()
	var out map[string]interface{}
	require.NoError(suite.T(), json.NewDecoder(resp.Body).Decode(&out))
	return out
}

// deleteAllCRDPolicies removes every Policy in the cluster. Use only in
// SetupTest — never in tests that need controlled cleanup.
func (suite *PolicyManagerIntegrationTestSuite) deleteAllCRDPolicies() {
	var list policiesv1.PolicyList
	if err := suite.k8sClient.List(suite.ctx, &list); err != nil {
		return
	}
	for i := range list.Items {
		_ = suite.k8sClient.Delete(suite.ctx, &list.Items[i])
	}
}

func (suite *PolicyManagerIntegrationTestSuite) deleteAllCRDExceptions() {
	var list policiesv1.PolicyExceptionList
	if err := suite.k8sClient.List(suite.ctx, &list); err != nil {
		return
	}
	for i := range list.Items {
		_ = suite.k8sClient.Delete(suite.ctx, &list.Items[i])
	}
}

func TestPolicyManagerIntegrationTestSuite(t *testing.T) {
	suite.Run(t, new(PolicyManagerIntegrationTestSuite))
}
