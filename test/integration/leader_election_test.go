package integration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	coordinationv1 "k8s.io/api/coordination/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/Jibbscript/kube-policies/internal/policy"
	"github.com/Jibbscript/kube-policies/internal/policymanager"
	policiesv1 "github.com/Jibbscript/kube-policies/internal/policymanager/apis/policies/v1"
)

// LeaderElectionIntegrationTestSuite proves that StartControllers honors the
// zero-value DisableLeaderElection contract: when election is enabled (the
// default), exactly one manager acquires the coordination.k8s.io/v1 Lease and
// holds it while a second manager stays as follower.
//
// Tests in this suite reuse the shared TestMain logger bridge (wired in
// setup_test.go) so that controller-runtime's leader-election log lines flow
// through the klog→zap pipeline and can be inspected via stdout capture.
type LeaderElectionIntegrationTestSuite struct {
	suite.Suite

	testEnv   *envtest.Environment
	cfg       *rest.Config
	k8sClient client.Client

	// Suite-level context; each test derives a child context so it can cancel
	// its own manager goroutine without affecting sibling tests.
	ctx    context.Context
	cancel context.CancelFunc
}

func (suite *LeaderElectionIntegrationTestSuite) SetupSuite() {
	suite.ctx, suite.cancel = context.WithCancel(context.TODO())

	// Install the Policy and PolicyException CRDs so controller-runtime's
	// informer cache can bootstrap successfully — the reconcilers reference
	// these types even in tests that don't exercise reconciliation.
	suite.testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{"../../deployments/kubernetes/crds"},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := suite.testEnv.Start()
	require.NoError(suite.T(), err)
	require.NotNil(suite.T(), cfg)
	suite.cfg = cfg

	// Build a typed client that can read coordination.k8s.io/v1 Lease objects.
	// clientgoscheme.AddToScheme registers all built-in k8s types (including
	// coordination) so a single scheme covers both Lease reads and the internal
	// Policy/PolicyException types the reconciler registers.
	scheme := runtime.NewScheme()
	require.NoError(suite.T(), clientgoscheme.AddToScheme(scheme))
	require.NoError(suite.T(), policiesv1.AddToScheme(scheme))
	k8sClient, err := client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(suite.T(), err)
	suite.k8sClient = k8sClient
}

func (suite *LeaderElectionIntegrationTestSuite) TearDownSuite() {
	if suite.cancel != nil {
		suite.cancel()
	}
	if suite.testEnv != nil {
		_ = suite.testEnv.Stop()
	}
}

// TestLeaderElection_SingleManagerAcquiresLease starts one manager with the
// zero-value ControllerOptions (DisableLeaderElection=false → election ON) and
// asserts that the coordination.k8s.io/v1 Lease named by LeaderElectionID is
// created and held within 10 seconds.
//
// A secondary assertion verifies that the logger bridge established in
// TestMain continues to route controller-runtime leader-election log lines
// through the klog→zap pipeline and out as structured JSON on stdout —
// proving the two features compose correctly.
func (suite *LeaderElectionIntegrationTestSuite) TestLeaderElection_SingleManagerAcquiresLease() {
	const (
		leaseID = "test-le-single"
		leaseNS = "default"
	)

	// Capture stdout before starting the manager so leader-election log lines
	// emitted through the klog→zap bridge are included.
	stdoutBuf, restoreStdout := captureStdout(suite.T())
	defer restoreStdout()

	ctx, cancel := context.WithCancel(suite.ctx)
	defer cancel()

	var wg sync.WaitGroup
	// Zero-value DisableLeaderElection → election ENABLED.
	wg.Go(func() {
		err := policymanager.StartControllers(ctx, suite.cfg, zap.NewNop(), policymanager.ControllerOptions{
			PolicySink:              &noopSink{},
			LeaderElectionNamespace: leaseNS,
			LeaderElectionID:        leaseID,
		})
		if err != nil && ctx.Err() == nil {
			suite.T().Logf("StartControllers returned unexpected error: %v", err)
		}
	})

	// Assert the Lease CR is created and its holderIdentity is set within 10s.
	require.Eventuallyf(suite.T(), func() bool {
		var lease coordinationv1.Lease
		if err := suite.k8sClient.Get(suite.ctx, types.NamespacedName{Name: leaseID, Namespace: leaseNS}, &lease); err != nil {
			return false
		}
		return lease.Spec.HolderIdentity != nil && *lease.Spec.HolderIdentity != ""
	}, 10*time.Second, 250*time.Millisecond,
		"Lease %s/%s was not acquired within 10s — zero-value DisableLeaderElection must enable election", leaseNS, leaseID)

	// Stop the manager before draining stdout so we collect the full output.
	cancel()
	wg.Wait()
	_ = sharedLogger.Sync()
	restoreStdout()

	// Inspect captured output. The primary assertion is that the logger bridge
	// produced at least one JSON line with both service and caller fields —
	// proving that controller-runtime's internal logs flow through the pipeline.
	// A secondary (advisory) check looks for a message containing an "acqui*"
	// or "leader" keyword as evidence that election traffic specifically was
	// bridged; the exact text is not part of controller-runtime's public API.
	sawStructuredLine := false
	sawLeaderLine := false
	leaderRe := regexp.MustCompile(`(?i)(acqui|leader)`)

	scanner := bufio.NewScanner(bytes.NewReader(stdoutBuf.Bytes()))
	for scanner.Scan() {
		var rec map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			continue
		}
		if rec["service"] == nil || rec["caller"] == nil {
			continue
		}
		sawStructuredLine = true
		if msg, _ := rec["message"].(string); leaderRe.MatchString(msg) {
			sawLeaderLine = true
		}
	}

	require.True(suite.T(), sawStructuredLine,
		"expected at least one JSON log line with service+caller from the leader-election run; "+
			"this indicates the klog→zap bridge is not routing controller-runtime logs")
	if !sawLeaderLine {
		suite.T().Logf("advisory: no 'acqui*'/'leader' message found in captured output; " +
			"controller-runtime may use different wording in v0.21.0 — service+caller assertion passed")
	}
}

// TestLeaderElection_TwoManagersOnlyOneLeader starts two managers that compete
// for the same Lease. It asserts that:
//
//  1. Exactly one manager acquires the Lease (holderIdentity is set) within 10s.
//  2. The holderIdentity does not change for the following 5s — the losing
//     manager stays as follower and never steals leadership.
//
// The Lease-CR observation strategy is used: no internal Runnable is needed,
// keeping the test independent of controller-runtime internals.
func (suite *LeaderElectionIntegrationTestSuite) TestLeaderElection_TwoManagersOnlyOneLeader() {
	const (
		leaseID = "test-le-two"
		leaseNS = "default"
	)

	ctx, cancel := context.WithCancel(suite.ctx)
	defer cancel()

	var wg sync.WaitGroup

	// Start two managers simultaneously; both compete for the same Lease.
	// Use zap.NewNop() to keep the test log quiet — the Lease CR is the
	// source of truth, not log messages.
	for i := range 2 {
		wg.Go(func() {
			err := policymanager.StartControllers(ctx, suite.cfg, zap.NewNop(), policymanager.ControllerOptions{
				PolicySink:              &noopSink{},
				LeaderElectionNamespace: leaseNS,
				LeaderElectionID:        leaseID,
				// DisableLeaderElection: zero value (false) → election ENABLED
			})
			if err != nil && ctx.Err() == nil {
				suite.T().Logf("manager %d StartControllers error: %v", i, err)
			}
		})
	}

	// Step 1: assert one manager acquires the Lease within 10s.
	var firstHolder string
	require.Eventuallyf(suite.T(), func() bool {
		var lease coordinationv1.Lease
		if err := suite.k8sClient.Get(suite.ctx, types.NamespacedName{Name: leaseID, Namespace: leaseNS}, &lease); err != nil {
			return false
		}
		if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity == "" {
			return false
		}
		firstHolder = *lease.Spec.HolderIdentity
		return true
	}, 10*time.Second, 250*time.Millisecond,
		"Lease %s/%s was not acquired by any manager within 10s", leaseNS, leaseID)

	suite.T().Logf("leader acquired: holderIdentity=%q", firstHolder)

	// Step 2: assert the holder does not change for 5s — the follower manager
	// must not steal the Lease while the leader is healthy.
	require.Never(suite.T(), func() bool {
		var lease coordinationv1.Lease
		if err := suite.k8sClient.Get(suite.ctx, types.NamespacedName{Name: leaseID, Namespace: leaseNS}, &lease); err != nil {
			return false
		}
		if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity == "" {
			return false
		}
		return *lease.Spec.HolderIdentity != firstHolder
	}, 5*time.Second, 500*time.Millisecond,
		"Lease holder changed within 5s — more than one manager acquired leadership (firstHolder=%q)", firstHolder)

	cancel()
	wg.Wait()
}

// TestLeaderElectionIntegrationTestSuite is the testify entry-point.
func TestLeaderElectionIntegrationTestSuite(t *testing.T) {
	suite.Run(t, new(LeaderElectionIntegrationTestSuite))
}

// noopSink satisfies policymanager.PolicySink by discarding all operations.
// Used in leader-election tests where the reconciler behavior is not under
// test — only the leader-election machinery matters.
type noopSink struct{}

func (n *noopSink) UpsertPolicyFromCRD(*policiesv1.Policy) *policy.Policy { return nil }
func (n *noopSink) RemovePolicyByID(string) bool                          { return false }
