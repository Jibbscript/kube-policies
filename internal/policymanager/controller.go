package policymanager

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	configv1alpha1 "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/Jibbscript/kube-policies/internal/audit"
	"github.com/Jibbscript/kube-policies/internal/policy"
	policiesv1 "github.com/Jibbscript/kube-policies/internal/policymanager/apis/policies/v1"
)

// PolicySink is the contract a target registry implements so a
// PolicyReconciler can push CRD-driven Policy changes into it. The
// policy-manager's *Manager satisfies this for its in-memory registry, and
// the admission-webhook wraps its OPA *policy.Engine in a thin adapter that
// also satisfies it (see cmd/admission-webhook/main.go).
//
// Upsert returns the converted internal Policy so callers can use it for
// status updates or telemetry.
type PolicySink interface {
	UpsertPolicyFromCRD(*policiesv1.Policy) *policy.Policy
	RemovePolicyByID(string) bool
}

// ExceptionSink is the optional counterpart of PolicySink for
// PolicyException CRDs. Pass nil when the caller (currently the
// admission-webhook engine) does not consume exceptions — the controller
// manager simply skips wiring the exception reconciler.
//
// NAMING NOTE: "Sink" reflects the write-side contract (CRD upserts/removes
// flow IN). An implementation MAY also satisfy `policy.ExceptionRegistry`
// (the read-side contract consumed by the admission engine) — the
// admission-webhook's `cmd/admission-webhook/exception_sink.go` is the
// canonical dual-interface example. The two interfaces live in separate
// packages on purpose so neither side depends on the other.
type ExceptionSink interface {
	UpsertExceptionFromCRD(*policiesv1.PolicyException) *Exception
	RemoveExceptionByID(string) bool
}

// ControllerOptions configures StartControllers. PolicySink is required;
// ExceptionSink is optional — pass nil to skip exception watching when the
// caller has no use for them (e.g. the admission engine).
type ControllerOptions struct {
	// PolicySink receives CRD-driven Policy updates. Required.
	PolicySink PolicySink

	// ExceptionSink receives CRD-driven PolicyException updates. Optional —
	// nil disables exception reconciliation. The policy-manager passes its
	// *Manager; the admission-webhook passes nil because the engine has no
	// exception code path yet.
	ExceptionSink ExceptionSink

	// DisableLeaderElection opts out of controller-runtime's Lease-based leader
	// election (coordination.k8s.io/Lease, the default for controller-runtime
	// ≥ v0.7). The zero value enables election so multi-replica deployments are
	// safe by default. Set true only for single-process scenarios where
	// contention is impossible (e.g. envtest unit suites).
	DisableLeaderElection bool

	// LeaderElectionNamespace is the namespace the Lease resource is created in
	// when leader election is enabled (i.e. DisableLeaderElection=false).
	// Required when leader election is enabled.
	LeaderElectionNamespace string

	// LeaderElectionID is the lease name. Defaults to
	// "kube-policies-policy-manager" when empty as a defensive fallback.
	// Production callers MUST set this explicitly — two embedders sharing the
	// default contend over the same lease.
	LeaderElectionID string

	// LeaderlessReconcilers makes the embedded Policy/PolicyException
	// reconcilers run on every pod (NeedLeaderElection=false) while the
	// manager itself still acquires the leader-election lease. Set this for
	// embedders whose reconciler's job is to populate a per-pod local cache
	// — the admission-webhook in particular MUST set this true, otherwise
	// only the leader's local OPA engine receives Policy CRD updates and
	// admission requests load-balanced to follower pods bypass policy
	// enforcement. The status-patch races between replicas are benign:
	// every replica writes the same Phase/Conditions for the same CRD spec.
	// Leave false for policy-manager, whose reconciler owns the
	// cluster-wide registry state and should run on the leader only.
	LeaderlessReconcilers bool

	// MaxConcurrentReconciles bounds the number of concurrent Reconcile calls per
	// reconciler (RES-WU-17, DoS protection). controller-runtime defaults to 1;
	// a small bound (e.g. 2) keeps a CRD-apply storm from spawning unbounded
	// goroutines while still allowing modest parallelism. <= 0 falls back to the
	// defensive default of 2 so an unset value is never an unbounded worker pool.
	MaxConcurrentReconciles int

	// AuditLogger records a reconcile-driven ConfigurationChange / system event
	// for every CRD create/update/delete and exception expiry (AUD-WU-12,
	// AU-2/AU-12). It is OPTIONAL and NIL-SAFE: a nil logger makes every audit
	// emission a no-op, so embedders that do not audit reconciles (the
	// admission-webhook, which already passes nil here) compile and run
	// unchanged. The policy-manager threads its own *audit.Logger so CRD-driven
	// registry changes are attributed to the controller service account.
	AuditLogger *audit.Logger

	// ControllerNamespace is the namespace the controller service account runs
	// in; it is woven into the synthesized controlling identity recorded on
	// reconcile audit events (Username
	// "system:serviceaccount:<ns>:kube-policies-controller"). Empty falls back to
	// "kube-system" only as a defensive last resort — production callers set it
	// to the pod namespace (the same value used for LeaderElectionNamespace).
	ControllerNamespace string
}

// defaultMaxConcurrentReconciles is the bound applied when
// ControllerOptions.MaxConcurrentReconciles is unset (<= 0). It caps the
// per-reconciler worker pool so a flood of CRD changes cannot exhaust process
// resources (RES-WU-17).
const defaultMaxConcurrentReconciles = 2

// StartControllers builds and starts a controller-runtime Manager that
// watches Policy CRDs (always) and PolicyException CRDs (when opts.ExceptionSink
// is non-nil), pushing reconciled state into the supplied sinks. The function
// blocks until ctx is canceled or the controller manager exits with an error.
//
// cfg should normally be obtained via ctrl.GetConfigOrDie() so the calling
// binary uses the in-cluster service-account credentials in production and
// a kubeconfig file under development.
//
// The returned error wraps any failure from manager.New / Reconciler.Setup /
// manager.Start; callers in main.go log fatal on it.
func StartControllers(ctx context.Context, cfg *rest.Config, log *zap.Logger, opts ControllerOptions) error {
	if opts.PolicySink == nil {
		return fmt.Errorf("ControllerOptions.PolicySink is required")
	}
	scheme := runtime.NewScheme()
	// Register the core k8s types so the client can address Lease resources for
	// leader election. Without this, leader election would panic on first run.
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return fmt.Errorf("register core scheme: %w", err)
	}
	if err := policiesv1.AddToScheme(scheme); err != nil {
		return fmt.Errorf("register policies.kube-policies.io scheme: %w", err)
	}

	if opts.LeaderElectionID == "" {
		opts.LeaderElectionID = "kube-policies-policy-manager"
	}

	effectiveLeaderElection := !opts.DisableLeaderElection
	if effectiveLeaderElection && opts.LeaderElectionNamespace == "" {
		return fmt.Errorf("LeaderElectionNamespace is required when leader election is enabled; call policymanager.ResolvePodNamespace from your binary or set DisableLeaderElection: true for test/single-process scenarios")
	}

	// SkipNameValidation = true disables controller-runtime's process-wide
	// uniqueness check on controller names. The check exists to prevent two
	// controllers in the SAME manager from registering the same Prometheus
	// metric — but we disable the metrics server above (BindAddress: "0"),
	// so the check gives us no value and actively breaks the case where two
	// independent managers (policy-manager + admission-webhook, or two test
	// suites in the same `go test` binary) each spin up a reconciler with
	// the canonical "policy"/"policyexception" name.
	skipNameValidation := true
	// Root logger is wired in cmd/*/main.go via logger.SetControllerRuntimeLogger;
	// we deliberately do NOT call ctrl.SetLogger from here so library callers
	// retain control of global state and integration tests can mount this manager
	// multiple times under a single shared wiring established in TestMain.
	mgr, err := manager.New(cfg, manager.Options{
		Scheme: scheme,
		// The calling binary (policy-manager or admission-webhook) already
		// exposes its own /metrics endpoint; disable controller-runtime's
		// own metrics listener to avoid port contention.
		Metrics: metricsserver.Options{BindAddress: "0"},
		// Health probes are served by the calling binary, not this embedded
		// controller manager.
		HealthProbeBindAddress:        "0",
		LeaderElection:                effectiveLeaderElection,
		LeaderElectionID:              opts.LeaderElectionID,
		LeaderElectionNamespace:       opts.LeaderElectionNamespace,
		LeaderElectionReleaseOnCancel: true,
		Controller: configv1alpha1.Controller{
			SkipNameValidation: &skipNameValidation,
		},
	})
	if err != nil {
		return fmt.Errorf("build controller manager: %w", err)
	}

	// Bound the per-reconciler worker pool (RES-WU-17). An unset/non-positive
	// value falls back to the defensive default so a CRD-apply storm cannot spawn
	// an unbounded number of concurrent Reconcile goroutines.
	maxConcurrent := opts.MaxConcurrentReconciles
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrentReconciles
	}

	// Synthesized controlling identity recorded on reconcile-driven audit events
	// (AUD-WU-12). It is the controller service account, not a human principal —
	// CRD reconciliation is a system actor. ControllerNamespace falls back to
	// kube-system only defensively; production callers set it to the pod namespace.
	controllerNS := opts.ControllerNamespace
	if controllerNS == "" {
		controllerNS = "kube-system"
	}
	controllerIdentity := authenticationv1.UserInfo{
		Username: fmt.Sprintf("system:serviceaccount:%s:kube-policies-controller", controllerNS),
		Groups:   []string{"system:serviceaccounts", "system:serviceaccounts:" + controllerNS},
	}

	policyReconciler := &PolicyReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Sink:     opts.PolicySink,
		Log:      log.Named("policy-reconciler"),
		Audit:    opts.AuditLogger,
		Identity: controllerIdentity,
	}
	if err := policyReconciler.SetupWithManager(mgr, opts.LeaderlessReconcilers, maxConcurrent); err != nil {
		return fmt.Errorf("setup Policy reconciler: %w", err)
	}

	if opts.ExceptionSink != nil {
		exceptionReconciler := &PolicyExceptionReconciler{
			Client:   mgr.GetClient(),
			Scheme:   mgr.GetScheme(),
			Sink:     opts.ExceptionSink,
			Log:      log.Named("exception-reconciler"),
			Audit:    opts.AuditLogger,
			Identity: controllerIdentity,
		}
		if err := exceptionReconciler.SetupWithManager(mgr, opts.LeaderlessReconcilers, maxConcurrent); err != nil {
			return fmt.Errorf("setup PolicyException reconciler: %w", err)
		}
	}

	log.Info("starting CRD controllers",
		zap.Bool("leader_election", effectiveLeaderElection),
		zap.Bool("leaderless_reconcilers", opts.LeaderlessReconcilers),
		zap.Bool("exception_reconciler_enabled", opts.ExceptionSink != nil),
		zap.Int("max_concurrent_reconciles", maxConcurrent),
	)
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("controller manager exited: %w", err)
	}
	return nil
}

// PolicyReconciler watches policies.kube-policies.io/v1 Policy resources and
// pushes them into the supplied PolicySink. Deletes are handled by the
// NotFound branch — controller-runtime doesn't deliver explicit Delete
// events to Reconcile().
type PolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Sink   PolicySink
	Log    *zap.Logger
	// Audit records a reconcile-driven ConfigurationChange for every CRD
	// create/update/delete (AUD-WU-12, AU-2/AU-12). Optional and nil-safe: nil
	// makes auditReconcile a no-op so embedders that pass no logger are
	// unaffected.
	Audit *audit.Logger
	// Identity is the synthesized controller service-account UserInfo recorded
	// on the audit events emitted by this reconciler.
	Identity authenticationv1.UserInfo
}

// Reconcile is the controller-runtime entry point. The reconcile contract is
// idempotent: each invocation re-reads the apiserver state and rewrites the
// in-memory registry from it. Status condition updates use Patch so we don't
// race with the user updating spec.
func (r *PolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	id := CRDPolicyID(req.Namespace, req.Name)

	var crd policiesv1.Policy
	if err := r.Get(ctx, req.NamespacedName, &crd); err != nil {
		if apierrors.IsNotFound(err) {
			// Policy was deleted at the apiserver — drop it from the sink.
			// NotFound is not an error from the reconciler's POV.
			r.Sink.RemovePolicyByID(id)
			r.auditReconcile("DELETE", "policy", id, map[string]interface{}{
				"crd_namespace": req.Namespace,
				"crd_name":      req.Name,
			})
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get Policy %s: %w", req.NamespacedName, err)
	}

	// Compile-check every rule's Rego before publishing. A broken CRD must
	// not get accepted into the registry where the dashboard would render it
	// as healthy. We surface the compile failure via the Ready condition.
	for i := range crd.Spec.Rules {
		rule := &crd.Spec.Rules[i]
		// Reuse the same compile helper /api/v1/policies/validate runs so
		// CRD-driven and REST-driven policies share one syntactic gate.
		if err := compileRegoModule(id+"_"+rule.Name, rule.Name, rule.Rego); err != nil {
			r.Log.Warn("Policy CRD rejected: rego compile failure",
				zap.String("crd_namespace", crd.Namespace),
				zap.String("crd_name", crd.Name),
				zap.String("rule", rule.Name),
				zap.Error(err),
			)
			// Best-effort status update; do not block reconcile loop on the
			// status patch — the apiserver may not yet have the status
			// subresource enabled for example, and we'd rather log than retry.
			r.publishPolicyStatus(ctx, &crd, "Failed", metav1.ConditionFalse, "RegoCompileError", err.Error())
			// Drop any previously-good copy of this CRD so a broken update
			// can't keep serving stale rules.
			r.Sink.RemovePolicyByID(id)
			return ctrl.Result{}, nil
		}
	}

	r.Sink.UpsertPolicyFromCRD(&crd)
	r.publishPolicyStatus(ctx, &crd, "Active", metav1.ConditionTrue, "Reconciled", "Policy is loaded into the engine")
	// A create and an update are indistinguishable at the reconcile level (each is
	// an idempotent re-read of apiserver state), so we record UPSERT and let the
	// generation/UID distinguish a first apply from a spec change.
	r.auditReconcile("UPSERT", "policy", id, map[string]interface{}{
		"crd_namespace": crd.Namespace,
		"crd_name":      crd.Name,
		"uid":           string(crd.UID),
		"generation":    crd.Generation,
	})
	return ctrl.Result{}, nil
}

// auditReconcile records a reconcile-driven ConfigurationChange attributed to
// the controller service account (AUD-WU-12, AU-2/AU-12). It is nil-safe: a nil
// r.Audit makes this a no-op. The correlation id is synthesized by the logger
// (a reconcile is not part of an inbound HTTP request chain).
func (r *PolicyReconciler) auditReconcile(verb, resource, id string, changes map[string]interface{}) {
	if r.Audit == nil {
		return
	}
	changes["controller"] = "reconcile"
	r.Audit.LogConfigChange(r.Identity, verb, resource, id, changes)
}

// SetupWithManager wires the reconciler into the controller-runtime manager.
// When leaderless is true, the controller is registered with
// NeedLeaderElection=false so it runs on every replica — required by
// embedders whose Sink populates a per-pod local cache (e.g. the
// admission-webhook's OPA engine). maxConcurrent bounds the worker pool
// (RES-WU-17); a non-positive value defers to controller-runtime's default of 1.
func (r *PolicyReconciler) SetupWithManager(mgr ctrl.Manager, leaderless bool, maxConcurrent int) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&policiesv1.Policy{}).
		Named("policy").
		WithOptions(controller.Options{
			NeedLeaderElection:      ptr.To(!leaderless),
			MaxConcurrentReconciles: maxConcurrent,
		}).
		Complete(r)
}

func (r *PolicyReconciler) publishPolicyStatus(ctx context.Context, crd *policiesv1.Policy, phase string, status metav1.ConditionStatus, reason, message string) {
	patch := client.MergeFrom(crd.DeepCopy())
	crd.Status.Phase = phase
	cond := metav1.Condition{
		Type:               "Ready",
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.NewTime(time.Now()),
	}
	upsertCondition(&crd.Status.Conditions, cond)
	if err := r.Status().Patch(ctx, crd, patch); err != nil {
		r.Log.Debug("policy status patch failed (non-fatal)",
			zap.String("crd_namespace", crd.Namespace),
			zap.String("crd_name", crd.Name),
			zap.Error(err),
		)
	}
}

// PolicyExceptionReconciler watches PolicyException CRDs.
type PolicyExceptionReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Sink   ExceptionSink
	Log    *zap.Logger
	// Audit records a reconcile-driven ConfigurationChange for every
	// PolicyException create/update/delete and a system event when the reconciler
	// observes an expired exception (AUD-WU-12, AU-2/AU-12). Optional and nil-safe.
	Audit *audit.Logger
	// Identity is the synthesized controller service-account UserInfo recorded on
	// the audit events emitted by this reconciler.
	Identity authenticationv1.UserInfo
}

func (r *PolicyExceptionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	id := CRDExceptionID(req.Namespace, req.Name)

	var crd policiesv1.PolicyException
	if err := r.Get(ctx, req.NamespacedName, &crd); err != nil {
		if apierrors.IsNotFound(err) {
			r.Sink.RemoveExceptionByID(id)
			r.auditReconcile("DELETE", "exception", id, map[string]interface{}{
				"crd_namespace": req.Namespace,
				"crd_name":      req.Name,
			})
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("get PolicyException %s: %w", req.NamespacedName, err)
	}

	if crd.Spec.PolicyID == "" {
		r.Log.Warn("PolicyException rejected: spec.policy_id is required",
			zap.String("crd_namespace", crd.Namespace),
			zap.String("crd_name", crd.Name),
		)
		r.publishExceptionStatus(ctx, &crd, "Failed", metav1.ConditionFalse, "MissingPolicyID", "spec.policy_id is required")
		r.Sink.RemoveExceptionByID(id)
		return ctrl.Result{}, nil
	}

	r.Sink.UpsertExceptionFromCRD(&crd)

	// Capture prior observed state BEFORE publishing the new status, to dedup
	// reconcile-driven audit records (AUD-WU-12): a periodic resync of an
	// unchanged exception must NOT flood the audit log. We audit an UPSERT only
	// when the spec generation advances, and an expiry only on the TRANSITION
	// into Expired. (publishExceptionStatus is a no-op patch when nothing
	// changed, so steady state does not even re-reconcile; this guards the 10h
	// resync and post-restart cases where it does.)
	priorPhase := crd.Status.Phase
	priorObservedGen := crd.Status.ObservedGeneration

	phase := "Active"
	expired := crd.Spec.ExpiresAt != nil && crd.Spec.ExpiresAt.Time.Before(time.Now())
	if expired {
		phase = "Expired"
	}
	r.publishExceptionStatus(ctx, &crd, phase, metav1.ConditionTrue, "Reconciled", "Exception is loaded into the registry")

	if crd.Generation != priorObservedGen {
		r.auditReconcile("UPSERT", "exception", id, map[string]interface{}{
			"crd_namespace": crd.Namespace,
			"crd_name":      crd.Name,
			"uid":           string(crd.UID),
			"generation":    crd.Generation,
			"policy_id":     crd.Spec.PolicyID,
			"phase":         phase,
		})
	}
	// An exception transitioning INTO phase=Expired is a lifecycle event distinct
	// from the upsert; record it explicitly (once per transition) so AU-2 expiry
	// coverage does not depend on a reader inferring expiry from a phase field.
	if expired && priorPhase != "Expired" {
		r.auditExpiry(id, crd.Namespace, crd.Name, string(crd.UID), crd.Generation, crd.Spec.PolicyID)
	}
	return ctrl.Result{}, nil
}

// auditReconcile records a reconcile-driven ConfigurationChange attributed to
// the controller service account (AUD-WU-12). Nil-safe.
func (r *PolicyExceptionReconciler) auditReconcile(verb, resource, id string, changes map[string]interface{}) {
	if r.Audit == nil {
		return
	}
	changes["controller"] = "reconcile"
	r.Audit.LogConfigChange(r.Identity, verb, resource, id, changes)
}

// auditExpiry records the CRD-reconciler exception-expiry lifecycle event
// (AUD-WU-12, AU-2). Nil-safe. The controlling identity and resource
// generation/UID are recorded so the expiry is attributable. This is the
// CRD-reconciler half of the expiry coverage; the in-memory hourly ticker
// (Manager.checkExpiredExceptions) records the other half.
func (r *PolicyExceptionReconciler) auditExpiry(id, ns, name, uid string, generation int64, policyID string) {
	if r.Audit == nil {
		return
	}
	r.Audit.LogSystemEvent("ExceptionExpired",
		fmt.Sprintf("policy exception %s expired (reconcile)", id),
		map[string]interface{}{
			"controller":    "reconcile",
			"identity":      r.Identity.Username,
			"exception_id":  id,
			"crd_namespace": ns,
			"crd_name":      name,
			"uid":           uid,
			"generation":    generation,
			"policy_id":     policyID,
		})
}

func (r *PolicyExceptionReconciler) SetupWithManager(mgr ctrl.Manager, leaderless bool, maxConcurrent int) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&policiesv1.PolicyException{}).
		Named("policyexception").
		WithOptions(controller.Options{
			NeedLeaderElection:      ptr.To(!leaderless),
			MaxConcurrentReconciles: maxConcurrent,
		}).
		Complete(r)
}

func (r *PolicyExceptionReconciler) publishExceptionStatus(ctx context.Context, crd *policiesv1.PolicyException, phase string, status metav1.ConditionStatus, reason, message string) {
	patch := client.MergeFrom(crd.DeepCopy())
	crd.Status.Phase = phase
	crd.Status.ObservedGeneration = crd.Generation
	cond := metav1.Condition{
		Type:               "Ready",
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.NewTime(time.Now()),
	}
	upsertCondition(&crd.Status.Conditions, cond)
	if err := r.Status().Patch(ctx, crd, patch); err != nil {
		r.Log.Debug("exception status patch failed (non-fatal)",
			zap.String("crd_namespace", crd.Namespace),
			zap.String("crd_name", crd.Name),
			zap.Error(err),
		)
	}
}

// upsertCondition inserts or updates a condition by Type, preserving its
// LastTransitionTime when status hasn't changed (per the k8s conditions
// contract).
func upsertCondition(conds *[]metav1.Condition, next metav1.Condition) {
	for i, c := range *conds {
		if c.Type != next.Type {
			continue
		}
		if c.Status == next.Status {
			// Same status — keep the original transition time.
			next.LastTransitionTime = c.LastTransitionTime
		}
		(*conds)[i] = next
		return
	}
	*conds = append(*conds, next)
}
