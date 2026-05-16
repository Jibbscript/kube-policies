package policymanager

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	configv1alpha1 "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	policiesv1 "github.com/Jibbscript/kube-policies/internal/policymanager/apis/policies/v1"
	"github.com/Jibbscript/kube-policies/internal/policy"
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

	// LeaderElection enables controller-runtime's standard configmap-based
	// leader election so multi-replica deployments converge on a single
	// reconciler. Off by default because the bundled Helm chart ships
	// replicas: 1.
	LeaderElection bool

	// LeaderElectionNamespace is the namespace the lease ConfigMap is created
	// in when LeaderElection is true. Required when LeaderElection=true.
	LeaderElectionNamespace string

	// LeaderElectionID is the lease name. Defaults to
	// "kube-policies-policy-manager" when empty. Set per-binary when running
	// the controller in both processes (otherwise they would contend over
	// the same lease).
	LeaderElectionID string
}

// StartControllers builds and starts a controller-runtime Manager that
// watches Policy CRDs (always) and PolicyException CRDs (when opts.ExceptionSink
// is non-nil), pushing reconciled state into the supplied sinks. The function
// blocks until ctx is cancelled or the controller manager exits with an error.
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
	// Register the core k8s types so the client can address ConfigMaps for
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

	// SkipNameValidation = true disables controller-runtime's process-wide
	// uniqueness check on controller names. The check exists to prevent two
	// controllers in the SAME manager from registering the same Prometheus
	// metric — but we disable the metrics server above (BindAddress: "0"),
	// so the check gives us no value and actively breaks the case where two
	// independent managers (policy-manager + admission-webhook, or two test
	// suites in the same `go test` binary) each spin up a reconciler with
	// the canonical "policy"/"policyexception" name.
	skipNameValidation := true
	mgr, err := manager.New(cfg, manager.Options{
		Scheme: scheme,
		// The calling binary (policy-manager or admission-webhook) already
		// exposes its own /metrics endpoint; disable controller-runtime's
		// own metrics listener to avoid port contention.
		Metrics: metricsserver.Options{BindAddress: "0"},
		// Health probes are served by the calling binary, not this embedded
		// controller manager.
		HealthProbeBindAddress:  "0",
		LeaderElection:          opts.LeaderElection,
		LeaderElectionID:        opts.LeaderElectionID,
		LeaderElectionNamespace: opts.LeaderElectionNamespace,
		Controller: configv1alpha1.Controller{
			SkipNameValidation: &skipNameValidation,
		},
	})
	if err != nil {
		return fmt.Errorf("build controller manager: %w", err)
	}

	policyReconciler := &PolicyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Sink:   opts.PolicySink,
		Log:    log.Named("policy-reconciler"),
	}
	if err := policyReconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("setup Policy reconciler: %w", err)
	}

	if opts.ExceptionSink != nil {
		exceptionReconciler := &PolicyExceptionReconciler{
			Client: mgr.GetClient(),
			Scheme: mgr.GetScheme(),
			Sink:   opts.ExceptionSink,
			Log:    log.Named("exception-reconciler"),
		}
		if err := exceptionReconciler.SetupWithManager(mgr); err != nil {
			return fmt.Errorf("setup PolicyException reconciler: %w", err)
		}
	}

	log.Info("starting CRD controllers",
		zap.Bool("leader_election", opts.LeaderElection),
		zap.Bool("exception_reconciler_enabled", opts.ExceptionSink != nil),
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
	return ctrl.Result{}, nil
}

// SetupWithManager wires the reconciler into the controller-runtime manager.
func (r *PolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&policiesv1.Policy{}).
		Named("policy").
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
}

func (r *PolicyExceptionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	id := CRDExceptionID(req.Namespace, req.Name)

	var crd policiesv1.PolicyException
	if err := r.Get(ctx, req.NamespacedName, &crd); err != nil {
		if apierrors.IsNotFound(err) {
			r.Sink.RemoveExceptionByID(id)
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
	phase := "Active"
	if crd.Spec.ExpiresAt != nil && crd.Spec.ExpiresAt.Time.Before(time.Now()) {
		phase = "Expired"
	}
	r.publishExceptionStatus(ctx, &crd, phase, metav1.ConditionTrue, "Reconciled", "Exception is loaded into the registry")
	return ctrl.Result{}, nil
}

func (r *PolicyExceptionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&policiesv1.PolicyException{}).
		Named("policyexception").
		Complete(r)
}

func (r *PolicyExceptionReconciler) publishExceptionStatus(ctx context.Context, crd *policiesv1.PolicyException, phase string, status metav1.ConditionStatus, reason, message string) {
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

