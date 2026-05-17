package main

import (
	"go.uber.org/zap"

	"github.com/Jibbscript/kube-policies/internal/policy"
	"github.com/Jibbscript/kube-policies/internal/policymanager"
	policiesv1 "github.com/Jibbscript/kube-policies/internal/policymanager/apis/policies/v1"
)

// engineSink is the admission-webhook's adapter that lets a Policy CRD
// reconciler push policy state into a live *policy.Engine. It satisfies
// policymanager.PolicySink by wrapping policymanager.PolicyFromCRD (the
// shared CRD → internal-Policy converter) and engine.LoadPolicy /
// engine.RemovePolicy.
//
// The webhook intentionally does NOT implement an exception sink. The
// admission engine has no exception-aware code path today, so wiring
// exceptions in would create the illusion of enforcement that doesn't
// happen — surfaced as a flagged gap in the operator-extension docs.
type engineSink struct {
	engine *policy.Engine
	log    *zap.Logger
}

func newEngineSink(engine *policy.Engine, log *zap.Logger) *engineSink {
	return &engineSink{engine: engine, log: log}
}

// UpsertPolicyFromCRD converts the CRD into an internal Policy and loads it
// into the engine. engine.LoadPolicy evicts any cached prepared queries for
// the same policyID, so an updated CRD always picks up the new Rego on the
// next admission request.
func (s *engineSink) UpsertPolicyFromCRD(crd *policiesv1.Policy) *policy.Policy {
	internal := policymanager.PolicyFromCRD(crd)
	if err := s.engine.LoadPolicy(internal); err != nil {
		s.log.Error("engine failed to load policy from CRD",
			zap.String("crd_namespace", crd.Namespace),
			zap.String("crd_name", crd.Name),
			zap.String("internal_id", internal.ID),
			zap.Error(err),
		)
		// Returning the converted policy still lets the reconciler publish a
		// Ready=False / RegoCompileError status condition based on its own
		// pre-publish compile gate. The engine.LoadPolicy failure here is
		// reported separately on the engine logger.
	}
	return internal
}

// RemovePolicyByID removes the policy from the engine and reports whether
// the engine actually held it. Returns true on success or "already absent",
// false only on engine error — engine.RemovePolicy is currently
// best-effort and returns nil for unknown IDs.
func (s *engineSink) RemovePolicyByID(id string) bool {
	if err := s.engine.RemovePolicy(id); err != nil {
		s.log.Error("engine failed to remove policy",
			zap.String("internal_id", id),
			zap.Error(err),
		)
		return false
	}
	return true
}
