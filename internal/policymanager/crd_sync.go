package policymanager

import (
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/Jibbscript/kube-policies/internal/policy"
	policiesv1 "github.com/Jibbscript/kube-policies/internal/policymanager/apis/policies/v1"
)

// CRDPolicyIDPrefix is the leading token of every CRD-derived Policy /
// Exception ID. Bundled defaults use unprefixed IDs (e.g. "security-baseline"),
// so the prefix lets reset/reconcile paths distinguish them.
const CRDPolicyIDPrefix = "crd"

// crdIDSeparator is the namespace/name separator used inside CRD-derived IDs.
// Slashes would be the natural choice but Gin's /policies/:id/test route
// only matches a single path segment, so any ID with a slash is unaddressable
// via the playground proxy. Colons are URL-safe per RFC 3986 path-segment
// rules, Kubernetes object names cannot contain them (DNS-1123 forbids `:`),
// and Gin uses `:` only as a route-pattern prefix in pattern strings — not as
// a separator within segment data.
const crdIDSeparator = ":"

// CRDPolicyID returns the canonical internal ID for a CRD-derived Policy.
// Format: "crd:<namespace>:<name>". The format is stable across reconcile
// passes so an update to the CRD overwrites the prior in-memory copy.
func CRDPolicyID(namespace, name string) string {
	return CRDPolicyIDPrefix + crdIDSeparator + namespace + crdIDSeparator + name
}

// CRDExceptionID returns the canonical internal ID for a CRD-derived Exception.
func CRDExceptionID(namespace, name string) string {
	return CRDPolicyIDPrefix + crdIDSeparator + namespace + crdIDSeparator + name
}

// IsCRDDerivedID reports whether id was minted by CRDPolicyID/CRDExceptionID.
// Bundled-default IDs do not start with the CRD prefix, so the reset paths in
// integration tests can keep the defaults while purging CRD-derived entries.
func IsCRDDerivedID(id string) bool {
	return strings.HasPrefix(id, CRDPolicyIDPrefix+crdIDSeparator)
}

// PolicyFromCRD is the pure-conversion path: it maps a CRD-shaped Policy
// into the engine's internal policy.Policy. The function is stateless so
// both the Manager (which mutates its in-memory registry) and the
// admission-webhook engineSink (which calls engine.LoadPolicy) can share
// the same field-mapping rules.
//
// CreatedAt is left zero — callers preserve or set it based on whether
// they have a pre-existing copy.
func PolicyFromCRD(crd *policiesv1.Policy) *policy.Policy {
	rules := make([]policy.Rule, 0, len(crd.Spec.Rules))
	for _, r := range crd.Spec.Rules {
		rules = append(rules, policy.Rule{
			ID:          r.Name, // CRD rules use Name as their stable identifier
			Name:        r.Name,
			Description: r.Description,
			Rego:        r.Rego,
			Severity:    coalesce(r.Severity, crd.Spec.Severity),
			Category:    coalesce(r.Category, crd.Spec.Category),
			Frameworks:  append([]string(nil), r.Frameworks...),
			Metadata:    metadataMap(r.Metadata),
		})
	}

	enabled := true
	if crd.Spec.Enabled != nil {
		enabled = *crd.Spec.Enabled
	}

	return &policy.Policy{
		ID:          CRDPolicyID(crd.Namespace, crd.Name),
		Name:        crd.Name,
		Description: crd.Spec.Description,
		// Pin the engine view to the CRD revision the apiserver hands us so
		// callers can detect "what version of the CRD am I running on?"
		Version:   crd.ResourceVersion,
		Enabled:   enabled,
		Rules:     rules,
		Metadata:  metadataMap(crd.Spec.Metadata),
		UpdatedAt: time.Now(),
	}
}

// UpsertPolicyFromCRD converts a Policy CRD into the engine's internal
// policy.Policy shape and stores it under the canonical CRD-derived ID. If a
// policy with the same ID already exists, its CreatedAt is preserved.
//
// Returns the resulting internal policy so the reconciler can publish a
// status condition reflecting what landed in the registry.
func (m *Manager) UpsertPolicyFromCRD(crd *policiesv1.Policy) *policy.Policy {
	internal := PolicyFromCRD(crd)
	now := time.Now()

	m.mutex.Lock()
	if existing, ok := m.policies[internal.ID]; ok {
		internal.CreatedAt = existing.CreatedAt
	} else {
		internal.CreatedAt = now
	}
	m.policies[internal.ID] = internal
	m.mutex.Unlock()

	m.logger.Info("policy upserted from CRD",
		zap.String("crd_namespace", crd.Namespace),
		zap.String("crd_name", crd.Name),
		zap.String("internal_id", internal.ID),
		zap.Int("rule_count", len(internal.Rules)),
		zap.String("resource_version", crd.ResourceVersion),
	)

	return internal
}

// RemovePolicyByID removes a CRD-derived policy from the registry. It is a
// no-op for unknown IDs so the reconciler can call it unconditionally on
// delete events.
func (m *Manager) RemovePolicyByID(id string) bool {
	m.mutex.Lock()
	_, ok := m.policies[id]
	if ok {
		delete(m.policies, id)
	}
	m.mutex.Unlock()
	if ok {
		m.logger.Info("policy removed from CRD delete event",
			zap.String("internal_id", id),
		)
	}
	return ok
}

// ExceptionFromCRD is the pure-conversion counterpart of PolicyFromCRD.
// CreatedAt is left zero — callers preserve or set it.
func ExceptionFromCRD(crd *policiesv1.PolicyException) *Exception {
	now := time.Now()
	internal := &Exception{
		ID:            CRDExceptionID(crd.Namespace, crd.Name),
		Name:          crd.Name,
		Description:   crd.Spec.Description,
		PolicyID:      crd.Spec.PolicyID,
		RuleID:        crd.Spec.RuleID,
		Justification: crd.Spec.Justification,
		Approver:      crd.Spec.Approver,
		Scope: ExceptionScope{
			Namespaces: append([]string(nil), crd.Spec.Scope.Namespaces...),
			Resources:  append([]string(nil), crd.Spec.Scope.Resources...),
			Users:      append([]string(nil), crd.Spec.Scope.Users...),
			Groups:     append([]string(nil), crd.Spec.Scope.Groups...),
		},
		Status:    "active",
		UpdatedAt: now,
	}
	if crd.Spec.ExpiresAt != nil {
		t := crd.Spec.ExpiresAt.Time
		internal.ExpiresAt = &t
		if t.Before(now) {
			internal.Status = "expired"
		}
	}
	return internal
}

// UpsertExceptionFromCRD mirrors UpsertPolicyFromCRD for the PolicyException
// CRD. The internal Exception is keyed by the same crd/<ns>/<name> scheme.
func (m *Manager) UpsertExceptionFromCRD(crd *policiesv1.PolicyException) *Exception {
	internal := ExceptionFromCRD(crd)
	now := time.Now()

	m.mutex.Lock()
	if existing, ok := m.exceptions[internal.ID]; ok {
		internal.CreatedAt = existing.CreatedAt
	} else {
		internal.CreatedAt = now
	}
	m.exceptions[internal.ID] = internal
	m.mutex.Unlock()

	m.logger.Info("policy exception upserted from CRD",
		zap.String("crd_namespace", crd.Namespace),
		zap.String("crd_name", crd.Name),
		zap.String("internal_id", internal.ID),
		zap.String("policy_id", internal.PolicyID),
	)
	return internal
}

// RemoveExceptionByID is the delete counterpart to UpsertExceptionFromCRD.
func (m *Manager) RemoveExceptionByID(id string) bool {
	m.mutex.Lock()
	_, ok := m.exceptions[id]
	if ok {
		delete(m.exceptions, id)
	}
	m.mutex.Unlock()
	if ok {
		m.logger.Info("policy exception removed from CRD delete event",
			zap.String("internal_id", id),
		)
	}
	return ok
}

func coalesce(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// metadataMap converts the CRD's string→string map into the internal
// map[string]interface{} shape so it can be marshaled via the same JSON path
// as policies authored through the HTTP API.
func metadataMap(in map[string]string) map[string]interface{} {
	if in == nil {
		return nil
	}
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
