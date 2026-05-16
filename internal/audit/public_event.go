package audit

import (
	"time"

	"github.com/Jibbscript/kube-policies/internal/policy"
)

// PublicEvent is a strict-whitelist DTO for streaming audit decisions to
// external consumers (dashboard, SSE subscribers). It deliberately omits
// UserInfo, RequestID, ProcessingTime, Object, and OldObject to prevent
// accidental PII leakage over the wire. Per plan §7, opt-in for full payloads
// is gated by a future flag --audit.stream.full=true.
type PublicEvent struct {
	Decision  string    `json:"decision"`
	Namespace string    `json:"namespace,omitempty"`
	Kind      string    `json:"kind"`
	Name      string    `json:"name,omitempty"`
	RuleID    string    `json:"rule_id,omitempty"`
	PolicyID  string    `json:"policy_id,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// NewPublicEvent constructs a PublicEvent from an audit Context and an optional
// first policy violation. Kind is extracted from ctx.Kind.Kind (the bare Kind
// string — not the full GroupVersionKind struct). RuleID and PolicyID are only
// populated when firstViolation is non-nil.
//
// TODO(M2): support audit.stream.full — include UserInfo, Object, OldObject when flag is set.
func NewPublicEvent(ctx *Context, firstViolation *policy.PolicyViolation) PublicEvent {
	ev := PublicEvent{
		Decision:  ctx.Decision,
		Namespace: ctx.Namespace,
		Kind:      ctx.Kind.Kind,
		Name:      ctx.Name,
		Timestamp: ctx.Timestamp,
	}
	if firstViolation != nil {
		ev.RuleID = firstViolation.RuleID
		ev.PolicyID = firstViolation.PolicyID
	}
	return ev
}
