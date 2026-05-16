package policy

import (
	"github.com/Jibbscript/kube-policies/internal/config"
	"github.com/open-policy-agent/opa/storage/inmem"
	"go.uber.org/zap"
)

// NewEvaluatorForPolicy constructs an Engine scoped strictly to the given
// policy's rules. It does NOT call loadDefaultPolicies(). This is the
// playground/test endpoint constructor — the Engine returned will evaluate
// ONLY against `p`, so violations from the bundled default policies do not
// bleed into a user's test of an unrelated policy.
//
// The returned Engine uses a fresh in-memory store and a fresh
// preparedQueries cache; it shares no state with any other Engine.
func NewEvaluatorForPolicy(p *Policy, cfg *config.PolicyConfig, log *zap.Logger) (*Engine, error) {
	engine := &Engine{
		store:    inmem.New(),
		policies: map[string]*Policy{p.ID: p},
		logger:   log,
		config:   cfg,
	}
	return engine, nil
}
