package policy

import (
	"context"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/rego"
)

// ValidateRuleRego compiles a single rule's Rego TOGETHER WITH the shared
// library modules (POL-WU-01) — exactly as the engine compiles it in
// preparedQueryFor — and verifies it honors the engine contract (POL-WU-24).
//
// It rejects two classes of customer-authored Policy CRD that would otherwise
// install silently and degrade enforcement:
//
//  1. Non-compiling Rego (syntax/type errors, or — now that rules may
//     `import data.kube_policies.lib` — references to library symbols that fail
//     to resolve). Before this gate compiled with the library, a CRD rule using
//     the shared lib would have been wrongly rejected; with it, the gate matches
//     the engine's real compilation.
//  2. A module that does not define data.kube_policies.evaluate, or whose
//     evaluate does not return an object with a boolean "allowed" field. Such a
//     rule "always allows" (the engine's contract check fails open per rule at
//     runtime), so it is rejected at admission/reconcile time instead.
//
// It returns nil for a rule that compiles and satisfies the contract.
//
// Limitation: the contract probe is a single benign input, so it cannot detect a
// rule that only produces an OPA complete-document conflict (two `evaluate`
// values) for SPECIFIC objects — that surfaces at evaluation time (fail-closed
// deny on the validate path; the mutate path is best-effort by design). Author
// bundled and customer rules as single-output (one `default evaluate` plus
// list-and-pick-first deny logic) as the existing packs do.
func ValidateRuleRego(moduleName, regoBody string) error {
	if strings.TrimSpace(regoBody) == "" {
		return fmt.Errorf("empty rego body")
	}
	if moduleName == "" || moduleName == "_" {
		moduleName = "validate_module"
	}

	opts := []func(*rego.Rego){
		rego.Query("data.kube_policies.evaluate"),
		rego.Module(moduleName, regoBody),
	}
	opts = append(opts, libModuleOptions()...)

	ctx := context.Background()
	pq, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("rego does not compile: %w", err)
	}

	// Contract probe: evaluate against a minimal but well-formed object so an
	// always-allow rule that omits `evaluate` (0 results) is caught. A rule that
	// errors on this benign input would fail-closed at runtime anyway, so the
	// error is surfaced here as a contract violation.
	rs, err := pq.Eval(ctx, rego.EvalInput(contractProbeInput()))
	if err != nil {
		return fmt.Errorf("rego evaluation failed on contract probe: %w", err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return fmt.Errorf("rego must define data.kube_policies.evaluate")
	}
	v, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("data.kube_policies.evaluate must return an object")
	}
	if _, ok := v["allowed"].(bool); !ok {
		return fmt.Errorf("data.kube_policies.evaluate must include a boolean \"allowed\" field")
	}
	return nil
}

// ValidatePolicy validates every rule in a policy (POL-WU-24). The first failing
// rule short-circuits with a wrapped, rule-scoped error.
func ValidatePolicy(p *Policy) error {
	if p == nil {
		return fmt.Errorf("nil policy")
	}
	if len(p.Rules) == 0 {
		return fmt.Errorf("policy %q has no rules", p.ID)
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		if err := ValidateRuleRego(p.ID+"_"+r.ID, r.Rego); err != nil {
			return fmt.Errorf("rule %q: %w", r.ID, err)
		}
	}
	return nil
}

// contractProbeInput is a minimal, well-formed admission input used to confirm a
// rule actually defines data.kube_policies.evaluate. It carries empty object
// metadata/spec and an empty parameters map so parameter-driven rules
// (object.get(input.parameters, ...)) probe cleanly.
func contractProbeInput() map[string]interface{} {
	return map[string]interface{}{
		"object": map[string]interface{}{
			"metadata": map[string]interface{}{},
			"spec":     map[string]interface{}{},
		},
		"parameters": map[string]interface{}{},
	}
}
