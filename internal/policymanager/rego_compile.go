package policymanager

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/rego"

	"github.com/Jibbscript/kube-policies/internal/policy"
)

// compileRego checks that the rule's Rego module parses and type-checks
// without errors. It returns a wrapped error whose message begins with
// "rego syntax error" so callers (and tests) can detect compile failures
// without depending on OPA's internal error prefix.
//
// The query "data.kube_policies.evaluate" matches the engine's runtime
// contract. PrepareForEval performs parse + compile (including type
// checking of stdlib builtins) but does not execute the policy, so this is
// safe to run during validate-only paths.
func compileRego(policyID string, r *policy.Rule) error {
	if r == nil {
		return fmt.Errorf("nil rule")
	}
	if r.Rego == "" {
		return fmt.Errorf("rule %q has empty rego body", r.Name)
	}
	moduleName := policyID + "_" + r.ID
	return compileRegoModule(moduleName, r.Name, r.Rego)
}

// compileRegoModule is the string-form compile helper used by the CRD
// reconciler. It runs the same OPA parse+typecheck path as compileRego but
// takes the module name directly so callers that don't have a *policy.Rule
// (notably controller.go for CRD-supplied rules) can validate without
// constructing one.
func compileRegoModule(moduleName, ruleName, regoBody string) error {
	if regoBody == "" {
		return fmt.Errorf("rule %q has empty rego body", ruleName)
	}
	if moduleName == "" || moduleName == "_" {
		// Generate a non-empty name when both policyID and rule.ID are blank
		// (typical in validate-only paths where the policy hasn't been
		// assigned an ID yet). OPA otherwise refuses an unnamed module.
		moduleName = "validate_module"
	}
	_, err := rego.New(
		rego.Query("data.kube_policies.evaluate"),
		rego.Module(moduleName, regoBody),
	).PrepareForEval(context.Background())
	if err != nil {
		return fmt.Errorf("rego syntax error in rule %q: %w", ruleName, err)
	}
	return nil
}
