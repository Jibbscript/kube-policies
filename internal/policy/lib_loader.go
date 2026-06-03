package policy

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

// deniedBuiltins is the set of OPA builtins stripped from the capability set used
// to compile and evaluate ALL rule Rego — request-supplied (evaluate/test RPCs),
// CRD-supplied, and bundled (defense in depth). Untrusted Rego could otherwise
// exfiltrate via SSRF or leak host/process state through these builtins:
//
//   - http.send / net.lookup_ip_addr: outbound network (SSRF, DNS exfil).
//   - opa.runtime: exposes process env/config to the policy.
//   - rego.parse_module / trace: dynamic-module construction and trace spam
//     that legitimate admission deny/allow logic never needs.
//
// Legitimate rules only read the input document (object/parameters/userInfo) and
// the shared library, so none of these are required for normal evaluation.
var deniedBuiltins = map[string]struct{}{
	"http.send":          {},
	"net.lookup_ip_addr": {},
	"opa.runtime":        {},
	"rego.parse_module":  {},
	"trace":              {},
}

// restrictedCapabilities is the OPA capability set every rule compiles/evaluates
// against. Built once from CapabilitiesForThisVersion() (the full default set for
// the linked OPA version) with deniedBuiltins removed, so a rule referencing a
// denied builtin fails to COMPILE (unknown builtin) rather than executing it.
var restrictedCapabilities = newRestrictedCapabilities()

func newRestrictedCapabilities() *ast.Capabilities {
	caps := ast.CapabilitiesForThisVersion()
	filtered := caps.Builtins[:0:0]
	for _, b := range caps.Builtins {
		if _, denied := deniedBuiltins[b.Name]; denied {
			continue
		}
		filtered = append(filtered, b)
	}
	caps.Builtins = filtered
	return caps
}

// restrictedRegoOptions returns the security options applied to EVERY rego.New
// build (engine evaluation and the validation/compile gate): the restricted
// capability set (strips the dangerous builtins above) plus StrictBuiltinErrors
// so a denied/erroring builtin fails the evaluation instead of returning
// undefined and silently passing.
func restrictedRegoOptions() []func(*rego.Rego) {
	return []func(*rego.Rego){
		rego.Capabilities(restrictedCapabilities),
		rego.StrictBuiltinErrors(true),
	}
}

// regoLibFS embeds the shared Rego helper modules that every bundled rule is
// compiled against. Keeping them as real .rego files (rather than Go string
// literals) lets `opa check`/`opa fmt` and editors treat them as first-class
// Rego, and lets the per-rule compilation in preparedQueryFor pull them in as
// additional modules (POL-WU-01).
//
//go:embed rego/*.rego
var regoLibFS embed.FS

// libModules is the parsed set of shared library modules, loaded once at package
// init. Each entry is (module-name, source). The module name is derived from the
// file path so compile errors point back at the file.
var libModules = mustLoadLibModules()

type libModule struct {
	name   string
	source string
}

// mustLoadLibModules reads every embedded rego/*.rego file. A malformed embed
// set is a build/packaging bug, so it panics at init rather than degrading the
// engine to a no-library state at admission time (which would silently reopen
// the workload-controller enforcement bypass).
func mustLoadLibModules() []libModule {
	entries, err := fs.ReadDir(regoLibFS, "rego")
	if err != nil {
		panic(fmt.Sprintf("policy: failed to read embedded rego lib dir: %v", err))
	}

	mods := make([]libModule, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".rego") {
			continue
		}
		path := "rego/" + e.Name()
		src, err := regoLibFS.ReadFile(path)
		if err != nil {
			panic(fmt.Sprintf("policy: failed to read embedded rego lib %q: %v", path, err))
		}
		// Module name "lib/podspec.rego" → "kube_policies_lib_podspec" style is
		// unnecessary; OPA only needs a unique, stable identifier per module.
		mods = append(mods, libModule{name: path, source: string(src)})
	}

	// Deterministic order so compilation is reproducible regardless of the
	// filesystem's directory-entry ordering.
	sort.Slice(mods, func(i, j int) bool { return mods[i].name < mods[j].name })

	if len(mods) == 0 {
		panic("policy: no embedded rego lib modules found under rego/*.rego")
	}
	return mods
}

// libModuleOptions returns the rego.Module options for the shared library so
// preparedQueryFor can compile every rule together with the library.
func libModuleOptions() []func(*rego.Rego) {
	opts := make([]func(*rego.Rego), 0, len(libModules))
	for _, m := range libModules {
		opts = append(opts, rego.Module(m.name, m.source))
	}
	return opts
}

// LibrarySources returns a copy of the embedded library sources keyed by module
// name. Exposed for the policy-validation compile gate (POL-WU-24) and tests so
// customer Rego is compiled against the same library the engine ships.
func LibrarySources() map[string]string {
	out := make(map[string]string, len(libModules))
	for _, m := range libModules {
		out[m.name] = m.source
	}
	return out
}
