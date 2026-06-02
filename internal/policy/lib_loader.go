package policy

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/rego"
)

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
