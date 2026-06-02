package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPolicyLibraryCatalogCoversEveryRule is the POL-WU-29 link check: every
// rule the engine ships must appear in docs/policy-library.md, so the published
// catalog can never silently drift behind the enforced rule set.
func TestPolicyLibraryCatalogCoversEveryRule(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "policy-library.md")
	raw, err := os.ReadFile(path)
	require.NoError(t, err, "policy library catalog must exist at %s", path)
	catalog := string(raw)

	eng := newDefaultEngine(t)
	var missing []string
	for _, p := range eng.ListPolicies() {
		for _, r := range p.Rules {
			if !strings.Contains(catalog, r.ID) {
				missing = append(missing, r.ID)
			}
		}
	}
	require.Emptyf(t, missing, "rules missing from docs/policy-library.md: %v", missing)
}
