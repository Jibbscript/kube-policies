package policy

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func hasNumberedControl(controls []string) bool {
	for _, c := range controls {
		if strings.ContainsAny(c, "0123456789") {
			return true
		}
	}
	return false
}

// TestControlMatrixCoversEveryRule proves POL-WU-28: every shipped rule maps to
// at least one numbered control ID, the matrix and engine agree on every rule's
// owning policy, and there are no missing or orphan entries. This is the ATO
// evidence gate for the "what the product enforces" dimension.
func TestControlMatrixCoversEveryRule(t *testing.T) {
	m, err := LoadControlMatrix()
	require.NoError(t, err)
	assert.Equal(t, PolicyBundleVersion, m.BundleVersion, "matrix bundleVersion must track the policy bundle")

	matrixByID := make(map[string]ControlMatrixEntry, len(m.Rules))
	for _, e := range m.Rules {
		_, dup := matrixByID[e.ID]
		assert.Falsef(t, dup, "duplicate matrix entry %q", e.ID)
		matrixByID[e.ID] = e
		assert.Truef(t, hasNumberedControl(e.Controls),
			"matrix entry %q must list at least one numbered control ID; got %v", e.ID, e.Controls)
	}

	eng := newDefaultEngine(t)
	shipped := make(map[string]bool)
	for _, p := range eng.ListPolicies() {
		for _, r := range p.Rules {
			shipped[r.ID] = true
			e, ok := matrixByID[r.ID]
			assert.Truef(t, ok, "rule %q is missing from control_matrix.yaml", r.ID)
			if ok {
				assert.Equalf(t, p.ID, e.Policy, "control_matrix.yaml policy mismatch for rule %q", r.ID)
			}
			// The engine rule's own Frameworks must also carry a numbered control,
			// so the in-code metadata can't silently drift from the matrix.
			assert.Truef(t, hasNumberedControl(r.Frameworks),
				"engine rule %q Frameworks must include a numbered control; got %v", r.ID, r.Frameworks)
		}
	}

	for id := range matrixByID {
		assert.Truef(t, shipped[id], "control_matrix.yaml has orphan rule %q (no longer shipped)", id)
	}
}
