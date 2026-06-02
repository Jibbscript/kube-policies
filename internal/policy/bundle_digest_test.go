package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBundleDigest proves POL-WU-27: the bundle digest is deterministic
// (reproducible from source so CI can re-derive and verify the signature), is a
// SHA-256 hex string, and the manifest covers every shipped rule plus the shared
// library.
func TestBundleDigest(t *testing.T) {
	d1, err := BundleDigest()
	require.NoError(t, err)
	d2, err := BundleDigest()
	require.NoError(t, err)
	assert.Equal(t, d1, d2, "bundle digest must be deterministic")
	assert.Len(t, d1, 64, "digest must be a SHA-256 hex string")

	m, err := ComputeBundleManifest()
	require.NoError(t, err)
	assert.Equal(t, PolicyBundleVersion, m.BundleVersion)
	assert.NotEmpty(t, m.Library, "manifest must include the shared library sources")

	eng := newDefaultEngine(t)
	want := 0
	for _, p := range eng.ListPolicies() {
		want += len(p.Rules)
	}
	assert.Equal(t, want, len(m.Rules), "manifest must cover every shipped rule")
}
