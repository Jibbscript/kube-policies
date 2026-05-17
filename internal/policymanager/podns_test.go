package policymanager

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolvePodNamespace_EnvWins(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "foo")
	// File has different content — env must win.
	dir := t.TempDir()
	nsFile := filepath.Join(dir, "namespace")
	require.NoError(t, os.WriteFile(nsFile, []byte("bar"), 0o644))

	ns, err := ResolvePodNamespace(nsFile)
	require.NoError(t, err)
	assert.Equal(t, "foo", ns)
}

func TestResolvePodNamespace_FileFallback(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "") // clear env → fall back to file
	dir := t.TempDir()
	nsFile := filepath.Join(dir, "namespace")
	require.NoError(t, os.WriteFile(nsFile, []byte("bar"), 0o644))

	ns, err := ResolvePodNamespace(nsFile)
	require.NoError(t, err)
	assert.Equal(t, "bar", ns)
}

func TestResolvePodNamespace_FileTrimsWhitespace(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "")
	dir := t.TempDir()
	nsFile := filepath.Join(dir, "namespace")
	require.NoError(t, os.WriteFile(nsFile, []byte(" baz\n"), 0o644))

	ns, err := ResolvePodNamespace(nsFile)
	require.NoError(t, err)
	assert.Equal(t, "baz", ns)
}

func TestResolvePodNamespace_NotFoundReturnsError(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "")
	dir := t.TempDir()
	nsFile := filepath.Join(dir, "does-not-exist")

	ns, err := ResolvePodNamespace(nsFile)
	assert.Error(t, err)
	assert.Empty(t, ns)
}

func TestResolvePodNamespace_EmptyEnvFallsBackToFile(t *testing.T) {
	// POD_NAMESPACE explicitly empty → treat as unset and use file.
	t.Setenv("POD_NAMESPACE", "")
	dir := t.TempDir()
	nsFile := filepath.Join(dir, "namespace")
	require.NoError(t, os.WriteFile(nsFile, []byte("from-file"), 0o644))

	ns, err := ResolvePodNamespace(nsFile)
	require.NoError(t, err)
	assert.Equal(t, "from-file", ns)
}
