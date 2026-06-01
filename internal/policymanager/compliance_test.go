package policymanager

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/Jibbscript/kube-policies/internal/audit"
	"github.com/Jibbscript/kube-policies/internal/config"
	"github.com/Jibbscript/kube-policies/internal/policy"
)

// AUD-WU-19 (AU-6/AU-7): the compliance read/query layer aggregates the local
// file audit backend into a populated ComplianceReport (no longer a 501 stub),
// honors time-range / namespace / decision filters, transparently unwraps sealed
// integrity envelopes, and never mutates the source file.

// seedAuditFile writes the given audit lines (already-serialized JSON strings)
// to a temp file and returns its path. Each line is one NDJSON record.
func seedAuditFile(t *testing.T, lines []string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	var buf []byte
	for _, l := range lines {
		buf = append(buf, []byte(l)...)
		buf = append(buf, '\n')
	}
	require.NoError(t, os.WriteFile(path, buf, 0o600))
	return path
}

// decisionLine serializes a PolicyDecision Event to a JSON line.
func decisionLine(t *testing.T, ts time.Time, ns, name, decision string, violations []policy.PolicyViolation) string {
	t.Helper()
	ev := audit.Event{
		Timestamp:        ts,
		EventType:        "PolicyDecision",
		Namespace:        ns,
		Name:             name,
		Decision:         decision,
		PolicyViolations: violations,
	}
	b, err := json.Marshal(ev)
	require.NoError(t, err)
	return string(b)
}

// managerForAuditFile builds a Manager pointed at the given audit file path via
// config.Audit.Config["filename"], exercising the same resolution NewManager
// uses in production.
func managerForAuditFile(t *testing.T, path string) *Manager {
	t.Helper()
	cfg := &config.Config{
		Policy: config.PolicyConfig{FailureMode: "fail-closed"},
		Audit: config.AuditConfig{
			Config: map[string]string{"filename": path},
		},
	}
	m, err := NewManager(cfg, zaptest.NewLogger(t))
	require.NoError(t, err)
	require.Equal(t, path, m.auditFilename, "manager must resolve the configured audit filename")
	return m
}

func TestCompliance_GenerateReport_Populated(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	lines := []string{
		decisionLine(t, base, "prod", "pod-a", "allow", nil),
		decisionLine(t, base.Add(1*time.Minute), "prod", "pod-b", "deny", []policy.PolicyViolation{
			{PolicyID: "no-privileged", Severity: "high", Message: "privileged container"},
		}),
		decisionLine(t, base.Add(2*time.Minute), "staging", "pod-c", "allow", nil),
		decisionLine(t, base.Add(3*time.Minute), "staging", "pod-d", "deny", []policy.PolicyViolation{
			{PolicyID: "require-limits", Severity: "medium", Message: "no resource limits"},
		}),
		// A non-decision event must be ignored by the aggregation.
		`{"event_type":"ConfigurationChange","operation":"CREATE","timestamp":"2026-01-01T12:05:00Z"}`,
	}
	path := seedAuditFile(t, lines)
	m := managerForAuditFile(t, path)

	report, err := m.buildComplianceReport(complianceQuery{})
	require.NoError(t, err)
	require.NotNil(t, report)

	// Four decision records, two allowed-clean, two denied-with-violation.
	assert.Equal(t, 4, report.Summary.TotalChecks)
	assert.Equal(t, 2, report.Summary.PassedChecks)
	assert.Equal(t, 2, report.Summary.FailedChecks)
	assert.InDelta(t, 0.5, report.Summary.ComplianceRate, 1e-9)
	require.Len(t, report.Violations, 2, "each denied decision contributed one violation")

	gotControls := map[string]bool{}
	for _, v := range report.Violations {
		gotControls[v.ControlID] = true
	}
	assert.True(t, gotControls["no-privileged"])
	assert.True(t, gotControls["require-limits"])
}

func TestCompliance_TimeRangeFilter(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	lines := []string{
		decisionLine(t, base, "prod", "old", "allow", nil),
		decisionLine(t, base.Add(10*time.Minute), "prod", "mid", "deny", []policy.PolicyViolation{{PolicyID: "p1"}}),
		decisionLine(t, base.Add(20*time.Minute), "prod", "new", "allow", nil),
	}
	path := seedAuditFile(t, lines)
	m := managerForAuditFile(t, path)

	since := base.Add(5 * time.Minute)
	until := base.Add(15 * time.Minute)
	report, err := m.buildComplianceReport(complianceQuery{Since: &since, Until: &until})
	require.NoError(t, err)
	// Only the "mid" record (deny) falls inside [12:05, 12:15].
	assert.Equal(t, 1, report.Summary.TotalChecks)
	assert.Equal(t, 1, report.Summary.FailedChecks)
	assert.Equal(t, 0, report.Summary.PassedChecks)
}

func TestCompliance_NamespaceAndDecisionFilters(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	lines := []string{
		decisionLine(t, base, "prod", "a", "allow", nil),
		decisionLine(t, base, "prod", "b", "deny", []policy.PolicyViolation{{PolicyID: "p1"}}),
		decisionLine(t, base, "staging", "c", "deny", []policy.PolicyViolation{{PolicyID: "p2"}}),
	}
	path := seedAuditFile(t, lines)
	m := managerForAuditFile(t, path)

	t.Run("namespace filter", func(t *testing.T) {
		report, err := m.buildComplianceReport(complianceQuery{Namespace: "prod"})
		require.NoError(t, err)
		assert.Equal(t, 2, report.Summary.TotalChecks)
	})
	t.Run("decision filter", func(t *testing.T) {
		report, err := m.buildComplianceReport(complianceQuery{Decision: "deny"})
		require.NoError(t, err)
		assert.Equal(t, 2, report.Summary.TotalChecks)
		assert.Equal(t, 2, report.Summary.FailedChecks)
	})
	t.Run("policy filter", func(t *testing.T) {
		report, err := m.buildComplianceReport(complianceQuery{PolicyID: "p2"})
		require.NoError(t, err)
		assert.Equal(t, 1, report.Summary.TotalChecks)
	})
}

// TestCompliance_SealedEnvelopeUnwrapped proves the read layer transparently
// unwraps {"record":<event>,"hmac":<hex>} integrity envelopes.
func TestCompliance_SealedEnvelopeUnwrapped(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	plain := decisionLine(t, base, "prod", "sealed-pod", "deny", []policy.PolicyViolation{{PolicyID: "px"}})
	sealed, err := json.Marshal(map[string]any{
		"record": json.RawMessage(plain),
		"hmac":   "deadbeef",
	})
	require.NoError(t, err)
	path := seedAuditFile(t, []string{string(sealed)})
	m := managerForAuditFile(t, path)

	report, err := m.buildComplianceReport(complianceQuery{})
	require.NoError(t, err)
	assert.Equal(t, 1, report.Summary.TotalChecks)
	require.Len(t, report.Violations, 1)
	assert.Equal(t, "px", report.Violations[0].ControlID)
}

// TestCompliance_DoesNotMutateSourceFile proves the read/query layer is
// non-destructive: building reports does not change the audit file's bytes or
// mod time.
func TestCompliance_DoesNotMutateSourceFile(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	lines := []string{
		decisionLine(t, base, "prod", "a", "allow", nil),
		decisionLine(t, base, "prod", "b", "deny", []policy.PolicyViolation{{PolicyID: "p1"}}),
	}
	path := seedAuditFile(t, lines)
	m := managerForAuditFile(t, path)

	before, err := os.ReadFile(path)
	require.NoError(t, err)
	infoBefore, err := os.Stat(path)
	require.NoError(t, err)

	// Run several reports with different filters.
	for _, q := range []complianceQuery{
		{},
		{Namespace: "prod"},
		{Decision: "deny"},
		{PolicyID: "p1"},
	} {
		_, err := m.buildComplianceReport(q)
		require.NoError(t, err)
	}

	after, err := os.ReadFile(path)
	require.NoError(t, err)
	infoAfter, err := os.Stat(path)
	require.NoError(t, err)

	assert.Equal(t, before, after, "compliance reporting must not mutate the audit source bytes")
	assert.Equal(t, infoBefore.ModTime(), infoAfter.ModTime(), "compliance reporting must not touch the audit file mod time")
}

// TestCompliance_MissingFileYieldsEmptyReport proves that a not-yet-written
// audit file is not an error: the report is valid and empty.
func TestCompliance_MissingFileYieldsEmptyReport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.log")
	m := managerForAuditFile(t, path)

	report, err := m.buildComplianceReport(complianceQuery{})
	require.NoError(t, err)
	require.NotNil(t, report)
	assert.Equal(t, 0, report.Summary.TotalChecks)
	assert.Empty(t, report.Violations)
}

// TestCompliance_DefaultFilename proves NewManager falls back to the well-known
// audit path when config does not set one.
func TestCompliance_DefaultFilename(t *testing.T) {
	cfg := &config.Config{Policy: config.PolicyConfig{FailureMode: "fail-closed"}}
	m, err := NewManager(cfg, zaptest.NewLogger(t))
	require.NoError(t, err)
	assert.Equal(t, defaultAuditFilename, m.auditFilename)
}
