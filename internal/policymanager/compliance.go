package policymanager

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/Jibbscript/kube-policies/internal/audit"
)

// AUD-WU-19 (AU-6/AU-7): real compliance reporting built as a READ-ONLY query
// layer over the local file-backend audit log. The previous handlers returned
// 501; these read the newline-delimited JSON audit log, aggregate PolicyDecision
// records into a ComplianceReport, and never mutate the source.
//
// HONEST SCOPE LIMITATION: reports cover ONLY the records still present in the
// configured LOCAL file backend (config.Audit.Config["filename"], default
// /var/log/kube-policies/audit.log). Records that have been rotated off this
// file, or that were emitted to a remote/forward sink, are NOT aggregated here.
// A complete compliance picture in a forwarded deployment requires querying the
// downstream SIEM. This is a deliberate, documented boundary — not an oversight.

// supportedFrameworks is the control set ListComplianceFrameworks returns. These
// are the frameworks the project's policies and docs map controls against; the
// query layer does not (yet) filter aggregation by framework, so the catalog is
// advisory metadata the dashboard renders.
var supportedFrameworks = []complianceFramework{
	{ID: "cis", Name: "CIS Kubernetes Benchmark", Description: "Center for Internet Security Kubernetes hardening benchmark."},
	{ID: "nist-800-53", Name: "NIST SP 800-53", Description: "NIST Special Publication 800-53 security and privacy controls."},
}

// complianceFramework is one supported control framework in the catalog.
type complianceFramework struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// complianceQuery captures the optional filters a caller may apply to a report.
// A zero value matches every PolicyDecision record in the log.
type complianceQuery struct {
	Framework string     // advisory; stamped on the report, does not filter records
	Since     *time.Time // inclusive lower bound on Event.Timestamp
	Until     *time.Time // inclusive upper bound on Event.Timestamp
	Namespace string     // exact-match Event.Namespace filter
	Decision  string     // exact-match Event.Decision filter (e.g. "allow"/"deny")
	PolicyID  string     // matches a PolicyViolation.PolicyID on the record
}

// buildComplianceReport reads the local audit file and aggregates the matching
// PolicyDecision records into a ComplianceReport. It is READ-ONLY: the source
// file is opened O_RDONLY and never written. A missing file yields an empty
// (but valid, zero-count) report rather than an error, so a freshly deployed
// cluster that has not yet emitted a decision returns 200 with an empty summary.
func (m *Manager) buildComplianceReport(q complianceQuery) (*ComplianceReport, error) {
	events, err := readAuditDecisionEvents(m.auditFilename, q)
	if err != nil {
		return nil, err
	}

	report := &ComplianceReport{
		ID:          uuid.NewString(),
		Framework:   q.Framework,
		Period:      compliancePeriod(q),
		Status:      "generated",
		GeneratedAt: time.Now().UTC(),
		Violations:  []ComplianceViolation{},
		Metadata: map[string]interface{}{
			"source":          "local-file-audit-backend",
			"source_filename": m.auditFilename,
			// Explicit honesty: rotated/forwarded records are out of scope.
			"coverage_limitation": "aggregates only records present in the local file backend; rotated or remotely-forwarded records are not included",
		},
	}
	if q.Namespace != "" {
		report.Metadata["filter_namespace"] = q.Namespace
	}
	if q.Decision != "" {
		report.Metadata["filter_decision"] = q.Decision
	}
	if q.PolicyID != "" {
		report.Metadata["filter_policy_id"] = q.PolicyID
	}

	total := len(events)
	var passed, failed int
	for _, ev := range events {
		// A decision is a "pass" when it was allowed with no recorded violations;
		// any deny or any recorded violation is a "fail" for compliance purposes.
		isFail := strings.EqualFold(ev.Decision, "deny") || len(ev.PolicyViolations) > 0
		if isFail {
			failed++
		} else {
			passed++
		}
		for _, v := range ev.PolicyViolations {
			report.Violations = append(report.Violations, ComplianceViolation{
				ControlID:   v.PolicyID,
				Description: v.Message,
				Severity:    v.Severity,
				Resource:    ev.Name,
				Namespace:   ev.Namespace,
				Timestamp:   ev.Timestamp,
			})
		}
	}

	report.Summary = ComplianceSummary{
		TotalChecks:  total,
		PassedChecks: passed,
		FailedChecks: failed,
	}
	if total > 0 {
		report.Summary.ComplianceRate = float64(passed) / float64(total)
	}
	return report, nil
}

// compliancePeriod renders a human-readable period string for the report from
// the query's time bounds. Open-ended bounds render as "*".
func compliancePeriod(q complianceQuery) string {
	if q.Since == nil && q.Until == nil {
		return "all"
	}
	lo, hi := "*", "*"
	if q.Since != nil {
		lo = q.Since.UTC().Format(time.RFC3339)
	}
	if q.Until != nil {
		hi = q.Until.UTC().Format(time.RFC3339)
	}
	return lo + "/" + hi
}

// readAuditDecisionEvents reads the audit file at path as newline-delimited JSON
// and returns the PolicyDecision events matching q. Each line is either a plain
// Event or a sealed integrity envelope {"record":<event>,"hmac":<hex>}; the
// latter is unwrapped to its .record before decoding. The file is opened
// read-only and never modified. A non-existent file is not an error (empty
// result) so reporting on a cluster that has not yet logged a decision succeeds.
func readAuditDecisionEvents(path string, q complianceQuery) ([]audit.Event, error) {
	f, err := os.Open(path) // #nosec G304 -- path is operator-configured audit filename, read-only
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("open audit log %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var out []audit.Event
	scanner := bufio.NewScanner(f)
	// Audit lines can be large (they may embed the admission object); raise the
	// scanner's max token size well above the 64KiB default.
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		ev, ok := decodeAuditLine([]byte(line))
		if !ok {
			// A malformed line must not abort the whole report — skip it. (A
			// partially-written tail line during rotation is the common case.)
			continue
		}
		if ev.EventType != "PolicyDecision" {
			continue
		}
		if !matchesQuery(ev, q) {
			continue
		}
		out = append(out, ev)
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("scan audit log %q: %w", path, err)
	}
	return out, nil
}

// sealedEnvelope mirrors internal/audit.sealedRecord (which is unexported). When
// audit integrity is enabled each on-disk line is {"record":<event>,"hmac":<hex>};
// we unwrap .record. We do NOT verify the HMAC here — this is a read/aggregate
// path, not the integrity verifier (see internal/audit.VerifyChain for that).
type sealedEnvelope struct {
	Record json.RawMessage `json:"record"`
	HMAC   string          `json:"hmac"`
}

// decodeAuditLine decodes one NDJSON audit line into an Event, transparently
// unwrapping a sealed integrity envelope when present. Returns ok=false for a
// line that is neither a plain Event nor a sealed envelope.
func decodeAuditLine(line []byte) (audit.Event, bool) {
	// Try the sealed envelope first: a plain Event has no top-level "record"
	// field, so env.Record stays empty and we fall through to the plain decode.
	var env sealedEnvelope
	if err := json.Unmarshal(line, &env); err == nil && len(env.Record) > 0 {
		var ev audit.Event
		if err := json.Unmarshal(env.Record, &ev); err == nil {
			return ev, true
		}
		return audit.Event{}, false
	}
	var ev audit.Event
	if err := json.Unmarshal(line, &ev); err == nil {
		return ev, true
	}
	return audit.Event{}, false
}

// matchesQuery reports whether a PolicyDecision event satisfies every set filter
// in q. Unset filters match everything.
func matchesQuery(ev audit.Event, q complianceQuery) bool {
	if q.Since != nil && ev.Timestamp.Before(*q.Since) {
		return false
	}
	if q.Until != nil && ev.Timestamp.After(*q.Until) {
		return false
	}
	if q.Namespace != "" && ev.Namespace != q.Namespace {
		return false
	}
	if q.Decision != "" && !strings.EqualFold(ev.Decision, q.Decision) {
		return false
	}
	if q.PolicyID != "" {
		matched := false
		for _, v := range ev.PolicyViolations {
			if v.PolicyID == q.PolicyID {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// parseComplianceQuery builds a complianceQuery from gin query params. Bad time
// values yield an error so a caller learns its filter was rejected rather than
// silently ignored. Accepted: framework, namespace, decision, policy_id, since,
// until (RFC3339).
func parseComplianceQuery(c *gin.Context) (complianceQuery, error) {
	q := complianceQuery{
		Framework: c.Query("framework"),
		Namespace: c.Query("namespace"),
		Decision:  c.Query("decision"),
		PolicyID:  c.Query("policy_id"),
	}
	if s := c.Query("since"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return q, fmt.Errorf("invalid 'since' (want RFC3339): %w", err)
		}
		q.Since = &t
	}
	if s := c.Query("until"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return q, fmt.Errorf("invalid 'until' (want RFC3339): %w", err)
		}
		q.Until = &t
	}
	return q, nil
}

// generateReportRequest is the optional JSON body POST /compliance/reports
// accepts. Every field maps to a complianceQuery filter; all are optional.
type generateReportRequest struct {
	Framework string `json:"framework"`
	Namespace string `json:"namespace"`
	Decision  string `json:"decision"`
	PolicyID  string `json:"policy_id"`
	Since     string `json:"since"`
	Until     string `json:"until"`
}

func (r generateReportRequest) toQuery() (complianceQuery, error) {
	q := complianceQuery{
		Framework: r.Framework,
		Namespace: r.Namespace,
		Decision:  r.Decision,
		PolicyID:  r.PolicyID,
	}
	if r.Since != "" {
		t, err := time.Parse(time.RFC3339, r.Since)
		if err != nil {
			return q, fmt.Errorf("invalid 'since' (want RFC3339): %w", err)
		}
		q.Since = &t
	}
	if r.Until != "" {
		t, err := time.Parse(time.RFC3339, r.Until)
		if err != nil {
			return q, fmt.Errorf("invalid 'until' (want RFC3339): %w", err)
		}
		q.Until = &t
	}
	return q, nil
}

// complianceError is the shared JSON error envelope for the compliance handlers.
func complianceError(c *gin.Context, status int, msg string) {
	c.JSON(status, gin.H{"error": msg})
}
