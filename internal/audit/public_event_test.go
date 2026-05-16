package audit

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Jibbscript/kube-policies/internal/policy"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNewPublicEvent_EmptyContext(t *testing.T) {
	ctx := &Context{}
	ev := NewPublicEvent(ctx, nil)
	if ev.Kind != "" {
		t.Errorf("expected empty Kind for zero-value Context, got %q", ev.Kind)
	}
	if ev.RuleID != "" {
		t.Errorf("expected empty RuleID for nil violation, got %q", ev.RuleID)
	}
	if ev.PolicyID != "" {
		t.Errorf("expected empty PolicyID for nil violation, got %q", ev.PolicyID)
	}
}

func TestNewPublicEvent_WithViolation(t *testing.T) {
	ts := time.Date(2024, 6, 1, 10, 0, 0, 0, time.UTC)
	ctx := &Context{
		Decision:  "DENY",
		Namespace: "default",
		Kind:      metav1.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"},
		Name:      "my-deploy",
		Timestamp: ts,
	}
	v := &policy.PolicyViolation{
		RuleID:   "require-security-context",
		PolicyID: "security-baseline",
	}

	ev := NewPublicEvent(ctx, v)

	if ev.Decision != "DENY" {
		t.Errorf("Decision: want DENY, got %q", ev.Decision)
	}
	if ev.Kind != "Deployment" {
		t.Errorf("Kind: want Deployment (bare Kind string), got %q", ev.Kind)
	}
	if ev.Namespace != "default" {
		t.Errorf("Namespace: want default, got %q", ev.Namespace)
	}
	if ev.Name != "my-deploy" {
		t.Errorf("Name: want my-deploy, got %q", ev.Name)
	}
	if ev.RuleID != "require-security-context" {
		t.Errorf("RuleID: want require-security-context, got %q", ev.RuleID)
	}
	if ev.PolicyID != "security-baseline" {
		t.Errorf("PolicyID: want security-baseline, got %q", ev.PolicyID)
	}
	if !ev.Timestamp.Equal(ts) {
		t.Errorf("Timestamp: want %v, got %v", ts, ev.Timestamp)
	}
}

func TestNewPublicEvent_NilViolationLeavesIDsEmpty(t *testing.T) {
	ctx := &Context{
		Decision: "ALLOW",
		Kind:     metav1.GroupVersionKind{Kind: "Pod"},
	}
	ev := NewPublicEvent(ctx, nil)
	if ev.RuleID != "" || ev.PolicyID != "" {
		t.Errorf("expected empty rule/policy IDs for nil violation, got rule=%q policy=%q",
			ev.RuleID, ev.PolicyID)
	}
}

func TestPublicEvent_JSONKeys(t *testing.T) {
	ts := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	ev := PublicEvent{
		Decision:  "ALLOW",
		Namespace: "prod",
		Kind:      "Pod",
		Name:      "my-pod",
		RuleID:    "r1",
		PolicyID:  "p1",
		Timestamp: ts,
	}
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	m := make(map[string]any)
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	for _, key := range []string{"decision", "namespace", "kind", "name", "rule_id", "policy_id", "timestamp"} {
		if _, ok := m[key]; !ok {
			t.Errorf("expected JSON key %q to be present", key)
		}
	}
	if m["decision"] != "ALLOW" {
		t.Errorf("decision: want ALLOW, got %v", m["decision"])
	}
	if m["kind"] != "Pod" {
		t.Errorf("kind: want Pod, got %v", m["kind"])
	}
}

func TestPublicEvent_JSONOmitEmpty(t *testing.T) {
	ev := PublicEvent{
		Decision:  "ALLOW",
		Kind:      "Pod",
		Timestamp: time.Now(),
	}
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	m := make(map[string]any)
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	for _, key := range []string{"namespace", "name", "rule_id", "policy_id"} {
		if _, ok := m[key]; ok {
			t.Errorf("expected JSON key %q to be absent (omitempty), but it was present", key)
		}
	}
}
