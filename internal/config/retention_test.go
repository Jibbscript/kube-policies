package config

import (
	"testing"
	"time"
)

// AUD-WU-07: the 'd'-aware retention parser is the single source of truth for
// audit retention; time.ParseDuration cannot handle the default "90d".
func TestParseRetention(t *testing.T) {
	cases := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"90d", 90 * 24 * time.Hour, false},
		{"180d", 180 * 24 * time.Hour, false},
		{"2160h", 2160 * time.Hour, false}, // == 90d
		{"720h", 720 * time.Hour, false},
		{"", 0, true},
		{"-1d", 0, true},
		{"abc", 0, true},
		{"90x", 0, true},
	}
	for _, tc := range cases {
		got, err := ParseRetention(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseRetention(%q): expected error, got %v", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseRetention(%q): unexpected error %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseRetention(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func baseAudit() *AuditConfig {
	return &AuditConfig{
		Enabled:        true,
		Backend:        "file",
		Retention:      "90d",
		OverflowPolicy: "drop",
		MaxSizeMB:      100,
	}
}

// AUD-WU-07: retention below the FedRAMP-Moderate 90-day floor must be rejected.
func TestValidateAudit_RetentionFloor(t *testing.T) {
	a := baseAudit()
	a.Retention = "30d"
	if err := validateAudit(a); err == nil {
		t.Fatal("expected validateAudit to reject retention < 90d")
	}

	a.Retention = "89d"
	if err := validateAudit(a); err == nil {
		t.Fatal("expected validateAudit to reject 89d (< 90d)")
	}

	a.Retention = "90d"
	if err := validateAudit(a); err != nil {
		t.Fatalf("90d retention should be accepted, got %v", err)
	}

	a.Retention = "2160h" // exactly 90 days
	if err := validateAudit(a); err != nil {
		t.Fatalf("2160h (=90d) retention should be accepted, got %v", err)
	}
}

// AUD-WU-09: the forward backend must have a destination address.
func TestValidateAudit_ForwardRequiresAddress(t *testing.T) {
	a := baseAudit()
	a.Backend = "forward"
	if err := validateAudit(a); err == nil {
		t.Fatal("expected validateAudit to reject forward backend without forward_address")
	}

	a.Config = map[string]string{"forward_address": "siem.example.com:6514"}
	if err := validateAudit(a); err != nil {
		t.Fatalf("forward backend with address should be accepted, got %v", err)
	}
}

// AUD-WU-14: overflow_policy is constrained to drop|block.
func TestValidateAudit_OverflowPolicy(t *testing.T) {
	a := baseAudit()
	a.OverflowPolicy = "explode"
	if err := validateAudit(a); err == nil {
		t.Fatal("expected validateAudit to reject an unknown overflow_policy")
	}
	for _, ok := range []string{"", "drop", "block"} {
		a.OverflowPolicy = ok
		if err := validateAudit(a); err != nil {
			t.Fatalf("overflow_policy %q should be accepted, got %v", ok, err)
		}
	}
}

// A disabled audit stanza skips all validation.
func TestValidateAudit_DisabledSkips(t *testing.T) {
	a := &AuditConfig{Enabled: false, Backend: "bogus", Retention: "1d"}
	if err := validateAudit(a); err != nil {
		t.Fatalf("disabled audit must skip validation, got %v", err)
	}
}
