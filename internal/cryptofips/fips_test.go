package cryptofips

import (
	"testing"
)

// TestCheck covers the self-test decision table. The critical row for the
// exit gate is required && !enabled, which must error (and in MustEnforce
// triggers log.Fatal → process abort).
func TestCheck(t *testing.T) {
	cases := []struct {
		name     string
		required bool
		enabled  bool
		wantErr  bool
	}{
		{"required and enabled", true, true, false},
		{"required but disabled aborts", true, false, true},
		{"not required and disabled", false, false, false},
		{"not required but enabled", false, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Check(tc.required, tc.enabled)
			if tc.wantErr && err == nil {
				t.Fatalf("Check(%v,%v) = nil, want error", tc.required, tc.enabled)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Check(%v,%v) = %v, want nil", tc.required, tc.enabled, err)
			}
		})
	}
}

func TestRequired(t *testing.T) {
	cases := map[string]bool{
		"true":  true,
		"1":     true,
		"TRUE":  true,
		"false": false,
		"0":     false,
		"":      false,
		"yes":   false, // ParseBool does not accept "yes"
		"bogus": false,
	}
	for val, want := range cases {
		t.Run("REQUIRE_FIPS="+val, func(t *testing.T) {
			t.Setenv("REQUIRE_FIPS", val)
			if got := Required(); got != want {
				t.Fatalf("Required() with REQUIRE_FIPS=%q = %v, want %v", val, got, want)
			}
		})
	}
}

// TestEnabled documents the build-dependent behavior: under a normal (non-FIPS)
// test build Enabled() is false. When the suite is run with a GOFIPS140 build
// and GODEBUG=fips140=on it reports true. The assertion is only that it does
// not panic and returns a bool consistent with the build.
func TestEnabled(t *testing.T) {
	_ = Enabled()
}
