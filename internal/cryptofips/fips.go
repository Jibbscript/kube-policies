// Package cryptofips provides a startup self-test that verifies the process is
// running with the Go FIPS 140-3 cryptographic module active when FIPS mode is
// required (CRY-WU-02).
//
// FIPS mode is selected at build time with GOFIPS140 and at runtime with
// GODEBUG=fips140=on (or "only"); crypto/fips140.Enabled() reports the
// effective state. Whether the deployment *requires* FIPS is an operational
// decision driven by the REQUIRE_FIPS environment variable: non-production
// builds may run without the validated module, while production Helm values
// set REQUIRE_FIPS=true so a misbuilt or misconfigured image fails fast instead
// of silently serving traffic on non-validated crypto.
package cryptofips

import (
	"crypto/fips140"
	"fmt"
	"os"
	"strconv"

	"go.uber.org/zap"
)

// Enabled reports whether the Go FIPS 140-3 module is active for this process.
func Enabled() bool {
	return fips140.Enabled()
}

// Required reports whether FIPS mode is mandatory for this process. It is
// driven by REQUIRE_FIPS (default false). Any value parseable as a true
// boolean by strconv.ParseBool ("1", "true", "TRUE", ...) enables the
// requirement; anything else (including unset or unparseable) leaves it off.
func Required() bool {
	v, err := strconv.ParseBool(os.Getenv("REQUIRE_FIPS"))
	return err == nil && v
}

// Check is the pure, testable core of the self-test: it returns a non-nil
// error when FIPS mode is required but the module is not active.
func Check(required, enabled bool) error {
	if required && !enabled {
		return fmt.Errorf("FIPS 140-3 mode is required (REQUIRE_FIPS=true) but the module is not active: " +
			"rebuild with GOFIPS140=v1.0.0 and run with GODEBUG=fips140=on")
	}
	return nil
}

// MustEnforce runs the startup self-test and aborts the process via
// logger.Fatal when FIPS mode is required but not active. It always logs the
// effective FIPS status so operators can confirm the mode at boot. Call it
// from each main() before any network listener is opened.
func MustEnforce(logger *zap.Logger) {
	enabled := Enabled()
	required := Required()
	logger.Info("FIPS 140-3 self-test",
		zap.Bool("fips_enabled", enabled),
		zap.Bool("fips_required", required),
	)
	if err := Check(required, enabled); err != nil {
		logger.Fatal("FIPS 140-3 self-test failed", zap.Error(err))
	}
}
