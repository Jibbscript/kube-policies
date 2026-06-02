package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Jibbscript/kube-policies/internal/config"
)

// baseRateLimit returns a fully-populated RateLimitConfig with values distinct
// from every flag default, so a test can prove an override either replaced or
// preserved each field.
func baseRateLimit() config.RateLimitConfig {
	return config.RateLimitConfig{
		Enabled:              true,
		RequestsPerSecond:    50,
		Burst:                100,
		MaxConcurrent:        100,
		MaxBodyBytes:         3145728,
		MaxStreamConnections: 100,
	}
}

// noopOverrides mirrors the flag defaults (disabled=false, every numeric
// sentinel negative) so resolveRateLimit must return the config unchanged.
func noopOverrides() rateLimitOverrides {
	return rateLimitOverrides{
		disabled:          false,
		requestsPerSecond: -1,
		burst:             -1,
		maxConcurrent:     -1,
		maxBodyBytes:      -1,
		maxStreamConns:    -1,
	}
}

func TestResolveRateLimit(t *testing.T) {
	t.Run("no overrides keeps config values", func(t *testing.T) {
		cfg := baseRateLimit()
		got := resolveRateLimit(cfg, noopOverrides())
		if got != cfg {
			t.Fatalf("resolveRateLimit with sentinel overrides changed config: got %+v want %+v", got, cfg)
		}
	})

	t.Run("disabled flag overrides enabled config", func(t *testing.T) {
		o := noopOverrides()
		o.disabled = true
		got := resolveRateLimit(baseRateLimit(), o)
		if got.Enabled {
			t.Fatal("ratelimit-disabled flag must force Enabled=false")
		}
		// Other fields must be untouched.
		if got.RequestsPerSecond != 50 || got.Burst != 100 {
			t.Fatalf("disabled override leaked into other fields: %+v", got)
		}
	})

	t.Run("each numeric flag beats config when non-negative", func(t *testing.T) {
		o := rateLimitOverrides{
			disabled:          false,
			requestsPerSecond: 10,
			burst:             20,
			maxConcurrent:     30,
			maxBodyBytes:      40,
			maxStreamConns:    50,
		}
		got := resolveRateLimit(baseRateLimit(), o)
		want := config.RateLimitConfig{
			Enabled:              true,
			RequestsPerSecond:    10,
			Burst:                20,
			MaxConcurrent:        30,
			MaxBodyBytes:         40,
			MaxStreamConnections: 50,
		}
		if got != want {
			t.Fatalf("override merge wrong: got %+v want %+v", got, want)
		}
	})

	t.Run("zero overrides are applied (>= 0), distinguishing zero from unset", func(t *testing.T) {
		// requests_per_second=0 / burst=0 are MEANINGFUL (disable the rate limiter)
		// and must override the config — only the negative sentinel defers.
		o := noopOverrides()
		o.requestsPerSecond = 0
		o.burst = 0
		o.maxConcurrent = 0
		o.maxBodyBytes = 0
		o.maxStreamConns = 0
		got := resolveRateLimit(baseRateLimit(), o)
		if got.RequestsPerSecond != 0 || got.Burst != 0 || got.MaxConcurrent != 0 ||
			got.MaxBodyBytes != 0 || got.MaxStreamConnections != 0 {
			t.Fatalf("zero-valued overrides must be applied (>= 0), got %+v", got)
		}
		// Enabled stays true: a zero rate disables the limiter inside the
		// middleware, not the Enabled toggle.
		if !got.Enabled {
			t.Fatal("zero numeric overrides must not flip Enabled")
		}
	})

	t.Run("does not mutate the input config (value semantics)", func(t *testing.T) {
		cfg := baseRateLimit()
		o := noopOverrides()
		o.disabled = true
		o.burst = 7
		_ = resolveRateLimit(cfg, o)
		if !cfg.Enabled || cfg.Burst != 100 {
			t.Fatalf("resolveRateLimit mutated its caller's config: %+v", cfg)
		}
	})
}

func TestNewHTTPServer(t *testing.T) {
	h := http.NewServeMux()
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS13}
	to := serverTimeouts{read: 30 * time.Second, write: 31 * time.Second, idle: 60 * time.Second}

	srv := newHTTPServer(8080, h, tlsConf, to)
	if srv.Addr != ":8080" {
		t.Fatalf("Addr = %q, want :8080", srv.Addr)
	}
	if srv.Handler == nil {
		t.Fatal("Handler must be wired")
	}
	if srv.TLSConfig != tlsConf {
		t.Fatal("TLSConfig must be the supplied config")
	}
	if srv.ReadTimeout != 30*time.Second || srv.WriteTimeout != 31*time.Second || srv.IdleTimeout != 60*time.Second {
		t.Fatalf("timeouts not wired: read=%v write=%v idle=%v", srv.ReadTimeout, srv.WriteTimeout, srv.IdleTimeout)
	}
}

func TestNewHTTPServerNilTLS(t *testing.T) {
	// The metrics server is constructed with a nil TLS config in the plain-HTTP
	// (default) case; newHTTPServer must carry that through unchanged.
	srv := newHTTPServer(9091, http.NewServeMux(), nil, serverTimeouts{read: 10 * time.Second, write: 10 * time.Second, idle: 30 * time.Second})
	if srv.Addr != ":9091" {
		t.Fatalf("Addr = %q, want :9091", srv.Addr)
	}
	if srv.TLSConfig != nil {
		t.Fatal("nil TLSConfig must stay nil (plain-HTTP metrics default)")
	}
}

func TestClassifyInternalAuthMode(t *testing.T) {
	cases := []struct {
		raw  string
		want internalAuthMode
	}{
		{"static", authModeStatic},
		{"tokenreview", authModeTokenReview},
		{"", authModeTokenReview},        // unset defaults to TokenReview (Inc5 default)
		{"TokenReview", authModeInvalid}, // case-sensitive: a typo fails closed
		{"static ", authModeInvalid},     // trailing space is not "static"
		{"none", authModeInvalid},
		{"disabled", authModeInvalid},
	}
	for _, c := range cases {
		if got := classifyInternalAuthMode(c.raw); got != c.want {
			t.Errorf("classifyInternalAuthMode(%q) = %v, want %v", c.raw, got, c.want)
		}
	}
}

// TestNewHTTPServerServes proves the constructed server is actually functional:
// it serves the wired handler over a real listener and returns 200 with the
// expected body, then shuts down cleanly within a short timeout. This exercises
// the start/serve/Shutdown path the main() goroutines drive, kept fast and
// race-clean via a loopback listener on an ephemeral port and a 1s deadline.
func TestNewHTTPServerServes(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	srv := newHTTPServer(0, mux, nil, serverTimeouts{read: time.Second, write: time.Second, idle: time.Second})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	resp, err := http.Get("http://" + ln.Addr().String() + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "ok" {
		t.Fatalf("body = %q, want ok", string(body))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("Serve returned unexpected error: %v", err)
	}
}
