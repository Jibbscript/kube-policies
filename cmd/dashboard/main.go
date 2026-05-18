package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/Jibbscript/kube-policies/pkg/logger"
)

var (
	port        = flag.Int("port", 8090, "Dashboard HTTP server port")
	metricsPort = flag.Int("metrics-port", 9092, "Dashboard /metrics server port")

	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	flag.Parse()

	log := logger.NewLoggerFromEnv("dashboard")
	// Defensive no-op today (Dashboard does not import controller-runtime).
	// Future informer-driven features benefit immediately and stay consistent
	// with the other two Operator binaries.
	logger.SetControllerRuntimeLogger(log)
	defer func() { _ = log.Sync() }()

	log.Info("dashboard starting",
		zap.String("version", version),
		zap.String("commit", commit),
		zap.String("date", date),
	)

	cfg, err := LoadConfig()
	if err != nil {
		log.Fatal("failed to load configuration", zap.Error(err))
	}

	log.Info("configuration loaded",
		zap.String("policy_manager_url", cfg.PolicyManagerURL),
		zap.Bool("allow_writes", cfg.AllowWrites),
		zap.Bool("csp_unsafe_inline_style", cfg.CSPUnsafeInlineStyle),
	)

	// svcCtx is canceled on SIGTERM/SIGINT to stop the upstream SSE subscriber.
	svcCtx, svcCancel := context.WithCancel(context.Background())
	defer svcCancel()

	apiServer, err := newAPIServer(svcCtx, cfg, log)
	if err != nil {
		log.Fatal("failed to construct API server", zap.Error(err))
	}
	metricsServer := newMetricsServer(*metricsPort)

	go func() {
		log.Info("starting dashboard API server", zap.Int("port", *port))
		if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("API server failed", zap.Error(err))
		}
	}()

	go func() {
		log.Info("starting dashboard metrics server", zap.Int("port", *metricsPort))
		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("metrics server failed", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("shutting down dashboard...")
	svcCancel() // stop upstream SSE subscriber goroutine
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := apiServer.Shutdown(shutdownCtx); err != nil {
		log.Error("API server shutdown error", zap.Error(err))
	}
	if err := metricsServer.Shutdown(shutdownCtx); err != nil {
		log.Error("metrics server shutdown error", zap.Error(err))
	}
	log.Info("dashboard stopped")
}

func newAPIServer(ctx context.Context, cfg *Config, log *zap.Logger) (*http.Server, error) {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(cspMiddleware(cfg.CSPUnsafeInlineStyle))

	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})
	router.GET("/readyz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})

	ring := NewRing(100)

	// Eagerly subscribe to the upstream policy-manager SSE stream so the ring
	// fills as cluster admission events flow, regardless of whether any
	// browser ever opens an SSE connection. The SPA polls
	// /api/decisions/recent today, so the upstream stream is the ring's only
	// data source under normal operation.
	subscriber := NewStreamSubscriber(ctx, cfg, ring, log)
	subscriber.Start()

	router.GET("/api/metrics/summary", NewMetricsHandler(cfg, log))
	router.GET("/api/decisions/recent", NewRecentHandler(ring, log))
	router.GET("/api/decisions/stream", subscriber.Handler())
	router.POST("/api/decisions/internal", NewIngestHandler(cfg, ring, log))

	proxy, err := NewProxyHandler(cfg, log)
	if err != nil {
		return nil, fmt.Errorf("proxy init: %w", err)
	}
	// Wildcard match — Gin requires distinct method registration for the
	// shared prefix, so we register the common verbs explicitly. Disallowed
	// verbs are rejected inside the proxy handler (verb gate); unknown verbs
	// fall through to NoRoute.
	for _, m := range []string{
		http.MethodGet, http.MethodHead, http.MethodPost,
		http.MethodPut, http.MethodPatch, http.MethodDelete,
	} {
		router.Handle(m, "/api/v1/*proxyPath", proxy)
	}

	// SPA fallback: any route the API layer didn't claim falls through to the
	// embedded asset handler. spaHandler() is provided by either web_embed.go
	// (default build) or web_stub.go (-tags=no_ui).
	router.NoRoute(gin.WrapH(spaHandler()))

	return &http.Server{
		Addr:              fmt.Sprintf(":%d", *port),
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}, nil
}

func newMetricsServer(port int) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	return &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
}

// cspMiddleware emits a strict Content-Security-Policy header on every
// response. The empirical M1 verdict (web/CSP_VERDICT.md) determined that
// Tailwind v4 + the shipped SPA build emits no inline <style> tags, so the
// default keeps style-src 'self'. The env var
// DASHBOARD_CSP_UNSAFE_INLINE_STYLE re-introduces 'unsafe-inline' on
// style-src for operators who customize the SPA in ways that emit inline
// styles.
func cspMiddleware(unsafeInline bool) gin.HandlerFunc {
	style := "'self'"
	if unsafeInline {
		style = "'self' 'unsafe-inline'"
	}
	parts := []string{
		"default-src 'self'",
		"img-src 'self' data:",
		"style-src " + style,
		"connect-src 'self'",
		"script-src 'self'",
		"object-src 'none'",
		"base-uri 'self'",
	}
	header := strings.Join(parts, "; ")
	return func(c *gin.Context) {
		c.Header("Content-Security-Policy", header)
		c.Next()
	}
}
