// Package tlsreload serves a TLS server certificate that can be rotated on
// disk without restarting the process (CRY-WU-10).
//
// A one-shot http.Server.ListenAndServeTLS(certFile, keyFile) reads the key
// pair exactly once, so a cert-manager / Kubernetes Secret rotation would
// otherwise require a pod restart. This package instead loads the pair into an
// atomically-swapped cache and exposes GetCertificate for tls.Config, so the
// next TLS handshake serves the rotated certificate.
//
// The watcher deliberately watches the mount DIRECTORY, not the leaf files.
// Kubernetes projects Secret volumes through an atomically-swapped "..data"
// symlink directory: /etc/certs/tls.crt is a symlink into a timestamped dir,
// and rotation swaps the "..data" symlink rather than rewriting tls.crt. An
// fsnotify watch on the leaf file therefore usually does NOT fire on rotation;
// watching the directory (and reacting to the "..data" Create/Rename) does. A
// periodic re-read provides a belt-and-suspenders fallback in case any
// filesystem event is missed.
package tlsreload

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// defaultReloadInterval is the periodic fallback re-read cadence. Kubernetes
// Secret propagation to the kubelet's mounted volume is eventually consistent
// and can take up to ~1 minute, so a sub-minute fallback is well matched while
// avoiding needless I/O.
const defaultReloadInterval = 60 * time.Second

// Reloader loads and caches a TLS server key pair and refreshes it when the
// backing files change. The zero value is not usable; construct with New.
type Reloader struct {
	certPath string
	keyPath  string
	log      *zap.Logger
	interval time.Duration

	// cached holds the last-known-good certificate. Reads happen on every TLS
	// handshake (GetCertificate), so an atomic pointer keeps that path
	// lock-free; writes are rare (only on rotation).
	cached atomic.Pointer[tls.Certificate]

	// onReload, if set, is invoked with the freshly loaded certificate on the
	// initial load and after each successful reload. Used to update the
	// cert-expiry metric (CRY-WU-12) without coupling this package to metrics.
	onReload func(*tls.Certificate)
}

// Option customizes a Reloader.
type Option func(*Reloader)

// WithReloadInterval overrides the periodic fallback re-read cadence. A
// non-positive value is ignored.
func WithReloadInterval(d time.Duration) Option {
	return func(r *Reloader) {
		if d > 0 {
			r.interval = d
		}
	}
}

// WithOnReload registers a callback invoked with each newly loaded certificate
// (initial load and every successful reload). Typically wired to publish the
// certificate's expiry as a metric (CRY-WU-12).
func WithOnReload(fn func(*tls.Certificate)) Option {
	return func(r *Reloader) {
		r.onReload = fn
	}
}

// New constructs a Reloader and performs an initial synchronous load. It
// returns an error if the key pair cannot be loaded: serving a webhook that
// cannot present a certificate is worse than failing fast at startup.
func New(certPath, keyPath string, log *zap.Logger, opts ...Option) (*Reloader, error) {
	if log == nil {
		log = zap.NewNop()
	}
	r := &Reloader{
		certPath: certPath,
		keyPath:  keyPath,
		log:      log,
		interval: defaultReloadInterval,
	}
	for _, opt := range opts {
		opt(r)
	}
	cert, err := r.load()
	if err != nil {
		return nil, fmt.Errorf("tlsreload: initial certificate load: %w", err)
	}
	r.cached.Store(cert)
	r.logLoaded("initial certificate loaded", cert)
	r.notify(cert)
	return r, nil
}

// notify invokes the onReload callback (if any) with the loaded certificate.
func (r *Reloader) notify(cert *tls.Certificate) {
	if r.onReload != nil {
		r.onReload(cert)
	}
}

// load reads the key pair from disk. tls.LoadX509KeyPair reads BOTH files and
// verifies the private key matches the leaf, so a transiently half-swapped or
// mismatched pair returns an error rather than a bad certificate.
func (r *Reloader) load() (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return nil, fmt.Errorf("load key pair (%s, %s): %w", r.certPath, r.keyPath, err)
	}
	return &cert, nil
}

// GetCertificate is a tls.Config.GetCertificate callback returning the cached
// certificate. It never reads the disk on the handshake hot path.
func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c := r.cached.Load(); c != nil {
		return c, nil
	}
	return nil, errors.New("tlsreload: no certificate loaded")
}

// GetClientCertificate is a tls.Config.GetClientCertificate callback returning
// the cached certificate for CLIENT-side mutual TLS (IAM-WU-03): an outbound
// caller (the admission-webhook or dashboard) presents this key pair to a
// policy-manager that requires a client certificate. Like GetCertificate it
// serves the atomically-cached pair so a rotated client cert is presented
// without a restart, and never reads the disk on the handshake hot path. The
// CertificateRequestInfo is ignored — the loaded pair is the pod's single
// service identity.
func (r *Reloader) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if c := r.cached.Load(); c != nil {
		return c, nil
	}
	return nil, errors.New("tlsreload: no certificate loaded")
}

// reload attempts to refresh the cached certificate. On failure it logs and
// KEEPS the last-known-good certificate (never blanks the cache).
func (r *Reloader) reload() {
	cert, err := r.load()
	if err != nil {
		r.log.Warn("certificate reload failed; keeping previous certificate", zap.Error(err))
		return
	}
	r.cached.Store(cert)
	r.logLoaded("certificate reloaded", cert)
	r.notify(cert)
}

// logLoaded emits the leaf subject and expiry of a freshly loaded certificate.
func (r *Reloader) logLoaded(msg string, cert *tls.Certificate) {
	if cert == nil || cert.Leaf == nil {
		r.log.Info(msg)
		return
	}
	r.log.Info(msg,
		zap.String("subject", cert.Leaf.Subject.String()),
		zap.Time("not_after", cert.Leaf.NotAfter),
	)
}

// Start runs the watch loop until ctx is canceled. It watches the directory
// containing the cert files (to catch the Kubernetes "..data" symlink swap)
// and also re-reads on a periodic ticker as a fallback. Start blocks; run it in
// its own goroutine.
func (r *Reloader) Start(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("tlsreload: new watcher: %w", err)
	}
	defer func() { _ = watcher.Close() }()

	// Watch the directory, not the leaf file: the leaf is a symlink that does
	// not itself change on a Kubernetes Secret rotation.
	dir := filepath.Dir(r.certPath)
	if err := watcher.Add(dir); err != nil {
		return fmt.Errorf("tlsreload: watch %s: %w", dir, err)
	}
	r.log.Info("watching certificate directory for rotation",
		zap.String("dir", dir),
		zap.Duration("fallback_interval", r.interval),
	)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			// Any create/write/rename/remove under the directory (including the
			// "..data" swap) is a reason to re-read.
			if event.Has(fsnotify.Create) || event.Has(fsnotify.Write) ||
				event.Has(fsnotify.Rename) || event.Has(fsnotify.Remove) {
				r.reload()
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			// ErrEventOverflow and friends are non-fatal; the periodic ticker
			// recovers state.
			r.log.Warn("certificate watcher error", zap.Error(err))
		case <-ticker.C:
			r.reload()
		}
	}
}
