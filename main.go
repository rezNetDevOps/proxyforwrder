// Package main implements a secure reverse proxy for Supabase services with features such as
// rate limiting, domain validation, access control, TLS support with hot-reloading,
// and metrics collection.
package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/time/rate"
)

// Define Prometheus metrics for latency tracking.
var (
	// totalLatency measures the end-to-end request duration from client perspective
	totalLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "proxy_request_duration_seconds",
		Help:    "Total duration (in seconds) for proxy requests from client perspective",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path", "status"})

	// upstreamLatency measures the time taken to receive response from Supabase
	upstreamLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "proxy_upstream_duration_seconds",
		Help:    "Duration (in seconds) for upstream (Supabase) requests to complete",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path", "status"})
)

// init registers Prometheus metrics collectors
func init() {
	prometheus.MustRegister(totalLatency, upstreamLatency)
}

// instrumentedRoundTripper wraps an http.RoundTripper to measure upstream latency.
// This allows us to track how long the backend takes to respond independently of
// client-side connection time.
type instrumentedRoundTripper struct {
	rt http.RoundTripper
}

// RoundTrip implements the http.RoundTripper interface and records metrics for each request
func (irt *instrumentedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := irt.rt.RoundTrip(req)
	duration := time.Since(start)
	statusLabel := "error"
	if resp != nil {
		statusLabel = http.StatusText(resp.StatusCode)
	}
	upstreamLatency.WithLabelValues(req.Method, req.URL.Path, statusLabel).Observe(duration.Seconds())
	return resp, err
}

// statusResponseWriter captures the HTTP status code to be used for metrics
type statusResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader overrides the http.ResponseWriter method to capture status codes
func (w *statusResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

// getEnv returns the value of an environment variable or a default value if not set
func getEnv(key, defaultVal string) string {
	if val, exists := os.LookupEnv(key); exists {
		return val
	}
	return defaultVal
}

// allowedPathsMiddleware restricts access to only specified API paths
// This is a security feature that prevents access to unintended endpoints
func allowedPathsMiddleware(allowedPaths []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowed := false
		for _, prefix := range allowedPaths {
			if strings.HasPrefix(r.URL.Path, prefix) {
				allowed = true
				break
			}
		}
		if !allowed {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs details of each request for monitoring and debugging
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log details: timestamp, method, URL, client IP.
		log.Printf("[ACCESS] %s - %s %s from %s", time.Now().Format(time.RFC3339), r.Method, r.URL.String(), r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}

// globalLimiter controls the overall rate of requests to prevent abuse
var globalLimiter = rate.NewLimiter(10, 20) // 10 requests per second with a burst of 20; adjust as needed.

// rateLimitMiddleware implements rate limiting to protect backend services
func rateLimitMiddleware(limiter *rate.Limiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// checkAllowedDomain enforces that requests come only from authorized domains
// This prevents domain spoofing and improves security
func checkAllowedDomain(allowedDomain string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check the Host header.
		if !strings.EqualFold(r.Host, allowedDomain) {
			http.Error(w, "Forbidden: invalid host", http.StatusForbidden)
			return
		}
		// If an Origin header is present, verify it contains the allowed domain.
		if origin := r.Header.Get("Origin"); origin != "" {
			if !strings.Contains(origin, allowedDomain) {
				http.Error(w, "Forbidden: invalid origin", http.StatusForbidden)
				return
			}
		}
		// Set CORS header for browsers.
		w.Header().Set("Access-Control-Allow-Origin", "https://"+allowedDomain)
		w.Header().Set("Vary", "Origin")
		next.ServeHTTP(w, r)
	})
}

// CertReloader handles hot-reloading of TLS certificates without server restarts
// This enables certificate renewals without downtime
type CertReloader struct {
	certPath string
	keyPath  string

	mu   sync.RWMutex
	cert *tls.Certificate
}

// loadCertificate loads the certificate from the file paths
func (cr *CertReloader) loadCertificate() error {
	cert, err := tls.LoadX509KeyPair(cr.certPath, cr.keyPath)
	if err != nil {
		return err
	}
	cr.mu.Lock()
	cr.cert = &cert
	cr.mu.Unlock()
	log.Println("TLS certificate reloaded")
	return nil
}

// GetCertificate is used as the GetCertificate callback for tls.Config
// This allows the server to use the latest certificate without restarting
func (cr *CertReloader) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	if cr.cert == nil {
		return nil, nil
	}
	return cr.cert, nil
}

// watchCertificates sets up a file watcher to reload certs on change
// This enables automatic detection of certificate updates
func (cr *CertReloader) watchCertificates() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	// Watch both certificate and key files.
	for _, file := range []string{cr.certPath, cr.keyPath} {
		if err := watcher.Add(file); err != nil {
			return err
		}
	}
	go func() {
		defer watcher.Close()
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				// If the file is modified, reload certificate.
				if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) != 0 {
					log.Printf("Detected change in %s, reloading certificate...", event.Name)
					if err := cr.loadCertificate(); err != nil {
						log.Printf("Error reloading certificate: %v", err)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("Watcher error: %v", err)
			}
		}
	}()
	return nil
}

// main is the entry point for the application
func main() {
	// Load configuration from environment variables
	listenAddr := getEnv("LISTEN_ADDR", ":443")
	allowedDomain := os.Getenv("ALLOWED_DOMAIN")
	if allowedDomain == "" {
		log.Fatal("ALLOWED_DOMAIN environment variable must be set")
	}
	targetURLStr := os.Getenv("SUPABASE_TARGET_DOMAIN")
	if targetURLStr == "" {
		log.Fatal("SUPABASE_TARGET_DOMAIN environment variable must be set")
	}
	targetURL, err := url.Parse(targetURLStr)
	if err != nil {
		log.Fatalf("Invalid SUPABASE_TARGET_DOMAIN: %v", err)
	}

	// TLS configuration
	enforceHTTPS := strings.EqualFold(getEnv("ENFORCE_HTTPS", "false"), "true")
	tlsCertFile := os.Getenv("TLS_CERT_FILE")
	tlsKeyFile := os.Getenv("TLS_KEY_FILE")
	if enforceHTTPS && (tlsCertFile == "" || tlsKeyFile == "") {
		log.Fatal("ENFORCE_HTTPS is true but TLS_CERT_FILE or TLS_KEY_FILE is not set; failing fast.")
	}

	// Configure certificate reloader for TLS
	var certReloader *CertReloader
	if tlsCertFile != "" && tlsKeyFile != "" {
		certReloader = &CertReloader{
			certPath: tlsCertFile,
			keyPath:  tlsKeyFile,
		}
		// Initial load – if it fails and HTTPS is required, exit.
		if err := certReloader.loadCertificate(); err != nil {
			if enforceHTTPS {
				log.Fatalf("Failed to load TLS certificate: %v", err)
			} else {
				log.Printf("Warning: failed to load TLS certificate, falling back to HTTP: %v", err)
			}
		}
		// Start watching for certificate changes.
		if err := certReloader.watchCertificates(); err != nil {
			log.Fatalf("Failed to watch TLS certificate files: %v", err)
		}
	}

	// Create a reverse proxy to the Supabase target
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Instrument the transport to measure upstream latency
	if proxy.Transport == nil {
		proxy.Transport = http.DefaultTransport
	}
	proxy.Transport = &instrumentedRoundTripper{rt: proxy.Transport}

	// Configure the Director to properly set request headers for Supabase
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		// Override Host header to target's host.
		req.Host = targetURL.Host
		// Also set X-Forwarded-Host to your allowed domain.
		req.Header.Set("X-Forwarded-Host", allowedDomain)
	}

	// Rewrite response headers from Supabase to use our domain
	proxy.ModifyResponse = func(resp *http.Response) error {
		if loc := resp.Header.Get("Location"); loc != "" {
			// Replace the upstream domain with your allowed domain in the Location header.
			newLoc := strings.ReplaceAll(loc, targetURL.Host, allowedDomain)
			resp.Header.Set("Location", newLoc)
		}
		return nil
	}

	// Simple health check endpoint
	healthHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	// Main handler with instrumentation for total request latency
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		proxy.ServeHTTP(rw, r)
		duration := time.Since(start)
		totalLatency.WithLabelValues(r.Method, r.URL.Path, http.StatusText(rw.statusCode)).Observe(duration.Seconds())
	})

	// Define allowed API paths for security
	allowedPaths := []string{"/", "/functions/v1/", "/rest/v1/", "/auth/v1/"}

	// Chain all middleware to create the final handler
	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loggingMiddleware(checkAllowedDomain(allowedDomain, rateLimitMiddleware(globalLimiter, allowedPathsMiddleware(allowedPaths, handler)))).ServeHTTP(w, r)
	})

	// Set up the public-facing router
	publicMux := http.NewServeMux()
	publicMux.Handle("/", finalHandler)

	// Create the main HTTP server with appropriate timeouts for security and stability
	srv := &http.Server{
		Addr:         listenAddr,
		Handler:      publicMux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Set up a separate internal metrics server (not publicly accessible)
	metricsAddr := getEnv("METRICS_ADDR", ":9100")
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsMux.Handle("/healthz", healthHandler)
	metricsSrv := &http.Server{
		Addr:         metricsAddr,
		Handler:      metricsMux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	// Start servers based on TLS configuration
	if certReloader != nil {
		// Configure TLS with minimum security standards
		srv.TLSConfig = &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: certReloader.GetCertificate,
		}
		log.Printf("Starting HTTPS proxy on %s (allowed domain %s), forwarding to %s", listenAddr, allowedDomain, targetURLStr)
		go func() {
			if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("ListenAndServeTLS error: %v", err)
			}
		}()
		// Run HTTP redirect server to ensure HTTPS is used, unless disabled
		disableRedirect := strings.EqualFold(getEnv("DISABLE_HTTP_REDIRECT", "false"), "true")
		if !disableRedirect {
			go func() {
				httpAddr := ":80"
				redirectMux := http.NewServeMux()
				redirectMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
					target := "https://" + r.Host + r.RequestURI
					http.Redirect(w, r, target, http.StatusPermanentRedirect)
				})
				log.Printf("Starting HTTP redirect server on %s", httpAddr)
				if err := http.ListenAndServe(httpAddr, redirectMux); err != nil {
					log.Fatalf("HTTP redirect server error: %v", err)
				}
			}()
		} else {
			log.Printf("HTTP redirect server is disabled")
		}
	} else {
		// HTTP-only mode (less secure, but useful for development or behind another TLS terminator)
		if enforceHTTPS {
			log.Fatal("ENFORCE_HTTPS is true but TLS certificates are not loaded. Exiting.")
		}
		log.Printf("Starting HTTP proxy on %s (allowed domain %s), forwarding to %s", listenAddr, allowedDomain, targetURLStr)
		go func() {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("ListenAndServe error: %v", err)
			}
		}()
	}

	// Start the internal metrics server
	go func() {
		log.Printf("Starting internal metrics server on %s", metricsAddr)
		if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Metrics server error: %v", err)
		}
	}()

	// Set up graceful shutdown on system signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Error during shutdown: %v", err)
	}
	log.Println("Server gracefully stopped.")
}
