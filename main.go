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
)

// Define Prometheus metrics for latency tracking.
var (
	totalLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "proxy_request_duration_seconds",
		Help:    "Total duration (in seconds) for proxy requests from client perspective",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path", "status"})

	upstreamLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "proxy_upstream_duration_seconds",
		Help:    "Duration (in seconds) for upstream (Supabase) requests to complete",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path", "status"})
)

func init() {
	prometheus.MustRegister(totalLatency, upstreamLatency)
}

// instrumentedRoundTripper wraps an http.RoundTripper to measure upstream latency.
type instrumentedRoundTripper struct {
	rt http.RoundTripper
}

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

// statusResponseWriter captures the HTTP status code.
type statusResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *statusResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

// getEnv returns the value of an environment variable or a default.
func getEnv(key, defaultVal string) string {
	if val, exists := os.LookupEnv(key); exists {
		return val
	}
	return defaultVal
}

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

// CertReloader for hot-reloads.
type CertReloader struct {
	certPath string
	keyPath  string

	mu   sync.RWMutex
	cert *tls.Certificate
}

// loadCertificate loads the certificate from the file paths.
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

// GetCertificate is used as the GetCertificate callback for tls.Config.
func (cr *CertReloader) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cr.mu.RLock()
	defer cr.mu.RUnlock()
	if cr.cert == nil {
		return nil, nil
	}
	return cr.cert, nil
}

// watchCertificates sets up a file watcher to reload certs on change.
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

func main() {
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

	// Enforce HTTPS if required.
	enforceHTTPS := strings.EqualFold(getEnv("ENFORCE_HTTPS", "false"), "true")
	tlsCertFile := os.Getenv("TLS_CERT_FILE")
	tlsKeyFile := os.Getenv("TLS_KEY_FILE")
	if enforceHTTPS && (tlsCertFile == "" || tlsKeyFile == "") {
		log.Fatal("ENFORCE_HTTPS is true but TLS_CERT_FILE or TLS_KEY_FILE is not set; failing fast.")
	}

	// Set up certificate reloader.
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

	// Create a reverse proxy to the Supabase target.
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	// Wrap the default transport to instrument upstream latency.
	if proxy.Transport == nil {
		proxy.Transport = http.DefaultTransport
	}
	proxy.Transport = &instrumentedRoundTripper{rt: proxy.Transport}

	// Set the Host header for the outgoing request so that Supabase sees its expected domain.
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		// Override Host header to target's host.
		req.Host = targetURL.Host
		// Also set X-Forwarded-Host to your allowed domain.
		req.Header.Set("X-Forwarded-Host", allowedDomain)
	}

	// Add ModifyResponse to rewrite response headers (e.g., Location) from Supabase.
	proxy.ModifyResponse = func(resp *http.Response) error {
		if loc := resp.Header.Get("Location"); loc != "" {
			// Replace the upstream domain with your allowed domain in the Location header.
			newLoc := strings.ReplaceAll(loc, targetURL.Host, allowedDomain)
			resp.Header.Set("Location", newLoc)
		}
		return nil
	}

	// Health endpoint.
	healthHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	// Main handler that instruments the total request latency.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		proxy.ServeHTTP(rw, r)
		duration := time.Since(start)
		totalLatency.WithLabelValues(r.Method, r.URL.Path, http.StatusText(rw.statusCode)).Observe(duration.Seconds())
	})

	// Wrap the handler with the domain check middleware.
	finalHandler := checkAllowedDomain(allowedDomain, handler)

	// Create an HTTP mux and register the proxy and Prometheus metrics endpoints.
	mux := http.NewServeMux()
	mux.Handle("/", finalHandler)
	mux.Handle("/metrics", promhttp.Handler())
	mux.Handle("/healthz", healthHandler)

	// Create the HTTP server with appropriate timeouts.
	srv := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Configure TLS if certReloader is available.
	if certReloader != nil {
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
		// Optionally, run a separate HTTP server to redirect to HTTPS.
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
		// If no certificate, fail fast if enforcement is enabled.
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

	// graceful shutdown.
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
