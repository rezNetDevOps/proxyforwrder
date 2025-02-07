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
	"syscall"
	"time"

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

	// Create a reverse proxy to the Supabase target.
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	// Wrap the default transport to instrument upstream latency.
	if proxy.Transport == nil {
		proxy.Transport = http.DefaultTransport
	}
	proxy.Transport = &instrumentedRoundTripper{rt: proxy.Transport}

	// Optionally adjust the Director for add custom headers.
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		// Example: add an X-Forwarded-Host header if needed.
		req.Header.Set("X-Forwarded-Host", allowedDomain)
	}

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

	// Create the HTTP server with appropriate timeouts.
	srv := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// TLS configuration: cert-manager will typically mount certificates as files.
	tlsCertFile := os.Getenv("TLS_CERT_FILE")
	tlsKeyFile := os.Getenv("TLS_KEY_FILE")
	if tlsCertFile != "" && tlsKeyFile != "" {
		srv.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			// TODO: Add further TLS configuration as needed.
		}
		log.Printf("Starting HTTPS proxy on %s (allowed domain %s), forwarding to %s", listenAddr, allowedDomain, targetURLStr)
		go func() {
			if err := srv.ListenAndServeTLS(tlsCertFile, tlsKeyFile); err != nil && err != http.ErrServerClosed {
				log.Fatalf("ListenAndServeTLS error: %v", err)
			}
		}()
	} else {
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
