package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	// Structured logging.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	cfg, err := LoadConfig()
	if err != nil {
		slog.Error("config error", "err", err)
		os.Exit(1)
	}

	auth := NewAuth(cfg.ClerkJWKSURL)
	rl := NewRateLimiter(cfg.MaxConnsPerIP, cfg.MaxConnsPerUser)
	tm := NewTunnelManager(cfg)

	mux := http.NewServeMux()

	// Health check — no auth, no rate limit.
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// WebSocket relay — bidirectional WS↔TCP for SSH.
	mux.HandleFunc("GET /relay", HandleRelay(cfg, auth, rl))

	// Tunnel registration — browser connects to establish a port forward tunnel.
	mux.HandleFunc("GET /tunnel", tm.HandleTunnelRegister(auth, rl))

	// Main handler with subdomain routing for tunnel HTTP traffic.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if this is a tunnel subdomain request.
		if cfg.TunnelDomain != "" && isTunnelSubdomain(r.Host, cfg.TunnelDomain) {
			tm.HandleTunnelHTTP(w, r)
			return
		}
		// Otherwise, use the standard mux.
		mux.ServeHTTP(w, r)
	})

	// Wrap with CORS middleware.
	corsHandler := corsMiddleware(cfg.AllowedOrigins, handler)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      corsHandler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 0, // WebSocket connections are long-lived.
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		slog.Info("wsproxy starting",
			"port", cfg.Port,
			"tunnel_domain", cfg.TunnelDomain,
			"auth", cfg.ClerkJWKSURL != "",
		)
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	server.Shutdown(shutdownCtx)

	slog.Info("wsproxy stopped")
}

// isTunnelSubdomain checks if the host is a subdomain of the tunnel domain.
func isTunnelSubdomain(host, tunnelDomain string) bool {
	// Strip port.
	if i := strings.LastIndex(host, ":"); i != -1 {
		host = host[:i]
	}
	return strings.HasSuffix(host, "."+tunnelDomain) && host != tunnelDomain
}

// corsMiddleware adds CORS headers for browser WebSocket connections.
func corsMiddleware(allowedOrigins []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && isOriginAllowed(origin, allowedOrigins) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Max-Age", "86400")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// isOriginAllowed checks if the request origin is in the allowed list.
func isOriginAllowed(origin string, allowed []string) bool {
	for _, a := range allowed {
		if a == "*" {
			return true
		}
		if a == origin {
			return true
		}
		// Support wildcard prefix matching: http://localhost:*
		if strings.HasSuffix(a, ":*") {
			prefix := strings.TrimSuffix(a, ":*")
			if strings.HasPrefix(origin, prefix+":") {
				return true
			}
		}
	}
	return false
}
