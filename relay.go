package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/coder/websocket"
)

const (
	// tcpDialTimeout is the maximum time to establish TCP to the target.
	tcpDialTimeout = 10 * time.Second
	// wsPingInterval is how often the proxy pings the browser WebSocket.
	wsPingInterval = 30 * time.Second
)

// HandleRelay upgrades the HTTP request to WebSocket and relays data
// bidirectionally to the target SSH server via TCP.
//
// Protocol: wss://proxy/relay?host=X&port=Y&token=JWT
// After WebSocket upgrade, raw bytes flow in both directions — the proxy
// never inspects, logs, or modifies the data (zero-knowledge).
func HandleRelay(cfg *Config, auth *Auth, rl *RateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		portStr := r.URL.Query().Get("port")
		if host == "" || portStr == "" {
			http.Error(w, "host and port query params required", http.StatusBadRequest)
			return
		}

		target := net.JoinHostPort(host, portStr)

		// Authenticate.
		userID, err := auth.Authenticate(r)
		if err != nil {
			slog.Warn("relay auth failed", "err", err, "remote", r.RemoteAddr)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Check target blacklist.
		if cfg.IsTargetBlocked(host) {
			slog.Warn("relay blocked target", "target", target, "user", userID)
			http.Error(w, "target address not allowed", http.StatusForbidden)
			return
		}

		// Rate limit.
		clientIP := extractIP(r)
		if !rl.Acquire(clientIP, userID) {
			slog.Warn("relay rate limited", "ip", clientIP, "user", userID)
			http.Error(w, "too many connections", http.StatusTooManyRequests)
			return
		}
		defer rl.Release(clientIP, userID)

		// Upgrade to WebSocket.
		wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			OriginPatterns: cfg.AllowedOrigins,
		})
		if err != nil {
			slog.Error("relay websocket upgrade failed", "err", err)
			return
		}
		defer wsConn.CloseNow()

		// Dial the target SSH server.
		tcpConn, err := net.DialTimeout("tcp", target, tcpDialTimeout)
		if err != nil {
			slog.Error("relay tcp dial failed", "target", target, "err", err)
			wsConn.Close(websocket.StatusInternalError, "cannot reach target")
			return
		}
		defer tcpConn.Close()

		slog.Info("relay started", "target", target, "user", userID, "ip", clientIP)

		// Bidirectional relay.
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()

		// Wrap WebSocket as a net.Conn for io.Copy.
		wsNetConn := websocket.NetConn(ctx, wsConn, websocket.MessageBinary)

		// Start ping loop to keep connection alive through NAT/proxies.
		go func() {
			ticker := time.NewTicker(wsPingInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := wsConn.Ping(ctx); err != nil {
						cancel()
						return
					}
				}
			}
		}()

		// Two goroutines: WS→TCP and TCP→WS.
		// When either direction ends, cancel the other.
		errc := make(chan error, 2)

		go func() {
			_, err := io.Copy(tcpConn, wsNetConn)
			errc <- fmt.Errorf("ws→tcp: %w", err)
			// Signal TCP that write side is done.
			if tc, ok := tcpConn.(*net.TCPConn); ok {
				tc.CloseWrite()
			}
		}()

		go func() {
			_, err := io.Copy(wsNetConn, tcpConn)
			errc <- fmt.Errorf("tcp→ws: %w", err)
			cancel() // Signal WebSocket read to stop.
		}()

		// Wait for first direction to finish, then cancel the other.
		firstErr := <-errc
		cancel()
		<-errc // Wait for the second to finish too.

		slog.Info("relay ended", "target", target, "user", userID, "reason", firstErr)
		wsConn.Close(websocket.StatusNormalClosure, "relay ended")
	}
}

// extractIP gets the client IP from the request, preferring X-Forwarded-For
// (for use behind Caddy/nginx).
func extractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP (closest to client).
		if i := len(xff); i > 0 {
			parts := splitFirst(xff, ",")
			return parts
		}
	}
	if xff := r.Header.Get("X-Real-IP"); xff != "" {
		return xff
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// splitFirst returns the part before the first occurrence of sep,
// or the full string if sep is not found.
func splitFirst(s, sep string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == sep[0] {
			return s[:i]
		}
	}
	return s
}
