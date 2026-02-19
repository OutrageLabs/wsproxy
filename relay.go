package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
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

		// Validate port is a valid TCP port number.
		portNum, err := strconv.Atoi(portStr)
		if err != nil || portNum < 1 || portNum > 65535 {
			http.Error(w, "invalid port (must be 1-65535)", http.StatusBadRequest)
			return
		}

		target := net.JoinHostPort(host, portStr)

		// Authenticate.
		userID, err := auth.Authenticate(r)
		if err != nil {
			slog.Warn("relay auth failed", "err", err)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Check target blacklist.
		if cfg.IsTargetBlocked(host) {
			slog.Warn("relay blocked target")
			http.Error(w, "target address not allowed", http.StatusForbidden)
			return
		}

		// Rate limit.
		clientIP := extractIP(r, cfg)
		if !rl.Acquire(clientIP, userID) {
			slog.Warn("relay rate limited")
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

		// Limit maximum message size to prevent OOM.
		wsConn.SetReadLimit(1 * 1024 * 1024) // 1 MB (SSH packets are max ~35 KB)

		// Dial the target SSH server via SafeDial (checks resolved IP against blocklist).
		dialCtx, dialCancel := context.WithTimeout(r.Context(), tcpDialTimeout)
		defer dialCancel()
		tcpConn, err := cfg.SafeDial(dialCtx, "tcp", target)
		if err != nil {
			slog.Error("relay tcp dial failed", "err", err)
			if closeErr := wsConn.Close(websocket.StatusInternalError, "cannot reach target"); closeErr != nil {
				slog.Warn("relay websocket close failed", "err", closeErr)
			}
			return
		}
		defer tcpConn.Close()

		slog.Info("relay started")

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
				if closeErr := tc.CloseWrite(); closeErr != nil {
					slog.Debug("relay tcp close-write failed", "err", closeErr)
				}
			}
		}()

		go func() {
			_, err := io.Copy(wsNetConn, tcpConn)
			errc <- fmt.Errorf("tcp→ws: %w", err)
			cancel() // Signal WebSocket read to stop.
		}()

		// Wait for first direction to finish, then cancel the other.
		firstErr := <-errc
		slog.Info("relay first close", "err", firstErr)
		cancel()
		secondErr := <-errc // Wait for the second to finish too.
		slog.Info("relay second close", "err", secondErr)

		slog.Info("relay ended")
		if closeErr := wsConn.Close(websocket.StatusNormalClosure, "relay ended"); closeErr != nil {
			slog.Debug("relay websocket close failed", "err", closeErr)
		}
	}
}

// extractIP gets the client IP from the request.
// X-Forwarded-For and X-Real-IP are only trusted when the direct connection
// comes from a configured trusted proxy. Otherwise, RemoteAddr is used.
func extractIP(r *http.Request, cfg *Config) string {
	directIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		directIP = r.RemoteAddr
	}
	directParsed := normalizeIP(net.ParseIP(strings.TrimSpace(directIP)))
	if directParsed != nil {
		directIP = directParsed.String()
	}

	// Only trust proxy headers from configured trusted proxies.
	if cfg != nil && cfg.IsTrustedProxy(directIP) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.SplitN(xff, ",", 2)
			candidate := normalizeIP(net.ParseIP(strings.TrimSpace(parts[0])))
			if candidate != nil {
				return candidate.String()
			}
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			candidate := normalizeIP(net.ParseIP(strings.TrimSpace(xri)))
			if candidate != nil {
				return candidate.String()
			}
		}
	}

	return directIP
}
