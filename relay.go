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
	// maxCFTokenLen is the maximum length for CF Access service token values.
	maxCFTokenLen = 512
)

// HandleRelay upgrades the HTTP request to WebSocket and relays data
// bidirectionally to the target SSH server.
//
// Standard mode: wss://proxy/relay?host=X&port=Y&token=JWT
//   → WS↔TCP relay to host:port
//
// CF tunnel mode: wss://proxy/relay?host=X&port=Y&token=JWT&cf_domain=D&cf_id=I&cf_secret=S
//   → WS↔WS relay through Cloudflare Access tunnel
//   Proxy dials wss://<cf_domain>/ with CF-Access-Client-Id/Secret headers.
//   Browser cannot set these headers on WebSocket upgrade, so proxy acts as intermediary.
//
// In both modes, raw bytes flow bidirectionally — zero-knowledge.
func HandleRelay(cfg *Config, auth *Auth, rl *RateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		// Authenticate first — before exposing any validation oracle.
		userID, err := auth.Authenticate(r)
		if err != nil {
			slog.Warn("relay auth failed", "err", err)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// CF tunnel params (optional — when present, relay uses WS↔WS).
		cfDomain := q.Get("cf_domain")
		cfID := q.Get("cf_id")
		cfSecret := q.Get("cf_secret")
		isCFTunnel := cfDomain != "" && cfID != "" && cfSecret != ""

		// Standard mode: host + port required for TCP dial.
		// CF tunnel mode: host + port may be present (GoSSH adds them) but are unused.
		host := q.Get("host")
		portStr := q.Get("port")

		if !isCFTunnel {
			if host == "" || portStr == "" {
				http.Error(w, "host and port query params required", http.StatusBadRequest)
				return
			}
			portNum, err := strconv.Atoi(portStr)
			if err != nil || portNum < 1 || portNum > 65535 {
				http.Error(w, "invalid port (must be 1-65535)", http.StatusBadRequest)
				return
			}
		}

		if isCFTunnel {
			// Reject raw IPs — cf_domain must be a hostname, not an address.
			if net.ParseIP(cfDomain) != nil {
				http.Error(w, "cf_domain must be a hostname, not an IP", http.StatusBadRequest)
				return
			}
			if !isValidHostname(cfDomain) {
				http.Error(w, "invalid cf_domain", http.StatusBadRequest)
				return
			}
			// Check resolved IPs against the same blacklist used for TCP targets.
			if cfg.IsTargetBlocked(cfDomain) {
				slog.Warn("relay blocked cf_domain")
				http.Error(w, "cf_domain resolves to a blocked address", http.StatusForbidden)
				return
			}
			// Sanitize CF credentials: reject CRLF / control chars / excessive length.
			if len(cfID) > maxCFTokenLen || len(cfSecret) > maxCFTokenLen {
				http.Error(w, "cf_id or cf_secret too long", http.StatusBadRequest)
				return
			}
			if !isSafeHTTPHeaderValue(cfID) || !isSafeHTTPHeaderValue(cfSecret) {
				http.Error(w, "cf_id or cf_secret contains invalid characters", http.StatusBadRequest)
				return
			}
		}

		// Target blacklist (standard mode only — CF domain checked above).
		if !isCFTunnel && cfg.IsTargetBlocked(host) {
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

		// Upgrade browser WebSocket.
		wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			OriginPatterns: cfg.AllowedOrigins,
		})
		if err != nil {
			slog.Error("relay websocket upgrade failed", "err", err)
			return
		}
		defer wsConn.CloseNow()
		wsConn.SetReadLimit(1 * 1024 * 1024) // 1 MB

		// Cancellable context for the entire relay lifetime.
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()

		// Dial upstream.
		dialCtx, dialCancel := context.WithTimeout(ctx, tcpDialTimeout)
		defer dialCancel()

		var upstream net.Conn
		var cfConn *websocket.Conn

		if isCFTunnel {
			cfConn, err = dialCFTunnel(dialCtx, cfDomain, cfID, cfSecret)
			if err != nil {
				slog.Error("relay cf tunnel dial failed", "domain", cfDomain, "err", err)
				if closeErr := wsConn.Close(websocket.StatusInternalError, "cannot reach CF tunnel"); closeErr != nil {
					slog.Warn("relay websocket close failed", "err", closeErr)
				}
				return
			}
			defer cfConn.CloseNow()
			cfConn.SetReadLimit(1 * 1024 * 1024)
			upstream = websocket.NetConn(ctx, cfConn, websocket.MessageBinary)
		} else {
			target := net.JoinHostPort(host, portStr)
			tcpConn, err := cfg.SafeDial(dialCtx, "tcp", target)
			if err != nil {
				slog.Error("relay tcp dial failed", "err", err)
				if closeErr := wsConn.Close(websocket.StatusInternalError, "cannot reach target"); closeErr != nil {
					slog.Warn("relay websocket close failed", "err", closeErr)
				}
				return
			}
			defer tcpConn.Close()
			upstream = tcpConn
		}

		slog.Info("relay started", "cf_tunnel", isCFTunnel)

		// Wrap browser WebSocket as net.Conn.
		wsNetConn := websocket.NetConn(ctx, wsConn, websocket.MessageBinary)

		// Ping loops to keep connections alive through NAT/proxies.
		go pingLoop(ctx, wsConn, cancel)
		if cfConn != nil {
			go pingLoop(ctx, cfConn, cancel)
		}

		// Bidirectional relay: browser WS ↔ upstream (TCP or CF WS).
		errc := make(chan error, 2)

		go func() {
			_, err := io.Copy(upstream, wsNetConn)
			errc <- fmt.Errorf("ws→upstream: %w", err)
			// For TCP upstream, signal write-side done.
			if tc, ok := upstream.(*net.TCPConn); ok {
				if closeErr := tc.CloseWrite(); closeErr != nil {
					slog.Debug("relay tcp close-write failed", "err", closeErr)
				}
			}
		}()

		go func() {
			_, err := io.Copy(wsNetConn, upstream)
			errc <- fmt.Errorf("upstream→ws: %w", err)
			cancel()
		}()

		// Wait for first direction to finish, then cancel the other.
		firstErr := <-errc
		slog.Info("relay first close", "err", firstErr)
		cancel()
		secondErr := <-errc
		slog.Info("relay second close", "err", secondErr)

		slog.Info("relay ended")
		if closeErr := wsConn.Close(websocket.StatusNormalClosure, "relay ended"); closeErr != nil {
			slog.Debug("relay websocket close failed", "err", closeErr)
		}
	}
}

// dialCFTunnel dials a WebSocket to a Cloudflare Access tunnel endpoint,
// authenticating with service-token headers on the upgrade request.
func dialCFTunnel(ctx context.Context, domain, clientID, clientSecret string) (*websocket.Conn, error) {
	u := "wss://" + domain + "/"
	conn, _, err := websocket.Dial(ctx, u, &websocket.DialOptions{
		HTTPHeader: http.Header{
			"CF-Access-Client-Id":     {clientID},
			"CF-Access-Client-Secret": {clientSecret},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("dial CF tunnel %s: %w", domain, err)
	}
	return conn, nil
}

// pingLoop sends WebSocket pings at regular intervals.
// Calls cancel if a ping fails (peer unresponsive).
func pingLoop(ctx context.Context, conn *websocket.Conn, cancel context.CancelFunc) {
	ticker := time.NewTicker(wsPingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := conn.Ping(ctx); err != nil {
				cancel()
				return
			}
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
