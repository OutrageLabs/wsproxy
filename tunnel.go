package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

const (
	maxTunnelHeaders            = 100
	maxTunnelHeaderValueLen     = 8 * 1024
	maxTunnelResponseBodyBytes  = 10 * 1024 * 1024
	maxTunnelBinaryConnIDLength = 64
)

// ────────────────────────────────────────────────────────────────────
// Tunnel control protocol messages (JSON over WebSocket)
// ────────────────────────────────────────────────────────────────────

// TunnelReady is sent proxy → browser after tunnel registration.
type TunnelReady struct {
	Type      string `json:"type"`      // "tunnel_ready"
	TunnelURL string `json:"tunnelUrl"` // https://abc123.tunnel.example.com
	RawPort   int    `json:"rawPort"`   // 10042 (0 if unavailable)
}

// HTTPRequest is sent proxy → browser for incoming HTTP requests on the subdomain.
type HTTPRequest struct {
	Type         string            `json:"type"`                   // "http_request"
	ID           string            `json:"id"`                     // unique request ID for correlation
	Method       string            `json:"method"`                 // GET, POST, etc.
	Path         string            `json:"path"`                   // /api/data
	Headers      map[string]string `json:"headers"`                // flattened headers
	Body         string            `json:"body"`                   // text or base64-encoded
	BodyEncoding string            `json:"bodyEncoding,omitempty"` // "base64" if body is encoded
}

// HTTPResponse is sent browser → proxy as response to an HTTPRequest.
type HTTPResponse struct {
	Type         string            `json:"type"`   // "http_response"
	ID           string            `json:"id"`     // matches HTTPRequest.ID
	Status       int               `json:"status"` // 200, 404, etc.
	Headers      map[string]string `json:"headers"`
	Body         string            `json:"body"`                   // text or base64-encoded
	BodyEncoding string            `json:"bodyEncoding,omitempty"` // "base64" if body is encoded
}

// TCPOpen is sent proxy → browser when a new raw TCP connection arrives.
type TCPOpen struct {
	Type   string `json:"type"`   // "tcp_open"
	ConnID string `json:"connId"` // unique connection ID
}

// TCPClose is sent in either direction when a TCP connection ends.
type TCPClose struct {
	Type   string `json:"type"` // "tcp_close"
	ConnID string `json:"connId"`
}

// ControlMessage is a generic envelope for decoding incoming messages.
type ControlMessage struct {
	Type string `json:"type"`
}

// ────────────────────────────────────────────────────────────────────
// Tunnel represents an active tunnel registration.
// ────────────────────────────────────────────────────────────────────

type Tunnel struct {
	ID        string
	Subdomain string
	RawPort   int
	UserID    string
	WS        *websocket.Conn
	Ctx       context.Context
	Cancel    context.CancelFunc

	// wsMu serializes all writes to the WebSocket connection.
	// coder/websocket does NOT support concurrent writers.
	wsMu sync.Mutex

	// Pending HTTP requests waiting for responses from the browser.
	mu      sync.Mutex
	pending map[string]chan *HTTPResponse

	// Raw TCP connections multiplexed over this tunnel.
	tcpConns sync.Map // connID → net.Conn
}

// writeWS is a concurrency-safe write to the tunnel WebSocket.
func (t *Tunnel) writeWS(msgType websocket.MessageType, data []byte) error {
	t.wsMu.Lock()
	defer t.wsMu.Unlock()
	return t.WS.Write(t.Ctx, msgType, data)
}

// ────────────────────────────────────────────────────────────────────
// TunnelManager tracks all active tunnels and routes traffic.
// ────────────────────────────────────────────────────────────────────

type TunnelManager struct {
	cfg *Config

	mu      sync.RWMutex
	tunnels map[string]*Tunnel // subdomain → tunnel

	// Global TCP connection cap across all active tunnels.
	tcpConnSem chan struct{}

	// Port allocation.
	portMu    sync.Mutex
	usedPorts map[int]bool
}

// NewTunnelManager creates a tunnel manager.
func NewTunnelManager(cfg *Config) *TunnelManager {
	globalCap := cfg.MaxTunnelTCPConnsGlobal
	if globalCap <= 0 {
		globalCap = 1000
	}
	return &TunnelManager{
		cfg:        cfg,
		tunnels:    make(map[string]*Tunnel),
		tcpConnSem: make(chan struct{}, globalCap),
		usedPorts:  make(map[int]bool),
	}
}

// HandleTunnelRegister handles the WebSocket endpoint for registering a new tunnel.
// The browser connects here to establish a tunnel control channel.
//
// Protocol: wss://proxy/tunnel?token=JWT
func (tm *TunnelManager) HandleTunnelRegister(auth *Auth, rl *RateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authenticate.
		userID, err := auth.Authenticate(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Rate limit.
		clientIP := extractIP(r, tm.cfg)
		if !rl.Acquire(clientIP, userID) {
			http.Error(w, "too many connections", http.StatusTooManyRequests)
			return
		}
		defer rl.Release(clientIP, userID)

		// Upgrade to WebSocket.
		wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			OriginPatterns: tm.cfg.AllowedOrigins,
		})
		if err != nil {
			slog.Error("tunnel websocket upgrade failed", "err", err)
			return
		}
		defer wsConn.CloseNow()

		// Generate unique subdomain.
		subdomain := generateSubdomain()

		// Allocate raw port.
		rawPort := tm.allocatePort()

		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()

		tunnel := &Tunnel{
			ID:        subdomain,
			Subdomain: subdomain,
			RawPort:   rawPort,
			UserID:    userID,
			WS:        wsConn,
			Ctx:       ctx,
			Cancel:    cancel,
			pending:   make(map[string]chan *HTTPResponse),
		}

		// Register tunnel.
		tm.mu.Lock()
		tm.tunnels[subdomain] = tunnel
		tm.mu.Unlock()

		defer func() {
			tm.mu.Lock()
			delete(tm.tunnels, subdomain)
			tm.mu.Unlock()
			if rawPort > 0 {
				tm.releasePort(rawPort)
			}
			slog.Info("tunnel closed", "subdomain", subdomain, "user", userID)
		}()

		// Build tunnel URL.
		tunnelURL := ""
		if tm.cfg.TunnelDomain != "" {
			tunnelURL = fmt.Sprintf("https://%s.%s", subdomain, tm.cfg.TunnelDomain)
		}

		// Send tunnel_ready to browser.
		ready := TunnelReady{
			Type:      "tunnel_ready",
			TunnelURL: tunnelURL,
			RawPort:   rawPort,
		}
		readyJSON, _ := json.Marshal(ready)
		if err := wsConn.Write(ctx, websocket.MessageText, readyJSON); err != nil {
			slog.Error("tunnel write ready failed", "err", err)
			return
		}

		slog.Info("tunnel registered", "subdomain", subdomain, "rawPort", rawPort)

		// Start raw TCP listener if port allocated.
		if rawPort > 0 {
			go tm.serveTCPPort(tunnel, rawPort)
		}

		// Set read size limit to prevent OOM from malicious clients.
		wsConn.SetReadLimit(10 * 1024 * 1024) // 10 MB

		// Start ping loop to keep tunnel alive through NAT/proxies.
		go func() {
			ticker := time.NewTicker(30 * time.Second)
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

		// Read control messages and binary TCP data from browser.
		for {
			msgType, data, err := wsConn.Read(ctx)
			if err != nil {
				return
			}

			// Binary frames carry TCP data: [4B connID len][connID][payload]
			if msgType == websocket.MessageBinary {
				connID, payload := parseBinaryFrame(data)
				if connID != "" && len(payload) > 0 && isHexSubdomain(connID, 12) {
					if conn, ok := tunnel.tcpConns.Load(connID); ok {
						tcpConn := conn.(net.Conn)
						if err := tcpConn.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
							tunnel.tcpConns.Delete(connID)
							_ = tcpConn.Close()
							continue
						}
						if _, err := tcpConn.Write(payload); err != nil {
							// Write failed — close the TCP connection and notify browser.
							tunnel.tcpConns.Delete(connID)
							_ = tcpConn.Close()
							closeMsg := TCPClose{Type: "tcp_close", ConnID: connID}
							closeJSON, _ := json.Marshal(closeMsg)
							if writeErr := tunnel.writeWS(websocket.MessageText, closeJSON); writeErr != nil {
								slog.Debug("tunnel tcp close notify failed", "err", writeErr)
							}
						}
					}
				}
				continue
			}

			var msg ControlMessage
			if err := json.Unmarshal(data, &msg); err != nil {
				continue
			}

			switch msg.Type {
			case "http_response":
				var resp HTTPResponse
				if err := json.Unmarshal(data, &resp); err != nil {
					continue
				}
				if !isHexSubdomain(resp.ID, 12) {
					continue
				}
				tunnel.mu.Lock()
				ch, ok := tunnel.pending[resp.ID]
				if ok {
					delete(tunnel.pending, resp.ID)
				}
				tunnel.mu.Unlock()
				if ok {
					select {
					case ch <- &resp:
					default:
					}
				}

			case "tcp_close":
				var tc TCPClose
				if err := json.Unmarshal(data, &tc); err != nil {
					continue
				}
				if !isHexSubdomain(tc.ConnID, 12) {
					continue
				}
				if conn, ok := tunnel.tcpConns.LoadAndDelete(tc.ConnID); ok {
					_ = conn.(net.Conn).Close()
				}
			}
		}
	}
}

// HandleTunnelHTTP routes incoming HTTP requests on tunnel subdomains
// to the appropriate browser via WebSocket.
func (tm *TunnelManager) HandleTunnelHTTP(w http.ResponseWriter, r *http.Request, rl *RateLimiter) {
	// Extract subdomain from Host header.
	subdomain := tm.extractSubdomain(r.Host)
	if subdomain == "" {
		http.Error(w, "invalid tunnel", http.StatusNotFound)
		return
	}

	tm.mu.RLock()
	tunnel, ok := tm.tunnels[subdomain]
	tm.mu.RUnlock()
	if !ok {
		http.Error(w, "tunnel not found", http.StatusNotFound)
		return
	}

	// Rate limit tunnel HTTP traffic by client IP only.
	// Don't attribute to tunnel owner — external DDoS traffic shouldn't
	// exhaust the tunnel owner's per-user quota.
	clientIP := extractIP(r, tm.cfg)
	if !rl.Acquire(clientIP, "") {
		http.Error(w, "too many connections", http.StatusTooManyRequests)
		return
	}
	defer rl.Release(clientIP, "")

	// Generate unique request ID.
	reqID := generateShortID()

	// Flatten headers, stripping sensitive ones that the tunnel owner shouldn't see.
	headers := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		switch strings.ToLower(k) {
		case "cookie", "authorization", "proxy-authorization",
			"set-cookie", "x-csrf-token", "x-xsrf-token":
			continue
		}
		headers[k] = strings.Join(v, ", ")
	}

	// Read body — encode as base64 to preserve binary data through JSON.
	var body string
	bodyEncoding := ""
	if r.Body != nil {
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024)) // 10MB limit
		if err == nil && len(bodyBytes) > 0 {
			body = base64.StdEncoding.EncodeToString(bodyBytes)
			bodyEncoding = "base64"
		}
	}

	// Create pending response channel.
	respCh := make(chan *HTTPResponse, 1)
	tunnel.mu.Lock()
	tunnel.pending[reqID] = respCh
	tunnel.mu.Unlock()

	defer func() {
		tunnel.mu.Lock()
		delete(tunnel.pending, reqID)
		tunnel.mu.Unlock()
	}()

	// Send HTTP request to browser.
	httpReq := HTTPRequest{
		Type:         "http_request",
		ID:           reqID,
		Method:       r.Method,
		Path:         r.URL.RequestURI(),
		Headers:      headers,
		Body:         body,
		BodyEncoding: bodyEncoding,
	}
	reqJSON, _ := json.Marshal(httpReq)
	if err := tunnel.writeWS(websocket.MessageText, reqJSON); err != nil {
		http.Error(w, "tunnel write failed", http.StatusBadGateway)
		return
	}

	// Wait for response from browser, or tunnel disconnect.
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	select {
	case <-tunnel.Ctx.Done():
		http.Error(w, "tunnel disconnected", http.StatusBadGateway)
		return
	case resp := <-respCh:
		// Validate status code to prevent panics from malformed responses.
		status := resp.Status
		if status < 100 || status > 999 {
			http.Error(w, "invalid response from tunnel", http.StatusBadGateway)
			return
		}
		// Set headers, filtering out hop-by-hop and security-sensitive headers.
		// The browser controls these headers — don't let it set cookies,
		// override CORS, or manipulate security policies on the tunnel domain.
		headerCount := 0
		for k, v := range resp.Headers {
			if headerCount >= maxTunnelHeaders {
				break // Limit total headers to prevent memory exhaustion.
			}
			if !isValidHTTPHeaderName(k) || !isSafeHTTPHeaderValue(v) {
				continue
			}
			switch strings.ToLower(k) {
			case "connection", "keep-alive", "transfer-encoding", "upgrade",
				"te", "trailer", "content-length",
				"set-cookie", "set-cookie2",
				"access-control-allow-origin", "access-control-allow-credentials",
				"access-control-allow-methods", "access-control-allow-headers",
				"strict-transport-security",
				"content-security-policy", "content-security-policy-report-only",
				"x-frame-options", "x-content-type-options", "x-xss-protection",
				"public-key-pins", "public-key-pins-report-only":
				continue
			}
			w.Header().Set(k, v)
			headerCount++
		}
		w.WriteHeader(status)
		// Decode body if base64-encoded.
		var body []byte
		if resp.BodyEncoding == "base64" {
			decoded, err := base64.StdEncoding.DecodeString(resp.Body)
			if err != nil {
				http.Error(w, "invalid base64 response from tunnel", http.StatusBadGateway)
				return
			}
			body = decoded
		} else if resp.BodyEncoding == "" {
			body = []byte(resp.Body)
		} else {
			http.Error(w, "invalid body encoding from tunnel", http.StatusBadGateway)
			return
		}
		if len(body) > maxTunnelResponseBodyBytes {
			http.Error(w, "tunnel response too large", http.StatusBadGateway)
			return
		}
		if _, err := w.Write(body); err != nil {
			slog.Warn("tunnel response write failed", "err", err)
		}

	case <-ctx.Done():
		http.Error(w, "tunnel response timeout", http.StatusGatewayTimeout)
	}
}

// serveTCPPort listens on a raw TCP port and multiplexes connections
// through the tunnel WebSocket.
func (tm *TunnelManager) serveTCPPort(tunnel *Tunnel, port int) {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		slog.Error("tunnel tcp listen failed", "port", port, "err", err)
		return
	}
	defer listener.Close()

	// Close listener when tunnel context is done.
	go func() {
		<-tunnel.Ctx.Done()
		_ = listener.Close()
	}()

	// Limit concurrent TCP connections per tunnel to prevent goroutine exhaustion.
	const maxTCPConnsPerTunnel = 100
	sem := make(chan struct{}, maxTCPConnsPerTunnel)

	for {
		conn, err := listener.Accept()
		if err != nil {
			return // Listener closed.
		}
		select {
		case sem <- struct{}{}:
			if !tm.tryAcquireGlobalTCPSlot() {
				<-sem
				_ = conn.Close()
				continue
			}
			go func() {
				defer func() {
					tm.releaseGlobalTCPSlot()
					<-sem
				}()
				tm.handleTCPConn(tunnel, conn)
			}()
		default:
			// At limit — reject connection.
			_ = conn.Close()
		}
	}
}

// handleTCPConn handles a single raw TCP connection coming in on a tunnel port.
func (tm *TunnelManager) handleTCPConn(tunnel *Tunnel, conn net.Conn) {
	defer conn.Close()

	connID := generateShortID()
	tunnel.tcpConns.Store(connID, conn)
	defer tunnel.tcpConns.Delete(connID)

	// Notify browser of new TCP connection.
	openMsg := TCPOpen{Type: "tcp_open", ConnID: connID}
	openJSON, _ := json.Marshal(openMsg)
	if err := tunnel.writeWS(websocket.MessageText, openJSON); err != nil {
		return
	}

	// Read from TCP and send binary frames to browser.
	// Binary frames are prefixed: [4 bytes connID length][connID][payload]
	buf := make([]byte, 32*1024)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Minute)); err != nil {
			return
		}
		n, err := conn.Read(buf)
		if n > 0 {
			frame := buildBinaryFrame(connID, buf[:n])
			if len(frame) == 0 {
				return
			}
			if writeErr := tunnel.writeWS(websocket.MessageBinary, frame); writeErr != nil {
				return
			}
		}
		if err != nil {
			// Notify browser that TCP connection closed.
			closeMsg := TCPClose{Type: "tcp_close", ConnID: connID}
			closeJSON, _ := json.Marshal(closeMsg)
			if writeErr := tunnel.writeWS(websocket.MessageText, closeJSON); writeErr != nil {
				slog.Debug("tunnel tcp close notify failed", "err", writeErr)
			}
			return
		}
	}
}

// extractSubdomain extracts the tunnel subdomain from a Host header.
// For "abc123.tunnel.example.com", returns "abc123".
func (tm *TunnelManager) extractSubdomain(host string) string {
	if tm.cfg.TunnelDomain == "" {
		return ""
	}
	h := canonicalHost(host)
	tunnelDomain := canonicalHost(tm.cfg.TunnelDomain)
	suffix := "." + tunnelDomain
	if strings.HasSuffix(h, suffix) {
		sub := strings.TrimSuffix(h, suffix)
		if !strings.Contains(sub, ".") && isHexSubdomain(sub, 16) {
			return sub
		}
	}
	return ""
}

// allocatePort finds an available port from the configured range.
func (tm *TunnelManager) allocatePort() int {
	tm.portMu.Lock()
	defer tm.portMu.Unlock()

	for p := tm.cfg.TunnelPortMin; p < tm.cfg.TunnelPortMax; p++ {
		if !tm.usedPorts[p] {
			tm.usedPorts[p] = true
			return p
		}
	}
	slog.Warn("tunnel port exhaustion: no ports available", "rangeMin", tm.cfg.TunnelPortMin, "rangeMax", tm.cfg.TunnelPortMax)
	return 0 // No ports available.
}

// releasePort returns a port to the available pool.
func (tm *TunnelManager) releasePort(port int) {
	tm.portMu.Lock()
	defer tm.portMu.Unlock()
	delete(tm.usedPorts, port)
}

func (tm *TunnelManager) tryAcquireGlobalTCPSlot() bool {
	select {
	case tm.tcpConnSem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (tm *TunnelManager) releaseGlobalTCPSlot() {
	select {
	case <-tm.tcpConnSem:
	default:
	}
}

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

// generateSubdomain creates a random 16-character hex subdomain (64-bit entropy).
func generateSubdomain() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// generateShortID creates a random 12-character hex ID.
func generateShortID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// buildBinaryFrame constructs a binary WebSocket frame for TCP tunnel data.
// Format: [4 bytes connID length (big-endian)][connID bytes][payload bytes]
func buildBinaryFrame(connID string, payload []byte) []byte {
	idBytes := []byte(connID)
	idLen := len(idBytes)
	if idLen <= 0 || idLen > maxTunnelBinaryConnIDLength {
		return nil
	}
	frame := make([]byte, 4+idLen+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(idLen))
	copy(frame[4:], idBytes)
	copy(frame[4+idLen:], payload)
	return frame
}

// parseBinaryFrame extracts connID and payload from a binary TCP frame.
// Format: [4B connID len (big-endian)][connID bytes][payload bytes]
func parseBinaryFrame(data []byte) (connID string, payload []byte) {
	if len(data) < 4 {
		return "", nil
	}
	idLen := int(binary.BigEndian.Uint32(data[:4]))
	if idLen <= 0 || idLen > maxTunnelBinaryConnIDLength {
		return "", nil
	}
	if idLen > len(data)-4 {
		return "", nil
	}
	return string(data[4 : 4+idLen]), data[4+idLen:]
}

func isValidHTTPHeaderName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		isTokenChar := (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '!' || c == '#' || c == '$' || c == '%' || c == '&' ||
			c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' ||
			c == '^' || c == '_' || c == '`' || c == '|' || c == '~'
		if !isTokenChar {
			return false
		}
	}
	return true
}

func isSafeHTTPHeaderValue(value string) bool {
	if len(value) > maxTunnelHeaderValueLen {
		return false
	}
	for _, r := range value {
		switch {
		case r == '\r' || r == '\n' || r == '\u2028' || r == '\u2029' || r == 0:
			return false
		case r < 0x20 || r == 0x7f:
			return false
		}
	}
	return true
}
