package main

import (
	"context"
	"crypto/rand"
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
	Type    string            `json:"type"`    // "http_request"
	ID      string            `json:"id"`      // unique request ID for correlation
	Method  string            `json:"method"`  // GET, POST, etc.
	Path    string            `json:"path"`    // /api/data
	Headers map[string]string `json:"headers"` // flattened headers
	Body    string            `json:"body"`    // base64 for binary
}

// HTTPResponse is sent browser → proxy as response to an HTTPRequest.
type HTTPResponse struct {
	Type    string            `json:"type"`    // "http_response"
	ID      string            `json:"id"`      // matches HTTPRequest.ID
	Status  int               `json:"status"`  // 200, 404, etc.
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`    // base64 for binary
}

// TCPOpen is sent proxy → browser when a new raw TCP connection arrives.
type TCPOpen struct {
	Type   string `json:"type"`   // "tcp_open"
	ConnID string `json:"connId"` // unique connection ID
}

// TCPClose is sent in either direction when a TCP connection ends.
type TCPClose struct {
	Type   string `json:"type"`   // "tcp_close"
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

	// Pending HTTP requests waiting for responses from the browser.
	mu       sync.Mutex
	pending  map[string]chan *HTTPResponse

	// Raw TCP connections multiplexed over this tunnel.
	tcpConns sync.Map // connID → net.Conn
}

// ────────────────────────────────────────────────────────────────────
// TunnelManager tracks all active tunnels and routes traffic.
// ────────────────────────────────────────────────────────────────────

type TunnelManager struct {
	cfg *Config

	mu      sync.RWMutex
	tunnels map[string]*Tunnel // subdomain → tunnel

	// Port allocation.
	portMu    sync.Mutex
	usedPorts map[int]bool
}

// NewTunnelManager creates a tunnel manager.
func NewTunnelManager(cfg *Config) *TunnelManager {
	return &TunnelManager{
		cfg:       cfg,
		tunnels:   make(map[string]*Tunnel),
		usedPorts: make(map[int]bool),
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
		clientIP := extractIP(r)
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

		slog.Info("tunnel registered", "subdomain", subdomain, "rawPort", rawPort, "user", userID)

		// Start raw TCP listener if port allocated.
		if rawPort > 0 {
			go tm.serveTCPPort(tunnel, rawPort)
		}

		// Read control messages from browser.
		for {
			_, data, err := wsConn.Read(ctx)
			if err != nil {
				return
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
				tunnel.mu.Lock()
				ch, ok := tunnel.pending[resp.ID]
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
				if conn, ok := tunnel.tcpConns.LoadAndDelete(tc.ConnID); ok {
					conn.(net.Conn).Close()
				}
			}
		}
	}
}

// HandleTunnelHTTP routes incoming HTTP requests on tunnel subdomains
// to the appropriate browser via WebSocket.
func (tm *TunnelManager) HandleTunnelHTTP(w http.ResponseWriter, r *http.Request) {
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

	// Generate unique request ID.
	reqID := generateShortID()

	// Flatten headers.
	headers := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		headers[k] = strings.Join(v, ", ")
	}

	// Read body.
	var body string
	if r.Body != nil {
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024)) // 10MB limit
		if err == nil {
			body = string(bodyBytes)
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
		Type:    "http_request",
		ID:      reqID,
		Method:  r.Method,
		Path:    r.URL.RequestURI(),
		Headers: headers,
		Body:    body,
	}
	reqJSON, _ := json.Marshal(httpReq)
	if err := tunnel.WS.Write(tunnel.Ctx, websocket.MessageText, reqJSON); err != nil {
		http.Error(w, "tunnel write failed", http.StatusBadGateway)
		return
	}

	// Wait for response from browser.
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	select {
	case resp := <-respCh:
		for k, v := range resp.Headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(resp.Status)
		w.Write([]byte(resp.Body))

	case <-ctx.Done():
		http.Error(w, "tunnel response timeout", http.StatusGatewayTimeout)
	}
}

// serveTCPPort listens on a raw TCP port and multiplexes connections
// through the tunnel WebSocket.
func (tm *TunnelManager) serveTCPPort(tunnel *Tunnel, port int) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		slog.Error("tunnel tcp listen failed", "port", port, "err", err)
		return
	}
	defer listener.Close()

	// Close listener when tunnel context is done.
	go func() {
		<-tunnel.Ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return // Listener closed.
		}
		go tm.handleTCPConn(tunnel, conn)
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
	if err := tunnel.WS.Write(tunnel.Ctx, websocket.MessageText, openJSON); err != nil {
		return
	}

	// Read from TCP and send binary frames to browser.
	// Binary frames are prefixed: [4 bytes connID length][connID][payload]
	buf := make([]byte, 32*1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			frame := buildBinaryFrame(connID, buf[:n])
			if writeErr := tunnel.WS.Write(tunnel.Ctx, websocket.MessageBinary, frame); writeErr != nil {
				return
			}
		}
		if err != nil {
			// Notify browser that TCP connection closed.
			closeMsg := TCPClose{Type: "tcp_close", ConnID: connID}
			closeJSON, _ := json.Marshal(closeMsg)
			tunnel.WS.Write(tunnel.Ctx, websocket.MessageText, closeJSON)
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
	// Strip port if present.
	h, _, _ := net.SplitHostPort(host)
	if h == "" {
		h = host
	}
	suffix := "." + tm.cfg.TunnelDomain
	if strings.HasSuffix(h, suffix) {
		sub := strings.TrimSuffix(h, suffix)
		if sub != "" && !strings.Contains(sub, ".") {
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
	return 0 // No ports available.
}

// releasePort returns a port to the available pool.
func (tm *TunnelManager) releasePort(port int) {
	tm.portMu.Lock()
	defer tm.portMu.Unlock()
	delete(tm.usedPorts, port)
}

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

// generateSubdomain creates a random 8-character hex subdomain.
func generateSubdomain() string {
	b := make([]byte, 4)
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
	frame := make([]byte, 4+idLen+len(payload))
	frame[0] = byte(idLen >> 24)
	frame[1] = byte(idLen >> 16)
	frame[2] = byte(idLen >> 8)
	frame[3] = byte(idLen)
	copy(frame[4:], idBytes)
	copy(frame[4+idLen:], payload)
	return frame
}
