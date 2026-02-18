package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestHandleRelay_MissingParams(t *testing.T) {
	cfg := &Config{
		AllowedOrigins: []string{"*"},
		MaxConnsPerIP:  10,
		MaxConnsPerUser: 20,
	}
	auth := NewAuth("") // Auth disabled
	rl := NewRateLimiter(10, 20)

	handler := HandleRelay(cfg, auth, rl)

	// Missing host
	req := httptest.NewRequest("GET", "/relay?port=22", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	// Missing port
	req = httptest.NewRequest("GET", "/relay?host=example.com", nil)
	w = httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleRelay_BlockedTarget(t *testing.T) {
	cfg, _ := LoadConfig()
	cfg.AllowedOrigins = []string{"*"}
	auth := NewAuth("")
	rl := NewRateLimiter(10, 20)

	handler := HandleRelay(cfg, auth, rl)

	// Localhost should be blocked
	req := httptest.NewRequest("GET", "/relay?host=127.0.0.1&port=22", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for localhost, got %d", w.Code)
	}

	// Private range should be blocked
	req = httptest.NewRequest("GET", "/relay?host=10.0.0.1&port=22", nil)
	w = httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for 10.x, got %d", w.Code)
	}
}

func TestHandleRelay_EndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	// Start a TCP echo server to act as a "target".
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoListener.Close()

	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					c.Write(buf[:n])
				}
			}(conn)
		}
	}()

	// Get the echo server address.
	echoAddr := echoListener.Addr().(*net.TCPAddr)

	// Build wsproxy handler that allows localhost (for testing).
	cfg := &Config{
		AllowedOrigins: []string{"*"},
		MaxConnsPerIP:  10,
		MaxConnsPerUser: 20,
		BlockedNets:    nil, // Allow all for testing
	}
	auth := NewAuth("")
	rl := NewRateLimiter(10, 20)

	handler := HandleRelay(cfg, auth, rl)
	server := httptest.NewServer(handler)
	defer server.Close()

	// Connect via WebSocket.
	wsURL := "ws" + server.URL[4:] + "?host=127.0.0.1&port=" + itoa(echoAddr.Port)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	wsConn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("websocket dial: %v", err)
	}
	defer wsConn.CloseNow()

	// Send data through the relay.
	testData := []byte("hello wsproxy")
	if err := wsConn.Write(ctx, websocket.MessageBinary, testData); err != nil {
		t.Fatalf("ws write: %v", err)
	}

	// Read echo response.
	_, data, err := wsConn.Read(ctx)
	if err != nil {
		t.Fatalf("ws read: %v", err)
	}

	if string(data) != string(testData) {
		t.Errorf("echo mismatch: got %q, want %q", data, testData)
	}

	wsConn.Close(websocket.StatusNormalClosure, "done")
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}
