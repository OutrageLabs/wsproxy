package main

import "testing"

func TestTunnelManager_GlobalTCPSlotCap(t *testing.T) {
	cfg := &Config{
		MaxTunnelTCPConnsGlobal: 2,
		TunnelDomain:            "tunnel.example.com",
	}
	tm := NewTunnelManager(cfg)

	if !tm.tryAcquireGlobalTCPSlot() {
		t.Fatal("first slot acquisition should succeed")
	}
	if !tm.tryAcquireGlobalTCPSlot() {
		t.Fatal("second slot acquisition should succeed")
	}
	if tm.tryAcquireGlobalTCPSlot() {
		t.Fatal("third slot acquisition should fail at capacity")
	}

	tm.releaseGlobalTCPSlot()
	if !tm.tryAcquireGlobalTCPSlot() {
		t.Fatal("slot acquisition should succeed after release")
	}
}

func TestParseBinaryFrame_RejectsOversizedConnID(t *testing.T) {
	// idLen=65 (> maxTunnelBinaryConnIDLength) with no payload.
	data := make([]byte, 4+65)
	data[3] = 65
	connID, payload := parseBinaryFrame(data)
	if connID != "" || payload != nil {
		t.Fatalf("expected invalid frame rejection, got connID=%q payload=%v", connID, payload)
	}
}

func TestExtractSubdomain_RequiresHexID(t *testing.T) {
	cfg := &Config{TunnelDomain: "tunnel.example.com"}
	tm := NewTunnelManager(cfg)

	if got := tm.extractSubdomain("abc123.tunnel.example.com"); got != "" {
		t.Fatalf("expected rejection for short non-standard subdomain, got %q", got)
	}
	if got := tm.extractSubdomain("0123456789abcdef.tunnel.example.com"); got != "0123456789abcdef" {
		t.Fatalf("expected valid hex subdomain, got %q", got)
	}
	if got := tm.extractSubdomain("ZZZZZZZZZZZZZZZZ.tunnel.example.com"); got != "" {
		t.Fatalf("expected rejection for non-hex subdomain, got %q", got)
	}
}

func TestBuildAndParseBinaryFrame_RoundTrip(t *testing.T) {
	connID := "0123456789ab"
	payload := []byte("hello")

	frame := buildBinaryFrame(connID, payload)
	if len(frame) == 0 {
		t.Fatal("expected non-empty frame")
	}
	gotID, gotPayload := parseBinaryFrame(frame)
	if gotID != connID {
		t.Fatalf("connID mismatch: got %q want %q", gotID, connID)
	}
	if string(gotPayload) != string(payload) {
		t.Fatalf("payload mismatch: got %q want %q", string(gotPayload), string(payload))
	}
}

func TestHeaderValidators(t *testing.T) {
	if !isValidHTTPHeaderName("Content-Type") {
		t.Fatal("expected valid header name")
	}
	if isValidHTTPHeaderName("Bad Header") {
		t.Fatal("expected invalid header name with space")
	}
	if isValidHTTPHeaderName("Bad\rName") {
		t.Fatal("expected invalid header name with CR")
	}

	if !isSafeHTTPHeaderValue("text/plain; charset=utf-8") {
		t.Fatal("expected valid header value")
	}
	if isSafeHTTPHeaderValue("evil\r\nInjected: yep") {
		t.Fatal("expected invalid header value with CRLF")
	}
	if isSafeHTTPHeaderValue("evil\u2028line") {
		t.Fatal("expected invalid header value with unicode newline")
	}
}
