package main

import (
	"net"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuth_Disabled(t *testing.T) {
	auth := NewAuth("") // No JWKS URL = auth disabled.

	req := httptest.NewRequest("GET", "/relay", nil)
	userID, err := auth.Authenticate(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if userID != "anonymous" {
		t.Errorf("expected anonymous, got %q", userID)
	}
}

func TestAuth_MissingToken(t *testing.T) {
	auth := NewAuth("https://example.com/.well-known/jwks.json")

	req := httptest.NewRequest("GET", "/relay", nil)
	_, err := auth.Authenticate(req)
	if err != errNoToken {
		t.Errorf("expected errNoToken, got %v", err)
	}
}

func TestAuth_InvalidToken(t *testing.T) {
	auth := NewAuth("https://example.com/.well-known/jwks.json")

	req := httptest.NewRequest("GET", "/relay?token=not.a.valid.jwt", nil)
	_, err := auth.Authenticate(req)
	if err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestBase64URLDecode(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"aGVsbG8", "hello"},
		{"aGVsbG8gd29ybGQ", "hello world"},
	}

	for _, tt := range tests {
		got, err := base64URLDecode(tt.input)
		if err != nil {
			t.Errorf("base64URLDecode(%q): %v", tt.input, err)
			continue
		}
		if string(got) != tt.expected {
			t.Errorf("base64URLDecode(%q): got %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestExtractIP(t *testing.T) {
	_, trusted, _ := net.ParseCIDR("1.2.3.0/24")
	trustedCfg := &Config{TrustedProxies: []*net.IPNet{trusted}}

	tests := []struct {
		remoteAddr string
		xff        string
		xRealIP    string
		cfg        *Config
		expected   string
	}{
		// No proxy headers, no trusted config.
		{"1.2.3.4:5000", "", "", nil, "1.2.3.4"},
		// XFF from trusted proxy — use XFF.
		{"1.2.3.4:5000", "5.6.7.8, 9.10.11.12", "", trustedCfg, "5.6.7.8"},
		// X-Real-IP from trusted proxy — use it.
		{"1.2.3.4:5000", "", "9.10.11.12", trustedCfg, "9.10.11.12"},
		// XFF from untrusted source — ignore, use RemoteAddr.
		{"9.9.9.9:5000", "5.6.7.8", "", trustedCfg, "9.9.9.9"},
		// No config at all (nil) — use RemoteAddr.
		{"1.2.3.4:5000", "5.6.7.8", "", nil, "1.2.3.4"},
	}

	for _, tt := range tests {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = tt.remoteAddr
		if tt.xff != "" {
			req.Header.Set("X-Forwarded-For", tt.xff)
		}
		if tt.xRealIP != "" {
			req.Header.Set("X-Real-IP", tt.xRealIP)
		}
		got := extractIP(req, tt.cfg)
		if got != tt.expected {
			t.Errorf("extractIP(%q, xff=%q, xri=%q): got %q, want %q",
				tt.remoteAddr, tt.xff, tt.xRealIP, got, tt.expected)
		}
	}
}

func TestAuth_InvalidJWKSURLFailsClosed(t *testing.T) {
	auth := NewAuth("http://example.com/jwks.json")
	req := httptest.NewRequest("GET", "/relay?token=a.b.c", nil)
	_, err := auth.Authenticate(req)
	if err == nil {
		t.Fatal("expected auth failure for insecure JWKS URL")
	}
	if !strings.Contains(err.Error(), "JWKS URL must use https") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateJWKSURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{name: "https allowed", url: "https://clerk.example.com/.well-known/jwks.json", wantErr: false},
		{name: "local http allowed", url: "http://localhost:8080/jwks.json", wantErr: false},
		{name: "non local http rejected", url: "http://example.com/jwks.json", wantErr: true},
		{name: "bad scheme rejected", url: "ftp://example.com/jwks", wantErr: true},
		{name: "empty host rejected", url: "https:///jwks", wantErr: true},
	}

	for _, tt := range tests {
		err := validateJWKSURL(tt.url)
		if (err != nil) != tt.wantErr {
			t.Fatalf("%s: validateJWKSURL(%q) err=%v wantErr=%v", tt.name, tt.url, err, tt.wantErr)
		}
	}
}
