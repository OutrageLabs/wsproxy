package main

import (
	"net/http/httptest"
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
	tests := []struct {
		remoteAddr string
		xff        string
		xRealIP    string
		expected   string
	}{
		{"1.2.3.4:5000", "", "", "1.2.3.4"},
		{"1.2.3.4:5000", "5.6.7.8, 9.10.11.12", "", "5.6.7.8"},
		{"1.2.3.4:5000", "", "9.10.11.12", "9.10.11.12"},
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
		got := extractIP(req)
		if got != tt.expected {
			t.Errorf("extractIP(%q, xff=%q, xri=%q): got %q, want %q",
				tt.remoteAddr, tt.xff, tt.xRealIP, got, tt.expected)
		}
	}
}
