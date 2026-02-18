package main

import (
	"context"
	"testing"
)

func TestLoadConfig_Defaults(t *testing.T) {
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.Port != 8080 {
		t.Errorf("Port: got %d, want 8080", cfg.Port)
	}
	if cfg.MaxConnsPerIP != 10 {
		t.Errorf("MaxConnsPerIP: got %d, want 10", cfg.MaxConnsPerIP)
	}
	if cfg.MaxConnsPerUser != 20 {
		t.Errorf("MaxConnsPerUser: got %d, want 20", cfg.MaxConnsPerUser)
	}
	if cfg.TunnelPortMin != 10000 {
		t.Errorf("TunnelPortMin: got %d, want 10000", cfg.TunnelPortMin)
	}
	if len(cfg.BlockedNets) == 0 {
		t.Error("BlockedNets: expected default blocked networks")
	}
}

func TestIsTargetBlocked(t *testing.T) {
	cfg, _ := LoadConfig()

	tests := []struct {
		host    string
		blocked bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"169.254.1.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}

	for _, tt := range tests {
		if got := cfg.IsTargetBlocked(tt.host); got != tt.blocked {
			t.Errorf("IsTargetBlocked(%q): got %v, want %v", tt.host, got, tt.blocked)
		}
	}
}

func TestSafeDial_ContextCanceled(t *testing.T) {
	cfg := &Config{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := cfg.SafeDial(ctx, "tcp", "8.8.8.8:53")
	if err == nil {
		t.Fatal("expected dial to fail with canceled context")
	}
}
