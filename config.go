package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// Config holds all server configuration, loaded from environment variables.
type Config struct {
	Port            int
	ClerkJWKSURL    string
	AllowedOrigins  []string
	TunnelDomain    string
	TunnelPortMin   int
	TunnelPortMax   int
	MaxConnsPerIP   int
	MaxConnsPerUser int
	BlockedNets     []*net.IPNet
}

// LoadConfig reads configuration from environment variables with defaults.
func LoadConfig() (*Config, error) {
	c := &Config{
		Port:            envInt("PORT", 8080),
		ClerkJWKSURL:    envStr("CLERK_JWKS_URL", ""),
		AllowedOrigins:  envList("ALLOWED_ORIGINS", []string{"*"}),
		TunnelDomain:    envStr("TUNNEL_DOMAIN", ""),
		TunnelPortMin:   envInt("TUNNEL_PORT_MIN", 10000),
		TunnelPortMax:   envInt("TUNNEL_PORT_MAX", 10100),
		MaxConnsPerIP:   envInt("MAX_CONNS_PER_IP", 10),
		MaxConnsPerUser: envInt("MAX_CONNS_PER_USER", 20),
	}

	// Parse blocked target networks.
	defaultBlocked := "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,::1/128,fc00::/7,fe80::/10"
	blockedStr := envStr("BLOCKED_TARGETS", defaultBlocked)
	for _, cidr := range strings.Split(blockedStr, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid BLOCKED_TARGETS CIDR %q: %w", cidr, err)
		}
		c.BlockedNets = append(c.BlockedNets, ipNet)
	}

	if c.TunnelPortMin >= c.TunnelPortMax {
		return nil, fmt.Errorf("TUNNEL_PORT_MIN (%d) must be less than TUNNEL_PORT_MAX (%d)", c.TunnelPortMin, c.TunnelPortMax)
	}

	return c, nil
}

// IsTargetBlocked checks if a host IP falls within any blocked network range.
// Returns true if the target should be rejected.
func (c *Config) IsTargetBlocked(host string) bool {
	ips, err := net.LookupIP(host)
	if err != nil {
		// If we can't resolve, check if it's a raw IP.
		ip := net.ParseIP(host)
		if ip == nil {
			return true // Can't resolve and not an IP — block it.
		}
		ips = []net.IP{ip}
	}

	for _, ip := range ips {
		for _, blocked := range c.BlockedNets {
			if blocked.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func envStr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func envList(key string, fallback []string) []string {
	if v := os.Getenv(key); v != "" {
		parts := strings.Split(v, ",")
		result := make([]string, 0, len(parts))
		for _, p := range parts {
			if t := strings.TrimSpace(p); t != "" {
				result = append(result, t)
			}
		}
		return result
	}
	return fallback
}
