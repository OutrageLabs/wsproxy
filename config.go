package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
)

// Config holds all server configuration, loaded from environment variables.
type Config struct {
	Port                    int
	ClerkJWKSURL            string
	JWTIssuer               string // Expected JWT iss claim (empty = skip check)
	JWTAudience             string // Expected JWT aud claim (empty = skip check)
	AllowedOrigins          []string
	TunnelDomain            string
	TunnelPortMin           int
	TunnelPortMax           int
	MaxConnsPerIP           int
	MaxConnsPerUser         int
	MaxTunnelHTTPPerIP      int // Separate limit for tunnel HTTP requests
	MaxTunnelTCPConnsGlobal int // Global cap across all tunnels.
	BlockedNets             []*net.IPNet
	TrustedProxies          []*net.IPNet // CIDRs whose X-Forwarded-For headers are trusted
}

// LoadConfig reads configuration from environment variables with defaults.
func LoadConfig() (*Config, error) {
	c := &Config{
		Port:                    envInt("PORT", 8080),
		ClerkJWKSURL:            envStr("CLERK_JWKS_URL", ""),
		JWTIssuer:               envStr("JWT_ISSUER", ""),
		JWTAudience:             envStr("JWT_AUDIENCE", ""),
		AllowedOrigins:          envList("ALLOWED_ORIGINS", []string{"*"}),
		TunnelDomain:            envStr("TUNNEL_DOMAIN", ""),
		TunnelPortMin:           envInt("TUNNEL_PORT_MIN", 10000),
		TunnelPortMax:           envInt("TUNNEL_PORT_MAX", 10100),
		MaxConnsPerIP:           envInt("MAX_CONNS_PER_IP", 10),
		MaxConnsPerUser:         envInt("MAX_CONNS_PER_USER", 20),
		MaxTunnelHTTPPerIP:      envInt("MAX_TUNNEL_HTTP_PER_IP", 50),
		MaxTunnelTCPConnsGlobal: envInt("MAX_TUNNEL_TCP_CONNS_GLOBAL", 1000),
	}

	// Parse blocked target networks.
	defaultBlocked := "0.0.0.0/8,127.0.0.0/8,10.0.0.0/8,100.64.0.0/10,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,198.18.0.0/15,::1/128,fc00::/7,fe80::/10"
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

	// Parse trusted proxy CIDRs (e.g., "10.0.0.0/8,172.16.0.0/12").
	// Only requests from these IPs will have X-Forwarded-For / X-Real-IP honored.
	if trustedStr := envStr("TRUSTED_PROXIES", ""); trustedStr != "" {
		for _, cidr := range strings.Split(trustedStr, ",") {
			cidr = strings.TrimSpace(cidr)
			if cidr == "" {
				continue
			}
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("invalid TRUSTED_PROXIES CIDR %q: %w", cidr, err)
			}
			c.TrustedProxies = append(c.TrustedProxies, ipNet)
		}
	}

	if c.TunnelPortMin >= c.TunnelPortMax {
		return nil, fmt.Errorf("TUNNEL_PORT_MIN (%d) must be less than TUNNEL_PORT_MAX (%d)", c.TunnelPortMin, c.TunnelPortMax)
	}

	return c, nil
}

// IsTargetBlocked checks if a host IP falls within any blocked network range.
// Returns true if the target should be rejected.
// Note: SafeDial also checks resolved IPs, preventing DNS rebinding.
// This pre-check provides fast rejection before attempting a TCP connection.
func (c *Config) IsTargetBlocked(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return true
	}

	// First check if it's a raw IP.
	if ip := net.ParseIP(host); ip != nil {
		return c.isBlockedIP(ip)
	}

	// Reject invalid hostnames up front.
	if !isValidHostname(host) {
		return true
	}

	// DNS lookup with timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return true // Can't resolve — block it.
	}

	for _, addr := range ips {
		if c.isBlockedIP(addr.IP) {
			return true
		}
	}
	return false
}

// SafeDial dials a TCP connection after verifying the resolved IP is not blocked.
// This prevents DNS rebinding attacks where the first resolution (IsTargetBlocked)
// returns a safe IP but a second resolution (net.Dial) returns a blocked IP.
func (c *Config) SafeDial(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(network, address string, rawConn syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("invalid address %q: %w", address, err)
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("resolved address %q is not an IP", host)
			}
			if c.isBlockedIP(ip) {
				return fmt.Errorf("resolved IP %s is blocked", ip)
			}
			return nil
		},
	}
	return d.DialContext(ctx, network, addr)
}

// IsTrustedProxy checks if the given IP belongs to a trusted proxy network.
func (c *Config) IsTrustedProxy(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range c.TrustedProxies {
		if cidr.Contains(parsed) {
			return true
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

func (c *Config) isBlockedIP(ip net.IP) bool {
	ip = normalizeIP(ip)
	if ip == nil {
		return true
	}

	// Preserve existing behavior for explicit allow-all configs
	// (used by tests and opt-out deployments).
	if len(c.BlockedNets) == 0 {
		return false
	}

	// Defense in depth: deny non-public targets even if BLOCKED_TARGETS is misconfigured.
	if ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() {
		return true
	}

	for _, blocked := range c.BlockedNets {
		if blocked.Contains(ip) {
			return true
		}
	}
	return false
}

func normalizeIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

func isValidHostname(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 {
		return false
	}
	if strings.ContainsAny(host, " \t\r\n/\\") {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}
