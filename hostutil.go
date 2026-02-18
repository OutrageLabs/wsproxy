package main

import (
	"net"
	"strings"
)

func canonicalHost(host string) string {
	host = strings.TrimSpace(host)
	if h, p, err := net.SplitHostPort(host); err == nil && p != "" {
		host = h
	}
	host = strings.TrimSuffix(host, ".")
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	return strings.ToLower(host)
}

func isHexSubdomain(sub string, expectedLen int) bool {
	if expectedLen > 0 && len(sub) != expectedLen {
		return false
	}
	if sub == "" {
		return false
	}
	for _, r := range sub {
		if ('0' <= r && r <= '9') || ('a' <= r && r <= 'f') {
			continue
		}
		return false
	}
	return true
}
