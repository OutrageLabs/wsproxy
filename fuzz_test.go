package main

import "testing"

func FuzzParseBinaryFrame(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 1, 'x'})
	if seed := buildBinaryFrame("0123456789ab", []byte("payload")); len(seed) > 0 {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		connID, payload := parseBinaryFrame(data)
		if connID == "" {
			return
		}
		if len(connID) > maxTunnelBinaryConnIDLength {
			t.Fatalf("connID too large: %d", len(connID))
		}
		if payload == nil {
			t.Fatal("payload must be non-nil when connID is returned")
		}
	})
}

func FuzzHeaderValidators(f *testing.F) {
	f.Add("Content-Type", "text/plain")
	f.Add("Bad Header", "ok")
	f.Add("X-Test", "evil\r\nInjected: yes")

	f.Fuzz(func(t *testing.T, name, value string) {
		nameOK := isValidHTTPHeaderName(name)
		valueOK := isSafeHTTPHeaderValue(value)

		if nameOK && (containsCRLF(name) || containsSpace(name)) {
			t.Fatalf("header name accepted unsafe content: %q", name)
		}
		if valueOK && containsForbiddenHeaderValueChars(value) {
			t.Fatalf("header value accepted unsafe content: %q", value)
		}
	})
}

func containsCRLF(s string) bool {
	for _, r := range s {
		if r == '\r' || r == '\n' {
			return true
		}
	}
	return false
}

func containsSpace(s string) bool {
	for _, r := range s {
		if r == ' ' || r == '\t' {
			return true
		}
	}
	return false
}

func containsForbiddenHeaderValueChars(s string) bool {
	for _, r := range s {
		if r == '\r' || r == '\n' || r == '\u2028' || r == '\u2029' || r == 0 {
			return true
		}
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
