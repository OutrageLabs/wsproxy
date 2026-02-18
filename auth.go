package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

var cryptoSHA256 = crypto.SHA256

var (
	errNoToken       = errors.New("auth: no token provided")
	errInvalidToken  = errors.New("auth: invalid token")
	errTokenExpired  = errors.New("auth: token expired")
	errNoMatchingKey = errors.New("auth: no matching JWK for kid")
	errAuthDisabled  = errors.New("auth: JWKS URL not configured")
)

// Auth handles JWT validation using Clerk's JWKS endpoint.
type Auth struct {
	jwksURL   string
	issuer    string // Expected iss claim (empty = skip)
	audience  string // Expected aud claim (empty = skip)
	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey // kid → public key
	fetchedAt time.Time
	cacheTTL  time.Duration
	sfGroup   singleflight.Group
}

// NewAuth creates a new JWT authenticator. If jwksURL is empty, auth is disabled
// (all requests pass — useful for development).
func NewAuth(jwksURL string, opts ...AuthOption) *Auth {
	a := &Auth{
		jwksURL:  jwksURL,
		keys:     make(map[string]*rsa.PublicKey),
		cacheTTL: 15 * time.Minute,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// AuthOption configures optional Auth parameters.
type AuthOption func(*Auth)

// WithIssuer sets the expected JWT issuer (iss claim).
func WithIssuer(iss string) AuthOption {
	return func(a *Auth) { a.issuer = iss }
}

// WithAudience sets the expected JWT audience (aud claim).
func WithAudience(aud string) AuthOption {
	return func(a *Auth) { a.audience = aud }
}

// Claims holds the validated JWT claims we care about.
type Claims struct {
	Sub    string          `json:"sub"` // Clerk user ID
	Exp    int64           `json:"exp"`
	Nbf    int64           `json:"nbf"` // not-before (RFC 7519 §4.1.5)
	Iss    string          `json:"iss"`
	RawAud json.RawMessage `json:"aud"` // can be string or []string per RFC 7519
}

// Audiences returns the aud claim as a string slice, handling both
// the string and array formats allowed by RFC 7519.
func (c *Claims) Audiences() []string {
	if len(c.RawAud) == 0 {
		return nil
	}
	// Try string first.
	var s string
	if err := json.Unmarshal(c.RawAud, &s); err == nil {
		return []string{s}
	}
	// Try array.
	var arr []string
	if err := json.Unmarshal(c.RawAud, &arr); err == nil {
		return arr
	}
	return nil
}

// Authenticate extracts and validates the JWT from the request.
// Token can be in query param "token" or Authorization header.
// Returns the user ID (sub claim) on success.
//
// SECURITY NOTE: The "token" query parameter is necessary because browsers
// cannot set custom headers during WebSocket upgrade. This means the JWT
// may appear in server access logs. Operators should:
// 1. Use short-lived tokens (Clerk defaults to 60s)
// 2. Ensure reverse proxy access logs are protected
// 3. Use wss:// (TLS) to prevent token interception in transit
func (a *Auth) Authenticate(r *http.Request) (string, error) {
	if a.jwksURL == "" {
		return "anonymous", nil // Auth disabled for dev.
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			token = strings.TrimPrefix(auth, "Bearer ")
		}
	}
	if token == "" {
		return "", errNoToken
	}

	claims, err := a.validateJWT(token)
	if err != nil {
		return "", err
	}

	return claims.Sub, nil
}

// validateJWT decodes and verifies a JWT token against cached JWKS keys.
func (a *Auth) validateJWT(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errInvalidToken
	}

	// Decode header to get kid.
	headerJSON, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("auth: decode header: %w", err)
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("auth: parse header: %w", err)
	}

	if header.Alg != "RS256" {
		return nil, fmt.Errorf("auth: unsupported algorithm %q", header.Alg)
	}

	// Get the public key for this kid.
	pubKey, err := a.getKey(header.Kid)
	if err != nil {
		return nil, err
	}

	// Verify signature.
	if err := verifyRS256(parts[0]+"."+parts[1], parts[2], pubKey); err != nil {
		return nil, fmt.Errorf("auth: signature verification failed: %w", err)
	}

	// Decode and validate claims.
	claimsJSON, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("auth: decode claims: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("auth: parse claims: %w", err)
	}

	now := time.Now().Unix()
	if now > claims.Exp {
		return nil, errTokenExpired
	}
	if claims.Nbf > 0 && now < claims.Nbf {
		return nil, fmt.Errorf("auth: token not yet valid (nbf=%d, now=%d)", claims.Nbf, now)
	}

	if a.issuer != "" && claims.Iss != a.issuer {
		return nil, fmt.Errorf("auth: invalid issuer %q, expected %q", claims.Iss, a.issuer)
	}
	if a.audience != "" {
		audiences := claims.Audiences()
		found := false
		for _, aud := range audiences {
			if aud == a.audience {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("auth: token audience %v does not contain %q", audiences, a.audience)
		}
	}

	return &claims, nil
}

// getKey retrieves the RSA public key for the given kid, refreshing the JWKS
// cache if needed.
func (a *Auth) getKey(kid string) (*rsa.PublicKey, error) {
	a.mu.RLock()
	key, ok := a.keys[kid]
	stale := time.Since(a.fetchedAt) > a.cacheTTL
	a.mu.RUnlock()

	if ok && !stale {
		return key, nil
	}

	// Refresh JWKS (deduped via singleflight to avoid thundering herd).
	_, sfErr, _ := a.sfGroup.Do("jwks", func() (any, error) {
		return nil, a.fetchJWKS()
	})
	if sfErr != nil {
		// If we have a cached key, use it even if stale.
		if ok {
			return key, nil
		}
		return nil, fmt.Errorf("auth: fetch JWKS: %w", sfErr)
	}

	a.mu.RLock()
	key, ok = a.keys[kid]
	a.mu.RUnlock()

	if !ok {
		return nil, errNoMatchingKey
	}
	return key, nil
}

// JWKS response types.
type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// fetchJWKS downloads and caches the JWKS keys from the Clerk endpoint.
func (a *Auth) fetchJWKS() error {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(a.jwksURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned %d", resp.StatusCode)
	}

	// Limit JWKS response to 1 MB to prevent OOM from malicious/misconfigured endpoints.
	var jwks jwksResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&jwks); err != nil {
		return err
	}

	newKeys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" || k.Use != "sig" {
			continue
		}
		pubKey, err := jwkToRSAPublicKey(k)
		if err != nil {
			continue
		}
		newKeys[k.Kid] = pubKey
	}

	a.mu.Lock()
	a.keys = newKeys
	a.fetchedAt = time.Now()
	a.mu.Unlock()

	return nil
}

// jwkToRSAPublicKey converts a JWK to an RSA public key.
func jwkToRSAPublicKey(k jwkKey) (*rsa.PublicKey, error) {
	nBytes, err := base64URLDecode(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64URLDecode(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

// verifyRS256 verifies an RS256 JWT signature.
func verifyRS256(signingInput, signatureB64 string, key *rsa.PublicKey) error {
	signature, err := base64URLDecode(signatureB64)
	if err != nil {
		return err
	}

	// Hash the signing input.
	hash := sha256.Sum256([]byte(signingInput))

	return rsa.VerifyPKCS1v15(key, cryptoSHA256, hash[:], signature)
}

// base64URLDecode decodes a base64url-encoded string (no padding).
func base64URLDecode(s string) ([]byte, error) {
	// Add padding if needed.
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}
