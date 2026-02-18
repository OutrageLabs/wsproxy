# wsproxy Security Audit Report

## Scope and Method

- Scope: repository-only audit for `wsproxy`.
- In-scope components: `main.go`, `auth.go`, `config.go`, `relay.go`, `tunnel.go`, `ratelimit.go`, tests, and deployment configs in this repository.
- Method: threat modeling, static/dynamic analysis, targeted adversarial tests, and code hardening with regression coverage.

## Threat Model

### Security Objectives

1. Prevent unauthorized relay/tunnel access.
2. Prevent SSRF/private-network pivoting through relay and tunnel paths.
3. Preserve availability under malformed traffic and connection churn.
4. Prevent trust-boundary confusion at proxy, origin, and subdomain boundaries.
5. Avoid leakage of sensitive authentication material.

### Assets

- JWT tokens and claim integrity.
- Tunnel ownership mapping (`subdomain -> tunnel`).
- Relay target routing (`host:port`) and network egress controls.
- Availability of websocket relay/tunnel control planes.
- Proxy logs and operational metadata.

### Trust Boundaries

- Internet client to HTTP/WebSocket server boundary (`/relay`, `/tunnel`, tunnel subdomain HTTP).
- Proxy to target TCP host boundary (`SafeDial` and DNS resolution path).
- Proxy to JWKS endpoint boundary (`auth.fetchJWKS`).
- Trusted reverse proxy boundary (`TRUSTED_PROXIES`, `X-Forwarded-For`, `X-Real-IP`).
- Tunnel-browser control channel boundary (JSON and binary frame protocol).

### High-Risk Data Flows

1. `GET /relay?host=X&port=Y&token=JWT` -> auth -> target selection -> websocket<->tcp relay.
2. `GET /tunnel?token=JWT` -> tunnel registration -> control channel for `http_response` / `tcp_close` / binary payloads.
3. HTTP requests to `*.TUNNEL_DOMAIN` -> forwarded to browser over tunnel control protocol.
4. JWT validation path -> JWKS fetch/caching -> signature verification.

### Threat Actors

- Unauthenticated internet attacker probing HTTP and websocket endpoints.
- Authenticated but malicious tunnel/relay client abusing protocol edges.
- External attacker flooding tunnel HTTP traffic to exhaust resources.
- Misconfigured or compromised deployment operator (unsafe defaults).
- Malicious intermediary if TLS/proxy constraints are weak.

### Abuse Cases to Validate

- JWT bypass via malformed headers/claims or weak JWKS handling.
- SSRF bypass by host parsing quirks or DNS-rebinding edge behavior.
- Host/subdomain confusion using crafted `Host` values.
- Header injection or response-splitting via tunnel `http_response` headers.
- Parser abuse via malformed binary frames and oversized control messages.
- Resource exhaustion via unbounded unique IP/user keys and connection churn.
- Token leakage through URL query logging and unredacted log lines.

### Security Test Matrix (Initial)

- AuthN/AuthZ: JWT algorithm, issuer/audience/nbf/exp, key lookup/fetch failure behavior.
- Input validation: header names/values, host/subdomain parsing, frame parsing, JSON decoding.
- Availability: per-IP/per-user limiter behavior, map growth, concurrent websocket/tcp pressure.
- Boundary controls: trusted proxy header handling, blocked target enforcement, CORS/origin semantics.

## Baseline Tooling Results

### Commands Executed

- `go test ./...` -> pass.
- `go test -race ./...` -> pass.
- `go vet ./...` -> pass.
- `govulncheck ./...` -> no known vulnerabilities.
- `gosec ./...` -> 27 findings (4 high, 23 low).

### Triage Summary

- **High (needs hardening):**
  - `G115` integer conversion/overflow warnings in `tunnel.go` (`buildBinaryFrame` int->byte shifts).
- **Low (mostly hygiene/defense-in-depth):**
  - `G706` log injection taint warnings where untrusted fields can be logged (`relay.go`, `tunnel.go`).
  - `G104` unhandled-return warnings (close/write/deadline/shutdown call sites).

### Baseline Risk Readout

- No dependency CVEs were flagged by `govulncheck`.
- Existing tests do not cover parser fuzzing, hostile header values, subdomain edge cases, or rate-limiter map growth under high key churn.
- Highest technical risk remains in protocol/input hardening and resource-exhaustion defenses rather than third-party dependency exposure.

## Manual Review: Auth and JWKS (`auth.go`)

### Confirmed Findings

1. **Token transport exposure (medium):** JWT in `?token=` is required for browser WS upgrades but remains log/referrer-sensitive.
2. **JWKS endpoint trust policy is weak (medium):** no explicit scheme/host policy validation for `CLERK_JWKS_URL`.
3. **Stale key acceptance is unbounded (medium):** on JWKS fetch failure, stale keys may be used indefinitely.
4. **Claim strictness gap (low-medium):** `sub` is not required to be non-empty before successful authentication.
5. **JWK key-shape validation gaps (low):** missing stricter checks for exponent validity and optional `alg` consistency.

### Existing Strengths

- Signature algorithm constrained to `RS256`.
- Signature verified against fetched RSA key by `kid`.
- `exp` and `nbf` checked; optional issuer/audience checks supported.
- Singleflight deduplicates concurrent JWKS refreshes.
- JWKS response body size capped to 1 MiB.

### Implemented Hardening

- Add JWKS URL validation (scheme and host safety rules).
- Bound stale-key fallback duration.
- Require non-empty `sub` claim.
- Harden JWK parsing (algorithm consistency and exponent sanity checks).

## Manual Review: Network Boundary and SSRF Controls (`config.go`, `relay.go`, `main.go`, `tunnel.go`)

### Confirmed Findings

1. **Hostname parsing trust gap (medium):** target host validation was permissive and did not reject malformed host tokens before DNS resolution.
2. **Proxy header parsing trust gap (medium):** `X-Forwarded-For` / `X-Real-IP` values were not IP-validated after proxy trust decision.
3. **Host canonicalization inconsistency (medium):** host parsing used mixed logic across handlers, increasing edge-case risk with port, case, and trailing dot forms.
4. **Subdomain format validation gap (medium):** tunnel HTTP routing accepted any single-label subdomain, not the expected generated hex format.

### Implemented Hardening

- Added explicit hostname validation for relay targets prior to DNS resolution.
- Added centralized IP normalization and blocking helper (`normalizeIP`, `isBlockedIP`).
- Validated forwarded IP headers and fallback to direct peer IP on invalid values.
- Added canonical host normalization helper and reused it for subdomain checks.
- Enforced hex/length validation for tunnel subdomains in extraction path.

## Manual Review: Tunnel Protocol and Response Handling (`tunnel.go`)

### Confirmed Findings

1. **Binary frame parsing/encoding robustness gap (high):** int/byte conversion patterns and parser arithmetic were fragile and scanner-flagged for overflow risk.
2. **Header sanitization incompleteness (high):** only CR/LF filtering existed; no strict header-name token validation or value length/control-character policy.
3. **Correlation replay window (medium):** pending `http_response` IDs were not removed at first match, allowing repeated deliveries until request scope exited.
4. **Body decoding ambiguity (medium):** invalid base64 responses silently downgraded to raw text.

### Implemented Hardening

- Switched binary frame length handling to `binary.BigEndian` and bounded conn-ID length.
- Added strict response-header validators (`isValidHTTPHeaderName`, `isSafeHTTPHeaderValue`) and expanded blocked header list.
- Enforced one-shot response correlation by deleting pending IDs on first accepted match.
- Removed silent base64 fallback; invalid encoding now fails with `502`.
- Added response body size guardrail before writeback.

## Resource-Exhaustion Testing and Hardening

### Focus Areas

- Rate-limiter behavior under high unique IP/user churn.
- Global and per-tunnel TCP connection cap behavior.
- Timeout/cancellation behavior on connection paths.

### Implemented Hardening

- Added tracked-key caps to `RateLimiter` maps to limit memory growth (`maxTrackedIPs`, `maxTrackedUsers`).
- Added global TCP slot semaphore in `TunnelManager` (`MAX_TUNNEL_TCP_CONNS_GLOBAL`, default `1000`).
- Kept per-tunnel cap and enforced global+per-tunnel admission in accept path.

### Added/Updated Tests

- `TestRateLimiter_TrackedKeyCaps` verifies rejection under key-churn exhaustion and recovery after cleanup.
- `TestTunnelManager_GlobalTCPSlotCap` verifies global TCP slot cap enforcement.
- `TestSafeDial_ContextCanceled` verifies dial cancellation/timeout behavior is respected.

### Test Outcome

- Exhaustion-oriented tests pass and demonstrate bounded behavior under simulated pressure.

## Security Regression and Fuzzing Coverage

### Added Security Regression Tests

- `TestAuth_InvalidJWKSURLFailsClosed`
- `TestValidateJWKSURL`
- `TestBuildAndParseBinaryFrame_RoundTrip`
- `TestParseBinaryFrame_RejectsOversizedConnID`
- `TestHeaderValidators`
- `TestExtractSubdomain_RequiresHexID`

### Added Fuzz Harnesses

- `FuzzParseBinaryFrame`: stresses parser length/shape handling for arbitrary byte streams.
- `FuzzHeaderValidators`: stresses header-name/value validation logic with random unicode/control data.

### Fuzz Smoke Execution

- `go test -run=^$ -fuzz=FuzzParseBinaryFrame -fuzztime=3s ./...` -> pass.
- `go test -run=^$ -fuzz=FuzzHeaderValidators -fuzztime=3s ./...` -> pass.

## Post-Remediation Verification

### Full Verification Commands

- `go test ./...` -> pass
- `go test -race ./...` -> pass
- `go vet ./...` -> pass
- `govulncheck ./...` -> no known vulnerabilities
- `gosec ./...` -> **0 issues**

### Security Scan Delta

- Baseline `gosec`: 27 findings (4 high, 23 low).
- Final `gosec`: 0 findings.
- High-risk parser and header validation issues were eliminated with regression and fuzz coverage added.

## Final Findings Register (Prioritized)

### Resolved During Audit

1. **High:** tunnel binary frame parser hardening and overflow-safe encoding/decoding.
2. **High:** strict tunnel response header validation and response body decoding hardening.
3. **Medium:** JWKS URL trust policy and stale-key fallback bounded behavior.
4. **Medium:** host/subdomain canonicalization and stricter relay target/proxy IP validation.
5. **Medium:** resource exhaustion controls improved with rate-limiter key caps and global TCP conn caps.

### Residual Risks / Operational Requirements

1. **Medium (operational):** JWT in query params remains necessary for browser websocket flows; access log hygiene is still required.
2. **Medium (configuration):** auth can be disabled if `CLERK_JWKS_URL` is unset; production deployments must enforce non-empty auth settings.
3. **Medium (configuration):** default `ALLOWED_ORIGINS=*` is permissive; production should set explicit trusted origins.
4. **Low:** `/health` remains unauthenticated by design and should be protected at network/proxy layer if internet-exposed.

## Release Readiness

- **Code security readiness:** pass.
- **Blocking technical findings:** none in current repository scope.
- **Release recommendation:** **Go**, conditional on production config hardening:
  - Set `CLERK_JWKS_URL`, `JWT_ISSUER`, and `JWT_AUDIENCE`.
  - Replace `ALLOWED_ORIGINS=*` with an explicit allow-list.
  - Configure `TRUSTED_PROXIES` accurately when behind reverse proxies.
  - Ensure TLS termination and sensitive access-log controls are enforced.
