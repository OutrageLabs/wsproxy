# wsproxy

WebSocket↔TCP relay proxy for browser SSH. Zero-knowledge — the proxy only copies encrypted bytes, never sees plaintext.

Designed to work with [gossh-wasm](https://github.com/OutrageLabs/gossh-wasm) for browser-based SSH clients.

## Features

- **WebSocket↔TCP relay** — bidirectional byte copy, no inspection
- **Subdomain tunneling** — port forwarding via `abc123.tunnel.example.com`
- **Raw TCP ports** — allocate ports from a configurable pool for non-HTTP forwarding
- **JWT authentication** — Clerk JWKS validation with caching
- **Rate limiting** — per-IP and per-user connection limits
- **Target blacklist** — blocks connections to private IP ranges (RFC 1918)
- **CORS** — configurable allowed origins with wildcard support
- **Graceful shutdown** — clean connection draining on SIGINT/SIGTERM
- **Docker** — multi-stage build, `FROM scratch`, ~6 MB image

## Architecture

```
Browser (gossh-wasm)
    │
    │ wss://proxy.example.com/relay?host=X&port=22&token=JWT
    ▼
┌──────────────┐
│   wsproxy    │
│              │
│ /relay  ─────│──── TCP ──── SSH Server
│ /tunnel ─────│──── Subdomain + Raw Port routing
│ /health ─────│──── 200 OK
└──────────────┘
```

## Quick Start

### Run directly

```bash
go build -o wsproxy .
PORT=8080 ./wsproxy
```

### Docker

```bash
docker build -t wsproxy .
docker run -p 8080:8080 wsproxy
```

### Docker Compose

```bash
docker compose up
```

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check, returns `200 ok` |
| `/relay` | GET (WebSocket) | Bidirectional WS↔TCP relay |
| `/tunnel` | GET (WebSocket) | Register a port forwarding tunnel |

### `/relay` — SSH Relay

Upgrades to WebSocket, dials `host:port` via TCP, copies bytes bidirectionally.

```
wss://proxy.example.com/relay?host=192.168.1.100&port=22&token=eyJ...
```

| Param | Required | Description |
|-------|----------|-------------|
| `host` | Yes | Target SSH server hostname/IP |
| `port` | Yes | Target SSH server port |
| `token` | If auth enabled | JWT (Clerk-issued) |

### `/tunnel` — Port Forward Tunnel

Browser connects to register a tunnel. Proxy allocates a subdomain and optional raw TCP port.

```
wss://proxy.example.com/tunnel?token=eyJ...
```

**Control protocol (JSON over WebSocket):**

```jsonc
// Proxy → Browser (after registration):
{ "type": "tunnel_ready", "tunnelUrl": "https://abc123.tunnel.example.com", "rawPort": 10042 }

// Proxy → Browser (incoming HTTP request on subdomain):
{ "type": "http_request", "id": "req-1", "method": "GET", "path": "/api", "headers": {...}, "body": "..." }

// Browser → Proxy (HTTP response):
{ "type": "http_response", "id": "req-1", "status": 200, "headers": {...}, "body": "..." }

// Proxy → Browser (new raw TCP connection):
{ "type": "tcp_open", "connId": "conn-1" }

// Either direction (TCP connection closed):
{ "type": "tcp_close", "connId": "conn-1" }
```

## Configuration

All configuration via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP/WebSocket listen port |
| `CLERK_JWKS_URL` | _(empty = auth disabled)_ | Clerk JWKS endpoint for JWT validation |
| `JWT_ISSUER` | _(empty)_ | Expected JWT `iss` claim |
| `JWT_AUDIENCE` | _(empty)_ | Expected JWT `aud` claim |
| `ALLOWED_ORIGINS` | `*` | CORS allowed origins (comma-separated) |
| `TUNNEL_DOMAIN` | _(empty = tunneling disabled)_ | Base domain for tunnel subdomains |
| `TUNNEL_PORT_MIN` | `10000` | Start of raw TCP port range |
| `TUNNEL_PORT_MAX` | `10100` | End of raw TCP port range |
| `MAX_CONNS_PER_IP` | `10` | Max concurrent connections per IP |
| `MAX_CONNS_PER_USER` | `20` | Max concurrent connections per user |
| `MAX_TUNNEL_HTTP_PER_IP` | `50` | Max concurrent tunnel HTTP requests per source IP |
| `MAX_TUNNEL_TCP_CONNS_GLOBAL` | `1000` | Max concurrent raw TCP connections across all tunnels |
| `BLOCKED_TARGETS` | RFC 1918 + loopback | Blocked target IP ranges (CIDR) |
| `TRUSTED_PROXIES` | _(empty)_ | Comma-separated proxy CIDRs allowed to set `X-Forwarded-For` / `X-Real-IP` |

## Production Deployment

Example with Caddy for TLS termination and wildcard subdomain routing:

```
┌───────────────────────────────────────────┐
│  Server                                   │
│                                           │
│  Caddy (port 443, TLS)                    │
│  ├─ proxy.example.com → localhost:8080    │
│  └─ *.tunnel.example.com → localhost:8080 │
│                                           │
│  Docker: wsproxy (port 8080)              │
│  ├─ /relay → WebSocket↔TCP relay          │
│  ├─ /tunnel → subdomain registration      │
│  └─ /health → healthcheck                │
│                                           │
│  Raw TCP ports 10000-10100                │
└───────────────────────────────────────────┘
```

**Caddyfile example:**

```
proxy.example.com {
    reverse_proxy localhost:8080
}

*.tunnel.example.com {
    tls {
        dns cloudflare {env.CF_API_TOKEN}
    }
    reverse_proxy localhost:8080
}
```

## Security

- **Zero-knowledge**: proxy copies encrypted SSH bytes, never decrypts
- **JWT validation**: RS256 signature verification against Clerk JWKS
- **Target blacklist**: prevents connections to localhost, private networks, link-local
- **Rate limiting**: connection-based (not request-based) for WebSocket
- **CORS**: configurable origin restrictions
- **Proxy sees**: target IP:port, data volume, timing (metadata)
- **Proxy does NOT see**: SSH keys, passwords, terminal content, file transfers

## Dependencies

- `github.com/coder/websocket` — WebSocket library with `NetConn()` wrapper

Single dependency beyond Go stdlib.

## License

MIT
