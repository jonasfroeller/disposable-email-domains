# Disposable Email Domains Service Checker

A small, production-ready HTTP service using only Go's standard library to check disposable/temporary email domains and manage block/allow lists.

Features
- Routing with http.ServeMux
- Endpoints: Health, Blocklist (GET/POST), Check (GET/POST), Validate (GET), Report (HTML), Raw list downloads
- Middleware: logging, panic recovery, security headers
- JSON responses with proper Content-Type, nosniff, and no-store
- Strict JSON request handling (Content-Type, size limit, unknown fields)
- Graceful shutdown on SIGINT/SIGTERM
- Sensible server timeouts and MaxHeaderBytes
- Simple in-memory components plus on-disk list files

Project structure
- cmd/server/main.go — server bootstrap (logging, routing, timeouts, graceful shutdown)
- internal/router/router.go — routes and middleware chain
- internal/middleware/middleware.go — logging, recovery, security headers
- internal/handlers/handlers.go — health, blocklist, check, validate, report, file download handlers
- internal/storage/memory.go — thread-safe in-memory store (used by checker and examples)

API endpoints
- GET  /            — HTML index
- GET  /healthz     — health check
- GET  /blocklist   — returns JSON { entries: [...], count: N }
- POST /blocklist   — extend list via { "entries": ["foo.com", ...] } or { "url": "https://.../list.txt" } (admin token required)
- GET  /check       — query via /check?q=<email-or-domain>
- GET  /check/emails/{email}
- GET  /check/domains/{domain}
- GET  /validate    — returns validation summary of list consistency
- POST /reload      — reload lists from disk (admin token required)
- GET  /report      — HTML report page
- GET  /report/emails/{email}
- GET  /report/domains/{domain}
- GET  /allowlist.conf            — raw allowlist file (text/plain)
- GET  /blocklist.conf            — raw blocklist file (text/plain)
- GET  /public_suffix_list.dat    — raw PSL file (text/plain)

Run locally
Prerequisites: Go 1.21+

- Build: go build ./...
- Run:   go run ./cmd/server
- Port:  set PORT environment variable to override (default :8080)
  - PowerShell: $env:PORT = "3333"; go run ./cmd/server
  - Bash:       PORT=3333 go run ./cmd/server
- Stop:  Ctrl+C (graceful shutdown)

Authentication
All non-GET endpoints are protected by an admin token. Supply it via the `X-Admin-Token` header. Set an environment variable `ADMIN_TOKEN` (or place it in a local `.env` file as `ADMIN_TOKEN=...`) before starting the server. The process environment always wins over `.env` (variables already set are not overwritten). If `ADMIN_TOKEN` is absent the server runs in read-only mode and will return 403 to any mutating request.

Examples (Unix shell):
```bash
export ADMIN_TOKEN=$(openssl rand -hex 32)
go run ./cmd/server

curl -sS -H "X-Admin-Token: $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"entries":["example.com"]}' http://localhost:8080/blocklist | jq
```

Windows (cmd):
```bat
set ADMIN_TOKEN=replace_with_random_value
go run ./cmd\server
curl -sS -H "X-Admin-Token: %ADMIN_TOKEN%" -H "Content-Type: application/json" -d "{\"entries\":[\"example.com\"]}" http://localhost:8080/blocklist
```

Quick checks
- Health:
  - curl -i http://localhost:8080/healthz
  - PowerShell: Invoke-RestMethod http://localhost:8080/healthz | ConvertTo-Json -Depth 5
- Blocklist (JSON):
  - curl -s http://localhost:8080/blocklist | jq
  - curl -s -H "X-Admin-Token: $ADMIN_TOKEN" -H "Content-Type: application/json" -d '{"entries":["foo.com","bar.io"]}' http://localhost:8080/blocklist | jq
  - curl -s -H "X-Admin-Token: $ADMIN_TOKEN" -H "Content-Type: application/json" -d '{"url":"https://example.com/list.txt"}' http://localhost:8080/blocklist | jq
- Check:
  - curl -s 'http://localhost:8080/check?q=test@example.com' | jq
  - curl -s http://localhost:8080/check/emails/test@example.com | jq
  - curl -s http://localhost:8080/check/domains/example.com | jq
- Validate + Report:
  - curl -s http://localhost:8080/validate | jq
  - curl -s http://localhost:8080/report

What’s included
- Proper error handling and JSON problem responses
- Security headers (Referrer-Policy, X-Frame-Options, X-Content-Type-Options, COOP, CORP, Permissions-Policy, CSP)
- Performance-minded defaults (timeouts, small allocs, no external deps)
- Maintainable layout and clear interfaces between layers

What’s not included (yet)
- Persistent storage (uses in-memory + on-disk files)
- Advanced authorization / multi-user identity (single shared admin token only)
- TLS termination (intended to run behind a reverse proxy)
- CORS, rate limiting, request ID/trace propagation
- Structured logging (using standard log for simplicity)
- Unit/integration tests and benchmarks
- Separate readiness endpoint beyond /healthz

Notes
- The server enforces application/json for POST/PUT/PATCH and rejects oversized/invalid payloads.
- For production, consider adding persistence, structured logging, metrics, and TLS/identity at the edge.

Future auth enhancements
- Token rotation (support multiple active tokens e.g. ADMIN_TOKEN_PREVIOUS)
- Audit logging for each mutating request (IP, UA, path)
- Rate limiting / anomaly detection on mutating endpoints
- Per-action tokens / scoped capabilities (append-only vs reload)
- Secret storage in external vault provider

Similar
- https://github.com/disposable-email-domains/disposable-email-domains
- https://github.com/disposable/disposable-email-domains
- https://github.com/7c/fakefilter
- https://github.com/FGRibreau/mailchecker
- https://github.com/ivolo/disposable-email-domains (https://github.com/ivolo/disposable-email-domains/blob/master/wildcard.json)
- https://github.com/amieiro/disposable-email-domains
- https://gist.github.com/ammarshah/f5c2624d767f91a7cbdc4e54db8dd0bf
- https://github.com/gblmarquez/disposable-email-domains
- https://github.com/unkn0w/disposable-email-domain-list
- https://github.com/IntegerAlex/disposable-email-detector (https://github.com/IntegerAlex/disposable-email-detector/blob/main/index.json)

https://www.usercheck.com/guides/best-github-lists-for-disposable-email-domains
