# Disposable Email Domains Service Checker

A small, hardened baseline HTTP service (security & observability enhanced) using only Go's standard library plus Prometheus client for metrics to check disposable/temporary email domains and manage block/allow lists.

Features
- Lean codebase (std lib + Prometheus metrics only)
- Endpoints: Health (`/healthz`), Status (`/status`), Readiness (`/readyz`), Blocklist (GET/POST), Check, Validate, Report (HTML), Raw list & PSL downloads, Metrics (`/metrics`)
- Middleware: structured logging (JSON via slog), panic recovery, security headers, request ID, per-IP token bucket rate limiting (x/time/rate), service version + request duration headers
- JSON responses with proper Content-Type, nosniff, and no-store
- Strict JSON request handling (Content-Type, size limit, unknown fields)
- Atomic blocklist mutations with HTTPS-only remote list ingestion, entry count & line-length caps + SSRF IP range protections (private/link-local/ULA IP rejection)
- Immediate in-memory index patching (no stale window) + optional full reload; persisted to disk (`blocklist.conf`) so mutations survive restarts
- Background Public Suffix List (PSL) refresher (integrity checks, conditional GET, exponential backoff, safety belt metrics)
- Prometheus observability: request counters + latency histograms, rate-limit rejections, blocklist size, PSL refresh metrics & failure streak, last refresh timestamp
- Graceful shutdown on SIGINT/SIGTERM
 - Sensible server timeouts and MaxHeaderBytes (ReadTimeout 5s, ReadHeaderTimeout 5s, WriteTimeout 10s, IdleTimeout 60s, MaxHeaderBytes 1MB)
- Simple in-memory components plus on-disk list files

Project structure
- cmd/server/main.go — server bootstrap (logging, routing, timeouts, graceful shutdown)
- internal/router/router.go — routes and middleware chain
- internal/middleware/middleware.go — logging, recovery, security headers
- internal/handlers/handlers.go — health, blocklist, check, validate, report, file download handlers
- internal/storage/memory.go — simple example store (NOT used for block/allow lists persistence; block/allow lists persist via on-disk `*.conf` files)

API endpoints
- GET  /            — HTML index
- GET  /healthz     — health check
- GET  /livez       — liveness (always OK while process running)
- GET  /status      — lightweight JSON status (counts & last update)
- GET  /readyz      — readiness (lists & PSL presence)
- GET  /blocklist   — JSON { entries: [...], count: N }
- POST /blocklist   — extend list via { "entries": ["foo.com"...] }, { "url": "https://..." }, or { "urls": [..] } (admin token)
- GET  /check       — query via /check?q=<email-or-domain>
- GET  /check/emails/{email}
- GET  /check/domains/{domain}
- POST /check/emails  — batch check emails (JSON array/object or text/plain newline list)
- POST /check/domains — batch check domains (JSON array/object or text/plain newline list)
  - Add `?format=ndjson` to stream results as NDJSON for very large batches
- GET  /validate    — validation summary of list consistency
- POST /reload      — reload lists from disk (admin token; rarely needed now)
- GET  /report      — HTML validation report
- GET  /report/emails/{email} — HTML single email check
- GET  /report/domains/{domain} — HTML single domain check
- GET  /allowlist.conf            — raw allowlist file (text/plain)
- GET  /blocklist.conf            — raw blocklist file (text/plain)
- GET  /public_suffix_list.dat    — raw PSL snapshot (text/plain)
- GET  /metrics                   — Prometheus exposition
 - POST /admin/psl/refresh        — force an immediate PSL refresh attempt (admin token)

Additional semantics
- `POST /blocklist` supports optional `?reload=true` to force a full parse + validation after applying a patch (normally unnecessary because in-memory state is patched immediately).
- `POST /reload?strict=true` will fail (400) if validation finds issues (duplicates, public suffix only entries, etc.). Without `strict=true` it always reloads.

Run locally
Prerequisites: Go 1.21+

- Build: go build ./...
- Run:   go run ./cmd/server
- Port:  set PORT environment variable to override (default :8080)
  - PowerShell: $env:PORT = "3333"; go run ./cmd/server
  - Bash:       PORT=3333 go run ./cmd/server
- Stop:  Ctrl+C (graceful shutdown)

Authentication
Mutating endpoints (POST) require an admin token via `X-Admin-Token`.

Options:
- `ADMIN_TOKENS` (comma separated) — supports multiple active tokens for rotation.
- Fallback: single `ADMIN_TOKEN` (still supported). Tokens <16 chars are rejected (ignored) for safety.

If no valid token is configured the server operates in read-only mode (mutations return 403).

`.env` support: If a `.env` file exists in the working directory it is loaded at startup (first) and any variables already present in the real environment are NOT overridden. This is a convenience for local development only.

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

Batch examples (Windows cmd):
```bat
REM Emails JSON array
curl -s -H "Content-Type: application/json" -d "[\"test@example.com\",\"foo@bar.com\"]" http://localhost:8080/check/emails

REM Domains newline file
> domains.txt (echo example.com& echo sub.mail.xyz)
curl -s -H "Content-Type: text/plain" --data-binary @domains.txt http://localhost:8080/check/domains
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
  - Batch (emails) JSON array:
    - curl -s -H 'Content-Type: application/json' -d '["test@example.com","foo@bar.com"]' http://localhost:8080/check/emails | jq
  - Batch (emails) text/plain:
    - printf "a@b.com\nc@d.net\n" | curl -s -H 'Content-Type: text/plain' --data-binary @- http://localhost:8080/check/emails | jq
  - Batch (domains) JSON array:
    - curl -s -H 'Content-Type: application/json' -d '["example.com","sub.mail.xyz"]' http://localhost:8080/check/domains | jq
  - Batch (domains) text/plain:
    - printf "example.com\nsub.mail.xyz\n" | curl -s -H 'Content-Type: text/plain' --data-binary @- http://localhost:8080/check/domains | jq
  - NDJSON streaming (emails):
    - printf "a@b.com\nc@d.net\n" | curl -s -H 'Content-Type: text/plain' --data-binary @- "http://localhost:8080/check/emails?format=ndjson" | head
- Validate + Report:
  - curl -s http://localhost:8080/validate | jq
  - curl -s http://localhost:8080/report

What's included
- Proper error handling and JSON problem responses
- Security headers (Referrer-Policy, X-Frame-Options, X-Content-Type-Options, COOP, CORP, Permissions-Policy, CSP)
- Performance-minded defaults (timeouts, small allocs, no external deps)
- Maintainable layout and clear interfaces between layers

Recent hardening & observability
- `/readyz` readiness endpoint (lists loaded + PSL present)
- `/status` lightweight status (blocklist/allowlist counts, last update, readiness)
- Structured JSON logging (UTC, slog) + request metadata
  *Note*: startup/config and refresher messages are JSON via slog; per-request access logs are plain text lines (`METHOD PATH STATUS BYTES DURATION ip=... rid=... ua=...`).
- Request ID header `X-Request-ID` per request
- Service version header `X-Service-Version` (build with: go build -ldflags "-X main.version=v1.2.3" ./cmd/server)
- Request duration header `X-Request-Duration-ms` (integer milliseconds per request)
- Per-IP token bucket rate limiting (configurable via env)
- HTTPS-only remote list ingestion with SSRF safeguards (DNS resolve + private/IP range denial)
- Immediate in-memory blocklist patching (no stale window after POST)
- Background PSL refresher with integrity & size bounds + failure streak + size delta warnings
  *Validation details*: startup performs an initial fetch; refresher then runs periodically. Accepted PSL fetch size range 200,000-2,000,000 bytes (inclusive), must include `===BEGIN ICANN DOMAINS===` and `===END ICANN DOMAINS===`, contain ≥5,000 lines, and not be HTML. >20% size delta vs previous successful size increments `psl_size_delta_warnings_total`.
- Prometheus metrics: HTTP totals/latency (status code label), rate-limit rejections, blocklist & allowlist sizes, blocklist appends & duplicate skips, PSL success/fail, last refresh unixtime, consecutive failures, PSL size delta warnings, admin auth successes/failures
- Optional background sample warming job
- Trust proxy toggle for `X-Forwarded-For` / `X-Real-IP` honoring

What's still missing for production (beyond current hardening)
- Persistent storage / replication / HA
- Distributed rate limiting & coordination
- Additional observability: tracing, pprof (guarded), log sampling
- Advanced auth: audit log, per-action scopes, automated rotation hook
- Extensive fuzzing + property tests
- CI pipeline (lint, vet, vuln scan, tests, container build)
- Threat model & documented deployment topology (reverse proxy / TLS)

Notes
- Enforces `application/json` for mutating verbs; rejects unknown JSON fields.
- For production add: persistence, structured JSON logs, metrics, tracing, multi-token auth, secret management, improved rate limiting, DoS protections, and TLS at the edge.
 - Allowlist is currently static (loaded at startup / reload); only blocklist supports runtime append operations.
 - Readiness (`/readyz`) only asserts that lists have been loaded and the PSL snapshot file exists; it does not guarantee list validation cleanliness or PSL freshness (see metrics for health).
 - Rate limit bypass applies by exact match on the HTTP `Host` header (sans port), not on client IP or the queried domain/email.
 - Remote list ingestion: each HTTPS URL must resolve to public IP addresses (private / loopback / link-local / unique-local ranges are rejected after DNS resolution) to reduce SSRF risk.

Ingestion limits (blocklist POST)
- Max JSON request body size: 5MB
- Per remote URL body size: 12MB (hard cap)
- Cumulative fetched remote data per request: 32MB
- Max candidate domains collected across all sources: 200,000
- Max individual line length: 256 characters
- Remote sources may be plaintext (one domain per non-empty non-comment line) or a JSON array of strings. Comment lines (prefix `#`) and empties skipped.
- Duplicate and already-present domains are skipped; metrics reflect appended vs duplicate counts.

Batch check limits (/check/emails and /check/domains)
- Max JSON/text request body size: 16MB
- Max items per request (non-streaming): default 200,000 (override via `BATCH_MAX_ITEMS`)
- Max items per request (streaming NDJSON): default 1,000,000 (override via `BATCH_STREAM_MAX_ITEMS`)
- Accepted JSON formats: array of strings, or an object with one of keys `items`, `values`, `emails`, `domains` mapping to an array of strings
- For text/plain: one value per line; blank lines ignored

Response Headers
- X-Service-Version: service build version (defaults to dev if not set) — inject via: go build -ldflags "-X main.version=v1.2.3" ./cmd/server
- X-Request-Duration-ms: total handler execution time in whole milliseconds
- X-Request-ID: unique per request ID (also logged)

Future auth enhancements
- Fine-grained scopes (append vs reload, ingestion vs manual)
- Audit logging (structured) for every mutation
- Passive anomaly detection (sudden spike in mutations)
- External secret manager integration (Vault/Azure Key Vault/etc.)

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

## Configuration
Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 8080 | Listen port (prefixed with colon automatically) |
| `ADMIN_TOKEN` | (empty) | Single admin token fallback (>=16 chars) |
| `ADMIN_TOKENS` | (empty) | Comma-separated list of tokens (>=16 chars each) for rotation |
| `RATE_LIMIT_RPS` | 5.0 | Steady-state requests per second per IP |
| `RATE_LIMIT_BURST` | 20 | Burst size per IP bucket |
| `RATE_LIMIT_BUCKET_TTL` | 10m | Idle bucket eviction horizon |
| `PSL_REFRESH_INTERVAL` | 24h | Background PSL refresh cadence |
| `ENABLE_SAMPLE_WARMING` | false | Enable background sample /check warming job |
| `SAMPLE_CHECK_INTERVAL` | 10m | Interval for sample warming requests |
| `TRUST_PROXY_HEADERS` | false | Honor X-Forwarded-For / X-Real-IP for client IP extraction |
| `RATE_LIMIT_BYPASS_DOMAINS` | (empty) | Comma/space separated hostnames that completely bypass rate limiting (e.g. `42websites.com`) |
| `ENABLE_SAMPLE_WARMING` + `SAMPLE_CHECK_INTERVAL` | (see above) | Periodic POST /check warming job (JSON payload) when enabled |

Access log vs metrics
- `http_requests_total` labels: `method`, `path`, `status` (status text string)
- `http_request_duration_seconds` labels: `method`, `path`, `status_code` (numeric code as string)

Example:
```bash
ADMIN_TOKENS="$(openssl rand -hex 24),$(openssl rand -hex 24)" \
RATE_LIMIT_RPS=10 RATE_LIMIT_BURST=40 RATE_LIMIT_BUCKET_TTL=30m \
PSL_REFRESH_INTERVAL=12h TRUST_PROXY_HEADERS=true RATE_LIMIT_BYPASS_DOMAINS="42websites.com" \
go run ./cmd/server
```

### Metrics Reference
| Metric | Description |
|--------|-------------|
| `http_requests_total{method,path,status}` | Request count |
| `http_request_duration_seconds{method,path,status_code}` | Histogram of latency (status code labeled) |
| `rate_limiter_rejected_total` | Count of rate limited requests |
| `blocklist_domains` | Current in-memory blocklist size |
| `allowlist_domains` | Current in-memory allowlist size |
| `blocklist_appends_total` | Number of new blocklist domains appended |
| `blocklist_duplicates_skipped_total` | Duplicates skipped during mutations |
| `psl_refresh_success_total` / `psl_refresh_failure_total` | PSL refresh attempts |
| `psl_last_refresh_unixtime` | Unix time of last successful (or 304) refresh |
| `psl_consecutive_failures` | Current failure streak for PSL refresh |
| `psl_size_delta_warnings_total` | Count of PSL refreshes with >20% size delta |
| `admin_auth_failures_total` / `admin_auth_success_total` | Admin authentication outcomes |

Operational notes
- Allowlist / blocklist gauge values update on load/patch; allowlist will not change unless file modified + reload.
- `psl_consecutive_failures` resets to 0 on any success (including 304 Not Modified) and increments on failed attempts.
- `psl_last_refresh_unixtime` updates on successful (200) or not-modified (304) fetch.

## Benchmark / Load Testing
An included lightweight load generator lives at `cmd/bench` for exercising the `/check` endpoint (or any GET endpoint) and measuring basic latency percentiles.

Build/Run (from repo root):

```
go run ./cmd/bench -h
```

Key flags:
- `-url` Target URL. If it contains `{q}` that placeholder is replaced by rotating generated / file-provided values. If it does not contain `{q}` a `?q=` (or `&q=`) param is appended automatically.
- `-duration` Total wall time test length (default 10s).
- `-c` Concurrency (number of worker goroutines). Default = CPU cores.
- `-qps` Approximate global QPS cap. `0` (default) means unrestricted (go as fast as possible).
- `-queries` Optional file of newline-separated values for `{q}` substitution (comments starting with `#` & blank lines ignored). Falls back to a synthetic set if omitted.
- `-warmup` Optional warmup duration; requests during this period are executed but excluded from recorded latency samples.
- `-allow-http` By default true (allow plain HTTP). Set `-allow-http=false` to require an https URL.

Unlimited throughput example (attempt to push as hard as possible):
```
go run ./cmd/bench -url http://127.0.0.1:8080/check -duration=30s -c=200
```

Cap QPS (e.g. 3000 req/s) with fewer workers (workers should still be enough to hit your cap):
```
go run ./cmd/bench -url http://127.0.0.1:8080/check -duration=45s -c=150 -qps=3000
```

Use explicit placeholder and a custom queries file:
```
printf "foo@example.com\nbar@example.net\n" > queries.txt
go run ./cmd/bench -url "http://127.0.0.1:8080/check?q={q}" -queries=queries.txt -duration=20s -c=64
```

Add a warmup period (excluded from stats) then 60s measurement:
```
go run ./cmd/bench -url http://127.0.0.1:8080/check -warmup=10s -duration=70s -c=128
```

Windows (cmd.exe) example (unlimited mode; qps=0 is implicit):
```
go run .\cmd\bench -url http://127.0.0.1:8080/check -duration=20s -c=100
```

Sample output:
```
=== Benchmark Summary ===
Target:      http://127.0.0.1:8080/check
Duration:    30s (warmup 0s)
Workers:     200
Requests:    5,432,100 (success 5,432,100, error 0)
Throughput:  181070.0 req/s
Latency p50: 1.4ms  p95: 3.2ms  p99: 5.8ms
Status codes:
  200: 5432100
```

Interpretation:
- Throughput is total successful + error responses divided by wall time (including warmup if any – warmup samples are excluded from percentile stats only).
- Latency percentiles are computed from per-request durations recorded after the warmup window.
- If you see non-2xx codes, they will be listed with counts (e.g. 429 for rate limiting, 500 for server errors) – correlate with server logs/metrics (`http_requests_total{status}`) for deeper analysis.
- For more stable numbers run longer (e.g. 2–5 minutes) and pin CPU frequency / avoid other system load.

Tips:
- Increase `-c` until additional concurrency no longer meaningfully increases throughput (you have saturated CPU, memory bandwidth, or hitting rate limits).
- Use `-qps` to study latency under controlled steady load vs. maximum burst capacity.
- Provide a diverse `-queries` file if cache effects could skew results.
- Run the server with Prometheus metrics scraped to correlate latency histogram (`http_request_duration_seconds`) with benchmark results.

NOTE: This tool is intentionally simple (no coordinated omission correction, no open/closed model switching). For more rigorous benchmarking consider vegeta, hey, oha, wrk2, or k6; retain this internal tool for quick local smoke tests.
