package handlers

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"disposable-email-domains/internal/config"
	"disposable-email-domains/internal/domain"
	"disposable-email-domains/internal/metrics"
)

type Item struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// (currently not heavily exercised; kept for future extension/testing scaffolding).
type Store interface {
	List() []Item
	Get(id string) (Item, bool)
	Create(name string) (Item, error)
	Update(id, name string) (Item, error)
	Delete(id string) bool
}

type API struct {
	Store  Store
	Logger *log.Logger
	Check  *domain.Checker
	// mutex to serialize blocklist mutation operations
	blMu     sync.Mutex
	statusMu sync.RWMutex
	status   ServiceStatus
	// optional config for limits
	cfg *config.Config
}

// Attaches configuration for limits and options.
func (a *API) SetConfig(cfg *config.Config) {
	a.cfg = cfg
}

// Lightweight snapshot for diagnostics.
type ServiceStatus struct {
	BlocklistCount int       `json:"blocklist_count"`
	AllowlistCount int       `json:"allowlist_count"`
	LastListUpdate time.Time `json:"last_list_update"`
	Ready          bool      `json:"ready"`
}

func (a *API) InitStatus() {
	if a.Check == nil || !a.Check.IsReady() {
		return
	}
	a.statusMu.Lock()
	a.status.BlocklistCount = a.Check.BlockCount()
	// allow count (reflecting raw length minus comments)
	a.status.AllowlistCount = a.Check.AllowCount()
	// get updatedAt from a check of a dummy value to avoid new accessor; UpdatedAt already exposed via a check result.
	// Cheaper: access internal via Validate() which copies raw slices but also sets CheckedAt; instead perform a lightweight domain. Checker method by adding future accessor if needed.
	// For now rely on performing a no-op validation to approximate last update; or simply set to time.Now() since Load just occurred before calling.
	if a.status.LastListUpdate.IsZero() {
		a.status.LastListUpdate = time.Now().UTC()
	}
	a.statusMu.Unlock()
}

func (a *API) Health(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func (a *API) Live(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondMethodNotAllowed(w, http.MethodGet)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"alive": true})
}

// Returns quick diagnostic counts & last update timestamp.
func (a *API) Status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondMethodNotAllowed(w, http.MethodGet)
		return
	}
	// Refresh dynamic readiness cheaply
	ready := a.Check != nil && a.Check.IsReady()
	a.statusMu.RLock()
	st := a.status
	a.statusMu.RUnlock()
	st.Ready = ready
	respondJSON(w, http.StatusOK, st)
}

// Reports application readiness (lists loaded & checker initialized & PSL file exists).
func (a *API) Ready(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondMethodNotAllowed(w, http.MethodGet)
		return
	}
	if a.Check == nil || !a.Check.IsReady() {
		respondJSON(w, http.StatusServiceUnavailable, map[string]any{"ready": false})
		return
	}
	// Verify PSL snapshot exists
	if _, err := os.Stat("public_suffix_list.dat"); err != nil {
		respondJSON(w, http.StatusServiceUnavailable, map[string]any{"ready": false, "error": "psl missing"})
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"ready": true, "updated_at": a.Check.Validate().CheckedAt.Format(time.RFC3339)})
}

func (a *API) Index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	nonceBytes := make([]byte, 16)
	_, _ = rand.Read(nonceBytes)
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; script-src 'nonce-"+nonce+"'; frame-ancestors 'none'; base-uri 'none'")

	host := r.Host

	// Build endpoint metadata for the in-page API Explorer (used to render dynamic details)
	type ep struct {
		Method       string `json:"method"`
		Path         string `json:"path"`
		Desc         string `json:"desc"`
		SampleURL    string `json:"sample_url,omitempty"`
		RespType     string `json:"resp_type"`
		ContentType  string `json:"content_type"`
		BodyTemplate string `json:"body_template,omitempty"`
		NeedsToken   bool   `json:"needs_token,omitempty"`
	}
	// type strings derived dynamically where possible
	statusType := "" + (func() string { return (func(v any) string { return fmt.Sprintf("%T", v) })(ServiceStatus{}) })()
	resultType := "" + (func() string { return (func(v any) string { return fmt.Sprintf("%T", v) })(domain.Result{}) })()
	reportType := "" + (func() string { return (func(v any) string { return fmt.Sprintf("%T", v) })(domain.Report{}) })()

	// compose list
	eps := []ep{
		{Method: "GET", Path: "/healthz", Desc: "Health check", SampleURL: "/healthz", RespType: fmt.Sprintf("%T", map[string]any{}), ContentType: "application/json"},
		{Method: "GET", Path: "/livez", Desc: "Liveness (always OK)", SampleURL: "/livez", RespType: fmt.Sprintf("%T", map[string]any{}), ContentType: "application/json"},
		{Method: "GET", Path: "/status", Desc: "Status snapshot", SampleURL: "/status", RespType: statusType, ContentType: "application/json"},
		{Method: "GET", Path: "/readyz", Desc: "Readiness probe", SampleURL: "/readyz", RespType: fmt.Sprintf("%T", map[string]any{}), ContentType: "application/json"},
		{Method: "GET", Path: "/blocklist", Desc: "List blocklist (use ?summary=true or paginate ?offset=&limit=)", SampleURL: "/blocklist?summary=true", RespType: fmt.Sprintf("%T", map[string]any{}), ContentType: "application/json"},
		{Method: "POST", Path: "/blocklist", Desc: "Extend blocklist (entries/url(s))", SampleURL: "/blocklist", RespType: fmt.Sprintf("%T", map[string]any{}), ContentType: "application/json", BodyTemplate: `{"entries":["foo.com","bar.io"]}`, NeedsToken: true},
		{Method: "GET", Path: "/check", Desc: "Check via ?q=", SampleURL: "/check?q=test@example.com", RespType: resultType, ContentType: "application/json"},
		{Method: "GET", Path: "/check/emails/{email}", Desc: "Check email", SampleURL: "/check/emails/test@example.com", RespType: resultType, ContentType: "application/json"},
		{Method: "GET", Path: "/check/domains/{domain}", Desc: "Check domain", SampleURL: "/check/domains/example.com", RespType: resultType, ContentType: "application/json"},
		{Method: "POST", Path: "/check/emails", Desc: "Batch emails (JSON or text)", SampleURL: "/check/emails", RespType: "[]" + resultType, ContentType: "application/json", BodyTemplate: `{"items":["a@b.com","c@d.com"]}`},
		{Method: "POST", Path: "/check/domains", Desc: "Batch domains (JSON or text)", SampleURL: "/check/domains", RespType: "[]" + resultType, ContentType: "application/json", BodyTemplate: `{"items":["example.com","a.b.com"]}`},
		{Method: "GET", Path: "/validate", Desc: "Validate lists", SampleURL: "/validate", RespType: reportType, ContentType: "application/json"},
		{Method: "POST", Path: "/reload", Desc: "Full reload", SampleURL: "/reload", RespType: fmt.Sprintf("%T", map[string]any{}), ContentType: "application/json", NeedsToken: true},
		{Method: "GET", Path: "/report", Desc: "Validate report (HTML)", SampleURL: "/report", RespType: "text/html", ContentType: "text/html"},
		{Method: "GET", Path: "/report/emails/{email}", Desc: "Check report (HTML)", SampleURL: "/report/emails/test@example.com", RespType: "text/html", ContentType: "text/html"},
		{Method: "GET", Path: "/report/domains/{domain}", Desc: "Check report (HTML)", SampleURL: "/report/domains/example.com", RespType: "text/html", ContentType: "text/html"},
		{Method: "GET", Path: "/allowlist.conf", Desc: "Download allowlist", SampleURL: "/allowlist.conf", RespType: "text/plain", ContentType: "text/plain"},
		{Method: "GET", Path: "/blocklist.conf", Desc: "Download blocklist", SampleURL: "/blocklist.conf", RespType: "text/plain", ContentType: "text/plain"},
		{Method: "GET", Path: "/public_suffix_list.dat", Desc: "Download PSL snapshot", SampleURL: "/public_suffix_list.dat", RespType: "text/plain", ContentType: "text/plain"},
		{Method: "GET", Path: "/metrics", Desc: "Prometheus metrics", SampleURL: "/metrics", RespType: "text/plain; OpenMetrics", ContentType: "text/plain"},
		{Method: "POST", Path: "/admin/psl/refresh", Desc: "Force PSL refresh", SampleURL: "/admin/psl/refresh", RespType: fmt.Sprintf("%T", map[string]any{}), ContentType: "application/json", NeedsToken: true},
	}
	epJSON, _ := json.Marshal(eps)

	html := `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>API Index</title>
<style>
:root{--bg:#0b1020;--panel:#121a2e;--text:#e6eefc;--muted:#9fb3d9;--accent:#7cc4ff;--ok:#22c55e;--warn:#f59e0b;--err:#ef4444;--chip:#243250;--col-method:72px;--col-path-min:220px;--col-desc-min:260px;--col-type:220px}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:linear-gradient(180deg,#0b1020, #0d1730 50%, #0b1020);color:var(--text);font:16px/1.5 system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Arial, "Apple Color Emoji","Segoe UI Emoji"}
.container{max-width:920px;margin:0 auto;padding:32px 16px}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
.h1{font-size:22px;font-weight:700;letter-spacing:.3px}
.small{color:var(--muted);font-size:13px}
.panel{background:rgba(18,26,46,.8);backdrop-filter:blur(6px);border:1px solid #1d2947;border-radius:14px;overflow:hidden;box-shadow:0 10px 30px rgba(0,0,0,.4)}
.panel h2{margin:0;padding:14px 16px;border-bottom:1px solid #1d2947;font-size:16px;display:flex;align-items:center;gap:8px}
.panel h2 .select{margin-left:auto}
.list{padding:6px}
.list .row > .resp{display:none}
.row{display:grid;align-items:center;gap:10px;padding:10px 12px;border-radius:10px;transition:background .15s;grid-template-columns:var(--col-method) minmax(var(--col-path-min),1fr) minmax(var(--col-desc-min),auto);min-height:44px}
.row:hover{background:#0e162a}
a.row{text-decoration:none;color:inherit}
a.row:visited{color:inherit}
.method{font-weight:700;font-size:12px;padding:6px 10px;border-radius:999px;background:var(--chip);letter-spacing:.6px;min-width:var(--col-method);text-align:center}
.get{color:#7dd3fc}
.post{color:#a7f3d0}
.put{color:#fde68a}
.del{color:#fecaca}
.path{font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;color:#e2e8f0;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.desc{color:var(--muted);font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.code{background:#0b1326;border:1px solid #172243;border-radius:10px;padding:14px;margin:12px}
code{font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;color:#d1e9ff;font-size:13px}
.footer{color:var(--muted);font-size:12px;text-align:center;margin-top:22px}
.badge{display:inline-block;margin-left:8px;padding:2px 8px;border-radius:999px;background:#132042;color:#9cc2ff;font-size:12px;border:1px solid #1f2c4a}
/* API Explorer styles */
details.api{border-top:1px solid #1d2947}
details.api[open]{background:#0e162a}
summary.api-row{list-style:none;display:grid;align-items:center;gap:10px;padding:10px 12px;cursor:pointer;grid-template-columns:12px var(--col-method) minmax(var(--col-path-min),1fr) minmax(var(--col-desc-min),1fr) var(--col-type);min-height:44px}
summary.api-row::-webkit-details-marker{display:none}
.arrow{display:inline-block;width:8px;height:8px;border-right:2px solid #9fb3d9;border-bottom:2px solid #9fb3d9;transform:rotate(-45deg);transition:transform .2s ease;margin-right:4px}
details[open] .arrow{transform:rotate(45deg)}
.resp{margin-left:auto;color:#93c5fd;font-size:12px;background:#0c1733;border:1px solid #1f2c4a;border-radius:999px;padding:2px 8px;justify-self:end;white-space:nowrap}
.try{padding:12px;border-top:1px solid #1d2947}
.field{display:flex;gap:8px;align-items:center;margin:8px 0}
.field input,.field textarea,.field select{flex:1;min-width:120px;background:#0b1326;border:1px solid #172243;border-radius:8px;color:#d1e9ff;padding:8px}
.actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:8px}
.btn{background:#132042;border:1px solid #1f2c4a;color:#9cc2ff;border-radius:8px;cursor:pointer;display:inline-flex;align-items:center;justify-content:center;height:36px;padding:0 12px;line-height:1;text-decoration:none}
.btn:link,.btn:visited,.btn:hover,.btn:active{color:#9cc2ff;text-decoration:none}
.btn:focus{outline:2px solid #1f2c4a;outline-offset:2px}
.result{margin-top:10px;background:#0b1326;border:1px solid #172243;border-radius:10px;color:#d1e9ff;padding:10px;white-space:pre-wrap;max-height:320px;overflow:auto}
/* Responsive fallback: stack description below on small screens */
@media (max-width: 720px){
	.row{grid-template-columns:var(--col-method) 1fr}
	.row .desc{grid-column:1 / -1}
	summary.api-row{grid-template-columns:12px var(--col-method) 1fr}
	summary.api-row .desc{grid-column:1 / -1}
	summary.api-row .resp{grid-column:1 / -1;justify-self:start}
}
</style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="h1">Disposable Email Domains API</div>
      <div class="small">Host: ` + host + `</div>
    </div>

    <div class="panel">
      <h2>
        <span>View</span>
        <span class="badge">net/http</span>
        <select id="viewSelect" class="select" style="background:#0b1326;border:1px solid #172243;border-radius:8px;color:#d1e9ff;padding:6px 8px">
          <option value="endpoints" selected>Endpoints</option>
          <option value="explorer">API Explorer</option>
        </select>
      </h2>
      <div class="list" id="endpointsView">
		<a class="row" href="/" target="_blank" rel="noopener"><span class="method get">GET</span><span class="path">/</span><span class="desc">Index (this page)</span></a>
		<a class="row" href="/healthz" target="_blank" rel="noopener"><span class="method get">GET</span><span class="path">/healthz</span><span class="desc">Health check</span></a>
		<a class="row" href="/livez" target="_blank" rel="noopener"><span class="method get">GET</span><span class="path">/livez</span><span class="desc">Liveness (always OK)</span></a>
		<a class="row" href="/status" target="_blank" rel="noopener"><span class="method get">GET</span><span class="path">/status</span><span class="desc">Status snapshot (JSON)</span></a>
		<a class="row" href="/readyz" target="_blank" rel="noopener"><span class="method get">GET</span><span class="path">/readyz</span><span class="desc">Readiness probe</span></a>
		<a class="row" href="/blocklist" target="_blank" rel="noopener"><span class="method get">GET</span><span class="path">/blocklist</span><span class="desc">List blocklist (JSON)</span></a>
		<div class="row"><span class="method post">POST</span><span class="path">/blocklist</span><span class="desc">Extend blocklist (JSON)</span></div>
		<a class="row" href="/check?q=test@example.com" target="_blank" rel="noopener"><span class="method get">GET</span><span class="path">/check</span><span class="desc">JSON check via ?q=</span></a>
		<a class="row" href="/check/emails/test@example.com" target="_blank" rel="noopener"><span class="method get">GET</span><span class="path">/check/emails/{email}</span><span class="desc">Check email (JSON)</span></a>
		<a class="row" href="/check/domains/example.com" target="_blank" rel="noopener"><span class="method get">GET</span><span class="path">/check/domains/{domain}</span><span class="desc">Check domain (JSON)</span></a>
		<div class="row"><span class="method post">POST</span><span class="path">/check/emails</span><span class="desc">Batch check emails (JSON array or text/plain)</span></div>
		<div class="row"><span class="method post">POST</span><span class="path">/check/domains</span><span class="desc">Batch check domains (JSON array or text/plain)</span></div>
		<a class="row" href="/validate" target="_blank" rel="noopener"><span class="method get">GET</span><span class="path">/validate</span><span class="desc">Validate lists (JSON)</span></a>
		<div class="row"><span class="method post">POST</span><span class="path">/reload</span><span class="desc">Full reload (optional)</span></div>
		<a class="row" href="/report" target="_blank" rel="noopener"><span class="method get">GET</span><span class="path">/report</span><span class="desc">Validate report (HTML)</span></a>
		<a class="row" href="/report/emails/test@example.com" target="_blank" rel="noopener"><span class="method get">GET</span><span class="path">/report/emails/{email}</span><span class="desc">Check report for email (HTML)</span></a>
		<a class="row" href="/report/domains/example.com" target="_blank" rel="noopener"><span class="method get">GET</span><span class="path">/report/domains/{domain}</span><span class="desc">Check report for domain (HTML)</span></a>
		<a class="row" href="/allowlist.conf" target="_blank" rel="noopener"><span class="method get">GET</span><span class="path">/allowlist.conf</span><span class="desc">Download allowlist</span></a>
		<a class="row" href="/blocklist.conf" target="_blank" rel="noopener"><span class="method get">GET</span><span class="path">/blocklist.conf</span><span class="desc">Download blocklist</span></a>
		<a class="row" href="/public_suffix_list.dat" target="_blank" rel="noopener"><span class="method get">GET</span><span class="path">/public_suffix_list.dat</span><span class="desc">Download PSL snapshot</span></a>
		<a class="row" href="/metrics" target="_blank" rel="noopener"><span class="method get">GET</span><span class="path">/metrics</span><span class="desc">Prometheus metrics</span></a>
		<div class="row"><span class="method post">POST</span><span class="path">/admin/psl/refresh</span><span class="desc">Force PSL refresh</span></div>
	  </div>
      <div class="list" id="explorerView" style="display:none">
        <div id="apiExplorerList"></div>
      </div>
    </div>

    <div class="panel" style="margin-top:16px">
      <h2>Quick start</h2>
      <div class="code"><code>curl -sS http://` + host + `/healthz</code></div>
      <div class="code"><code>curl -sS http://` + host + `/blocklist</code></div>
	  <div class="code"><code>curl -sS -H "X-Admin-Token: &lt;token&gt;" -H "Content-Type: application/json" -d '{"entries":["foo.com","bar.io"]}' http://` + host + `/blocklist</code></div>
	  <div class="code"><code>curl -sS -H "X-Admin-Token: &lt;token&gt;" -H "Content-Type: application/json" -d '{"url":"https://example.com/list.txt"}' http://` + host + `/blocklist</code></div>
      <div class="code"><code>curl -sS 'http://` + host + `/check?q=test@example.com'</code></div>
      <div class="code"><code>curl -sS http://` + host + `/validate</code></div>
      <div class="code"><code>http://` + host + `/report</code></div>
      <div class="small" style="padding:0 14px 12px 14px;color:#9fb3d9">Tip: add “| jq” to pretty-print JSON if you have jq installed.</div>
    </div>

	<div class="panel" style="margin-top:16px">
      <h2>Bulk add from URLs</h2>
      <div class="list">
        <div class="row" style="display:block">
          <div class="small" style="margin-bottom:8px">Paste one or more URLs (one per line). Each URL should point to a plaintext list where non-empty, non-comment lines are domains.</div>
          <textarea id="urlsInput" rows="6" style="width:100%;background:#0b1326;border:1px solid #172243;border-radius:10px;color:#d1e9ff;padding:12px;line-height:1.6" placeholder="https://example.com/list1.txt&#10;https://example.com/list2.txt"></textarea>
		  <div style="margin-top:10px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">
            <button id="addUrlsBtn" style="background:#132042;border:1px solid #1f2c4a;color:#9cc2ff;border-radius:8px;padding:8px 12px;cursor:pointer">Add to blocklist</button>
            <label class="small" style="display:flex;align-items:center;gap:6px"><input id="reloadAfter" type="checkbox" checked /> <span>Reload lists after adding</span></label>
			<input id="adminTokenInput" type="password" placeholder="Admin token" autocomplete="off" style="flex:1;min-width:200px;background:#0b1326;border:1px solid #172243;border-radius:8px;color:#d1e9ff;padding:8px" />
          </div>
          <div id="urlsResult" style="display:none;margin-top:10px;width:100%;background:#0b1326;border:1px solid #172243;border-radius:10px;color:#d1e9ff;padding:10px;white-space:pre-wrap"></div>
        </div>
      </div>
    </div>

	<script nonce="` + nonce + `">
	// Endpoint metadata injected from server
	const __ENDPOINTS__ = ` + string(epJSON) + `;
	const __HOST__ = ` + strconv.Quote(host) + `;
			(function mountViewSelector(){
				const sel = document.getElementById('viewSelect');
				const endpoints = document.getElementById('endpointsView');
				const explorer = document.getElementById('explorerView');
				if (!sel || !endpoints || !explorer) return;
				sel.addEventListener('change', () => {
					const v = sel.value;
					endpoints.style.display = (v === 'endpoints') ? 'block' : 'none';
					explorer.style.display = (v === 'explorer') ? 'block' : 'none';
				});
			})();
	(function renderAPIExplorer(){
		const root = document.getElementById('apiExplorerList');
		if (!root) return;
		for (const e of __ENDPOINTS__) {
			const details = document.createElement('details');
			details.className = 'api';
			const summary = document.createElement('summary');
			summary.className = 'api-row';
		const arrow = document.createElement('span'); arrow.className='arrow'; arrow.setAttribute('aria-hidden','true');
			const m = document.createElement('span'); m.className = 'method ' + (e.method.toLowerCase()); m.textContent = e.method;
			const p = document.createElement('span'); p.className = 'path'; p.textContent = e.path;
			const d = document.createElement('span'); d.className = 'desc'; d.textContent = e.desc;
			const t = document.createElement('span'); t.className = 'resp'; t.textContent = 'type: ' + e.resp_type;
			summary.append(arrow, m, p, d, t);
			details.append(summary);
			const tryDiv = document.createElement('div'); tryDiv.className = 'try';
			// URL field
			const urlField = document.createElement('div'); urlField.className='field';
			const urlLabel = document.createElement('label'); urlLabel.className='small'; urlLabel.textContent='URL';
			const urlInput = document.createElement('input'); urlInput.value = (e.sample_url || e.path);
			urlInput.placeholder = e.path;
			urlField.append(urlLabel, urlInput);
			tryDiv.append(urlField);
			// Token field when needed or for any non-GET
			if (e.needs_token || e.method !== 'GET') {
				const tok = document.createElement('div'); tok.className='field';
				const l = document.createElement('label'); l.className='small'; l.textContent='X-Admin-Token';
				const i = document.createElement('input'); i.type='password'; i.placeholder='optional for GET; required for admin endpoints';
				tok.append(l, i); tryDiv.append(tok); tryDiv._token = i;
			}
			// Body for POST/PUT/PATCH
			if (e.method !== 'GET') {
				const ctField = document.createElement('div'); ctField.className='field';
				const ctl = document.createElement('label'); ctl.className='small'; ctl.textContent='Content-Type';
				const cts = document.createElement('select');
				for (const opt of ['application/json','text/plain']) { const o=document.createElement('option'); o.value=opt; o.textContent=opt; if (opt===e.content_type) o.selected=true; cts.append(o); }
				ctField.append(ctl, cts); tryDiv.append(ctField);
				const bodyField = document.createElement('div'); bodyField.className='field';
				const bl = document.createElement('label'); bl.className='small'; bl.textContent='Body';
				const ta = document.createElement('textarea'); ta.rows=6; ta.value = e.body_template || '';
				bodyField.append(bl, ta); tryDiv.append(bodyField); tryDiv._body = ta; tryDiv._ct = cts;
			}
			// Actions
			const actions = document.createElement('div'); actions.className='actions';
			const send = document.createElement('button'); send.className='btn'; send.textContent='Send';
			const open = document.createElement('a'); open.className='btn'; open.textContent='Open'; open.target='_blank'; open.rel='noopener';
			actions.append(send, open); tryDiv.append(actions);
			const result = document.createElement('div'); result.className='result'; result.style.display='none'; tryDiv.append(result);

			const buildURL = (u) => {
				if (!/^https?:\/\//i.test(u)) { return '//' + __HOST__ + (u.startsWith('/')?u:'/'+u); }
				return u;
			};
			open.addEventListener('click', (ev)=>{
				ev.preventDefault();
				let raw = urlInput.value.trim() || '/';
				// If default sample equals the summary URL, open the base path instead; otherwise leave as-is
				const defaultSample = e.sample_url || e.path;
				if (defaultSample && defaultSample.includes('summary=true') && raw === defaultSample) {
					raw = e.path || '/';
				}
				open.href = buildURL(raw);
				window.open(open.href,'_blank');
			});
			send.addEventListener('click', async ()=>{
				const full = buildURL(urlInput.value.trim()||'/');
				result.style.display='block'; result.textContent='Sending...';
				const init = { method: e.method, headers: {} };
				if (tryDiv._token && tryDiv._token.value) { init.headers['X-Admin-Token'] = tryDiv._token.value; }
				if (e.method !== 'GET') {
					const ct = tryDiv._ct.value;
					init.headers['Content-Type'] = ct;
					init.body = tryDiv._body.value || '';
				}
				const t0 = performance.now();
				try{
					const resp = await fetch(full, init);
					const dt = (performance.now()-t0).toFixed(0);
					const ctype = resp.headers.get('content-type') || '';
					let bodyText;
					if (ctype.includes('application/json')) {
						const data = await resp.json().catch(()=>null);
						bodyText = data? JSON.stringify(data,null,2) : await resp.text();
					} else {
						bodyText = await resp.text();
					}
					result.textContent = ` + "`" + `HTTP ${resp.status} ${resp.statusText} (${dt} ms)\nContent-Type: ${ctype}\n\n${bodyText}` + "`" + `;
				}catch(err){
					result.textContent = 'Request failed: ' + err;
				}
			});

			details.append(tryDiv);
			root.append(details);
		}
	})();

    (() => {
      const defaultUrls = [
        'https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/refs/heads/main/disposable_email_blocklist.conf',
		'https://disposable.github.io/disposable-email-domains/domains.txt',
		'https://raw.githubusercontent.com/7c/fakefilter/refs/heads/main/txt/data.txt',
		'https://raw.githubusercontent.com/FGRibreau/mailchecker/refs/heads/master/list.txt',
		'https://raw.githubusercontent.com/amieiro/disposable-email-domains/refs/heads/master/denyDomains.txt',
		'https://gist.githubusercontent.com/ammarshah/f5c2624d767f91a7cbdc4e54db8dd0bf/raw/660fd949eba09c0b86574d9d3aa0f2137161fc7c/all_email_provider_domains.txt',
		'https://github.com/gblmarquez/disposable-email-domains/raw/refs/heads/main/disposable_email_domains_blocklist.txt',
		'https://raw.githubusercontent.com/unkn0w/disposable-email-domain-list/refs/heads/main/domains.txt',
		'https://raw.githubusercontent.com/ivolo/disposable-email-domains/refs/heads/master/wildcard.json',
		'https://github.com/IntegerAlex/disposable-email-detector/raw/refs/heads/main/index.json'
      ];

      const ta = document.getElementById('urlsInput');
      if (ta && !ta.value.trim()) {
        ta.value = defaultUrls.join('\n');
      }

      const btn = document.getElementById('addUrlsBtn');
      if (!btn) return;
			btn.addEventListener('click', async () => {
				const taEl = document.getElementById('urlsInput');
				const resEl = document.getElementById('urlsResult');
				const reload = document.getElementById('reloadAfter').checked;
				const urls = (taEl.value || '').split(/\r?\n/).map(s => s.trim()).filter(s => /^https?:\/\//i.test(s));
				if (urls.length === 0) {
					resEl.style.display = 'none';
					resEl.textContent = '';
					return;
				}
				resEl.style.display = 'block';
				resEl.textContent = 'Processing ' + urls.length + ' URL(s)...';
				try {
					const token = (document.getElementById('adminTokenInput') || {}).value || '';
					if (!token) {
						resEl.style.display = 'block';
						resEl.textContent = 'Admin token required.';
						return;
					}
					const resp = await fetch('/blocklist' + (reload ? '?reload=true' : ''), {
						method: 'POST',
						headers: { 'Content-Type': 'application/json', 'X-Admin-Token': token },
						body: JSON.stringify({ urls })
					});
					const data = await resp.json().catch(() => ({}));
					if (!resp.ok) {
						resEl.style.display = 'block';
						if (resp.status === 401 || resp.status === 403) {
							resEl.textContent = 'Auth error: ' + (data.error || 'unauthorized');
						} else {
							resEl.textContent = 'Error: ' + (data.error || (resp.status + ' ' + resp.statusText));
						}
						return;
					}
					resEl.style.display = 'block';
					resEl.textContent = 'Appended: ' + (data.appended || 0) + ', Skipped duplicates: ' + (data.skipped_duplicates || 0) + (data.reloaded ? ', Reloaded: true' : '');
				} catch (e) {
					resEl.style.display = 'block';
					resEl.textContent = 'Request failed: ' + e;
				}
			});
    })();
    </script>
  </div>
</body>
</html>`
	_, _ = io.WriteString(w, html)
}

func (a *API) Blocklist(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/blocklist" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query()
		summary := q.Get("summary") == "true"
		offset := 0
		limit := 0
		if s := strings.TrimSpace(q.Get("offset")); s != "" {
			if v, err := strconv.Atoi(s); err == nil && v >= 0 {
				offset = v
			}
		}
		if s := strings.TrimSpace(q.Get("limit")); s != "" {
			if v, err := strconv.Atoi(s); err == nil && v >= 0 {
				limit = v
			}
		}
		entries, total, err := readBlocklistEntriesPaged("blocklist.conf", offset, limit)
		if err != nil {
			respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if summary {
			respondJSON(w, http.StatusOK, map[string]any{"count": total})
			return
		}
		respondJSON(w, http.StatusOK, map[string]any{"entries": entries, "count": total, "offset": offset, "limit": limit})
	case http.MethodPost:
		var payload struct {
			Entries []string `json:"entries"`
			URL     string   `json:"url"`
			URLs    []string `json:"urls"`
		}
		if err := decodeJSON(w, r, &payload, 5<<20); err != nil { // 5MB
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		if len(payload.Entries) == 0 && strings.TrimSpace(payload.URL) == "" && len(payload.URLs) == 0 {
			respondError(w, http.StatusBadRequest, "provide entries or url(s)")
			return
		}

		// Collect candidates
		candidates := make([]string, 0, len(payload.Entries))
		for _, e := range payload.Entries {
			e = strings.ToLower(strings.TrimSpace(e))
			if e == "" || strings.HasPrefix(e, "#") {
				continue
			}
			candidates = append(candidates, e)
		}
		// Collect URLs to fetch (deduplicated)
		urlSet := make(map[string]struct{})
		if u := strings.TrimSpace(payload.URL); u != "" {
			urlSet[u] = struct{}{}
		}
		for _, u := range payload.URLs {
			u = strings.TrimSpace(u)
			if u == "" {
				continue
			}
			urlSet[u] = struct{}{}
		}
		const (
			maxPerFetchEntries = 200_000 // safety upper bound
			maxLineLen         = 256
		)
		totalCandidateLimitTriggered := false
		if len(urlSet) > 0 {
			client := &http.Client{Timeout: 12 * time.Second}
			// cumulative limit across all fetched bodies (32MB)
			var cumulative int64
			const cumulativeCap = 32 << 20
			for u := range urlSet {
				if !(strings.HasPrefix(u, "https://")) { // enforce https only
					respondError(w, http.StatusBadRequest, "only https scheme allowed for remote lists")
					return
				}
				// Resolve host and reject private / special IP ranges to reduce SSRF risk.
				parsed, err := url.Parse(u)
				if err != nil {
					respondError(w, http.StatusBadRequest, "invalid url: "+err.Error())
					return
				}
				host := parsed.Host
				if hIdx := strings.Index(host, ":"); hIdx != -1 { // strip port
					host = host[:hIdx]
				}
				ips, err := net.LookupIP(host)
				if err != nil || len(ips) == 0 {
					respondError(w, http.StatusBadRequest, "dns lookup failed for host")
					return
				}
				for _, ip := range ips {
					if isDisallowedIP(ip) {
						respondError(w, http.StatusBadRequest, "disallowed host ip range")
						return
					}
				}

				resp, err := client.Get(u)
				if err != nil {
					respondError(w, http.StatusBadRequest, "failed to fetch url: "+err.Error())
					return
				}
				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					_ = resp.Body.Close()
					respondError(w, http.StatusBadRequest, "fetch url status: "+resp.Status)
					return
				}
				const maxURLBody = 12 << 20 // 12MB per URL
				lr := &io.LimitedReader{R: resp.Body, N: maxURLBody + 1}
				data, err := io.ReadAll(lr)
				_ = resp.Body.Close()
				if err != nil {
					respondError(w, http.StatusBadRequest, "failed reading url body: "+err.Error())
					return
				}
				if int64(len(data)) > maxURLBody {
					respondError(w, http.StatusBadRequest, "url body too large")
					return
				}
				cumulative += int64(len(data))
				if cumulative > cumulativeCap {
					respondError(w, http.StatusBadRequest, "cumulative fetched data too large")
					return
				}

				trimmed := bytes.TrimSpace(data)

				// Try to parse as JSON array of strings first
				var arr []string
				if len(trimmed) > 0 && trimmed[0] == '[' && json.Unmarshal(trimmed, &arr) == nil {
					for _, v := range arr {
						v = strings.ToLower(strings.TrimSpace(v))
						if v == "" || strings.HasPrefix(v, "#") {
							continue
						}
						if len(v) > maxLineLen {
							continue
						}
						if len(candidates) < maxPerFetchEntries {
							candidates = append(candidates, v)
						} else {
							totalCandidateLimitTriggered = true
							break
						}
					}
					continue
				}

				// Fallback to plaintext, one domain per non-empty, non-comment line
				s := bufio.NewScanner(bytes.NewReader(data))
				for s.Scan() {
					line := strings.ToLower(strings.TrimSpace(s.Text()))
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					if len(line) > maxLineLen {
						continue
					}
					if len(candidates) < maxPerFetchEntries {
						candidates = append(candidates, line)
					} else {
						totalCandidateLimitTriggered = true
						break
					}
				}
				if err := s.Err(); err != nil {
					respondError(w, http.StatusBadRequest, "failed reading url body: "+err.Error())
					return
				}
			}
		}
		if len(candidates) == 0 {
			respondError(w, http.StatusBadRequest, "no valid entries to add")
			return
		}
		if totalCandidateLimitTriggered {
			a.Logger.Println("blocklist fetch: candidate cap reached")
		}

		// Build existing set and count total lines for id calculation
		existingSet := make(map[string]struct{})
		totalLines, err := buildExistingSet("blocklist.conf", existingSet)
		if err != nil {
			respondError(w, http.StatusInternalServerError, err.Error())
			return
		}

		// Filter new unique entries
		unique := make([]string, 0, len(candidates))
		for _, c := range candidates {
			if _, ok := existingSet[c]; ok {
				continue
			}
			existingSet[c] = struct{}{}
			unique = append(unique, c)
		}

		// Atomic append: serialize and write via temp file rename
		if len(unique) > 0 {
			a.blMu.Lock()
			// read existing full file (including comments) to preserve content
			orig, _ := os.ReadFile("blocklist.conf")
			var b bytes.Buffer
			b.Write(orig)
			if len(orig) > 0 && !bytes.HasSuffix(orig, []byte{'\n'}) {
				b.WriteByte('\n')
			}
			for _, v := range unique {
				b.WriteString(v)
				b.WriteByte('\n')
			}
			tmpName := filepath.Join(filepath.Dir("blocklist.conf"), "blocklist.conf.tmp")
			if err := os.WriteFile(tmpName, b.Bytes(), 0o644); err != nil {
				a.blMu.Unlock()
				respondError(w, http.StatusInternalServerError, "write temp: "+err.Error())
				return
			}
			if err := os.Rename(tmpName, "blocklist.conf"); err != nil {
				a.blMu.Unlock()
				respondError(w, http.StatusInternalServerError, "rename: "+err.Error())
				return
			}
			// Ensure in-memory checker view reflects appended domains immediately.
			if a.Check != nil {
				a.Check.PatchBlock(unique)
			}
			// Update status snapshot
			if a.Check != nil {
				a.statusMu.Lock()
				a.status.BlocklistCount = a.Check.BlockCount()
				a.status.LastListUpdate = time.Now().UTC()
				a.statusMu.Unlock()
			}
			a.blMu.Unlock()
		}

		// Optional reload via query param (now generally unnecessary for correctness,
		// but kept for callers who want a full re-parse + validation path).
		reload := r.URL.Query().Get("reload") == "true"
		reloaded := false
		if reload && a.Check != nil {
			if err := a.Check.Reload(false); err == nil {
				reloaded = true
				a.statusMu.Lock()
				a.status.BlocklistCount = a.Check.BlockCount()
				a.status.AllowlistCount = a.Check.AllowCount()
				a.status.LastListUpdate = time.Now().UTC()
				a.statusMu.Unlock()
			}
		}

		// Compute ids for appended entries
		added := make([]map[string]any, 0, len(unique))
		for i, v := range unique {
			added = append(added, map[string]any{"id": totalLines + i + 1, "domain": v})
		}

		appended := len(unique)
		skipped := len(candidates) - len(unique)
		if appended > 0 {
			metrics.BlocklistAppendsTotal.Add(float64(appended))
		}
		if skipped > 0 {
			metrics.BlocklistDuplicatesSkippedTotal.Add(float64(skipped))
		}
		respondJSON(w, http.StatusOK, map[string]any{
			"appended":           appended,
			"skipped_duplicates": skipped,
			"added":              added,
			"reloaded":           reloaded,
		})
	default:
		respondMethodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

// readBlocklistEntriesPaged streams the file and returns up to 'limit' entries after skipping 'offset' entries.
// It also returns the total number of entries in the file (excluding comments/blank lines). If limit is 0, no
// entries are returned but total is still computed. IDs correspond to the line number in the file to remain
// consistent with other API shapes.
func readBlocklistEntriesPaged(path string, offset, limit int) ([]map[string]any, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	fileLine := 0
	entriesSeen := 0
	var out []map[string]any
	for s.Scan() {
		fileLine++
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entriesSeen++
		if entriesSeen <= offset {
			continue
		}
		if limit > 0 && len(out) >= limit {
			continue
		}
		out = append(out, map[string]any{"id": fileLine, "domain": strings.ToLower(line)})
	}
	if err := s.Err(); err != nil {
		return nil, entriesSeen, err
	}
	return out, entriesSeen, nil
}

func buildExistingSet(path string, set map[string]struct{}) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	lineNo := 0
	for s.Scan() {
		lineNo++
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		set[strings.ToLower(line)] = struct{}{}
	}
	if err := s.Err(); err != nil {
		return 0, err
	}
	return lineNo, nil
}

func (a *API) GetAllowlistFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondMethodNotAllowed(w, http.MethodGet)
		return
	}
	if r.URL.Path != "/allowlist.conf" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	http.ServeFile(w, r, "allowlist.conf")
}

func (a *API) GetBlocklistFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondMethodNotAllowed(w, http.MethodGet)
		return
	}
	if r.URL.Path != "/blocklist.conf" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	http.ServeFile(w, r, "blocklist.conf")
}

func (a *API) GetPSLFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondMethodNotAllowed(w, http.MethodGet)
		return
	}
	if r.URL.Path != "/public_suffix_list.dat" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	http.ServeFile(w, r, "public_suffix_list.dat")
}

func (a *API) CheckHandler(w http.ResponseWriter, r *http.Request) {
	if a.Check == nil {
		respondError(w, http.StatusServiceUnavailable, "checker not initialized")
		return
	}
	switch r.Method {
	case http.MethodGet:
		q := strings.TrimSpace(r.URL.Query().Get("q"))
		if q == "" {
			respondError(w, http.StatusBadRequest, "missing q")
			return
		}
		res := a.Check.Check(q)
		respondJSON(w, http.StatusOK, res)
	default:
		respondMethodNotAllowed(w, http.MethodGet)
	}
}

// CheckEmailsBatch handles POST /check/emails
// Accepts either:
//   - Content-Type: application/json with body ["a@b.com", "c@d.com", ...]
//     or {"items":["a@b.com", ...]} or {"emails":[...]} or {"values":[...]}
//   - Content-Type: text/plain with newline-separated emails
//
// Returns JSON array of domain.Result objects in the same order as provided.
func (a *API) CheckEmailsBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondMethodNotAllowed(w, http.MethodPost)
		return
	}
	if r.URL.Path != "/check/emails" {
		http.NotFound(w, r)
		return
	}
	if a.Check == nil || !a.Check.IsReady() {
		respondError(w, http.StatusServiceUnavailable, "checker not initialized")
		return
	}
	items, err := parseBatchStrings(w, r)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if r.URL.Query().Get("format") == "ndjson" {
		a.streamBatchNDJSON(w, r, items)
		return
	}
	max := 200000
	if a.cfg != nil && a.cfg.BatchMaxItems > 0 {
		max = a.cfg.BatchMaxItems
	}
	if len(items) > max {
		respondError(w, http.StatusRequestEntityTooLarge, "too many items (max "+strconv.Itoa(max)+")")
		return
	}
	results := make([]domain.Result, len(items))
	for i, s := range items {
		results[i] = a.Check.Check(s)
	}
	respondJSON(w, http.StatusOK, results)
}

// CheckDomainsBatch handles POST /check/domains with same formats as emails.
func (a *API) CheckDomainsBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondMethodNotAllowed(w, http.MethodPost)
		return
	}
	if r.URL.Path != "/check/domains" {
		http.NotFound(w, r)
		return
	}
	if a.Check == nil || !a.Check.IsReady() {
		respondError(w, http.StatusServiceUnavailable, "checker not initialized")
		return
	}
	items, err := parseBatchStrings(w, r)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if r.URL.Query().Get("format") == "ndjson" {
		a.streamBatchNDJSON(w, r, items)
		return
	}
	max := 200000
	if a.cfg != nil && a.cfg.BatchMaxItems > 0 {
		max = a.cfg.BatchMaxItems
	}
	if len(items) > max {
		respondError(w, http.StatusRequestEntityTooLarge, "too many items (max "+strconv.Itoa(max)+")")
		return
	}
	results := make([]domain.Result, len(items))
	for i, s := range items {
		results[i] = a.Check.Check(s)
	}
	respondJSON(w, http.StatusOK, results)
}

// streamBatchNDJSON writes one JSON object per line for each input, minimizing memory usage.
func (a *API) streamBatchNDJSON(w http.ResponseWriter, r *http.Request, items []string) {
	max := 1_000_000
	if a.cfg != nil && a.cfg.BatchStreamMaxItems > 0 {
		max = a.cfg.BatchStreamMaxItems
	}
	if len(items) > max {
		respondError(w, http.StatusRequestEntityTooLarge, "too many items for streaming (max "+strconv.Itoa(max)+")")
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	enc := json.NewEncoder(w)
	// Stream one by one; best-effort flush
	flusher, _ := w.(http.Flusher)
	for _, s := range items {
		res := a.Check.Check(s)
		if err := enc.Encode(res); err != nil {
			// can't write JSON? abort
			return
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// parseBatchStrings parses the request body into a slice of strings.
// Supported formats:
// - JSON array of strings
// - JSON object with one of keys: items, values, emails, domains (array of strings)
// - text/plain newline-separated values
func parseBatchStrings(w http.ResponseWriter, r *http.Request) ([]string, error) {
	const maxBody = 16 << 20 // 16MB
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/json") {
		// Attempt array first
		var arr []string
		if err := decodeJSON(w, r, &arr, maxBody); err == nil {
			return sanitizeStrings(arr), nil
		}
		// Attempt object with common keys
		var obj map[string]any
		if err := decodeJSON(w, r, &obj, maxBody); err != nil {
			return nil, err
		}
		for _, k := range []string{"items", "values", "emails", "domains"} {
			if v, ok := obj[k]; ok {
				switch vv := v.(type) {
				case []any:
					out := make([]string, 0, len(vv))
					for _, iv := range vv {
						if s, ok := iv.(string); ok {
							out = append(out, s)
						}
					}
					return sanitizeStrings(out), nil
				case []string:
					return sanitizeStrings(vv), nil
				}
			}
		}
		return nil, errors.New("invalid JSON payload; expected array of strings or {items|values|emails|domains: [...]} ")
	}
	// Fallback: treat as text
	limited := http.MaxBytesReader(w, r.Body, maxBody)
	defer limited.Close()
	var lines []string
	s := bufio.NewScanner(limited)
	// Increase scanner buffer for long lines
	buf := make([]byte, 0, 64*1024)
	s.Buffer(buf, 1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, errors.New("empty body")
	}
	return sanitizeStrings(lines), nil
}

func sanitizeStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

func (a *API) ValidateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondMethodNotAllowed(w, http.MethodGet)
		return
	}
	if a.Check == nil {
		respondError(w, http.StatusServiceUnavailable, "checker not initialized")
		return
	}
	rep := a.Check.Validate()
	respondJSON(w, http.StatusOK, rep)
}

func (a *API) ReloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondMethodNotAllowed(w, http.MethodPost)
		return
	}
	if a.Check == nil {
		respondError(w, http.StatusServiceUnavailable, "checker not initialized")
		return
	}
	strict := r.URL.Query().Get("strict") == "true"
	if err := a.Check.Reload(strict); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Update counts after full reload
	if a.Check != nil {
		a.statusMu.Lock()
		a.status.BlocklistCount = a.Check.BlockCount()
		a.status.AllowlistCount = a.Check.AllowCount()
		a.status.LastListUpdate = time.Now().UTC()
		a.statusMu.Unlock()
	}
	respondJSON(w, http.StatusOK, map[string]any{"reloaded": true, "strict": strict})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any, maxBytes int64) error {
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch {
		ct := r.Header.Get("Content-Type")
		if !strings.HasPrefix(ct, "application/json") {
			return errors.New("Content-Type must be application/json")
		}
	}

	if r.Body == nil {
		return errors.New("empty body")
	}
	defer r.Body.Close()

	limited := http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(limited)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("empty body")
		}
		return err
	}
	if dec.More() {
		return errors.New("only a single JSON object is allowed")
	}
	return nil
}

func respondJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")

	w.WriteHeader(status)
	if v == nil || status == http.StatusNoContent {
		return
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

type apiError struct {
	Error struct {
		Code    string         `json:"code"`
		Message string         `json:"message"`
		Meta    map[string]any `json:"meta,omitempty"`
	} `json:"error"`
}

func writeAPIError(w http.ResponseWriter, status int, code, msg string, meta map[string]any) {
	if code == "" {
		code = http.StatusText(status)
	}
	var body apiError
	body.Error.Code = code
	body.Error.Message = msg
	if len(meta) > 0 {
		body.Error.Meta = meta
	}
	respondJSON(w, status, body)
}

func respondError(w http.ResponseWriter, status int, msg string) {
	writeAPIError(w, status, "", msg, nil)
}

func respondMethodNotAllowed(w http.ResponseWriter, allowed ...string) {
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	respondError(w, http.StatusMethodNotAllowed, "method not allowed")
}

// Path-based check: /check/emails/{email}
func (a *API) CheckEmailPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondMethodNotAllowed(w, http.MethodGet)
		return
	}
	if a.Check == nil {
		respondError(w, http.StatusServiceUnavailable, "checker not initialized")
		return
	}
	prefix := "/check/emails/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		respondError(w, http.StatusNotFound, "not found")
		return
	}
	raw := strings.TrimPrefix(r.URL.Path, prefix)
	if raw == "" || strings.Contains(raw, "/") {
		respondError(w, http.StatusNotFound, "not found")
		return
	}
	val, err := url.PathUnescape(raw)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid path encoding")
		return
	}
	res := a.Check.Check(val)
	respondJSON(w, http.StatusOK, res)
}

// Path-based check: /check/domains/{domain}
func (a *API) CheckDomainPath(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondMethodNotAllowed(w, http.MethodGet)
		return
	}
	if a.Check == nil {
		respondError(w, http.StatusServiceUnavailable, "checker not initialized")
		return
	}
	prefix := "/check/domains/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		respondError(w, http.StatusNotFound, "not found")
		return
	}
	raw := strings.TrimPrefix(r.URL.Path, prefix)
	if raw == "" || strings.Contains(raw, "/") {
		respondError(w, http.StatusNotFound, "not found")
		return
	}
	val, err := url.PathUnescape(raw)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid path encoding")
		return
	}
	res := a.Check.Check(val)
	respondJSON(w, http.StatusOK, res)
}

// HTML report: /report (validate findings)
func (a *API) ReportValidateHTML(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondMethodNotAllowed(w, http.MethodGet)
		return
	}
	if r.URL.Path != "/report" {
		http.NotFound(w, r)
		return
	}
	if a.Check == nil {
		respondError(w, http.StatusServiceUnavailable, "checker not initialized")
		return
	}
	rep := a.Check.Validate()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>Validate Report</title><style>`)
	b.WriteString(`:root{--bg:#0b1020;--panel:#121a2e;--text:#e6eefc;--muted:#9fb3d9;--accent:#7cc4ff;--err:#ef4444;--warn:#f59e0b;--ok:#22c55e}*{box-sizing:border-box}body{margin:0;background:#0b1020;color:var(--text);font:16px/1.5 system-ui} .wrap{max-width:960px;margin:0 auto;padding:24px} .card{background:#121a2e;border:1px solid #1d2947;border-radius:14px;margin-bottom:16px;overflow:hidden} .card h2{margin:0;padding:12px 16px;border-bottom:1px solid #1d2947;font-size:16px} .content{padding:12px 16px} ul{margin:8px 0 0 20px} li{margin:2px 0} .pill{display:inline-block;margin-left:8px;padding:2px 8px;border-radius:999px;background:#132042;color:#9cc2ff;border:1px solid #1f2c4a;font-size:12px}`)
	b.WriteString(`</style></head><body><div class="wrap">`)
	b.WriteString(`<div class="card"><h2>Summary<span class="pill">`)
	if rep.ErrorsFound {
		b.WriteString("errors found")
	} else {
		b.WriteString("no errors")
	}
	b.WriteString(`</span></h2><div class="content"><div>Checked at: ` + time.Now().UTC().Format(time.RFC3339) + `</div></div></div>`)

	renderList := func(title string, items []string) {
		b.WriteString(`<div class="card"><h2>` + title + ` <span class="pill">` + strconv.Itoa(len(items)) + `</span></h2><div class="content">`)
		if len(items) == 0 {
			b.WriteString(`<div style="color:var(--muted)">None</div>`)
		} else {
			b.WriteString(`<ul>`)
			for _, it := range items {
				b.WriteString(`<li>` + htmlEscape(it) + `</li>`)
			}
			b.WriteString(`</ul>`)
		}
		b.WriteString(`</div></div>`)
	}

	renderList("Public suffix entries in blocklist", rep.PublicSuffixInBlock)
	renderList("Third-or-lower level entries in blocklist", rep.ThirdLevelInBlock)
	renderList("Non-lowercase in allowlist", rep.NonLowercaseAllow)
	renderList("Non-lowercase in blocklist", rep.NonLowercaseBlock)
	renderList("Duplicates in allowlist", rep.DuplicatesAllow)
	renderList("Duplicates in blocklist", rep.DuplicatesBlock)
	renderList("Intersection between allowlist and blocklist", rep.Intersection)

	if rep.UnsortedAllowHint != "" || rep.UnsortedBlockHint != "" {
		b.WriteString(`<div class="card"><h2>Sorting hints</h2><div class="content">`)
		if rep.UnsortedAllowHint != "" {
			b.WriteString(`<div>Allowlist: ` + htmlEscape(rep.UnsortedAllowHint) + `</div>`)
		}
		if rep.UnsortedBlockHint != "" {
			b.WriteString(`<div>Blocklist: ` + htmlEscape(rep.UnsortedBlockHint) + `</div>`)
		}
		b.WriteString(`</div></div>`)
	}

	b.WriteString(`</div></body></html>`)
	_, _ = io.WriteString(w, b.String())
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// HTML single-check report: /report/emails/{email}
func (a *API) ReportCheckEmailHTML(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondMethodNotAllowed(w, http.MethodGet)
		return
	}
	if a.Check == nil {
		respondError(w, http.StatusServiceUnavailable, "checker not initialized")
		return
	}
	prefix := "/report/emails/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	raw := strings.TrimPrefix(r.URL.Path, prefix)
	if raw == "" || strings.Contains(raw, "/") {
		http.NotFound(w, r)
		return
	}
	val, err := url.PathUnescape(raw)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid path encoding")
		return
	}
	res := a.Check.Check(val)
	writeCheckHTML(w, r, res)
}

// HTML single-check report: /report/domains/{domain}
func (a *API) ReportCheckDomainHTML(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondMethodNotAllowed(w, http.MethodGet)
		return
	}
	if a.Check == nil {
		respondError(w, http.StatusServiceUnavailable, "checker not initialized")
		return
	}
	prefix := "/report/domains/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	raw := strings.TrimPrefix(r.URL.Path, prefix)
	if raw == "" || strings.Contains(raw, "/") {
		http.NotFound(w, r)
		return
	}
	val, err := url.PathUnescape(raw)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid path encoding")
		return
	}
	res := a.Check.Check(val)
	writeCheckHTML(w, r, res)
}

func writeCheckHTML(w http.ResponseWriter, r *http.Request, res domain.Result) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>Check Report</title><style>`)
	b.WriteString(`:root{--bg:#0b1020;--panel:#121a2e;--text:#e6eefc;--muted:#9fb3d9;--accent:#7cc4ff;--ok:#22c55e;--warn:#f59e0b;--err:#ef4444}*{box-sizing:border-box}body{margin:0;background:#0b1020;color:var(--text);font:16px/1.5 system-ui} .wrap{max-width:720px;margin:0 auto;padding:24px} .card{background:#121a2e;border:1px solid #1d2947;border-radius:14px;margin-bottom:16px;overflow:hidden} .card h2{margin:0;padding:12px 16px;border-bottom:1px solid #1d2947;font-size:16px} .content{padding:12px 16px} .kv{display:grid;grid-template-columns:220px 1fr;gap:8px 16px} .key{color:#9fb3d9} .val{color:#e6eefc}`)
	b.WriteString(`</style></head><body><div class="wrap">`)
	b.WriteString(`<div class="card"><h2>Input</h2><div class="content kv">`)
	b.WriteString(`<div class="key">input</div><div class="val">` + htmlEscape(res.Input) + `</div>`)
	b.WriteString(`<div class="key">type</div><div class="val">` + res.Type + `</div>`)
	b.WriteString(`<div class="key">valid_format</div><div class="val">` + boolStr(res.ValidFormat) + `</div>`)
	if res.LocalPart != "" {
		b.WriteString(`<div class="key">local_part</div><div class="val">` + htmlEscape(res.LocalPart) + `</div>`)
	}
	b.WriteString(`</div></div>`)

	b.WriteString(`<div class="card"><h2>Domain</h2><div class="content kv">`)
	b.WriteString(`<div class="key">domain</div><div class="val">` + htmlEscape(res.Domain) + `</div>`)
	b.WriteString(`<div class="key">normalized_domain</div><div class="val">` + htmlEscape(res.NormalizedDomain) + `</div>`)
	b.WriteString(`<div class="key">public_suffix</div><div class="val">` + htmlEscape(res.PublicSuffix) + `</div>`)
	b.WriteString(`<div class="key">registrable_domain</div><div class="val">` + htmlEscape(res.RegistrableDomain) + `</div>`)
	b.WriteString(`<div class="key">is_public_suffix_only</div><div class="val">` + boolStr(res.IsPublicSuffixOnly) + `</div>`)
	b.WriteString(`<div class="key">is_subdomain</div><div class="val">` + boolStr(res.IsSubdomain) + `</div>`)
	b.WriteString(`</div></div>`)

	b.WriteString(`<div class="card"><h2>Decision</h2><div class="content kv">`)
	b.WriteString(`<div class="key">allowlisted</div><div class="val">` + boolStr(res.Allowlisted) + `</div>`)
	b.WriteString(`<div class="key">blocklisted</div><div class="val">` + boolStr(res.Blocklisted) + `</div>`)
	b.WriteString(`<div class="key">status</div><div class="val">` + res.Status + `</div>`)
	b.WriteString(`</div></div>`)

	b.WriteString(`<div class="card"><h2>Timestamps</h2><div class="content kv">`)
	b.WriteString(`<div class="key">checked_at</div><div class="val">` + res.CheckedAt.Format(time.RFC3339) + `</div>`)
	b.WriteString(`<div class="key">lists_updated_at</div><div class="val">` + res.UpdatedAt.Format(time.RFC3339) + `</div>`)
	b.WriteString(`</div></div>`)

	b.WriteString(`</div></body></html>`)
	_, _ = io.WriteString(w, b.String())
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// isDisallowedIP returns true if the IP is within private, loopback, link-local,
// multicast, unspecified or unique-local (IPv6) ranges. This reduces SSRF risk
// when fetching remote blocklist sources.
func isDisallowedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// Private IPv4 ranges
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 10: // 10.0.0.0/8
			return true
		case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31: // 172.16.0.0/12
			return true
		case v4[0] == 192 && v4[1] == 168: // 192.168.0.0/16
			return true
		case v4[0] == 169 && v4[1] == 254: // link-local 169.254/16 (already caught, keep explicit)
			return true
		}
		return false
	}
	// Unique local IPv6 fc00::/7
	if ip.To16() != nil {
		b0 := ip[0]
		if b0&0xfe == 0xfc { // 0b11111100 -> fc00::/7
			return true
		}
	}
	return false
}
