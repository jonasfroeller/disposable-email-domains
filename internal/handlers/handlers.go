package handlers

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"disposable-email-domains/internal/domain"
)

type Store interface {
	List() []Item
	Get(id string) (Item, bool)
	Create(name string) (Item, error)
	Update(id, name string) (Item, error)
	Delete(id string) bool
}

type Item struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type API struct {
	Store  Store
	Logger *log.Logger
	Check  *domain.Checker
}

func (a *API) Health(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339Nano),
	})
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
	html := `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>API Index</title>
<style>
:root{--bg:#0b1020;--panel:#121a2e;--text:#e6eefc;--muted:#9fb3d9;--accent:#7cc4ff;--ok:#22c55e;--warn:#f59e0b;--err:#ef4444;--chip:#243250}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:linear-gradient(180deg,#0b1020, #0d1730 50%, #0b1020);color:var(--text);font:16px/1.5 system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Arial, "Apple Color Emoji","Segoe UI Emoji"}
.container{max-width:920px;margin:0 auto;padding:32px 16px}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
.h1{font-size:22px;font-weight:700;letter-spacing:.3px}
.small{color:var(--muted);font-size:13px}
.panel{background:rgba(18,26,46,.8);backdrop-filter:blur(6px);border:1px solid #1d2947;border-radius:14px;overflow:hidden;box-shadow:0 10px 30px rgba(0,0,0,.4)}
.panel h2{margin:0;padding:14px 16px;border-bottom:1px solid #1d2947;font-size:16px}
.list{padding:6px}
.row{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:10px}
.row:hover{background:#0e162a}
.method{font-weight:700;font-size:12px;padding:6px 10px;border-radius:999px;background:var(--chip);letter-spacing:.6px}
.get{color:#7dd3fc}
.post{color:#a7f3d0}
.put{color:#fde68a}
.del{color:#fecaca}
.path{font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;color:#e2e8f0;font-size:14px}
.desc{color:var(--muted);font-size:13px;margin-left:auto}
.code{background:#0b1326;border:1px solid #172243;border-radius:10px;padding:14px;margin:12px}
code{font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;color:#d1e9ff;font-size:13px}
.footer{color:var(--muted);font-size:12px;text-align:center;margin-top:22px}
.badge{display:inline-block;margin-left:8px;padding:2px 8px;border-radius:999px;background:#132042;color:#9cc2ff;font-size:12px;border:1px solid #1f2c4a}
</style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="h1">Disposable Email Domains API</div>
      <div class="small">Host: ` + host + `</div>
    </div>

    <div class="panel">
      <h2>Endpoints <span class="badge">net/http</span></h2>
      <div class="list">
        <div class="row"><span class="method get">GET</span><span class="path">/healthz</span><span class="desc">Health check</span></div>
        <div class="row"><span class="method get">GET</span><span class="path">/blocklist</span><span class="desc">List blocklist (JSON)</span></div>
        <div class="row"><span class="method post">POST</span><span class="path">/blocklist</span><span class="desc">Extend blocklist (JSON)</span></div>
        <div class="row"><span class="method get">GET</span><span class="path">/check</span><span class="desc">JSON check via ?q=</span></div>
        <div class="row"><span class="method post">POST</span><span class="path">/check</span><span class="desc">JSON check (body {"input":"..."})</span></div>
        <div class="row"><span class="method get">GET</span><span class="path">/check/emails/{email}</span><span class="desc">Check email (JSON)</span></div>
        <div class="row"><span class="method get">GET</span><span class="path">/check/domains/{domain}</span><span class="desc">Check domain (JSON)</span></div>
        <div class="row"><span class="method get">GET</span><span class="path">/validate</span><span class="desc">Validate lists (JSON)</span></div>
        <div class="row"><span class="method get">GET</span><span class="path">/report</span><span class="desc">Validate report (HTML)</span></div>
        <div class="row"><span class="method get">GET</span><span class="path">/report/emails/{email}</span><span class="desc">Check report for email (HTML)</span></div>
        <div class="row"><span class="method get">GET</span><span class="path">/report/domains/{domain}</span><span class="desc">Check report for domain (HTML)</span></div>
        <div class="row"><span class="method get">GET</span><span class="path">/allowlist.conf</span><span class="desc">Download allowlist</span></div>
        <div class="row"><span class="method get">GET</span><span class="path">/blocklist.conf</span><span class="desc">Download blocklist</span></div>
        <div class="row"><span class="method get">GET</span><span class="path">/public_suffix_list.dat</span><span class="desc">Download PSL snapshot</span></div>
      </div>
    </div>

    <div class="panel" style="margin-top:16px">
      <h2>Quick start</h2>
      <div class="code"><code>curl -sS http://` + host + `/healthz</code></div>
      <div class="code"><code>curl -sS http://` + host + `/blocklist</code></div>
      <div class="code"><code>curl -sS -H "Content-Type: application/json" -d '{"entries":["foo.com","bar.io"]}' http://` + host + `/blocklist</code></div>
      <div class="code"><code>curl -sS -H "Content-Type: application/json" -d '{"url":"https://example.com/list.txt"}' http://` + host + `/blocklist</code></div>
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
          <div style="margin-top:10px;display:flex;gap:8px;align-items:center">
            <button id="addUrlsBtn" style="background:#132042;border:1px solid #1f2c4a;color:#9cc2ff;border-radius:8px;padding:8px 12px;cursor:pointer">Add to blocklist</button>
            <label class="small" style="display:flex;align-items:center;gap:6px"><input id="reloadAfter" type="checkbox" checked /> <span>Reload lists after adding</span></label>
          </div>
          <div id="urlsResult" style="display:none;margin-top:10px;width:100%;background:#0b1326;border:1px solid #172243;border-radius:10px;color:#d1e9ff;padding:10px;white-space:pre-wrap"></div>
        </div>
      </div>
    </div>

    <script nonce="` + nonce + `">
    (() => {
      const defaultUrls = [
        'https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/refs/heads/main/disposable_email_blocklist.conf',
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
          const resp = await fetch('/blocklist' + (reload ? '?reload=true' : ''), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ urls })
          });
          const data = await resp.json().catch(() => ({}));
          if (!resp.ok) {
            resEl.style.display = 'block';
            resEl.textContent = 'Error: ' + (data.error || (resp.status + ' ' + resp.statusText));
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
		list, err := readBlocklistEntries("blocklist.conf")
		if err != nil {
			respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		respondJSON(w, http.StatusOK, map[string]any{"entries": list, "count": len(list)})
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
		if len(urlSet) > 0 {
			client := &http.Client{Timeout: 12 * time.Second}
			for u := range urlSet {
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
				s := bufio.NewScanner(resp.Body)
				for s.Scan() {
					line := strings.ToLower(strings.TrimSpace(s.Text()))
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					candidates = append(candidates, line)
				}
				if err := s.Err(); err != nil {
					_ = resp.Body.Close()
					respondError(w, http.StatusBadRequest, "failed reading url body: "+err.Error())
					return
				}
				_ = resp.Body.Close()
			}
		}
		if len(candidates) == 0 {
			respondError(w, http.StatusBadRequest, "no valid entries to add")
			return
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

		// Append to file
		if len(unique) > 0 {
			f, err := os.OpenFile("blocklist.conf", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
			if err != nil {
				respondError(w, http.StatusInternalServerError, "open file: "+err.Error())
				return
			}
			for _, v := range unique {
				_, _ = io.WriteString(f, v+"\n")
			}
			_ = f.Close()
		}

		// Optional reload via query param
		reload := r.URL.Query().Get("reload") == "true"
		reloaded := false
		if reload && a.Check != nil {
			if err := a.Check.Reload(false); err == nil {
				reloaded = true
			}
		}

		// Compute ids for appended entries
		added := make([]map[string]any, 0, len(unique))
		for i, v := range unique {
			added = append(added, map[string]any{"id": totalLines + i + 1, "domain": v})
		}

		respondJSON(w, http.StatusOK, map[string]any{
			"appended":           len(unique),
			"skipped_duplicates": len(candidates) - len(unique),
			"added":              added,
			"reloaded":           reloaded,
		})
	default:
		respondMethodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

func readBlocklistEntries(path string) ([]map[string]any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	res := make([]map[string]any, 0, 1024)
	s := bufio.NewScanner(f)
	lineNo := 0
	for s.Scan() {
		lineNo++
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		res = append(res, map[string]any{"id": lineNo, "domain": strings.ToLower(line)})
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return res, nil
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
	case http.MethodPost:
		var payload struct {
			Input string `json:"input"`
		}
		if err := decodeJSON(w, r, &payload, 1<<20); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		if strings.TrimSpace(payload.Input) == "" {
			respondError(w, http.StatusBadRequest, "input is required")
			return
		}
		res := a.Check.Check(payload.Input)
		respondJSON(w, http.StatusOK, res)
	default:
		respondMethodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
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

func respondError(w http.ResponseWriter, status int, msg string) {
	respondJSON(w, status, map[string]any{"error": msg})
}

func respondMethodNotAllowed(w http.ResponseWriter, allowed ...string) {
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	respondError(w, http.StatusMethodNotAllowed, "method not allowed")
}

func generateID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
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
