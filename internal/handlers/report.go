package handlers

import (
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"disposable-email-domains/internal/domain"
)

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
	// Accept multiple aliases to avoid upstream filters blocking .dat paths
	if r.URL.Path != "/public_suffix_list.dat" && r.URL.Path != "/psl" && r.URL.Path != "/psl.txt" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=public_suffix_list.dat")
	http.ServeFile(w, r, "public_suffix_list.dat")
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

// HTML single-check report via query: /report/check?input=...
func (a *API) ReportCheckQueryHTML(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondMethodNotAllowed(w, http.MethodGet)
		return
	}
	if a.Check == nil {
		respondError(w, http.StatusServiceUnavailable, "checker not initialized")
		return
	}
	if r.URL.Path != "/report/check" {
		http.NotFound(w, r)
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("input"))
	if q == "" {
		respondError(w, http.StatusBadRequest, "missing input")
		return
	}
	res := a.Check.Check(q)
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
